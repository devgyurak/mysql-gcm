/* SPDX-License-Identifier: GPL-2.0-only */
/* Component entry point: service placeholders, UDF registration with rollback,
   and the gcm.strict sysvar. No cryptography and no argument handling here. */

#include <cstddef>

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/component_sys_var_service.h>
#include <mysql/components/services/mysql_runtime_error.h>
#include <mysql/components/services/udf_metadata.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/udf_registration_types.h>

#include "gcm.h"
#include "sysvar.h"

#if GCM_HAS_SESSION_SYSVAR
#include <mysql/components/services/mysql_current_thread_reader.h>
#include <mysql/components/services/mysql_system_variable.h>
#endif

REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
REQUIRES_SERVICE_PLACEHOLDER(mysql_udf_metadata);
REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_register);
REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_unregister);
REQUIRES_SERVICE_PLACEHOLDER(mysql_runtime_error);
#if GCM_HAS_SESSION_SYSVAR
/* Session scope for a component sysvar, and the service that reads it, exist
   only from 9.0.0 (design A5). REQUIRES_SERVICE is a hard load dependency, so on
   8.0/8.4 these must be absent or INSTALL COMPONENT fails with
   ER_COMPONENTS_CANT_SATISFY_DEPENDENCY. */
REQUIRES_SERVICE_PLACEHOLDER(mysql_system_variable_reader);
REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);
#endif

extern "C" {
bool gcm_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_encrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                      unsigned char *is_null, unsigned char *error);
void gcm_encrypt_deinit(UDF_INIT *initid);

bool gcm_encrypt_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_encrypt_det_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                          unsigned char *is_null, unsigned char *error);
void gcm_encrypt_det_deinit(UDF_INIT *initid);

bool gcm_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_decrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                      unsigned char *is_null, unsigned char *error);
void gcm_decrypt_deinit(UDF_INIT *initid);
}

namespace {

struct UdfSpec {
  const char *name;
  Item_result return_type;
  Udf_func_any func;
  Udf_func_init init;
  Udf_func_deinit deinit;
};

const UdfSpec kUdfs[] = {
    {"gcm_encrypt", STRING_RESULT, reinterpret_cast<Udf_func_any>(gcm_encrypt_udf),
     gcm_encrypt_init, gcm_encrypt_deinit},
    {"gcm_encrypt_det", STRING_RESULT, reinterpret_cast<Udf_func_any>(gcm_encrypt_det_udf),
     gcm_encrypt_det_init, gcm_encrypt_det_deinit},
    {"gcm_decrypt", STRING_RESULT, reinterpret_cast<Udf_func_any>(gcm_decrypt_udf),
     gcm_decrypt_init, gcm_decrypt_deinit},
};

constexpr size_t kUdfCount = sizeof(kUdfs) / sizeof(kUdfs[0]);

/* Returns true when every one of the first `count` functions is gone.
   The return value matters: see the rollback in gcm_component_init. */
bool unregister_first(size_t count) {
  bool all_gone = true;
  for (size_t i = 0; i < count; ++i) {
    int was_present = 0;
    if (mysql_service_udf_registration->udf_unregister(kUdfs[i].name, &was_present) &&
        was_present) {
      all_gone = false;
    }
  }
  return all_gone;
}

/* Re-registers the first `count` functions. Used to undo a partial deinit: if the
   component stays loaded, every function it advertises has to be callable. */
/* Returns true when every one of the first `count` functions is registered again. */
bool register_first(size_t count) {
  bool all_back = true;
  for (size_t i = 0; i < count; ++i) {
    const UdfSpec &udf = kUdfs[i];
    if (mysql_service_udf_registration->udf_register(udf.name, udf.return_type, udf.func, udf.init,
                                                     udf.deinit)) {
      all_back = false;
    }
  }
  return all_back;
}

mysql_service_status_t gcm_component_init() {
  /* EVP_CIPHER_fetch / EVP_MAC_fetch happen once here. A failure must stop the
     install: a loaded component whose algorithms are missing would fail every
     call instead (crypto-safety rule). */
  if (gcm::crypto_init() != 0) return 1;

  if (gcm::sysvar_register()) {
    gcm::crypto_deinit();
    return 1;
  }

  for (size_t i = 0; i < kUdfCount; ++i) {
    const UdfSpec &udf = kUdfs[i];
    if (mysql_service_udf_registration->udf_register(udf.name, udf.return_type, udf.func, udf.init,
                                                     udf.deinit)) {
      /* Never report success with only some functions registered. Both results are
         checked: this path used to discard them and free the algorithms regardless.

         What is actually at stake is not the EVP handles. When init returns 1 the
         loader rolls back and its scope guard calls the scheme's unload, which
         dlclose()s the library — and dlopen is given RTLD_NODELETE only in ASan/LSan
         builds (components/libminchassis/dynamic_loader_scheme_file.cc, verified in
         the 8.4.11 tree). So anything still registered points into an unmapped
         segment: a function that refused to unregister will take its caller down
         whatever we do with the cipher handles, and a sysvar that refused to
         unregister leaves the dictionary holding `&g_strict` in unmapped memory,
         which any session can touch with SELECT @@global.gcm.strict. That second one
         is the more reachable half, and it is why unregistering the variable is
         checked here now rather than fired and forgotten.

         Neither can be repaired from inside a component: there is no way to ask the
         loader to keep the library mapped. Releasing the algorithms only when both
         unregisters succeeded is therefore about not adding a second fault to a
         broken install, and about matching gcm_component_deinit — where the same
         reasoning does hold, because a refused UNINSTALL leaves the component loaded
         and the library mapped.

         Reaching any of it needs udf_register to fail on a later function while an
         earlier one is in use, or unregister_variable to fail. udf_register fails on
         a duplicate name or an allocation failure, and unregister_variable fails on
         allocation too, so the two are correlated under memory pressure rather than
         independent. Not reproduced; it came out of review as a question. */
      const bool udfs_gone = unregister_first(i);
      const bool sysvar_gone = !gcm::sysvar_unregister();
      if (udfs_gone && sysvar_gone) gcm::crypto_deinit();
      return 1;
    }
  }
  return 0;
}

mysql_service_status_t gcm_component_deinit() {
  for (size_t i = 0; i < kUdfCount; ++i) {
    int was_present = 0;
    if (mysql_service_udf_registration->udf_unregister(kUdfs[i].name, &was_present) &&
        was_present) {
      /* A function is still in use, so the unload has to fail — otherwise the
         server would hold pointers into a library about to be closed. The
         component stays loaded, which means the functions unregistered before
         this one must come back: leaving them gone would turn a refused
         UNINSTALL into a half-working component that only a restart repairs. */
      if (!register_first(i)) {
        /* Worse than a refused unload: some functions did not come back, so the
           component is loaded and incomplete until a restart. udf_register fails on a
           duplicate name or an allocation failure, and this component requires no
           logging service, so the UNINSTALL error the caller already sees is the only
           signal there is to give. Nothing further is recoverable from here. */
      }
      /* Refused either way — the resources stay and a retry can succeed. */
      return 1;
    }
  }
  if (gcm::sysvar_unregister()) {
    register_first(kUdfCount);
    return 1;
  }
  gcm::crypto_deinit();
  return 0;
}

}  // namespace

BEGIN_COMPONENT_PROVIDES(gcm)
END_COMPONENT_PROVIDES();

BEGIN_COMPONENT_REQUIRES(gcm)
REQUIRES_SERVICE(udf_registration), REQUIRES_SERVICE(mysql_udf_metadata),
    REQUIRES_SERVICE(component_sys_variable_register),
    REQUIRES_SERVICE(component_sys_variable_unregister), REQUIRES_SERVICE(mysql_runtime_error),
#if GCM_HAS_SESSION_SYSVAR
    REQUIRES_SERVICE(mysql_system_variable_reader), REQUIRES_SERVICE(mysql_current_thread_reader),
#endif
    END_COMPONENT_REQUIRES();

BEGIN_COMPONENT_METADATA(gcm)
METADATA("mysql.author", "mysql-gcm contributors"), METADATA("mysql.license", "GPL"),
    END_COMPONENT_METADATA();

DECLARE_COMPONENT(gcm, "gcm")
gcm_component_init, gcm_component_deinit END_DECLARE_COMPONENT();

DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(gcm) END_DECLARE_LIBRARY_COMPONENTS
