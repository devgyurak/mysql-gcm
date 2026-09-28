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

void unregister_first(size_t count) {
  for (size_t i = 0; i < count; ++i) {
    int was_present = 0;
    mysql_service_udf_registration->udf_unregister(kUdfs[i].name, &was_present);
  }
}

/* Re-registers the first `count` functions. Used to undo a partial deinit: if the
   component stays loaded, every function it advertises has to be callable. */
void register_first(size_t count) {
  for (size_t i = 0; i < count; ++i) {
    const UdfSpec &udf = kUdfs[i];
    mysql_service_udf_registration->udf_register(udf.name, udf.return_type, udf.func, udf.init,
                                                 udf.deinit);
  }
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
      /* Never report success with only some functions registered. */
      unregister_first(i);
      gcm::sysvar_unregister();
      gcm::crypto_deinit();
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
      register_first(i);
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
