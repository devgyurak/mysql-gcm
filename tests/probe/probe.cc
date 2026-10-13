/* SPDX-License-Identifier: GPL-2.0-only */
/* A test-only component that exists to pin one server behaviour (issue #43): a
   prepared statement whose **re-prepare at `EXECUTE`** fails after a loadable
   function has been fixed abandons that function's `UDF_INIT` — its `deinit` is
   never called and the component can no longer be uninstalled. The first shape found is a function
   that raises while the server is evaluating it as the argument of another loadable function,
   during that outer function's `init`; it is not the only one (a sibling function, and a re-prepare
   invalidated by `ALTER TABLE`, leak the same way, and a function that raises nothing is dropped
   too — cases 23 to 26). The cause is read in `docs/upstream-udf-handler-leak.md`.

   Why this is a component of its own rather than part of `component_gcm`: the
   behaviour must be observable independently of this project's code, and
   `component_gcm` has no counter of its own. This file therefore contains no
   cryptography, no key material, no server header beyond the two services it
   needs, and no reference to `src/`. It registers five throwaway functions and
   counts their `init` and `deinit` calls.

   Not shipped. `src/CMakeLists.txt` does not list it, nothing links it, and it
   goes into no image. `scripts/build-probe.sh` builds it inside the build image
   and `scripts/verify-nested.sh` installs it next to `component_gcm` on a
   throwaway server, so that a case can print how many `init`s a leaked
   `UDF_INIT` produced against how many `deinit`s the server ever ran.

   Counters are global and reset explicitly by `probe_reset()`, so a case's
   output does not depend on how many times the server was restarted before it. */

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/mysql_runtime_error_service.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/udf_registration_types.h>
#include <mysqld_error.h>

REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
REQUIRES_SERVICE_PLACEHOLDER(mysql_runtime_error);

namespace {

/* The same buffer the server hands an init function, mirrored for the reason
   `src/udf_glue.cc` gives: MYSQL_ERRMSG_SIZE lives in a header a component must
   not include. */
constexpr size_t kInitMsgLen = 512;

struct Counts {
  std::atomic<unsigned long long> init{0};
  std::atomic<unsigned long long> deinit{0};
};

Counts g_outer;
Counts g_raise_const;
Counts g_raise_volatile;

/* probe_counts() returns this; one thread drives one UDF_INIT, so a thread-local
   buffer is enough and no allocation is needed. */
thread_local char g_json[512];

bool any_arg_is_null(const UDF_ARGS *args) {
  for (unsigned i = 0; i < args->arg_count; ++i) {
    if (args->args[i] == nullptr) return true;
  }
  return false;
}

/* The error a function raises when the server has given it no value for a bound
   parameter — the empty string. Raised through mysql_runtime_error and not only
   returned as *error, because the leak it pins needs the raised SQL error. */
void raise_empty(const char *func) {
  mysql_error_service_printf(ER_UDF_ERROR, 0, func,
                             "no value for the argument: the server evaluated this function "
                             "before its bound parameter had one");
}

bool value_init(UDF_INIT *initid, UDF_ARGS *args, char *message, Counts *counts, bool const_item,
                const char *name) {
  if (args->arg_count < 1 || args->arg_count > 3) {
    std::snprintf(message, kInitMsgLen, "%s(plaintext, key [, aad]) needs 1 to 3 arguments", name);
    return true;
  }
  for (unsigned i = 0; i < args->arg_count; ++i) args->arg_type[i] = STRING_RESULT;
  initid->maybe_null = true;
  /* The one thing a probe function chooses: `gcm_encrypt_det` claims const_item
     and `gcm_encrypt` does not, and the nested defect may depend on it. */
  initid->const_item = const_item;
  initid->max_length = args->lengths[0];
  counts->init.fetch_add(1, std::memory_order_relaxed);
  return false;
}

/* Mirrors the first argument, and, when `raise_on_empty`, does what a served
   function does when the empty string is not a value it accepts. */
char *value_row(const char *func, UDF_ARGS *args, unsigned long *length, unsigned char *is_null,
                unsigned char *error, bool raise_on_empty) {
  if (any_arg_is_null(args)) {
    *is_null = 1;
    return nullptr;
  }
  if (raise_on_empty && args->lengths[0] == 0) {
    raise_empty(func);
    *error = 1;
    return nullptr;
  }
  *length = args->lengths[0];
  return args->args[0];
}

bool no_args_init(UDF_INIT *initid, UDF_ARGS *args, char *message, const char *name) {
  if (args->arg_count != 0) {
    std::snprintf(message, kInitMsgLen, "%s() takes no arguments", name);
    return true;
  }
  initid->maybe_null = false;
  initid->const_item = false;
  return false;
}

}  // namespace

extern "C" {

/* The do-nothing outer: it takes 1 to 3 arguments, returns the first unchanged,
   and raises nothing. `probe_outer(probe_raise_volatile(?, ?), ?)` is the shape
   `gcm_decrypt(gcm_encrypt(?, ?), ?)` has, reduced to functions that know nothing
   about keys. */
bool probe_outer_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return value_init(initid, args, message, &g_outer, false, "probe_outer");
}
char *probe_outer(UDF_INIT *, UDF_ARGS *args, char *, unsigned long *length, unsigned char *is_null,
                  unsigned char *error) {
  return value_row("probe_outer", args, length, is_null, error, false);
}
void probe_outer_deinit(UDF_INIT *) { g_outer.deinit.fetch_add(1, std::memory_order_relaxed); }

/* The inner that raises on an empty first argument, in the two const_item
   variants. The server evaluates a constant argument while it initialises the
   function that owns it, which is why an empty value here means the parameter had
   no value yet. */
bool probe_raise_const_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return value_init(initid, args, message, &g_raise_const, true, "probe_raise_const");
}
char *probe_raise_const(UDF_INIT *, UDF_ARGS *args, char *, unsigned long *length,
                        unsigned char *is_null, unsigned char *error) {
  return value_row("probe_raise_const", args, length, is_null, error, true);
}
void probe_raise_const_deinit(UDF_INIT *) {
  g_raise_const.deinit.fetch_add(1, std::memory_order_relaxed);
}

bool probe_raise_volatile_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return value_init(initid, args, message, &g_raise_volatile, false, "probe_raise_volatile");
}
char *probe_raise_volatile(UDF_INIT *, UDF_ARGS *args, char *, unsigned long *length,
                           unsigned char *is_null, unsigned char *error) {
  return value_row("probe_raise_volatile", args, length, is_null, error, true);
}
void probe_raise_volatile_deinit(UDF_INIT *) {
  g_raise_volatile.deinit.fetch_add(1, std::memory_order_relaxed);
}

/* What the three functions above have counted since the last probe_reset(). The
   order is fixed, so the line diffs. */
bool probe_counts_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return no_args_init(initid, args, message, "probe_counts");
}
char *probe_counts(UDF_INIT *, UDF_ARGS *, char *, unsigned long *length, unsigned char *is_null,
                   unsigned char *error) {
  static_assert(sizeof(g_json) >= 512);
  const int written = std::snprintf(g_json, sizeof(g_json),
                                    "{\"probe_outer\":{\"init\":%llu,\"deinit\":%llu},"
                                    "\"probe_raise_const\":{\"init\":%llu,\"deinit\":%llu},"
                                    "\"probe_raise_volatile\":{\"init\":%llu,\"deinit\":%llu}}",
                                    g_outer.init.load(std::memory_order_relaxed),
                                    g_outer.deinit.load(std::memory_order_relaxed),
                                    g_raise_const.init.load(std::memory_order_relaxed),
                                    g_raise_const.deinit.load(std::memory_order_relaxed),
                                    g_raise_volatile.init.load(std::memory_order_relaxed),
                                    g_raise_volatile.deinit.load(std::memory_order_relaxed));
  if (written < 0 || static_cast<size_t>(written) >= sizeof(g_json)) {
    *error = 1;
    return nullptr;
  }
  *length = static_cast<unsigned long>(written);
  (void)is_null;
  return g_json;
}
void probe_counts_deinit(UDF_INIT *) {}

/* Zeroes the counters, so a case that prints them does not depend on how many
   times the server was restarted before it ran. */
bool probe_reset_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return no_args_init(initid, args, message, "probe_reset");
}
char *probe_reset(UDF_INIT *, UDF_ARGS *, char *, unsigned long *length, unsigned char *is_null,
                  unsigned char *error) {
  static char kReset[] = "reset";
  g_outer.init = 0;
  g_outer.deinit = 0;
  g_raise_const.init = 0;
  g_raise_const.deinit = 0;
  g_raise_volatile.init = 0;
  g_raise_volatile.deinit = 0;
  *length = sizeof(kReset) - 1;
  (void)is_null;
  (void)error;
  return kReset;
}
void probe_reset_deinit(UDF_INIT *) {}

}  // extern "C"

namespace {

struct UdfSpec {
  const char *name;
  Udf_func_any func;
  Udf_func_init init;
  Udf_func_deinit deinit;
};

const UdfSpec kUdfs[] = {
    {"probe_outer", reinterpret_cast<Udf_func_any>(probe_outer), probe_outer_init,
     probe_outer_deinit},
    {"probe_raise_const", reinterpret_cast<Udf_func_any>(probe_raise_const), probe_raise_const_init,
     probe_raise_const_deinit},
    {"probe_raise_volatile", reinterpret_cast<Udf_func_any>(probe_raise_volatile),
     probe_raise_volatile_init, probe_raise_volatile_deinit},
    {"probe_counts", reinterpret_cast<Udf_func_any>(probe_counts), probe_counts_init,
     probe_counts_deinit},
    {"probe_reset", reinterpret_cast<Udf_func_any>(probe_reset), probe_reset_init,
     probe_reset_deinit},
};

constexpr size_t kUdfCount = sizeof(kUdfs) / sizeof(kUdfs[0]);

mysql_service_status_t probe_component_init() {
  for (size_t i = 0; i < kUdfCount; ++i) {
    const UdfSpec &udf = kUdfs[i];
    if (mysql_service_udf_registration->udf_register(udf.name, STRING_RESULT, udf.func, udf.init,
                                                     udf.deinit)) {
      /* The probe is not shipped and has no resources of its own, but a
         half-registered component is worse than a failed install: the server would
         keep function names pointing into this library and the caller could not
         uninstall them. Roll the first i registrations back, as `component_gcm`
         does. */
      for (size_t j = i; j > 0; --j) {
        int was_present = 0;
        (void)mysql_service_udf_registration->udf_unregister(kUdfs[j - 1].name, &was_present);
      }
      return 1;
    }
  }
  return 0;
}

mysql_service_status_t probe_component_deinit() {
  /* Refuse to unload while a function is still in use, exactly as
     `component_gcm` does: that refusal is the observable this probe exists to
     pin. A registration the server still holds means the unload must fail, or
     the server would keep pointers into a library about to be unmapped. */
  bool refused = false;
  for (size_t i = 0; i < kUdfCount; ++i) {
    int was_present = 0;
    if (mysql_service_udf_registration->udf_unregister(kUdfs[i].name, &was_present) &&
        was_present) {
      refused = true;
    }
  }
  return refused ? 1 : 0;
}

}  // namespace

BEGIN_COMPONENT_PROVIDES(probe)
END_COMPONENT_PROVIDES();

BEGIN_COMPONENT_REQUIRES(probe)
REQUIRES_SERVICE(udf_registration), REQUIRES_SERVICE(mysql_runtime_error), END_COMPONENT_REQUIRES();

BEGIN_COMPONENT_METADATA(probe)
METADATA("mysql.author", "mysql-gcm contributors"), METADATA("mysql.license", "GPL"),
    END_COMPONENT_METADATA();

DECLARE_COMPONENT(probe, "probe")
probe_component_init, probe_component_deinit END_DECLARE_COMPONENT();

DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(probe) END_DECLARE_LIBRARY_COMPONENTS
