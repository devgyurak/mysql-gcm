/* SPDX-License-Identifier: GPL-2.0-only */
#include "sysvar.h"

#include "envelope.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/bits/system_variables_bits.h>
#include <mysql/components/services/component_sys_var_service.h>
#if GCM_HAS_SESSION_SYSVAR
#include <mysql/components/services/mysql_current_thread_reader.h>
#include <mysql/components/services/mysql_system_variable.h>
#endif

extern REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_register);
extern REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_unregister);
#if GCM_HAS_SESSION_SYSVAR
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_system_variable_reader);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);
#endif

namespace gcm {
namespace {

constexpr const char *kComponent = "gcm";
constexpr const char *kStrict = "strict";
constexpr const char *kMinKeyBytes = "min_key_bytes";

/* Both read paths get the SHOW representation of a bool — "ON" or "OFF", not a bool,
   because sql/sql_plugin_var.cc maps PLUGIN_VAR_BOOL to SHOW_MY_BOOL and
   sql/sql_show.cc renders that with my_stpcpy(buff, value ? "ON" : "OFF").

   Only an explicit OFF turns strict off. Anything else — a truncated buffer, an
   unexpected spelling, a future server that renders it differently — leaves strict on,
   because the failure this variable controls is "return NULL instead of raising on a
   tag mismatch" and guessing wrong in that direction hides a forgery. */
bool reads_as_off(const char *value, size_t len) {
  /* `len == 3`, not `len >= 3`: a prefix match would read "OFFLINE" — or a future
     "OFF (deprecated)" — as off, which is the one direction this function must never
     get wrong. Unreachable against today's servers, and that is exactly the situation
     the function exists for. */
  return value != nullptr && len == 3 && std::strncmp(value, "OFF", 3) == 0;
}

/* Storage the registration hands to the server. On 8.0/8.4 a GLOBAL-only variable
   makes update_func_bool() in sql/sql_plugin_var.cc assign straight into this byte; on
   9.x the value lives in per-THD storage and this only supplies the initial default.

   Never read by this component on any version — strict_enabled() goes through a
   service that holds the same mutex as the server's write. It exists because
   register_variable requires somewhere to put the value. */
bool g_strict = true;

/* Storage for gcm.min_key_bytes. Not read by this component either — see
   min_key_bytes() for why the value goes through the service instead. */
int g_min_key_bytes = static_cast<int>(kKeyLen256);

/* Which of the two are registered right now. The server fails an unregister of a
   variable it does not have, so attempting one unconditionally turns a retry into
   a permanent failure: UNINSTALL removes gcm.strict, the floor refuses, the
   component stays loaded, and every later UNINSTALL then fails on the strict that
   is already gone. Tracking the state is what makes a refused uninstall retryable
   (architecture rule §3: "track which releases succeeded so a retry does not
   double-free"). */
bool g_strict_registered = false;
bool g_floor_registered = false;

/* Unregisters one variable if it is registered, and clears its flag on success.
   Returns true on failure, the MySQL convention. A variable that is not
   registered is already in the wanted state, so that is success, not a call. */
bool drop(const char *name, bool *registered) {
  if (!*registered) return false;
  if (mysql_service_component_sys_variable_unregister->unregister_variable(kComponent, name)) {
    return true;
  }
  *registered = false;
  return false;
}

/* Parses the SHOW representation of an integer sysvar. Returns false when the
   buffer is not a plain decimal number that fits the registered range, which the
   caller turns into the strictest answer rather than a guess. */
bool parse_int(const char *value, size_t len, long *out) {
  if (value == nullptr || len == 0 || len >= 16) return false;
  char buf[16];
  std::memcpy(buf, value, len);
  buf[len] = '\0';
  char *end = nullptr;
  errno = 0;
  const long parsed = std::strtol(buf, &end, 10);
  if (errno != 0 || end != buf + len) return false;
  *out = parsed;
  return true;
}

bool register_strict() {
  /* A stack local is correct here: register_variable copies the field rather than
     keeping the pointer — sql/server_component/component_sys_var_service.cc does
     `sysvar_bool->def_val = bool_arg->def_val` into a my_malloc'd struct. */
  BOOL_CHECK_ARG(bool) arg;
  arg.def_val = true;  // spec/envelope.md §4: strict is ON unless asked otherwise

  int flags = PLUGIN_VAR_BOOL;
#if GCM_HAS_SESSION_SYSVAR
  flags |= PLUGIN_VAR_THDLOCAL;  // 9.0.0+ only — see sysvar.h
#endif

  const bool failed = mysql_service_component_sys_variable_register->register_variable(
      kComponent, kStrict, flags,
      "Raise an error (ON, default) or return NULL (OFF) when GCM tag "
      "verification fails. Malformed envelopes and wrong key lengths are "
      "always errors.",
      nullptr /* check */, nullptr /* update */, static_cast<void *>(&arg),
      static_cast<void *>(&g_strict));
  if (!failed) g_strict_registered = true;
  return failed;
}

bool register_min_key_bytes() {
  /* GLOBAL-only on every version, deliberately, and not for the A5 reason.
     design A10 asks whether this is an administrator policy or a mistake guard:
     GLOBAL-only makes it the former, because a session cannot lower the floor
     its administrator set. A session-scoped floor would be a setting a caller
     could turn off for itself, which is not a policy. */
  INTEGRAL_CHECK_ARG(int) arg;
  arg.def_val = static_cast<int>(kKeyLen256);  // design A10: the feature is opt-in
  arg.min_val = static_cast<int>(kKeyLen128);
  arg.max_val = static_cast<int>(kKeyLen256);
  arg.blk_sz = 0;

  const bool failed = mysql_service_component_sys_variable_register->register_variable(
      kComponent, kMinKeyBytes, PLUGIN_VAR_INT,
      "Smallest key, in bytes, that gcm_encrypt and gcm_encrypt_det will accept "
      "(32 = AES-256 only, the default; 16 also allows AES-128). Decryption is "
      "not affected, so lowering and then raising this never locks out data.",
      nullptr /* check */, nullptr /* update */, static_cast<void *>(&arg),
      static_cast<void *>(&g_min_key_bytes));
  if (!failed) g_floor_registered = true;
  return failed;
}
}  // namespace

bool sysvar_register(bool *fully_rolled_back) {
  *fully_rolled_back = true;
  if (register_strict()) return true;
  if (register_min_key_bytes()) {
    /* Roll the first one back. Leaving gcm.strict registered while reporting
       failure would put a variable in the dictionary of a component the loader
       is about to unmap, which is exactly the exposure A9 orders against — and
       a variable is reachable by enumeration, so nobody has to name it.

       The result is reported rather than discarded. If the server refuses, a
       variable pointing at this component's storage survives, and the caller
       must keep the crypto handles alive for the same reason deinit does.
       Discarding it here was a real defect, caught by
       GivenTheFloorFailsAndStrictWillNotUnregister_WhenInit_ThenAlgorithmsAreKept
       — the same shape as the discarded result that issue #7 was opened for. */
    *fully_rolled_back = !drop(kStrict, &g_strict_registered);
    return true;
  }
  return false;
}

bool sysvar_unregister() {
  /* The floor comes out first so that a refusal leaves the pair in a state a
     retry can act on. If the floor refuses, nothing has been removed yet and the
     component is exactly as it was. If it succeeds and strict then refuses, the
     floor is re-registered before returning, so the component that stays loaded
     keeps both variables and the next UNINSTALL starts from the same place this
     one did.

     Each call is guarded by the state flag, because the server fails an
     unregister of a variable it does not have — attempting one unconditionally
     is what would turn a single refusal into a component that can never be
     uninstalled. */
  if (drop(kMinKeyBytes, &g_floor_registered)) return true;
  if (drop(kStrict, &g_strict_registered)) {
    /* Put the floor back. A component that survives a refused UNINSTALL must be
       whole: leaving it without its floor would mean gcm.min_key_bytes silently
       stops existing while the functions still run, and min_key_bytes() would
       then fail closed to 32 for every statement — a configuration the operator
       set, quietly discarded. If this re-registration also fails the component is
       loaded and incomplete until a restart, which is the same unrecoverable
       corner gcm_component_deinit documents for the functions. */
    (void)register_min_key_bytes();
    return true;
  }
  return false;
}

size_t min_key_bytes() {
  /* GLOBAL on every version (design A10), so the scope is never in question —
     unlike strict_enabled(), the branch below is about which service may be
     called, not about which value is correct.

     Read through a service rather than from g_min_key_bytes: the server assigns
     into that storage under LOCK_global_system_variables and loading it directly
     is a data race, the same reasoning sysvar.h gives for strict.

     Any failure returns the strictest floor. For this variable "fail closed"
     means refusing the weaker suites, so a lost setting can never widen what the
     server accepts. */
  char buf[32] = {0};
  void *value = buf;
  size_t len = sizeof(buf) - 1;

#if GCM_HAS_SESSION_SYSVAR
  /* 9.0+ deprecates get_variable() in favour of the reader, and -Werror makes
     that a build failure rather than a warning. "GLOBAL" is explicit here
     because that is the only scope this variable has. */
  MYSQL_THD thd = nullptr;
  if (mysql_service_mysql_current_thread_reader->get(&thd) || thd == nullptr) return kKeyLen256;
  if (mysql_service_mysql_system_variable_reader->get(thd, "GLOBAL", kComponent, kMinKeyBytes,
                                                      &value, &len)) {
    return kKeyLen256;
  }
#else
  if (mysql_service_component_sys_variable_register->get_variable(kComponent, kMinKeyBytes, &value,
                                                                  &len)) {
    return kKeyLen256;
  }
#endif

  long parsed = 0;
  if (!parse_int(static_cast<const char *>(value), len, &parsed)) return kKeyLen256;
  if (parsed < static_cast<long>(kKeyLen128) || parsed > static_cast<long>(kKeyLen256)) {
    return kKeyLen256;
  }
  return static_cast<size_t>(parsed);
}

#if GCM_HAS_SESSION_SYSVAR

bool strict_enabled() {
  MYSQL_THD thd = nullptr;
  if (mysql_service_mysql_current_thread_reader->get(&thd) || thd == nullptr) return true;

  char buf[32] = {0};
  void *value = buf;
  size_t len = sizeof(buf) - 1;
  if (mysql_service_mysql_system_variable_reader->get(thd, "SESSION", kComponent, kStrict, &value,
                                                      &len)) {
    return true;  // fail closed
  }
  return !reads_as_off(static_cast<const char *>(value), len);
}

#else

bool strict_enabled() {
  /* 8.0/8.4: GLOBAL only (design A5). SET SESSION gcm.strict is rejected by the
     server with ER_INCORRECT_GLOBAL_LOCAL_VAR.

     Read through the service, not from g_strict. The server assigns into that byte
     from update_func_bool() while holding LOCK_global_system_variables
     (sql/sql_plugin_var.cc), and get_variable() takes the same mutex to read it
     (sql/server_component/component_sys_var_service.cc, which asserts the owner on
     the way through sys_var::value_ptr). Loading the byte directly was a data race:
     a torn read of one aligned byte is not a thing that happens on any machine this
     runs on, but "unlikely in practice" is not the standard's position and a
     sanitizer build is right to say so.

     get_variable() has been on this service since 8.0.11, so this costs no new
     dependency, and it is called once per UDF_INIT — per statement, not per row
     (architecture rule §5). That is a structural statement, not a measurement: the
     bench suite covers the server-independent core only, so nothing here times a
     mutex acquisition. A prepared statement or a stored routine pays it per execution.

     The two branches stay separate rather than being unified on this call: 9.x
     deprecates get_variable() in favour of the reader, and more importantly
     get_variable() returns the GLOBAL value on every version, which would silently
     ignore SET SESSION on the one major where that works. */
  char buf[32] = {0};
  void *value = buf;
  size_t len = sizeof(buf) - 1;
  if (mysql_service_component_sys_variable_register->get_variable(kComponent, kStrict, &value,
                                                                  &len)) {
    return true;  // fail closed
  }
  return !reads_as_off(static_cast<const char *>(value), len);
}

#endif

}  // namespace gcm
