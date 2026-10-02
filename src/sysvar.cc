/* SPDX-License-Identifier: GPL-2.0-only */
#include "sysvar.h"

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

}  // namespace

bool sysvar_register() {
  /* A stack local is correct here: register_variable copies the field rather than
     keeping the pointer — sql/server_component/component_sys_var_service.cc does
     `sysvar_bool->def_val = bool_arg->def_val` into a my_malloc'd struct. */
  BOOL_CHECK_ARG(bool) arg;
  arg.def_val = true;  // spec/envelope.md §4: strict is ON unless asked otherwise

  int flags = PLUGIN_VAR_BOOL;
#if GCM_HAS_SESSION_SYSVAR
  flags |= PLUGIN_VAR_THDLOCAL;  // 9.0.0+ only — see sysvar.h
#endif

  return mysql_service_component_sys_variable_register->register_variable(
      kComponent, kStrict, flags,
      "Raise an error (ON, default) or return NULL (OFF) when GCM tag "
      "verification fails. Malformed envelopes and wrong key lengths are "
      "always errors.",
      nullptr /* check */, nullptr /* update */, static_cast<void *>(&arg),
      static_cast<void *>(&g_strict));
}

bool sysvar_unregister() {
  return mysql_service_component_sys_variable_unregister->unregister_variable(kComponent, kStrict);
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
