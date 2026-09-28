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

/* Storage the server writes into, and the value we read, on 8.0/8.4: with a
   GLOBAL-only registration update_func_bool() in sql/sql_plugin_var.cc assigns
   straight into this. On 9.x the value lives in per-THD storage instead and this
   only supplies the initial default. */
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

  /* The reader hands back the SHOW representation of a bool, i.e. "ON"/"OFF",
     not a bool (sql/sql_plugin_var.cc maps it to SHOW_MY_BOOL). */
  char buf[32] = {0};
  char *value = buf;
  size_t len = sizeof(buf) - 1;
  if (mysql_service_mysql_system_variable_reader->get(thd, "SESSION", kComponent, kStrict,
                                                      reinterpret_cast<void **>(&value), &len)) {
    return true;
  }
  /* Only an explicit OFF turns strict off; anything unexpected stays strict. */
  return !(value != nullptr && len >= 3 && std::strncmp(value, "OFF", 3) == 0);
}

#else

bool strict_enabled() {
  /* 8.0/8.4: GLOBAL only (design A5). SET SESSION gcm.strict is rejected by the
     server with ER_INCORRECT_GLOBAL_LOCAL_VAR.

     Read without synchronisation on purpose. The server writes this single byte
     under LOCK_global_system_variables while we read it once per statement, so the
     read cannot tear: it observes the value from before or after a concurrent SET
     GLOBAL, and both are valid answers for a statement that raced the change. */
  return g_strict;
}

#endif

}  // namespace gcm
