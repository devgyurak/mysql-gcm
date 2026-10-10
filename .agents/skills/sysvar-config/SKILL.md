---
name: sysvar-config
description: Registering the component sysvar (gcm.strict), reading the session scope, and the my.cnf integration with the loose_ prefix. Use it when writing sysvar.cc or when SET SESSION / GLOBAL does not behave.
---

# sysvar-config

## Surface
| sysvar | Type | Scope | Default |
|---|---|---|---|
| `gcm.strict` | BOOL | MySQL 9.0+ GLOBAL + SESSION / 8.0 and 8.4 GLOBAL only | ON |

**The scope is not a choice (amendment A5, confirmed by measurement).** The session scope for a
component sysvar is only implemented from 9.0.0. `PLUGIN_VAR_THDLOCAL` appears in
`sql/server_component/component_sys_var_service.cc` zero times in 8.0.43 and 8.4.11, and eleven times
in 9.4.0. Pass THDLOCAL on 8.x and registration succeeds, but reading the value interprets the address
of a global as an offset into session storage — an **out-of-bounds read**. Do not pass it.

my.cnf: `loose_gcm.strict = ON`. Without `loose_`, a startup before the component is installed fails
with "unknown variable" (design §6).

## Registration — `src/sysvar.cc`
```cpp
#include <mysql_version.h>
#define GCM_HAS_SESSION_SYSVAR (MYSQL_VERSION_ID >= 90000)   // amendment A5

bool gcm::sysvar_register() {                 // MySQL convention: true = failure
  BOOL_CHECK_ARG(bool) arg; arg.def_val = true;
  int flags = PLUGIN_VAR_BOOL;
#if GCM_HAS_SESSION_SYSVAR
  flags |= PLUGIN_VAR_THDLOCAL;               // 9.0+ only
#endif
  return mysql_service_component_sys_variable_register->register_variable(
      "gcm", "strict", flags,
      "Raise an error (ON, default) or return NULL (OFF) when GCM tag verification fails",
      nullptr /*check*/, nullptr /*update*/, (void *)&arg, (void *)&g_strict);
}
```
`g_strict` is a global `bool`. Registered without THDLOCAL, the server's default update function
(`update_func_bool` in `sql/sql_plugin_var.cc`) writes straight into that global. On 9.x the value
lives in session storage, so the global only supplies the default.

**Register the variable after the functions**, and unregister it last in deinit
(`docs/design.md` amendment A9).

## Reading the value (**once in UDF init** — never per row)
`component_sys_variable_register::get_variable` is **GLOBAL only** — both the header comment and the
implementation say so (`OPT_GLOBAL` is hardcoded). It cannot read a session value. The
`mysql_system_variable_reader` added in 9.0.0 is the only way, and the THD comes from
`mysql_current_thread_reader`.

```cpp
#if GCM_HAS_SESSION_SYSVAR
bool gcm::strict_enabled() {
  MYSQL_THD thd = nullptr;
  if (mysql_service_mysql_current_thread_reader->get(&thd) || thd == nullptr) return true;  // fail closed
  char buf[32] = {0}; void *value = buf; size_t len = sizeof(buf) - 1;
  if (mysql_service_mysql_system_variable_reader->get(thd, "SESSION", "gcm", "strict", &value, &len))
    return true;  // fail closed
  return !reads_as_off(static_cast<const char *>(value), len);
}
#else
bool gcm::strict_enabled() {                  // 8.0/8.4: the GLOBAL value
  char buf[32] = {0}; void *value = buf; size_t len = sizeof(buf) - 1;
  if (mysql_service_component_sys_variable_register->get_variable("gcm", "strict", &value, &len))
    return true;  // fail closed
  return !reads_as_off(static_cast<const char *>(value), len);
}
#endif

bool reads_as_off(const char *value, size_t len) {
  // len == 3, not len >= 3: a prefix match would read "OFFLINE" as off, and this is the
  // one direction the function must never get wrong.
  return value != nullptr && len == 3 && std::strncmp(value, "OFF", 3) == 0;
}
```
- A bool comes back as its **SHOW representation**, the string "ON" or "OFF", because
  `sql/sql_plugin_var.cc` maps `PLUGIN_VAR_BOOL` to `SHOW_MY_BOOL` and `sql/sql_show.cc` renders that
  with `my_stpcpy(buff, value ? "ON" : "OFF")`. Only an explicit OFF turns strict off.
- **Do not read `g_strict` directly on 8.0/8.4.** The server assigns into that byte from
  `update_func_bool()` while holding `LOCK_global_system_variables`, and `get_variable()` takes the
  same mutex to read it, asserting ownership on the way through `sys_var::value_ptr`. Loading the byte
  directly is a data race, and `std::atomic<bool>` does not fix it — the store the server performs
  through that pointer is not atomic. `get_variable()` has been on this service since 8.0.11, so this
  costs no new dependency.
- The two branches stay separate rather than being unified on `get_variable()`: 9.x deprecates it in
  favour of the reader, and more importantly it returns the GLOBAL value on every version, which would
  silently ignore `SET SESSION` on the one major where that works.
- The reader goes through a `LOCK_system_variables_hash` read lock, a hash lookup and a string
  conversion. **Do not call it per row** — read it once in `Udf_func_init` and cache it on
  `UDF_INIT::ptr`. `SET SESSION` only takes effect at a statement boundary, so the semantics are exact
  too.
- `REQUIRES_SERVICE` is a hard dependency. On an 8.x build the reader and thread_reader have to be
  `#if`'d out of the REQUIRES list, or `INSTALL COMPONENT` fails with a dependency error.
- Reference implementations: `components/test/test_session_var_service.cc` in the 9.x tree, and
  `mysql-test/suite/service_sys_var_registration`.

## Verification (it goes into the integration tests as-is, GWT)
The result differs per version, so `tests/integration/31_strict_scope.sql` is marked
`per-major-expected` with a `31_strict_scope.<major>.expected` for each.

```sql
--echo # Given: a tampered envelope and gcm.strict at its default
SET @k = UNHEX('0001...1f');
SET @good = gcm_encrypt_det('홍길동', @k);
SET @bad = CONCAT(LEFT(@good, LENGTH(@good)-1), UNHEX('FF'));
--echo # When: strict is turned off at both scopes
SET GLOBAL gcm.strict = OFF;    -- takes effect in this session on 8.0/8.4
SET SESSION gcm.strict = OFF;   -- ER_INCORRECT_GLOBAL_LOCAL_VAR on 8.0/8.4, succeeds on 9.x
SELECT gcm_decrypt(@bad, @k) IS NULL AS null_when_strict_off;   -- 1 on every version
--echo # Then: 1 on every major, through whichever scope that major supports
```

Confirmed by measurement (8.0.43 · 8.4.11 · 9.4.0):

| | 8.0 / 8.4 | 9.x |
|---|---|---|
| `SET SESSION gcm.strict` | `ER_INCORRECT_GLOBAL_LOCAL_VAR` (1229) | succeeds |
| `@@SESSION.gcm.strict` | `ER_INCORRECT_GLOBAL_LOCAL_VAR` (1238) | returns the value |
| Effect of `SET GLOBAL` on the current session | immediate | none (the session holds its own value) |
