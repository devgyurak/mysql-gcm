---
name: mysql-component
description: Writing the MySQL 8.0+ component skeleton, registering UDFs, charset tagging and the in-tree build procedure. Use it when creating or changing component.cc / udf_*.cc / CMakeLists.txt, or when the service macros are confusing.
---

# mysql-component

Goal: register `gcm_encrypt` / `gcm_encrypt_det` / `gcm_decrypt` as a **component** rather than a
legacy plugin, and build it inside a server source tree.

## Procedure
1. Read `docs/design.md` §2 (amendment A1) and §5.1, and `.agents/rules/component-src.md`.
2. If anything about a service API is even slightly uncertain, open
   `$MYSQL_SRC/include/mysql/components/services/*.h` and confirm it (the `component-api-researcher`
   subagent). No guessing.
3. Fill in the skeleton below. The pure logic is only *called* from here — it lives in `gcm.cc`,
   `envelope.cc` and `nonce.cc` under the `gcm-crypto` skill.
4. Build with `scripts/build-in-docker.sh <ver>`, then install and verify with the `dev-container`
   skill.

## Services needed (all under `include/mysql/components/services/`)
| Service | Header | Purpose | Minimum version |
|---|---|---|---|
| `udf_registration` | `udf_registration.h` | Registering and unregistering UDFs | 8.0.0 (WL#8020) |
| `mysql_udf_metadata` | `udf_metadata.h` | Setting the result and argument charset | 8.0.19 (WL#12370) |
| `component_sys_variable_register` / `_unregister` | `component_sys_var_service.h` | `gcm.strict` | 8.0.0 |
| `mysql_runtime_error` | `mysql_runtime_error.h` | Replaces `my_error`; the tag-failure error | 8.0.x |

## Skeleton — `src/component.cc`
```cpp
#include <mysql/components/component_implementation.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/components/services/udf_metadata.h>
#include <mysql/components/services/component_sys_var_service.h>
#include <mysql/components/services/mysql_runtime_error.h>

REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
REQUIRES_SERVICE_PLACEHOLDER(mysql_udf_metadata);
REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_register);
REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_unregister);
REQUIRES_SERVICE_PLACEHOLDER(mysql_runtime_error);

struct UdfSpec { const char *name; Item_result type; Udf_func_any fn; Udf_func_init init; Udf_func_deinit deinit; };
static const UdfSpec kUdfs[] = { /* gcm_encrypt, gcm_encrypt_det, gcm_decrypt */ };

static mysql_service_status_t gcm_init() {
  if (gcm::crypto_init())  return 1;          // EVP_CIPHER_fetch / EVP_MAC_fetch; 1 on failure
  size_t done = 0;
  for (auto &u : kUdfs) {
    if (mysql_service_udf_registration->udf_register(u.name, u.type, u.fn, u.init, u.deinit)) {
      for (size_t i = 0; i < done; ++i) { int was_present = 0; mysql_service_udf_registration->udf_unregister(kUdfs[i].name, &was_present); }
      gcm::crypto_deinit(); return 1;   // never report success in a half-registered state
    }
    ++done;
  }
  if (gcm::sysvar_register()) { /* roll the UDFs back */ gcm::crypto_deinit(); return 1; }
  return 0;
}
static mysql_service_status_t gcm_deinit() {
  for (auto &u : kUdfs) { int was_present = 0;
    if (mysql_service_udf_registration->udf_unregister(u.name, &was_present) && was_present) return 1; } // in use: fail
  gcm::sysvar_unregister(); gcm::crypto_deinit(); return 0;
}

BEGIN_COMPONENT_PROVIDES(component_gcm)
END_COMPONENT_PROVIDES();

BEGIN_COMPONENT_REQUIRES(component_gcm)
  REQUIRES_SERVICE(udf_registration),
  REQUIRES_SERVICE(mysql_udf_metadata),
  REQUIRES_SERVICE(component_sys_variable_register),
  REQUIRES_SERVICE(component_sys_variable_unregister),
  REQUIRES_SERVICE(mysql_runtime_error),
END_COMPONENT_REQUIRES();

BEGIN_COMPONENT_METADATA(component_gcm)
  METADATA("mysql.author", "mysql-gcm contributors"),
  METADATA("mysql.license", "GPL"),
END_COMPONENT_METADATA();

DECLARE_COMPONENT(component_gcm, "mysql:component_gcm")
  gcm_init, gcm_deinit
END_DECLARE_COMPONENT();

DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(component_gcm) END_DECLARE_LIBRARY_COMPONENTS
```

**The variable is registered after the functions**, and `deinit` also takes it last — see
`docs/design.md` amendment A9 for why, and `tests/adapter` for the cases that pin the order.

## UDF glue — the shape of `src/udf_decrypt.cc`
```cpp
extern "C" bool gcm_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count < 2 || args->arg_count > 3) { strcpy(msg, "gcm_decrypt(ciphertext, key [, aad])"); return true; }
  for (unsigned i = 0; i < args->arg_count; ++i) args->arg_type[i] = STRING_RESULT;
  if (mysql_service_mysql_udf_metadata->result_set(initid, "charset", const_cast<char *>("utf8mb4"))) { strcpy(msg, "cannot set result charset"); return true; }
  initid->maybe_null = true;                       // the strict=OFF path
  initid->max_length = args->lengths[0];           // plaintext <= envelope
  initid->ptr = static_cast<char *>(malloc(initid->max_length + 1));
  return initid->ptr == nullptr;
}
extern "C" char *gcm_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length, unsigned char *is_null, unsigned char *error) {
  if (!args->args[0] || !args->args[1]) { *is_null = 1; return nullptr; }          // NULL propagation
  if (args->lengths[1] != gcm::kKeyLen) { gcm::raise(GcmError::bad_key_len); *error = 1; return nullptr; }
  // ... call gcm::open(...); on bad_tag either raise or set is_null, according to the strict sysvar
}
extern "C" void gcm_decrypt_deinit(UDF_INIT *initid) { free(initid->ptr); }
```
- `gcm_encrypt*` uses `result_set(initid, "charset", "binary")` and
  `max_length = lengths[0] + 1 + 12 + 16`.
- Request the plaintext argument's charset with `argument_set(args, "charset", 0, "utf8mb4")` so the
  server does the conversion.

## Build (in-tree)
`CONFIGURE_COMPONENTS()` in `cmake/component.cmake` globs `components/*` **at configure time**, so the
sources have to sit in `$MYSQL_SRC/components/gcm` and **cmake has to be re-run** for them to enter the
build graph. That is why it is a copy plus a re-configure rather than a symlink into a read-only mount
(`docker/build-component.sh`).

`MYSQL_ADD_COMPONENT(gcm ...)` produces the target `component_gcm` with `PREFIX ""` and
`OUTPUT_NAME component_gcm`, i.e. `plugin_output_directory/component_gcm.so`.

```cmake
# OpenSSL is exposed differently per version: 8.4 and 9.x give an imported target,
# 8.0 (WITH_SSL=system) gives ${SSL_LIBRARIES}
if(TARGET OpenSSL::Crypto)
  set(GCM_CRYPTO_LIBRARIES OpenSSL::Crypto)
else()
  set(GCM_CRYPTO_LIBRARIES ${SSL_LIBRARIES})
endif()

MYSQL_ADD_COMPONENT(gcm
  component.cc udf_encrypt.cc udf_decrypt.cc udf_glue.cc sysvar.cc gcm.cc envelope.cc nonce.cc
  MODULE_ONLY
  LINK_LIBRARIES ${GCM_CRYPTO_LIBRARIES}   # the same libcrypto the server uses — no static link, no bundle
)
```
```sh
scripts/build-in-docker.sh 8.4        # output: build/8.4/component_gcm.so
```
Build `--target component_gcm` only, not the whole server (GenError, mysys and strings come along as
dependencies).

**boost and the compiler differ per version (measured).**

| | 8.0.43 | 8.4.11 | 9.4.0 |
|---|---|---|---|
| boost | needs external 1.77 → `mysql-boost-<ver>.tar.gz` + `-DWITH_BOOST=<src>/boost` | bundled in `extra/boost`, no flag | same |
| RHEL9 compiler (`ALTERNATIVE_PATHS`) | gcc-toolset-12 | gcc-toolset-12 | gcc-toolset-14 |

`-DDOWNLOAD_BOOST` does not exist in 8.4 or 9.x. Install the wrong toolset and configure fails with
"Could not find devtoolset compiler/linker"; without `readelf` you get a separate error (`binutils`
and `elfutils` are required).

## Reporting errors
There is no component-specific error code. Raise `ER_UDF_ERROR` ("%s UDF failed; %s") through
`mysql_error_service_printf(ER_UDF_ERROR, 0, func_name, detail)` (`mysqld_error.h` plus
`mysql_runtime_error_service.h`) and set `*error = 1` in the row function. The client sees
`ERROR 3200 (HY000)`. `detail` carries lengths and the version byte and nothing more — no key,
plaintext, nonce, tag or ciphertext (`spec/envelope.md` §4 rule 4).

## Common failures
- `INSTALL COMPONENT` says "Cannot satisfy dependency" → a service in the REQUIRES list does not exist
  on that server version. The two session-sysvar services are 9.0+ only (the `sysvar-config` skill,
  amendment A5). Check the `docs/design.md` §8 table.
- The `.so` loads but the functions are missing → a `udf_register` return value was discarded. Check
  the rollback path in the init skeleton.
- Korean `LIKE` returns 0 → `result_set("charset")` was not called in init, or it was set to `binary`.
- The server crashes → a shared global buffer, or a missing `deinit`. Reproduce with an ASan build.
- `docker cp` says "Could not find the file /usr/lib/mysql/plugin" → `plugin_dir` differs per image
  (the OL-based official images use `/usr/lib64/mysql/plugin/`). Ask with `SELECT @@plugin_dir`.
- An integration test that passes a computed SQL expression as an argument returns the wrong plaintext
  from the second row onwards → that is a server defect (amendment A7). Switch to a column, a literal
  or a bind parameter. Do not try to fix it in the component.
- `#error This header shall not be included in components` → a server-internal header such as
  `mysql_com.h` or `my_io.h` was included. If you need a constant from one, such as
  `MYSQL_ERRMSG_SIZE`, duplicate the value and leave the reasoning in a comment.
  **8.0 and 8.4 pass silently and only 9.x fails, so this is caught only by building all three.**
- A truncated result, or `ERROR 1406 Data too long` → `initid->max_length` is too small, for one of two
  reasons.
  ① **`args->lengths[i]` is the length *before* charset conversion.** Request utf8mb4 for the plaintext
  argument and the server widens the value before handing it over, so a latin1 `VARCHAR(1)` arrives
  with `lengths[0]=1` while the envelope is 31 bytes. Under a non-strict SQL mode it is **silently
  truncated on store and decryption then fails**. Use the fact that every charset is at least one byte
  per character and bound it at `4 × lengths[0]`.
  ② Wraparound. The server clamps with `min<uint32>(initid.max_length, MAX_BLOB_WIDTH)`, **truncating
  to uint32 first** (`udf_handler::fix_fields` in `sql/item_func.cc`). Saturate the addition
  (`envelope_max_length()` in `udf_glue.h`).
- The deterministic functions need `initid->const_item = true` for a constant-argument lookup to use an
  index (measured: `type=const`). Never set it true for the random function.
