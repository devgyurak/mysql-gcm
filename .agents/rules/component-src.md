---
paths:
  - "src/**"
  - "CMakeLists.txt"
---
# Component source rules

- **Components only.** No `mysql_declare_plugin`, no `CREATE FUNCTION ... SONAME`, no
  `#include <mysql/plugin.h>`. Register through the `udf_registration` service and configure through
  `component_sys_variable_register`.
- File responsibilities, dependency direction and resource lifetimes follow
  `.agents/rules/architecture.md`.
- Argument contract: `plaintext`, `ciphertext`, `key` and `aad` are all forced to `STRING_RESULT`
  (`args->arg_type[i] = STRING_RESULT` in init). `key` is checked for `args->lengths[1]` in {32, 24, 16} **on
  every call**, because at init time it need not be a constant; the length selects the suite
  (amendment A10), and the two encryption functions also refuse anything below `gcm.min_key_bytes`.
- `gcm_decrypt`'s result charset: in init, call
  `mysql_service_mysql_udf_metadata->result_set(initid, "charset", "utf8mb4")`. For the plaintext
  argument, use `argument_set(args, "charset", 0, "utf8mb4")` so the server does the conversion. No
  hand-written charset conversion. `gcm_encrypt*` results are `binary`.
- Result buffer: a per-UDF-instance heap buffer on `initid->ptr`, released in `deinit`. For encryption,
  `initid->max_length` is the maximum input plus the envelope overhead (1+12+16); for decryption, the
  input envelope length is the upper bound. Size arithmetic follows the architecture rule.
- A new service dependency is added to both `REQUIRES_SERVICE_PLACEHOLDER` and
  `BEGIN_COMPONENT_REQUIRES`, and the minimum MySQL version that introduced it is recorded in the
  `docs/design.md` §8 table.
- A failed `init()` rolls back and returns 1. If `deinit()` cannot unregister a UDF that is in use, it
  leaves the resources alone and reports the failure. Partially successful states and retries follow
  the architecture rule.
- Compiled with `-std=c++17 -Wall -Wextra -Werror -fno-exceptions`, the server tree's defaults. Nothing
  throws; errors are return values.
- The build is in-tree in a server source tree (`MYSQL_ADD_COMPONENT`). Standalone CMake exists only
  for `tests/unit`.
- Each function's SQL behaviour (NULL arguments, the empty string, maximum length, with and without
  AAD, a wrong key length) is verified in both `mysql-test/suite/gcm` and `tests/integration`.
