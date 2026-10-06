---
paths:
  - "src/**"
  - "tests/**"
  - "mysql-test/**"
  - "spec/**"
  - "docs/design.md"
  - "**/CMakeLists.txt"
  - "scripts/check-architecture.py"
  - ".github/**"
---
# Architecture — responsibilities, dependency direction, resource lifetimes

The rationale is `docs/design.md` amendment A6. For MySQL API usage follow `component-src.md`, for
crypto safety `crypto-safety.md`, and for how to write tests `testing.md`.

## 1. Module responsibilities and dependency direction

| Module | Responsibility | Project dependencies allowed |
|---|---|---|
| `component.cc` | Service declarations, UDF registration and unregistration, coordinating init and deinit | The UDF entry points, `sysvar`, core init/deinit |
| `udf_*.cc`, `udf_glue.h` | SQL arguments, NULL, charset, the result buffer, error translation | `gcm`, `sysvar`, the shared byte and error types |
| `sysvar.{h,cc}` | Registering and reading server configuration, per-version service differences | MySQL services |
| `gcm.{h,cc}` | The encryption and decryption construction, the authentication result, crypto resource init/deinit | `envelope`, `nonce`, OpenSSL |
| `nonce.{h,cc}` | Domain separation and nonce derivation | The shared byte and error types, OpenSSL |
| `envelope.{h,cc}` | Version, length, offset and field parsing; the shared types | The C++ standard library |

- The core (`gcm`, `envelope`, `nonce`) must stay independent of the server. No direct or indirect
  dependency on MySQL headers, services, version macros, UDF types or sysvars, and no reference back
  into an adapter.
- `envelope` does not depend on OpenSSL either. Do not duplicate envelope byte interpretation into a
  UDF.
- Do not call the whole core "pure functions" — it uses randomness and OpenSSL state. The boundary is
  that it builds and tests without a server.
- When you add a file, decide its responsibility and its allowed dependencies first. Do not add a
  general backend or factory layer for a hypothetical future algorithm or store without a real
  requirement and a design amendment.

## 2. Byte formats and SQL semantics

- The core exchanges bytes and an `Error`. SQL NULL, charset, server error messages and `gcm.strict`
  are not passed into the core.
- On an authentication failure the core cleanses the output and returns `bad_tag`. Only the UDF layer
  chooses error-or-NULL according to strict. A key length or envelope error is never hidden by strict.
- Independently of the SQL argument validation, the core validates its own key-length and envelope
  preconditions. A direct call from a test must not depend on the UDF's validation.
- A change to the public SQL functions or the envelope flows `docs/design.md` → `spec/` →
  implementation and tests, in that order. An internal test function is never grounds for extending the
  public API.

## 3. Ownership and lifetimes

| Lifetime | Resource and responsibility |
|---|---|
| component | The fetched algorithm handles, the sysvar storage, the registration state. Prepared in init and released in a safe deinit |
| `UDF_INIT` | That UDF instance's result buffer and strict snapshot. Managed by init/deinit and not equated with a whole session |
| operation | The EVP operation context, derived keys, transient secrets. Cleaned up when the operation ends and on every error path |

- Input bytes are borrowed from a buffer the caller owns. Do not retain a pointer beyond that
  ownership. Cleansing a copied secret is the responsibility of whoever made the copy.
- Do not share keys, plaintext, per-row results or operation contexts in globals. Any component-level
  global state must have a stated lifetime and a stated synchronisation responsibility.
- For each new resource, define where it is acquired, where it is released, and who cleans up on
  failure. A failed initialisation rolls back partial registrations.
- If the component survives because a release failed, keep the resources that are in use. Track which
  releases succeeded so that a retry does not double-free.

## 4. The server compatibility boundary

- `MYSQL_VERSION_ID` checks and branches on service availability live only in the server adapters. For
  a new service, record the minimum supported version and the behaviour on versions without it in the
  design document.
- Follow amendment A5 for the strict scope and the read-failure policy. A version difference never
  changes the authentication policy or the envelope bytes.

## 5. Per-row cost

- Fetch algorithms in component init and read strict in UDF init. Do not read configuration, fetch, or
  touch a file or the network repeatedly in a per-row callback.
- The result buffer is reused by the UDF instance. Size arithmetic checks the upper bound, addition
  overflow and the range of OpenSSL's integer arguments, and translates a failure into a SQL error.
- No optimisation omits authentication, the key length check or the cleansing of secrets. A change in
  per-row cost is confirmed with the load tests.

## 6. Test boundaries and verification

- `encrypt_with_nonce` is an internal entry point for the vector tests. Do not reference it from a
  server adapter and do not register it in SQL. The same constraint applies to any new test entry
  point.
- Do not ship experimental code that skips encryption or returns plaintext as a successful result under
  an environment variable or a debug option. Experiments belong in a target that is not shipped.
- `python3 scripts/check-architecture.py` checks the core's explicit include dependencies and
  references to known test entry points from the adapters. When you add an allowed header, review this
  rule and the checker's list together.
- Keep `unit.yml`'s server-free core build and test. The static check is not a full C++ semantic
  analysis, so indirect dependencies, new test bypasses, lifetimes and per-row cost are confirmed by
  review and by the integration tests.
