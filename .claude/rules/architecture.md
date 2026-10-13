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
<!-- Generated from .agents/rules/architecture.md by scripts/agents-sync.py — edit the source. -->
# Architecture — responsibilities, dependency direction, resource lifetimes

The rationale is `docs/design.md` amendment A6. For MySQL API usage follow `component-src.md`, for
crypto safety `crypto-safety.md`, and for how to write tests `testing.md`.

## 1. Module responsibilities and dependency direction

| Module | Responsibility | Project dependencies allowed |
|---|---|---|
| `component.cc` | Service declarations, UDF registration and unregistration, coordinating init and deinit | The UDF entry points, `sysvar`, core init/deinit, `usage` init/deinit |
| `udf_*.cc`, `udf_glue.h` | SQL arguments, NULL, charset, the result buffer, error translation | `gcm`, `sysvar`, `key_source`, `usage`, the shared byte and error types |
| `key_source.{h,cc}` | The calling account and the keyring read behind the `_kr` functions (amendment A13). No cryptography and no SQL policy | MySQL services, `gcm` for wiping, `envelope` for the key lengths and the shared byte types |
| `sysvar.{h,cc}` | Registering and reading server configuration, per-version service differences | MySQL services |
| `gcm.{h,cc}` | The encryption and decryption construction, the authentication result, crypto resource init/deinit | `envelope`, `nonce`, OpenSSL |
| `nonce.{h,cc}` | Domain separation and nonce derivation | The shared byte and error types, OpenSSL |
| `envelope.{h,cc}` | Version, length, offset and field parsing; the shared types | The C++ standard library |
| `usage.{h,cc}` | The table of usage counts for the key-id functions (amendment A14): names and integers, one lock. No key material, no cryptography, no SQL policy | The C++ standard library |

- `usage` is not part of the cryptographic core, but it is held to the same independence: no MySQL
  header, service or type, so that `tests/unit` builds and tests it, concurrency included.
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
| component | The fetched algorithm handles, the sysvar storage, the registration state, and the table of usage counts (amendment A14: names and integers, one mutex, created in init before any function is registered and released with the algorithm handles). Prepared in init and released in a safe deinit |
| `UDF_INIT` | That UDF instance's result buffer and its `gcm.strict` and `gcm.min_key_bytes` snapshots; and, under amendment A11, `gcm_decrypt`'s scheduled EVP context with the copy of the key it was scheduled with and its suite, and `gcm_encrypt_det`'s derived nonce key with its key copy. Managed by init/deinit — cleansed in deinit, cleansed and forgotten on any core error — and not equated with a whole session. And, under amendment A13, a `_kr` function's key as fetched from the keyring, with its key id and account and a latched failure: acquired on the first non-NULL row, kept across a `bad_tag` that strict=OFF turns into NULL, and cleansed in deinit. Under amendment A16 any row that raises gives all of this up at once — the fetched key, the A11 context and its key copy, the A11 nonce key, the result buffer — and marks the instance spent, so a call made afterwards is refused instead of served from what was released |
| keyring read | The reader object of `keyring_reader_with_status`. Acquired and released inside one call of `key_source`, on every path — it holds the server's global keyring read lock — and never stored (amendment A13) |
| operation | The EVP *operation* (the init with the nonce through Final), derived per-row values and transient secrets — the nonce, the MAC output, a scratch copy. Cleaned up when the operation ends and on every error path. The decrypt context *object* is `UDF_INIT`-lifetime (A11); the operation run in it is not |

- Input bytes are borrowed from a buffer the caller owns. Do not retain a pointer beyond that
  ownership. Cleansing a copied secret is the responsibility of whoever made the copy.
- The table of usage counts is the one piece of shared mutable state (amendment A14). It is written
  once per `UDF_INIT`, by `fold_usage`, and read by `gcm_key_usage` — one lock per call of that
  function, which is a read someone asked for, not a cost added to encryption or decryption;
  nothing else touches it.
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
- Reuse across rows is confined to what amendment A11 allows — `gcm_decrypt`'s scheduled context and
  `gcm_encrypt_det`'s nonce key, each inside one `UDF_INIT` — and is keyed on the full key bytes,
  compared in constant time. The one other value carried from row to row is a `_kr` function's
  fetched key (amendment A13), keyed on the calling account and the key id, both compared on every
  row. Nothing else is.
- A `_kr` function reads the keyring once, on its first non-NULL row — not in init, where a prepared
  statement's parameter is not visible. Reading the calling account on every row touches no keyring.
  Through a definer stored *function* the server creates a `UDF_INIT` per row, so that shape reads
  per row: an accepted, documented cost (`docs/ops-constraints.md` item 17), not something to cache
  around.
- An error is final for the `UDF_INIT` of every one of the six crypto functions, `_kr` or not: the
  server makes no further row call, and the row that raises gives up everything the instance holds —
  the fetched key, both A11 states and the result buffer — and marks it spent, rather than leave any
  of it to a `deinit` the server does not always run (amendment A16).

## 6. Test boundaries and verification

- `encrypt_with_nonce` is an internal entry point for the vector tests. Do not reference it from a
  server adapter and do not register it in SQL. The same constraint applies to any new test entry
  point.
- `decrypt_session_has_key` (amendment A11) is a core test seam under the same constraint.
  `fault_inject_decrypt_init` is compiled only when `GCM_FAULT_INJECTION` is defined, which
  `tests/unit` does and the component build never does, so the shipped `.so` contains no injection
  point. Both are listed in `scripts/check-architecture.py`.
- Do not ship experimental code that skips encryption or returns plaintext as a successful result under
  an environment variable or a debug option. Experiments belong in a target that is not shipped.
- `tests/probe` is a test-only component that registers throwaway UDFs to pin a server defect
  (issue #43). Its name, `probe`, is reserved: `scripts/build-probe.sh` builds it from its own
  directory only, and `scripts/check-architecture.py` refuses the word anywhere under `src/` or
  `docker/`, so the scaffolding cannot reach the component build or an image.
- `python3 scripts/check-architecture.py` checks the core's explicit include dependencies and
  references to known test entry points from the adapters. When you add an allowed header, review this
  rule and the checker's list together.
- Keep `unit.yml`'s server-free core build and test. The static check is not a full C++ semantic
  analysis, so indirect dependencies, new test bypasses, lifetimes and per-row cost are confirmed by
  review and by the integration tests.
