<!-- Generated from .agents/rules/crypto-safety.md by scripts/agents-sync.py — edit the source. -->
# Crypto safety rules (always apply)

This whole project is "make AEAD safe inside a MySQL server". Nothing below is negotiable.

## OpenSSL
- Fetch algorithms by name: `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)`,
  `EVP_MAC_fetch(NULL, "HMAC", NULL)` with the `SHA256` digest. Never call a legacy symbol such as
  `EVP_aes_256_gcm()` or `HMAC()` directly — that binds to the OpenSSL present at build time and
  bypasses providers.
- Create the fetched handles once in component init, cache them, and release them in deinit with
  `EVP_CIPHER_free` / `EVP_MAC_free`. Do not fetch per UDF call.
- Use the libcrypto the server process has already loaded. No static linking, no bundling, no `dlopen`
  of a different version — a symbol clash kills the server.
- Nonce length is fixed at 12 and tag length at 16. Do not add an argument that accepts another length.
- Random nonces come from `RAND_bytes`. Any return other than 1 is an error. No `rand()`, nothing
  time-based.
- On decryption, call `EVP_CTRL_AEAD_SET_TAG` **before** `EVP_DecryptFinal_ex`; the return value of
  Final *is* the tag verification result. When Final returns 0, discard the output buffer with
  `OPENSSL_cleanse` — never return unauthenticated plaintext.

## Key handling (amendment A1: the key is a SQL argument)
- The key arrives only as the UDF argument `key`, and is **exactly 32, 24 or 16 bytes** — the length
  selects AES-256, AES-192 or AES-128 and nothing else does (amendment A10), and the two encryption
  functions additionally refuse anything below `gcm.min_key_bytes` (default 32). Any other length is
  an error. Do not fold (XOR), hash or pad it to length — that weakness of `AES_ENCRYPT` is not to be
  reproduced.
- Reference the buffers `UDF_ARGS` provides for the key and the plaintext directly, and if you make a
  copy, `OPENSSL_cleanse` it immediately after use. Do not put either in a `std::string`, which leaves
  copies behind when it reallocates. The one exception is amendment A11: a `UDF_INIT` may keep a copy
  of the key (at most 32 bytes) beside `gcm_decrypt`'s scheduled EVP context or beside
  `gcm_encrypt_det`'s derived nonce key, on these conditions and no others — the copy is compared
  with the incoming key by `CRYPTO_memcmp`; it is replaced only when the bytes or the suite differ,
  and cleansed before replacement; it is cleansed and forgotten on any failure of the cipher operation, `bad_tag`
  included, and the context is reset with it; it is cleansed in `deinit`; and it is never shared
  across threads.
- Derive the deterministic nonce key as `HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`. Never use the
  encryption key directly as an HMAC key (domain separation). The label string is a single constant in
  `nonce.h`.
- Do not put key bytes in a repository file, in my.cnf, in a sysvar, in an environment variable or in a
  test fixture. The only exception is the public vector keys in `spec/test-vectors.json`.
- That a key appears in a SQL statement and can therefore reach the server logs is a **known
  operational constraint** (design §6). Do not try to work around it in code — no log-filtering code,
  which would mean touching server internals and is out of scope.

## Failure semantics
- Tag mismatch: with `gcm.strict=ON` (the default) an error, raised through the `mysql_runtime_error`
  service with a dedicated message. With OFF, NULL. There is no third state.
- A malformed envelope (too short, unknown version) and a wrong key length are **always** errors,
  regardless of strict. Data corruption and misconfiguration are not hidden behind a setting.
- Never put key, plaintext, nonce, tag or ciphertext bytes in an error message, a server log, an
  assertion or an exception string. Lengths and the version byte are as far as it goes.

## The deterministic variant
- `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`. AAD is **not** an input to the nonce calculation
  (design §5.2). Changing that means amending the design document first.
- The deterministic variant is for joins, UNIQUE constraints and exact-match lookups. Keep the warning
  against using it on free text in both the documentation and the function comments.
- Every deterministic call under one key uses the same AAD bytes — or always none — regardless of
  server, column or application. Use a different key for a different AAD domain. A join on ciphertext
  requires both sides to share key and AAD. Do not describe the component as validating an AAD policy
  across calls; it does not.
- Explain the exposure of equality, frequency and length together with the nonce-collision assumption.
  Do not present passing vectors, a sample collision test or a collision-probability calculation as a
  proof that the whole construction is safe.

## Operational responsibility (amendment A8)
- Before deployment, have a security review set a usage budget that sums **every** use of a given key,
  and the criteria for rotating it. Do not assume the component counts per-key usage, rotates
  automatically or detects a repeated nonce. Do not document an arbitrary number as a universal safe
  limit.
- Distinguish copying or restoring an envelope from re-encrypting. Random re-encryption takes a fresh
  nonce; a deterministic retry uses the same key, plaintext and AAD. Recovery does not roll back
  accumulated usage. If you cannot establish that the usage history or the RNG state is sound, stop
  writing. Recover and verify the RNG state of every writer and resume with a new key generated
  independently and safely. Rotating a key does not by itself resolve a duplicated RNG state.
- When rotating a key, plan the migration of deterministic ciphertext used for joins and UNIQUE
  constraints, and the retention of old keys for historical data and backups. Key management itself is
  an external operational responsibility and does not extend the component's scope.
- The development guard hook is a command blocker, not monitoring of crypto calls in production.
  Keep the detailed operational guidance in items 11–13 of `docs/ops-constraints.md` and in the README
  together.

## Patterns blocked automatically (P1) in code review
Scope is C++ under `src/`. The Python `hmac.HMAC` in the internal vector generator is an allowed
library and therefore out of scope — per-language checks are step 3 of the `code-review` skill.

`EVP_aes_`, `HMAC(`, `rand(`, `srand(`, `printf.*key`, `LogErr.*(key|plain)`, `std::string key`, a
hardcoded key literal, any branch that accepts a key length outside {16, 24, 32} or skips the
`gcm.min_key_bytes` check on encryption, any branch that turns a tag
failure into NULL without consulting strict, an unchecked `EVP_DecryptFinal_ex` return value, a key
copy that outlives its `UDF_INIT`, and a cross-row cache keyed on anything but the full key bytes
(amendment A11).
