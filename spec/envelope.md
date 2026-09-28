# mysql-gcm envelope specification

Status: **FINAL** (v1 of this document, 2026-09-28). Supersedes the draft that carried open issue A2.
Rationale lives in `docs/design.md` (amendments A1–A4); this file is the normative byte-level
contract for the server implementation, stored data and conformance tests.

Conformance keywords MUST / MUST NOT / SHOULD are used in the usual sense.

## 1. Scope

The envelope is the value stored in a MySQL column. It is produced by the server functions
`gcm_encrypt` and `gcm_encrypt_det` and consumed by `gcm_decrypt`. Applications use these functions
through an existing MySQL driver. No language-specific encryption SDK is shipped.
Internal fixture generation MUST match this format; this scope change does not alter its bytes.

| Function | Envelope | Result type |
|---|---|---|
| `gcm_encrypt(plaintext, key [, aad])` | version `0x02` | BLOB (charset `binary`) |
| `gcm_encrypt_det(plaintext, key [, aad])` | version `0x03` | BLOB (charset `binary`) |
| `gcm_decrypt(ciphertext, key [, aad])` | accepts `0x01`, `0x02`, `0x03` | VARCHAR tagged `utf8mb4` |

## 2. Byte layout

All lengths are in bytes. `n` is the plaintext length, which MAY be zero. Multi-byte fields have no
endianness: they are opaque octet strings.

### 2.1 Version `0x02` — GCM, random nonce

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | version = `0x02` |
| 1 | 12 | nonce (96-bit, from a CSPRNG) |
| 13 | n | AES-256-GCM ciphertext |
| 13 + n | 16 | authentication tag (128-bit) |

Total length = `n + 29`. Minimum 29.

### 2.2 Version `0x03` — GCM, deterministic (synthetic) nonce

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | version = `0x03` |
| 1 | 12 | nonce, derived per §3 and **stored** |
| 13 | n | AES-256-GCM ciphertext |
| 13 + n | 16 | authentication tag (128-bit) |

Total length = `n + 29`. Minimum 29. Layout is identical to `0x02`; only the nonce's origin differs.

The nonce is stored, not recomputed (`docs/design.md` amendment A2): it is a function of the
plaintext, which a decryptor does not have. Storing it costs 12 bytes and changes nothing about
determinism — the same `(key, plaintext, aad)` still yields the same complete envelope.

Decryptors MUST use the stored nonce. Re-deriving the nonce after decryption and comparing is
OPTIONAL and MUST NOT be required for a decryption to succeed; the GCM tag already authenticates
every byte of the envelope body.

> `gcm_encrypt_det` reveals equality of plaintexts. It exists for join keys, UNIQUE constraints and
> exact-match lookups. It MUST NOT be used for free text.

### 2.3 Version `0x01` — legacy CBC, decrypt only

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | version = `0x01` |
| 1 | 16 | CBC IV |
| 17 | 16·k, k ≥ 1 | AES-256-CBC ciphertext, PKCS#7 padded |

Total length = `17 + 16k`. Minimum 33.

Produced only by a migration that prefixes an existing `AES_ENCRYPT` value with the version byte and
its IV — no re-encryption. MySQL uses a 32-byte key directly as the AES-256 key, so
`gcm_decrypt(CONCAT(0x01, iv, AES_ENCRYPT(pt, k, iv)), k)` equals `AES_DECRYPT(...)` when
`block_encryption_mode = 'aes-256-cbc'`.

Implementations MUST NOT produce `0x01`. Two properties follow from CBC and MUST be documented
wherever v1 is exposed:

* **v1 is not authenticated.** A wrong key yields garbage that occasionally has valid padding, so a
  v1 decryption can return meaningless plaintext instead of failing. Migrating a row to `0x02`/`0x03`
  removes this.
* **v1 carries no AAD.** Decrypting a v1 envelope with a non-empty AAD MUST fail with `bad_envelope`.
* **A v1 plaintext MUST already be UTF-8.** `gcm_decrypt` tags its result `utf8mb4` for every
  version. For `0x02`/`0x03` the encryption path asks the server for the plaintext argument as
  `utf8mb4`, so a *character* argument is converted on the way in — but a `binary` argument is not
  (converting from `binary` copies bytes), so `gcm_encrypt(UNHEX('ff'), key)` seals `FF` and the
  decrypted result is ill-formed `utf8mb4` just the same. v1 is the worse case because it skips
  encryption entirely: its bytes are whatever the legacy column held, with no conversion at any
  point. A latin1 name such as `Müller` becomes `4D FC 6C 6C 65 72`, which is invalid UTF-8; the
  server then returns an ill-formed string and `LIKE '%ller%'` evaluates to 0 with no error — the
  search this project exists for fails silently. A migration MUST convert such a column to `utf8mb4` before
  prefixing `0x01 || iv`, and implementations MUST NOT paper over it by converting inside
  `gcm_decrypt`: the function cannot know the legacy charset, and guessing would corrupt values that
  really are binary.

### 2.4 Reserved versions

Every other version byte (`0x00`, `0x04`–`0xFF`) is unassigned. A decryptor MUST reject it with
`bad_envelope`; it MUST NOT be silently treated as a known version and MUST NOT return NULL.

## 3. Key and nonce derivation

The key is an argument, exactly 32 bytes (AES-256). Any other length is an error
(`bad_key_len`) — implementations MUST NOT fold, hash, truncate or pad a key to length, which is
precisely the `AES_ENCRYPT` weakness this project does not reproduce.

The deterministic nonce uses a separate, domain-separated key:

```
DET_NONCE_LABEL = "mysql-gcm/v1/det-nonce"          # 22 ASCII bytes, no NUL terminator
nonce_key       = HMAC-SHA256(key, DET_NONCE_LABEL)             # 32 bytes
nonce           = HMAC-SHA256(nonce_key, plaintext)[0..12)      # first 12 bytes
```

* The encryption key MUST NOT be used directly as the HMAC key for the nonce.
* The AAD MUST NOT be an input to the nonce (`docs/design.md` §5.2). Changing this requires a design
  amendment first. It has one consequence that deployments MUST respect:

  > **One AAD convention per key.** Because the nonce depends only on the plaintext, encrypting the
  > *same* plaintext under one key with *two different* AADs reuses the (key, nonce) pair across two
  > authenticated messages. The ciphertexts are identical but the tags differ, and that pair is the
  > classic GCM nonce-reuse condition for recovering the GHASH subkey `H`, which enables tag forgery
  > for that nonce. Confidentiality of the plaintext is unaffected (the key stream never covers two
  > different plaintexts), but integrity for that nonce is. Use identical AAD bytes for every
  > deterministic call with that key, across all servers, columns and applications. A column-specific
  > AAD such as `schema.table.column` requires a separate key for each different AAD domain;
  > ciphertext equality joins require the same key and AAD on both sides. Never vary the AAD while
  > keeping the key and plaintext fixed, and never mix "with AAD" and "without AAD" writes of the same
  > value under one key. The random variant (`0x02`) is not affected.
* The server derives `nonce_key` per call and MUST wipe its buffer after use with
  `OPENSSL_cleanse` — see `.agents/rules/crypto-safety.md`.

Collision safety: a truncated HMAC-SHA256 gives ~2⁻⁹⁶ per pair; at 10⁷ distinct plaintexts the
birthday probability is ≈ 10⁻¹⁵. Identical plaintexts colliding is the intended determinism.
This estimate is not a proof of the construction's overall security or an approved per-key usage
budget. Operational accounting, rotation and recovery responsibilities are defined in
`docs/ops-constraints.md` items 11–13 and `docs/design.md` amendment A8. The component does not
enforce these across calls. This clarification does not change the envelope bytes or derivation.

## 4. Failure semantics

`gcm.strict` (GLOBAL + SESSION, default ON) affects exactly one failure: tag mismatch.

| Condition | Error code | `gcm.strict=ON` | `gcm.strict=OFF` |
|---|---|---|---|
| Key length ≠ 32 | `bad_key_len` | error | **error** |
| Envelope shorter than its version's minimum | `bad_envelope` | error | **error** |
| Unknown version byte | `bad_envelope` | error | **error** |
| v1 body not a multiple of 16 | `bad_envelope` | error | **error** |
| v1 with non-empty AAD | `bad_envelope` | error | **error** |
| v1 PKCS#7 padding invalid | `bad_envelope` | error | **error** |
| GCM tag mismatch (wrong key, wrong AAD, tampering) | `bad_tag` | error | **NULL** |
| CSPRNG failure | `rng` | error | error |
| Any other OpenSSL failure | `openssl` | error | error |

Rules that follow, and that every implementation MUST honour:

1. Unauthenticated plaintext is NEVER returned. On tag mismatch the output buffer is wiped before the
   error or NULL is produced.
2. Corrupt data and misconfiguration (`bad_envelope`, `bad_key_len`) are never hidden by a setting;
   `gcm.strict=OFF` does not turn them into NULL.
3. SQL NULL in any argument yields SQL NULL, with no cryptographic work. This is argument propagation,
   not a failure mode.
4. Error messages, logs and assertion strings MUST NOT contain key, plaintext, nonce, tag or
   ciphertext bytes. Lengths and the version byte are the only values allowed.

## 5. Worked examples

Key for every example (from `spec/test-vectors.json`, never a real key):

```
key      = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
nonce_key= 43b7cb83fce7816ff9164b1ff231e617ab054f0c790200cd8fbfa59e6cc61a3a   # HMAC-SHA256(key, label)
```

### 5.1 Deterministic, Korean plaintext (`det-korean-hong`)

```
plaintext = 홍길동  -> UTF-8  ed998deab8b8eb8f99                (9 bytes)
aad       = (empty)
nonce     = HMAC-SHA256(nonce_key, plaintext)[0..12) = b9c3a065d8c76ea9d627c591
envelope  = 03 b9c3a065d8c76ea9d627c591 bb12160661ad43902e b8263c49815e0748315855 5819839732
            ^v ^nonce(12)               ^ciphertext(9)      ^tag(16)
full hex  = 03b9c3a065d8c76ea9d627c591bb12160661ad43902eb8263c49815e07483158555819839732   (38 bytes)
```

### 5.2 Deterministic, empty plaintext (`det-empty`)

```
envelope = 0378141e6daf391e6c40d3ea31d6b3f5b6f2f82e3c86118232b25fc0f2            (29 bytes)
```

### 5.3 Random nonce, same plaintext (`random-korean`, nonce fixed for reproducibility)

```
nonce    = 0f1e2d3c4b5a69788796a5b4
envelope = 020f1e2d3c4b5a69788796a5b4182426483ab7c82bec34e0721f33028ea13399fed3664fde5e   (38 bytes)
```

### 5.4 Legacy v1 (`legacy-cbc-korean`)

```
iv       = 101112131415161718191a1b1c1d1e1f
envelope = 01101112131415161718191a1b1c1d1e1fc40f242a0eb2f5da5572ab310442d463   (33 bytes)
```

## 6. Test vectors

`spec/test-vectors.json` is the single source of truth for the C++ conformance tests.
`scripts/gen-vectors.py` generates reproducible fixtures with `cryptography` and checks known-good
fixtures before writing. It is an internal development tool, not a client library. The C++ suite
MUST consume every case, including expected failures; SQL integration tests cover server behavior.

```jsonc
{
  "version": 1,                      // schema version: added field = minor, changed meaning = major
  "spec": "spec/envelope.md",
  "generated_by": "scripts/gen-vectors.py",
  "vectors": [
    {
      "id":            "det-korean-hong",      // stable, used as the test name
      "kind":          "nist|random|det|legacy",
      "key_hex":       "...",                  // 32 bytes, except in bad_key_len cases
      "nonce_key_hex": "...",                  // optional, det only: expected HMAC-SHA256(key, label)
      "nonce_hex":     "...",                  // optional: 12-byte nonce, or the 16-byte IV for legacy
      "aad_hex":       "",
      "plaintext_hex": "...",                  // empty for failure cases
      "envelope_hex":  "...",
      "expect":        "ok|bad_tag|bad_envelope|bad_key_len",
      "note":          "why this case exists"  // optional
    }
  ]
}
```

How a suite MUST consume a vector:

| `expect` | Required assertions |
|---|---|
| `ok`, kind `nist`/`random` | `seal_with_nonce(key, nonce, pt, aad) == envelope` and `decrypt(envelope, key, aad) == pt` |
| `ok`, kind `det` | `decrypt(envelope, key, aad) == pt`, `encrypt_det(pt, key, aad) == envelope` and, when present, `derive_nonce_key(key) == nonce_key_hex` and the derived nonce equals `nonce_hex`. Not `seal_with_nonce`: that seam writes version `0x02` and cannot produce a `0x03` envelope |
| `ok`, kind `legacy` | `decrypt(envelope, key, aad) == pt` only — encryption of v1 does not exist |
| `bad_tag` | `decrypt` raises the tag error (server: error under `strict=ON`, NULL under OFF) |
| `bad_envelope` | `decrypt` raises the envelope error under **both** strict settings |
| `bad_key_len` | `encrypt`, `encrypt_det` and `decrypt` all raise the key-length error |

Current contents: 750 NIST CAVP cases (`[Keylen=256][IVlen=96][Taglen=128]` from
`gcmEncryptExtIV256.rsp` and `gcmDecrypt256.rsp`, 191 of them authentication failures) and 33
project cases. Regenerate with `scripts/gen-vectors.py --rsp-dir <unzipped CAVP dir>`; verify with
`scripts/gen-vectors.py --check` (CI does this).

## 7. Versioning of this document

The envelope version bytes and the derivation label are frozen. A change to either is a new spec
version and a new version byte, never a redefinition of an existing one. Changing this file requires
updating, in the same change: `docs/design.md`, the component, server tests, the internal vector generator and
`spec/test-vectors.json` when the byte contract changes. Documentation-only scope corrections do not
require changes to the envelope version or existing vector bytes.
