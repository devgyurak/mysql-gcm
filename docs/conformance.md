# Conformance — checking an independent implementation against the server

Status: **non-normative how-to (2026-10-16, amendment A18).** The normative contract is
[`spec/envelope.md`](../spec/envelope.md). This document describes how to compare an implementation of
that envelope against a real mysql-gcm server — the *oracle* — for the properties the byte vectors
cannot check. It is a procedure and SQL only: it ships no client code and no reusable API, and passing
it is neither a security proof nor a support commitment (`docs/design.md` amendment A18).

The checkable statements below (§a and §d–§e) are pinned by
`tests/integration/70_conformance_oracle.sql` and use the same variable names, so the document cannot
drift from the server it describes; §b and §c take *your* implementation's bytes and are interactive.
If a pinned statement disagrees with the test, the test is right.

## What the two checks cover, and what they do not

| Check | It establishes | It does not establish |
|---|---|---|
| `spec/test-vectors.json` (§6) | Byte-level correctness: layout, derivation, tags, failures | That the plaintext and AAD **inputs** were the ones the server would have used |
| this recipe | That the plaintext conversion and the AAD bytes match the server's (§2.7) | The one-AAD-per-key convention, nonce safety, or anything cross-call |

The second check is why the recipe exists: a suite can pass every vector and still seal the wrong bytes
because it normalised the text or encoded the AAD differently. Those are inputs, and the vectors cannot
see them.

## Before you start

* **Use a throwaway server and test keys only.** The keys are arguments of the SQL below, so they land
  in the server's general and slow logs and in `performance_schema` (operational constraint 2). Never
  point this recipe at production or use a production key.
* One server is enough. Start one from a release image, or with `scripts/dev-up.sh <8.0|8.4|9>`, and
  install the component (`README.md`, "Try it").
* The keys are the published fixture keys. `@k` is the 32-byte vector key; `@k192` and `@k128` are the
  24- and 16-byte keys the vectors use. They are public and exist to be committed.

```sql
SET @k    = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @k192 = UNHEX('091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734');
SET @k128 = UNHEX('030a11181f262d343b424950575e656c');
```

## a. Deterministic seals, three suites, byte for byte

Your implementation seals `홍길동` (`ed998deab8b8eb8f99`) deterministically under each key; the server
reseals the same plaintext and must produce the same bytes. The server's answers are the vectors
`det-korean-hong`, `aes192-det-korean` and `aes128-det-korean` in `spec/test-vectors.json`.

```sql
-- The 16- and 24-byte suites are refused by the default floor; lower it only for this check.
SET GLOBAL gcm.min_key_bytes = 16;
SELECT HEX(gcm_encrypt_det('홍길동', @k)) AS det_256,
       HEX(gcm_encrypt_det('홍길동', @k192)) AS det_192,
       HEX(gcm_encrypt_det('홍길동', @k128)) AS det_128;
SET GLOBAL gcm.min_key_bytes = DEFAULT;
```

Compare each with your implementation's `encrypt_det` output for the same key, plaintext and empty
AAD. A difference means the nonce derivation, the version byte or the plaintext bytes differ.

## b. Your random seal opens on the server

Seal anything with your implementation's random variant (version `0x02`/`0x04`/`0x06`), then hand the
envelope hex to the server:

```sql
SELECT gcm_decrypt(UNHEX('<your implementation''s random envelope hex>'), @k) AS opened;
```

The server must return your original plaintext. A `bad_tag` means the key stream or the tag differs;
`bad_envelope` means the layout or the version byte differs; and `bad_key_len` means the version byte
and the key length disagree — pass the key that matches your envelope's version (`@k` for `0x02`/`0x03`,
`@k192` for `0x06`/`0x07`, `@k128` for `0x04`/`0x05`).

## c. The server's seal opens in your implementation

In the other direction, take the server's envelope and open it with your implementation:

```sql
SELECT HEX(gcm_encrypt('홍길동', @k)) AS random_envelope;
```

Steps (b) and (c) together are the round trip the migration in amendment A18 rests on: a value sealed
by either side opens on the other, byte for byte, with no conversion step.

## d. v1 (`0x01`), read-only, on both sides

Your implementation must open the legacy v1 vectors and must never produce one. The server does the
same:

```sql
SELECT gcm_decrypt(UNHEX('01101112131415161718191a1b1c1d1e1fc40f242a0eb2f5da5572ab310442d463'),
                   @k) AS legacy_plaintext;   -- 홍길동
```

Compare with your implementation's decryption of the same bytes. Both sides must also reject a v1
envelope carrying a non-empty AAD with `bad_envelope` (it cannot bind one), and refuse to produce
`0x01` at all.

## e. The charset traps

These are the checks the vectors cannot make. Run them against both sides and compare envelopes.

**Plaintext: a character argument is converted, `binary` is not.** A `latin1` *character* and the same
string as `utf8mb4` seal identically; a `binary` value and a character value of the same visible text do
not, because the `binary` bytes are sealed as they are.

```sql
SET @s_latin1  = CONVERT('Müller' USING latin1);          -- 4D FC 6C 6C 65 72
SET @s_utf8mb4 = CONVERT(CONVERT('Müller' USING latin1) USING utf8mb4);
SELECT gcm_encrypt_det(@s_latin1, @k) = gcm_encrypt_det(@s_utf8mb4, @k) AS character_converted,      -- 1
       gcm_encrypt_det(UNHEX('4DFC6C6C6572'), @k) <>
       gcm_encrypt_det(@s_latin1, @k) AS binary_sealed_as_bytes;                                      -- 1
```

**Plaintext: no normalisation.** NFC and NFD are different bytes and must give different envelopes.

```sql
SELECT gcm_encrypt_det(CONVERT(UNHEX('C3A9') USING utf8mb4), @k) =
       gcm_encrypt_det(CONVERT(UNHEX('65CC81') USING utf8mb4), @k) AS normalised;  -- 0
```

**AAD: bytes only, never converted or normalised.** A string AAD keeps its source-charset bytes, so the
same visible string from a `latin1` connection and a `utf8mb4` connection gives different tags — which
is why an implementation must fix the encoding it uses for AAD. A normalised AAD is a different mistake
with the same effect.

```sql
SELECT gcm_encrypt_det('patient-42', @k, CONVERT('ü' USING latin1)) =
       gcm_encrypt_det('patient-42', @k, 'ü') AS aad_converted;                     -- 0
SELECT gcm_encrypt_det('patient-42', @k, CONVERT('ü' USING latin1)) =
       gcm_encrypt_det('patient-42', @k, UNHEX('FC')) AS aad_is_raw_bytes;          -- 1
SELECT gcm_encrypt_det('patient-42', @k, CONVERT(UNHEX('65CC81') USING utf8mb4)) =
       gcm_encrypt_det('patient-42', @k, CONVERT(UNHEX('C3A9') USING utf8mb4)) AS aad_normalised;  -- 0
```

A result of `0` on `character_converted`, `binary_sealed_as_bytes` or `aad_is_raw_bytes`, or `1` on
`aad_converted` or `aad_normalised`, means the implementation is converting or normalising bytes the
server passes through unchanged.

## What no oracle can check

The AAD **bytes** above are checkable. **One AAD byte-convention per key** (`spec/envelope.md` §3) is
not: the server enforces no cross-call AAD policy, so no comparison can. An implementation owns that
rule itself, along with its usage budget and key handling — the component's cleanse guarantees
(amendments A11, A13, A16) do not carry over, and a client's own seals are invisible to
`gcm_key_usage` (`spec/envelope.md` §4.3).