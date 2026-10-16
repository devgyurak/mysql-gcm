-- The server-oracle recipe of docs/conformance.md, pinned so the document cannot drift from
-- the server it describes (docs/design.md amendment A18). Public keys only — the keys
-- spec/test-vectors.json uses (and the same @k/@k192 as tests/integration/12_key_sizes.sql); no branching.
SELECT '# Given: the three public fixture keys and the spec deterministic vectors';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @k192 = UNHEX('091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734');
SET @k128 = UNHEX('030a11181f262d343b424950575e656c');
-- The 16- and 24-byte suites are refused by the default floor; lower it only for this check.
SET GLOBAL gcm.min_key_bytes = 16;
SELECT '# When: the server reseals 홍길동 under each suite';
SELECT HEX(gcm_encrypt_det('홍길동', @k))    AS det_256,
       HEX(gcm_encrypt_det('홍길동', @k192)) AS det_192,
       HEX(gcm_encrypt_det('홍길동', @k128)) AS det_128;
SELECT '# Then: the vectors det-korean-hong, aes192-det-korean, aes128-det-korean (above)';
SET GLOBAL gcm.min_key_bytes = DEFAULT;

SELECT '# Scenario 2 — Given: the v1 (legacy CBC) spec vector, which is decrypt-only';
SELECT '# When: it is opened with the 32 byte key';
SELECT gcm_decrypt(UNHEX('01101112131415161718191a1b1c1d1e1fc40f242a0eb2f5da5572ab310442d463'), @k) AS legacy_plaintext,
       HEX(gcm_decrypt(UNHEX('01101112131415161718191a1b1c1d1e1fc40f242a0eb2f5da5572ab310442d463'), @k)) AS legacy_hex;
SELECT '# Then: 홍길동 and ed998deab8b8eb8f99 — v1 opens byte for byte on both sides (above)';

SELECT '# Scenario 3 — Given: the same v1 vector with a non-empty AAD';
SELECT '# When: it is decrypted';
SELECT gcm_decrypt(UNHEX('01101112131415161718191a1b1c1d1e1fc40f242a0eb2f5da5572ab310442d463'), @k, 'x') AS never_reached;
SELECT '# Then: bad_envelope — v1 predates AAD and cannot bind one (errors below)';

SELECT '# Scenario 4 — Given: the same visible string as a latin1 and a utf8mb4 character argument,';
SELECT '#              and the same bytes as a binary argument';
SET @s_latin1  = CONVERT('Müller' USING latin1);
SET @s_utf8mb4 = CONVERT(CONVERT('Müller' USING latin1) USING utf8mb4);
SELECT '# When: each is sealed deterministically under one key';
SELECT gcm_encrypt_det(@s_latin1, @k) = gcm_encrypt_det(@s_utf8mb4, @k) AS character_converted,
       gcm_encrypt_det(UNHEX('4DFC6C6C6572'), @k) <> gcm_encrypt_det(@s_latin1, @k) AS binary_sealed_as_bytes,
       HEX(gcm_encrypt_det(@s_utf8mb4, @k)) AS utf8mb4_envelope_hex;
SELECT '# Then: 1 and 1 — a character argument is converted to utf8mb4, binary bytes are sealed as they are (above)';

SELECT '# Scenario 5 — Given: one letter as NFC (C3A9) and NFD (65CC81) utf8mb4 bytes';
SELECT '# When: each is sealed deterministically under one key';
SELECT gcm_encrypt_det(CONVERT(UNHEX('C3A9') USING utf8mb4), @k) =
       gcm_encrypt_det(CONVERT(UNHEX('65CC81') USING utf8mb4), @k) AS same_envelope;
SELECT '# Then: 0 — the server does not normalise, so a normalising client diverges (above)';

SELECT '# Scenario 6 — Given: one visible AAD string from a latin1 and a utf8mb4 source,';
SELECT '#              and the same letter as NFC and NFD';
SELECT '# When: each is the AAD of the same plaintext, and the latin1 form is compared with its raw byte';
SELECT gcm_encrypt_det('patient-42', @k, CONVERT('ü' USING latin1)) =
       gcm_encrypt_det('patient-42', @k, 'ü') AS aad_converted,
       gcm_encrypt_det('patient-42', @k, CONVERT('ü' USING latin1)) =
       gcm_encrypt_det('patient-42', @k, UNHEX('FC')) AS aad_is_raw_bytes,
       gcm_encrypt_det('patient-42', @k, CONVERT(UNHEX('65CC81') USING utf8mb4)) =
       gcm_encrypt_det('patient-42', @k, CONVERT(UNHEX('C3A9') USING utf8mb4)) AS aad_normalised;
SELECT '# Then: 0, 1 and 0 — AAD is used as bytes and is neither converted nor normalised (above)';