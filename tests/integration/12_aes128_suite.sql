-- AES-128-GCM (design A10): the key length selects the suite, and gcm.min_key_bytes
-- is the floor that keeps a truncated key from silently choosing a weaker one.
SELECT '# Given: a 32-byte and a 16-byte fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @k128 = UNHEX('0310171e252c333a41484f565d646b72');
SELECT '# When: the floor is lowered so the smaller suite is allowed';
SET GLOBAL gcm.min_key_bytes = 16;

SELECT '# When: the same plaintext is sealed under each key length';
SELECT HEX(LEFT(gcm_encrypt('홍길동', @k), 1))        AS random_256_version,
       HEX(LEFT(gcm_encrypt('홍길동', @k128), 1))     AS random_128_version,
       HEX(LEFT(gcm_encrypt_det('홍길동', @k), 1))    AS det_256_version,
       HEX(LEFT(gcm_encrypt_det('홍길동', @k128), 1)) AS det_128_version;
SELECT '# Then: 02 / 04 / 03 / 05 — the version byte follows the key (above)';

SELECT '# Scenario 2 — Given: an AES-128 envelope';
SELECT '# When: it is round-tripped and matched with native LIKE';
SELECT gcm_decrypt(gcm_encrypt('홍길동', @k128), @k128) AS plaintext_back,
       gcm_decrypt(gcm_encrypt_det('홍길동', @k128), @k128) LIKE '%길%' AS korean_like,
       CHARSET(gcm_decrypt(gcm_encrypt('홍길동', @k128), @k128)) AS result_charset,
       LENGTH(gcm_encrypt_det('홍길동', @k128)) AS envelope_length;
SELECT '# Then: the plaintext, 1, utf8mb4 and 38 = 9 + 29 (above)';

SELECT '# Scenario 3 — Given: deterministic values under the two suites';
SELECT '# When: they are compared';
SELECT gcm_encrypt_det('EMR-001', @k128) = gcm_encrypt_det('EMR-001', @k128) AS det_128_stable,
       gcm_encrypt_det('EMR-001', @k) = gcm_encrypt_det('EMR-001', @k128) AS joins_across_suites;
SELECT '# Then: 1 and 0 — ciphertext never joins across suites (above)';

SELECT '# Scenario 4 — Given: an envelope and a key that disagree';
SET @e256 = gcm_encrypt_det('홍길동', @k);
SET @e128 = gcm_encrypt_det('홍길동', @k128);
SELECT '# When: each is decrypted with the other suite key';
SELECT gcm_decrypt(@e256, @k128) AS wrong_way_round;
SELECT gcm_decrypt(@e128, @k) AS other_way_round;
SELECT '# Then: bad_key_len, never bad_tag — a key problem reported as one (errors below)';

SELECT '# Scenario 5 — Given: a 24-byte key (AES-192 is allocated, not implemented)';
SELECT '# When: it is used to encrypt';
SELECT gcm_encrypt('홍길동', UNHEX('000102030405060708090a0b0c0d0e0f1011121314151617')) AS aes192;
SELECT '# Then: an error — never folded into a neighbouring suite (errors below)';

SELECT '# Scenario 6 — Given: the floor back at its default';
SET GLOBAL gcm.min_key_bytes = DEFAULT;
SELECT @@global.gcm.min_key_bytes AS floor_default;
SELECT '# When: a 16-byte key is used to encrypt';
SELECT gcm_encrypt('홍길동', @k128) AS below_floor;
SELECT '# Then: refused by policy — the feature is opt-in (errors below)';

SELECT '# Scenario 7 — Given: the floor is 32 but AES-128 data already exists';
SELECT '# When: it is decrypted';
SELECT gcm_decrypt(@e128, @k128) AS decrypt_ignores_floor;
SELECT '# Then: the plaintext — raising the floor never locks out data (above)';
