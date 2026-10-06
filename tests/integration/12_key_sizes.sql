-- All three key sizes (design A10): the key length selects the suite, and
-- gcm.min_key_bytes is the floor that keeps a truncated key from silently
-- choosing a weaker one.
SELECT '# Given: a 32-, 24- and 16-byte fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @k192 = UNHEX('091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734');
SET @k128 = UNHEX('0310171e252c333a41484f565d646b72');
SELECT '# When: the floor is lowered so the smaller suite is allowed';
SET GLOBAL gcm.min_key_bytes = 16;

SELECT '# When: the same plaintext is sealed under each key length';
SELECT HEX(LEFT(gcm_encrypt('홍길동', @k), 1))        AS random_256_version,
       HEX(LEFT(gcm_encrypt('홍길동', @k192), 1))     AS random_192_version,
       HEX(LEFT(gcm_encrypt('홍길동', @k128), 1))     AS random_128_version,
       HEX(LEFT(gcm_encrypt_det('홍길동', @k), 1))    AS det_256_version,
       HEX(LEFT(gcm_encrypt_det('홍길동', @k192), 1)) AS det_192_version,
       HEX(LEFT(gcm_encrypt_det('홍길동', @k128), 1)) AS det_128_version;
SELECT '# Then: 02 / 06 / 04 and 03 / 07 / 05 — the version byte follows the key (above)';

SELECT '# Scenario 2 — Given: AES-128 and AES-192 envelopes';
SELECT '# When: it is round-tripped and matched with native LIKE';
SELECT gcm_decrypt(gcm_encrypt('홍길동', @k128), @k128) AS plaintext_128,
       gcm_decrypt(gcm_encrypt('홍길동', @k192), @k192) AS plaintext_192,
       gcm_decrypt(gcm_encrypt_det('홍길동', @k128), @k128) LIKE '%길%' AS korean_like_128,
       gcm_decrypt(gcm_encrypt_det('홍길동', @k192), @k192) LIKE '%길%' AS korean_like_192,
       CHARSET(gcm_decrypt(gcm_encrypt('홍길동', @k192), @k192)) AS result_charset,
       LENGTH(gcm_encrypt_det('홍길동', @k192)) AS envelope_length;
SELECT '# Then: the plaintext twice, 1, 1, utf8mb4 and 38 = 9 + 29 (above)';

SELECT '# Scenario 3 — Given: deterministic values under the three suites';
SELECT '# When: they are compared';
SELECT gcm_encrypt_det('EMR-001', @k128) = gcm_encrypt_det('EMR-001', @k128) AS det_128_stable,
       gcm_encrypt_det('EMR-001', @k192) = gcm_encrypt_det('EMR-001', @k192) AS det_192_stable,
       gcm_encrypt_det('EMR-001', @k) = gcm_encrypt_det('EMR-001', @k192) AS joins_256_192,
       gcm_encrypt_det('EMR-001', @k192) = gcm_encrypt_det('EMR-001', @k128) AS joins_192_128;
SELECT '# Then: 1, 1, 0, 0 — ciphertext never joins across suites (above)';

SELECT '# Scenario 4 — Given: an envelope and a key that disagree';
SET @e256 = gcm_encrypt_det('홍길동', @k);
SET @e192 = gcm_encrypt_det('홍길동', @k192);
SET @e128 = gcm_encrypt_det('홍길동', @k128);
SELECT '# When: each is decrypted with another suite key';
SELECT gcm_decrypt(@e256, @k128) AS wrong_way_round;
SELECT gcm_decrypt(@e128, @k) AS other_way_round;
SELECT gcm_decrypt(@e192, @k) AS v192_with_256_key;
SELECT gcm_decrypt(@e256, @k192) AS v256_with_192_key;
SELECT '# Then: bad_key_len, never bad_tag — a key problem reported as one (errors below)';

SELECT '# Scenario 5 — Given: a 23-byte key, one short of AES-192';
SELECT '# When: it is used to encrypt';
SELECT gcm_encrypt('홍길동', UNHEX('000102030405060708090a0b0c0d0e0f10111213141516')) AS short_key;
SELECT '# Then: an error — never rounded to a neighbouring suite (errors below)';

SELECT '# Scenario 6 — Given: the floor back at its default';
SET GLOBAL gcm.min_key_bytes = DEFAULT;
SELECT @@global.gcm.min_key_bytes AS floor_default;
SELECT '# When: a 16-byte key is used to encrypt';
SELECT gcm_encrypt('홍길동', @k128) AS below_floor;
SELECT '# Then: refused by policy — the feature is opt-in (errors below)';

SELECT '# Scenario 7 — Given: a tampered AES-192 envelope and strict ON';
SET @bad192 = CONCAT(LEFT(@e192, LENGTH(@e192)-1),
                     UNHEX(LPAD(HEX(ORD(RIGHT(@e192, 1)) ^ 255), 2, '0')));
-- XOR rather than a fixed 0xFF: appending a constant is a no-op when the tag
-- already ends in that byte, which is exactly what happened here and made the
-- case pass by returning the plaintext.
SET GLOBAL gcm.strict = ON;  -- GLOBAL: session scope is 9.0+ only (design A5), and 31_strict_scope covers it
SELECT '# When: it is decrypted';
SELECT gcm_decrypt(@bad192, @k192) AS strict_on;
SELECT '# Then: an error — tag verification is not suite-specific (errors below)';

-- The strict=OFF half lives in mysql-test/suite/gcm/t/gcm_aes128.test instead.
-- SET GLOBAL reaches the current session on 8.0/8.4 but not on 9.x, where the
-- session holds its own value (design A5), so putting it here would split this
-- case into per-major expected files for a difference that has nothing to do
-- with the suite. MTR runs 8.4 only, so it can set the scope and assert the NULL.

SELECT '# Scenario 8 — Given: the floor is 32 but AES-128 data already exists';
SELECT '# When: it is decrypted';
SELECT gcm_decrypt(@e128, @k128) AS decrypt_ignores_floor;
SELECT '# Then: the plaintext — raising the floor never locks out data (above)';
