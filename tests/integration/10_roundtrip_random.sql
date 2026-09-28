-- gcm_encrypt: random nonce. Non-deterministic output is checked by property, not
-- by value (testing rule).
SELECT '# Given: the fixture key and three rows holding the same plaintext';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
CREATE TABLE two_rows (n INT);
INSERT INTO two_rows VALUES (1), (2), (3);
SELECT '# When: the same plaintext is encrypted once per row and the result stored';
-- Stored first, on purpose. `COUNT(DISTINCT gcm_encrypt('x', @k))` over N rows
-- returns 1: the server evaluates that constant expression once per aggregate, so
-- the count says nothing about nonce freshness and would keep passing even if every
-- row reused one nonce. Writing the envelopes to a column forces per-row evaluation,
-- which is the property this case exists to guard.
CREATE TABLE sealed_rows AS SELECT n, gcm_encrypt('홍길동', @k) AS c FROM two_rows;
SELECT COUNT(*) AS rows_sealed,
       COUNT(DISTINCT c) AS distinct_envelopes,
       COUNT(DISTINCT HEX(LEFT(c, 1))) AS distinct_versions,
       MIN(HEX(LEFT(c, 1))) AS version_byte,
       MIN(LENGTH(c)) AS envelope_length,
       SUM(gcm_decrypt(c, @k) = '홍길동') AS all_decrypt
FROM sealed_rows;
SELECT '# Then: 3 rows, 3 distinct envelopes from one shared version byte, each 38';
SELECT '#       bytes and each decrypting back to the plaintext (above)';
DROP TABLE sealed_rows;
DROP TABLE two_rows;

SELECT '# Scenario 2 — Given: the fixture key';
SELECT '# When: a random-nonce envelope is decrypted';
SELECT gcm_decrypt(gcm_encrypt('홍길동', @k), @k) AS plaintext,
       gcm_decrypt(gcm_encrypt('홍길동', @k), @k) = '홍길동' AS round_trips;
SELECT '# Then: the original plaintext comes back (above)';

SELECT '# Scenario 3 — Given: the fixture key and an AAD';
SELECT '# When: the value is sealed and opened with the same AAD';
SELECT gcm_decrypt(gcm_encrypt('홍길동', @k, 'patients.name'), @k, 'patients.name') AS with_aad,
       LENGTH(gcm_encrypt('홍길동', @k, 'patients.name')) AS length_unchanged_by_aad;
SELECT '# Then: the plaintext returns and the AAD adds no bytes (above)';
