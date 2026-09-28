-- Signature and argument validation. Each scenario below is a complete
-- Given/When/Then; the labels land in the compared output so a reviewer reads the
-- intent straight from the .expected diff.
SELECT '# Scenario 1 — Given: the installed component and a 32-byte fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT '# When: each function is called with a valid signature';
SELECT gcm_encrypt('x', @k) IS NOT NULL AS random_answers,
       gcm_encrypt_det('x', @k) IS NOT NULL AS det_answers,
       gcm_decrypt(gcm_encrypt('x', @k), @k) AS decrypted;
SELECT '# Then: all three answer and the round trip returns the plaintext (above)';

SELECT '# Scenario 2 — Given: the same key';
SELECT '# When: gcm_encrypt is called with too few arguments';
SELECT gcm_encrypt('x');
SELECT '# Then: the call is rejected at init with the usage message (errors section)';

SELECT '# Scenario 3 — Given: the same key';
SELECT '# When: gcm_decrypt is called with too many arguments';
SELECT gcm_decrypt('x', @k, 'aad', 'extra');
SELECT '# Then: the call is rejected at init with the usage message (errors section)';

SELECT '# Scenario 4 — Given: a key that is 5 bytes instead of 32';
SELECT '# When: gcm_encrypt is called with it';
SELECT gcm_encrypt('x', 'short');
SELECT '# Then: bad_key_len, reported with lengths only and no key bytes (errors section)';

SELECT '# Scenario 5 — Given: a key that is 31 bytes, one short of AES-256';
SELECT '# When: gcm_decrypt is called with it';
SELECT gcm_decrypt(UNHEX('030000000000000000000000000000000000000000000000000000000000'), LEFT(@k, 31));
SELECT '# Then: bad_key_len — the length check runs on every call (errors section)';

SELECT '# Scenario 6 — Given: a 33-byte key, one byte too long';
SELECT '# When: gcm_encrypt_det is called with it';
SELECT gcm_encrypt_det('x', CONCAT(@k, UNHEX('00')));
SELECT '# Then: bad_key_len — no folding, hashing or padding to length (errors section)';
