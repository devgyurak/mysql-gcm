-- A server with NO keyring component loaded (run by scripts/verify-bare.sh, not by
-- verify.sh, whose server has one). The key-id functions add four required services
-- to the component (docs/design.md amendment A13); this pins that requiring them
-- does not need a keyring: the component installs, the key-argument functions work
-- as before, and only the key-id functions fail — as an error, whatever gcm.strict says.
SELECT '# Given: a server with no keyring, the component installed, and the fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT '# When: the key-argument functions are used';
SELECT gcm_decrypt(gcm_encrypt('홍길동', @k), @k) LIKE '%길%' AS random_round_trip,
       gcm_decrypt(gcm_encrypt_det('홍길동', @k), @k) LIKE '%길%' AS det_round_trip;
SELECT '# Then: they work exactly as on any other server (above)';

SELECT '# Scenario 2 — Given: the same server';
SELECT '# When: each key-id function is called';
SELECT gcm_encrypt_kr('x', 'any_id') AS never_reached;
SELECT gcm_encrypt_det_kr('x', 'any_id') AS never_reached;
SELECT gcm_decrypt_kr(REPEAT('x', 40), 'any_id') AS never_reached;
SELECT '# Then: each reports that the keyring is unavailable (errors section)';

SELECT '# Scenario 3 — Given: gcm.strict turned OFF, in a new connection so it applies on every major';
SET GLOBAL gcm.strict = OFF;
connect;
SELECT '# When: a key-id function is called';
SELECT gcm_decrypt_kr(REPEAT('x', 40), 'any_id') AS never_reached;
SELECT '# Then: still an error, not NULL — a missing keyring is not hidden by the setting (errors section)';
SET GLOBAL gcm.strict = DEFAULT;

SELECT '# Scenario 4 — Given: a NULL key id';
SELECT '# When: a key-id function is called';
SELECT gcm_encrypt_kr('x', NULL) IS NULL AS null_result;
SELECT '# Then: NULL, with no error — the keyring is not consulted (above)';

SELECT '# Scenario 5 — Given: the same server, with no keyring';
SELECT '# When: the usage of a key id is read';
SELECT JSON_EXTRACT(gcm_key_usage('any_id'), '$.random_seals', '$.tag_failures', '$.complete') AS usage_counts;
SELECT '# Then: zeros — gcm_key_usage reads the component''s own table and needs no keyring (above)';
