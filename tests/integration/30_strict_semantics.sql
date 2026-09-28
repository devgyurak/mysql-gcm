-- Failure semantics that hold on every supported server major
-- (spec/envelope.md §4). Anything that depends on where gcm.strict can be set,
-- including the strict=OFF path, lives in 31_strict_scope.sql — that scope differs
-- by version (docs/design.md amendment A5).
SELECT '# Given: a valid envelope, the same envelope with its last tag byte flipped, and strict at its default';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @good = gcm_encrypt_det('홍길동', @k);
SET @tampered = CONCAT(LEFT(@good, LENGTH(@good) - 1), UNHEX('FF'));
SELECT '# When: the tampered envelope is decrypted';
SELECT gcm_decrypt(@tampered, @k) AS never_reached;
SELECT '# Then: an error, never NULL and never unauthenticated plaintext (errors section)';

SELECT '# Scenario 2 — Given: envelopes that are malformed rather than unauthentic';
SELECT '# When: each is decrypted';
SELECT gcm_decrypt(UNHEX('07000000'), @k) AS unknown_version;
SELECT gcm_decrypt(UNHEX('02'), @k) AS too_short;
SELECT gcm_decrypt(CONCAT(UNHEX('01'), REPEAT(UNHEX('00'), 20)), @k) AS v1_misaligned;
SELECT '# Then: each is an error — and 31_strict_scope shows strict=OFF does not';
SELECT '#       soften these (errors section)';

SELECT '# Scenario 3 — Given: a value sealed with one AAD';
SET @with_aad = gcm_encrypt_det('홍길동', @k, 'patients.name');
SELECT '# When: it is opened with a different AAD';
SELECT gcm_decrypt(@with_aad, @k, 'patients.other') AS never_reached;
SELECT '# Then: a tag error — the AAD is authenticated (errors section)';

SELECT '# Scenario 4 — Given: the same value sealed with an AAD';
SELECT '# When: it is opened with no AAD at all';
SELECT gcm_decrypt(@with_aad, @k) AS never_reached;
SELECT '# Then: a tag error (errors section)';
