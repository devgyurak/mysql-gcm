-- per-major-expected: behaviour legitimately differs between server majors,
-- so this case is compared against <name>.<major>.expected.
-- Where gcm.strict can be set, and the strict=OFF path.
--
-- Scope is version-dependent (docs/design.md amendment A5): component sysvars
-- gained session scope in MySQL 9.0.0, so before that gcm.strict is GLOBAL-only
-- and SET SESSION is rejected by the server. Both statements are issued below so
-- one script covers every major; the .expected files differ per major, which is
-- exactly the divergence being pinned:
--   8.0 / 8.4 : SET SESSION errors, SET GLOBAL changes this session
--   9.x       : SET SESSION works, SET GLOBAL does not change this session
SELECT '# Given: a tampered envelope and gcm.strict at its default';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @good = gcm_encrypt_det('홍길동', @k);
SET @tampered = CONCAT(LEFT(@good, LENGTH(@good) - 1), UNHEX('FF'));
SELECT @@GLOBAL.gcm.strict AS global_default;
SELECT '# When: strict is turned off at both scopes and the tampered envelope is decrypted';
SET GLOBAL gcm.strict = OFF;
SET SESSION gcm.strict = OFF;
SELECT gcm_decrypt(@tampered, @k) IS NULL AS null_when_strict_off;
SELECT '# Then: NULL on every major, reached through whichever scope that major';
SELECT '#       supports (errors section lists the rejected one)';

SELECT '# Scenario 2 — Given: strict off in this session';
SELECT '# When: a malformed envelope is decrypted';
SELECT gcm_decrypt(UNHEX('07000000'), @k) AS never_reached;
SELECT '# Then: still an error — strict only ever governs tag failures (errors section)';

SELECT '# Scenario 3 — Given: strict off';
SELECT '# When: strict is restored to its default and the tampered envelope is decrypted again';
SET GLOBAL gcm.strict = ON;
SET SESSION gcm.strict = DEFAULT;
SELECT gcm_decrypt(@tampered, @k) AS never_reached;
SELECT '# Then: the error is back (errors section)';
