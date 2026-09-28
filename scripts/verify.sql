-- Phase S spike checklist (docs/design.md §4, as amended by A1: the key is a SQL
-- argument, there is no keyring). Answers the "unconfirmed" items of §8.
--
-- This is a MANUAL checklist, kept for eyeballing a new server or a new version by
-- hand. It is not part of any gate: the automated equivalents are
-- tests/integration/*.sql (run by scripts/verify.sh on every major) and
-- mysql-test/suite/gcm. If you change behaviour, change those; this file exists so a
-- human can watch the same things scroll past on an unfamiliar server.
--
--   docker exec -i mysql-dev-8.4 mysql -uroot --default-character-set=utf8mb4 -t \
--     < scripts/verify.sql
--
-- @k is the public fixture key from spec/test-vectors.json — never a real key.
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

SELECT '1. registration: all three functions answer' AS check_;
SELECT gcm_encrypt('x', @k) IS NOT NULL AS random_registered,
       gcm_encrypt_det('x', @k) IS NOT NULL AS det_registered,
       gcm_decrypt(gcm_encrypt('x', @k), @k) AS decrypted;

SELECT '2. envelope shape: version byte and plaintext + 29' AS check_;
SELECT HEX(LEFT(gcm_encrypt('x', @k), 1)) AS random_version,
       HEX(LEFT(gcm_encrypt_det('x', @k), 1)) AS det_version,
       LENGTH(gcm_encrypt_det('홍길동', @k)) AS det_len_for_9_byte_utf8;

SELECT '3. key length is enforced on every call (expect an error next)' AS check_;
-- Deliberately wrong length; the client continues with --force.
SELECT gcm_encrypt('x', 'short');

SELECT '4. sysvar gcm.strict — GLOBAL always, SESSION only on 9.0+ (design A5)' AS check_;
SELECT @@GLOBAL.gcm.strict AS global_strict;
SET GLOBAL gcm.strict = OFF;
SELECT @@GLOBAL.gcm.strict AS global_strict_off;
SET GLOBAL gcm.strict = ON;
-- On 8.0/8.4 the next statement must fail with ER_INCORRECT_GLOBAL_LOCAL_VAR;
-- on 9.0+ it succeeds. That divergence is the whole content of amendment A5.
SET SESSION gcm.strict = OFF;
SET SESSION gcm.strict = DEFAULT;

SELECT '4b. tag failure semantics under each gcm.strict value' AS check_;
SET @good = gcm_encrypt_det('홍길동', @k);
SET @bad = CONCAT(LEFT(@good, LENGTH(@good) - 1), UNHEX('FF'));
SET GLOBAL gcm.strict = OFF;
SELECT gcm_decrypt(@bad, @k) IS NULL AS null_when_strict_off;
SET GLOBAL gcm.strict = ON;
-- expected to error: a tag mismatch is never silently NULL under strict
SELECT gcm_decrypt(@bad, @k) AS must_error;
-- a malformed envelope errors under either setting
SET GLOBAL gcm.strict = OFF;
SELECT gcm_decrypt(UNHEX('07000000'), @k) AS bad_envelope_still_errors;
SET GLOBAL gcm.strict = ON;

SELECT '5. Korean partial match through native LIKE — the reason this exists' AS check_;
SELECT gcm_decrypt(gcm_encrypt_det('홍길동', @k), @k) LIKE '%길%' AS korean_like,
       CHARSET(gcm_decrypt(gcm_encrypt_det('홍길동', @k), @k)) AS result_charset,
       gcm_decrypt(gcm_encrypt_det('Kim', @k), @k) LIKE '%kim%' AS case_insensitive_like;

SELECT '6. deterministic variant is stable and usable as a join key' AS check_;
SELECT gcm_encrypt_det('홍길동', @k) = gcm_encrypt_det('홍길동', @k) AS det_equal,
       gcm_encrypt('홍길동', @k) = gcm_encrypt('홍길동', @k) AS random_equal;

SELECT '6b. spec conformance: the det-korean-hong worked example' AS check_;
SELECT HEX(gcm_encrypt_det('홍길동', @k)) AS envelope_hex,
       HEX(gcm_encrypt_det('홍길동', @k)) =
         '03B9C3A065D8C76EA9D627C591BB12160661AD43902EB8263C49815E07483158555819839732'
         AS matches_spec_5_1;

SELECT '7. disk temp tables around a decrypt + ORDER BY (design §5.3)' AS check_;
CREATE DATABASE IF NOT EXISTS gcm_spike_db;
USE gcm_spike_db;
SHOW STATUS LIKE 'Created_tmp_disk_tables';
CREATE TEMPORARY TABLE gcm_spike (c BLOB);
INSERT INTO gcm_spike
SELECT gcm_encrypt_det(CONCAT('김', n), @k)
FROM (SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3) AS gen;
SELECT COUNT(*) AS korean_rows
FROM (SELECT gcm_decrypt(c, @k) AS name FROM gcm_spike ORDER BY gcm_decrypt(c, @k)) AS sorted
WHERE name LIKE '%김%';
DROP TEMPORARY TABLE gcm_spike;
SHOW STATUS LIKE 'Created_tmp_disk_tables';
DROP DATABASE gcm_spike_db;

SELECT '8. EVP_CIPHER_fetch succeeded — INSTALL COMPONENT itself is the evidence' AS check_;
SELECT COUNT(*) AS installed_components
FROM mysql.component WHERE component_urn = 'file://component_gcm';
