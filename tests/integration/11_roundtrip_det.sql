-- gcm_encrypt_det: deterministic, for join keys / UNIQUE / exact match.
SELECT '# Given: the fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT '# When: the same plaintext is encrypted deterministically twice';
SELECT gcm_encrypt_det('홍길동', @k) = gcm_encrypt_det('홍길동', @k) AS det_stable,
       HEX(LEFT(gcm_encrypt_det('홍길동', @k), 1)) AS version_byte,
       LENGTH(gcm_encrypt_det('홍길동', @k)) AS envelope_length;
SELECT '# Then: identical bytes, version 03, length = 9 + 29 = 38 (above)';

SELECT '# Scenario 2 — Given: the spec worked example det-korean-hong';
SELECT '# When: the deterministic envelope is produced';
SELECT HEX(gcm_encrypt_det('홍길동', @k)) AS envelope_hex;
SELECT '# Then: it equals spec/envelope.md §5.1 byte for byte (above)';

SELECT '# Scenario 3 — Given: two tables joined on a deterministic ciphertext';
CREATE TEMPORARY TABLE patient (emr_id VARBINARY(64));
CREATE TEMPORARY TABLE encounter (patient_id VARBINARY(64), note VARCHAR(32));
INSERT INTO patient VALUES (gcm_encrypt_det('EMR-001', @k));
INSERT INTO encounter VALUES (gcm_encrypt_det('EMR-001', @k), 'first visit');
SELECT '# When: the join runs on the encrypted column';
SELECT e.note AS joined_note
FROM patient p JOIN encounter e ON p.emr_id = e.patient_id;
SELECT '# Then: the row joins without decrypting anything (above)';
DROP TEMPORARY TABLE encounter;
DROP TEMPORARY TABLE patient;

SELECT '# Scenario 4 — Given: a UNIQUE key over a deterministic ciphertext';
CREATE TEMPORARY TABLE bed (natural_key VARBINARY(64), UNIQUE KEY uq (natural_key));
INSERT INTO bed VALUES (gcm_encrypt_det('ward-3/room-12/bed-A', @k));
SELECT '# When: the same natural key is inserted again';
-- INSERT IGNORE, so the constraint is asserted by the row count rather than by an
-- error message that would print the ciphertext bytes into the expected file.
INSERT IGNORE INTO bed VALUES (gcm_encrypt_det('ward-3/room-12/bed-A', @k));
SELECT COUNT(*) AS rows_after_duplicate_insert FROM bed;
SELECT '# Then: still one row — the deterministic ciphertext collided as intended (above)';
DROP TEMPORARY TABLE bed;
