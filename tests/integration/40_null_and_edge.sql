-- Argument propagation and boundary inputs (spec/envelope.md §4 rule 3).
SELECT '# Given: the fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT '# When: NULL is passed in each argument position';
SELECT gcm_encrypt(NULL, @k) IS NULL AS enc_null_plaintext,
       gcm_encrypt('x', NULL) IS NULL AS enc_null_key,
       gcm_encrypt('x', @k, NULL) IS NULL AS enc_null_aad,
       gcm_encrypt_det(NULL, @k) IS NULL AS det_null_plaintext,
       gcm_decrypt(NULL, @k) IS NULL AS dec_null_ciphertext,
       gcm_decrypt('x', NULL) IS NULL AS dec_null_key;
SELECT '# Then: SQL NULL propagates with no cryptographic work (above)';

SELECT '# Scenario 1b — Given: an empty string, which is not NULL';
SELECT '# When: it arrives as a literal, as an expression result and from a column';
CREATE TABLE empties (id INT, c VARCHAR(8)) CHARSET utf8mb4;
INSERT INTO empties VALUES (1, ''), (2, NULL);
SELECT LENGTH(gcm_encrypt_det('', @k)) AS from_literal,
       LENGTH(gcm_encrypt_det(SUBSTRING('a', 2), @k)) AS from_expression;
SELECT id, gcm_encrypt_det(c, @k) IS NULL AS enc_is_null,
       LENGTH(gcm_encrypt_det(c, @k)) AS enc_len
FROM empties ORDER BY id;
SELECT '# Then: 29 bytes in every case, and only the real NULL propagates — an';
SELECT '#       argument of length 0 must not be mistaken for a NULL one (above)';
DROP TABLE empties;

SELECT '# Scenario 2 — Given: the empty string';
SELECT '# When: it is sealed and opened';
SELECT LENGTH(gcm_encrypt_det('', @k)) AS empty_envelope_length,
       HEX(gcm_encrypt_det('', @k)) AS empty_envelope_hex,
       gcm_decrypt(gcm_encrypt_det('', @k), @k) = '' AS round_trips,
       LENGTH(gcm_decrypt(gcm_encrypt_det('', @k), @k)) AS decrypted_length;
SELECT '# Then: 29 bytes, matching spec/envelope.md §5.2, and an empty round trip (above)';

SELECT '# Scenario 3 — Given: a 64 KiB plaintext';
SET @big = REPEAT('가', 21845);
SELECT '# When: it is sealed and opened';
SELECT LENGTH(@big) AS plaintext_bytes,
       LENGTH(gcm_encrypt_det(@big, @k)) - LENGTH(@big) AS envelope_overhead,
       gcm_decrypt(gcm_encrypt_det(@big, @k), @k) = @big AS round_trips;
SELECT '# Then: the overhead is exactly 29 bytes at any size (above)';

SELECT '# Scenario 4 — Given: plaintexts of many boundary lengths, stored in a column';
-- The plaintexts are materialised first, on purpose. Passing a freshly computed
-- string expression straight to a loadable function is corrupted by some server
-- versions (91_server_udf_arg_defect.sql pins that down, including the fact that
-- CAST does not reliably avoid it), so materialising keeps this case about the
-- component's own length handling rather than the server's argument marshalling.
CREATE TEMPORARY TABLE lens (n INT);
INSERT INTO lens
SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 15 UNION ALL SELECT 16
UNION ALL SELECT 17 UNION ALL SELECT 31 UNION ALL SELECT 32 UNION ALL SELECT 33 UNION ALL SELECT 40;
CREATE TEMPORARY TABLE sized (n INT, pt VARCHAR(64)) CHARSET utf8mb4;
INSERT INTO sized SELECT n, REPEAT('a', n) FROM lens;
SELECT '# When: each is sealed and opened';
SELECT COUNT(*) AS lengths_checked,
       SUM(gcm_decrypt(gcm_encrypt_det(pt, @k), @k) = pt) AS round_trips,
       SUM(LENGTH(gcm_encrypt_det(pt, @k)) = n + 29) AS overheads_correct
FROM sized;
SELECT '# Then: every length round-trips with a 29 byte overhead (above)';
DROP TEMPORARY TABLE sized;
DROP TEMPORARY TABLE lens;

SELECT '# Scenario 5 — Given: a latin1 column one byte wide holding a two-byte UTF-8 char';
-- The plaintext argument is requested as utf8mb4, so the server widens it before the
-- component sees it. Sizing the result from the pre-conversion length would declare 30
-- bytes for a 31 byte envelope. Plain tables, not temporary ones: MySQL cannot reopen a
-- temporary table twice within one statement.
CREATE TABLE narrow (c VARCHAR(1) CHARACTER SET latin1);
INSERT INTO narrow VALUES (_latin1 0xE9);
SELECT '# When: the envelope is materialised under strict mode';
CREATE TABLE narrow_strict AS SELECT gcm_encrypt_det(c, @k) AS e FROM narrow;
SELECT LENGTH(e) AS strict_length, HEX(gcm_decrypt(e, @k)) AS strict_decrypted FROM narrow_strict;
SELECT '# Then: 31 bytes and it decrypts (above)';

SELECT '# Scenario 6 — Given: the same column with strict SQL mode switched off';
SET @saved_sql_mode = @@SESSION.sql_mode;
SET SESSION sql_mode = '';
SELECT '# When: the envelope is materialised again';
CREATE TABLE narrow_loose AS SELECT gcm_encrypt_det(c, @k) AS e FROM narrow;
SHOW WARNINGS;
SELECT LENGTH(e) AS loose_length, HEX(gcm_decrypt(e, @k)) AS loose_decrypted FROM narrow_loose;
SET SESSION sql_mode = @saved_sql_mode;
SELECT '# Then: no truncation warning, still 31 bytes, still decrypts — the case that';
SELECT '#       would silently destroy ciphertext if the declared width were too narrow';
DROP TABLE narrow_loose;
DROP TABLE narrow_strict;
DROP TABLE narrow;
