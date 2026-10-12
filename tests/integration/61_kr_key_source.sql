-- What the key-id functions do when the key cannot be had (docs/design.md
-- amendment A13). Every one of these is an error whatever gcm.strict says, and no
-- message names the key id, the account, or the type or length of an entry.
SELECT '# Given: a keyring holding an AES-256 key, a SECRET and an 8 byte AES entry';
DO keyring_key_generate('it_good', 'AES', 32);
DO keyring_key_store('it_secret', 'SECRET', 'sixteen byte str');
DO keyring_key_generate('it_odd', 'AES', 8);
SELECT '# When: an absent id, the SECRET and the odd-length entry are each used';
SELECT gcm_encrypt_kr('x', 'it_absent') AS never_reached;
SELECT gcm_encrypt_kr('x', 'it_secret') AS never_reached;
SELECT gcm_decrypt_kr(REPEAT('x', 40), 'it_odd') AS never_reached;
SELECT '# Then: the same "no usable AES key" error for all three (errors section)';

SELECT '# Scenario 2 — Given: ids that are not ids';
SELECT '# When: an empty id, a 256 byte id and an id with a NUL byte are used';
SELECT gcm_encrypt_kr('x', '') AS never_reached;
SELECT gcm_encrypt_kr('x', REPEAT('k', 256)) AS never_reached;
SELECT gcm_encrypt_kr('x', CONCAT('it_', CHAR(0), 'good')) AS never_reached;
SELECT '# Then: an invalid-id error for each (errors section)';

SELECT '# Scenario 3 — Given: the longest id allowed, with nothing stored under it';
SELECT '# When: it is used';
SELECT gcm_encrypt_kr('x', REPEAT('k', 255)) AS never_reached;
SELECT '# Then: it is a valid id, so the answer is "no usable AES key" (errors section)';

SELECT '# Scenario 4 — Given: NULL in each argument position';
SELECT '# When: the functions are called';
SELECT gcm_encrypt_kr(NULL, 'it_good') IS NULL AS null_plaintext,
       gcm_encrypt_kr('x', NULL) IS NULL AS null_id,
       gcm_encrypt_det_kr('x', 'it_good', NULL) IS NULL AS null_aad,
       gcm_decrypt_kr(NULL, 'it_absent') IS NULL AS null_ciphertext_absent_id;
SELECT '# Then: NULL each time, even under an id that names nothing (above)';

SELECT '# Scenario 5 — Given: a table whose rows name two different key ids';
DO keyring_key_generate('it_other', 'AES', 32);
CREATE TEMPORARY TABLE jobs (id INT, key_id VARCHAR(32));
INSERT INTO jobs VALUES (1, 'it_good'), (2, 'it_other');
SELECT '# When: the id is taken from the column';
SELECT COUNT(gcm_encrypt_kr('x', key_id)) AS never_reached FROM jobs ORDER BY id;
SELECT '# Then: refused on the second id — one key id per call site per statement (errors section)';
DROP TEMPORARY TABLE jobs;

SELECT '# Scenario 6 — Given: a table whose rows all name the same key id';
CREATE TEMPORARY TABLE same_jobs (id INT, key_id VARCHAR(32));
INSERT INTO same_jobs VALUES (1, 'it_good'), (2, 'it_good'), (3, 'it_good');
SELECT '# When: the id is taken from the column';
SELECT COUNT(gcm_encrypt_kr('x', key_id)) AS sealed FROM same_jobs;
SELECT '# Then: three rows sealed — the rule is about the bytes, not about being a constant (above)';
DROP TEMPORARY TABLE same_jobs;

SELECT '# Scenario 7 — Given: an envelope with one bit of its last tag byte flipped, strict at its default';
-- XOR, not a fixed byte: this envelope has a random nonce, so its tag ends in any
-- given byte one time in 256 and overwriting with that byte would change nothing.
SET @good = gcm_encrypt_kr('홍길동', 'it_good');
SET @tampered = CONCAT(LEFT(@good, LENGTH(@good) - 1), CHAR(ASCII(RIGHT(@good, 1)) ^ 1));
SELECT '# When: it is opened by key id';
SELECT gcm_decrypt_kr(@tampered, 'it_good') AS never_reached;
SELECT '# Then: a tag error, never NULL and never plaintext (errors section)';

SELECT '# Scenario 8 — Given: an AES-128 envelope and the id of an AES-256 key';
DO keyring_key_generate('it_k16', 'AES', 16);
SET GLOBAL gcm.min_key_bytes = 16;
SET @e16 = gcm_encrypt_kr('x', 'it_k16');
SET GLOBAL gcm.min_key_bytes = DEFAULT;
SELECT '# When: the envelope is opened under that id';
SELECT gcm_decrypt_kr(@e16, 'it_good') AS never_reached;
SELECT '# Then: a suite mismatch that does not state the key length (errors section)';

SELECT '# Scenario 9 — Given: the key id sent as a bound parameter';
SET @id = 'it_good';
SET @pt = '홍길동';
PREPARE seal FROM 'SELECT gcm_encrypt_det_kr(?, ?) INTO @bound';
PREPARE open_it FROM 'SELECT gcm_decrypt_kr(?, ?) AS opened';
SELECT '# When: the statements are executed';
EXECUTE seal USING @pt, @id;
EXECUTE open_it USING @bound, @id;
SELECT '# Then: the name — a parameter is not visible in init, so the key is read on the first row (above)';
DEALLOCATE PREPARE seal;
DEALLOCATE PREPARE open_it;

SELECT '# Scenario 10 — Given: the three functions';
SELECT '# When: each is called with one argument and with four';
SELECT gcm_encrypt_kr('x') AS never_reached;
SELECT gcm_encrypt_det_kr('x', 'it_good', 'aad', 'extra') AS never_reached;
SELECT gcm_decrypt_kr('x') AS never_reached;
SELECT '# Then: each is refused when the statement is prepared, with its usage (errors section)';

SELECT '# Scenario 11 — Given: three sealed rows, the middle one with a bit of its tag flipped, and gcm.strict OFF';
-- A table, not user variables: the strict setting is read per session on 9.x and
-- GLOBAL-only before it (docs/design.md amendment A5), so the one way to turn it
-- off that works on every major is SET GLOBAL followed by a new connection.
CREATE TABLE strict_rows (id INT PRIMARY KEY, name_enc VARBINARY(128));
INSERT INTO strict_rows VALUES
  (1, gcm_encrypt_kr('김철수', 'it_good')),
  (2, gcm_encrypt_kr('홍길동', 'it_good')),
  (3, gcm_encrypt_kr('박길수', 'it_good'));
UPDATE strict_rows
   SET name_enc = CONCAT(LEFT(name_enc, LENGTH(name_enc) - 1), CHAR(ASCII(RIGHT(name_enc, 1)) ^ 1))
 WHERE id = 2;
SET GLOBAL gcm.strict = OFF;
connect;
SELECT '# When: one statement opens all three by key id';
SELECT id, gcm_decrypt_kr(name_enc, 'it_good') AS name FROM strict_rows ORDER BY id;
SELECT '# Then: name, NULL, name — the key read on the first row survives the bad tag (above)';

SELECT '# Scenario 12 — Given: gcm.strict still OFF';
SELECT '# When: the rows are opened under an id that names nothing';
SELECT id, gcm_decrypt_kr(name_enc, 'it_absent') AS never_reached FROM strict_rows ORDER BY id;
SELECT '# Then: an error, not NULL — a key that cannot be had is not hidden by the setting (errors section)';
SET GLOBAL gcm.strict = DEFAULT;
connect;
DROP TABLE strict_rows;
