-- Usage counts for the key-id functions (docs/design.md amendment A14).
-- gcm_key_usage answers for the calling account, from the component's own table;
-- it reads no keyring. A count is one input to a key's usage budget, not the
-- budget: this server, these functions, since the component started counting.
SELECT '# Given: a key that has not been used since the component was installed';
DO keyring_key_generate('it_usage', 'AES', 32);
SELECT '# When: its usage is read';
SELECT JSON_VALID(gcm_key_usage('it_usage')) AS is_json,
       JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals', '$.det_seals', '$.bytes_sealed', '$.tag_failures') AS counts,
       JSON_EXTRACT(gcm_key_usage('it_usage'), '$.since') > 1700000000 AS since_is_a_recent_time,
       JSON_EXTRACT(gcm_key_usage('it_usage'), '$.complete') AS complete,
       CHARSET(gcm_key_usage('it_usage')) AS result_charset;
SELECT '# Then: valid JSON, all zeros, a start time, complete, utf8mb4 (above)';

SELECT '# Scenario 2 — Given: three names sealed at random and one value sealed deterministically';
CREATE TABLE usage_rows (id INT PRIMARY KEY, name_enc VARBINARY(128));
INSERT INTO usage_rows VALUES
  (1, gcm_encrypt_kr('김철수', 'it_usage')),
  (2, gcm_encrypt_kr('홍길동', 'it_usage')),
  (3, gcm_encrypt_kr('박길수', 'it_usage'));
SET @d = gcm_encrypt_det_kr('EMR-001', 'it_usage');
SELECT '# When: the usage is read';
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals', '$.det_seals', '$.bytes_sealed', '$.tag_failures') AS counts;
SELECT '# Then: 3 random, 1 deterministic, 27 + 7 plaintext bytes, no tag failure (above)';

SELECT '# Scenario 3 — Given: one statement that seals three rows through one call site';
CREATE TABLE usage_copy (id INT PRIMARY KEY, name_enc VARBINARY(128));
INSERT INTO usage_copy SELECT id, gcm_encrypt_kr(gcm_decrypt_kr(name_enc, 'it_usage'), 'it_usage') FROM usage_rows;
SELECT '# When: the usage is read after it';
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals', '$.bytes_sealed') AS counts;
SELECT '# Then: three more seals and 27 more bytes; opening them counted nothing (above)';

SELECT '# Scenario 4 — Given: a statement that seals and reads the usage in the same row';
SELECT '# When: it runs';
SELECT gcm_encrypt_kr('x', 'it_usage') IS NOT NULL AS sealed,
       JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals') AS seen_in_the_same_statement;
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals') AS seen_afterwards;
SELECT '# Then: 6 inside the statement and 7 after it — a count appears when its statement has finished (above)';

SELECT '# Scenario 5 — Given: an envelope with a bit of its tag flipped, strict at its default';
UPDATE usage_rows
   SET name_enc = CONCAT(LEFT(name_enc, LENGTH(name_enc) - 1), CHAR(ASCII(RIGHT(name_enc, 1)) ^ 1))
 WHERE id = 2;
SELECT '# When: it is opened, and the usage is read';
SELECT gcm_decrypt_kr(name_enc, 'it_usage') AS never_reached FROM usage_rows WHERE id = 2;
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.tag_failures') AS tag_failures;
SELECT '# Then: an error, and one tag failure counted even though the statement failed (above, errors section)';

SELECT '# Scenario 6 — Given: gcm.strict OFF, in a new connection so it applies on every major';
SET GLOBAL gcm.strict = OFF;
connect;
SELECT '# When: the three rows are opened in one statement, and the usage is read';
SELECT id, gcm_decrypt_kr(name_enc, 'it_usage') IS NULL AS is_null FROM usage_rows ORDER BY id;
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.tag_failures') AS tag_failures;
SELECT '# Then: the middle row is NULL, and it is a second tag failure (above)';
SET GLOBAL gcm.strict = DEFAULT;
connect;

SELECT '# Scenario 7 — Given: the same key bytes passed to the key-argument functions';
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals', '$.det_seals') AS before_them;
DO gcm_encrypt('홍길동', keyring_key_fetch('it_usage'));
DO gcm_encrypt_det('홍길동', keyring_key_fetch('it_usage'));
SELECT '# When: the usage is read';
SELECT JSON_EXTRACT(gcm_key_usage('it_usage'), '$.random_seals', '$.det_seals') AS after_them;
SELECT '# Then: the same 7 and 1 — the key-argument functions are not counted (above)';

SELECT '# Scenario 8 — Given: another account, reading the same key id through a definer function';
DROP USER IF EXISTS 'kr_reader'@'%';
CREATE USER 'kr_reader'@'%';
GRANT ALL ON gcm_it.* TO 'kr_reader'@'%';
CREATE DEFINER = 'kr_reader'@'%' FUNCTION reader_usage() RETURNS VARCHAR(255) CHARSET utf8mb4
  SQL SECURITY DEFINER NO SQL
  RETURN gcm_key_usage('it_usage');
SELECT '# When: it is called';
SELECT JSON_EXTRACT(reader_usage(), '$.random_seals', '$.det_seals', '$.bytes_sealed', '$.tag_failures') AS their_counts;
SELECT '# Then: zeros — the name is the account and the key id, and that account has sealed nothing (above)';
DROP FUNCTION reader_usage;
DROP USER 'kr_reader'@'%';

SELECT '# Scenario 9 — Given: ids that name nothing, are NULL, or are not ids';
SELECT '# When: their usage is read';
SELECT JSON_EXTRACT(gcm_key_usage('it_never_created'), '$.random_seals') AS absent_id,
       JSON_EXTRACT(gcm_key_usage(REPEAT('k', 255)), '$.random_seals') AS longest_id,
       gcm_key_usage(NULL) IS NULL AS null_id;
SELECT gcm_key_usage('') AS never_reached;
SELECT gcm_key_usage(REPEAT('k', 256)) AS never_reached;
SELECT gcm_key_usage(CONCAT('it_', CHAR(0), 'usage')) AS never_reached;
SELECT gcm_key_usage() AS never_reached;
SELECT '# Then: zero without asking whether the key exists, zero for the longest id, NULL, and an error for each of the rest (above, errors section)';

DROP TABLE usage_copy;
DROP TABLE usage_rows;
