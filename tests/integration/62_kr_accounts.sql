-- The authorisation boundary of the key-id functions is the keyring namespace of
-- the calling account, priv_user@priv_host (docs/design.md amendment A13). A SQL
-- SECURITY DEFINER routine runs as its definer and so uses the definer's keys; a
-- view does not.
SELECT '# Given: a second account that owns a key, and a key of our own';
DROP USER IF EXISTS 'kr_owner'@'%';
CREATE USER 'kr_owner'@'%';
GRANT EXECUTE ON *.* TO 'kr_owner'@'%';
GRANT ALL ON gcm_it.* TO 'kr_owner'@'%';
-- The other account's key cannot be removed by the harness, which is not that account,
-- so this case removes it itself: before, in case an earlier run stopped half way, and
-- after. The handler is what lets "remove if present" be one call with no output.
DELIMITER //
CREATE DEFINER = 'kr_owner'@'%' PROCEDURE owner_drop_key() SQL SECURITY DEFINER
BEGIN
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION BEGIN END;
  DO keyring_key_remove('it_shared');
END//
DELIMITER ;
CREATE DEFINER = 'kr_owner'@'%' PROCEDURE owner_make_key() SQL SECURITY DEFINER
  DO keyring_key_generate('it_shared', 'AES', 32);
CALL owner_drop_key();
CALL owner_make_key();
DO keyring_key_generate('it_mine', 'AES', 32);
SELECT '# When: we use the other account''s key id directly';
SELECT gcm_encrypt_kr('x', 'it_shared') AS never_reached;
SELECT '# Then: no usable key — an id names a key only within the caller''s own namespace (errors section)';

SELECT '# Scenario 2 — Given: definer functions owned by that account, with the id hard-coded';
CREATE DEFINER = 'kr_owner'@'%' FUNCTION owner_seal(p VARCHAR(64) CHARSET utf8mb4)
  RETURNS VARBINARY(512) SQL SECURITY DEFINER NO SQL
  RETURN gcm_encrypt_kr(p, 'it_shared');
CREATE DEFINER = 'kr_owner'@'%' FUNCTION owner_open(c VARBINARY(512))
  RETURNS VARCHAR(64) CHARSET utf8mb4 SQL SECURITY DEFINER NO SQL
  RETURN gcm_decrypt_kr(c, 'it_shared');
CREATE TEMPORARY TABLE patients (id INT, name_enc VARBINARY(512));
INSERT INTO patients VALUES (1, owner_seal('김철수')), (2, owner_seal('홍길동')), (3, owner_seal('박길수'));
SELECT '# When: we search through them';
SELECT id FROM patients WHERE owner_open(name_enc) LIKE '%길%' ORDER BY id;
SELECT '# Then: rows 2 and 3 — the definer''s key is used on our behalf (above)';
DROP TEMPORARY TABLE patients;

SELECT '# Scenario 3 — Given: the same function body with SQL SECURITY INVOKER';
CREATE DEFINER = 'kr_owner'@'%' FUNCTION invoker_seal(p VARCHAR(64) CHARSET utf8mb4)
  RETURNS VARBINARY(512) SQL SECURITY INVOKER NO SQL
  RETURN gcm_encrypt_kr(p, 'it_shared');
SELECT '# When: we call it';
SELECT invoker_seal('x') AS never_reached;
SELECT '# Then: no usable key — it runs as us (errors section)';

SELECT '# Scenario 4 — Given: a SQL SECURITY DEFINER view owned by that account';
CREATE DEFINER = 'kr_owner'@'%' SQL SECURITY DEFINER VIEW owner_view AS
  SELECT gcm_encrypt_kr('x', 'it_shared') AS sealed;
SELECT '# When: we select from it';
SELECT sealed AS never_reached FROM owner_view;
SELECT '# Then: no usable key — a function in a view runs as the invoker (errors section)';

SELECT '# Scenario 5 — Given: a definer routine of that account naming our key id';
CREATE DEFINER = 'kr_owner'@'%' FUNCTION owner_uses_mine()
  RETURNS VARBINARY(512) SQL SECURITY DEFINER NO SQL
  RETURN gcm_encrypt_kr('x', 'it_mine');
SELECT '# When: we call it';
SELECT owner_uses_mine() AS never_reached;
SELECT '# Then: no usable key — the boundary holds in that direction too (errors section)';

SELECT '# Scenario 6 — Given: our own key id';
SELECT '# When: we use it directly';
SELECT gcm_decrypt_kr(gcm_encrypt_kr('홍길동', 'it_mine'), 'it_mine') AS ours;
SELECT '# Then: the name (above)';

DROP VIEW owner_view;
DROP FUNCTION owner_uses_mine;
DROP FUNCTION invoker_seal;
DROP FUNCTION owner_open;
DROP FUNCTION owner_seal;
CALL owner_drop_key();
DROP PROCEDURE owner_drop_key;
DROP PROCEDURE owner_make_key;
DROP USER 'kr_owner'@'%';
