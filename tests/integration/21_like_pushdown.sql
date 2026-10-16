-- Index condition pushdown over the loadable function, and the scope that keeps the
-- decrypting call off the rows outside it. The recipes this backs are in
-- docs/like-recipes.md; the plan shape itself is pinned in mysql-test/suite/gcm
-- (gcm_pushdown), which only records against 8.4.
--
-- The behaviour here is the same on every supported major, so there is one .expected:
-- when a `gcm_decrypt(col, @k) LIKE` predicate is pushed into a `(dept_id, name_enc)`
-- index read, the index still returns the right rows for healthy data, a tampered row
-- *inside* the scope is not hidden (strict=ON is an error), and the rows outside the
-- scope are never decrypted at all. That the predicate really is pushed into the index
-- read — the plan — is pinned separately by mysql-test/suite/gcm/t/gcm_pushdown.test,
-- which records against 8.4 only.
SELECT '# Given: a scoped table with an index on (dept_id, name_enc)';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
CREATE TABLE pushdown_names (
  id INT AUTO_INCREMENT PRIMARY KEY,
  dept_id INT NOT NULL,
  name_enc VARBINARY(128) NOT NULL,
  note VARCHAR(64) NOT NULL,
  KEY ix_dept_name (dept_id, name_enc)
) ENGINE=InnoDB;
INSERT INTO pushdown_names (dept_id, name_enc, note) VALUES
  (1, gcm_encrypt_det('김철수', @k), 'in-scope-a'),
  (1, gcm_encrypt_det('홍길동', @k), 'in-scope-b'),
  (1, gcm_encrypt_det('박길수', @k), 'in-scope-c'),
  (2, gcm_encrypt_det('김길희', @k), 'other-scope-a'),
  (2, gcm_encrypt_det('이길동', @k), 'other-scope-b'),
  (2, gcm_encrypt_det('최길순', @k), 'other-scope-c');

SELECT '# Scenario 1 — When: a scoped search is forced through the index';
SELECT id, note FROM pushdown_names FORCE INDEX (ix_dept_name)
 WHERE dept_id = 1 AND gcm_decrypt(name_enc, @k) LIKE '%길%'
 ORDER BY id;
SELECT '# Then: the two in-scope 길 rows, taken through the index (above)';

SELECT '# Scenario 2 — Given: a tampered in-scope row that would match if it were intact';
SET @good = gcm_encrypt_det('최길동', @k);
SET @tampered = CONCAT(LEFT(@good, LENGTH(@good) - 1), UNHEX('FF'));
INSERT INTO pushdown_names (dept_id, name_enc, note) VALUES (1, @tampered, 'tampered-in-scope');
SELECT '# When: the same scoped search is forced through the index';
SELECT id, note FROM pushdown_names FORCE INDEX (ix_dept_name)
 WHERE dept_id = 1 AND gcm_decrypt(name_enc, @k) LIKE '%길%'
 ORDER BY id;
SELECT '# Then: a tag error — the row inside the scope is decrypted and rejected (errors section)';

SELECT '# Scenario 3 — When: a different scope is searched the same way';
SELECT id, note FROM pushdown_names FORCE INDEX (ix_dept_name)
 WHERE dept_id = 2 AND gcm_decrypt(name_enc, @k) LIKE '%길%'
 ORDER BY id;
SELECT '# Then: the three healthy other-scope rows — the tampered row is never decrypted (above)';

SELECT '# Scenario 4 — Given: a covering (dept_id, id, name_enc) index';
ALTER TABLE pushdown_names ADD INDEX ix_dept_id_name (dept_id, id, name_enc);
SELECT '# When: the newest page is forced through it';
SELECT id FROM pushdown_names FORCE INDEX (ix_dept_id_name)
 WHERE dept_id = 2 AND gcm_decrypt(name_enc, @k) LIKE '%길%'
 ORDER BY id DESC LIMIT 50;
SELECT '# Then: the same three matches, newest first (the plan is pinned in the MTR case)';

DROP TABLE pushdown_names;
