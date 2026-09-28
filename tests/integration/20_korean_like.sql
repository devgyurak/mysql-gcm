-- The reason this project exists: a decrypted value must be filterable with
-- MySQL's own LIKE and its own collation (docs/design.md §1.2, §5.3).
--
-- DO NOT DELETE ANY SCENARIO IN THIS FILE (.agents/rules/testing.md). If these
-- stop passing the component has no purpose.
SELECT '# Given: a deterministic envelope of a Korean name';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @c = gcm_encrypt_det('홍길동', @k);
SELECT '# When: the decrypted value is filtered with native LIKE';
SELECT gcm_decrypt(@c, @k) LIKE '%길%' AS infix_hit,
       gcm_decrypt(@c, @k) LIKE '홍%' AS prefix_hit,
       gcm_decrypt(@c, @k) LIKE '%동' AS suffix_hit,
       gcm_decrypt(@c, @k) LIKE '%박%' AS non_match,
       CHARSET(gcm_decrypt(@c, @k)) AS result_charset;
SELECT '# Then: infix/prefix/suffix hit, non-match misses, charset is utf8mb4 (above)';

SELECT '# Scenario 2 — Given: a Latin name encrypted deterministically';
SELECT '# When: filtered case-insensitively through the default collation';
SELECT gcm_decrypt(gcm_encrypt_det('Kim', @k), @k) LIKE '%kim%' AS ci_lower,
       gcm_decrypt(gcm_encrypt_det('Kim', @k), @k) LIKE '%KIM%' AS ci_upper,
       COLLATION(gcm_decrypt(gcm_encrypt_det('Kim', @k), @k)) AS result_collation;
SELECT '# Then: both match — MySQL collation does the work, not C code (above)';

SELECT '# Scenario 3 — Given: a table of encrypted Korean names';
CREATE TEMPORARY TABLE patients (id INT, name_enc VARBINARY(128));
INSERT INTO patients VALUES
  (1, gcm_encrypt_det('김철수', @k)),
  (2, gcm_encrypt_det('홍길동', @k)),
  (3, gcm_encrypt_det('박길수', @k));
SELECT '# When: the server searches for the partial match %길%';
SELECT id FROM patients WHERE gcm_decrypt(name_enc, @k) LIKE '%길%' ORDER BY id;
SELECT '# Then: rows 2 and 3 match server-side, no rows shipped to the client (above)';
DROP TEMPORARY TABLE patients;
