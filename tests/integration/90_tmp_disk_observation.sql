-- design.md §5.3: does gcm_decrypt put plaintext into a disk-based temp table?
-- The counter itself is recorded by scripts/verify.sh into build/<ver>/tmp_disk.txt
-- (it is server- and version-dependent, so asserting on it here would be a false
-- gate). What this case asserts is that a decrypt-heavy sort and group still
-- returns the right rows.
SELECT '# Given: encrypted Korean names forced through a sort and a group by';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
CREATE TEMPORARY TABLE names (id INT, enc VARBINARY(128));
INSERT INTO names VALUES
  (1, gcm_encrypt_det('김일', @k)),
  (2, gcm_encrypt_det('김이', @k)),
  (3, gcm_encrypt_det('박삼', @k)),
  (4, gcm_encrypt_det('김사', @k));
SELECT '# When: the decrypted column drives ORDER BY, GROUP BY and LIKE at once';
SELECT LEFT(gcm_decrypt(enc, @k), 1) AS surname, COUNT(*) AS n
FROM names
WHERE gcm_decrypt(enc, @k) LIKE '김%'
GROUP BY LEFT(gcm_decrypt(enc, @k), 1)
ORDER BY n DESC, surname;
SELECT '# Then: three 김 rows group under one surname (above)';
DROP TEMPORARY TABLE names;
