-- per-major-expected
-- nested-uninstall: gcm
--
-- The shape issue #43 was filed with. The inner call takes bound parameters, and a
-- prepared statement re-prepares a UDF on every EXECUTE, so the server evaluates
-- the inner call while initialising the outer one — before the parameters have
-- their values. The inner sees the empty string.
SELECT '# Given: the public fixture key and a plaintext bound with a prepared statement';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @pt = 'x';
SELECT '# When: EXECUTE evaluates gcm_encrypt first, as the argument of gcm_decrypt';
PREPARE s FROM 'SELECT gcm_decrypt(gcm_encrypt(?, ?), ?)';
EXECUTE s USING @pt, @k, @k;
DEALLOCATE PREPARE s;
SELECT '# Then: the statement either fails with a key-length error, which is the defect, or';
SELECT '#       round-trips — and the after block records whether gcm was still uninstallable';
