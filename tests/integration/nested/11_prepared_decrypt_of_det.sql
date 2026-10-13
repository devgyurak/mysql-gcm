-- per-major-expected
-- nested-uninstall: gcm
--
-- The same shape with the deterministic inner function, which is the one that
-- claims const_item (its envelope depends only on key, plaintext and AAD, so the
-- server may fold it). If the server evaluates a constant argument during the
-- outer function's init, this shape should reproduce even when gcm_encrypt above
-- does not.
SELECT '# Given: the public fixture key and a plaintext bound with a prepared statement';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @pt = 'x';
SELECT '# When: EXECUTE evaluates gcm_encrypt_det first, as the argument of gcm_decrypt';
PREPARE s FROM 'SELECT gcm_decrypt(gcm_encrypt_det(?, ?), ?)';
EXECUTE s USING @pt, @k, @k;
DEALLOCATE PREPARE s;
SELECT '# Then: see .expected — the const_item variant may differ from 10 above';
