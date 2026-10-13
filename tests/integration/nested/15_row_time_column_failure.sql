-- per-major-expected
-- nested-uninstall: gcm
--
-- The control for a failure that is not during the outer function's init: the
-- inner call's key comes from a column, so it is evaluated per row, after the
-- outer's init has already succeeded. Row 2's key is one byte and the inner
-- raises there. If the uninstall is refused here too, then "raises while the outer
-- is being initialised" is not what the refusal needs.
SELECT '# Given: the fixture key, a table, and one row whose key is a single byte';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
CREATE TEMPORARY TABLE nested_keys (id INT, k VARBINARY(32));
INSERT INTO nested_keys VALUES (1, @k), (2, UNHEX('00'));
SELECT '# When: the nested call reads the key from the column, one row at a time';
SELECT id, gcm_decrypt(gcm_encrypt('x', k), @k) IS NOT NULL AS sealed
FROM nested_keys ORDER BY id;
SELECT '# Then: row 1 seals and row 2 fails at row time — the after block is the control';
DROP TEMPORARY TABLE nested_keys;
