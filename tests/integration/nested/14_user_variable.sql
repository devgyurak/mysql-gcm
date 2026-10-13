-- per-major-expected
-- nested-uninstall: gcm
--
-- A user variable has its value before the statement runs, unlike a `?` of a
-- prepared statement. This pins that the empty string the inner sees in 10 and 11
-- is specific to a bound parameter and not to any non-constant argument.
SELECT '# Given: the fixture key and the plaintext in a user variable';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @pt = 'x';
SELECT '# When: the nested call takes the user variable, with no prepared statement';
SELECT gcm_decrypt(gcm_encrypt(@pt, @k), @k) = @pt AS round_trip;
SELECT '# Then: 1 — a user variable arrives intact — and the uninstall succeeds';
