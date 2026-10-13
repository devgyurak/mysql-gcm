-- per-major-expected
-- nested-uninstall: gcm
--
-- The fork in issue #43's plan: is the defect reachable without a prepared
-- statement? Here the inner call has literal arguments, so the server has values
-- for all of them when it initialises the outer function — and the inner fails on
-- its own (the key is one byte). If the defect only needs the inner to raise while
-- the outer is being initialised, this reproduces the uninstall refusal with no
-- `?` anywhere.
SELECT '# Given: the fixture key and an inner gcm_encrypt_det whose key argument is one byte';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT '# When: the inner call is the argument of gcm_decrypt, with no prepared statement';
SELECT gcm_decrypt(gcm_encrypt_det('x', UNHEX('00')), @k) AS never_reached;
SELECT '# Then: the key-length error is expected either way — what the after block records is';
SELECT '#       whether gcm became uninstallable, with no bound parameter in the statement';
