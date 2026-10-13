-- per-major-expected
-- nested-uninstall: gcm
--
-- The control for 12: the same literal, failing inner call, but with the random
-- variant, which does not claim const_item. If 12 refuses the uninstall and this
-- one does not, the trigger is the eager evaluation of a *constant* inner argument
-- and not the raising itself.
SELECT '# Given: the fixture key and an inner gcm_encrypt whose key argument is one byte';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT '# When: the inner call is the argument of gcm_decrypt, with no prepared statement';
SELECT gcm_decrypt(gcm_encrypt('x', UNHEX('00')), @k) AS never_reached;
SELECT '# Then: the key-length error is expected and the uninstall succeeds, as in 12';
