-- per-major-expected
-- nested-uninstall: gcm
--
-- The other half of the defect, from the second comment on issue #43: the inner
-- call succeeds and the *outer* function's own init fails — here on an argument
-- count. Observed on 8.4.11 with #41's build (the inner was gcm_encrypt_kr over a
-- keyring id): UNINSTALL COMPONENT succeeded afterwards, unlike in 10 and 11.
SELECT '# Given: a keyring entry for the inner call and the fixture key';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
DO keyring_key_generate('it_nested', 'AES', 32);
SELECT '# When: the outer gcm_decrypt is given four arguments, so its init fails';
SELECT gcm_decrypt(gcm_encrypt_kr('x', 'it_nested'), @k, 'a', 'extra') AS never_reached;
SELECT '# Then: an argument-count error, and the after block records whether gcm uninstalls';
