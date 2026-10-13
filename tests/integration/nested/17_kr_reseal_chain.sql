-- per-major-expected
-- nested-uninstall: gcm
--
-- Amendment A15's re-seal example is this shape: gcm_encrypt_kr over
-- gcm_decrypt_kr, with the key id bound as a `?`. A15 says it is not established
-- whether the defect reaches it, because the inner call also has a column
-- argument, which may keep the server from evaluating it early (design.md A15,
-- "What it does not solve"). This case answers it. The re-sealed row is opened
-- again so the case ends in a boolean instead of printing raw ciphertext.
SELECT '# Given: a keyring entry, one sealed row, the plaintext, and the key id bound as a ?';
DO keyring_key_generate('it_chain', 'AES', 32);
SET @id = 'it_chain';
SET @pt = '홍길동';
CREATE TEMPORARY TABLE nested_reseal (id INT, c BLOB);
INSERT INTO nested_reseal VALUES (1, gcm_encrypt_kr(@pt, @id));
SELECT '# When: the A15 re-seal shape is prepared, with a ? in every key-id position';
PREPARE s FROM 'SELECT gcm_decrypt_kr(gcm_encrypt_kr(gcm_decrypt_kr(c, ?), ?), ?) = ? AS resealed FROM nested_reseal';
EXECUTE s USING @id, @id, @id, @pt;
DEALLOCATE PREPARE s;
SELECT '# Then: 1 if the re-sealed row opens again, and the after block says whether the';
SELECT '#       defect reached this shape';
DROP TEMPORARY TABLE nested_reseal;
