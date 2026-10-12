-- The key-id functions (docs/design.md amendment A13): the key is read from the
-- keyring under the calling account, so it is never an argument here. Same
-- envelopes as the key-argument functions, which scenario 4 pins.
SELECT '# Given: an AES-256 key generated inside the keyring';
DO keyring_key_generate('it_name_v1', 'AES', 32);
SELECT '# When: a Korean name is sealed and opened by key id';
SET @c = gcm_encrypt_kr('홍길동', 'it_name_v1');
SELECT gcm_decrypt_kr(@c, 'it_name_v1') AS round_trip,
       HEX(LEFT(@c, 1)) AS version_byte,
       LENGTH(@c) - LENGTH('홍길동') AS overhead,
       CHARSET(gcm_decrypt_kr(@c, 'it_name_v1')) AS result_charset,
       gcm_encrypt_kr('홍길동', 'it_name_v1') = @c AS same_bytes_twice;
SELECT '# Then: the name, version 02, 29 bytes of overhead, utf8mb4, a fresh nonce per call (above)';

SELECT '# Scenario 2 — Given: a table of names sealed by key id';
CREATE TEMPORARY TABLE patients (id INT, name_enc VARBINARY(128));
INSERT INTO patients VALUES
  (1, gcm_encrypt_kr('김철수', 'it_name_v1')),
  (2, gcm_encrypt_kr('홍길동', 'it_name_v1')),
  (3, gcm_encrypt_kr('박길수', 'it_name_v1'));
SELECT '# When: the server searches for the partial match %길%';
SELECT id FROM patients WHERE gcm_decrypt_kr(name_enc, 'it_name_v1') LIKE '%길%' ORDER BY id;
SELECT '# Then: rows 2 and 3 — native LIKE works with no key in the statement (above)';
DROP TEMPORARY TABLE patients;

SELECT '# Scenario 3 — Given: the deterministic variant under the same key id';
SET @d = gcm_encrypt_det_kr('EMR-001', 'it_name_v1');
SELECT '# When: the same value is sealed again, and a different one';
SELECT gcm_encrypt_det_kr('EMR-001', 'it_name_v1') = @d AS equal_plaintexts_equal_envelopes,
       gcm_encrypt_det_kr('EMR-002', 'it_name_v1') = @d AS different_plaintexts,
       HEX(LEFT(@d, 1)) AS version_byte,
       gcm_decrypt_kr(@d, 'it_name_v1') AS opens;
SELECT '# Then: equal, not equal, version 03, and it opens (above)';

SELECT '# Scenario 4 — Given: the same key bytes used as a key argument';
SELECT '# When: each family opens what the other sealed';
SELECT gcm_decrypt(gcm_encrypt_kr('홍길동', 'it_name_v1'), keyring_key_fetch('it_name_v1')) AS kr_sealed_arg_opened,
       gcm_decrypt_kr(gcm_encrypt('홍길동', keyring_key_fetch('it_name_v1')), 'it_name_v1') AS arg_sealed_kr_opened,
       gcm_encrypt_det('EMR-001', keyring_key_fetch('it_name_v1')) = @d AS det_bytes_identical;
SELECT '# Then: both open and the deterministic bytes are identical — one envelope format (above)';

SELECT '# Scenario 5 — Given: a value sealed by key id with an AAD';
SET @a = gcm_encrypt_kr('홍길동', 'it_name_v1', 'patients.name');
SELECT '# When: it is opened with the same AAD, then with another';
SELECT gcm_decrypt_kr(@a, 'it_name_v1', 'patients.name') AS same_aad;
SELECT gcm_decrypt_kr(@a, 'it_name_v1', 'patients.other') AS never_reached;
SELECT '# Then: the name, then a tag error (errors section)';

SELECT '# Scenario 6 — Given: an AES-128 key in the keyring and the default floor of 32';
DO keyring_key_generate('it_short', 'AES', 16);
SELECT '# When: it is used to seal';
SELECT gcm_encrypt_kr('x', 'it_short') AS never_reached;
SELECT '# Then: refused by gcm.min_key_bytes, naming the floor and not the key (errors section)';

SELECT '# Scenario 7 — Given: the floor lowered to 16';
SET GLOBAL gcm.min_key_bytes = 16;
SET @s = gcm_encrypt_kr('홍길동', 'it_short');
SET GLOBAL gcm.min_key_bytes = DEFAULT;
SELECT '# When: the value is opened after the floor is back at 32';
SELECT HEX(LEFT(@s, 1)) AS version_byte, gcm_decrypt_kr(@s, 'it_short') AS opens;
SELECT '# Then: version 04, and decryption never consults the floor (above)';

SELECT '# Scenario 8 — Given: a legacy 0x01 envelope whose key is in the keyring';
SET @iv = UNHEX('101112131415161718191a1b1c1d1e1f');
SET SESSION block_encryption_mode = 'aes-256-cbc';
SET @v1 = CONCAT(UNHEX('01'), @iv, AES_ENCRYPT('홍길동', keyring_key_fetch('it_name_v1'), @iv));
SELECT '# When: it is opened by key id';
SELECT gcm_decrypt_kr(@v1, 'it_name_v1') AS legacy_plaintext;
SELECT '# Then: the name — gcm_decrypt_kr reads everything gcm_decrypt reads (above)';

SELECT '# Scenario 9 — Given: the empty string and a 64 KB value';
SET @empty = gcm_encrypt_kr('', 'it_name_v1');
SET @big = gcm_encrypt_det_kr(REPEAT('가', 21845), 'it_name_v1');
SELECT '# When: each is sealed and opened by key id';
SELECT LENGTH(@empty) AS empty_envelope_length,
       gcm_decrypt_kr(@empty, 'it_name_v1') = '' AS empty_round_trip,
       LENGTH(@big) - 65535 AS big_overhead,
       gcm_decrypt_kr(@big, 'it_name_v1') = REPEAT('가', 21845) AS big_round_trip;
SELECT '# Then: a 29 byte envelope that opens to the empty string, and 29 bytes over 65535 that open intact (above)';
