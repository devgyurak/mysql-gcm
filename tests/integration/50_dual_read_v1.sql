-- Legacy v1 dual-read: an existing AES_ENCRYPT value prefixed with 0x01 and its IV
-- decrypts with gcm_decrypt and no re-encryption (docs/design.md amendment A3).
SELECT '# Given: a CBC ciphertext produced by the builtin AES_ENCRYPT with an explicit IV';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @iv = UNHEX('101112131415161718191a1b1c1d1e1f');
SET SESSION block_encryption_mode = 'aes-256-cbc';
SET @cbc = AES_ENCRYPT('홍길동', @k, @iv);
SET @v1 = CONCAT(UNHEX('01'), @iv, @cbc);
SELECT '# When: the v1 envelope is decrypted by the component';
SELECT gcm_decrypt(@v1, @k) AS plaintext,
       gcm_decrypt(@v1, @k) = CONVERT(AES_DECRYPT(@cbc, @k, @iv) USING utf8mb4) AS agrees_with_builtin,
       LENGTH(@v1) AS envelope_length,
       HEX(LEFT(@v1, 1)) AS version_byte;
SELECT '# Then: the same plaintext the builtin returns, from a 33 byte v1 envelope (above)';

SELECT '# Scenario 2 — Given: the same v1 envelope';
SELECT '# When: a non-empty AAD is supplied';
SELECT gcm_decrypt(@v1, @k, 'anything') AS never_reached;
SELECT '# Then: bad_envelope — v1 predates AAD and cannot bind one (errors section)';

SELECT '# Scenario 3 — Given: a v1 envelope whose ciphertext length is not a block multiple';
SELECT '# When: it is decrypted';
SELECT gcm_decrypt(CONCAT(UNHEX('01'), @iv, LEFT(@cbc, 15)), @k) AS never_reached;
SELECT '# Then: bad_envelope, regardless of gcm.strict (errors section)';

SELECT '# Scenario 5 — Given: a legacy column whose plaintext is latin1, not utf8mb4';
-- The migration in amendment A3 prefixes an existing AES_ENCRYPT value with 0x01||iv
-- and re-encrypts nothing, so the plaintext keeps the legacy column's encoding. The
-- result of gcm_decrypt is tagged utf8mb4 for every version, so a non-UTF-8 legacy
-- plaintext comes back ill-formed.
SET @latin1_v1 = CONCAT(UNHEX('01'), @iv, AES_ENCRYPT(CONVERT('Müller' USING latin1), @k, @iv));
SELECT '# When: it is decrypted and searched';
SELECT HEX(gcm_decrypt(@latin1_v1, @k)) AS decrypted_hex,
       gcm_decrypt(@latin1_v1, @k) LIKE '%ller%' AS like_on_the_ascii_tail;
SELECT '# Then: the bytes come back unchanged but LIKE returns 0 — no error, just a';
SELECT '#       silently failed search. This is why spec/envelope.md §2.3 requires a v1';
SELECT '#       plaintext to be utf8mb4 already: convert the legacy column before';
SELECT '#       prefixing 0x01||iv (above)';

SELECT '# Scenario 6 — Given: the same name migrated properly, i.e. converted first';
SET @utf8_v1 = CONCAT(UNHEX('01'), @iv,
                      AES_ENCRYPT(CONVERT(CONVERT('Müller' USING latin1) USING utf8mb4), @k, @iv));
SELECT '# When: that v1 envelope is decrypted and searched';
SELECT HEX(gcm_decrypt(@utf8_v1, @k)) AS decrypted_hex,
       gcm_decrypt(@utf8_v1, @k) LIKE '%ller%' AS like_on_the_ascii_tail,
       gcm_decrypt(@utf8_v1, @k) LIKE '%ü%' AS like_on_the_accented_char;
SELECT '# Then: both matches succeed (above)';

SELECT '# Scenario 4 — Given: v2, v3 and v1 values side by side, as during a migration';
CREATE TEMPORARY TABLE mixed (id INT, c VARBINARY(128));
INSERT INTO mixed VALUES (1, @v1), (2, gcm_encrypt('홍길동', @k)), (3, gcm_encrypt_det('홍길동', @k));
SELECT '# When: one query decrypts all three versions';
SELECT id, HEX(LEFT(c, 1)) AS version, gcm_decrypt(c, @k) AS plaintext FROM mixed ORDER BY id;
SELECT '# Then: dual-read works across versions with one function (above)';
DROP TEMPORARY TABLE mixed;
