-- per-major-expected
-- nested-uninstall: gcm
--
-- The instance that is dropped need not have raised anything. Here the key-id
-- function seals successfully while the outer function's init evaluates it, and the
-- statement then fails on another function's error. Two things follow, and the case
-- prints both: the seal is never folded (design A14 already says a count is a lower
-- bound), and the instance that holds the key read from the keyring is never
-- de-initialised, so nothing wipes it — amendment A16 gives up the secrets of the
-- instance that *raises*, and this one did not raise. (Issue #43; the cause is in
-- docs/upstream-udf-handler-leak.md.)
SELECT '# Given: a key in the keyring';
SELECT keyring_key_generate('it_nested_silent', 'AES', 32) AS key_generated;
SET @a = 'x';
SELECT '# When: a key-id seal is evaluated inside an outer function, and another function raises in the same select list';
PREPARE s FROM 'SELECT LENGTH(probe_outer(gcm_encrypt_kr(?, ''it_nested_silent''))), probe_outer(probe_raise_volatile(?, ?), ?)';
EXECUTE s USING @a, @a, @a, @a;
DEALLOCATE PREPARE s;
SELECT CONCAT('random_seals after the failed statement: ',
              JSON_EXTRACT(gcm_key_usage('it_nested_silent'), '$.random_seals'));
SELECT '# And one plain seal of the same key, for what a folded count looks like';
SELECT CONCAT('envelope length: ', LENGTH(gcm_encrypt_kr('x', 'it_nested_silent')));
SELECT CONCAT('random_seals after it: ',
              JSON_EXTRACT(gcm_key_usage('it_nested_silent'), '$.random_seals'));
SELECT '# Then: the first line is 0 — the seal inside the leaked instance was lost — the second is 1,';
SELECT '#       and the after block shows gcm unable to uninstall, so the instance is still held';
