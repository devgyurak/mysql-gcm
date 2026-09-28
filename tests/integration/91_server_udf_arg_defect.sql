-- per-major-expected: behaviour legitimately differs between server majors,
-- so this case is compared against <name>.<major>.expected.
--
-- KNOWN SERVER DEFECT, not a component bug. Characterisation test.
--
-- For some *computed* string argument expressions, MySQL hands a loadable function
-- a stale view of the argument from the second row of a statement onward — wrong
-- bytes, or a length longer than the value. Built-in functions over the identical
-- expression always see the correct value, and an echo-only build of this
-- component (returning the argument untouched) sees the same corruption, so
-- nothing inside the component can detect or repair it. The marshalling code is
-- udf_handler::get_and_convert_string in sql/item_func.cc, which shallow-copies
-- the String an argument Item returned and then calls c_ptr_safe() on it; which
-- expression shapes trip it differs per version:
--
--   8.0.43 : REPEAT(str, non_constant_count) -> length inflated
--   8.4.11 : CONCAT / CONCAT_WS with an implicitly stringified operand -> byte 0
--   9.4.0  : neither shape reproduces
--
-- Asking the server to convert the argument (a different requested collation) was
-- measured to move the corruption rather than remove it, so the component asks
-- only for the charset its contract needs (utf8mb4) and this file records reality.
--
-- Impact: gcm_encrypt* would silently seal the wrong plaintext. What is reliably
-- safe on every major is a *materialised* value — a column, a literal, a user
-- variable or a bound parameter — which is how an application calls these
-- functions anyway. Wrapping in CAST is NOT a general fix: on 8.4 it fails at a
-- 16-byte plaintext, a String reallocation boundary. Scenario 3 pins the safe
-- shapes; docs/ops-constraints.md and README carry the constraint.
--
-- The assertions are booleans, so this file records "is the server still wrong"
-- instead of baking in corrupted bytes. A 0 turning into a 1 means that server
-- version was fixed; update this file and the docs when it happens.
SELECT '# Given: a table with a text column and an integer column';
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SET @pt = '홍길동';
CREATE TEMPORARY TABLE defect (id INT, nm VARCHAR(16)) CHARSET utf8mb4;
INSERT INTO defect VALUES (1, '김'), (2, '김'), (3, '김');
SELECT '# When: an argument expression implicitly stringifies the integer operand';
SELECT id,
       gcm_decrypt(gcm_encrypt_det(CONCAT(nm, id), @k), @k) = CONCAT(nm, id) AS concat_col_int,
       gcm_decrypt(gcm_encrypt_det(CONCAT_WS('-', nm, id), @k), @k) = CONCAT_WS('-', nm, id)
         AS concat_ws_col_int,
       gcm_decrypt(gcm_encrypt_det(LOWER(CONCAT(nm, id)), @k), @k) = LOWER(CONCAT(nm, id))
         AS wrapped_in_lower
FROM defect ORDER BY id;
SELECT '# Then: 1 everywhere except MySQL 8.4, which corrupts byte 0 (above)';

SELECT '# Scenario 2 — Given: the same table';
SELECT '# When: the integer is used as a repeat count instead of an operand';
SELECT id,
       gcm_decrypt(gcm_encrypt_det(REPEAT('a', id), @k), @k) = REPEAT('a', id) AS repeat_count
FROM defect ORDER BY id;
SELECT '# Then: 1 everywhere except MySQL 8.0, which inflates the length (above)';

SELECT '# Scenario 3 — Given: the same rows with the computed plaintext materialised';
CREATE TEMPORARY TABLE ready (id INT, pt VARCHAR(64)) CHARSET utf8mb4;
INSERT INTO ready SELECT id, CONCAT(nm, id) FROM defect;
SELECT '# When: the functions are called on materialised values only';
SELECT r.id,
       gcm_decrypt(gcm_encrypt_det(r.pt, @k), @k) = r.pt AS from_column,
       gcm_decrypt(gcm_encrypt_det('홍길동', @k), @k) = '홍길동' AS from_literal,
       gcm_decrypt(gcm_encrypt_det(@pt, @k), @k) = @pt AS from_user_variable
FROM ready r ORDER BY r.id;
SELECT '# Then: all 1 on every major — a column, a literal or a variable is always';
SELECT '#       safe, and that is what an application with bound parameters sends (above)';
DROP TEMPORARY TABLE ready;
DROP TEMPORARY TABLE defect;
