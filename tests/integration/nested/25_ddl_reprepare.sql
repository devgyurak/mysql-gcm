-- per-major-expected
-- nested-uninstall: probe
--
-- Neither nesting nor a bound parameter is needed. All it takes is a statement whose
-- re-prepare fails after a loadable function has been fixed: ALTER TABLE invalidates
-- the prepared statement, and the failing column makes the second EXECUTE fail after
-- the function has been fixed again. The last statement is the control — the same
-- failing column, but first in the field list, so the fix never reaches the function.
-- (Issue #43; the cause is in docs/upstream-udf-handler-leak.md.)
SELECT '# Given: a table and a prepared statement that calls a function on one of its columns';
DROP TABLE IF EXISTS nested_t;
CREATE TABLE nested_t (d VARCHAR(10), c VARCHAR(10));
INSERT INTO nested_t VALUES ('d1', 'c1');
PREPARE s FROM 'SELECT probe_outer(d), c FROM nested_t';
EXECUTE s;
SELECT '# When: the column is dropped, and the statement is executed again';
ALTER TABLE nested_t DROP COLUMN c;
EXECUTE s;
DEALLOCATE PREPARE s;
SELECT '# And the control: the failing column first, which fails before the function is fixed';
SELECT c, probe_outer(d) FROM nested_t;
SELECT '# Then: probe_outer has two inits and one deinit — the failed second EXECUTE kept the';
SELECT '#       handler it fixed — and the control adds no init. The after block shows the refusal';
