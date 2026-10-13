-- per-major-expected
-- nested-uninstall: probe
--
-- Neither nesting nor a bound parameter is needed. All it takes is a prepared
-- statement whose **re-prepare at EXECUTE** fails after a loadable function has been
-- fixed: ALTER TABLE invalidates the prepared statement, and the failing column makes
-- the second EXECUTE fail after the function has been fixed again. The second half is
-- the control, in the same prepared form but with the failing column first in the
-- field list, so its re-prepare fails before the function is fixed. (Issue #43; the
-- cause is in docs/upstream-udf-handler-leak.md.)
SELECT '# Given: two tables and a prepared statement that calls a function on one of its columns';
DROP TABLE IF EXISTS nested_t, nested_t2;
CREATE TABLE nested_t (d VARCHAR(10), c VARCHAR(10));
CREATE TABLE nested_t2 (d VARCHAR(10), c VARCHAR(10));
INSERT INTO nested_t VALUES ('d1', 'c1');
INSERT INTO nested_t2 VALUES ('d1', 'c1');
PREPARE s FROM 'SELECT probe_outer(d), c FROM nested_t';
EXECUTE s;
SELECT '# When: that column is dropped, and the statement is executed again';
ALTER TABLE nested_t DROP COLUMN c;
EXECUTE s;
DEALLOCATE PREPARE s;
SELECT CONCAT('after the failed re-prepare: ', probe_counts()) AS counts_after_the_leak;
SELECT '# And the control: the same prepared form, with the failing column first, so its';
SELECT '#       re-prepare fails before the function is ever fixed';
PREPARE s2 FROM 'SELECT c, probe_outer(d) FROM nested_t2';
EXECUTE s2;
ALTER TABLE nested_t2 DROP COLUMN c;
EXECUTE s2;
DEALLOCATE PREPARE s2;
SELECT CONCAT('after the control: ', probe_counts()) AS counts_after_the_control;
SELECT '# Then: probe_outer went to two inits and one deinit, and the control added one of';
SELECT '#       each — the leak needs the re-prepare to fail *after* the function is fixed';
