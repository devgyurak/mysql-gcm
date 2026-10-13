-- per-major-expected
-- nested-uninstall: probe
--
-- The defect is not about nesting. A function that is a *sibling* of the one that
-- raises is dropped the same way: what matters is that the statement's re-prepare
-- fails after the sibling has already been fixed. (Issue #43; A13's
-- "Implementation notes"; the cause is read in
-- docs/upstream-udf-handler-leak.md.)
SELECT '# Given: two probe functions and four parameters';
SET @a = 'x';
SET @b = 'y';
SELECT '# When: a sibling function stands beside one whose inner raises, in one select list';
PREPARE s FROM 'SELECT probe_outer(?), probe_outer(probe_raise_volatile(?, ?), ?)';
EXECUTE s USING @a, @a, @b, @b;
DEALLOCATE PREPARE s;
SELECT '# Then: probe_outer has one init and no deinit — the sibling was dropped — and the';
SELECT '#       after block shows the component unable to uninstall';
