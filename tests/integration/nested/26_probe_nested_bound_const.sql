-- per-major-expected
-- nested-uninstall: probe
--
-- The nested shape of case 20 with the probe's other variant: probe_raise_const
-- declares const_item, so the server may fold it, while probe_raise_volatile does
-- not. A difference between the two variants here would say that the eager
-- evaluation of a *constant* argument is what matters; the same counts say it is the
-- failed fix, not constness. (Issue #43.)
SELECT '# Given: the probe functions with the const variant as the inner, and two parameters';
SET @a = 'x';
SET @b = 'y';
SELECT '# When: the const inner is nested in the outer with a ? and the statement is EXECUTEd twice';
PREPARE s FROM 'SELECT probe_outer(probe_raise_const(?, ?), ?)';
EXECUTE s USING @a, @b, @b;
EXECUTE s USING @a, @b, @b;
DEALLOCATE PREPARE s;
SELECT '# Then: the same leak as case 20 — the inner has one init per EXECUTE and no deinit,';
SELECT '#       the component cannot be uninstalled, and the after block counts both';
