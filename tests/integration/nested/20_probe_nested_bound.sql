-- per-major-expected
-- nested-uninstall: probe
--
-- The same shape as 10, with the probe component (tests/probe) instead of the
-- crypto functions, so the after block can count what the server did: probe_counts
-- prints the probe's init and deinit calls since probe_reset — the leak as an init
-- with no matching deinit. 8.0 differs from 8.4 and 9.x (see .expected).
SELECT '# Given: the probe functions, whose inner raises on an empty argument, and two parameters';
SET @a = 'x';
SET @b = 'y';
SELECT '# When: the inner is nested in the outer with a ? and the statement is EXECUTEd twice';
PREPARE s FROM 'SELECT probe_outer(probe_raise_volatile(?, ?), ?)';
EXECUTE s USING @a, @b, @b;
EXECUTE s USING @a, @b, @b;
DEALLOCATE PREPARE s;
SELECT '# Then: the inner has one init per EXECUTE and no deinit, so the component cannot be';
SELECT '#       uninstalled; on 8.0 the outer leaks too (see the per-major counts)';
