-- per-major-expected
-- nested-uninstall: probe
--
-- The other control: a bound parameter with no nesting at all. The probe's init
-- sees no value (that is the A13 observation table), but the row function does, so
-- nothing raises and the counts should match.
SELECT '# Given: the probe functions and two parameters';
SET @a = 'x';
SET @b = 'y';
SELECT '# When: the function is called directly, with a ? and no outer function around it';
PREPARE s FROM 'SELECT probe_raise_volatile(?, ?)';
EXECUTE s USING @a, @b;
DEALLOCATE PREPARE s;
SELECT '# Then: the after block shows a bound parameter on its own is harmless';
