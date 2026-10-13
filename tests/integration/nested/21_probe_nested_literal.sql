-- per-major-expected
-- nested-uninstall: probe
--
-- The control for 20: the same nesting without a bound parameter, so nothing is
-- empty and the inner does not raise. If the counts in the after block do not match
-- here either, then the counting itself is the problem; if they do, the leak in 20
-- needs the raised error.
SELECT '# Given: the probe functions';
SELECT '# When: the inner, whose arguments are literals, is nested in the outer';
SELECT probe_outer(probe_raise_volatile('x', 'y'), 'y') AS nested_ok;
SELECT '# Then: every init has its deinit and the uninstall succeeds — literal arguments do not leak';
