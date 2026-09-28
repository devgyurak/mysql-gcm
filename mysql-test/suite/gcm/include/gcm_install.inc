# Installs component_gcm and defines the shared fixture key.
# Sourced by every test in this suite; gcm_uninstall.inc undoes it, so each test
# cleans up after itself (testing rule).
--disable_query_log
INSTALL COMPONENT 'file://component_gcm';
# Public fixture key from spec/test-vectors.json — never a real key.
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
--enable_query_log
