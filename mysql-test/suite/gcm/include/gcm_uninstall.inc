# Reverses gcm_install.inc, including any global sysvar a test changed.
--disable_query_log
SET GLOBAL gcm.strict = DEFAULT;
SET GLOBAL gcm.min_key_bytes = DEFAULT;
UNINSTALL COMPONENT 'file://component_gcm';
--enable_query_log
