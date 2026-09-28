# In-tree build only. docker/build-component.sh copies this directory to
# $MYSQL_SRC/components/gcm, where CONFIGURE_COMPONENTS() (cmake/component.cmake)
# globs components/* and adds it. The standalone CMake project lives in
# tests/unit and covers the three server-header-free files (component-src rule).
#
# MYSQL_ADD_COMPONENT(gcm ...) produces target component_gcm with PREFIX "" and
# OUTPUT_NAME component_gcm, i.e. plugin_output_directory/component_gcm.so.
# The server exposes its OpenSSL differently per version (cmake/ssl.cmake): 8.4 and
# 9.x define the imported target OpenSSL::Crypto, while 8.0 built with
# WITH_SSL=system defines no such target and only sets ${SSL_LIBRARIES}, adding the
# include directory globally. Either way this resolves to the libcrypto the server
# process itself loads — never a bundled or statically linked copy, which would
# collide on symbols and take the server down (crypto-safety rule).
if(TARGET OpenSSL::Crypto)
  set(GCM_CRYPTO_LIBRARIES OpenSSL::Crypto)
else()
  set(GCM_CRYPTO_LIBRARIES ${SSL_LIBRARIES})
endif()

MYSQL_ADD_COMPONENT(gcm
  component.cc
  udf_encrypt.cc
  udf_decrypt.cc
  udf_glue.cc
  sysvar.cc
  gcm.cc
  envelope.cc
  nonce.cc
  MODULE_ONLY
  LINK_LIBRARIES ${GCM_CRYPTO_LIBRARIES}
)
