# Standalone build for the component *adapter* tests: component.cc, sysvar.cc and the UDF glue
# linked against stub services instead of a server (tests/adapter/service_stubs.h).
#
# This cannot live in tests/unit, which deliberately links only the server-independent core.
# These files include server headers, so this project has to be configured with the include
# paths of a MySQL source tree — which is why scripts/adapter-tests.sh runs it inside the build
# image rather than on the host.
cmake_minimum_required(VERSION 3.20)
project(gcm_adapter CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Supplied by scripts/adapter-tests.sh from the build image's MYSQL_SRC / MYSQL_BUILD. Both are
# needed: the checked-in headers live under the source tree, and mysqld_error.h and
# mysql_version.h are generated into the build tree.
set(GCM_MYSQL_SRC "" CACHE PATH "MySQL source tree root")
set(GCM_MYSQL_BUILD "" CACHE PATH "Configured MySQL build tree root")
if(NOT EXISTS "${GCM_MYSQL_SRC}/include/mysql/components/component_implementation.h")
  message(FATAL_ERROR "set GCM_MYSQL_SRC to a MySQL source tree (got '${GCM_MYSQL_SRC}')")
endif()
if(NOT EXISTS "${GCM_MYSQL_BUILD}/include/mysqld_error.h")
  message(FATAL_ERROR
    "set GCM_MYSQL_BUILD to a *built* MySQL tree: mysqld_error.h is generated, and "
    "scripts/adapter-tests.sh builds the component target first to produce it "
    "(got '${GCM_MYSQL_BUILD}')")
endif()

# Sanitizers off, unlike tests/unit. Two reasons: these tests are about control flow rather
# than memory safety, and ASan is the one configuration where the loader passes RTLD_NODELETE
# (design A9) — building the subject of that discussion under ASan would be a trap.
option(GCM_ADAPTER_SANITIZE "Build the adapter tests with ASan + UBSan" OFF)
if(GCM_ADAPTER_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(OpenSSL 3.0 REQUIRED)

# Pinned by URL and hash, the same release tests/unit pins.
find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

set(GCM_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
set(GCM_REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# Every source the component ships, including the adapters. The point of this target is the
# files tests/unit cannot take.
add_library(gcm_component_under_test
  ${GCM_SRC_DIR}/component.cc
  ${GCM_SRC_DIR}/sysvar.cc
  ${GCM_SRC_DIR}/udf_glue.cc
  ${GCM_SRC_DIR}/udf_encrypt.cc
  ${GCM_SRC_DIR}/udf_decrypt.cc
  ${GCM_SRC_DIR}/gcm.cc
  ${GCM_SRC_DIR}/envelope.cc
  ${GCM_SRC_DIR}/nonce.cc
)
target_include_directories(gcm_component_under_test PUBLIC
  ${GCM_SRC_DIR}
  ${GCM_MYSQL_SRC}/include
  ${GCM_MYSQL_BUILD}/include
)
target_link_libraries(gcm_component_under_test PUBLIC OpenSSL::Crypto)
# The same flags the server tree uses for components, so this builds the shipped code as
# shipped: errors are return values, not exceptions.
target_compile_options(gcm_component_under_test PRIVATE -Wall -Wextra -Werror -fno-exceptions)

add_executable(gcm_adapter
  service_stubs.cc
  lifecycle_test.cc
)
target_compile_options(gcm_adapter PRIVATE -Wall -Wextra -Werror)
target_link_libraries(gcm_adapter PRIVATE gcm_component_under_test GTest::gtest_main)

# enable_testing() must come first: without it CMake writes no CTestTestfile.cmake and `ctest`
# reports "No tests were found" while still exiting 0 — the same green-gate-that-ran-nothing
# that tests/unit documents.
enable_testing()

add_test(NAME gcm_adapter COMMAND gcm_adapter)
set_tests_properties(gcm_adapter PROPERTIES
  WORKING_DIRECTORY ${GCM_REPO_ROOT}
  TIMEOUT 300
)
