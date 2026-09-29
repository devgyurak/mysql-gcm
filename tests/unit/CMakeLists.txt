# Standalone build for the pure-logic unit tests: gcm.cc / envelope.cc / nonce.cc link against
# libcrypto only, with no server headers, so the tests run without a MySQL tree
# (component-src rule). The component itself is built in-tree by src/CMakeLists.txt.
cmake_minimum_required(VERSION 3.20)
project(gcm_unit CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GCM_SANITIZE "Build the unit tests with ASan + UBSan" ON)
if(GCM_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(OpenSSL 3.0 REQUIRED)

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

add_library(gcm_core
  ${GCM_SRC_DIR}/gcm.cc
  ${GCM_SRC_DIR}/envelope.cc
  ${GCM_SRC_DIR}/nonce.cc
)
target_include_directories(gcm_core PUBLIC ${GCM_SRC_DIR})
target_link_libraries(gcm_core PUBLIC OpenSSL::Crypto)
# Same flags the server tree uses for components: errors are return values, not exceptions.
target_compile_options(gcm_core PRIVATE -Wall -Wextra -Werror -fno-exceptions)

add_executable(gcm_unit
  vectors.cc
  envelope_test.cc
  nonce_test.cc
  gcm_test.cc
)
target_include_directories(gcm_unit PRIVATE ${GCM_REPO_ROOT}/third_party)
target_compile_definitions(gcm_unit PRIVATE GCM_REPO_ROOT="${GCM_REPO_ROOT}")
target_compile_options(gcm_unit PRIVATE -Wall -Wextra -Werror)
target_link_libraries(gcm_unit PRIVATE gcm_core GTest::gtest_main)

# enable_testing() must come first: without it CMake writes no CTestTestfile.cmake and
# `ctest` reports "No tests were found" while still exiting 0 — a green gate that ran
# nothing.
enable_testing()

# One ctest entry for the whole binary, deliberately, instead of gtest_discover_tests.
#
# The suite is parameterised over spec/test-vectors.json, so the parameter lists are
# built during static initialisation: loading and parsing 783 vectors under ASan costs
# ~24 s before main() runs. gtest_discover_tests pays that once for discovery and then
# once more per case, and there are 1434 cases — on a four-core runner that is hours.
# Running the binary once pays it a single time: ~41 s in total, of which ~18 s is the
# tests themselves.
#
# The cost is coarser reporting from ctest. gtest still names the failing case in its own
# output, and --output-on-failure surfaces it, so nothing is actually lost. A single case
# is still reachable directly: build/unit/gcm_unit --gtest_filter='DetNonce.*'
add_test(NAME gcm_unit COMMAND gcm_unit)
set_tests_properties(gcm_unit PROPERTIES
  WORKING_DIRECTORY ${GCM_REPO_ROOT}
  TIMEOUT 900
)
