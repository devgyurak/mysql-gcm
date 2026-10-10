# Micro-benchmarks for the server-independent core, built the way the component is built
# rather than the way the unit tests are.
#
# Separate from tests/unit on purpose. That build turns ASan and UBSan on by default, which
# is right for correctness and useless for timing: the sanitizers change the cost of every
# load, store and allocation, so a number measured under them says nothing about the .so
# that ships. Here sanitizers are off and the optimisation level matches the component.
cmake_minimum_required(VERSION 3.20)
project(gcm_bench CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# RelWithDebInfo is what the server tree builds components with, so the inlining and the
# optimisation level are the ones that reach production.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

# Guarded rather than absent: a sanitizer build is occasionally useful for chasing a
# benchmark that crashes, and leaving no switch invites someone to edit the file.
option(GCM_BENCH_SANITIZE "Build the benchmarks with ASan + UBSan (timings become meaningless)" OFF)
if(GCM_BENCH_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(OpenSSL 3.0 REQUIRED)

# Pinned by URL and hash, like GoogleTest in tests/unit: a benchmark dependency resolved
# from a moving ref would change the numbers without changing the repository.
find_package(benchmark QUIET)
if(NOT benchmark_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    googlebenchmark
    URL https://github.com/google/benchmark/archive/refs/tags/v1.9.4.tar.gz
    URL_HASH SHA256=b334658edd35efcf06a99d9be21e4e93e092bd5f95074c1673d5c8705d95c104
  )
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googlebenchmark)
endif()

set(GCM_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

add_library(gcm_core_bench
  ${GCM_SRC_DIR}/gcm.cc
  ${GCM_SRC_DIR}/envelope.cc
  ${GCM_SRC_DIR}/nonce.cc
)
target_include_directories(gcm_core_bench PUBLIC ${GCM_SRC_DIR})
target_link_libraries(gcm_core_bench PUBLIC OpenSSL::Crypto)
target_compile_options(gcm_core_bench PRIVATE -Wall -Wextra -Werror -fno-exceptions)

add_executable(gcm_bench
  bench_main.cc
  bench_support.cc
  bench_gcm.cc
  bench_nonce.cc
  bench_envelope.cc
)
target_compile_options(gcm_bench PRIVATE -Wall -Wextra -Werror)
target_link_libraries(gcm_bench PRIVATE gcm_core_bench benchmark::benchmark)
