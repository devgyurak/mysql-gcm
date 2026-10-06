---
name: unit-tests
description: How to structure the GoogleTest (C++) unit tests and the internal vector-generation checks as GWT. Use it when working in tests/unit or on scripts/gen-vectors.py.
---

# unit-tests

The rule source is `.agents/rules/testing.md` (GWT is mandatory). This is the "how".

## 1. The vector file is the truth
The `spec/test-vectors.json` schema is in the docs rule. If it does not exist, build it in this order:
1. Convert only the `[Keylen=256][IVlen=96][Taglen=128]` blocks of the NIST CAVP
   `gcmEncryptExtIV256.rsp` / `gcmDecrypt256.rsp` from `gcmtestvectors.zip` as `kind:"nist"`
   (`scripts/import-nist.py`, with deterministic output and a fixed ordering).
2. Generate the project's own `kind:"det"|"random"` vectors with Python `cryptography`, fill in
   `envelope_hex`, and check that the C++ server core reproduces those values. Commit the generator
   too.
3. Failure vectors: `expect:"bad_tag"` (tampered tag), `"bad_envelope"` (truncated, or a bad version),
   `"bad_key_len"`.

## 2. C++ — `tests/unit` (no server)
```cmake
cmake_minimum_required(VERSION 3.20)
project(gcm_unit CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL 3.0 REQUIRED)
find_package(GTest REQUIRED)             # FetchContent if absent
add_library(gcm_core ../../src/gcm.cc ../../src/envelope.cc ../../src/nonce.cc)
target_include_directories(gcm_core PUBLIC ../../src)
target_link_libraries(gcm_core PUBLIC OpenSSL::Crypto)
target_compile_options(gcm_core PRIVATE -Wall -Wextra -Werror -fno-exceptions)
option(GCM_SANITIZE "ASan/UBSan" ON)
if(GCM_SANITIZE) add_compile_options(-fsanitize=address,undefined) add_link_options(-fsanitize=address,undefined) endif()
add_executable(gcm_unit envelope_test.cc nonce_test.cc gcm_test.cc vectors.cc)
target_link_libraries(gcm_unit gcm_core GTest::gtest_main)
enable_testing()
add_test(NAME gcm_unit COMMAND gcm_unit)
set_tests_properties(gcm_unit PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../.. TIMEOUT 900)
```
- Without `enable_testing()`, `ctest` prints "No tests were found" and **exits 0** — a gate that runs
  nothing. Do not use `gtest_discover_tests`: the vectors are parsed in static initialisation, so
  per-case discovery repeats that cost once per case (under ASan, running the binary once takes ~40 s
  while merely listing the cases takes ~24 s).
- `vectors.cc`: the JSON parser is a single header (nlohmann, pinned under `third_party/`). Failing to
  load the vectors is a test failure, not a skip.
- File mapping: `envelope_test.cc` (parsing boundaries), `nonce_test.cc` (derivation, collisions),
  `gcm_test.cc` (KAT, tampering, round trip).
- Parameterisation: `TEST_P(Kat, GivenNistVector_WhenSeal_ThenMatches)` plus
  `INSTANTIATE_TEST_SUITE_P`, using the vector id as the name.
- Collision bound: `GivenRandomPlaintexts_WhenDetNonce_ThenNoDuplicate` — N comes from the environment
  variable `GCM_COLLISION_N` (default 100k, 1M nightly).
- Verifying the cleanse: inspect the key-copy buffer after `open()`, reading through `volatile` so the
  compiler cannot optimise the check away.

Run: `cmake -S tests/unit -B build/unit && cmake --build build/unit -j && ctest --test-dir build/unit --output-on-failure`

## 3. The internal vector generator
After `python -m pip install -r scripts/requirements.txt`, run `python scripts/gen-vectors.py --check`.
It generates and verifies vectors for fixed inputs with `cryptography`. It does not expose an
application-facing encrypt/decrypt/parse API. The output file and every existing vector byte stay as
they are unless the crypto spec changes. The semantics of the failure inputs are verified by the C++
tests.

## Done when
- [ ] The C++ server tests consume every vector and the generator's `--check` passes
- [ ] GWT in both names and bodies, with zero tests that assert nothing
- [ ] No logic or branching (`if`, `else`, `for`, `while`) added inside a test case body; conditions are
      split into separate cases or expressed through the framework's parameterisation
- [ ] ASan/UBSan clean
