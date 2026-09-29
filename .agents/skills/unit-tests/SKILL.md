---
name: unit-tests
description: GoogleTest(C++) 단위 테스트와 내부 벡터 생성 검증을 GWT 구조로 구성하는 절차. tests/unit 또는 scripts/gen-vectors.py 작업에 사용.
---

# unit-tests

규칙 원본: `.agents/rules/testing.md` (GWT 필수). 여기는 "어떻게".

## 1. 벡터 파일이 진실
`spec/test-vectors.json` 스키마 (docs 규칙 참조). 없으면 이 순서로 만든다:
1. NIST CAVP `gcmtestvectors.zip` 의 `gcmEncryptExtIV256.rsp` / `gcmDecrypt256.rsp` 에서 `[Keylen=256][IVlen=96][Taglen=128]` 블록만 `kind:"nist"` 로 변환 (`scripts/import-nist.py`, 결정적 출력·정렬 고정).
2. 자체 벡터 `kind:"det"|"random"` 은 Python `cryptography` 로 생성해 `envelope_hex` 를 채우고, C++ 서버 코어가 그 값을 재현하는지 검증. 생성 스크립트도 커밋.
3. 실패 벡터: `expect:"bad_tag"`(태그 변조) / `"bad_envelope"`(잘림·version) / `"bad_key_len"`.

## 2. C++ — `tests/unit` (서버 없이)
```cmake
cmake_minimum_required(VERSION 3.20)
project(gcm_unit CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL 3.0 REQUIRED)
find_package(GTest REQUIRED)             # 없으면 FetchContent
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
- `enable_testing()` 없이는 `ctest` 가 "No tests were found" 를 출력하면서 **0 으로 종료**한다 — 게이트가 아무것도
  실행하지 않는다. `gtest_discover_tests` 는 쓰지 않는다: 벡터를 정적 초기화에서 파싱하므로 케이스별 discovery 가
  그 비용을 케이스 수만큼 되풀이한다(ASan 에서 바이너리 하나 실행 ~40초 vs 목록 조회만 ~24초).
- `vectors.cc`: JSON 파서는 단일 헤더(nlohmann 을 `third_party/` 에 핀). 벡터 로드 실패는 테스트 실패(스킵 아님).
- 파일 대응: `envelope_test.cc`(파싱 경계), `nonce_test.cc`(유도·충돌), `gcm_test.cc`(KAT·변조·왕복).
- 파라미터화: `TEST_P(Kat, GivenNistVector_WhenSeal_ThenMatches)` + `INSTANTIATE_TEST_SUITE_P` 벡터 id 를 이름으로.
- 충돌 경계: `GivenRandomPlaintexts_WhenDetNonce_ThenNoDuplicate` — N 은 env `GCM_COLLISION_N` (기본 100k, nightly 1M).
- 소거 검증: 키 복사본 버퍼를 `open()` 후 검사 — 컴파일러가 최적화로 지우지 못하게 `volatile` 읽기.

실행: `cmake -S tests/unit -B build/unit && cmake --build build/unit -j && ctest --test-dir build/unit --output-on-failure`

## 3. 내부 벡터 생성 도구
`python -m pip install -r scripts/requirements.txt` 후 `python scripts/gen-vectors.py --check`.
`cryptography` 로 고정 입력의 벡터를 생성·검증한다. 애플리케이션용 encrypt/decrypt/parse API 는 제공하지 않는다.
출력 파일과 모든 기존 벡터 바이트는 암호 스펙 변경이 없는 한 유지한다. 실패 입력의 의미론은 C++ 테스트에서 검증한다.

## 완료 조건
- [ ] C++ 서버 테스트가 모든 벡터를 소비하고 생성기 `--check` 통과
- [ ] 이름·본문 GWT, 단언 없는 테스트 0
- [ ] 테스트 케이스 본문에 `if`·`else`·`for`·`while` 같은 로직·분기 추가 없음; 조건별 케이스 분리 또는 프레임워크 파라미터화 사용
- [ ] ASan/UBSan clean
