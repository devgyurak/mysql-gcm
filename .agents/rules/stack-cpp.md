---
paths:
  - "src/**"
  - "tests/unit/**"
  - "**/*.cc"
  - "**/*.h"
---
# C++ / CMake / OpenSSL 관례

- C++17, 서버 트리와 동일 플래그. 예외·RTTI 의존 금지. `-Werror`.
- RAII 래퍼로 OpenSSL 핸들 관리: `std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>` 패턴. 원시 new/delete·malloc 직접 사용은 `initid->ptr` 결과 버퍼에 한정하고 `deinit` 에서 짝을 맞춘다.
- 오류는 `enum class GcmError { ok, bad_envelope, bad_tag, key_unavailable, openssl_failure, ... }` 로 반환. 문자열 오류 금지 (메시지에 데이터가 섞이는 원인).
- 바이트는 `std::span<const unsigned char>` (C++20 불가 시 `const unsigned char*, size_t` 쌍). `std::string` 으로 바이너리를 옮기지 않는다.
- 상수는 `constexpr` 한 곳(`envelope.h`): `kVersionRandom`, `kVersionDet`, `kNonceLen=12`, `kTagLen=16`.
- 정적 분석: `clang-tidy` (`bugprone-*, cert-*, clang-analyzer-*, performance-*`), `clang-format` (Google 스타일 기반, 서버 트리 `.clang-format` 을 복사). CI 에서 강제.
  - **의도된 일탈 하나**: `ColumnLimit` 은 서버 트리의 80 이 아니라 **100** 이다. 이 저장소 코드가 100 기준으로
    작성돼 있고, 80 으로 다시 접으면 EVP 호출과 긴 시그니처가 심하게 쪼개져 실제 변경이 기계적 diff 에 묻힌다.
    `.clang-format` 머리에 같은 내용이 주석으로 있다. 되돌리지 말고, 바꾸려면 전체 재포맷을 별도 커밋으로.
- 업스트림 서버 트리에 기여할 목적이 아니므로 위 일탈이 문제되지 않는다. 그 외 설정은 서버 트리와 동일하게 유지한다.
- 단위 테스트 빌드는 `-fsanitize=address,undefined` 기본. 릴리스 빌드에서 켜지 않는다.
- 헤더 include 순서: 자기 헤더 → C 표준 → C++ 표준 → OpenSSL → MySQL 서비스 헤더. 허용 의존과 서버 헤더의 경계는 `architecture.md` 를 따른다.
- 주석은 "왜" 만. 설계 문서 절 번호를 인용 (`// design.md §5.5: tag failure must not degrade to NULL`).
