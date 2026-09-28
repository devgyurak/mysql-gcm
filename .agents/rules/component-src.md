---
paths:
  - "src/**"
  - "CMakeLists.txt"
---
# component 소스 규칙

- **component 만**. `mysql_declare_plugin`, `CREATE FUNCTION ... SONAME`, `#include <mysql/plugin.h>` 금지. 등록은 `udf_registration` 서비스, 설정은 `component_sys_variable_register`.
- 파일 책임·의존 방향·자원 수명은 `.agents/rules/architecture.md` 를 따른다.
- 인자 규약: `plaintext`/`ciphertext`/`key`/`aad` 모두 `STRING_RESULT` 로 강제 (`args->arg_type[i] = STRING_RESULT` in init). `key` 는 `args->lengths[1] == 32` 를 **호출마다** 검사 (init 시점엔 상수가 아닐 수 있다).
- `gcm_decrypt` 결과 charset: init 에서 `mysql_service_mysql_udf_metadata->result_set(initid, "charset", "utf8mb4")`. 평문 인자는 `argument_set(args, "charset", 0, "utf8mb4")` 로 서버가 변환하게 한다. 직접 문자셋 변환 코드 금지. `gcm_encrypt*` 결과는 `binary`.
- 결과 버퍼: `initid->ptr` 에 UDF 인스턴스별 힙 버퍼, `deinit` 에서 해제. 암호화의 `initid->max_length` 는 입력 최대 + 봉투 오버헤드(1+12+16), 복호화는 입력 봉투 길이를 상한으로 잡는다. 크기 계산은 architecture 규칙을 따른다.
- 새 서비스 의존은 `REQUIRES_SERVICE_PLACEHOLDER` + `BEGIN_COMPONENT_REQUIRES` 양쪽에 추가하고, 도입된 최소 MySQL 버전을 `docs/design.md` §8 표에 적는다.
- `init()` 실패는 롤백 후 1 을 반환한다. `deinit()` 에서 사용 중인 UDF 등록 해제가 실패하면 자원을 해제하지 않고 실패를 반환한다. 부분 성공 상태와 재시도는 architecture 규칙을 따른다.
- 컴파일: `-std=c++17 -Wall -Wextra -Werror -fno-exceptions` (서버 트리 기본). 예외를 던지지 않는다. 오류는 반환값.
- 빌드는 서버 소스 트리 in-tree (`MYSQL_ADD_COMPONENT`). 단독 CMake 는 `tests/unit` 에만.
- 각 함수의 SQL 동작(NULL 인자, 빈 문자열, 최대 길이, AAD 유무, 키 길이 오류)을 `mysql-test/suite/gcm` 과 `tests/integration` 양쪽에서 검증한다.
