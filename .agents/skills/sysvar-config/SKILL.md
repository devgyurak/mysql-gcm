---
name: sysvar-config
description: component sysvar(gcm.strict) 등록·세션 스코프 읽기·my.cnf(loose_ 접두) 통합 절차. sysvar.cc 작성이나 SET SESSION/GLOBAL 동작 문제에 사용.
---

# sysvar-config

## 표면
| sysvar | 타입 | 스코프 | 기본 |
|---|---|---|---|
| `gcm.strict` | BOOL | MySQL 9.0+ GLOBAL + SESSION / 8.0·8.4 GLOBAL 전용 | ON |

**스코프는 선택이 아니다 (개정 A5, 실측 확인).** component sysvar 의 세션 스코프는 9.0.0 부터만
구현돼 있다. `sql/server_component/component_sys_var_service.cc` 에 `PLUGIN_VAR_THDLOCAL` 이
8.0.43·8.4.11 은 0회, 9.4.0 은 11회 등장한다. 8.x 에 THDLOCAL 을 넘기면 등록은 성공하지만 값 접근이
전역 변수 주소를 세션 저장소 offset 으로 해석해 **범위 밖 읽기**가 된다. 넘기지 않는다.

my.cnf: `loose_gcm.strict = ON`. `loose_` 없으면 component 설치 전 기동에서 "unknown variable" 로 실패한다 (design §6).

## 등록 — `src/sysvar.cc`
```cpp
#include <mysql_version.h>
#define GCM_HAS_SESSION_SYSVAR (MYSQL_VERSION_ID >= 90000)   // 개정 A5

bool gcm::sysvar_register() {                 // MySQL 관례: true = 실패
  BOOL_CHECK_ARG(bool) arg; arg.def_val = true;
  int flags = PLUGIN_VAR_BOOL;
#if GCM_HAS_SESSION_SYSVAR
  flags |= PLUGIN_VAR_THDLOCAL;               // 9.0+ 에서만
#endif
  return mysql_service_component_sys_variable_register->register_variable(
      "gcm", "strict", flags,
      "Raise an error (ON, default) or return NULL (OFF) when GCM tag verification fails",
      nullptr /*check*/, nullptr /*update*/, (void *)&arg, (void *)&g_strict);
}
```
`g_strict` 는 전역 `bool`. THDLOCAL 없이 등록하면 서버의 기본 update 함수
(`sql/sql_plugin_var.cc` 의 `update_func_bool`)가 이 전역에 직접 쓴다 → 8.0/8.4 는 **이 전역을 읽으면
된다**. 9.x 는 값이 세션 저장소에 있으므로 전역은 기본값만 제공한다.

## 세션 값 읽기 (UDF **init 에서 한 번**, 행마다 금지)
`component_sys_variable_register::get_variable` 은 **GLOBAL 전용**이다 — 헤더 주석과 구현
(`OPT_GLOBAL` 하드코딩) 모두 그렇다. 세션 값에는 쓸 수 없다. 9.0.0 에 신설된
`mysql_system_variable_reader` 가 유일한 수단이고, THD 는 `mysql_current_thread_reader` 로 얻는다.

```cpp
#if GCM_HAS_SESSION_SYSVAR
bool gcm::strict_enabled() {
  MYSQL_THD thd = nullptr;
  if (mysql_service_mysql_current_thread_reader->get(&thd) || thd == nullptr) return true;  // fail closed
  char buf[32] = {0}; char *value = buf; size_t len = sizeof(buf) - 1;
  if (mysql_service_mysql_system_variable_reader->get(thd, "SESSION", "gcm", "strict",
                                                      (void **)&value, &len)) return true;
  // BOOL 은 SHOW 표현("ON"/"OFF") 문자열로 돌아온다. 명시적 OFF 만 strict 를 끈다.
  return !(len >= 3 && std::strncmp(value, "OFF", 3) == 0);
}
#else
bool gcm::strict_enabled() { return g_strict; }   // 8.0/8.4: GLOBAL 값
#endif
```
- reader 는 `LOCK_system_variables_hash` read lock + 해시 룩업 + 문자열 변환을 거친다. **행마다 부르지
  않는다** — `Udf_func_init` 에서 한 번 읽어 `UDF_INIT::ptr` 에 캐시한다. `SET SESSION` 은 statement
  경계에서만 바뀌므로 의미론도 정확하다.
- `REQUIRES_SERVICE` 는 하드 의존이다. 8.x 빌드에서는 reader·thread_reader 를 REQUIRES 목록에서
  `#if` 로 빼야 하고, 그러지 않으면 `INSTALL COMPONENT` 가 의존성 오류로 실패한다.
- 참고 구현: 9.x 트리의 `components/test/test_session_var_service.cc`,
  `mysql-test/suite/service_sys_var_registration`.

## 검증 (통합 테스트에 그대로 들어간다, GWT)
버전별로 결과가 갈리므로 `tests/integration/31_strict_scope.sql` 은 `per-major-expected` 로 표시하고
`31_strict_scope.<major>.expected` 를 각각 둔다.

```sql
--echo # Given: a tampered envelope and gcm.strict at its default
SET @k = UNHEX('0001...1f');
SET @good = gcm_encrypt_det('홍길동', @k);
SET @bad = CONCAT(LEFT(@good, LENGTH(@good)-1), UNHEX('FF'));
--echo # When: strict is turned off at both scopes
SET GLOBAL gcm.strict = OFF;    -- 8.0/8.4 에서 세션에 적용된다
SET SESSION gcm.strict = OFF;   -- 8.0/8.4 는 ER_INCORRECT_GLOBAL_LOCAL_VAR, 9.x 는 성공
SELECT gcm_decrypt(@bad, @k) IS NULL AS null_when_strict_off;   -- 모든 버전에서 1
--echo # Then: 1 on every major, through whichever scope that major supports
```

실측 확인 (8.0.43 · 8.4.11 · 9.4.0):

| | 8.0 / 8.4 | 9.x |
|---|---|---|
| `SET SESSION gcm.strict` | `ER_INCORRECT_GLOBAL_LOCAL_VAR` (1229) | 성공 |
| `@@SESSION.gcm.strict` | `ER_INCORRECT_GLOBAL_LOCAL_VAR` (1238) | 값 반환 |
| `SET GLOBAL` 이 현재 세션에 미치는 영향 | 즉시 적용 | 없음 (세션이 자기 값을 갖는다) |
