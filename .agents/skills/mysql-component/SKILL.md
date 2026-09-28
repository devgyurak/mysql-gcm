---
name: mysql-component
description: MySQL 8.0+ component 골격 작성·UDF 등록·charset 태깅·in-tree 빌드 절차. component.cc / udf_*.cc / CMakeLists.txt 를 만들거나 고칠 때, 서비스 매크로가 헷갈릴 때 사용.
---

# mysql-component

목표: legacy plugin 이 아닌 **component** 로 `gcm_encrypt` / `gcm_encrypt_det` / `gcm_decrypt` 를 등록하고, 서버 소스 트리 안에서 빌드한다.

## 절차
1. `docs/design.md` §2(개정 A1) · §5.1 과 `.agents/rules/component-src.md` 를 읽는다.
2. 서비스 API 가 조금이라도 불확실하면 `$MYSQL_SRC/include/mysql/components/services/*.h` 를 직접 열어 확인한다 (서브에이전트 `component-api-researcher`). 추측 금지.
3. 아래 골격을 채운다. 순수 로직은 `gcm-crypto` 스킬의 `gcm.cc` / `envelope.cc` / `nonce.cc` 를 호출만 한다.
4. `scripts/build-in-docker.sh <ver>` 로 빌드 → `dev-container` 스킬로 설치·검증.

## 필요한 서비스 (전부 `include/mysql/components/services/` 아래)
| 서비스 | 헤더 | 용도 | 최소 버전 |
|---|---|---|---|
| `udf_registration` | `udf_registration.h` | UDF 등록/해제 | 8.0.0 (WL#8020) |
| `mysql_udf_metadata` | `udf_metadata.h` | 결과·인자 charset 지정 | 8.0.19 (WL#12370) |
| `component_sys_variable_register` / `_unregister` | `component_sys_var_service.h` | `gcm.strict` | 8.0.0 |
| `mysql_runtime_error` | `mysql_runtime_error.h` | `my_error` 대체, 태그 실패 에러 | 8.0.x |

## 골격 — `src/component.cc`
```cpp
#include <mysql/components/component_implementation.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/components/services/udf_metadata.h>
#include <mysql/components/services/component_sys_var_service.h>
#include <mysql/components/services/mysql_runtime_error.h>

REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
REQUIRES_SERVICE_PLACEHOLDER(mysql_udf_metadata);
REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_register);
REQUIRES_SERVICE_PLACEHOLDER(component_sys_variable_unregister);
REQUIRES_SERVICE_PLACEHOLDER(mysql_runtime_error);

struct UdfSpec { const char *name; Item_result type; Udf_func_any fn; Udf_func_init init; Udf_func_deinit deinit; };
static const UdfSpec kUdfs[] = { /* gcm_encrypt, gcm_encrypt_det, gcm_decrypt */ };

static mysql_service_status_t gcm_init() {
  if (gcm::crypto_init())  return 1;          // EVP_CIPHER_fetch / EVP_MAC_fetch, 실패 시 1
  if (gcm::sysvar_register()) { gcm::crypto_deinit(); return 1; }
  size_t done = 0;
  for (auto &u : kUdfs) {
    if (mysql_service_udf_registration->udf_register(u.name, u.type, u.fn, u.init, u.deinit)) {
      for (size_t i = 0; i < done; ++i) { int was_present = 0; mysql_service_udf_registration->udf_unregister(kUdfs[i].name, &was_present); }
      gcm::sysvar_unregister(); gcm::crypto_deinit(); return 1;   // 절반 등록 상태로 성공 반환 금지
    }
    ++done;
  }
  return 0;
}
static mysql_service_status_t gcm_deinit() {
  for (auto &u : kUdfs) { int was_present = 0;
    if (mysql_service_udf_registration->udf_unregister(u.name, &was_present) && was_present) return 1; } // 사용 중이면 실패
  gcm::sysvar_unregister(); gcm::crypto_deinit(); return 0;
}

BEGIN_COMPONENT_PROVIDES(component_gcm)
END_COMPONENT_PROVIDES();

BEGIN_COMPONENT_REQUIRES(component_gcm)
  REQUIRES_SERVICE(udf_registration),
  REQUIRES_SERVICE(mysql_udf_metadata),
  REQUIRES_SERVICE(component_sys_variable_register),
  REQUIRES_SERVICE(component_sys_variable_unregister),
  REQUIRES_SERVICE(mysql_runtime_error),
END_COMPONENT_REQUIRES();

BEGIN_COMPONENT_METADATA(component_gcm)
  METADATA("mysql.author", "mysql-gcm contributors"),
  METADATA("mysql.license", "GPL"),
END_COMPONENT_METADATA();

DECLARE_COMPONENT(component_gcm, "mysql:component_gcm")
  gcm_init, gcm_deinit
END_DECLARE_COMPONENT();

DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(component_gcm) END_DECLARE_LIBRARY_COMPONENTS
```

## UDF 글루 — `src/udf_decrypt.cc` 요지
```cpp
extern "C" bool gcm_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count < 2 || args->arg_count > 3) { strcpy(msg, "gcm_decrypt(ciphertext, key [, aad])"); return true; }
  for (unsigned i = 0; i < args->arg_count; ++i) args->arg_type[i] = STRING_RESULT;
  if (mysql_service_mysql_udf_metadata->result_set(initid, "charset", const_cast<char *>("utf8mb4"))) { strcpy(msg, "cannot set result charset"); return true; }
  initid->maybe_null = true;                       // strict=OFF 경로
  initid->max_length = args->lengths[0];           // 평문 <= 봉투
  initid->ptr = static_cast<char *>(malloc(initid->max_length + 1));
  return initid->ptr == nullptr;
}
extern "C" char *gcm_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length, unsigned char *is_null, unsigned char *error) {
  if (!args->args[0] || !args->args[1]) { *is_null = 1; return nullptr; }          // NULL 전파
  if (args->lengths[1] != gcm::kKeyLen) { gcm::raise(GcmError::bad_key_len); *error = 1; return nullptr; }
  // ... gcm::open(...) 호출, bad_tag 이면 sysvar strict 에 따라 raise 또는 is_null
}
extern "C" void gcm_decrypt_deinit(UDF_INIT *initid) { free(initid->ptr); }
```
- `gcm_encrypt*` 는 `result_set(initid, "charset", "binary")`, `max_length = lengths[0] + 1 + 12 + 16`.
- 평문 인자 charset 을 `argument_set(args, "charset", 0, "utf8mb4")` 로 요구해 서버가 변환하게 한다.

## 빌드 (in-tree)
`cmake/component.cmake` 의 `CONFIGURE_COMPONENTS()` 가 **configure 시점에** `components/*` 를 glob 하므로,
소스를 `$MYSQL_SRC/components/gcm` 에 두고 **cmake 를 다시 돌려야** 빌드 그래프에 들어온다. 읽기 전용
마운트에 심링크가 아니라 복사 + 재-configure 인 이유다 (`docker/build-component.sh`).

`MYSQL_ADD_COMPONENT(gcm ...)` 는 타깃 `component_gcm`, `PREFIX ""`, `OUTPUT_NAME component_gcm` →
`plugin_output_directory/component_gcm.so` 를 만든다.

```cmake
# OpenSSL 노출 방식이 버전마다 다르다: 8.4·9.x 는 imported target, 8.0(WITH_SSL=system)은 ${SSL_LIBRARIES}
if(TARGET OpenSSL::Crypto)
  set(GCM_CRYPTO_LIBRARIES OpenSSL::Crypto)
else()
  set(GCM_CRYPTO_LIBRARIES ${SSL_LIBRARIES})
endif()

MYSQL_ADD_COMPONENT(gcm
  component.cc udf_encrypt.cc udf_decrypt.cc udf_glue.cc sysvar.cc gcm.cc envelope.cc nonce.cc
  MODULE_ONLY
  LINK_LIBRARIES ${GCM_CRYPTO_LIBRARIES}   # 서버가 쓰는 동일 libcrypto — 정적 링크·번들 금지
)
```
```sh
scripts/build-in-docker.sh 8.4        # 산출물: build/8.4/component_gcm.so
```
전체 서버 빌드가 아니라 `--target component_gcm` 만 (의존으로 GenError·mysys·strings 정도가 따라온다).

**boost 와 컴파일러는 버전마다 다르다 (실측).**

| | 8.0.43 | 8.4.11 | 9.4.0 |
|---|---|---|---|
| boost | 외부 1.77 필요 → `mysql-boost-<ver>.tar.gz` + `-DWITH_BOOST=<src>/boost` | `extra/boost` 번들, 플래그 없음 | 같음 |
| RHEL9 컴파일러 (`ALTERNATIVE_PATHS`) | gcc-toolset-12 | gcc-toolset-12 | gcc-toolset-14 |

`-DDOWNLOAD_BOOST` 는 8.4·9.x 에 존재하지 않는다. 틀린 toolset 을 깔면 configure 가
"Could not find devtoolset compiler/linker" 로 실패하고, `readelf` 가 없으면 별도 오류가 난다
(`binutils`·`elfutils` 필요).

## 에러 보고
component 전용 에러 코드는 없다. `ER_UDF_ERROR`("%s UDF failed; %s")를
`mysql_error_service_printf(ER_UDF_ERROR, 0, func_name, detail)` 로 올리고 (`mysqld_error.h` +
`mysql_runtime_error_service.h`), 행 함수에서 `*error = 1` 을 세운다. 클라이언트에는
`ERROR 3200 (HY000)` 으로 보인다. `detail` 에는 길이와 version 바이트까지만 넣는다 — 키·평문·nonce·
태그·암호문 금지 (`spec/envelope.md` §4 rule 4).

## 흔한 실패
- `INSTALL COMPONENT` 가 "Cannot satisfy dependency" → REQUIRES 목록의 서비스가 해당 서버 버전에 없다.
  세션 sysvar 관련 두 서비스는 9.0+ 전용이다 (`sysvar-config` 스킬, 개정 A5). `docs/design.md` §8 표 확인.
- `.so` 는 로드되나 함수 없음 → `udf_register` 반환값을 버렸다. init 골격의 롤백 경로 확인.
- 한글 LIKE 가 0 → `result_set("charset")` 이 init 에서 호출되지 않았거나 `binary` 로 설정됨.
- 서버 크래시 → 전역 버퍼 공유 또는 `deinit` 누락. ASan 빌드로 재현.
- `docker cp` 가 "Could not find the file /usr/lib/mysql/plugin" → 이미지마다 `plugin_dir` 이 다르다
  (OL 기반 공식 이미지는 `/usr/lib64/mysql/plugin/`). `SELECT @@plugin_dir` 로 물어본다.
- 계산된 SQL 식을 인자로 넘긴 통합 테스트가 두 번째 행부터 틀린 평문을 낸다 → 서버 결함이다
  (개정 A7). 컬럼·리터럴·바인드 파라미터로 바꾼다. component 를 고쳐서 해결하려 하지 않는다.
- `#error This header shall not be included in components` → `mysql_com.h`·`my_io.h` 같은 서버 내부
  헤더를 include 했다. `MYSQL_ERRMSG_SIZE` 처럼 그 안의 상수가 필요하면 값을 복제하고 근거를 주석에 남긴다.
  **8.0·8.4 는 조용히 통과하고 9.x 에서만 실패하므로 세 버전 빌드를 모두 돌려야 잡힌다.**
- 결과가 잘리거나 `ERROR 1406 Data too long` → `initid->max_length` 가 너무 좁다. 원인이 두 가지다.
  ① **`args->lengths[i]` 는 charset 변환 *전* 길이다.** 평문 인자를 utf8mb4 로 요청하면 서버가 넓힌 뒤
  넘겨주므로 latin1 `VARCHAR(1)` 은 `lengths[0]=1` 인데 봉투는 31바이트다. 비엄격 SQL 모드에서는
  **조용히 잘려 저장되고 복호화가 실패**한다. 모든 charset 이 문자당 1바이트 이상이라는 점을 써서
  `4 × lengths[0]` 로 상한을 잡는다.
  ② 랩어라운드. 서버는 `min<uint32>(initid.max_length, MAX_BLOB_WIDTH)` 로 **uint32 로 먼저 자른다**
  (`sql/item_func.cc` 의 `udf_handler::fix_fields`). 덧셈을 포화시킨다 (`udf_glue.h` 의
  `envelope_max_length()`).
- 결정적 함수는 `initid->const_item = true` 로 두어야 상수 인자 조회가 인덱스를 탄다 (실측 `type=const`).
  무작위 함수는 절대 true 로 두지 않는다.
