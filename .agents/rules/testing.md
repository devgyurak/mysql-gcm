---
paths:
  - "tests/**"
  - "mysql-test/**"
  - "spec/test-vectors.json"
---
# 테스트 규칙 — GWT 와 피라미드

```
        e2e / load        느림, nightly·릴리스 게이트. 실서버 SQL+복제
     integration / MTR    실서버 SQL 시나리오. PR 게이트
   unit (gtest)  서버 독립 코어 + 벡터. 초 단위. PR 게이트, 커밋 전 로컬
```

## GWT (Given-When-Then) — 모든 계층 필수
- **본문**: 세 블록을 주석/echo 로 명시하고 순서를 지킨다. Then 이후에 다시 When 을 두지 않는다 (한 테스트 = 한 행동).
- **분기·반복 금지**: 테스트 케이스 본문에는 `if`, `else`, `for`, `while` 같은 로직이나 분기를 추가하지 않는다. 조건별 기대 결과는 별도 케이스로 나누고, 여러 입력은 테스트 프레임워크의 파라미터화로 표현한다. 테스트 안에서 기대값을 계산하는 알고리즘을 재구현하지 않는다.
- **이름**: given/when/then 이 드러나게.
  - gtest: `TEST(Envelope, GivenEmptyInput_WhenParsed_ThenBadEnvelope)`
  - MTR / SQL 시나리오: 파일 상단 `--echo # Given: ...` `--echo # When: ...` `--echo # Then: ...` (`.result` 에 남아 리뷰어가 의도를 읽는다)
- **Given** 은 상태만 만든다 (키·벡터 로드·테이블·sysvar). **When** 은 단 하나의 호출. **Then** 은 단언만. 단언 없는 테스트 금지.
- 여러 입력은 파라미터화(`TEST_P` 등 테스트 프레임워크의 파라미터화)로 하나의 GWT 를 재사용한다. 복붙 금지.

```cpp
TEST(Envelope, GivenEmptyInput_WhenParsed_ThenBadEnvelope) {
  // Given
  const gcm::Bytes input{nullptr, 0};
  gcm::ParsedEnvelope parsed{};
  // When
  const gcm::Error error = gcm::parse(input, &parsed);
  // Then
  EXPECT_EQ(error, gcm::Error::bad_envelope);
}
```

```sql
--echo # Given: a deterministic envelope of a Korean name and strict mode ON
SET @k = UNHEX('000102...1f'); SET SESSION gcm.strict = ON;
SET @c = gcm_encrypt_det('홍길동', @k);
--echo # When: decrypted value is filtered with native LIKE
SELECT gcm_decrypt(@c, @k) LIKE '%길%' AS hit;
--echo # Then: hit = 1 (see .result)
```

## 공통
- 모든 벡터는 `spec/test-vectors.json` 한 곳. C++ 서버 테스트가 이 파일의 모든 케이스를 읽고, 내부 생성 도구는 `--check` 로 재현성을 확인한다. 값 복사 금지.
- 실키·PHI 를 픽스처에 넣지 않는다. 벡터 키는 NIST 공개 벡터 또는 `00..1f` 패턴.
- 비결정 함수(`gcm_encrypt`) 는 값이 아니라 **속성**(길이, version 바이트, 두 번 호출 결과 상이, 복호화 왕복) 을 검증한다.
- flaky 허용 없음. 재시도 데코레이터 금지. 시간 의존은 mock.

## 단위 (`tests/unit`)
- 대상: `gcm.cc` `envelope.cc` `nonce.cc` 의 서버 독립 코어. 서버 없이 실행하며 `architecture.md` 의 의존 경계를 유지한다. strict 에 따른 SQL 에러/NULL 변환은 통합 테스트에서 검증한다.
- 필수 케이스: NIST CAVP GCM KAT / 빈 평문 / AAD 유무 / 태그 1비트 변조 / nonce 1비트 변조 / 잘린 봉투(길이 0,1,12,28) / 알 수 없는 version / 키 길이 0,16,31,33 / 결정적 동일 입력→동일 출력 / 결정적 상이 입력→상이 nonce / nonce_key 유도 벡터 / 키 소거 후 버퍼 0.
- 결정적 nonce 충돌 경계: 무작위 평문에서 nonce 중복 0 (PR CI 10만, nightly 100만).

## 통합 (`tests/integration`, `mysql-test/suite/gcm`)
- 실서버(docker, MySQL 8.0/8.4/9.x)에 component 설치 후 SQL 시나리오. 기대 출력 diff.
- **절대 삭제 금지**: `gcm_decrypt(gcm_encrypt_det('홍길동',@k),@k) LIKE '%길%'` → 1. 대소문자 `LIKE '%kim%'`(utf8mb4_general_ci). 조인 동등성 `gcm_encrypt_det(a,@k) = gcm_encrypt_det(a,@k)`.
- NULL 전파, 인자 개수 오류, 키 길이 오류, `gcm.strict` ON/OFF 각각의 태그 실패, `SET SESSION gcm.strict` 세션 스코프, GLOBAL 변경이 기존 세션에 영향 없음.
- `SHOW STATUS LIKE 'Created_tmp_disk_tables'` 를 전후로 찍어 `gcm_decrypt` 의 디스크 temp 여부를 기록 (design §5.3).
- MTR: `.result` 는 `--record` 로 만들고 diff 를 눈으로 확인한 뒤 커밋. 테스트는 `INSTALL/UNINSTALL COMPONENT` 로 자기 뒷정리, 전역 sysvar 는 `SET GLOBAL ... = DEFAULT`.

## E2E (`tests/e2e`)
- compose: mysql(ROW binlog) + replica + Python runner. 시나리오: SQL 암호화 저장 → 서버 decrypt LIKE / SQL 암복호화 왕복 / v1(CBC) dual-read / replica 동일 값 / AAD 불일치 거부.
- E2E 실패는 "환경 문제"로 분류하지 않는다. 재현 불가면 로그를 첨부하고 이슈로 남긴다.

## 부하 (`tests/load`)
- 측정: `gcm_decrypt(col,@k) LIKE '%김%'` p50/p95 @ 10k/100k/300k 행, 동시 세션 1/8/32, `AES_DECRYPT` 동일 쿼리 대비 비율, 서버 RSS, `Created_tmp_disk_tables` 증가량.
- 약속(문서·README): p95 가 `AES_DECRYPT` 대비 **1.2배** 이내, 300k 행 직렬 p95 < **1.0초**.
- 실제 게이트(`tests/load/baseline.json`): p95 비율 **1.10배**. 측정값이 0.80~0.95 라 1.2 로는 행당 비용이 두 배가 되어도 통과한다. 더 조이지 않는 이유는 신중함이 아니라 측정된 노이즈다 — CI 6회 중 최악이 0.947 이고 그 느슨한 값들은 모두 동시 세션 1 축이다(표본 40개. 세션 8·32 는 320·1280 개이고 런 간 분산이 1.06·1.04배). 절대값 1.0초 게이트는 공용 러너에서 이 코드와 무관한 실패를 만들기 때문에 약속 그대로 둔다(실측 235~266ms).
- p95 는 nearest-rank(`ceil(0.95n)`). 표본 수를 줄이면 p95 가 최댓값에 붙어 게이트가 단일 요청 하나로 흔들린다.
- 기준치를 **올리려면** 하드웨어·서버 버전·회귀를 받아들이는 이유를 PR 에 적고 `docs/perf.md` 를 같은 PR 에서 갱신한다.
- nightly + `workflow_dispatch`. PR 마다 돌리지 않는다.
