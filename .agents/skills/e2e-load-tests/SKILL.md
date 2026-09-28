---
name: e2e-load-tests
description: docker compose E2E(서버 SQL 왕복·복제·dual-read)와 부하 테스트(10k/100k/300k 행 decrypt+LIKE, AES_DECRYPT 대비 회귀 게이트) 작성·실행 절차. tests/e2e, tests/load 작업에 사용.
---

# e2e-load-tests

## E2E — `tests/e2e`
`compose.yml` 서비스: `mysql-primary`(ROW binlog, `--loose_gcm.strict=ON`), `mysql-replica`, `runner`(python:3.12, `PyMySQL` 설치, SQL 실행 전용). `.so` 는 빌드 아티팩트 볼륨 마운트.

시나리오 (`tests/e2e/scenarios/*.py`, 각각 GWT 도크스트링 + given/when/then 이 드러나는 함수 이름):
| 파일 | Given | When | Then |
|---|---|---|---|
| `sql_write_like.py` | SQL `gcm_encrypt_det` 로 한글 이름 3행 INSERT | `gcm_decrypt(col,@k) LIKE '%길%'` | 해당 id 만 |
| `sql_roundtrip.py` | SQL `gcm_encrypt` 로 INSERT | `gcm_decrypt` 결과 조회 | 원문·길이·charset |
| `replica_consistency.py` | primary 에 무작위·결정적 값 INSERT | GTID 대기 후 replica SELECT | 바이트 동일 + replica 에서 LIKE |
| `dual_read_v1.py` | 0x01 CBC 봉투 행 존재 | `gcm_decrypt` | AES_DECRYPT 와 동일, AAD 는 거부 |
| `aad_mismatch.py` | AAD 'a' 로 암호화 | AAD 'b' 로 복호화 | `ER_UDF_ERROR`, 같은 AAD 는 성공 |
| `strict_scope_global.py` | 8.0·8.4 (세션 스코프 없음) | `SET GLOBAL` / `SET SESSION` | GLOBAL 적용, SESSION 은 1229 |
| `strict_scope_session.py` | 9.0+ (세션 스코프 있음) | 한 세션만 `SET SESSION ... = OFF` | 다른 세션은 여전히 에러 |

**버전 분기는 runner 가 한다.** `strict_scope_*` 중 하나를 서버 버전으로 골라 실행하고, 시나리오 본문에는
`if` 를 두지 않는다 (testing 규칙). 복제 대기는 `WAIT_FOR_EXECUTED_GTID_SET` — sleep·폴링 금지.
자격증명은 환경변수로만 (compose 가 `REPL_PASSWORD` 를 준다). runner 는 SQL 만 실행하고 암복호화하지
않는다 (개정 A4).

실행: `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner --abort-on-container-exit`.
`.so` 는 `GCM_SO`(기본 `build/8.4/...`) 로 양쪽 서버의 `plugin_dir` 에 읽기 전용 마운트된다.

## 부하 — `tests/load`
`run.py --rows {10000,100000,300000} --concurrency 1,8,32 --baseline aes --out result.json`
1. Given: `patients(id, name_gcm VARBINARY, name_cbc VARBINARY)` 에 N 행 — 한글 이름 생성기(시드 고정),
   두 컬럼 모두 **같은 평문**. CBC 컬럼은 빌트인 `AES_ENCRYPT` 로 쓴다 (이것이 비교 대상 baseline).
2. When: `gcm_decrypt(name_gcm,@k) LIKE '%김%'` 와 `AES_DECRYPT(name_cbc,@k,@iv) LIKE '%김%'` 를 각각
   warm-up 3회 후 20회, 동시 세션 수만큼 스레드(각 스레드가 자기 연결).
3. Then: p50/p95/max(ms), 비율 `gcm/aes`, `Created_tmp_disk_tables` 증가량을 JSON 으로 stdout,
   사람용 요약은 stderr. `--gate tests/load/baseline.json` 이면 임계 초과 시 exit 1.

게이트 (testing 규칙): `p95_ratio <= 1.2` AND `p95_ms(최대 행수, c=1) <= 1000`. 값은
`tests/load/baseline.json` 한 곳. 갱신은 PR 에 하드웨어·버전·근거 기재.

결과 표는 `docs/perf.md` 에 버전별로 누적 (설계 §1.2 의 추정치를 실측으로 대체하는 것이 목표).
baseline 은 릴리스 빌드 + 알려진 하드웨어에서 채운다 — 개발 노트북 수치를 게이트로 굳히지 않는다.

## 완료 조건
- [ ] E2E 6 시나리오 green, compose 가 `--exit-code-from` 으로 실패를 전파
- [ ] 부하 JSON 이 CI 아티팩트로 업로드되고 게이트가 exit code 로 동작
