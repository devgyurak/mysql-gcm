---
name: integration-tests
description: 실서버(docker) SQL 시나리오 스모크(tests/integration, scripts/verify.sh)와 MTR 스위트(mysql-test/suite/gcm) 작성·실행 절차. component 를 서버에 설치해 SQL 동작을 검증할 때 사용.
---

# integration-tests

두 계층. 둘 다 GWT (`--echo # Given/When/Then`).

| 계층 | 위치 | 언제 | 요구 |
|---|---|---|---|
| SQL 스모크 | `tests/integration/<case>.sql` + `<case>.expected` | 로컬 루프, PR CI | 공식 `mysql:<ver>` 이미지 + `.so` |
| MTR | `mysql-test/suite/gcm/t/*.test`, `r/*.result` | PR CI (서버 트리 빌드 잡), 릴리스 | 서버 소스 트리 빌드 |

## SQL 스모크
`scripts/verify.sh <ver>` (`GCM_RECORD=1` 이면 `.expected` 를 다시 기록):
1. `scripts/dev-up.sh <ver>` (이미 떠 있으면 재사용) → `SELECT @@plugin_dir` 로 경로를 물어 `docker cp`
2. `UNINSTALL` 후 `INSTALL COMPONENT 'file://component_gcm'` (재빌드한 .so 를 확실히 집는다)
3. 케이스마다 깨끗한 스키마(`gcm_it`)를 주고 `mysql --default-character-set=utf8mb4 -D gcm_it -N --force`
   로 실행. stdout 과 stderr 를 **따로 받아** stdout 뒤에 `--- errors, in statement order ---` 섹션으로
   이어 붙인 뒤 `.expected` 와 diff. 하나라도 다르면 exit 1.
4. `Created_tmp_disk_tables` 전후 차이를 `build/<ver>/tmp_disk.txt` 로 남기고 `UNINSTALL`.

**`2>&1` 로 합치지 않는 이유**: 클라이언트는 stdout 을 블록 버퍼링하고 stderr 는 하지 않아 순서가
버퍼 경계에 따라 달라진다 — flaky 금지 규칙에 걸린다. `--force` 는 에러를 기대하는 케이스 때문에 필요하다.

케이스 파일 (이름 = 의도):
```
00_install_and_signature.sql        인자 개수 오류, 키 길이 5·31·33 오류
10_roundtrip_random.sql             왕복, 행마다 다른 봉투, 길이 = pt+29, AAD 왕복
11_roundtrip_det.sql                동등성, 길이 = pt+29, spec §5.1 바이트 일치, 조인·UNIQUE
20_korean_like.sql                  ★ gcm_decrypt(...) LIKE '%길%' = 1, 전/후방일치, 대소문자 ci, 테이블 검색
30_strict_semantics.sql             버전 무관: 태그 실패 에러, 봉투 오류는 strict 와 무관, AAD 불일치
31_strict_scope.sql                 per-major-expected — GLOBAL vs SESSION (개정 A5)
40_null_and_edge.sql                NULL 전파, 빈 문자열(29B), 64KB, 경계 길이 왕복
50_dual_read_v1.sql                 0x01 봉투 → AES_DECRYPT 와 동일, AAD 거부, 세 버전 혼재 읽기
90_tmp_disk_observation.sql         decrypt + ORDER BY + GROUP BY 워크로드 (카운터는 tmp_disk.txt 가 기록)
91_server_udf_arg_defect.sql        per-major-expected — 개정 A7 서버 결함 고정
```
**per-major `.expected`**: 케이스 첫 3줄에 `per-major-expected` 를 적으면 `verify.sh` 가
`<case>.<major>.expected` 와 비교한다. 버전마다 정당하게 다른 동작만 여기에 둔다 (현재 31, 91).
그 외 케이스는 8.0·8.4·9 에서 **같은 출력**이어야 한다.

`.expected` 는 실행 결과로 만들고 **눈으로 검토한 뒤** 커밋한다. 리뷰에서 `.expected` 변경은 diff 를
설명해야 한다. 암호문·평문 바이트가 기대 파일에 들어가지 않게 한다 (UNIQUE 위반 메시지처럼 값을 찍는
에러는 `INSERT IGNORE` + 행 수 단언으로 바꾼다).

## MTR
- 위치: `mysql-test/suite/gcm/{t,r,include}`. `scripts/mtr.sh` 가 `$MYSQL_SRC/mysql-test/suite/gcm` 으로
  **복사**한다 (읽기 전용 마운트라 심링크는 쓰지 않는다).
- 공통 include: `include/gcm_install.inc` (`INSTALL COMPONENT` + 공개 픽스처 키
  `SET @k = UNHEX('0001..1f')`), `include/gcm_uninstall.inc` (`SET GLOBAL gcm.strict = DEFAULT` 포함).
- 테스트 골격:
```
--source suite/gcm/include/gcm_install.inc
--echo # Given: a deterministic envelope of a Korean name
SET @c = gcm_encrypt_det('홍길동', @k);
--echo # When: filtered with native LIKE
SELECT gcm_decrypt(@c, @k) LIKE '%길%' AS hit;
--echo # Then: hit must be 1
--source suite/gcm/include/gcm_uninstall.inc
```
- 에러 기대는 `--error ER_UDF_ERROR` (component 는 전용 에러 코드를 쓰지 않고 `ER_UDF_ERROR` 로 올린다),
  인자 개수 오류는 `--error ER_CANT_INITIALIZE_UDF`. 둘 다 서버 심볼이므로 숫자를 쓸 필요가 없다.
- 실행: `scripts/mtr.sh <major>` (컨테이너에서 서버를 빌드하고 스위트를 복사해 돌린다).
  결과 생성: `GCM_RECORD=1 scripts/mtr.sh <major>` → `.result` 가 저장소로 복사되므로 **diff 를 눈으로
  검토한 뒤** 커밋한다. 손으로 쓴 `.result` 는 커밋하지 않는다.
- 복제 케이스: `--source include/master-slave.inc` + `include/have_binlog_format_row.inc` 로 ROW binlog 에서
  `gcm_encrypt` 값이 replica 와 바이트 동일함을 확인 (SBR 위험의 근거 테스트).
- 서버 전체 빌드는 메모리를 많이 쓴다. 병렬도를 낮추고(`GCM_MTR_JOBS`), `group_replication` 은 끈다
  (`-DWITHOUT_GROUP_REPLICATION=1`) — gcm 스위트는 쓰지 않는다.

## 완료 조건
- [ ] `20_korean_like` 통과 (없으면 프로젝트 목적 미달)
- [ ] 8.0 · 8.4 · 9.x 세 버전에서 스모크 통과, per-major 케이스 외에는 출력 동일
- [ ] MTR `.result` 는 `--record` 산출물이고 변경 근거가 PR 설명에 기재
