# mysql-gcm — AGENTS.md

MySQL 8.0+ 서버 **component** 로 AES-256-GCM 암복호화 함수를 추가하는 오픈소스 프로젝트.
이 파일은 Codex · Cursor · OpenCode 가 직접 읽고, Claude Code 는 `CLAUDE.md` 의 import 로 읽는다.
설계 근거 전체는 `docs/design.md` (개정 A1 포함). **설계를 바꾸려면 그 문서를 먼저 고친 뒤 코드를 바꾼다.**

## 1. 한 줄 요약

MySQL 은 `block_encryption_mode` 에 GCM 이 없다 (8.4 · 9.4 실측, MariaDB 도 동일).
빌트인을 덮어쓸 수 없으므로 **새 이름의 함수를 component 로 등록**하고, **키는 `AES_ENCRYPT` 와 같이 SQL 인자로 받고**,
**복호화 결과에 charset 을 태깅**해 MySQL native `LIKE` 로 부분일치 검색을 유지한다.

## 2. 공개 표면 (변경 시 `docs/design.md` · `spec/` · 서버 테스트를 같은 PR 에서 갱신)

```
gcm_encrypt(plaintext, key [, aad])       -> BLOB     무작위 nonce (RAND_bytes 12B)
gcm_encrypt_det(plaintext, key [, aad])   -> BLOB     결정적 — 조인·UNIQUE·정확일치 전용
gcm_decrypt(ciphertext, key [, aad])      -> VARCHAR  charset utf8mb4 태깅 → native LIKE 가능
```

- `key`: 정확히 32 바이트 바이너리. 다른 길이는 에러 (`AES_ENCRYPT` 의 키 접기 미재현).
- 결정적 nonce: `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`, `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`.
- 봉투 (version 바이트 값은 Phase 1 에서 확정, 아래는 현재 제안):

```
0x01  legacy CBC (dual-read 전용, 생성하지 않음)
0x02  GCM 무작위 : 0x02 || nonce(12) || ciphertext || tag(16)
0x03  GCM 결정적 : 0x03 || nonce(12) || ciphertext || tag(16)  # 미해결 A2: nonce 는 평문 HMAC 이라 복호화 시 재계산 불가 → 저장 필요 (spec/envelope.md)
```

- sysvar: `gcm.strict` (GLOBAL + SESSION, 기본 ON). 태그 불일치 시 ON=에러, OFF=NULL. my.cnf 에서는 `loose_gcm.strict`.
- 폐기됨 (개정 A1): keyring 연동, `gcm.key_id`, `gcm.nonce_key_id`, `gcm_key_id()`. 요청받아도 설계 개정 제안으로 돌린다.

## 3. 저장소 배치 (현재 Phase 2 — component 구현·테스트가 들어와 있다)

```
AGENTS.md / CLAUDE.md          에이전트 지침 (이 파일이 원본)
.agents/rules/                도구 공통 규칙 원본
.agents/skills/               도구 공통 스킬 원본
docs/design.md                 설계 문서 (근거의 원본, 개정 A1 포함)
docs/ops-constraints.md        운영 제약 — README 첫 화면에도 복제
spec/envelope.md               봉투·실패 의미론 확정본 (Phase 1)
spec/test-vectors.json         NIST CAVP GCM KAT + 자체 벡터. 서버 테스트의 공통 기준
src/                           component (C++17)
  CMakeLists.txt               MYSQL_ADD_COMPONENT — 서버 트리 components/gcm 으로 복사돼 빌드된다
  component.cc                 DECLARE_COMPONENT, REQUIRES_SERVICE 목록, init/deinit (등록 롤백 포함)
  udf_encrypt.cc udf_decrypt.cc   UDF 글루 — 인자 검증·charset 태깅·에러 변환만
  udf_glue.{h,cc}              두 UDF 글루가 공유하는 인자·버퍼·에러 변환 (암호 로직 없음)
  gcm.{h,cc}                   OpenSSL EVP 래퍼 (서버 헤더 의존 없음 → 단위 테스트 가능)
  envelope.{h,cc}              봉투 인코딩/디코딩 (OpenSSL 에도 의존하지 않는다)
  nonce.{h,cc}                 합성 nonce + nonce_key 유도 (EVP_MAC HMAC-SHA256)
  sysvar.{h,cc}                gcm.strict 등록/조회 — 세션 스코프는 9.0+ 전용 (개정 A5)
tests/unit/                    GoogleTest — gcm/envelope/nonce, 서버 없이 libcrypto 만 링크
tests/integration/             docker 위 실서버 SQL 시나리오 (sql + expected)
mysql-test/suite/gcm/          MTR .test/.result (서버 소스 트리 빌드에서 실행)
tests/e2e/                     compose: mysql(ROW) + replica + Python SQL runner → LIKE / 복제 / dual-read
tests/load/                    부하: 10k/100k/300k 행 decrypt+LIKE, AES_DECRYPT 대비 회귀 게이트
scripts/                       dev-up.sh, build-in-docker.sh, verify.sh, verify.sql, mtr.sh, agents-sync.sh
  gen-vectors.py              내부 벡터 생성·검증 도구 (cryptography, 배포 API 아님)
  check-architecture.py       코어 의존·테스트 진입점 경계 검사 (개정 A6)
docker/                        build.Dockerfile (configure 된 서버 소스 트리) + build-component.sh + versions.json
docs/perf.md                   부하 측정 누적 — 설계 §1.2 의 추정치를 실측으로 대체한다
CHANGELOG.md                   릴리스별 변경. 봉투 변경은 호환성 메모와 함께
.github/workflows/             CI (lint · unit · build matrix · integration · e2e · load(nightly) · release)
```

## 4. 빌드 · 검증 명령 (스킬이 상세를 가진다)

| 목적 | 명령 | 스킬 |
|---|---|---|
| 개발 서버 기동 | `scripts/dev-up.sh 8.4` | `dev-container` |
| component 빌드 (서버 소스 트리 in-tree) | `scripts/build-in-docker.sh 8.4` | `mysql-component` |
| 단위 테스트 | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` | `unit-tests` |
| 통합 스모크 | `scripts/verify.sh 8.4` (컨테이너에 .so 설치 후 SQL 시나리오 diff) | `integration-tests` |
| MTR | `scripts/mtr.sh 8.4` (`GCM_RECORD=1` 로 `.result` 재생성) | `integration-tests` |
| E2E | `docker compose -f tests/e2e/compose.yml up --exit-code-from runner` | `e2e-load-tests` |
| 부하 | `python tests/load/run.py --rows 300000 --baseline aes` | `e2e-load-tests` |
| 벡터 재현성 | `python scripts/gen-vectors.py --check` (`scripts/requirements.txt` 설치 후) | `unit-tests` |
| 아키텍처 경계 | `python3 scripts/check-architecture.py` | `.agents/rules/architecture.md` |

명령이 아직 없으면(Phase S) **그 스킬의 지침대로 만든다**. 임의로 다른 빌드 방식을 도입하지 않는다.

## 5. 절대 규칙 (전문은 `.agents/rules/`)

**암호 (`crypto-safety.md`, 항상 적용)**
- `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)` 로 이름 fetch. `EVP_aes_256_gcm()` 심볼 직접 호출 금지.
- 서버가 로드한 libcrypto 를 그대로 쓴다. 정적 링크·다른 버전 번들 금지.
- 키·평문·nonce 는 로그·에러 메시지·assert 문자열에 절대 넣지 않는다. 키·평문 버퍼는 `OPENSSL_cleanse`.
- 태그 검증 실패는 `gcm.strict=ON` 이면 에러. NULL 로 삼키지 않는다. 미인증 평문은 절대 반환하지 않는다.
- 키 길이는 32 바이트 정확히. 접기·패딩·해싱으로 맞추지 않는다.
- 키를 저장소 파일·설정·환경변수·테스트 픽스처(스펙 벡터 제외)에 두지 않는다.

**아키텍처 (`architecture.md`)**
- 서버 어댑터 → 코어(`gcm` → `envelope`/`nonce`) 방향. 코어는 MySQL 에 의존하지 않는다.
- SQL 정책은 UDF, 서버 버전 차이는 어댑터에 둔다. component·UDF_INIT·연산 수명을 구분하고 테스트용 우회 경로를 SQL 에 노출하지 않는다.

**component (`component-src.md`)**
- legacy UDF plugin API(`mysql_declare_plugin`, `CREATE FUNCTION ... SONAME`) 금지. component + `udf_registration` 서비스만.

**테스트 (`testing.md`)**
- 모든 테스트는 **GWT(Given-When-Then)** 구조. 이름에도 given/when/then 이 드러난다.
- 테스트 케이스 본문에는 `if`, `else`, `for`, `while` 같은 로직·분기를 추가하지 않는다. 조건별로 케이스를 분리하거나 프레임워크의 파라미터화를 사용한다.
- 기능 변경 PR 은 단위 + 통합 테스트를 같이 낸다. 봉투·nonce 변경은 `spec/test-vectors.json` 갱신 + 서버 벡터 테스트 동반.
- 한글 부분일치 `LIKE '%길%'` 통합 테스트는 삭제 금지 (프로젝트 존재 이유).

**제품 범위와 Python 도구 (개정 A4)**
- 배포 대상은 MySQL component 와 SQL API 이다. Python·Java 암호화 클라이언트/SDK 를 만들지 않는다.
- 애플리케이션은 기존 MySQL 드라이버로 SQL 함수를 호출한다. 드라이버 통합은 범위 밖이다.
- Python 은 벡터 생성·검증 및 SQL E2E/부하 runner 에만 쓴다. 벡터 생성은 `cryptography` 만 사용하며 직접 만든 암호 프리미티브는 금지한다.
- `scripts/gen-vectors.py` 는 내부 도구이며 공개 encrypt/decrypt/parse API 를 제공하지 않는다. E2E runner 의 암복호화는 서버 SQL 함수로 수행한다.

**리뷰 (`code-review.md`)**
- 코멘트 우선순위 **P1(머지 차단) / P2(머지 전 해결 권장) / P3(선택)** + `Q`(질문).
- 암호·봉투·sysvar 경로를 건드리는 PR 은 `crypto-reviewer` 통과 + 사람 리뷰어 2인.

## 6. 현재 단계와 로드맵

현재: **Phase 2 (구현)**. Phase S·1 은 완료됐고 그 결과는 `docs/design.md` §8 에 있다.
Phase 2 의 남은 항목은 **부하 baseline** 뿐이다 (릴리스 빌드 + 알려진 하드웨어). MTR `.result` 는
`scripts/mtr.sh 8.4` 로 기록해 `mysql-test/suite/gcm/r/` 에 들어와 있다.

| Phase | 산출물 | 완료 기준 |
|---|---|---|
| S 스파이크 | 최소 component, `scripts/verify.sql` 통과 | 32B 키 인자 검증 · `SET SESSION gcm.strict` · 한글 LIKE · `Created_tmp_disk_tables` 관측 · `EVP_CIPHER_fetch` 성공 — 결과를 `docs/design.md` §8 에 기록 |
| 1 스펙 | `spec/envelope.md`, `spec/test-vectors.json` | 서버 구현과 테스트가 따를 바이트 포맷·실패 의미론 확정 |
| 2 구현 | `src/`, `tests/unit`, `mysql-test/suite/gcm`, `tests/integration` | CI green, nonce 충돌 경계 테스트 포함 |
| 3 SQL E2E | SQL 사용 예제, `tests/e2e` | 서버 SQL 왕복·한글 LIKE·복제·dual-read 검증 통과 |
| 4 배포 | 빌드 매트릭스, README, `docs/ops-constraints.md`, 부하 baseline | 릴리스 아티팩트 + 체크섬 + SBOM |
| 5 업스트림 | feature request | 선택 |

## 7. 도구별 에이전트 설정 배치

원본은 한 곳, 나머지는 **`scripts/agents-sync.sh` 가 생성하는** 어댑터다. 원본을 고친 뒤 스크립트를 다시 돌리고, CI(`lint.yml`)가 `--check` 로 어댑터가 낡지 않았는지 검사한다. 생성물을 직접 편집하지 않는다.

| 개념 | 원본 | Claude Code | Codex | Cursor | OpenCode |
|---|---|---|---|---|---|
| 프로젝트 지침 | `AGENTS.md` | `CLAUDE.md` (`@AGENTS.md`) | 네이티브 + 하위 `AGENTS.md` | 네이티브 | 네이티브 |
| 경로 규칙 | `.agents/rules/*.md` | `.claude/rules/*.md` (생성, `paths:`·본문 보존) | 하위 `AGENTS.md` 가 원본 참조 | `.cursor/rules/*.mdc` (생성, `@` 참조) | `opencode.json` `instructions` 가 원본 참조 |
| 스킬 | `.agents/skills/*/SKILL.md` | `.claude/skills` → 심링크 | 네이티브 | `.cursor/skills` → 심링크 | 네이티브 (`.agents/skills` 탐색) |
| 서브에이전트 | `.claude/agents/*.md` | 네이티브 | `.codex/agents/*.toml` (생성, `sandbox_mode` 로 읽기 전용) | `.cursor/agents` → 심링크 | `.opencode/agents/*.md` (생성, `permission` 으로 읽기 전용) |
| 권한·훅 | `.claude/settings.json` + `.claude/hooks/guard.sh` | 네이티브 | `sandbox_mode` (에이전트별) | — | `opencode.json` `permission` (전역) + 에이전트별 `permission` |

## 8. 스킬 · 서브에이전트 사용 시점

| 상황 | 사용 |
|---|---|
| component 소스·서비스 API·빌드를 만지기 전 | 스킬 `mysql-component`, `sysvar-config` |
| EVP·봉투·nonce 코드 작성/수정 | 스킬 `gcm-crypto` → 완료 후 서브에이전트 `crypto-reviewer` |
| 서버 API 시그니처가 불확실할 때 | 서브에이전트 `component-api-researcher` (추측 금지, 헤더 확인) |
| 테스트 작성 | 스킬 `unit-tests` / `integration-tests` / `e2e-load-tests` |
| 로컬 검증·Phase S 체크 | 스킬 `dev-container` → 서브에이전트 `verify-runner` |
| 벡터 생성·검증 | 스킬 `unit-tests`, 암호 구성 변경 시 `crypto-reviewer` |
| PR 리뷰 | 스킬 `code-review` → 서브에이전트 `code-reviewer` (+ `crypto-reviewer`) |
| CI/릴리스 워크플로 | 스킬 `ci-release` |
| 스택별 관례 확인 | `.agents/rules/stack-*.md` |

## 9. 작업 방식

- 작업 전에 `docs/design.md` 의 관련 절을 읽는다. 설계와 다른 판단이 필요하면 코드 대신 문서 개정을 먼저 제안한다.
- 모르는 MySQL/OpenSSL API 는 **헤더·공식 문서로 확인**한다. 시그니처를 추측해서 컴파일 안 되는 코드를 내지 않는다.
- 커밋: Conventional Commits (`feat(component): ...`, `fix(crypto): ...`, `test(mtr): ...`, `ci: ...`, `docs: ...`). 하나의 커밋은 하나의 관심사.
- PR: `.github/PULL_REQUEST_TEMPLATE.md` 체크리스트를 전부 채운다. 순 변경 400줄 초과 diff 는 분할한다.
- 사용자와의 대화는 한국어. 코드·주석·커밋·README·spec 은 영어 (오픈소스 대상).
- 관리형 MySQL, 프록시, 키 관리 시스템 자체, keyring 연동은 범위 밖. 요청받아도 설계 개정 제안으로 돌린다.
