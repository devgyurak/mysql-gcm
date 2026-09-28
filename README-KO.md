<h1 align="center">mysql-gcm</h1>

<p align="center">
  <strong>MySQL 용 AES-256-GCM — 서버 component 로, 평문에 대한 서버측 <code>LIKE</code> 를 유지합니다.</strong>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README-KO.md">한국어</a>
</p>

<p align="center">
  <img alt="MySQL 8.0 | 8.4 | 9.x" src="https://img.shields.io/badge/MySQL-8.0%20%7C%208.4%20%7C%209.x-4479A1?logo=mysql&logoColor=white">
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white">
  <img alt="OpenSSL 3" src="https://img.shields.io/badge/OpenSSL-3.x-721412?logo=openssl&logoColor=white">
  <img alt="status: Phase 2" src="https://img.shields.io/badge/status-Phase%202%20(%EA%B5%AC%ED%98%84)-orange">
  <a href="LICENSE"><img alt="license: GPLv2" src="https://img.shields.io/badge/license-GPLv2-blue"></a>
</p>

`gcm_encrypt`, `gcm_encrypt_det`, `gcm_decrypt` 를 MySQL **component** 로 등록합니다(레거시 UDF
플러그인이 아닙니다). 복호화 결과에 `utf8mb4` 문자셋을 태깅하므로 MySQL 자신의 collation 이
`LIKE '%길%'` 를 **서버 안에서** 처리합니다 — 암호화된 컬럼에 부분일치 검색을 유지하는 것이 이
프로젝트의 존재 이유입니다. 개발 머신에서 10만 행을 서버측으로 필터링하면 **p95 41ms** 이고,
`docs/design.md` §1.2 는 같은 후보 집합을 애플리케이션으로 가져와 복호화하는 비용을 ~1.1초로 추정합니다.
릴리스 baseline 이 아니라 참고 수치이며, 무엇을 어디서 측정했는지는 `docs/perf.md` 에 있습니다.

> **현재 단계: Phase 2(구현).** MySQL 8.0 · 8.4 · 9.x 서버 소스 트리에서 빌드·설치되고 단위 · 통합 ·
> MTR · E2E · 부하 테스트를 통과합니다. **아직 릴리스하지 않았습니다**: 공개 배포 파일, 기준
> 하드웨어에서의 부하 baseline, 라이선스 법률 검토가 남아 있습니다. `docs/design.md` 를 참고하세요.

## 먼저 확인하세요 — 운영 제약

이 목록은 결함 목록이 아니라 이 방식 자체의 성질이며, component 코드로 해결할 수 있는 것이 없습니다.
전체 내용과 근거는 `docs/ops-constraints.md`, `docs/design.md` §6 및 개정 A7 · A8 에 있습니다.

| 주제 | 해당 제약 |
|---|---|
| **토폴로지** — 복제, 승격, 샤딩 | 1, 14, 15 |
| **키와 nonce** — 사용량 예산, 교체, AAD 정책, 복구 | 7, 11, 12 |
| **쿼리 동작** — 옵티마이저, 결정적 암호화가 노출하는 것 | 5, 6 |
| **데이터와 버전** — legacy 봉투, charset, sysvar 범위, 인자 형태 | 8, 9, 10 |
| **환경** — 로그, 관리형 서비스, my.cnf | 2, 3, 4 |
| **보증의 범위** — 검증하는 것과 하지 않는 것 | 13 |

1. **`gcm_encrypt`는 비결정적이므로 ROW binlog가 필수입니다.** Statement 기반 복제에서는
   복제본이 다른 nonce를 생성합니다. 비결정 함수는 생성 컬럼이나 인덱스에도 사용할 수 없습니다.
2. **키와 평문은 SQL 인자입니다.** General log, slow log, `performance_schema.events_statements_*`,
   SBR binlog에 남을 수 있습니다. `'%김%'` 같은 검색 패턴도 평문 조각입니다.
   `AES_ENCRYPT`와 같은 노출 경로이므로 로그 접근을 통제해야 합니다.
3. **직접 운영하는 MySQL만 지원합니다.** RDS, Aurora, Cloud SQL 같은 관리형 서비스는
   `plugin_dir`에 대한 접근을 제공하지 않습니다.
4. **my.cnf에서는 `loose_` 접두사를 사용하세요** (`loose_gcm.strict=ON`). 접두사가 없으면
   component를 설치하기 전에 서버가 시작을 거부합니다.
5. **옵티마이저는 함수 내부를 알지 못합니다.** `WHERE gcm_decrypt(col, @k) LIKE '%김%'`는
   후보 행을 스캔합니다. 다른 조건으로 먼저 후보를 줄여야 합니다.
6. **`gcm_encrypt_det`는 평문의 동등성을 노출합니다.** 조인 키, UNIQUE 제약, 정확일치 검색을
   위한 기능입니다. 자유 텍스트에는 사용하지 마세요.
7. **결정적 암호화에서는 키 하나에 AAD 규칙 하나를 적용합니다.** `gcm_encrypt_det`는 평문만으로
   nonce를 유도하므로 같은 키·평문에 서로 다른 AAD를 사용하면 `(키, nonce)` 쌍이 재사용되고,
   두 결과를 관측한 공격자가 해당 nonce의 태그를 위조할 수 있습니다. 같은 키를 사용하는 모든
   결정적 호출은 서버·컬럼·애플리케이션에 관계없이 동일한 AAD 바이트열을 사용하거나 항상 비워야 합니다.
   다른 AAD 영역에는 다른 키가 필요합니다. 암호문 동등성으로 조인하려면 양쪽의 키와 AAD가 같아야 합니다.
8. **기존 `0x01`(CBC) 봉투는 읽을 수 있지만 인증되지 않으며, 그 평문은 이미 UTF-8이어야 합니다.**
   Dual-read는 데이터 이관용입니다. 잘못된 키로도 오류 대신 잘못된 평문이 반환될 수 있습니다.
   이관이 끝나면 `0x01`을 거부하세요. 복호화 결과는 버전과 무관하게 `utf8mb4`로 태깅되고 v1 봉투는
   변환을 수행하는 암호화 경로를 거치지 않았으므로, latin1 `Müller`는 불정 바이트로 돌아오고
   `LIKE '%ller%'`가 **오류 없이 0**을 반환합니다. `0x01 || iv`를 덧붙이기 전에 legacy 컬럼을
   `utf8mb4`로 변환하세요. 변환은 *문자형* 인자에만 적용되므로 `gcm_encrypt(UNHEX('ff'), @k)` 역시
   `0x02`/`0x03`에서 불정 결과가 됩니다. 검색해야 하는 값이라면 바이트가 아니라 텍스트를 암호화하세요.
9. **MySQL 9.0 이전에는 `gcm.strict`의 SESSION 범위가 없습니다.** Component 시스템 변수의
   세션 범위는 9.0.0부터 제공됩니다. 8.0과 8.4에서는 GLOBAL 전용이며 서버가
   `SET SESSION gcm.strict`를 거부합니다. ON/OFF의 동작 의미는 모든 버전에서 같습니다.
10. **즉석에서 계산한 식 대신 저장된 값을 전달하세요.** MySQL 8.0과 8.4는 일부 계산된 문자열을
    loadable function에 전달할 때 한 statement의 두 번째 행부터 낡은 인자 뷰를 넘깁니다.
    따라서 `gcm_encrypt_det(CONCAT(name, id), @k)`가 오류 없이 잘못된 바이트를 암호화할 수 있습니다.
    이 문제를 피하는 인자 형태는 컬럼, 리터럴, 사용자 변수, 바인드 파라미터입니다.
    SQL에서 계산해야 한다면 먼저 값을 구체화하세요. `CAST`만으로는 충분하지 않습니다.
    상세 내용과 버전별 실측은 `docs/design.md` 개정 A7에 있습니다.
11. **배포 전에 키당 사용량 예산과 키 교체 계획을 정하세요.** 같은 키를 사용하는 모든 서버·컬럼·
    애플리케이션의 암호화 사용량을 합산해야 합니다. Nonce 방식, 메시지 크기, 허용 위험에 맞춰
    한도를 검토하세요. 이 프로젝트는 모든 배포에 적용할 수 있는 안전한 사용 한도를 확정하지 않았습니다.
    Component는 사용량을 집계하거나 키를 자동 교체하지 않습니다. 키 교체는 결정적 암호문을 바꾸므로
    JOIN/UNIQUE 이관을 계획하고 백업 복호화에 필요한 키에 계속 접근할 수 있어야 합니다.
12. **재시도와 복구도 nonce 관리에 포함하세요.** 기존 봉투를 복사·복원하는 것은 새 암호화가 아닙니다.
    `gcm_encrypt`를 다시 호출하면 새로운 무작위 nonce를 생성합니다. 결정적 재시도는 키·평문·AAD가
    모두 같을 때만 같은 결과를 재현합니다. 결정적 재시도에서 AAD만 바꾸지 마세요.
    DB 복원 시 누적 키 사용량을 되돌리지 마세요. 복구나 프로세스 복제 후 누적 사용량 또는 난수 상태의
    안전성을 확신할 수 없다면 해당 키로 새 쓰기를 중단하세요. 모든 쓰기 주체의 난수 상태를 복구·확인한
    다음, 독립적으로 안전하게 생성한 새 키로 재개해야 합니다. 키 교체만으로 중복 난수 상태가 해결되지는 않습니다.
13. **보안 규칙은 운영 중 감시 기능이 아닙니다.** Component는 입력과 인증 태그를 검증하지만,
    nonce 재사용 탐지, 호출 간 AAD 정책 강제, 키 사용량 제한은 제공하지 않습니다.
    개발 가드 훅은 에이전트 명령을 제한하며 운영 중 암호화를 감시하지 않습니다.
    결정적 암호화는 동등성·빈도·길이를 노출합니다. 벡터 검증이나 샘플 충돌 테스트의 통과는
    안전성 증명이 아닙니다. 운영에 사용하기 전에 암호 구성과 배포 전제를 독립적으로 검토하세요.
    근거: [NIST SP 800-38D §8 및 부록 A/B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
14. **Component 설치는 복제되지 않습니다.** `INSTALL COMPONENT`는 해당 서버의 `mysql.component`에만
    기록됩니다. 복호화 조회를 받는 모든 서버와 승격 대상이 될 수 있는 모든 복제본에 각각 설치하고,
    애플리케이션이 그 서버에도 키를 전달할 수 있어야 합니다. ROW binlog는 암호문·nonce·태그를
    바이트로 그대로 전달하므로 복제본이 재암호화하지 않습니다 — 이것이 복제가 안전한 이유이면서,
    동시에 복제본이 그 값을 *읽기* 위해 component를 필요로 하는 이유입니다. MySQL 문서:
    [복제 형식](https://dev.mysql.com/doc/refman/8.4/en/replication-formats.html),
    [component 로딩](https://dev.mysql.com/doc/refman/8.4/en/component-loading.html).
15. **샤딩에서는 암호문이 아니라 안정적인 식별자로 라우팅하세요.** 무작위 nonce 값은 호출마다
    달라지므로 라우팅 키가 될 수 없습니다. 결정적 값은 안정적이지만 이를 샤드 키로 쓰면 키 교체가
    리샤딩 작업이 됩니다. 샤드 간 행 이동에는 재암호화가 필요하지 않습니다 — 목적지에서 원래 키와
    AAD로 복호화합니다. 결정적 암호문을 샤드 간 비교하려면 키·평문·**AAD**가 모두 같아야 하므로
    7항이 샤드 경계를 넘어 적용됩니다. 키를 공유하는 모든 샤드의 새 암호화 호출량을 합산하세요.
    기존 암호문을 복사하는 것은 새 암호화가 아닙니다. `gcm_decrypt(...) LIKE '%김%'` 만으로는
    샤드를 고를 수 없습니다. 라우팅 조건이 없으면 모든 샤드를 조회하고 각 샤드가 자기 후보 행을
    복호화합니다. 특정 샤딩 프록시가 loadable function 호출을 전달하고 결과 charset을 보존하는지는
    그 조합으로 별도 검증해야 합니다 — 이 프로젝트는 직접 운영하는 MySQL 서버만 검증합니다.

## 지원 범위

| MySQL | 빌드·테스트 버전 | `gcm.strict` 범위 | 제약 10이 재현되는 형태 |
|:--|:--|:--|:--|
| **8.0** | 8.0.43 | GLOBAL | `REPEAT(str, int_col)` 형태의 인자 |
| **8.4** | 8.4.11 | GLOBAL | `CONCAT(str, int_col)` 형태의 인자 |
| **9.x** | 9.4.0 | GLOBAL **+ SESSION** | 두 형태 모두 재현되지 않음 |

패치 버전, 이미지 digest, 소스 체크섬은 `docker/versions.json`에서 관리합니다. Component는 빌드 대상
서버에 맞춰 링크하므로 **MySQL 메이저 버전과 CPU 아키텍처별로 각각 빌드**해야 합니다.

## 설치

```sh
scripts/verify.sh 8.4          # 빌드 · 설치 · 통합 시나리오 재생까지 한 번에
```

또는 배포된 서버 이미지를 쓰면 됩니다. 공식 `mysql` 이미지에 component 가 `plugin_dir` 에 들어가
있고 첫 기동에 설치까지 됩니다.

```sh
docker run -d -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
  devgyurak/mysql-gcm-server:mysql8.4 --loose_gcm.strict=ON --binlog-format=ROW
```

태그는 `<version>-mysql<major>` 와 `mysql<major>` 입니다(멀티아치, amd64 + arm64). `latest` 는 두지
않습니다 — 어느 major 를 뜻하는지 모호합니다. 초기화는 **빈 데이터 디렉터리**에서만 실행되므로,
기존 볼륨에 붙이면 `INSTALL COMPONENT 'file://component_gcm'` 을 직접 실행해야 하고 이는 서버마다
필요합니다(제약 14).

개별 단계로 나누면 다음과 같습니다.

```sh
scripts/build-in-docker.sh 8.4            # -> build/8.4/component_gcm.so
docker cp build/8.4/component_gcm.so mysql-dev-8.4:"$(
  docker exec mysql-dev-8.4 mysql -uroot -N -e 'SELECT @@plugin_dir')"/component_gcm.so
docker exec mysql-dev-8.4 mysql -uroot -e "INSTALL COMPONENT 'file://component_gcm'"
```

`plugin_dir`는 이미지마다 다릅니다. Oracle Linux 기반 이미지에서는 `/usr/lib64/mysql/plugin/`입니다.
경로를 하드코딩하지 말고 서버에 조회하세요.

## 함수

| 함수 | 봉투 | 반환 | 용도 |
|:--|:--|:--|:--|
| `gcm_encrypt(plaintext, key [, aad])` | `0x02` — 무작위 96비트 nonce | `BLOB` | 다시 읽기만 하는 모든 값 |
| `gcm_encrypt_det(plaintext, key [, aad])` | `0x03` — 합성 nonce | `BLOB` | 조인 키, `UNIQUE`, 정확일치 |
| `gcm_decrypt(ciphertext, key [, aad])` | `0x01` · `0x02` · `0x03` 읽기 | `utf8mb4` 태깅된 `VARCHAR` | 읽기, 평문에 대한 `LIKE` |

`key`는 **정확히 32바이트**여야 하며, 다른 길이는 *매 호출*에서 오류입니다. `AES_ENCRYPT`의 키 접기
동작은 의도적으로 재현하지 않습니다. 태그 검증 실패는 `gcm.strict=ON`(기본값)일 때 오류, OFF일 때
NULL입니다 — 잘못된 봉투나 키 길이는 *항상* 오류입니다. `gcm.strict=OFF`로 데이터 손상을 숨기지
않습니다.

```sql
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');  -- fixture key

INSERT INTO patients (name_enc) VALUES (gcm_encrypt('홍길동', @k));
SELECT id FROM patients WHERE gcm_decrypt(name_enc, @k) LIKE '%길%';   -- 서버측 부분일치
```

### 봉투 형식

바이트 배치·오류 코드·테스트 벡터의 기준 문서는 **`spec/envelope.md`** 입니다.

```
0x02  무작위 nonce  ·  0x03  결정적                          전체 길이 = 평문 + 29 바이트
┌─────────┬───────────────────┬──────────────────────┬──────────────────┐
│ version │ nonce             │ ciphertext           │ tag              │
│ 1       │ 12                │ n                    │ 16               │
│ 02 / 03 │ RAND_bytes / HMAC │ AES-256-GCM          │ GCM, 128비트     │
└─────────┴───────────────────┴──────────────────────┴──────────────────┘
  결정적 nonce = HMAC-SHA256(HMAC-SHA256(key, "mysql-gcm/v1/det-nonce"), plaintext)[0..12)

0x01  legacy CBC, 복호화 전용, 인증되지 않음                  전체 길이 = 17 + 16k 바이트
┌─────────┬───────────────────┬─────────────────────────────────────────┐
│ 01      │ IV 16             │ AES-256-CBC + PKCS#7        (태그 없음)  │
└─────────┴───────────────────┴─────────────────────────────────────────┘
  기존 AES_ENCRYPT 값에 접두만 붙이는 이관 — 재암호화가 없습니다 (제약 8)
```

## 테스트

단위 테스트만 libcrypto 에만 링크해 서버 없이 돌고, 나머지는 모두 실서버를 씁니다.

| 계층 | 무엇을 보증하는가 | 명령 |
|:--|:--|:--|
| **단위** — 1,434 케이스, ASan + UBSan | NIST CAVP KAT, 스펙 벡터 전체, 봉투 경계, 키 소거, nonce 충돌 샘플링 | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit -j"$(getconf _NPROCESSORS_ONLN)"` |
| **통합** — 10 시나리오 × 3 메이저 | 한글 `LIKE`, strict 의미론과 버전별 범위, NULL·크기 경계, v1 dual-read, 8.x 인자 결함 | `scripts/verify.sh 8.0` · `8.4` · `9` |
| **MTR** — 7 테스트 | 서버 자체 하니스에서의 같은 표면 + ROW 복제와 SBR 불일치 | `scripts/mtr.sh 8.4` |
| **E2E** — 7 시나리오 | primary + replica + 독립 샤드, SQL 만으로 | `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner` |
| **부하** | `AES_DECRYPT` 대비 p95 와 회귀 게이트 | `python tests/load/run.py --rows 300000 --concurrency 1,8,32 --gate tests/load/baseline.json` |

최신 실측값과 게이트 기준은 `docs/perf.md` 에 있습니다.

## 저장소 구조

```
src/            component: component.cc, udf_*.cc, sysvar.cc + 서버 독립 코어
                (gcm, envelope, nonce — MySQL 헤더를 쓰지 않아 tests/unit 이 직접 링크)
spec/           envelope.md(기준 문서) + test-vectors.json(NIST CAVP + 프로젝트 벡터)
docs/           design.md(근거·개정 A1~A8) · ops-constraints.md · perf.md
tests/          unit(GoogleTest) · integration(SQL + expected) · e2e(compose) · load
mysql-test/     MTR 스위트 gcm/
docker/         MySQL 메이저별 빌드 이미지 + versions.json
scripts/        build-in-docker.sh · dev-up.sh · verify.sh · mtr.sh · gen-vectors.py
```

## 애플리케이션 연결과 개발 도구

애플리케이션은 기존 MySQL 드라이버로 SQL 함수를 호출합니다. 배포 대상은 서버 component이며
Python·Java 암호화 SDK를 제공하지 않습니다. 드라이버 통합도 필요하지 않습니다.

Python은 개발 도구와 SQL 테스트 runner에만 사용합니다. 저장소의 테스트 벡터를 확인하려면
`scripts/requirements.txt`의 의존성을 설치한 뒤 `python scripts/gen-vectors.py --check`를 실행하세요.
이 내부 생성기는 공개 픽스처 키와 고정 nonce를 사용하며, 애플리케이션 API가 아닙니다.

## AI 에이전트와 작업하기

Codex·Cursor·OpenCode는 `AGENTS.md`, Claude Code는 `CLAUDE.md`를 진입점으로 사용합니다.
스킬 원본은 `.agents/skills`, 규칙 원본은 `.agents/rules`, 서브에이전트 원본은 `.claude/agents`에 있습니다.
도구별 어댑터는 `scripts/agents-sync.sh`로 생성하며, CI에서 `--check`로 최신 상태를 확인합니다.

## 라이선스

**GPLv2** — [LICENSE](LICENSE) 참고. MySQL component 는 서버의 GPLv2 헤더에 링크하므로 GPLv2 가
호환되는 선택이며, 근거는 `docs/design.md` §7 에 있습니다. 소스에는
`SPDX-License-Identifier: GPL-2.0-only` 를 표기합니다.
