<p align="center">
  <img src="docs/assets/banner.png" width="720"
       alt="mysql-gcm — MySQL 용 AES-GCM. 서버 component 로, 평문에 대한 서버측 LIKE 를 유지합니다.">
</p>

<p align="center">
  <a href="#바로-해-보기">바로 해 보기</a> · <a href="#설치">설치</a> · <a href="#함수">함수</a> ·
  <a href="#정말-되나">근거</a> · <a href="docs/design-KO.md">설계</a> ·
  <a href="spec/envelope.md">Spec</a> · <a href="README.md">English</a>
</p>

<p align="center">
  <img alt="MySQL 8.0 | 8.4 | 9.x" src="https://img.shields.io/badge/MySQL-8.0%20%7C%208.4%20%7C%209.x-4479A1?logo=mysql&logoColor=white">
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white">
  <img alt="OpenSSL 3" src="https://img.shields.io/badge/OpenSSL-3.x-721412?logo=openssl&logoColor=white">
  <img alt="status: pre-release" src="https://img.shields.io/badge/status-%EB%A6%B4%EB%A6%AC%EC%8A%A4%20%EC%A0%84-orange">
  <a href="LICENSE"><img alt="license: GPLv2" src="https://img.shields.io/badge/license-GPLv2-blue"></a>
</p>

# mysql-gcm

**암호화한 컬럼에도 `LIKE` 가 됩니다.**

`gcm_encrypt`, `gcm_encrypt_det`, `gcm_decrypt` 세 SQL 함수로 MySQL 8.0 · 8.4 · 9.x 에 인증 암호화
AES-GCM 을 서버 **component** 로 더합니다. 복호화 결과에 `utf8mb4` 문자셋을 태깅하므로
`WHERE gcm_decrypt(name, @k) LIKE '%길%'` 가 MySQL 자신의 collation 으로 **서버 안에서** 돕니다.
암호화된 한글 컬럼에서 부분일치 검색을 지키는 것이 이 프로젝트의 존재 이유입니다.

**릴리스 전입니다. 아직 공개된 것이 없고, 이 구성은 사람의 암호 감사를 받지 않았습니다.** 두
질문에 대한 범위 한정 AI 설계 검토가 `docs/design-KO.md` A12 에 기록돼 있습니다(제약 13). 기대기
전에 아래 제약을 먼저 읽으세요.

## 먼저 확인하세요 — 운영 제약

버그 목록이 아니라 이 방식의 성질이며, component 가 고칠 수 없습니다. 전문과 근거:
[`docs/ops-constraints.md`](docs/ops-constraints.md), `docs/design-KO.md` §6 과 개정들.

| 주제 | 제약 |
|---|---|
| **토폴로지** — 복제, 승격, 샤딩 | 1, 14, 15 |
| **키와 nonce** — 예산, 교체, AAD, 복구, 키 크기 | 7, 11, 12, 16 |
| **질의 동작** — 옵티마이저, 결정적 변형이 드러내는 것 | 5, 6 |
| **데이터와 버전** — 레거시 봉투, 문자셋, sysvar 범위, 인자 | 8, 9, 10 |
| **환경** — 로그, 관리형 서비스, my.cnf | 2, 3, 4 |
| **보증 범위** — 무엇을 확인하고 무엇을 하지 않는가 | 13 |

1. **`gcm_encrypt` 는 비결정적입니다: ROW binlog 를 쓰세요.** 문장 기반 복제에서는 복제본이 다른
   nonce 를 계산합니다. 생성 컬럼과 인덱스에는 쓸 수 없습니다.
2. **키와 평문은 SQL 인자**이므로 general·slow 로그, `performance_schema`, SBR binlog 에 남을 수
   있습니다. `'%김%'` 같은 패턴도 마찬가지입니다. `AES_ENCRYPT` 와 같은 노출입니다.
3. **직접 운영하는 MySQL 전용입니다.** RDS · Aurora · Cloud SQL 은 `plugin_dir` 를 열어 주지 않습니다.
4. **my.cnf 에는 `loose_` 를 붙이세요**(`loose_gcm.strict=ON`). 붙이지 않으면 component 설치 전에는
   서버가 시작하지 않습니다.
5. **옵티마이저는 이 함수를 들여다보지 못합니다.** `gcm_decrypt(col) LIKE` 는 후보를 훑습니다.
   선택도는 다른 조건에서 와야 합니다.
6. **`gcm_encrypt_det` 은 평문이 같은지를 드러냅니다.** 조인 키 · `UNIQUE` · 정확일치에만 쓰고 자유
   텍스트에는 쓰지 마세요. 쓰기 비용은 평범한 봉인의 몇 배입니다.
7. **키 하나에 AAD 규칙은 하나**입니다. 결정적 호출이라면 모든 서버 · 컬럼 · 애플리케이션에서
   같아야 합니다. 한 키로 한 평문에 AAD 를 둘 쓰면 nonce 가 재사용되어 위조가 가능해집니다.
8. **레거시 `0x01`(CBC) 봉투는 인증되지 않으며, 평문이 이미 UTF-8 이어야 합니다.** dual-read 는
   이관용이니 끝나면 `0x01` 을 거부하세요. 검색해야 하는 값은 원시 바이트가 아니라 텍스트로 암호화하세요.
9. **MySQL 9.0 이전에는 `gcm.strict` 가 GLOBAL 전용입니다.** `SET SESSION` 은 9.x 에서만 됩니다.
10. **계산식이 아니라 저장된 값을 넘기세요.** 8.0 · 8.4 는 일부 계산된 문자열 인자를 두 번째 행부터
    낡은 값으로 넘기므로 `gcm_encrypt_det(CONCAT(a, b), @k)` 가 엉뚱한 바이트를 봉인할 수 있습니다.
    컬럼 · 리터럴 · 변수 · 바인딩 파라미터는 안전합니다(A7).
11. **배포 전에 키별 사용량 예산과 교체 계획을 정하세요.** 키를 공유하는 모든 곳을 합산합니다.
    키는 수트와 도메인마다 독립 생성하고, 한 키를 다른 길이로 바꿔 쓰지 마세요. 결정적 AES-128 은
    승인된 예산, 유한한 사용 기간, 보존 기간이 필요합니다(A12). component 는 아무것도 세지 않고 교체하지도 않습니다.
12. **재시도와 복원도 nonce 관리입니다.** 봉투 복사는 새 암호화가 아닙니다. 결정적 재시도에서 AAD 만
    바꾸지 마세요. 복원하면서 사용량 집계를 되돌리지 마세요. 복구 뒤 RNG 상태가 불확실하면 쓰기를 멈추세요.
13. **검증은 감시가 아니고, 테스트는 증명이 아닙니다.** nonce 재사용, 호출 간 AAD 정책, 사용량 한도는
    강제하지 않습니다. 사람의 암호 감사는 없었고, A12 의 AI 검토는 설계 질문 둘만 다룹니다. 운영 전에
    구성과 배포를 검토하세요.
14. **component 설치는 복제되지 않습니다.** 복호화하는 모든 서버와 승격될 수 있는 모든 복제본에 설치하세요.
15. **샤드는 암호문이 아니라 안정된 식별자로 나누세요.** 샤드 간 결정적 값 비교에는 같은 키 · 평문 ·
    AAD 가 필요하고, 키를 공유하는 모든 샤드의 암호화 횟수를 합산해야 합니다.
16. **잘린 키는 `gcm.min_key_bytes` 가 막지 않으면 조용히 약한 암호를 고릅니다.** 키 길이가 수트를
    정합니다. 이 하한은 GLOBAL 이고 기본값 `32` 이며 복호화는 무시하므로, 올려도 데이터가 잠기지 않습니다.

## 지원 범위

| MySQL | 빌드·테스트 버전 | `gcm.strict` 범위 | 제약 10 재현 형태 |
|:--|:--|:--|:--|
| **8.0** | 8.0.43 | GLOBAL | `REPEAT(str, int_col)` 꼴 인자 |
| **8.4** | 8.4.11 | GLOBAL | `CONCAT(str, int_col)` 꼴 인자 |
| **9.x** | 9.4.0 | GLOBAL **+ SESSION** | 둘 다 아님 |

component 는 빌드된 서버에 링크되므로 MySQL major 와 아키텍처마다 결과물이 하나씩입니다. 정확한
버전과 digest: `docker/versions.json`.

## 바로 해 보기

저장소를 클론하고 Docker 로 — component 가 설치된 MySQL 8.4 컨테이너:

```sh
scripts/dev-up.sh 8.4                    # 컨테이너 mysql-dev-8.4
scripts/build-in-docker.sh 8.4           # -> build/8.4/component_gcm.so
docker cp build/8.4/component_gcm.so \
  mysql-dev-8.4:"$(docker exec mysql-dev-8.4 mysql -uroot -N -e 'SELECT @@plugin_dir')"component_gcm.so
docker exec -it mysql-dev-8.4 mysql -uroot -e "INSTALL COMPONENT 'file://component_gcm'"
docker exec -it mysql-dev-8.4 mysql -uroot
```

```sql
CREATE DATABASE demo; USE demo;
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');  -- 공개 fixture 키

CREATE TABLE patients (id INT AUTO_INCREMENT PRIMARY KEY, name_enc VARBINARY(128));
INSERT INTO patients (name_enc) VALUES (gcm_encrypt('홍길동', @k)), (gcm_encrypt('김철수', @k));

SELECT id, gcm_decrypt(name_enc, @k) AS name FROM patients
 WHERE gcm_decrypt(name_enc, @k) LIKE '%길%';     -- 1행, 홍길동 — 서버 안에서 일치
```

저장된 값은 `0x02 ‖ nonce ‖ ciphertext ‖ tag` 입니다. 한 바이트만 바꿔도 `gcm_decrypt` 는 아무것도
돌려주지 않고 오류를 냅니다. 통합 시나리오 전체를 돌려 보려면 `scripts/verify.sh 8.4`.

## 설치

**소스에서**, major 하나씩: `scripts/build-in-docker.sh <8.0|8.4|9>` 가
`build/<major>/component_gcm.so` 를 만듭니다. 그 서버의 `plugin_dir`(서버에 물어보세요:
`SELECT @@plugin_dir`)에 복사하고 `INSTALL COMPONENT 'file://component_gcm'` 를 실행하세요 — 복호화하는
**모든** 서버에서(제약 14). 8.4 용으로 빌드한 component 는 9.x 에 올라가지 않습니다.

**릴리스에서**, 공개된 뒤에: tarball 6개(3 major × amd64/arm64), 릴리스 워크플로가 키 없이 서명한
`SHA256SUMS`, SPDX SBOM. 이 저장소의 태그된 워크플로로 서명을 확인한 뒤 체크섬을 확인하세요:

```sh
gh release download v<version> -R devgyurak/mysql-gcm
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/devgyurak/mysql-gcm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
```

`@refs/tags/v` 부분을 지우지 마세요. 없으면 같은 명령이 브랜치나 드라이런에서 만든 서명도 받아들입니다.
릴리스는 서버 이미지 `devgyurak/mysql-gcm-server` 도 `<version>-mysql<major>` 와 `mysql<major>`
태그(amd64 + arm64)로 게시합니다 — 새 데이터 디렉터리의 첫 기동 때 component 가 설치되는 공식
이미지입니다. 어느 major 를 뜻할지 모호하므로 `latest` 태그는 없습니다.

## 함수

| 함수 | 반환 | 용도 | 봉투 (AES-256 / 192 / 128) |
|:--|:--|:--|:--|
| `gcm_encrypt(plaintext, key [, aad])` | `BLOB` | 다시 읽기만 하는 모든 값 | 랜덤 nonce: `0x02` / `0x06` / `0x04` |
| `gcm_encrypt_det(plaintext, key [, aad])` | `BLOB` | 조인 키, `UNIQUE`, 정확일치 | 합성 nonce: `0x03` / `0x07` / `0x05` |
| `gcm_decrypt(ciphertext, key [, aad])` | `VARCHAR` `utf8mb4` | 읽기, 그리고 평문에 대한 `LIKE` | `0x01`–`0x07` 을 읽음 |

- **키 길이가 암호를 정하고, 다른 것은 정하지 않습니다:** 32바이트는 AES-256-GCM, 24는 AES-192,
  16은 AES-128. 다른 길이는 매 호출 오류이며, `AES_ENCRYPT` 의 키 접기는 일부러 따르지 않습니다.
- **AES-256 미만은 기본적으로 꺼져 있습니다.** `gcm.min_key_bytes`(GLOBAL, 기본값 `32`)가 암호화에서
  짧은 키를 거부합니다. 작은 수트를 쓰려면 `24` 나 `16` 으로 낮추세요(제약 16).
- **태그 검증 실패**는 `gcm.strict` 가 ON(기본값)이면 오류, OFF 면 NULL 입니다. 잘못된 봉투나 키
  길이는 언제나 오류입니다.

바이트 배치, 실패 코드, 테스트 벡터: [`spec/envelope.md`](spec/envelope.md).

## 정말 되나?

**맞는 행을 돌려주고, 변조를 거부하며, 암호화된 30만 행을 서버에서 거르는 데 어느 CI run 에서도
`AES_DECRYPT` 보다 느리지 않았습니다.** 그것이 무엇을 보여 주고 무엇은 보여 주지 않는지:

| 주장 | 근거 | 한계 |
|:--|:--|:--|
| 바이트가 맞다 | NIST CAVP KAT 와 모든 spec 벡터, ASan/UBSan 아래 단위 6,493건 | 적합성이지 안전성 증명은 아님 |
| 모든 major 에서 SQL 동작이 맞다 | 8.0 · 8.4 · 9.x 통합 시나리오 11개, 8.4 MTR, 복제본을 포함한 E2E | MTR 결과는 8.4 에서만 기록 |
| 서버측 `LIKE` 가 쓸 만하다 | 30만 행 `gcm_decrypt(col) LIKE` p95 가 `AES_DECRYPT` 의 **0.75~0.96배**, 세 수트에 걸친 CI 9회 | 호스팅 러너 기준. 개발 노트북에서는 1.0 을 넘은 적도 있음. 배포 하드웨어에서 다시 재세요 |
| 숨은 호출당 작업이 없다 | 같은 알고리즘의 직선 구현 OpenSSL 대비 코어 벤치 60개 게이트, 반복 5회를 섞어서 | 비율이지 절대 시간이 아님 |
| 평문이 디스크에 남지 않는다 | 모든 load run 에서 `Created_tmp_disk_tables` 변화 없음 | 이 워크로드 한정. 정렬이나 큰 `GROUP BY` 는 넘칠 수 있음 |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/perf/load-ratio-dark.svg">
  <img src="docs/assets/perf/load-ratio-light.svg" width="100%"
       alt="30만 행에서 gcm_decrypt LIKE 의 p95 를 AES_DECRYPT LIKE 로 나눈 비율을 CI 9회, 1·8·32 세션, AES-256·192·128 별로 찍은 점 그래프. 모든 점이 0.75~0.96 으로 1.0 아래에 있고, 1.10 에 회귀 게이트 선이 있다.">
</picture>

점 하나가 CI run 하나의 p95 비율이며, 실선 아래는 빌트인보다 빠르다는 뜻입니다. 수치, run 링크, 이
그래프의 데이터 파일: `docs/perf.md`,
[`docs/assets/perf/load-ratios.json`](docs/assets/perf/load-ratios.json).

함수를 고르기 전에 알아 둘 두 가지: **`gcm_encrypt_det` 은 쓰기 비용이 평범한 봉인의 몇 배**이고
(HMAC 두 번), AES 가속이 있는 하드웨어에서 **작은 수트는 속도를 거의 사지 못합니다** — 성능이 아니라
상호운용성 때문에 고르세요. 모든 숫자, run 링크, 단서: [`docs/perf.md`](docs/perf.md).

## 기여

봉투 · 함수 · sysvar 변경은 `docs/design.md` 개정으로 시작해서, `spec/` · 단위 · 서버 테스트와 같은
PR 로 들어옵니다. 암호 경로는 리뷰어 두 명이 필요합니다.

| 계층 | 실행 |
|:--|:--|
| unit | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` |
| integration | `scripts/verify.sh 8.0` · `8.4` · `9` |
| MTR | `scripts/mtr.sh 8.4` |
| E2E | `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner` |
| load | `python tests/load/run.py --rows 300000 --concurrency 1,8,32 --gate tests/load/baseline.json` |
| bench | `scripts/bench.sh --gate` |

[설계와 개정](docs/design-KO.md) · [봉투 spec](spec/envelope.md) · [운영 제약](docs/ops-constraints.md) ·
[성능](docs/perf.md) · [변경 이력](CHANGELOG.md). AI 에이전트와 작업한다면 `AGENTS.md`(또는
`CLAUDE.md`)에서 시작하세요.

애플리케이션은 기존 MySQL 드라이버로 이 함수를 부릅니다. 클라이언트 SDK 는 없습니다. 이 저장소의
Python 은 테스트, 벡터, 문서용 그래프 도구에만 씁니다.

## 라이선스

**GPLv2** — [LICENSE](LICENSE) 참고. MySQL component 는 서버의 GPLv2 헤더에 링크합니다. 근거는
`docs/design.md` §7 에 있습니다. 소스 파일에는 `SPDX-License-Identifier: GPL-2.0-only` 가 붙습니다.
