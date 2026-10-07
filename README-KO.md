<p align="center">
  <img src="docs/assets/banner.png" width="720"
       alt="mysql-gcm — MySQL 용 AES-256-GCM. 서버 component 로, 평문에 대한 서버측 LIKE 를 유지합니다.">
</p>

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
  <img alt="status: 0.1.0 ready to tag" src="https://img.shields.io/badge/status-0.1.0%20%ED%83%9C%EA%B9%85%20%EC%A4%80%EB%B9%84-brightgreen">
  <a href="LICENSE"><img alt="license: GPLv2" src="https://img.shields.io/badge/license-GPLv2-blue"></a>
</p>

`gcm_encrypt`, `gcm_encrypt_det`, `gcm_decrypt` 를 MySQL **component** 로 등록합니다(레거시 UDF
플러그인이 아닙니다). 복호화 결과에 `utf8mb4` 문자셋을 태깅하므로 MySQL 자신의 collation 이
`LIKE '%길%'` 를 **서버 안에서** 처리합니다 — 암호화된 컬럼에 부분일치 검색을 유지하는 것이 이
프로젝트의 존재 이유입니다. 측정한 워크로드에서는 `AES_DECRYPT` 빌트인과 비용을 비교하며, 결과는
하드웨어·수트·워크로드에 따라 달라집니다. [성능](#성능)을 참고하세요.

> **현재 상태: 0.1.0 태깅 준비 완료.** MySQL 8.0 · 8.4 · 9.x 서버 소스 트리에서 빌드되고, CI 에서 세 major
> 전부에 대해 단위 · 통합 테스트를, 8.4 에서 MTR · E2E · 부하 테스트를 통과합니다. 봉투 형식은 확정(`spec/envelope.md`),
> 부하 게이트는 CI 하드웨어 3회 측정으로 설정, 릴리스 파이프라인은 끝까지 드라이런했습니다 — 아티팩트 6개,
> 서버 이미지 3종 기동·쿼리 검증, 체크섬 서명 및 독립 검증. **아직 공개된 것은 없습니다**: 태그가 없으므로
> GitHub Release 도 Docker Hub 태그도 없습니다. 그대로 남아 있는 단서: **독립적인 암호 검토를 받지
> 않았습니다**(제약 13).

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
   위한 기능입니다. 자유 텍스트에는 사용하지 마세요. 또한 평범한 봉인의 **3.5~5배** 비용이 듭니다 —
   암호가 아니라 nonce 를 위한 HMAC 2회 때문입니다. 복호화 비용은 두 변형이 같습니다 (`docs/perf.md`).
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
    SQL에서 계산해야 한다면 **실제 테이블**에 먼저 쓰고 저장된 컬럼으로 호출하세요 — *파생* 테이블은
    기본 설정에서 바깥 쿼리로 병합되어 도움이 되지 않습니다. `CAST`만으로도 충분하지 않습니다.
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
16. **`gcm.min_key_bytes` 가 막지 않으면 잘린 키가 조용히 약한 암호를 고릅니다.** 키 길이가
    수트를 선택하므로(32바이트 = AES-256-GCM, 24 = AES-192, 16 = AES-128), 클라이언트 버그나 잘못
    설정된 환경변수, 잘못 자른 버퍼 때문에 잘린 32바이트 키는 *더 약한 수트의 유효한 키*가 되고,
    `gcm_encrypt` 가 그것으로 봉인한 뒤 아무도 요청하지 않은 강도로 성공을 보고합니다.
    `gcm.min_key_bytes` 는 GLOBAL 이고 기본값이 `32` 라 바로 그것을 거부합니다. 더 작은 수트를 쓸
    의도가 없다면 그대로 두세요. 세션 설정이 아니라 관리자 정책이며, 여러 애플리케이션이 쓰는
    서버에서 낮추면 그 전부가 보호를 잃습니다. 복호화는 이 값을 보지 않으므로 다시 올려도 낮은
    상태에서 쓴 데이터가 잠기지 않습니다. 복호화 시의 키 길이 오류는 봉투와 키가 어긋난다는
    뜻이지 절단의 증거가 아닙니다 — version 바이트 손상도 같은 오류를 냅니다. 바닥을 24 로 두면
    AES-192 와 AES-256 은 허용되고 AES-128 만 거부됩니다.

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

### 릴리스 파일 검증

릴리스에는 tar 6개(major 3종 x amd64/arm64), `SHA256SUMS`, 그에 대한 서명과 인증서, SPDX SBOM 이
들어 있습니다(SBOM 도 체크섬 대상입니다). 서명은 키 없는(keyless) 방식이라 검증으로 확인하는 것은
**어느 저장소의 어느 워크플로가 어느 ref 에서 그 체크섬을 만들었는지**입니다. 우리가 보관하거나 유출될
장기 키가 없습니다. 신원의 `@refs/tags/v` 부분을 빼지 마세요 — 빼면 같은 저장소가 브랜치에서 만든 서명,
즉 릴리스 드라이런의 산출물까지 통과합니다.

```sh
gh release download v0.1.0 -R devgyurak/mysql-gcm
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/devgyurak/mysql-gcm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf component_gcm-0.1.0-mysql8.4-amd64.tar.gz     # -> component_gcm.so
```

받은 `.so` 를 해당 서버의 `plugin_dir` 에 복사하고 위와 같이 설치합니다. major 를 맞추세요.
8.4 용으로 빌드한 component 는 9.x 에 로드되지 않습니다.

## 함수

| 함수 | 봉투 | 반환 | 용도 |
|:--|:--|:--|:--|
| `gcm_encrypt(plaintext, key [, aad])` | `0x02` / `0x04` / `0x06` — 무작위 96비트 nonce | `BLOB` | 다시 읽기만 하는 모든 값 |
| `gcm_encrypt_det(plaintext, key [, aad])` | `0x03` / `0x05` / `0x07` — 합성 nonce | `BLOB` | 조인 키, `UNIQUE`, 정확일치 |
| `gcm_decrypt(ciphertext, key [, aad])` | `0x01`~`0x07` 읽기 | `utf8mb4` 태깅된 `VARCHAR` | 읽기, 평문에 대한 `LIKE` |

`key`는 **32바이트(AES-256), 24바이트(AES-192) 또는 16바이트(AES-128)**여야 하며, 다른 길이는
*매 호출*에서 오류입니다.
`AES_ENCRYPT`의 키 접기 동작은 의도적으로 재현하지 않습니다. 태그 검증 실패는 `gcm.strict=ON`(기본값)
일 때 오류, OFF일 때 NULL입니다 — 잘못된 봉투나 키 길이는 *항상* 오류입니다. `gcm.strict=OFF`로
데이터 손상을 숨기지 않습니다.

**키 길이가 암호를 선택하며, 그 외에는 아무것도 선택하지 않습니다**(`docs/design.md` 개정 A10).

| 키 | 수트 | `gcm_encrypt` | `gcm_encrypt_det` |
|---:|:--|:--|:--|
| 32 B | AES-256-GCM | `0x02` | `0x03` |
| 24 B | AES-192-GCM | `0x06` | `0x07` |
| 16 B | AES-128-GCM | `0x04` | `0x05` |

배치는 모두 동일하고(평문 + 29바이트), 복호화할 때는 version 바이트가 필요한 키 길이를 말해주므로
불일치는 태그 실패가 아니라 키 오류로 보고됩니다.

여기에는 대가가 있고, 그래서 **AES-256 아래는 전부 기본적으로 꺼져 있습니다**. 전송 중에 잘린 32바이트
키는 *유효한* 24바이트 또는 16바이트 키라서, 바닥이 없으면 `gcm_encrypt` 가 그것으로 봉인하고 아무도
요청하지 않은 강도로 성공을 보고합니다. `gcm.min_key_bytes`(GLOBAL, 기본값 `32`)가 그 바닥입니다.
그대로 두면 서버는 이전과 똑같이 동작하며 짧은 키를 거부합니다. `24` 로 바꾸면 AES-192 까지, `16` 으로
바꾸면 두 작은 수트 모두 허용됩니다. 복호화는 이 값을 전혀 보지 않으므로, 바닥을 다시 올려도 낮은
상태에서 쓴 데이터가 잠기지 않습니다.

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

## 성능

GitHub 호스팅 `ubuntu-24.04` 러너, MySQL 8.4.11, 2026-10-02 측정. 30만 행 중 29,918행이 `'%김%'` 에
일치합니다. 비율은 실행 간 비교에 도움이 되지만 비율과 절대 시간 모두 하드웨어·워크로드에 따라
달라질 수 있습니다. 배포할 곳에서 다시 측정하세요.

### 서버측 복호화 + 부분일치

이 component 가 답하려는 질문입니다. 암호화된 컬럼을 서버 안에서 필터링하는 게 쓸 만한가?

| 행 | 동시 세션 | `gcm_decrypt(col) LIKE` p95 | `AES_DECRYPT(col) LIKE` p95 | 비율 |
|---:|---:|---:|---:|---:|
| 300,000 | 1 | 255 ms | 269 ms | **0.95** |
| 300,000 | 8 | 1,073 ms | 1,154 ms | **0.93** |
| 300,000 | 32 | 4,172 ms | 4,555 ms | **0.92** |

연속 3회 중 **가장 느린 런**이고, 각 쌍은 서로 다른 런에서 좋은 값을 골라 섞지 않고 **같은 런**에서
가져왔습니다. `docs/design.md` §1.2 는 후보 10만 행을 애플리케이션으로 가져와 복호화하는 비용만으로
~1.1초를 추정했는데, 같은 필터를 서버에서 돌리면 255ms 입니다.

`Created_tmp_disk_tables` 는 모든 런·모든 동시성에서 증가하지 않았습니다 — `docs/design.md` §5.3 이
제기한 "평문이 디스크 임시 테이블에 남는가" 에 대한 답입니다. 다만 이 워크로드에 대한 관측이지 보장은
아닙니다. 정렬이나 큰 그룹핑이 붙는 쿼리는 여전히 디스크로 넘칠 수 있습니다.

### 결정적 변형의 비용

`gcm_encrypt_det` 은 조인 키·`UNIQUE`·정확일치 조회용입니다(제약 6). 그리고 **쓰기 비용이 몇 배** 더
들며, 그 원인은 암호가 아니라 nonce 에 필요한 HMAC 입니다 — 쓰기가 많은 컬럼에 쓰기 전에 알아야 할
내용입니다.

| 평문 | `gcm_encrypt` | `gcm_encrypt_det` |
|---:|---:|---:|
| 16 B | 2.7~3.2배 | 4.9배 |
| 256 B | 2.6~3.0배 | 4.7~4.8배 |
| 4 KiB | 1.6~1.8배 | 4.0배 |
| 64 KiB | 1.07배 | 3.6배 |

평범한 AES-256-GCM 봉인 대비이고, 3회 측정의 범위입니다. `gcm_encrypt` 의 몫은 `RAND_bytes(12)` 의
고정 비용 약 450ns 입니다 — 새 nonce 의 값이고, 짧은 값에서는 지배적이지만 긴 값에서는 보이지 않습니다.
`gcm_encrypt_det` 은 대신 HMAC-SHA256 2회(`spec/envelope.md` §3)를 내는데, 그건 같은 방식으로
상쇄되지 않습니다. **이 비율이 크기에 따라 오르는지 내리는지는 CPU 에 달려 있습니다**: 이 런들은
4.9 → 3.6 으로 내려가지만, AES 가 빠른 러너에서는 5.6 → 9.7 로 올라갔습니다. 복호화 비용은 두 변형이
같습니다.

### 더 작은 수트가 얻는 것이 있나?

첫 측정만으로는 일관된 SQL 속도 이점이 확인되지 않았습니다. 개발 머신의 코어 측정 한 번에서
AES-192 와 AES-128 의 시간은 연산과 크기에 따라 AES-256 의 0.81~1.16배였습니다. 첫 CI 코어 측정에서는
0.919~1.012배였고, 64 KiB AES-128 복호화는 8.1% 빨랐습니다. 개별 실행의 관측값이며, 다른 머신의
범위를 보장하거나 비용이 같음을 증명하지 않습니다.

SQL 수준에서 개발 머신의 GCM p95 는 1세션에서 42.7~45.8 ms, 8세션에서 110.7~123.8 ms였습니다.
각 실행의 AES-256-CBC 기준값으로 나눈 비율은 각각 0.933~1.053, 0.773~0.795이며, 응답시간과는
다른 지표입니다. 각 수트의 첫 CI 부하 실행은 기존 게이트를 통과했지만, 서로 다른 호스팅 러너에서
실행했으므로 수트의 순위나 스캔·복호화가 각각 차지하는 시간을 확정할 수 없습니다.

AES-256 을 기본 권고로 유지합니다. 보안·상호운용성 요구가 허용할 때 더 작은 수트를 쓰고, 성능을
고려해 선택하기 전에는 실제 워크로드를 측정하세요. 반복 CI 측정은 #18 의 남은 항목입니다.
실행 링크와 전체 표는 `docs/perf.md` 에 있습니다.

두 게이트, 기존 기준값의 근거가 된 3회 측정, 새 수트별 측정 결과는
[`docs/perf.md`](docs/perf.md) 에 있습니다.

## 테스트

단위 테스트만 libcrypto 에만 링크해 서버 없이 돌고, 나머지는 모두 실서버를 씁니다.

| 계층 | 무엇을 보증하는가 | 명령 |
|:--|:--|:--|
| **단위** — 1,434 케이스, ASan + UBSan | NIST CAVP KAT, 스펙 벡터 전체, 봉투 경계, 키 소거, nonce 충돌 샘플링 | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` |
| **통합** — 10 시나리오 × 3 메이저 | 한글 `LIKE`, strict 의미론과 버전별 범위, NULL·크기 경계, v1 dual-read, 8.x 인자 결함 | `scripts/verify.sh 8.0` · `8.4` · `9` |
| **MTR** — 7 테스트 | 서버 자체 하니스에서의 같은 표면 + ROW 복제와 SBR 불일치 | `scripts/mtr.sh 8.4` |
| **E2E** — 7 시나리오 | primary + replica + 독립 샤드, SQL 만으로 | `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner` |
| **부하** | `AES_DECRYPT` 대비 p95 와 회귀 게이트 | `python tests/load/run.py --rows 300000 --concurrency 1,8,32 --gate tests/load/baseline.json` |
| **벤치** — 게이트 12 케이스 | 코어를 같은 알고리즘의 직선적 구현과 비교. 부하 게이트가 20% 도 못 보는 자리에서 ~7% 구조적 회귀에 실패한다 | `scripts/bench.sh --gate` |

최신 실측값과 두 게이트 기준은 `docs/perf.md` 에 있습니다. **벤치**는 PR 이 아니라 코어를 건드리는
`develop`·`main` 머지에서 돕니다.

## 저장소 구조

```
src/            component: component.cc, udf_*.cc, sysvar.cc + 서버 독립 코어
                (gcm, envelope, nonce — MySQL 헤더를 쓰지 않아 tests/unit 이 직접 링크)
spec/           envelope.md(기준 문서) + test-vectors.json(NIST CAVP + 프로젝트 벡터)
docs/           design.md(근거·개정 A1~A8) · ops-constraints.md · perf.md
tests/          unit(GoogleTest) · integration(SQL + expected) · e2e(compose) · load
                bench(Google Benchmark, 샌타이저 끔 — `docs/perf.md`)
mysql-test/     MTR 스위트 gcm/
docker/         MySQL 메이저별 빌드 이미지 + versions.json + 배포용 서버 이미지
scripts/        build-in-docker.sh · dev-up.sh · verify.sh · mtr.sh · bench.sh
                unit-in-docker.sh(CI 와 같은 GCC) · smoke-image.sh(릴리스 이미지 검증)
                gen-vectors.py · check-architecture.py · check-action-pins.py
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
