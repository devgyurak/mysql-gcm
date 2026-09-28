---
name: ci-release
description: GitHub Actions 워크플로(lint·unit·build 매트릭스·integration·e2e·load nightly·release)와 docker 빌드 이미지, 릴리스 아티팩트(체크섬·SBOM) 구성 절차. .github/, docker/ 작업에 사용.
---

# ci-release

규칙: `.agents/rules/stack-ci-docker.md`. 스켈레톤은 `.github/workflows/*.yml` 에 이미 있다 — 잡을 추가할 때 같은 패턴을 따른다.

## 워크플로 역할
| 파일 | 트리거 | 잡 | 게이트 |
|---|---|---|---|
| `lint.yml` | PR, push | clang-format/clang-tidy, ruff+mypy, architecture 경계 검사, agents-sync, shellcheck, gitleaks | 필수 |
| `unit.yml` | PR, push | gtest(ASan) 전체 벡터 · 내부 생성기 `--check` | 필수 |
| `build.yml` | PR, push, tag | 매트릭스 `versions.json` × `amd64/arm64`, 빌드 이미지 GHCR 캐시, `.so` 아티팩트 | 필수 |
| `integration.yml` | PR (build 후) | 공식 이미지 + `.so` → `scripts/verify.sh`, MTR(서버 트리 잡, 캐시) | 필수 |
| `e2e.yml` | PR label `e2e` / main push | compose 6 시나리오 | main 필수 |
| `load.yml` | nightly cron, dispatch | `tests/load/run.py --gate` , 결과 아티팩트 + `docs/perf.md` PR 자동 생성 | nightly |
| `release.yml` | tag `v*` | build 매트릭스 재사용 → tar.gz + `SHA256SUMS` + SBOM(syft) → GitHub Release | — |

## 빌드 이미지 — `docker/build.Dockerfile`
```
ARG MYSQL_VERSION
FROM oraclelinux:9 AS base        # 공식 mysql 이미지와 같은 계열 → 같은 OpenSSL
RUN dnf -y install gcc-toolset-13 cmake ninja-build openssl-devel ncurses-devel libtirpc-devel rpcgen bison wget
RUN wget https://dev.mysql.com/get/Downloads/MySQL-${MAJOR}/mysql-${MYSQL_VERSION}.tar.gz && tar xf ...
RUN cmake -S mysql-${MYSQL_VERSION} -B /build -G Ninja -DWITH_SSL=system -DDOWNLOAD_BOOST=1 -DWITH_BOOST=/boost -DWITH_UNIT_TESTS=OFF
# configure 만. 컴포넌트는 --target component_gcm 으로 필요한 것만 빌드
```
`docker/versions.json`: `{"8.0": "8.0.43", "8.4": "8.4.11", "9": "9.4.0"}` — 버전 갱신은 여기 한 곳 + README 호환표.

`scripts/build-in-docker.sh <ver>`: 이미지 없으면 build, 소스 `src/` 를 `/build-src/components/gcm` 으로 마운트하고 서버 트리 `components/` 에 `add_subdirectory` 되도록 심링크, `cmake --build /build --target component_gcm`, 산출물 `build/<ver>/component_gcm.so` 로 복사.

## 캐시 키
빌드 이미지: `sha256(docker/build.Dockerfile + versions.json[ver])`. MTR 서버 트리 빌드: 동일 키 + `mysqld` 타겟, `actions/cache` 대신 GHCR 이미지 레이어 (10GB 캐시 한도 회피).

## 릴리스 체크리스트
- [ ] `CHANGELOG.md` 항목, 봉투/스펙 변경이면 `spec/` 버전 bump 와 호환 표
- [ ] 세 서버 major × 두 arch 아티팩트, 이름 `component_gcm-<ver>-mysql<major>-<arch>.tar.gz`
- [ ] `SHA256SUMS` 서명(옵션: cosign), SBOM 첨부
- [ ] README 지원 매트릭스와 운영 제약 §6 최신
- [ ] 부하 baseline 이 이 릴리스 빌드로 갱신됐는지
