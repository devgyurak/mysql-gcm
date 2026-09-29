---
paths:
  - ".github/**"
  - "docker/**"
  - "scripts/**"
  - "tests/e2e/compose*.yml"
---
<!-- Generated from .agents/rules/stack-ci-docker.md by scripts/agents-sync.py — edit the source. -->
# CI · Docker · 스크립트 관례

- GitHub Actions. 워크플로 분리: `lint.yml`, `unit.yml`, `build.yml`(매트릭스), `integration.yml`, `e2e.yml`, `load.yml`(nightly/dispatch), `release.yml`(tag). 하나의 거대한 파일 금지.
- 액션은 SHA 로 핀 (`actions/checkout@<sha> # v4`). 태그 참조 금지 (공급망). `scripts/check-action-pins.sh` 가 강제하며 `lint.yml` 의 `workflows` 잡에서 돈다. 핀 갱신: `gh api repos/<owner>/<action>/commits/<tag> -q .sha`. 워크플로 자체는 같은 잡에서 digest 로 핀된 actionlint 이미지로 검사한다.
- 빌드 매트릭스 축: MySQL `8.0.x / 8.4.x / 9.x`(정확한 패치 버전은 `docker/versions.json` 한 곳) × `amd64 / arm64`. OpenSSL 은 각 서버 이미지의 시스템 것.
- MySQL 소스 트리 configure/build 는 비싸다. 빌드 이미지(`docker/build.Dockerfile`)를 GHCR 에 푸시하고 `versions.json` 해시로 캐시. 소스 변경 없으면 재빌드하지 않는다.
- 통합·E2E 는 공식 `mysql:<ver>` 이미지에 `.so` 를 `docker cp` 한다. **테스트는 커스텀 서버 이미지를 쓰지 않는다** — 그래야 component 버그가 이미지 빌드 문제로 가려지지 않는다.
- 예외는 **릴리스 배포 이미지** 하나뿐이다: `docker/server.Dockerfile` 이 공식 이미지에 `.so` 와 초기화 SQL 을 얹어 Docker Hub 로 나간다 (`release.yml` 의 `image`·`manifest` 잡, 태그 `v*` 에서만). 테스트 경로는 이 이미지에 의존하지 않는다. 자격증명은 `DOCKERHUB_USERNAME`·`DOCKERHUB_TOKEN` 시크릿.
- 비밀은 GitHub Secrets 만. 워크플로 파일에 토큰·키 금지. keyring 파일은 잡 안에서 생성하고 잡 종료 시 사라진다.
- 릴리스 아티팩트: `component_gcm-<ver>-mysql<major>-<arch>.tar.gz` + `SHA256SUMS` + SBOM(`syft`). 태그는 SemVer, 서버 major 별 호환표를 README 에.
- 셸 스크립트: `#!/usr/bin/env bash`, `set -euo pipefail`, `shellcheck` 통과. 인자 없이 실행 시 usage 출력.
- Dockerfile: 베이스 이미지 digest 핀, 단일 책임, `HEALTHCHECK` 로 mysqld 준비 대기 (sleep 금지).
- 부하 테스트 결과는 아티팩트로 업로드하고 `baseline.json` 과 비교해 회귀면 실패.
