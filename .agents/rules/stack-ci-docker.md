---
paths:
  - ".github/**"
  - "docker/**"
  - "scripts/**"
  - "tests/e2e/compose*.yml"
---
# CI · Docker · script conventions

- GitHub Actions, split by concern: `lint.yml`, `unit.yml`, `build.yml` (matrix), `integration.yml`
  (smoke — the required checks), `mtr.yml` (path-filtered), `adapter.yml` (path-filtered, three
  majors), `e2e.yml`, `load.yml` (nightly/dispatch), `bench.yml` (merges to develop and main, plus
  nightly), `release.yml` (tags). Never one giant file.
- Pin actions by SHA (`actions/checkout@<sha> # v4`). Never reference a tag — that is the supply-chain
  risk. `scripts/check-action-pins.py` enforces it from the `workflows` job in `lint.yml`. To refresh a
  pin: `gh api repos/<owner>/<action>/commits/<tag> -q .sha`. The workflows themselves are linted by
  the same job, using an actionlint image pinned by digest.
- Build matrix axes: MySQL `8.0.x / 8.4.x / 9.x` (the exact patch versions live in one place,
  `docker/versions.json`) × `amd64 / arm64`. OpenSSL is whatever each server image ships.
- Configuring and building a MySQL source tree is expensive. Push the build image
  (`docker/build.Dockerfile`) to GHCR and cache it by the `versions.json` hash. Do not rebuild it when
  nothing in the source changed.
- Integration and E2E `docker cp` the `.so` into the official `mysql:<ver>` image. **Tests do not use a
  custom server image** — that way a component bug cannot be mistaken for an image build problem.
- There is exactly one exception, the **release server image**: `docker/server.Dockerfile` layers the
  `.so` and the initialisation SQL onto the official image and ships to Docker Hub (the `image` and
  `manifest` jobs in `release.yml`, on `v*` tags only). No test path depends on that image. Credentials
  come from the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets.
- **Never put `paths` on a workflow that holds a required check.** A required check that does not
  report blocks merges forever. To filter an expensive job, split it into its own workflow — that is
  why `mtr.yml` was split out of `integration.yml` (it measured 49–63 minutes and was running on
  documentation-only PRs).
- Give the PR gate workflows (`lint`, `unit`, `build`, `integration`, `e2e`, `mtr`) a `concurrency`
  group: `group: ${{ github.workflow }}-${{ github.ref }}`, with `cancel-in-progress` only on
  `pull_request`. `mtr` builds a server from source, so without cancellation every push piles up
  another hour-long build. Pushes to main and develop, and tag runs, are the gate on the branch and are
  never cancelled. `load` has no group because it dispatches baseline measurements in parallel, and
  neither does `release`, so publication is never interrupted.
- Secrets come from GitHub Secrets only. No token or key in a workflow file. A keyring file is created
  inside the job and disappears when it ends.
- Release artifacts: `component_gcm-<ver>-mysql<major>-<arch>.tar.gz` plus `SHA256SUMS` and an SBOM
  (`syft`). Tags are SemVer, and the README carries the compatibility table per server major.
- Shell scripts: `#!/usr/bin/env bash`, `set -euo pipefail`, clean under `shellcheck`. Print usage when
  run with no arguments.
- Dockerfiles: base image pinned by digest, one responsibility each, and a `HEALTHCHECK` to wait for
  mysqld rather than a sleep.
- Upload load and bench results as artifacts and compare them against their own `baseline.json`,
  failing on a regression. Use `if: always()`, because the artifact from a failed run is precisely the
  one you need.
- Benchmarks build directly on the runner (`GCM_BENCH_LOCAL=1`). The runner is the reference
  environment, so wrapping it in another container only adds apt time. The container path in
  `scripts/bench.sh` is for a development machine, not for ubuntu-24.04.
