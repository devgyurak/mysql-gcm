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
  majors), `e2e.yml`, `load.yml` (nightly/dispatch), `site.yml` (builds and link-checks the docs site when its sources change; Cloudflare Pages deploys it
  from its own Git integration, so no Cloudflare credential lives here),
  `bench.yml` (merges to develop and main, plus
  nightly), `release.yml` (tags). Never one giant file.
- Pin actions by SHA (`actions/checkout@<sha> # v4`). Never reference a tag — that is the supply-chain
  risk. `scripts/check-action-pins.py` enforces it from the `workflows` job in `lint.yml`. To refresh a
  pin: `gh api repos/<owner>/<action>/commits/<tag> -q .sha`. The workflows themselves are linted by
  the same job, using an actionlint image pinned by digest.
- Build matrix axes: MySQL `8.0.x / 8.4.x / 9.x` (the exact patch versions live in one place,
  `docker/versions.json`) × `amd64 / arm64`. OpenSSL is whatever each server image ships.
- Configuring and building a MySQL source tree is expensive, and `images.yml` is what stops CI paying
  for it per run. It publishes two images per major to GHCR: `mysql-gcm-build` (a configured tree) and
  `mysql-gcm-mtr` (that plus a compiled server, 8.4 only, since the `.result` files are recorded
  there). `mtr` spent 49–63 minutes compiling a server whose test suite takes 16 seconds.
- **The tag carries a hash of the inputs, not just the MySQL version**: `build.Dockerfile`,
  `build-component.sh` and that major's `versions.json` entry (`scripts/image-ref.sh`). Change any of
  them and the tag does not exist yet, so every consumer falls back to building locally. A stale image
  can never be served for changed inputs, and the cost of a miss is paid once, by the PR that changed
  the input.
- **A published image is a cache, never a dependency.** `image-ref.sh` resolves local → registry →
  build, so the scripts work with no network and no registry. Set `GCM_REGISTRY` to opt a job in;
  leave it unset locally, where building once and keeping the image beats a 2 GB pull.
- Only amd64 jobs may pull. `images.yml` runs on `ubuntu-24.04`, so the images are amd64, and
  `build.yml`'s arm64 half deliberately does not set `GCM_REGISTRY` — an emulated pull would be slower
  than the build it replaced.
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
