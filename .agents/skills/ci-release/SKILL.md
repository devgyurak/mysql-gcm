---
name: ci-release
description: Composing the GitHub Actions workflows (lint, unit, the build matrix, integration, mtr, adapter, e2e, bench, nightly load, release), the docker build image, and the release artifacts (checksums, SBOM). Use it when working in .github/ or docker/.
---

# ci-release

The rule is `.agents/rules/stack-ci-docker.md`. The skeletons already exist in
`.github/workflows/*.yml` — follow the same pattern when adding a job.

## What each workflow is for
| File | Trigger | Jobs | Gate |
|---|---|---|---|
| `lint.yml` | PR, push to main/develop | clang-format/clang-tidy, ruff+mypy, the architecture boundary check, agents-sync, shellcheck, gitleaks, actionlint + action pins | required |
| `unit.yml` | PR, push, nightly | gtest (ASan) over every vector, the internal generator's `--check`. The nightly run is the 1M collision case | required |
| `build.yml` | PR, push, tag `v*` | the matrix from `versions.json` × `amd64/arm64`, the build image cached in GHCR, the `.so` artifact | required |
| `integration.yml` | PR, push | the official image plus the `.so` → `scripts/verify.sh` on three majors | **required (`smoke`)** |
| `mtr.yml` | PR, push — **path-filtered** | the MTR suite in a server tree build | not required |
| `adapter.yml` | PR, push — **path-filtered** | `tests/adapter` across three majors | not required |
| `e2e.yml` | push to main/develop, PR label, dispatch | the compose scenarios | required on main |
| `bench.yml` | push to main/develop (path-filtered), nightly, dispatch | the core micro-benchmarks and the ratio gate | not required |
| `load.yml` | nightly cron, dispatch | `tests/load/run.py --gate`, with the results as an artifact | nightly |
| `release.yml` | tag `v*`, dispatch (dry run) | `guard` → `build` → `image` → `manifest` → `package` → `publish` | — |
| `site.yml` | PR and push to main touching `site/`, README, `docs/`, `spec/`, CHANGELOG; dispatch | builds the Starlight site from the repository's Markdown with `SITE_BASE=/`, audits npm, checks internal links. Deployment is Cloudflare Pages' Git integration (`site/README.md`) | — |
| `images.yml` | push to main/develop (`docker/**`, `image-ref.sh`), weekly, dispatch | `mysql-gcm-build` per major and `mysql-gcm-mtr` for 8.4 to GHCR; skips a tag that exists | — |

**`mtr`, `adapter` and `bench` are path-filtered and therefore must never be made required.** A
filtered workflow does not report on a PR that misses the filter, and a required check that does not
report blocks merges forever. That is also why `integration.yml` holds the required `smoke` checks and
carries no path filter — the reason `mtr.yml` was split out of it.

`release.yml` runs `guard` first (the SemVer shape of the tag, that the tag is contained in `main`, and
that `CHANGELOG.md` has an entry), builds and smoke-tests the server image before pushing it, and
publishes the GitHub Release from a separate `publish` job that needs `guard`, `manifest` and
`package`. Publishing from `package` directly would let a Release appear after `manifest` had failed,
and adding `manifest` to `package`'s `needs` would instead skip packaging on a dry run, since a skipped
dependency skips the dependent.

## The build image — `docker/build.Dockerfile`
```
ARG MYSQL_VERSION
FROM oraclelinux:9 AS base        # the same family as the official mysql image → the same OpenSSL
RUN dnf -y install gcc-toolset-13 cmake ninja-build openssl-devel ncurses-devel libtirpc-devel rpcgen bison wget
RUN wget https://dev.mysql.com/get/Downloads/MySQL-${MAJOR}/mysql-${MYSQL_VERSION}.tar.gz && tar xf ...
RUN cmake -S mysql-${MYSQL_VERSION} -B /build -G Ninja -DWITH_SSL=system -DWITH_UNIT_TESTS=OFF
# configure only. The component is built with --target component_gcm, so only what is needed
```
The toolset and the boost flags differ per server version — see the table in the `mysql-component`
skill, which has the measured values. `docker/versions.json` holds
`{"8.0": "8.0.43", "8.4": "8.4.11", "9": "9.4.0"}`; bumping a version happens there and in the README
compatibility table.

`scripts/build-in-docker.sh <ver>`: builds the image if it is missing, copies `src/` into the server
tree's `components/gcm` and re-runs configure (the glob happens at configure time, so a symlink into a
read-only mount does not work), runs `cmake --build /build --target component_gcm`, and copies the
output to `build/<ver>/component_gcm.so`.

## Cache keys
Build image: `sha256(docker/build.Dockerfile + versions.json[ver])`. For the MTR server tree build, the
same key plus the `mysqld` target, held as GHCR image layers rather than `actions/cache`, to stay under
the 10 GB cache limit.

## Release checklist
- [ ] A `CHANGELOG.md` entry; for an envelope or spec change, a `spec/` version bump and a
      compatibility note
- [ ] Artifacts for three server majors × two architectures, named
      `component_gcm-<ver>-mysql<major>-<arch>.tar.gz`
- [ ] `SHA256SUMS` signed (cosign, keyless, with the identity pinned to `release.yml@refs/tags/v`) and
      the SBOM attached
- [ ] The README support matrix and operational constraints (§6) current
- [ ] The load baseline refreshed from this release build
- [ ] `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` present — without them the release fails as a whole,
      which is deliberate: it prevents a partial publication
