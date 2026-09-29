#!/usr/bin/env bash
# Builds and runs the unit suite the way CI does: Linux, GCC, -Werror.
#
# The host toolchain is usually clang on macOS, and GCC rejects things clang accepts
# (-Wdangling-reference is the one that has bitten this repository). Running this before
# pushing turns a red CI run into a local one.
#
#   scripts/unit-in-docker.sh                  # 100k nonce-collision samples, as PR CI does
#   GCM_COLLISION_N=1000000 scripts/unit-in-docker.sh   # the nightly sample count
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="mysql-gcm-unit:ubuntu-24.04"

if ! docker image inspect "${image}" >/dev/null 2>&1; then
  echo "building ${image} (once)" >&2
  docker build -t "${image}" - <<'DOCKERFILE'
# Matches the ubuntu-24.04 GitHub runner: same compiler generation, same OpenSSL.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      cmake ninja-build g++ libssl-dev libgtest-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

# The source is mounted read-only and the build tree lives in the container, so a host
# build directory from a different compiler cannot leak in.
docker run --rm \
  -v "${root}:/repo:ro" \
  -e "GCM_COLLISION_N=${GCM_COLLISION_N:-100000}" \
  "${image}" bash -euo pipefail -c '
    cmake -S /repo/tests/unit -B /build -G Ninja -DGCM_SANITIZE=ON >/dev/null
    cmake --build /build
    ctest --test-dir /build --output-on-failure --parallel "$(nproc)"
  '
