#!/usr/bin/env bash
# Builds and runs the core micro-benchmarks, then turns the results into ratios.
#
# The reference environment is ubuntu-24.04 with GCC and the distribution's OpenSSL 3, which is
# what .github/workflows/bench.yml runs on. On any other host the container reproduces it, because
# a ratio compared against a baseline recorded elsewhere is only meaningful if the toolchain and
# libcrypto match. GCM_BENCH_LOCAL=1 builds on the host instead — right on a CI runner, which
# already *is* the reference, and a quick look anywhere else.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/bench.sh [--gate]

  --gate   check the ratios against tests/bench/baseline.json and fail on a violation.
           Without it the run only records.

environment:
  GCM_BENCH_LOCAL=1       build and run on the host instead of in a container
  GCM_BENCH_MIN_TIME=0.5s per-case measurement budget (default 0.5s)
  GCM_BENCH_REPS=1        --benchmark_repetitions

Writes build/bench/results.json (raw Google Benchmark) and build/bench/ratios.json.
USAGE
  exit 2
}

gate_arg=""
case "${1-}" in
  --gate) gate_arg="--gate tests/bench/baseline.json" ;;
  "") ;;
  *) usage ;;
esac
[ $# -le 1 ] || usage

cd "$(dirname "$0")/.."

min_time=${GCM_BENCH_MIN_TIME:-0.5s}
reps=${GCM_BENCH_REPS:-1}

build_and_run() {
  cmake -S tests/bench -B build/bench -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
  cmake --build build/bench -j"$(getconf _NPROCESSORS_ONLN)" >/dev/null
  ./build/bench/gcm_bench \
    --benchmark_min_time="${min_time}" \
    --benchmark_repetitions="${reps}" \
    --benchmark_out=build/bench/results.json \
    --benchmark_out_format=json
}

if [ "${GCM_BENCH_LOCAL:-0}" = "1" ]; then
  echo "building on the host; comparable with the baseline only if this is ubuntu-24.04" >&2
  echo "with GCC and the distribution's OpenSSL 3 — otherwise drop GCM_BENCH_LOCAL." >&2
  build_and_run
else
  # Ubuntu 24.04 with GCC and the distribution's OpenSSL 3, matching the bench workflow.
  # --cpuset-cpus is not set: pinning inside Docker on a CI runner does not reduce the noise
  # that matters here, and the ratio divides the machine out anyway.
  docker run --rm -v "$PWD:/repo" -w /repo ubuntu:24.04 bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      build-essential cmake libssl-dev ca-certificates curl python3 >/dev/null
    cmake -S tests/bench -B build/bench -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
    cmake --build build/bench -j"$(nproc)" >/dev/null
    ./build/bench/gcm_bench \
      --benchmark_min_time='"${min_time}"' \
      --benchmark_repetitions='"${reps}"' \
      --benchmark_out=build/bench/results.json \
      --benchmark_out_format=json
  '
fi

echo >&2
echo "ratios against the bare-OpenSSL reference:" >&2
# shellcheck disable=SC2086  # gate_arg is a deliberate two-word option or empty
python3 tests/bench/gate.py build/bench/results.json --out build/bench/ratios.json ${gate_arg} \
  >/dev/null
echo >&2
echo "wrote build/bench/results.json and build/bench/ratios.json" >&2
