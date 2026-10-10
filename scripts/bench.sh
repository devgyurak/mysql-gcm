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
  GCM_BENCH_MIN_TIME=0.5s per-case measurement budget (default 0.5s). Lowering it to run
                          quickly makes the ratios noisy enough to breach the gate on their
                          own — measured: 0.05s produced ratios up to 1.11 where 0.5s on the
                          same machine produced 1.02. Do not use --gate with a shorter budget.
  GCM_BENCH_REPS          --benchmark_repetitions; default 5 with --gate, 1 without. Above 1, repetitions are also randomly
                          interleaved across all cases (--benchmark_enable_random_interleaving),
                          so a case and its reference are sampled over the same stretch of time
                          rather than minutes apart (#24), and gate.py judges their medians.

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
# Gating judges the median of five interleaved repetitions (#24): a single repetition, or
# repetitions run back to back, let one slow stretch on a shared runner decide a ratio. A
# recording run without --gate stays at one, which is quick.
default_reps=1
[ -n "${gate_arg}" ] && default_reps=5
reps=${GCM_BENCH_REPS:-${default_reps}}
# Registration order runs every gcm/* case before every ref/* reference, and a case's
# repetitions back to back, so a slow stretch on a shared runner lands on one side of a ratio.
# Interleaving spreads each case's repetitions, and its reference's, across the whole run.
interleave=false
[ "${reps}" -gt 1 ] && interleave=true

build_and_run() {
  cmake -S tests/bench -B build/bench -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
  cmake --build build/bench -j"$(getconf _NPROCESSORS_ONLN)" >/dev/null
  ./build/bench/gcm_bench \
    --benchmark_min_time="${min_time}" \
    --benchmark_repetitions="${reps}" \
    --benchmark_enable_random_interleaving="${interleave}" \
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
      --benchmark_enable_random_interleaving='"${interleave}"' \
      --benchmark_out=build/bench/results.json \
      --benchmark_out_format=json
  '
fi

echo >&2
echo "benchmark ratios:" >&2
# shellcheck disable=SC2086  # gate_arg is a deliberate two-word option or empty
python3 tests/bench/gate.py build/bench/results.json --out build/bench/ratios.json ${gate_arg} \
  >/dev/null
echo >&2
echo "wrote build/bench/results.json and build/bench/ratios.json" >&2
