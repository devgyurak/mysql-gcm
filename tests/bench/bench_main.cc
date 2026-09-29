/* SPDX-License-Identifier: GPL-2.0-only */
/* Entry point: brings the core and the reference up once, then hands over to Google
 * Benchmark. Both initialisations are the real ones — `gcm::crypto_init()` is what the
 * component calls from its init, and fetching the algorithms is exactly the cost that must
 * not appear per call. If it were done inside a benchmark loop instead, the numbers would
 * hide the thing the crypto-safety rule most wants measured. */

#include <cstdio>

#include <benchmark/benchmark.h>

#include "bench_support.h"
#include "gcm.h"

int main(int argc, char **argv) {
  if (gcm::crypto_init() != 0) {
    std::fprintf(stderr, "gcm::crypto_init failed; is this linked against OpenSSL 3?\n");
    return 1;
  }
  if (!gcm_bench::reference_init()) {
    std::fprintf(stderr, "the bare-OpenSSL reference failed to initialise\n");
    gcm::crypto_deinit();
    return 1;
  }

  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    gcm_bench::reference_deinit();
    gcm::crypto_deinit();
    return 1;
  }
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();

  gcm_bench::reference_deinit();
  gcm::crypto_deinit();
  return 0;
}
