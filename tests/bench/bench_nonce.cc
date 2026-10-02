/* SPDX-License-Identifier: GPL-2.0-only */
/* Deterministic nonce derivation.
 *
 * This is the one part of the design that costs something the random variant does not: two
 * HMAC-SHA256 passes per call, one for the nonce key and one over the plaintext
 * (spec/envelope.md §3). At 16 bytes that is most of `seal_det`, which is why the ratio
 * `gcm/seal_det` against `ref/seal` is several times one at the small end and close to one at
 * 64 KiB. Measuring the derivation on its own is what tells the two apart when a regression
 * appears in `seal_det` alone: either the HMAC path changed, or the sealing around it did.
 *
 * `derive_nonce_key` is included because it is invariant in the plaintext. Anything that
 * makes it scale with input size is a bug, and a benchmark that flat-lines across four sizes
 * is the cheapest way to see that it still does not. */

#include <vector>

#include <benchmark/benchmark.h>

#include "bench_support.h"
#include "envelope.h"
#include "nonce.h"

namespace {

using gcm_bench::filler;
using gcm_bench::fixture_key;

void derive_det_nonce(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  const std::vector<unsigned char> plaintext = filler(size, 0xDEADBEEFCAFEBABEULL);
  unsigned char nonce[gcm::kNonceLen] = {};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    const gcm::Error err =
        gcm::derive_det_nonce(fixture_key(), gcm::Bytes{plaintext.data(), size}, nonce);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(nonce);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void derive_nonce_key(benchmark::State &state) {
  unsigned char nonce_key[gcm::kHmacLen] = {};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    const gcm::Error err = gcm::derive_nonce_key(fixture_key(), nonce_key);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(nonce_key);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
}

void hmac_sha256(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  const std::vector<unsigned char> msg = filler(size, 0x0123456789ABCDEFULL);
  unsigned char mac[gcm::kHmacLen] = {};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    const gcm::Error err = gcm::hmac_sha256(fixture_key(), gcm::Bytes{msg.data(), size}, mac);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(mac);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

}  // namespace

/* No `ref/` counterpart: there is no bare-OpenSSL baseline worth dividing by here, because
 * `hmac_sha256` *is* the thin wrapper. These are recorded rather than gated by ratio — see
 * the `absolute` section of tests/bench/baseline.json. */
BENCHMARK(derive_det_nonce)
    ->Name("nonce/derive_det_nonce")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(derive_nonce_key)->Name("nonce/derive_nonce_key");
BENCHMARK(hmac_sha256)
    ->Name("nonce/hmac_sha256")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
