/* SPDX-License-Identifier: GPL-2.0-only */
/* Envelope parsing.
 *
 * `parse` touches no cipher and allocates nothing — it reads a version byte and computes
 * offsets (spec/envelope.md §2). It is here because it runs once per row on the decrypt path,
 * so the thing to watch is that it stays independent of the envelope's size. All three
 * versions are measured at one size: if a later change made parsing scan the body, the v2 and
 * v3 numbers would move away from v1 and away from each other, and nothing else in the
 * project would notice.
 *
 * No `ref/` counterpart: there is no OpenSSL operation to divide by. Recorded, not ratio-gated. */

#include <vector>

#include <benchmark/benchmark.h>

#include "bench_support.h"
#include "envelope.h"

namespace {

using gcm_bench::filler;

/* One body size for all three: parsing cost must not depend on it, and holding it constant is
 * what makes the three numbers comparable with each other. */
constexpr size_t kBodyLen = 256;

std::vector<unsigned char> envelope_with_version(unsigned char version, size_t body_len) {
  /* v1 carries a 16-byte IV and a block-aligned body; v2 and v3 carry a 12-byte nonce and a
     16-byte tag. Sized from the constants rather than from literals so a spec change breaks
     the build here rather than producing a benchmark of a malformed envelope. */
  const size_t prefix =
      gcm::kVersionLen + (version == gcm::kVersionLegacyCbc ? gcm::kIvLen : gcm::kNonceLen);
  const size_t suffix = version == gcm::kVersionLegacyCbc ? 0 : gcm::kTagLen;
  std::vector<unsigned char> envelope = filler(prefix + body_len + suffix, 0xA5A5A5A5A5A5A5A5ULL);
  envelope[0] = version;
  return envelope;
}

void parse_envelope(benchmark::State &state, unsigned char version) {
  const std::vector<unsigned char> envelope = envelope_with_version(version, kBodyLen);
  const gcm::Bytes bytes{envelope.data(), envelope.size()};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    gcm::ParsedEnvelope parsed{};
    const gcm::Error err = gcm::parse(bytes, &parsed);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(parsed);
  }
  /* A parse that started rejecting these inputs would otherwise be benchmarked as very fast
     code that returns an error, which is the failure mode this guard exists for. */
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
}

}  // namespace

BENCHMARK_CAPTURE(parse_envelope, v1_legacy_cbc, gcm::kVersionLegacyCbc)->Name("envelope/parse/v1");
BENCHMARK_CAPTURE(parse_envelope, v2_random, gcm::kVersionRandom)->Name("envelope/parse/v2");
BENCHMARK_CAPTURE(parse_envelope, v3_det, gcm::kVersionDet)->Name("envelope/parse/v3");
