/* SPDX-License-Identifier: GPL-2.0-only */
/* Sealing and opening, against the bare-OpenSSL reference in bench_support.h.
 *
 * Every case checks that the operation succeeded. Without that a benchmark is free to measure
 * an error path: `bad_key_len` returns before touching a cipher, and the result would be a
 * beautiful number for code that does nothing. The check is one comparison per iteration,
 * accumulated so the failure is reported once after the loop instead of branching inside it. */

#include <vector>

#include <benchmark/benchmark.h>

#include "bench_support.h"
#include "gcm.h"

namespace {

using gcm_bench::filler;
using gcm_bench::fixture_key;

/* Sized once per case, outside the timed loop. Allocation is not what is being measured: the
 * component allocates its result buffer once per UDF instance, not once per row. */
struct Buffers {
  std::vector<unsigned char> plaintext;
  std::vector<unsigned char> envelope;
  std::vector<unsigned char> out;
};

Buffers buffers_for(size_t size) {
  Buffers b;
  b.plaintext = filler(size, 0x9E3779B97F4A7C15ULL);
  b.envelope.resize(gcm::encrypt_out_len(size));
  b.out.resize(gcm::decrypt_out_len(b.envelope.size()));
  return b;
}

const gcm::Bytes kNoAad{nullptr, 0};

void seal_random(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const gcm::Bytes plaintext{b.plaintext.data(), size};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err =
        gcm::encrypt_random(fixture_key(), plaintext, kNoAad, b.envelope.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(written);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void seal_det(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const gcm::Bytes plaintext{b.plaintext.data(), size};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err =
        gcm::encrypt_det(fixture_key(), plaintext, kNoAad, b.envelope.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(written);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void open_envelope(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  size_t envelope_len = 0;
  const gcm::Error sealed = gcm::encrypt_det(fixture_key(), gcm::Bytes{b.plaintext.data(), size},
                                             kNoAad, b.envelope.data(), &envelope_len);
  if (sealed != gcm::Error::ok) {
    state.SkipWithError(gcm::error_name(sealed));
    return;
  }
  const gcm::Bytes envelope{b.envelope.data(), envelope_len};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err = gcm::decrypt(fixture_key(), envelope, kNoAad, b.out.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.out.data());
    benchmark::DoNotOptimize(written);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

/* References. `ref/seal` is a bare seal and is *not* what the gate divides by — it exists so the
 * cost of determinism itself stays visible in the recorded output. The gated references below it
 * perform the same work mix as the case they pair with, which is what makes the ratio a property
 * of this code rather than of the runner's SHA-to-AES throughput ratio (bench_support.h). */

void reference_seal(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const std::vector<unsigned char> nonce = filler(gcm::kNonceLen, 0x1234567890ABCDEFULL);
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal(fixture_key().data, nonce.data(), b.plaintext.data(), size,
                                   b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_open(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const std::vector<unsigned char> nonce = filler(gcm::kNonceLen, 0x1234567890ABCDEFULL);
  unsigned char tag[gcm::kTagLen] = {};
  if (!gcm_bench::reference_seal(fixture_key().data, nonce.data(), b.plaintext.data(), size,
                                 b.envelope.data(), tag)) {
    state.SkipWithError("reference seal failed while preparing the open case");
    return;
  }
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_open(fixture_key().data, nonce.data(), b.envelope.data(), size, tag,
                                   b.out.data()) &&
         ok;
    benchmark::DoNotOptimize(b.out.data());
  }
  if (!ok) state.SkipWithError("reference open failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_seal_random(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal_random(fixture_key().data, b.plaintext.data(), size,
                                          b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference random seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_seal_det(benchmark::State &state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal_det(fixture_key().data, b.plaintext.data(), size,
                                       b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference deterministic seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

}  // namespace

/* The names are the contract with tests/bench/gate.py, which pairs `gcm/<case>/<size>` against
 * `ref/<case>/<size>`. Renaming a case here means renaming it in tests/bench/baseline.json.
 *
 * RangeMultiplier(16) from 16 to 65536 is exactly 16, 256, 4096, 65536 — the sizes and the
 * reason for them are in bench_support.h. */
BENCHMARK(seal_random)
    ->Name("gcm/seal_random")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(seal_det)
    ->Name("gcm/seal_det")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(open_envelope)
    ->Name("gcm/open")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(reference_seal)
    ->Name("ref/seal")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(reference_seal_random)
    ->Name("ref/seal_random")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(reference_seal_det)
    ->Name("ref/seal_det")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
BENCHMARK(reference_open)
    ->Name("ref/open")
    ->RangeMultiplier(gcm_bench::kSizeMultiplier)
    ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize);
