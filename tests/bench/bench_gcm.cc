/* SPDX-License-Identifier: GPL-2.0-only */
/* Sealing and opening, against the bare-OpenSSL reference in bench_support.h.
 *
 * Every case checks that the operation succeeded. Without that a benchmark is free to measure
 * an error path: `bad_key_len` returns before touching a cipher, and the result would be a
 * beautiful number for code that does nothing. The check is one comparison per iteration,
 * accumulated so the failure is reported once after the loop instead of branching inside it.
 *
 * Every case is run once per suite. The key length is the only thing that differs between
 * the three (design A10): the same code path, the same envelope layout, a different cipher
 * fetched by name. Each suite is gated against a reference running that same cipher, so the
 * gated ratio is still "this project's structure over the algorithm" and says nothing about
 * what AES-128 costs relative to AES-256. That number is reported separately by gate.py and
 * depends on the hardware, provider and workload. */

#include <memory>
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

void seal_random(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const gcm::Bytes plaintext{b.plaintext.data(), size};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err =
        gcm::encrypt_random(fixture_key(key_len), plaintext, kNoAad, b.envelope.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(written);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void seal_det(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const gcm::Bytes plaintext{b.plaintext.data(), size};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err =
        gcm::encrypt_det(fixture_key(key_len), plaintext, kNoAad, b.envelope.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(written);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

/* seal_det through one DetSession across iterations with the same key (design A11): the
 * nonce_key HMAC runs once and every later iteration is a cache hit, which is the shape of
 * a statement sealing a column. Gated against `ref/seal_det_session`, which has the nonce_key
 * in hand too; `gcm/seal_det_session` against `gcm/seal_det` is reported as what the cache
 * saves. */
void seal_det_session(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const gcm::Bytes plaintext{b.plaintext.data(), size};
  gcm::DetSession session{};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err = gcm::encrypt_det_with_session(&session, fixture_key(key_len), plaintext,
                                                         kNoAad, b.envelope.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(written);
  }
  gcm::det_session_clear(&session);
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void open_envelope(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  size_t envelope_len = 0;
  const gcm::Error sealed =
      gcm::encrypt_det(fixture_key(key_len), gcm::Bytes{b.plaintext.data(), size}, kNoAad,
                       b.envelope.data(), &envelope_len);
  if (sealed != gcm::Error::ok) {
    state.SkipWithError(gcm::error_name(sealed));
    return;
  }
  const gcm::Bytes envelope{b.envelope.data(), envelope_len};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err =
        gcm::decrypt(fixture_key(key_len), envelope, kNoAad, b.out.data(), &written);
    last = err != gcm::Error::ok ? err : last;
    benchmark::DoNotOptimize(b.out.data());
    benchmark::DoNotOptimize(written);
  }
  if (last != gcm::Error::ok) state.SkipWithError(gcm::error_name(last));
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

/* The same open through one DecryptSession reused across iterations with one key (design A11)
 * — the shape of a statement scanning a column. Gated against `ref/open_session`, a context
 * scheduled once and re-initialised with the nonce only; `gcm/open_session` against `gcm/open`
 * is reported as what the reuse saves. */
void open_envelope_session(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  size_t envelope_len = 0;
  const gcm::Error sealed =
      gcm::encrypt_det(fixture_key(key_len), gcm::Bytes{b.plaintext.data(), size}, kNoAad,
                       b.envelope.data(), &envelope_len);
  if (sealed != gcm::Error::ok) {
    state.SkipWithError(gcm::error_name(sealed));
    return;
  }
  std::unique_ptr<gcm::DecryptSession, decltype(&gcm::decrypt_session_free)> session(
      gcm::decrypt_session_new(), gcm::decrypt_session_free);
  if (!session) {
    state.SkipWithError("decrypt_session_new failed");
    return;
  }
  const gcm::Bytes envelope{b.envelope.data(), envelope_len};
  gcm::Error last = gcm::Error::ok;

  for ([[maybe_unused]] auto iteration : state) {
    size_t written = 0;
    const gcm::Error err = gcm::decrypt_with_session(session.get(), fixture_key(key_len), envelope,
                                                     kNoAad, b.out.data(), &written);
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

void reference_seal(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const std::vector<unsigned char> nonce = filler(gcm::kNonceLen, 0x1234567890ABCDEFULL);
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal(fixture_key(key_len), nonce.data(), b.plaintext.data(), size,
                                   b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_open(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const std::vector<unsigned char> nonce = filler(gcm::kNonceLen, 0x1234567890ABCDEFULL);
  unsigned char tag[gcm::kTagLen] = {};
  if (!gcm_bench::reference_seal(fixture_key(key_len), nonce.data(), b.plaintext.data(), size,
                                 b.envelope.data(), tag)) {
    state.SkipWithError("reference seal failed while preparing the open case");
    return;
  }
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_open(fixture_key(key_len), nonce.data(), b.envelope.data(), size, tag,
                                   b.out.data()) &&
         ok;
    benchmark::DoNotOptimize(b.out.data());
  }
  if (!ok) state.SkipWithError("reference open failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_open_session(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  const std::vector<unsigned char> nonce = filler(gcm::kNonceLen, 0x1234567890ABCDEFULL);
  unsigned char tag[gcm::kTagLen] = {};
  if (!gcm_bench::reference_seal(fixture_key(key_len), nonce.data(), b.plaintext.data(), size,
                                 b.envelope.data(), tag)) {
    state.SkipWithError("reference seal failed while preparing the open case");
    return;
  }
  std::unique_ptr<gcm_bench::ReferenceOpenCtx, decltype(&gcm_bench::reference_open_ctx_free)> ctx(
      gcm_bench::reference_open_ctx_new(fixture_key(key_len)), gcm_bench::reference_open_ctx_free);
  if (!ctx) {
    state.SkipWithError("reference context setup failed");
    return;
  }
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_open_reuse(ctx.get(), nonce.data(), b.envelope.data(), size, tag,
                                         b.out.data()) &&
         ok;
    benchmark::DoNotOptimize(b.out.data());
  }
  if (!ok) state.SkipWithError("reference reused open failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_seal_det_session(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  unsigned char nonce_key[gcm::kHmacLen] = {};
  if (!gcm_bench::reference_nonce_key(fixture_key(key_len), nonce_key)) {
    state.SkipWithError("reference nonce_key derivation failed");
    return;
  }
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal_det_cached(fixture_key(key_len), nonce_key, b.plaintext.data(),
                                              size, b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference cached deterministic seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_seal_random(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal_random(fixture_key(key_len), b.plaintext.data(), size,
                                          b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference random seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

void reference_seal_det(benchmark::State &state, size_t key_len) {
  const size_t size = static_cast<size_t>(state.range(0));
  Buffers b = buffers_for(size);
  unsigned char tag[gcm::kTagLen] = {};
  bool ok = true;

  for ([[maybe_unused]] auto iteration : state) {
    ok = gcm_bench::reference_seal_det(fixture_key(key_len), b.plaintext.data(), size,
                                       b.envelope.data(), tag) &&
         ok;
    benchmark::DoNotOptimize(b.envelope.data());
    benchmark::DoNotOptimize(tag);
  }
  if (!ok) state.SkipWithError("reference deterministic seal failed");
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(size));
}

}  // namespace

/* The names are the contract with tests/bench/gate.py, which pairs `gcm/<case>/<suite>/<size>`
 * against `ref/<case>/<suite>/<size>`. Renaming a case or a suite here means renaming it in
 * tests/bench/baseline.json.
 *
 * RangeMultiplier(16) from 16 to 65536 is exactly 16, 256, 4096, 65536 — the sizes and the
 * reason for them are in bench_support.h. */
#define GCM_BENCH_SUITE(fn, prefix, suite, key_len) \
  BENCHMARK_CAPTURE(fn, suite, key_len)             \
      ->Name(prefix "/" #suite)                     \
      ->RangeMultiplier(gcm_bench::kSizeMultiplier) \
      ->Range(gcm_bench::kMinSize, gcm_bench::kMaxSize)

#define GCM_BENCH_ALL_SUITES(fn, prefix)                \
  GCM_BENCH_SUITE(fn, prefix, aes256, gcm::kKeyLen256); \
  GCM_BENCH_SUITE(fn, prefix, aes192, gcm::kKeyLen192); \
  GCM_BENCH_SUITE(fn, prefix, aes128, gcm::kKeyLen128)

GCM_BENCH_ALL_SUITES(seal_random, "gcm/seal_random");
GCM_BENCH_ALL_SUITES(seal_det, "gcm/seal_det");
GCM_BENCH_ALL_SUITES(seal_det_session, "gcm/seal_det_session");
GCM_BENCH_ALL_SUITES(open_envelope, "gcm/open");
GCM_BENCH_ALL_SUITES(open_envelope_session, "gcm/open_session");
GCM_BENCH_ALL_SUITES(reference_seal, "ref/seal");
GCM_BENCH_ALL_SUITES(reference_seal_random, "ref/seal_random");
GCM_BENCH_ALL_SUITES(reference_seal_det, "ref/seal_det");
GCM_BENCH_ALL_SUITES(reference_seal_det_session, "ref/seal_det_session");
GCM_BENCH_ALL_SUITES(reference_open, "ref/open");
GCM_BENCH_ALL_SUITES(reference_open_session, "ref/open_session");
