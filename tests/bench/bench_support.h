/* SPDX-License-Identifier: GPL-2.0-only */
/* Shared fixtures and the bare-OpenSSL reference for the micro-benchmarks.
 *
 * Why a reference at all: an absolute nanosecond count from a shared CI runner is not
 * comparable with one from a different runner, or the same runner an hour later. The load
 * suite solved that at the SQL level by dividing by `AES_DECRYPT` measured in the same
 * session; this is the same trick one layer down. Every case here has a counterpart that
 * performs the equivalent OpenSSL calls directly, and what the gate compares is the ratio,
 * which divides the machine out.
 *
 * Each case's reference performs the *same work mix*, and that is not a detail. The first
 * version of this file had one reference — a bare seal — for all three encrypt cases, and
 * three runs on identical CI runners showed why that cannot work:
 *
 *     open         (reference matches the work exactly)   run-to-run spread 1.03x
 *     seal_random  (reference omits RAND_bytes)                             1.31x
 *     seal_det     (reference omits two HMACs)                              2.69x
 *
 * Dividing an HMAC-dominated measurement by an AES-only reference does not divide the machine
 * out; it measures how that CPU's SHA throughput compares to its AES throughput. Putting the
 * runner's own speed beside the ratio it produced shows it directly — a bare 64 KiB seal cost
 * 4,565 / 6,541 / 17,058 ns across those three runs, a 3.7x fleet spread, and `seal_det`'s ratio
 * tracked it inversely at 9.673 / 6.803 / 3.590 while the absolute HMAC numbers held to 1.15x.
 * So `reference_seal_det` derives the nonce
 * exactly as spec/envelope.md §3 specifies and then seals, and `reference_seal_random` draws a
 * nonce from RAND_bytes and then seals. The ratio against those measures what it was always
 * meant to: the structural overhead this project adds over a straight-line implementation of
 * the same algorithm, with the algorithm's own cost cancelled.
 *
 * `reference_seal` stays, un-gated, so the *cost of determinism itself* is still reported.
 * `seal_det` against a bare seal is a real and useful number for anyone choosing between the
 * two SQL functions; it just cannot be a gate, because it moves with the runner.
 *
 * The same reference exists per suite. The key length selects AES-256, AES-192 or AES-128 on
 * both sides (design A10), so each suite's ratio divides by a reference running the same
 * cipher, and the gated number stays a property of this code's structure rather than of how
 * many rounds the suite runs. What the suites cost relative to *each other* is reported, not
 * gated, because the effect of key size depends on the hardware, provider and workload.
 */

#ifndef MYSQL_GCM_BENCH_SUPPORT_H
#define MYSQL_GCM_BENCH_SUPPORT_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "envelope.h"

namespace gcm_bench {

/* The sizes span the two regimes this code has. Below a few hundred bytes the per-call
 * setup — EVP context, key schedule, and for the deterministic variant two HMACs — is the
 * whole cost, which is the regime every row of a name column lives in. At 64 KiB the cipher
 * throughput dominates and per-call overhead is noise. A regression usually shows in one
 * regime and not the other, and which one it is says where to look.
 *
 * The load suite only ever measures the small end: its fixture rows are Korean names. */
inline constexpr int kMinSize = 16;
inline constexpr int kMaxSize = 65536;
inline constexpr int kSizeMultiplier = 16;  // 16, 256, 4096, 65536

/* The public fixture key from spec/test-vectors.json, or its first `key_len` bytes for the
 * shorter suites. It protects nothing. The default is the AES-256 key, which is what every
 * case that does not vary the suite uses. */
const gcm::Bytes fixture_key(size_t key_len = gcm::kKeyLen256);

/* Deterministic pseudo-random bytes, so two runs benchmark identical input. Not a CSPRNG
 * and not used as one: benchmark inputs only. */
std::vector<unsigned char> filler(size_t len, uint64_t seed);

/* Bare-OpenSSL equivalents of one seal and one open, fetching the three ciphers by name once
 * and caching them — `EVP_aes_256_gcm()` would bind the reference to the build-time OpenSSL
 * and bypass providers, which is forbidden in src/ and no more acceptable in a number that
 * src/ is judged against. `key.size` selects the cipher, exactly as src/gcm.cc does.
 *
 * All return false on any OpenSSL failure, including a key length no suite has, so a
 * benchmark can refuse to report. A silent failure here is the worst outcome available: an
 * error path returns fast, the reference looks cheap, and every ratio above it looks like a
 * regression. */
bool reference_init();
void reference_deinit();
bool reference_seal(gcm::Bytes key, const unsigned char *nonce, const unsigned char *plaintext,
                    size_t plaintext_len, unsigned char *out, unsigned char *tag);

/* RAND_bytes(12) then seal: what gcm_encrypt costs a straight-line implementation. */
bool reference_seal_random(gcm::Bytes key, const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char *out, unsigned char *tag);

/* The derivation of spec/envelope.md §3 — HMAC(key, label), then HMAC(nonce_key, plaintext),
   first 12 bytes — then seal. The same two HMACs src/nonce.cc performs, so a ratio against
   this is overhead rather than algorithm. */
bool reference_seal_det(gcm::Bytes key, const unsigned char *plaintext, size_t plaintext_len,
                        unsigned char *out, unsigned char *tag);
bool reference_open(gcm::Bytes key, const unsigned char *nonce, const unsigned char *ciphertext,
                    size_t ciphertext_len, const unsigned char *tag, unsigned char *out);

}  // namespace gcm_bench

#endif  // MYSQL_GCM_BENCH_SUPPORT_H
