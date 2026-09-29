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
 * The reference is deliberately *not* a fair implementation of the feature. It does the EVP
 * work and nothing else: no nonce, no envelope bytes, no error mapping. So a ratio above one
 * is expected and is exactly the quantity of interest — everything this project adds on top
 * of the cipher. `seal_det` in particular pays two HMACs the reference does not, so its ratio
 * is several times one at small sizes. The gate watches for that number *changing*.
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

/* The public fixture key from spec/test-vectors.json. It protects nothing. */
const gcm::Bytes fixture_key();

/* Deterministic pseudo-random bytes, so two runs benchmark identical input. Not a CSPRNG
 * and not used as one: benchmark inputs only. */
std::vector<unsigned char> filler(size_t len, uint64_t seed);

/* Bare-OpenSSL equivalents of one seal and one open, fetching the cipher by name once and
 * caching it — `EVP_aes_256_gcm()` would bind the reference to the build-time OpenSSL and
 * bypass providers, which is forbidden in src/ and no more acceptable in a number that
 * src/ is judged against.
 *
 * Both return false on any OpenSSL failure so a benchmark can refuse to report. A silent
 * failure here is the worst outcome available: an error path returns fast, the reference
 * looks cheap, and every ratio above it looks like a regression. */
bool reference_init();
void reference_deinit();
bool reference_seal(const unsigned char *key, const unsigned char *nonce,
                    const unsigned char *plaintext, size_t plaintext_len, unsigned char *out,
                    unsigned char *tag);
bool reference_open(const unsigned char *key, const unsigned char *nonce,
                    const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *tag, unsigned char *out);

}  // namespace gcm_bench

#endif  // MYSQL_GCM_BENCH_SUPPORT_H
