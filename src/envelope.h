/* SPDX-License-Identifier: GPL-2.0-only */
/* Envelope constants and parsing for mysql-gcm.

   Pure logic: this header and envelope.cc include no server and no OpenSSL
   headers, so tests/unit can link them directly (component-src rule).
   The byte layout is normative in spec/envelope.md. */

#ifndef MYSQL_GCM_ENVELOPE_H
#define MYSQL_GCM_ENVELOPE_H

#include <cstddef>

namespace gcm {

/* Error is the only error channel: no exceptions, no strings (a string error
   is how key or plaintext bytes end up in a log). */
enum class Error {
  ok = 0,
  bad_envelope,
  bad_tag,
  bad_key_len,
  rng,
  openssl,
};

/* Stable, data-free names for tests and error messages. */
const char *error_name(Error err);

/* A borrowed byte range. Never owns, never copies: UDF arguments are used in
   place so no extra copy of a key or plaintext exists to be wiped. */
struct Bytes {
  const unsigned char *data;
  size_t size;
};

inline constexpr unsigned char kVersionLegacyCbc = 0x01;  // decrypt only (design A3)
inline constexpr unsigned char kVersionRandom = 0x02;
inline constexpr unsigned char kVersionDet = 0x03;

inline constexpr size_t kKeyLen = 32;
inline constexpr size_t kNonceLen = 12;
inline constexpr size_t kTagLen = 16;
inline constexpr size_t kIvLen = 16;
inline constexpr size_t kCbcBlockLen = 16;
inline constexpr size_t kVersionLen = 1;

inline constexpr size_t kGcmOverhead = kVersionLen + kNonceLen + kTagLen;  // 29
inline constexpr size_t kMinGcmLen = kGcmOverhead;
inline constexpr size_t kMinCbcLen = kVersionLen + kIvLen + kCbcBlockLen;  // 33

/* Fields of a parsed envelope, all pointing into the caller's buffer.
   v1 carries a 16-byte IV in `nonce` and an empty `tag` — it is not
   authenticated (spec/envelope.md §2.3). */
struct ParsedEnvelope {
  unsigned char version;
  Bytes nonce;
  Bytes body;
  Bytes tag;
};

/* Splits `envelope` into fields. Returns bad_envelope for an unknown version,
   a length below the version's minimum, or a misaligned v1 body. */
Error parse(Bytes envelope, ParsedEnvelope *out);

/* Writes version||nonce (kVersionLen + kNonceLen bytes) and returns the offset
   where the ciphertext starts. */
size_t write_gcm_header(unsigned char version, const unsigned char *nonce, unsigned char *out);

/* Envelope size of a v2/v3 value for `plaintext_len` bytes of plaintext. */
inline constexpr size_t envelope_len(size_t plaintext_len) { return plaintext_len + kGcmOverhead; }

}  // namespace gcm

#endif  // MYSQL_GCM_ENVELOPE_H
