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
inline constexpr unsigned char kVersionRandom = 0x02;     // AES-256-GCM
inline constexpr unsigned char kVersionDet = 0x03;        // AES-256-GCM
inline constexpr unsigned char kVersionRandom128 = 0x04;  // AES-128-GCM (design A10)
inline constexpr unsigned char kVersionDet128 = 0x05;     // AES-128-GCM (design A10)

inline constexpr size_t kKeyLen256 = 32;
inline constexpr size_t kKeyLen128 = 16;
inline constexpr size_t kNonceLen = 12;
inline constexpr size_t kTagLen = 16;
inline constexpr size_t kIvLen = 16;
inline constexpr size_t kCbcBlockLen = 16;
inline constexpr size_t kVersionLen = 1;

inline constexpr size_t kGcmOverhead = kVersionLen + kNonceLen + kTagLen;  // 29
inline constexpr size_t kMinGcmLen = kGcmOverhead;
inline constexpr size_t kMinCbcLen = kVersionLen + kIvLen + kCbcBlockLen;  // 33

/* A GCM suite: the key length it takes and the two version bytes it writes.
   The suite is a function of the key length and of nothing else (design A10),
   so there is no selector argument and no sysvar to disagree with the key.

   This table is the single place the mapping lives. Adding AES-192 is one row
   here plus one EVP_CIPHER_fetch in gcm.cc; everything else is driven from it. */
struct Suite {
  size_t key_len;
  unsigned char version_random;
  unsigned char version_det;
};

/* nullptr when no suite has that key length — which is how a wrong key length
   is detected, so callers must not treat nullptr as a default. */
const Suite *suite_for_key_len(size_t key_len);

/* nullptr for a version byte that is not a GCM envelope, including the legacy
   v1 (0x01) and every reserved byte. */
const Suite *suite_for_version(unsigned char version);

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
