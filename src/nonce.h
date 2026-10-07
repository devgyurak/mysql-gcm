/* SPDX-License-Identifier: GPL-2.0-only */
/* Deterministic nonce derivation (spec/envelope.md §3).

       nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")
       nonce     = HMAC-SHA256(nonce_key, plaintext)[0..12)

   The label exists so the encryption key is never used directly as an HMAC key
   (domain separation). AAD is deliberately not an input — see design.md §5.2
   and the "one AAD convention per key" constraint in spec/envelope.md §3. */

#ifndef MYSQL_GCM_NONCE_H
#define MYSQL_GCM_NONCE_H

#include "envelope.h"

namespace gcm {

/* The one place the label is spelled out. 22 bytes, no NUL. */
inline constexpr char kDetNonceLabel[] = "mysql-gcm/v1/det-nonce";
inline constexpr size_t kDetNonceLabelLen = sizeof(kDetNonceLabel) - 1;

inline constexpr size_t kHmacLen = 32;

/* Fetches the HMAC implementation by name. Called from crypto_init only. */
int mac_init();
void mac_deinit();

/* HMAC-SHA256. `out` must have room for kHmacLen bytes. */
Error hmac_sha256(Bytes key, Bytes msg, unsigned char *out);

/* nonce_key = HMAC-SHA256(key, label). `out` needs kHmacLen bytes and holds
   key material: the caller wipes it. */
Error derive_nonce_key(Bytes key, unsigned char *out);

/* Full derivation in one call; the intermediate nonce_key lives no longer than the
   call. `out` needs kNonceLen. */
Error derive_det_nonce(Bytes key, Bytes plaintext, unsigned char *out);

/* The cached nonce_key and the key copy it belongs to (design A11). derive_nonce_key
   depends on the key alone, so one UDF_INIT keeps the result across rows and
   re-derives it only when the key bytes change. The key copy is compared with
   CRYPTO_memcmp; the copy and the nonce_key are cleansed whenever they are replaced
   and when the owner releases the session. Never shared between UDF_INITs.

   Plain data, no allocation: the owner embeds it, zero-initialises it, and calls
   det_session_clear on every reset and on release. key_len == 0 means empty. */
struct DetSession {
  unsigned char key[kKeyLen256];
  size_t key_len;
  unsigned char nonce_key[kHmacLen];
};

/* OPENSSL_cleanse of the key copy and the nonce_key; the session is then empty. */
void det_session_clear(DetSession *session);

/* derive_det_nonce with the nonce_key taken from `session` when the key bytes
   equal the cached copy (CRYPTO_memcmp), and re-derived — replacing both the copy
   and the nonce_key after cleansing them — when they differ. Byte-identical to
   derive_det_nonce: the derivation and the nonce construction do not change, only
   when the first HMAC runs. */
Error derive_det_nonce_cached(DetSession *session, Bytes key, Bytes plaintext, unsigned char *out);

}  // namespace gcm

#endif  // MYSQL_GCM_NONCE_H
