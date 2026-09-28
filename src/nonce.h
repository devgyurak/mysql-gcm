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

/* Full derivation; wipes the intermediate nonce_key. `out` needs kNonceLen. */
Error derive_det_nonce(Bytes key, Bytes plaintext, unsigned char *out);

}  // namespace gcm

#endif  // MYSQL_GCM_NONCE_H
