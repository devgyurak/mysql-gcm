/* SPDX-License-Identifier: GPL-2.0-only */
/* AES-256-GCM sealing/opening and the envelope-level operations behind the
   three SQL functions.

   Pure logic: no server headers, so tests/unit links this file directly. All
   buffers are caller-owned; nothing here allocates, logs, or throws. */

#ifndef MYSQL_GCM_GCM_H
#define MYSQL_GCM_GCM_H

#include "envelope.h"

namespace gcm {

/* Fetches AES-256-GCM, AES-256-CBC and HMAC once. Returns 0 on success, 1 on
   failure (the component must then refuse to install). Idempotent: calling it
   twice does not leak the fetched handles. */
int crypto_init();
void crypto_deinit();

/* Wipes `len` bytes at `data` so a caller does not have to reach for OpenSSL
   itself. The UDF layer holds plaintext in its result buffers and must clear
   them, but the architecture rule keeps OpenSSL out of the adapters. */
void wipe(void *data, size_t len);

/* Output capacity the callers must provide. */
inline constexpr size_t encrypt_out_len(size_t plaintext_len) {
  return envelope_len(plaintext_len);
}
/* A decrypted value is always shorter than its envelope; sizing the output
   buffer to the envelope is always safe, including the CBC block slack. */
inline constexpr size_t decrypt_out_len(size_t envelope_size) { return envelope_size; }

/* gcm_encrypt: fresh RAND_bytes nonce, version 0x02. */
Error encrypt_random(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len);

/* gcm_encrypt_det: synthetic nonce (nonce.h), version 0x03.
   Reveals equality of plaintexts — join keys, UNIQUE and exact match only. */
Error encrypt_det(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len);

/* Test seam: version 0x02 with a caller-supplied nonce, so NIST CAVP vectors
   run through the same path as production encryption. Not reachable from SQL. */
Error encrypt_with_nonce(Bytes key, Bytes nonce, Bytes plaintext, Bytes aad, unsigned char *out,
                         size_t *out_len);

/* gcm_decrypt: accepts 0x02, 0x03 and legacy 0x01. On bad_tag the output buffer
   is wiped before returning — unauthenticated plaintext never leaves. */
Error decrypt(Bytes key, Bytes envelope, Bytes aad, unsigned char *out, size_t *out_len);

}  // namespace gcm

#endif  // MYSQL_GCM_GCM_H
