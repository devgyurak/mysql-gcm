/* SPDX-License-Identifier: GPL-2.0-only */
/* AES-256-GCM sealing/opening and the envelope-level operations behind the
   three SQL functions.

   Pure logic: no server headers, so tests/unit links this file directly. All
   buffers are caller-owned; nothing here allocates, logs, or throws. */

#ifndef MYSQL_GCM_GCM_H
#define MYSQL_GCM_GCM_H

#include "envelope.h"
#include "nonce.h"

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
   Reveals equality of plaintexts — join keys, UNIQUE and exact match only.
   One call, no retained key material: a session that lives for this call only. */
Error encrypt_det(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len);

/* encrypt_det with the nonce_key taken from `session` when the key is the one
   cached there (nonce.h, design A11). Output is byte-identical to encrypt_det for
   the same inputs; only the HMAC over the label is skipped on a cache hit. */
Error encrypt_det_with_session(DetSession *session, Bytes key, Bytes plaintext, Bytes aad,
                               unsigned char *out, size_t *out_len);

/* Test seam: version 0x02 with a caller-supplied nonce, so NIST CAVP vectors
   run through the same path as production encryption. Not reachable from SQL. */
Error encrypt_with_nonce(Bytes key, Bytes nonce, Bytes plaintext, Bytes aad, unsigned char *out,
                         size_t *out_len);

/* gcm_decrypt: accepts every GCM version and legacy 0x01. On bad_tag the output
   buffer is wiped before returning — unauthenticated plaintext never leaves.
   Builds and releases its own context: one call, no retained key material. */
Error decrypt(Bytes key, Bytes envelope, Bytes aad, unsigned char *out, size_t *out_len);

/* A decryption session (design A11): one EVP_CIPHER_CTX and a copy of the key it
   is scheduled for, owned by one UDF_INIT and used by one thread. When a call brings
   the same key bytes for the same suite the context keeps its key schedule and only
   the nonce is set; otherwise it is rebuilt and the copy replaced. That is what
   takes the per-row cost of gcm_decrypt from the context setup to the cipher.

   The key copy is compared with CRYPTO_memcmp and wiped whenever it is replaced,
   whenever a call fails (bad_tag included, so a context that just reported an
   error is never trusted for the next row), and on free. Never shared between
   UDF_INITs; never retained beyond the owner's deinit.

   Semantics are those of decrypt(): same checks in the same order, same errors,
   bad_tag wipes the output. The legacy 0x01 envelope never touches the session. */
struct DecryptSession;

/* nullptr on allocation failure. */
DecryptSession *decrypt_session_new();
/* Wipes the key copy and frees the context. nullptr is accepted. */
void decrypt_session_free(DecryptSession *session);

Error decrypt_with_session(DecryptSession *session, Bytes key, Bytes envelope, Bytes aad,
                           unsigned char *out, size_t *out_len);

/* Test seam: whether the session currently holds key material — a key copy, or a
   context with a cipher still set up. Lets the unit tests
   pin that a failed open forgets the key and a successful one keeps it. Core-only, not
   reachable from SQL (architecture rule §6; scripts/check-architecture.py lists it). */
bool decrypt_session_has_key(const DecryptSession *session);

#ifdef GCM_FAULT_INJECTION
/* Test seam, compiled only into tests/unit (GCM_FAULT_INJECTION): the next context
   rebuild fails at step 1 (cipher), 2 (IV length) or 3 (key and nonce), after the real
   OpenSSL call has succeeded. Listed in scripts/check-architecture.py. */
void fault_inject_decrypt_init(int step);
#endif

}  // namespace gcm

#endif  // MYSQL_GCM_GCM_H
