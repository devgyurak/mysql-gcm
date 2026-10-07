/* SPDX-License-Identifier: GPL-2.0-only */
#include "nonce.h"

#include <cstring>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace gcm {
namespace {

/* Fetched once in crypto_init and shared read-only afterwards: EVP_MAC is
   immutable, the per-call EVP_MAC_CTX is not (component-src: no global mutable
   state besides fetched handles). */
EVP_MAC *g_hmac = nullptr;

}  // namespace

int mac_init() {
  if (g_hmac != nullptr) return 0;
  /* Fetch by name so the provider layer decides the implementation; the legacy
     HMAC() symbol would bind us to the build-time OpenSSL (crypto-safety). */
  g_hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  return g_hmac == nullptr ? 1 : 0;
}

void mac_deinit() {
  EVP_MAC_free(g_hmac);
  g_hmac = nullptr;
}

Error hmac_sha256(Bytes key, Bytes msg, unsigned char *out) {
  if (g_hmac == nullptr || out == nullptr) return Error::openssl;

  char digest[] = "SHA256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_end(),
  };

  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(g_hmac);
  if (ctx == nullptr) return Error::openssl;

  size_t out_len = 0;
  const unsigned char empty = 0;
  const bool ok = EVP_MAC_init(ctx, key.data, key.size, params) == 1 &&
                  EVP_MAC_update(ctx, msg.size != 0 ? msg.data : &empty, msg.size) == 1 &&
                  EVP_MAC_final(ctx, out, &out_len, kHmacLen) == 1 && out_len == kHmacLen;
  EVP_MAC_CTX_free(ctx);
  return ok ? Error::ok : Error::openssl;
}

Error derive_nonce_key(Bytes key, unsigned char *out) {
  /* Any suite's key length (design A10). The label and the derivation are
     identical for all of them — HMAC-SHA256 takes a key of any length, and the
     label is frozen by spec/envelope.md §7. Note that this does *not* make the
     suites domain-separated from each other: RFC 2104 §2 zero-pads a short key,
     so K and K||0^16 derive the same nonce key (design A10, open question). */
  if (suite_for_key_len(key.size) == nullptr) return Error::bad_key_len;
  const Bytes label{reinterpret_cast<const unsigned char *>(kDetNonceLabel), kDetNonceLabelLen};
  return hmac_sha256(key, label, out);
}

Error derive_det_nonce(Bytes key, Bytes plaintext, unsigned char *out) {
  /* One derivation body (derive_det_nonce_cached) and a session that lives for this
     call only, so the per-call path cannot drift from the cached one. */
  DetSession session{};
  const Error err = derive_det_nonce_cached(&session, key, plaintext, out);
  det_session_clear(&session);
  return err;
}

void det_session_clear(DetSession *session) {
  OPENSSL_cleanse(session->key, sizeof(session->key));
  OPENSSL_cleanse(session->nonce_key, sizeof(session->nonce_key));
  session->key_len = 0;
}

Error derive_det_nonce_cached(DetSession *session, Bytes key, Bytes plaintext, unsigned char *out) {
  /* The same length check derive_nonce_key performs, so a wrong length is
     reported before the cache is consulted or touched. */
  if (suite_for_key_len(key.size) == nullptr) return Error::bad_key_len;

  /* Constant-time compare of the key bytes (crypto-safety): a cache hit must not
     leak how many leading key bytes matched. The length check short-circuits
     only on a public quantity. */
  const bool hit =
      session->key_len == key.size && CRYPTO_memcmp(session->key, key.data, key.size) == 0;
  if (!hit) {
    det_session_clear(session);  // the previous key and its nonce_key go first
    const Error derived = derive_nonce_key(key, session->nonce_key);
    if (derived != Error::ok) {
      det_session_clear(session);
      return derived;
    }
    std::memcpy(session->key, key.data, key.size);
    session->key_len = key.size;
  }

  unsigned char mac[kHmacLen];
  const Error err =
      hmac_sha256(Bytes{session->nonce_key, sizeof(session->nonce_key)}, plaintext, mac);
  if (err != Error::ok) {
    /* An OpenSSL failure forgets the cache, as the decrypt session forgets its
       context: the next row re-derives rather than trusting state from a call that
       failed. The pre-check above (bad_key_len) returns before the cache is touched. */
    OPENSSL_cleanse(mac, sizeof(mac));
    det_session_clear(session);
    return err;
  }
  std::memcpy(out, mac, kNonceLen);  // first 12 bytes of the MAC (spec/envelope.md §3)
  OPENSSL_cleanse(mac, sizeof(mac));
  return Error::ok;
}

}  // namespace gcm
