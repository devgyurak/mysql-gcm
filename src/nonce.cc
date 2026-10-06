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
  unsigned char nonce_key[kHmacLen];
  Error err = derive_nonce_key(key, nonce_key);
  if (err != Error::ok) {
    OPENSSL_cleanse(nonce_key, sizeof(nonce_key));
    return err;
  }

  unsigned char mac[kHmacLen];
  err = hmac_sha256(Bytes{nonce_key, sizeof(nonce_key)}, plaintext, mac);
  OPENSSL_cleanse(nonce_key, sizeof(nonce_key));  // derived key material
  if (err != Error::ok) {
    OPENSSL_cleanse(mac, sizeof(mac));
    return err;
  }

  std::memcpy(out, mac, kNonceLen);  // first 12 bytes of the MAC
  OPENSSL_cleanse(mac, sizeof(mac));
  return Error::ok;
}

}  // namespace gcm
