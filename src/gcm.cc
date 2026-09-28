/* SPDX-License-Identifier: GPL-2.0-only */
#include "gcm.h"

#include <climits>
#include <cstring>
#include <memory>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "nonce.h"

namespace gcm {
namespace {

/* Fetched once; immutable afterwards. Per-call state lives in EVP_*_CTX so the
   UDFs are safe to call from many sessions at once. */
EVP_CIPHER *g_aes_gcm = nullptr;
EVP_CIPHER *g_aes_cbc = nullptr;

using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

CtxPtr new_ctx() { return CtxPtr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free); }

/* EVP takes int lengths. The UDF layer already rejects anything above
   INT_MAX - kGcmOverhead with a length-specific error (udf_glue.h: too_long), so from
   SQL this is unreachable; it stays as a guard for direct callers such as the unit
   tests, which is why the failure maps to the generic OpenSSL error rather than a
   dedicated one. */
bool fits_int(size_t n) { return n <= static_cast<size_t>(INT_MAX); }

Error seal(Bytes key, const unsigned char *nonce, Bytes plaintext, Bytes aad, unsigned char *ct,
           unsigned char *tag) {
  if (g_aes_gcm == nullptr) return Error::openssl;
  if (!fits_int(plaintext.size) || !fits_int(aad.size)) return Error::openssl;

  CtxPtr ctx = new_ctx();
  if (!ctx) return Error::openssl;

  if (EVP_EncryptInit_ex2(ctx.get(), g_aes_gcm, nullptr, nullptr, nullptr) != 1) {
    return Error::openssl;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceLen),
                          nullptr) != 1) {
    return Error::openssl;
  }
  if (EVP_EncryptInit_ex2(ctx.get(), nullptr, key.data, nonce, nullptr) != 1) {
    return Error::openssl;
  }
  /* The AAD pass reports the AAD length in its own out-length, so it needs its own
     variable: reusing one counter would leave `aad.size` behind and make the Final
     call below write at `ct + aad.size`, past the end of a buffer sized for the
     plaintext. GCM's Final emits no bytes today, so nothing is actually written, but
     the pointer would still be out of range and the AAD length is caller-controlled.
     open_gcm() keeps the two apart for the same reason. */
  int aad_out = 0;
  if (aad.size != 0 &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &aad_out, aad.data, static_cast<int>(aad.size)) != 1) {
    return Error::openssl;
  }
  int written = 0;
  if (plaintext.size != 0 && EVP_EncryptUpdate(ctx.get(), ct, &written, plaintext.data,
                                               static_cast<int>(plaintext.size)) != 1) {
    return Error::openssl;
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), ct + written, &final_len) != 1) return Error::openssl;
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kTagLen), tag) != 1) {
    return Error::openssl;
  }
  return Error::ok;
}

Error open_gcm(Bytes key, Bytes nonce, Bytes ciphertext, Bytes aad, Bytes tag, unsigned char *out,
               size_t *out_len) {
  if (g_aes_gcm == nullptr) return Error::openssl;
  if (!fits_int(ciphertext.size) || !fits_int(aad.size)) return Error::openssl;

  CtxPtr ctx = new_ctx();
  if (!ctx) return Error::openssl;

  /* The nonce width is fixed at 12 (crypto-safety), so it is asserted here rather
     than taken from the parsed envelope: no envelope byte may choose an IV length.
     seal() uses the same constant. */
  if (nonce.size != kNonceLen) return Error::bad_envelope;

  int len = 0;
  if (EVP_DecryptInit_ex2(ctx.get(), g_aes_gcm, nullptr, nullptr, nullptr) != 1) {
    return Error::openssl;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceLen),
                          nullptr) != 1) {
    return Error::openssl;
  }
  if (EVP_DecryptInit_ex2(ctx.get(), nullptr, key.data, nonce.data, nullptr) != 1) {
    return Error::openssl;
  }
  if (aad.size != 0 &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data, static_cast<int>(aad.size)) != 1) {
    return Error::openssl;
  }
  int written = 0;
  if (ciphertext.size != 0 && EVP_DecryptUpdate(ctx.get(), out, &written, ciphertext.data,
                                                static_cast<int>(ciphertext.size)) != 1) {
    OPENSSL_cleanse(out, ciphertext.size);
    return Error::openssl;
  }
  /* SET_TAG must precede Final: Final's return value *is* the verification. */
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kTagLen),
                          const_cast<unsigned char *>(tag.data)) != 1) {
    OPENSSL_cleanse(out, ciphertext.size);
    return Error::openssl;
  }
  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), out + written, &final_len) <= 0) {
    /* design.md §5.5: never hand back unauthenticated plaintext. */
    OPENSSL_cleanse(out, ciphertext.size);
    return Error::bad_tag;
  }
  *out_len = static_cast<size_t>(written) + static_cast<size_t>(final_len);
  return Error::ok;
}

/* Legacy v1 (design A3): AES-256-CBC with PKCS#7, decrypt only, no tag. */
Error open_cbc(Bytes key, Bytes iv, Bytes ciphertext, unsigned char *out, size_t *out_len) {
  if (g_aes_cbc == nullptr) return Error::openssl;
  if (!fits_int(ciphertext.size)) return Error::openssl;

  CtxPtr ctx = new_ctx();
  if (!ctx) return Error::openssl;

  if (EVP_DecryptInit_ex2(ctx.get(), g_aes_cbc, key.data, iv.data, nullptr) != 1) {
    return Error::openssl;
  }
  int written = 0;
  if (EVP_DecryptUpdate(ctx.get(), out, &written, ciphertext.data,
                        static_cast<int>(ciphertext.size)) != 1) {
    OPENSSL_cleanse(out, ciphertext.size);
    return Error::openssl;
  }
  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), out + written, &final_len) <= 0) {
    OPENSSL_cleanse(out, ciphertext.size);
    return Error::bad_envelope;  // invalid padding: corrupt data or wrong key
  }
  *out_len = static_cast<size_t>(written) + static_cast<size_t>(final_len);
  return Error::ok;
}

Error encrypt_common(unsigned char version, Bytes key, const unsigned char *nonce, Bytes plaintext,
                     Bytes aad, unsigned char *out, size_t *out_len) {
  const size_t offset = write_gcm_header(version, nonce, out);
  const Error err = seal(key, nonce, plaintext, aad, out + offset, out + offset + plaintext.size);
  if (err != Error::ok) {
    OPENSSL_cleanse(out, envelope_len(plaintext.size));
    return err;
  }
  *out_len = envelope_len(plaintext.size);
  return Error::ok;
}

}  // namespace

void wipe(void *data, size_t len) { OPENSSL_cleanse(data, len); }

int crypto_init() {
  /* Idempotent: a second call would otherwise overwrite the handles and leak the
     first pair. mac_init() already guards itself the same way. */
  if (g_aes_gcm != nullptr && g_aes_cbc != nullptr) return mac_init();

  /* Fetch by name (crypto-safety): EVP_aes_256_gcm() would bind the component
     to the build-time OpenSSL and bypass the provider the server configured. */
  g_aes_gcm = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  g_aes_cbc = EVP_CIPHER_fetch(nullptr, "AES-256-CBC", nullptr);
  if (g_aes_gcm == nullptr || g_aes_cbc == nullptr || mac_init() != 0) {
    crypto_deinit();
    return 1;
  }
  return 0;
}

void crypto_deinit() {
  EVP_CIPHER_free(g_aes_gcm);
  g_aes_gcm = nullptr;
  EVP_CIPHER_free(g_aes_cbc);
  g_aes_cbc = nullptr;
  mac_deinit();
}

Error encrypt_with_nonce(Bytes key, Bytes nonce, Bytes plaintext, Bytes aad, unsigned char *out,
                         size_t *out_len) {
  if (key.size != kKeyLen) return Error::bad_key_len;
  if (nonce.size != kNonceLen) return Error::bad_envelope;
  return encrypt_common(kVersionRandom, key, nonce.data, plaintext, aad, out, out_len);
}

Error encrypt_random(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len) {
  if (key.size != kKeyLen) return Error::bad_key_len;

  unsigned char nonce[kNonceLen];
  if (RAND_bytes(nonce, static_cast<int>(kNonceLen)) != 1) return Error::rng;
  return encrypt_common(kVersionRandom, key, nonce, plaintext, aad, out, out_len);
}

Error encrypt_det(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len) {
  if (key.size != kKeyLen) return Error::bad_key_len;

  unsigned char nonce[kNonceLen];
  const Error err = derive_det_nonce(key, plaintext, nonce);
  if (err != Error::ok) {
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return err;
  }
  const Error sealed = encrypt_common(kVersionDet, key, nonce, plaintext, aad, out, out_len);
  OPENSSL_cleanse(nonce, sizeof(nonce));
  return sealed;
}

Error decrypt(Bytes key, Bytes envelope, Bytes aad, unsigned char *out, size_t *out_len) {
  /* Checked on every call: init-time validation is not enough because the key
     argument need not be constant (component-src rule). */
  if (key.size != kKeyLen) return Error::bad_key_len;

  ParsedEnvelope parsed;
  const Error err = parse(envelope, &parsed);
  if (err != Error::ok) return err;

  if (parsed.version == kVersionLegacyCbc) {
    /* v1 predates AAD and cannot bind one (spec/envelope.md §2.3). */
    if (aad.size != 0) return Error::bad_envelope;
    return open_cbc(key, parsed.nonce, parsed.body, out, out_len);
  }
  return open_gcm(key, parsed.nonce, parsed.body, aad, parsed.tag, out, out_len);
}

}  // namespace gcm
