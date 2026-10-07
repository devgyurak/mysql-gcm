/* SPDX-License-Identifier: GPL-2.0-only */
#include "bench_support.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "nonce.h"

namespace gcm_bench {
namespace {

/* Fetched once, like the component does: one handle per suite plus the MAC. */
EVP_CIPHER *g_gcm256 = nullptr;
EVP_CIPHER *g_gcm192 = nullptr;
EVP_CIPHER *g_gcm128 = nullptr;
EVP_MAC *g_hmac = nullptr;

/* The key length selects the cipher and nothing else does — the same rule as src/gcm.cc,
   so the reference and the code under test always run the same suite for the same key.
   nullptr for a length no suite has, which every caller turns into a reported failure. */
const EVP_CIPHER *cipher_for(size_t key_len) {
  switch (key_len) {
    case gcm::kKeyLen256:
      return g_gcm256;
    case gcm::kKeyLen192:
      return g_gcm192;
    case gcm::kKeyLen128:
      return g_gcm128;
    default:
      return nullptr;
  }
}

/* HMAC-SHA256 the way src/nonce.cc does it, so the reference pays the same OpenSSL costs —
   a context per call, the digest passed as a parameter — and the difference that remains is
   this project's structure rather than a different way of calling the library. */
bool reference_hmac(const unsigned char *key, size_t key_len, const unsigned char *msg,
                    size_t msg_len, unsigned char *out) {
  char digest[] = "SHA256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_end(),
  };
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(g_hmac);
  if (ctx == nullptr) return false;
  const unsigned char empty = 0;
  size_t out_len = 0;
  const bool ok = EVP_MAC_init(ctx, key, key_len, params) == 1 &&
                  EVP_MAC_update(ctx, msg_len != 0 ? msg : &empty, msg_len) == 1 &&
                  EVP_MAC_final(ctx, out, &out_len, gcm::kHmacLen) == 1 && out_len == gcm::kHmacLen;
  EVP_MAC_CTX_free(ctx);
  return ok;
}

/* A 64-bit LCG. Benchmark input only — see the header. */
uint64_t next(uint64_t *state) {
  *state = *state * 6364136223846793005ULL + 1442695040888963407ULL;
  return *state;
}

const unsigned char kFixtureKey[gcm::kKeyLen256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

}  // namespace

const gcm::Bytes fixture_key(size_t key_len) {
  /* Preserve invalid lengths for the downstream suite check: clamping an oversized key to
     32 would silently turn a bad benchmark argument into a valid AES-256 measurement. */
  return gcm::Bytes{key_len <= sizeof(kFixtureKey) ? kFixtureKey : nullptr, key_len};
}

std::vector<unsigned char> filler(size_t len, uint64_t seed) {
  std::vector<unsigned char> out(len);
  uint64_t state = seed;
  for (size_t i = 0; i < len; ++i) {
    out[i] = static_cast<unsigned char>(next(&state) >> 56);
  }
  return out;
}

bool reference_init() {
  /* By name, not `EVP_aes_256_gcm()` / `HMAC()`: a number that src/ is judged against must not
     be produced through symbols src/ is forbidden to use (crypto-safety). */
  g_gcm256 = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  g_gcm192 = EVP_CIPHER_fetch(nullptr, "AES-192-GCM", nullptr);
  g_gcm128 = EVP_CIPHER_fetch(nullptr, "AES-128-GCM", nullptr);
  g_hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  return g_gcm256 != nullptr && g_gcm192 != nullptr && g_gcm128 != nullptr && g_hmac != nullptr;
}

void reference_deinit() {
  EVP_CIPHER_free(g_gcm256);
  g_gcm256 = nullptr;
  EVP_CIPHER_free(g_gcm192);
  g_gcm192 = nullptr;
  EVP_CIPHER_free(g_gcm128);
  g_gcm128 = nullptr;
  EVP_MAC_free(g_hmac);
  g_hmac = nullptr;
}

bool reference_seal(gcm::Bytes key, const unsigned char *nonce, const unsigned char *plaintext,
                    size_t plaintext_len, unsigned char *out, unsigned char *tag) {
  const EVP_CIPHER *cipher = cipher_for(key.size);
  if (cipher == nullptr) return false;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) return false;
  bool ok = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(gcm::kNonceLen),
                                nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data, nonce) == 1;
  int written = 0;
  ok = ok && EVP_EncryptUpdate(ctx, out, &written, plaintext, static_cast<int>(plaintext_len)) == 1;
  int final_written = 0;
  ok = ok && EVP_EncryptFinal_ex(ctx, out + written, &final_written) == 1 &&
       EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(gcm::kTagLen), tag) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool reference_open(gcm::Bytes key, const unsigned char *nonce, const unsigned char *ciphertext,
                    size_t ciphertext_len, const unsigned char *tag, unsigned char *out) {
  const EVP_CIPHER *cipher = cipher_for(key.size);
  if (cipher == nullptr) return false;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) return false;
  bool ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(gcm::kNonceLen),
                                nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data, nonce) == 1;
  int written = 0;
  ok = ok &&
       EVP_DecryptUpdate(ctx, out, &written, ciphertext, static_cast<int>(ciphertext_len)) == 1;
  /* SET_TAG before Final, and Final's return value is the authentication result — the same
     ordering src/gcm.cc uses, because a reference that skipped verification would be
     measuring a cheaper operation and would flatter nothing. */
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(gcm::kTagLen),
                                 const_cast<unsigned char *>(tag)) == 1;
  int final_written = 0;
  ok = ok && EVP_DecryptFinal_ex(ctx, out + written, &final_written) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool reference_seal_random(gcm::Bytes key, const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char *out, unsigned char *tag) {
  unsigned char nonce[gcm::kNonceLen];
  if (RAND_bytes(nonce, static_cast<int>(sizeof(nonce))) != 1) return false;
  return reference_seal(key, nonce, plaintext, plaintext_len, out, tag);
}

bool reference_seal_det(gcm::Bytes key, const unsigned char *plaintext, size_t plaintext_len,
                        unsigned char *out, unsigned char *tag) {
  unsigned char nonce_key[gcm::kHmacLen];
  unsigned char mac[gcm::kHmacLen];
  /* No OPENSSL_cleanse here, deliberately: the reference is meant to be the cheapest correct
     implementation of the algorithm, so wiping — which src/nonce.cc does and must — stays on
     this project's side of the ratio where it can be seen. The HMAC key is the whole
     encryption key, whatever its length — the derivation does not change per suite. */
  bool ok = reference_hmac(key.data, key.size,
                           reinterpret_cast<const unsigned char *>(gcm::kDetNonceLabel),
                           gcm::kDetNonceLabelLen, nonce_key) &&
            reference_hmac(nonce_key, sizeof(nonce_key), plaintext, plaintext_len, mac);
  ok = ok && reference_seal(key, mac, plaintext, plaintext_len, out, tag);
  return ok;
}

}  // namespace gcm_bench
