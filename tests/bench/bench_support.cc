/* SPDX-License-Identifier: GPL-2.0-only */
#include "bench_support.h"

#include <openssl/evp.h>

namespace gcm_bench {
namespace {

/* Fetched once, like the component does. */
EVP_CIPHER *g_gcm = nullptr;

/* A 64-bit LCG. Benchmark input only — see the header. */
uint64_t next(uint64_t *state) {
  *state = *state * 6364136223846793005ULL + 1442695040888963407ULL;
  return *state;
}

const unsigned char kFixtureKey[gcm::kKeyLen] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

}  // namespace

const gcm::Bytes fixture_key() { return gcm::Bytes{kFixtureKey, sizeof(kFixtureKey)}; }

std::vector<unsigned char> filler(size_t len, uint64_t seed) {
  std::vector<unsigned char> out(len);
  uint64_t state = seed;
  for (size_t i = 0; i < len; ++i) {
    out[i] = static_cast<unsigned char>(next(&state) >> 56);
  }
  return out;
}

bool reference_init() {
  g_gcm = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  return g_gcm != nullptr;
}

void reference_deinit() {
  EVP_CIPHER_free(g_gcm);
  g_gcm = nullptr;
}

bool reference_seal(const unsigned char *key, const unsigned char *nonce,
                    const unsigned char *plaintext, size_t plaintext_len, unsigned char *out,
                    unsigned char *tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) return false;
  bool ok = EVP_EncryptInit_ex(ctx, g_gcm, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(gcm::kNonceLen),
                                nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
  int written = 0;
  ok = ok && EVP_EncryptUpdate(ctx, out, &written, plaintext, static_cast<int>(plaintext_len)) == 1;
  int final_written = 0;
  ok = ok && EVP_EncryptFinal_ex(ctx, out + written, &final_written) == 1 &&
       EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(gcm::kTagLen), tag) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool reference_open(const unsigned char *key, const unsigned char *nonce,
                    const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *tag, unsigned char *out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) return false;
  bool ok = EVP_DecryptInit_ex(ctx, g_gcm, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(gcm::kNonceLen),
                                nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
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

}  // namespace gcm_bench
