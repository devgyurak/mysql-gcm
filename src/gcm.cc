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

/* design A11: one context and one key copy, living as long as the UDF_INIT that
   owns it. key_len == 0 means nothing is scheduled and the next call does a full
   initialisation. */
struct DecryptSession {
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher;      /* the suite the context is scheduled for */
  unsigned char key[kKeyLen256]; /* the scheduled key, key_len bytes of it */
  size_t key_len;
};

namespace {

/* Fetched once; immutable afterwards. Per-call state lives in EVP_*_CTX so the
   UDFs are safe to call from many sessions at once. */
EVP_CIPHER *g_aes_gcm_256 = nullptr;
EVP_CIPHER *g_aes_gcm_192 = nullptr;
EVP_CIPHER *g_aes_gcm_128 = nullptr;
EVP_CIPHER *g_aes_cbc = nullptr;

/* The key length picks the cipher (design A10). nullptr for a length no suite
   has, which the callers turn into bad_key_len rather than a default. */
const EVP_CIPHER *gcm_cipher_for(size_t key_len) {
  switch (key_len) {
    case kKeyLen256:
      return g_aes_gcm_256;
    case kKeyLen192:
      return g_aes_gcm_192;
    case kKeyLen128:
      return g_aes_gcm_128;
    default:
      return nullptr;
  }
}

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
  const EVP_CIPHER *cipher = gcm_cipher_for(key.size);
  if (cipher == nullptr) return Error::openssl;
  if (!fits_int(plaintext.size) || !fits_int(aad.size)) return Error::openssl;

  CtxPtr ctx = new_ctx();
  if (!ctx) return Error::openssl;

  if (EVP_EncryptInit_ex2(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1) {
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

/* Drops the scheduled key. Called on every failure so a context that reported an
   error is never trusted for the next row, and before a key is replaced (design A11). */
void session_forget(DecryptSession *s) {
  OPENSSL_cleanse(s->key, sizeof(s->key));
  s->key_len = 0;
  s->cipher = nullptr;
  /* The key schedule inside the context is key-equivalent material; a forgotten key
     must not leave it behind until the next rebuild. The reset frees the provider
     context (a clear-free), and the rebuild path passes the cipher again, which is
     exactly the first-call path. Error and key-change paths only, never the hit. */
  EVP_CIPHER_CTX_reset(s->ctx);
}

bool session_has_key(const DecryptSession *s, Bytes key, const EVP_CIPHER *cipher) {
  /* The length and the suite are public; only the key bytes get the constant-time
     compare. key_len == 0 short-circuits before CRYPTO_memcmp sees a stale buffer. */
  return s->key_len != 0 && s->key_len == key.size && s->cipher == cipher &&
         CRYPTO_memcmp(s->key, key.data, key.size) == 0;
}

/* The one GCM open. With the same key and suite as the previous call the context
   keeps its key schedule and only the nonce is set (design A11); otherwise the
   context is rebuilt and the key copy replaced. */
Error open_gcm(DecryptSession *s, Bytes key, Bytes nonce, Bytes ciphertext, Bytes aad, Bytes tag,
               unsigned char *out, size_t *out_len) {
  const EVP_CIPHER *cipher = gcm_cipher_for(key.size);
  if (cipher == nullptr) return Error::openssl;
  if (!fits_int(ciphertext.size) || !fits_int(aad.size)) return Error::openssl;
  /* The nonce width is fixed at 12 (crypto-safety), so it is asserted here rather
     than taken from the parsed envelope: no envelope byte may choose an IV length.
     seal() uses the same constant. */
  if (nonce.size != kNonceLen) return Error::bad_envelope;

  if (session_has_key(s, key, cipher)) {
    if (EVP_DecryptInit_ex2(s->ctx, nullptr, nullptr, nonce.data, nullptr) != 1) {
      session_forget(s);
      return Error::openssl;
    }
  } else {
    session_forget(s);
    if (EVP_DecryptInit_ex2(s->ctx, cipher, nullptr, nullptr, nullptr) != 1) return Error::openssl;
    if (EVP_CIPHER_CTX_ctrl(s->ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceLen),
                            nullptr) != 1) {
      return Error::openssl;
    }
    if (EVP_DecryptInit_ex2(s->ctx, nullptr, key.data, nonce.data, nullptr) != 1) {
      return Error::openssl;
    }
    std::memcpy(s->key, key.data, key.size);
    s->key_len = key.size;
    s->cipher = cipher;
  }

  int aad_out = 0;
  if (aad.size != 0 &&
      EVP_DecryptUpdate(s->ctx, nullptr, &aad_out, aad.data, static_cast<int>(aad.size)) != 1) {
    session_forget(s);
    return Error::openssl;
  }
  int written = 0;
  if (ciphertext.size != 0 && EVP_DecryptUpdate(s->ctx, out, &written, ciphertext.data,
                                                static_cast<int>(ciphertext.size)) != 1) {
    OPENSSL_cleanse(out, ciphertext.size);
    session_forget(s);
    return Error::openssl;
  }
  /* SET_TAG must precede Final: Final's return value *is* the verification. */
  if (EVP_CIPHER_CTX_ctrl(s->ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kTagLen),
                          const_cast<unsigned char *>(tag.data)) != 1) {
    OPENSSL_cleanse(out, ciphertext.size);
    session_forget(s);
    return Error::openssl;
  }
  int final_len = 0;
  if (EVP_DecryptFinal_ex(s->ctx, out + written, &final_len) <= 0) {
    /* design.md §5.5: never hand back unauthenticated plaintext. The key is
       forgotten too: a failed Final is a failure, and the next row starts clean. */
    OPENSSL_cleanse(out, ciphertext.size);
    session_forget(s);
    return Error::bad_tag;
  }
  *out_len = static_cast<size_t>(written) + static_cast<size_t>(final_len);
  return Error::ok;
}

/* Legacy v1 (design A3): AES-256-CBC with PKCS#7, decrypt only, no tag. Rare
   dual-read data, so it builds its own context per call and never touches the
   session. */
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
  if (g_aes_gcm_256 != nullptr && g_aes_gcm_192 != nullptr && g_aes_gcm_128 != nullptr &&
      g_aes_cbc != nullptr) {
    return mac_init();
  }

  /* Fetch by name (crypto-safety): EVP_aes_256_gcm() would bind the component
     to the build-time OpenSSL and bypass the provider the server configured.

     All suites are fetched here, including AES-128 on a server that will never
     see a 16-byte key: fetching once at init is the rule, and a first call that
     had to fetch would put provider lookup on the row path. A provider that
     offers neither is a configuration this component refuses to install on. */
  g_aes_gcm_256 = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  g_aes_gcm_192 = EVP_CIPHER_fetch(nullptr, "AES-192-GCM", nullptr);
  g_aes_gcm_128 = EVP_CIPHER_fetch(nullptr, "AES-128-GCM", nullptr);
  g_aes_cbc = EVP_CIPHER_fetch(nullptr, "AES-256-CBC", nullptr);
  if (g_aes_gcm_256 == nullptr || g_aes_gcm_192 == nullptr || g_aes_gcm_128 == nullptr ||
      g_aes_cbc == nullptr || mac_init() != 0) {
    crypto_deinit();
    return 1;
  }
  return 0;
}

void crypto_deinit() {
  EVP_CIPHER_free(g_aes_gcm_256);
  g_aes_gcm_256 = nullptr;
  EVP_CIPHER_free(g_aes_gcm_192);
  g_aes_gcm_192 = nullptr;
  EVP_CIPHER_free(g_aes_gcm_128);
  g_aes_gcm_128 = nullptr;
  EVP_CIPHER_free(g_aes_cbc);
  g_aes_cbc = nullptr;
  mac_deinit();
}

Error encrypt_with_nonce(Bytes key, Bytes nonce, Bytes plaintext, Bytes aad, unsigned char *out,
                         size_t *out_len) {
  const Suite *suite = suite_for_key_len(key.size);
  if (suite == nullptr) return Error::bad_key_len;
  if (nonce.size != kNonceLen) return Error::bad_envelope;
  return encrypt_common(suite->version_random, key, nonce.data, plaintext, aad, out, out_len);
}

Error encrypt_random(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len) {
  const Suite *suite = suite_for_key_len(key.size);
  if (suite == nullptr) return Error::bad_key_len;

  unsigned char nonce[kNonceLen];
  if (RAND_bytes(nonce, static_cast<int>(kNonceLen)) != 1) return Error::rng;
  return encrypt_common(suite->version_random, key, nonce, plaintext, aad, out, out_len);
}

Error encrypt_det_with_session(DetSession *session, Bytes key, Bytes plaintext, Bytes aad,
                               unsigned char *out, size_t *out_len) {
  const Suite *suite = suite_for_key_len(key.size);
  if (suite == nullptr) return Error::bad_key_len;

  unsigned char nonce[kNonceLen];
  const Error err = derive_det_nonce_cached(session, key, plaintext, nonce);
  if (err != Error::ok) {
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return err;
  }
  const Error sealed = encrypt_common(suite->version_det, key, nonce, plaintext, aad, out, out_len);
  OPENSSL_cleanse(nonce, sizeof(nonce));
  /* A seal failure is a cipher failure: the cache goes, as the decrypt session's
     context goes, and the next row re-derives (design A11). */
  if (sealed != Error::ok) det_session_clear(session);
  return sealed;
}

Error encrypt_det(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out, size_t *out_len) {
  /* A one-call session on the stack: the same path the UDF takes, with the key copy
     and nonce_key living no longer than this call. */
  DetSession session{};
  const Error err = encrypt_det_with_session(&session, key, plaintext, aad, out, out_len);
  det_session_clear(&session);
  return err;
}

DecryptSession *decrypt_session_new() {
  auto *s = static_cast<DecryptSession *>(OPENSSL_zalloc(sizeof(DecryptSession)));
  if (s == nullptr) return nullptr;
  s->ctx = EVP_CIPHER_CTX_new();
  if (s->ctx == nullptr) {
    OPENSSL_free(s);
    return nullptr;
  }
  return s;
}

bool decrypt_session_has_key(const DecryptSession *session) {
  return session != nullptr && session->key_len != 0;
}

void decrypt_session_free(DecryptSession *session) {
  if (session == nullptr) return;
  session_forget(session);
  EVP_CIPHER_CTX_free(session->ctx);
  OPENSSL_free(session);
}

Error decrypt_with_session(DecryptSession *session, Bytes key, Bytes envelope, Bytes aad,
                           unsigned char *out, size_t *out_len) {
  if (session == nullptr) return Error::openssl;
  /* Checked on every call: init-time validation is not enough because the key
     argument need not be constant (component-src rule).

     A length no suite has is rejected before the envelope is looked at, so a
     wrong key length reports as one whatever the envelope holds. A length that
     *is* a suite's is then checked against the version byte below. */
  if (suite_for_key_len(key.size) == nullptr) return Error::bad_key_len;

  ParsedEnvelope parsed;
  const Error err = parse(envelope, &parsed);
  if (err != Error::ok) return err;

  if (parsed.version == kVersionLegacyCbc) {
    /* v1 is AES-256-CBC only (design A3): the migration prefixes an existing
       AES_ENCRYPT value, and that value was written with a 32-byte key. */
    if (key.size != kKeyLen256) return Error::bad_key_len;
    /* v1 predates AAD and cannot bind one (spec/envelope.md §2.3). */
    if (aad.size != 0) return Error::bad_envelope;
    return open_cbc(key, parsed.nonce, parsed.body, out, out_len);
  }

  /* design A10: the version byte states the key length this envelope was
     written with, so a disagreement is reported as the key-length problem it
     is. Letting the tag check catch it would report bad_tag and point an
     operator at data corruption. */
  const Suite *suite = suite_for_version(parsed.version);
  if (suite == nullptr || key.size != suite->key_len) return Error::bad_key_len;

  return open_gcm(session, key, parsed.nonce, parsed.body, aad, parsed.tag, out, out_len);
}

Error decrypt(Bytes key, Bytes envelope, Bytes aad, unsigned char *out, size_t *out_len) {
  /* A one-call session: the same checks and the same open as the UDF path, with the
     context and the key copy released before returning. */
  DecryptSession *session = decrypt_session_new();
  if (session == nullptr) return Error::openssl;
  const Error err = decrypt_with_session(session, key, envelope, aad, out, out_len);
  decrypt_session_free(session);
  return err;
}

}  // namespace gcm
