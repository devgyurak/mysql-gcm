/* SPDX-License-Identifier: GPL-2.0-only */
/* AES-256-GCM: NIST known-answer tests, round trips, tampering and the failure
   semantics of spec/envelope.md §4. */

#include "gcm.h"

#include <cctype>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "nonce.h"
#include "vectors.h"

namespace {

using gcm::Bytes;
using gcm::Error;

Bytes span_of(const std::vector<unsigned char> &v) { return Bytes{v.data(), v.size()}; }

std::string sanitize(const std::string &id) {
  std::string name = id;
  for (char &c : name) {
    if (!std::isalnum(static_cast<unsigned char>(c))) c = '_';
  }
  return name;
}

template <typename T>
std::string param_name(const ::testing::TestParamInfo<T> &info) {
  return sanitize(info.param.id);
}

/* crypto_init fetches the algorithms once for the whole binary, exactly as the
   component does at INSTALL time. */
class CryptoEnvironment : public ::testing::Environment {
 public:
  void SetUp() override { ASSERT_EQ(gcm::crypto_init(), 0) << "EVP fetch failed"; }
  void TearDown() override { gcm::crypto_deinit(); }
};

[[maybe_unused]] const ::testing::Environment *const kCryptoEnv =
    ::testing::AddGlobalTestEnvironment(new CryptoEnvironment);

bool all_zero(const unsigned char *data, size_t size) {
  unsigned char acc = 0;
  for (size_t i = 0; i < size; ++i) acc |= static_cast<const volatile unsigned char *>(data)[i];
  return acc == 0;
}

// --- known-answer tests ------------------------------------------------------

class SealVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(SealVector, GivenVectorNonce_WhenSeal_ThenEnvelopeMatches) {
  // Given
  const gcm_test::Vector &v = GetParam();
  std::vector<unsigned char> out(gcm::encrypt_out_len(v.plaintext.size()), 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::encrypt_with_nonce(span_of(v.key), span_of(v.nonce), span_of(v.plaintext),
                                            span_of(v.aad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok) << v.id;
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(v.envelope.data(), v.envelope.size()));
}

INSTANTIATE_TEST_SUITE_P(Nist, SealVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "nist")),
                         param_name<gcm_test::Vector>);
INSTANTIATE_TEST_SUITE_P(Random, SealVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "random")),
                         param_name<gcm_test::Vector>);

class OpenVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(OpenVector, GivenValidEnvelope_WhenDecrypt_ThenPlaintextMatches) {
  // Given
  const gcm_test::Vector &v = GetParam();
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(v.envelope), span_of(v.aad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok) << v.id;
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(v.plaintext.data(), v.plaintext.size()));
}

INSTANTIATE_TEST_SUITE_P(Nist, OpenVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "nist")),
                         param_name<gcm_test::Vector>);
INSTANTIATE_TEST_SUITE_P(Random, OpenVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "random")),
                         param_name<gcm_test::Vector>);
INSTANTIATE_TEST_SUITE_P(Legacy, OpenVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "legacy")),
                         param_name<gcm_test::Vector>);
/* spec/envelope.md §6 requires `decrypt(envelope, key, aad) == pt` for every ok vector,
   deterministic ones included; DetVector below only covers the sealing direction. */
INSTANTIATE_TEST_SUITE_P(Det, OpenVector, ::testing::ValuesIn(gcm_test::vectors_where("ok", "det")),
                         param_name<gcm_test::Vector>);

class DetVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(DetVector, GivenSpecVector_WhenEncryptDet_ThenEnvelopeMatchesByteForByte) {
  // Given
  const gcm_test::Vector &v = GetParam();
  std::vector<unsigned char> out(gcm::encrypt_out_len(v.plaintext.size()), 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::encrypt_det(span_of(v.key), span_of(v.plaintext), span_of(v.aad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok) << v.id;
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(v.envelope.data(), v.envelope.size()));
  /* The version byte follows the key length (design A10), so it comes from the
     suite table rather than a constant — otherwise this assertion silently means
     "AES-256" and an AES-128 vector would have to be excluded from the suite. */
  const gcm::Suite *suite = gcm::suite_for_key_len(v.key.size());
  ASSERT_NE(suite, nullptr) << v.id;
  EXPECT_EQ(out[0], suite->version_det);
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, DetVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "det")),
                         param_name<gcm_test::Vector>);

// --- failure semantics -------------------------------------------------------

class BadTagVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(BadTagVector, GivenTamperedEnvelope_WhenDecrypt_ThenBadTagAndOutputWiped) {
  // Given: a vector whose tag cannot verify (tamper, wrong key, wrong AAD)
  const gcm_test::Vector &v = GetParam();
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0xFF);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(v.envelope), span_of(v.aad), out.data(), &out_len);
  // Then: no unauthenticated plaintext survives in the buffer
  ASSERT_EQ(err, Error::bad_tag) << v.id;
  EXPECT_TRUE(all_zero(out.data(), v.envelope.size() - gcm::kGcmOverhead)) << v.id;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, BadTagVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("bad_tag")),
                         param_name<gcm_test::Vector>);

class BadEnvelopeVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(BadEnvelopeVector, GivenMalformedEnvelope_WhenDecrypt_ThenBadEnvelope) {
  // Given
  const gcm_test::Vector &v = GetParam();
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 64, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(v.envelope), span_of(v.aad), out.data(), &out_len);
  // Then: always an error, independent of any strict setting
  EXPECT_EQ(err, Error::bad_envelope) << v.id;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, BadEnvelopeVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("bad_envelope")),
                         param_name<gcm_test::Vector>);

/* One entry point per case: testing.md wants a single call in When, and sharing one
   case across the three would hide which of them stopped checking the key length. */
enum class KeyLenEntry { random, det, decrypt };

struct BadKeyLenCase {
  gcm_test::Vector vector;
  KeyLenEntry entry;
};

std::vector<BadKeyLenCase> bad_key_len_cases() {
  std::vector<BadKeyLenCase> out;
  for (const gcm_test::Vector &v : gcm_test::vectors_where("bad_key_len")) {
    /* Decryption always applies: it has a version byte to disagree with.
       Encryption only when the key length belongs to no suite at all — a key
       whose length *is* a suite's is a perfectly good encryption key, and the
       mismatch vectors (design A10) exist precisely to fail on the decrypt side.
       Feeding those to encrypt_random would assert that sealing with a valid
       32-byte key fails, which is not the rule and is not what we want. */
    out.push_back({v, KeyLenEntry::decrypt});
    if (gcm::suite_for_key_len(v.key.size()) == nullptr) {
      out.push_back({v, KeyLenEntry::random});
      out.push_back({v, KeyLenEntry::det});
    }
  }
  return out;
}

const char *entry_name(KeyLenEntry entry) {
  switch (entry) {
    case KeyLenEntry::random:
      return "encrypt_random";
    case KeyLenEntry::det:
      return "encrypt_det";
    case KeyLenEntry::decrypt:
      return "decrypt";
  }
  return "unknown";
}

Error call_entry(const BadKeyLenCase &c, unsigned char *out, size_t *out_len) {
  switch (c.entry) {
    case KeyLenEntry::random:
      return gcm::encrypt_random(span_of(c.vector.key), span_of(c.vector.plaintext),
                                 span_of(c.vector.aad), out, out_len);
    case KeyLenEntry::det:
      return gcm::encrypt_det(span_of(c.vector.key), span_of(c.vector.plaintext),
                              span_of(c.vector.aad), out, out_len);
    case KeyLenEntry::decrypt:
      return gcm::decrypt(span_of(c.vector.key), span_of(c.vector.envelope), span_of(c.vector.aad),
                          out, out_len);
  }
  return Error::openssl;
}

class BadKeyLenVector : public ::testing::TestWithParam<BadKeyLenCase> {};

TEST_P(BadKeyLenVector, GivenWrongKeyLength_WhenThisEntryPointIsCalled_ThenBadKeyLen) {
  // Given
  const BadKeyLenCase &c = GetParam();
  std::vector<unsigned char> out(c.vector.envelope.size() + gcm::kGcmOverhead + 64, 0);
  size_t out_len = 0;

  // When
  const Error err = call_entry(c, out.data(), &out_len);

  // Then
  EXPECT_EQ(err, Error::bad_key_len) << c.vector.id << " via " << entry_name(c.entry);
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, BadKeyLenVector, ::testing::ValuesIn(bad_key_len_cases()),
                         [](const ::testing::TestParamInfo<BadKeyLenCase> &info) {
                           return sanitize(info.param.vector.id) + "_via_" +
                                  entry_name(info.param.entry);
                         });

// --- properties --------------------------------------------------------------

TEST(EncryptRandom, GivenSamePlaintextTwice_WhenEncryptRandom_ThenEnvelopesDiffer) {
  // Given
  const gcm_test::Vector &v = gcm_test::vector_by_id("det-korean-hong");
  std::vector<unsigned char> first(gcm::encrypt_out_len(v.plaintext.size()), 0);
  std::vector<unsigned char> second(first.size(), 0);
  size_t first_len = 0;
  size_t second_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_random(span_of(v.key), span_of(v.plaintext), Bytes{nullptr, 0},
                                first.data(), &first_len),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_random(span_of(v.key), span_of(v.plaintext), Bytes{nullptr, 0},
                                second.data(), &second_len),
            Error::ok);
  // Then: a fresh nonce each time (the property, not a fixed value)
  EXPECT_EQ(first_len, second_len);
  const gcm::Suite *suite = gcm::suite_for_key_len(v.key.size());
  ASSERT_NE(suite, nullptr) << v.id;
  EXPECT_EQ(first[0], suite->version_random);
  EXPECT_NE(gcm_test::to_hex(first.data(), first_len), gcm_test::to_hex(second.data(), second_len));
}

/* Pseudo-random plaintext of a given size. The loop lives outside the test body
   (testing rule) and the seed is fixed, so a failure is reproducible. */
std::vector<unsigned char> pseudo_random_plaintext(size_t size) {
  std::mt19937 rng(42);
  std::vector<unsigned char> plaintext(size);
  for (unsigned char &byte : plaintext) byte = static_cast<unsigned char>(rng());
  return plaintext;
}

/* Sizes chosen around the AES block and common buffer boundaries. */
class RoundTripSize : public ::testing::TestWithParam<size_t> {};

TEST_P(RoundTripSize, GivenPlaintextOfThisSize_WhenEncryptThenDecrypt_ThenOriginalReturned) {
  // Given
  const size_t size = GetParam();
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x77);
  const std::vector<unsigned char> aad = {'c', 'o', 'l'};
  const std::vector<unsigned char> plaintext = pseudo_random_plaintext(size);
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(size), 0);
  size_t sealed_len = 0;
  std::vector<unsigned char> opened(gcm::decrypt_out_len(gcm::encrypt_out_len(size)) + 1, 0);
  size_t opened_len = 0;

  // When
  ASSERT_EQ(gcm::encrypt_random(span_of(key), span_of(plaintext), span_of(aad), sealed.data(),
                                &sealed_len),
            Error::ok);
  ASSERT_EQ(gcm::decrypt(span_of(key), Bytes{sealed.data(), sealed_len}, span_of(aad),
                         opened.data(), &opened_len),
            Error::ok);

  // Then
  EXPECT_EQ(sealed_len, size + gcm::kGcmOverhead);
  EXPECT_EQ(gcm_test::to_hex(opened.data(), opened_len),
            gcm_test::to_hex(plaintext.data(), plaintext.size()));
}

INSTANTIATE_TEST_SUITE_P(Boundaries, RoundTripSize,
                         ::testing::Values(size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17},
                                           size_t{1024}, size_t{65536}),
                         [](const ::testing::TestParamInfo<size_t> &info) {
                           return "len" + std::to_string(info.param);
                         });

TEST(RoundTrip, GivenDetEnvelope_WhenDecryptedWithoutRecomputingNonce_ThenStoredNonceSuffices) {
  // Given: the A2 resolution — the nonce is stored, not recomputed
  const gcm_test::Vector &v = gcm_test::vector_by_id("det-korean-hong");
  unsigned char derived[gcm::kNonceLen] = {0};
  ASSERT_EQ(gcm::derive_det_nonce(span_of(v.key), span_of(v.plaintext), derived), Error::ok);
  // When
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0);
  size_t out_len = 0;
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(v.envelope), Bytes{nullptr, 0}, out.data(), &out_len);
  // Then: the envelope's stored nonce is exactly the derived one
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(v.envelope.data() + 1, gcm::kNonceLen),
            gcm_test::to_hex(derived, sizeof(derived)));
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(v.plaintext.data(), v.plaintext.size()));
}

/* AAD longer than the tag, with no plaintext at all: the combination where the
   ciphertext write offset must come from the plaintext pass and not from the AAD
   pass, or the seal writes past a 29-byte buffer. */
TEST(Aad, GivenEmptyPlaintextAndLongAad_WhenEncryptDet_ThenTwentyNineBytesAndRoundTrips) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x41);
  const std::vector<unsigned char> aad(64, 0x62);
  const std::vector<unsigned char> plaintext;
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(0), 0);
  size_t sealed_len = 0;
  std::vector<unsigned char> opened(gcm::decrypt_out_len(gcm::kGcmOverhead) + 1, 0);
  size_t opened_len = 0;

  // When
  ASSERT_EQ(
      gcm::encrypt_det(span_of(key), span_of(plaintext), span_of(aad), sealed.data(), &sealed_len),
      Error::ok);
  ASSERT_EQ(gcm::decrypt(span_of(key), Bytes{sealed.data(), sealed_len}, span_of(aad),
                         opened.data(), &opened_len),
            Error::ok);

  // Then
  EXPECT_EQ(sealed_len, gcm::kGcmOverhead);
  EXPECT_EQ(opened_len, 0u);
}

TEST(EncryptWithNonce, GivenNonceOfWrongLength_WhenSealing_ThenBadEnvelope) {
  // Given: the vector-test seam, which is the only caller that supplies a nonce
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x41);
  const std::vector<unsigned char> plaintext = {'x'};
  const std::vector<unsigned char> short_nonce(gcm::kNonceLen - 1, 0x00);
  std::vector<unsigned char> out(gcm::encrypt_out_len(plaintext.size()), 0);
  size_t out_len = 0;

  // When
  const Error err = gcm::encrypt_with_nonce(span_of(key), span_of(short_nonce), span_of(plaintext),
                                            Bytes{nullptr, 0}, out.data(), &out_len);

  // Then: the documented contract of gcm.h, so a mis-sized vector cannot silently
  // produce an envelope with a nonce of the wrong width
  EXPECT_EQ(err, Error::bad_envelope);
}

TEST(Aad, GivenEnvelopeWithAad_WhenDecryptedWithoutAad_ThenBadTag) {
  // Given
  const gcm_test::Vector &v = gcm_test::vector_by_id("det-aad");
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0xEE);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(v.envelope), Bytes{nullptr, 0}, out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::bad_tag);
}

TEST(Legacy, GivenLegacyEnvelopeWithAad_WhenDecrypt_ThenBadEnvelope) {
  // Given: v1 predates AAD and must not silently ignore one (design A3)
  const gcm_test::Vector &v = gcm_test::vector_by_id("legacy-cbc-korean");
  const std::vector<unsigned char> aad = {'x'};
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(v.envelope), span_of(aad), out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

TEST(Legacy, GivenLegacyEnvelopeWithCorruptPadding_WhenDecrypt_ThenBadEnvelope) {
  // Given: last block flipped, so PKCS#7 unpadding fails
  const gcm_test::Vector &v = gcm_test::vector_by_id("legacy-cbc-korean");
  std::vector<unsigned char> env = v.envelope;
  env[env.size() - 1] ^= 0xFF;
  std::vector<unsigned char> out(gcm::decrypt_out_len(env.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt(span_of(v.key), span_of(env), Bytes{nullptr, 0}, out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

TEST(Envelope, GivenEmptyPlaintext_WhenEncryptDet_ThenTwentyNineBytes) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x01);
  std::vector<unsigned char> out(gcm::encrypt_out_len(0), 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::encrypt_det(span_of(key), Bytes{nullptr, 0}, Bytes{nullptr, 0}, out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(out_len, gcm::kGcmOverhead);
}

// --- AES-128 (design A10) ----------------------------------------------------

TEST(Aes128, GivenA16ByteKey_WhenEncryptRandom_ThenVersionIs04AndRoundTrips) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen128, 0x3C);
  const std::vector<unsigned char> plaintext = {'h', 'e', 'l', 'l', 'o'};
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> opened(gcm::decrypt_out_len(sealed.size()) + 1, 0);
  size_t sealed_len = 0;
  size_t opened_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_random(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, sealed.data(),
                                &sealed_len),
            Error::ok);
  // Then
  EXPECT_EQ(sealed[0], gcm::kVersionRandom128);
  EXPECT_EQ(sealed_len, plaintext.size() + gcm::kGcmOverhead);
  ASSERT_EQ(gcm::decrypt(span_of(key), Bytes{sealed.data(), sealed_len}, Bytes{nullptr, 0},
                         opened.data(), &opened_len),
            Error::ok);
  EXPECT_EQ(gcm_test::to_hex(opened.data(), opened_len),
            gcm_test::to_hex(plaintext.data(), plaintext.size()));
}

TEST(Aes128, GivenA16ByteKey_WhenEncryptDetTwice_ThenIdenticalEnvelopeWithVersion05) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen128, 0x5A);
  const std::vector<unsigned char> plaintext = {'E', 'M', 'R', '-', '1'};
  std::vector<unsigned char> first(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> second(first.size(), 0);
  size_t first_len = 0;
  size_t second_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_det(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, first.data(),
                             &first_len),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_det(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, second.data(),
                             &second_len),
            Error::ok);
  // Then
  EXPECT_EQ(first[0], gcm::kVersionDet128);
  EXPECT_EQ(gcm_test::to_hex(first.data(), first_len), gcm_test::to_hex(second.data(), second_len));
}

TEST(Aes128, GivenTheSamePlaintextUnderBothSuites_WhenEncryptDet_ThenEnvelopesDiffer) {
  // Given: the AES-128 key is the AES-256 key truncated, the shape a client bug makes
  const std::vector<unsigned char> key256(gcm::kKeyLen256, 0x11);
  const std::vector<unsigned char> key128(gcm::kKeyLen128, 0x11);
  const std::vector<unsigned char> plaintext = {'j', 'o', 'i', 'n'};
  std::vector<unsigned char> wide(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> narrow(wide.size(), 0);
  size_t wide_len = 0;
  size_t narrow_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_det(span_of(key256), span_of(plaintext), Bytes{nullptr, 0}, wide.data(),
                             &wide_len),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_det(span_of(key128), span_of(plaintext), Bytes{nullptr, 0}, narrow.data(),
                             &narrow_len),
            Error::ok);
  // Then: ciphertext does not join across suites, which is why the key length is
  // part of the key's identity and not a tuning knob
  EXPECT_NE(gcm_test::to_hex(wide.data(), wide_len), gcm_test::to_hex(narrow.data(), narrow_len));
}

TEST(Aes128, GivenA256EnvelopeAndA128Key_WhenDecrypt_ThenBadKeyLenNotBadTag) {
  // Given
  const std::vector<unsigned char> key256(gcm::kKeyLen256, 0x21);
  const std::vector<unsigned char> key128(gcm::kKeyLen128, 0x21);
  const std::vector<unsigned char> plaintext = {'x'};
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> opened(sealed.size() + 1, 0);
  size_t sealed_len = 0;
  size_t opened_len = 0;
  ASSERT_EQ(gcm::encrypt_det(span_of(key256), span_of(plaintext), Bytes{nullptr, 0}, sealed.data(),
                             &sealed_len),
            Error::ok);
  // When
  const Error err = gcm::decrypt(span_of(key128), Bytes{sealed.data(), sealed_len},
                                 Bytes{nullptr, 0}, opened.data(), &opened_len);
  // Then: the version byte states the key length, so this is a key problem and is
  // reported as one. bad_tag would send an operator after data corruption.
  EXPECT_EQ(err, Error::bad_key_len);
}

TEST(Aes128, GivenA128EnvelopeAndA256Key_WhenDecrypt_ThenBadKeyLenNotBadTag) {
  // Given
  const std::vector<unsigned char> key128(gcm::kKeyLen128, 0x22);
  const std::vector<unsigned char> key256(gcm::kKeyLen256, 0x22);
  const std::vector<unsigned char> plaintext = {'y'};
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> opened(sealed.size() + 1, 0);
  size_t sealed_len = 0;
  size_t opened_len = 0;
  ASSERT_EQ(gcm::encrypt_det(span_of(key128), span_of(plaintext), Bytes{nullptr, 0}, sealed.data(),
                             &sealed_len),
            Error::ok);
  // When
  const Error err = gcm::decrypt(span_of(key256), Bytes{sealed.data(), sealed_len},
                                 Bytes{nullptr, 0}, opened.data(), &opened_len);
  // Then
  EXPECT_EQ(err, Error::bad_key_len);
}

TEST(Aes192, GivenA24ByteKey_WhenEncryptRandom_ThenVersionIs06AndRoundTrips) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen192, 0x44);
  const std::vector<unsigned char> plaintext = {'z', 'e', 'd'};
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> opened(gcm::decrypt_out_len(sealed.size()) + 1, 0);
  size_t sealed_len = 0;
  size_t opened_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_random(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, sealed.data(),
                                &sealed_len),
            Error::ok);
  // Then
  EXPECT_EQ(sealed[0], gcm::kVersionRandom192);
  EXPECT_EQ(sealed_len, plaintext.size() + gcm::kGcmOverhead);
  ASSERT_EQ(gcm::decrypt(span_of(key), Bytes{sealed.data(), sealed_len}, Bytes{nullptr, 0},
                         opened.data(), &opened_len),
            Error::ok);
  EXPECT_EQ(gcm_test::to_hex(opened.data(), opened_len),
            gcm_test::to_hex(plaintext.data(), plaintext.size()));
}

TEST(Aes192, GivenA24ByteKey_WhenEncryptDetTwice_ThenIdenticalEnvelopeWithVersion07) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen192, 0x55);
  const std::vector<unsigned char> plaintext = {'E', 'M', 'R', '-', '2'};
  std::vector<unsigned char> first(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> second(first.size(), 0);
  size_t first_len = 0;
  size_t second_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_det(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, first.data(),
                             &first_len),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_det(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, second.data(),
                             &second_len),
            Error::ok);
  // Then
  EXPECT_EQ(first[0], gcm::kVersionDet192);
  EXPECT_EQ(gcm_test::to_hex(first.data(), first_len), gcm_test::to_hex(second.data(), second_len));
}

TEST(Aes192, GivenA192EnvelopeAndA256Key_WhenDecrypt_ThenBadKeyLenNotBadTag) {
  // Given
  const std::vector<unsigned char> key192(gcm::kKeyLen192, 0x66);
  const std::vector<unsigned char> key256(gcm::kKeyLen256, 0x66);
  const std::vector<unsigned char> plaintext = {'w'};
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> opened(sealed.size() + 1, 0);
  size_t sealed_len = 0;
  size_t opened_len = 0;
  ASSERT_EQ(gcm::encrypt_det(span_of(key192), span_of(plaintext), Bytes{nullptr, 0}, sealed.data(),
                             &sealed_len),
            Error::ok);
  // When
  const Error err = gcm::decrypt(span_of(key256), Bytes{sealed.data(), sealed_len},
                                 Bytes{nullptr, 0}, opened.data(), &opened_len);
  // Then
  EXPECT_EQ(err, Error::bad_key_len);
}

TEST(Aes192, GivenThreeSuitesOverOnePlaintext_WhenEncryptDet_ThenAllThreeEnvelopesDiffer) {
  // Given: the shorter keys are the long one truncated, the shape a client bug makes
  const std::vector<unsigned char> key256(gcm::kKeyLen256, 0x11);
  const std::vector<unsigned char> key192(gcm::kKeyLen192, 0x11);
  const std::vector<unsigned char> key128(gcm::kKeyLen128, 0x11);
  const std::vector<unsigned char> plaintext = {'j', 'o', 'i', 'n'};
  std::vector<unsigned char> a(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> b(a.size(), 0);
  std::vector<unsigned char> c(a.size(), 0);
  size_t la = 0;
  size_t lb = 0;
  size_t lc = 0;
  // When
  ASSERT_EQ(gcm::encrypt_det(span_of(key256), span_of(plaintext), Bytes{nullptr, 0}, a.data(), &la),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_det(span_of(key192), span_of(plaintext), Bytes{nullptr, 0}, b.data(), &lb),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_det(span_of(key128), span_of(plaintext), Bytes{nullptr, 0}, c.data(), &lc),
            Error::ok);
  // Then: no pair joins, which is why the key length is part of the key's identity
  EXPECT_NE(gcm_test::to_hex(a.data(), la), gcm_test::to_hex(b.data(), lb));
  EXPECT_NE(gcm_test::to_hex(b.data(), lb), gcm_test::to_hex(c.data(), lc));
  EXPECT_NE(gcm_test::to_hex(a.data(), la), gcm_test::to_hex(c.data(), lc));
}

// --- The reusable decrypt session (design A11) ----------------------------------------

using SessionPtr = std::unique_ptr<gcm::DecryptSession, decltype(&gcm::decrypt_session_free)>;

SessionPtr new_session() {
  return SessionPtr(gcm::decrypt_session_new(), gcm::decrypt_session_free);
}

/* A sealed value for the session tests, produced by the per-call encrypt path. */
struct Sealed {
  Error err;
  std::vector<unsigned char> envelope;
};

Sealed seal_random(const std::vector<unsigned char> &key,
                   const std::vector<unsigned char> &plaintext,
                   const std::vector<unsigned char> &aad) {
  Sealed s{Error::openssl, std::vector<unsigned char>(gcm::encrypt_out_len(plaintext.size()), 0)};
  size_t len = 0;
  s.err =
      gcm::encrypt_random(span_of(key), span_of(plaintext), span_of(aad), s.envelope.data(), &len);
  s.envelope.resize(len);
  return s;
}

/* Warms a session with one decryption under `key`, so the test's When is the *reused*
   path — the second call, with the key schedule already in the context. */
Error warm(gcm::DecryptSession *session, const std::vector<unsigned char> &key,
           const Sealed &sealed, const std::vector<unsigned char> &aad) {
  std::vector<unsigned char> out(gcm::decrypt_out_len(sealed.envelope.size()) + 1, 0);
  size_t out_len = 0;
  return gcm::decrypt_with_session(session, span_of(key), span_of(sealed.envelope), span_of(aad),
                                   out.data(), &out_len);
}

/* One session shared across every vector of a suite, in file order. Keys, suites and
   AAD change from one vector to the next, so the key switch is exercised hundreds of
   times rather than once, and a bad-tag vector is followed by whatever comes next. */
class SessionVector : public ::testing::TestWithParam<gcm_test::Vector> {
 protected:
  static void SetUpTestSuite() { shared = gcm::decrypt_session_new(); }
  static void TearDownTestSuite() {
    gcm::decrypt_session_free(shared);
    shared = nullptr;
  }
  static gcm::DecryptSession *shared;
};
gcm::DecryptSession *SessionVector::shared = nullptr;

class SessionOpenVector : public SessionVector {};

TEST_P(SessionOpenVector, GivenSharedSession_WhenDecryptWithSession_ThenPlaintextMatches) {
  // Given
  const gcm_test::Vector &v = GetParam();
  ASSERT_NE(shared, nullptr);
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::decrypt_with_session(shared, span_of(v.key), span_of(v.envelope),
                                              span_of(v.aad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok) << v.id;
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(v.plaintext.data(), v.plaintext.size()));
}

INSTANTIATE_TEST_SUITE_P(AllOk, SessionOpenVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok")),
                         param_name<gcm_test::Vector>);

class SessionBadTagVector : public SessionVector {};

TEST_P(SessionBadTagVector, GivenSharedSession_WhenTamperedEnvelope_ThenBadTagAndOutputWiped) {
  // Given
  const gcm_test::Vector &v = GetParam();
  ASSERT_NE(shared, nullptr);
  std::vector<unsigned char> out(gcm::decrypt_out_len(v.envelope.size()) + 1, 0xFF);
  size_t out_len = 0;
  // When
  const Error err = gcm::decrypt_with_session(shared, span_of(v.key), span_of(v.envelope),
                                              span_of(v.aad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::bad_tag) << v.id;
  EXPECT_TRUE(all_zero(out.data(), v.envelope.size() - gcm::kGcmOverhead)) << v.id;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, SessionBadTagVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("bad_tag")),
                         param_name<gcm_test::Vector>);

class SessionBadKeyLenVector : public SessionVector {};

TEST_P(SessionBadKeyLenVector, GivenWrongKeyLength_WhenDecryptWithSession_ThenBadKeyLen) {
  // Given
  const gcm_test::Vector &v = GetParam();
  ASSERT_NE(shared, nullptr);
  std::vector<unsigned char> out(v.envelope.size() + 64, 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::decrypt_with_session(shared, span_of(v.key), span_of(v.envelope),
                                              span_of(v.aad), out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::bad_key_len) << v.id;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, SessionBadKeyLenVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("bad_key_len")),
                         param_name<gcm_test::Vector>);

class SessionBadEnvelopeVector : public SessionVector {};

TEST_P(SessionBadEnvelopeVector, GivenMalformedEnvelope_WhenDecryptWithSession_ThenBadEnvelope) {
  // Given
  const gcm_test::Vector &v = GetParam();
  ASSERT_NE(shared, nullptr);
  std::vector<unsigned char> out(v.envelope.size() + 64, 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::decrypt_with_session(shared, span_of(v.key), span_of(v.envelope),
                                              span_of(v.aad), out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::bad_envelope) << v.id;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, SessionBadEnvelopeVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("bad_envelope")),
                         param_name<gcm_test::Vector>);

const std::vector<unsigned char> kSessionKeyA(gcm::kKeyLen256, 0xA1);
const std::vector<unsigned char> kSessionKeyB(gcm::kKeyLen256, 0xB2);
const std::vector<unsigned char> kSessionKey128(gcm::kKeyLen128, 0xC3);
const std::vector<unsigned char> kSessionAad = {'c', 'o', 'l'};
const std::vector<unsigned char> kSessionTextOne = {'h', 'o', 'n', 'g'};
const std::vector<unsigned char> kSessionTextTwo = {'k', 'i', 'm'};

TEST(DecryptSession,
     GivenSessionWarmedWithKey_WhenSecondEnvelopeUnderSameKey_ThenPlaintextMatches) {
  // Given: the key schedule is already in the context
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  const Sealed first = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  const Sealed second = seal_random(kSessionKeyA, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(first.err, Error::ok);
  ASSERT_EQ(second.err, Error::ok);
  ASSERT_EQ(warm(session.get(), kSessionKeyA, first, kSessionAad), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(second.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When: the reused path — nonce only, no key schedule
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(kSessionKeyA), span_of(second.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(kSessionTextTwo.data(), kSessionTextTwo.size()));
}

TEST(DecryptSession, GivenWarmSession_WhenTagBitFlipped_ThenBadTagAndOutputWiped) {
  // Given
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  const Sealed first = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  Sealed tampered = seal_random(kSessionKeyA, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(first.err, Error::ok);
  ASSERT_EQ(tampered.err, Error::ok);
  tampered.envelope.back() ^= 0x01;
  ASSERT_EQ(warm(session.get(), kSessionKeyA, first, kSessionAad), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(tampered.envelope.size()) + 1, 0xFF);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(kSessionKeyA), span_of(tampered.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then: nothing unauthenticated survives in the buffer
  ASSERT_EQ(err, Error::bad_tag);
  EXPECT_TRUE(all_zero(out.data(), kSessionTextTwo.size()));
}

TEST(DecryptSession, GivenSessionAfterBadTag_WhenValidEnvelopeUnderSameKey_ThenPlaintextMatches) {
  // Given: the previous call on this session failed verification
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  Sealed tampered = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  const Sealed valid = seal_random(kSessionKeyA, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(tampered.err, Error::ok);
  ASSERT_EQ(valid.err, Error::ok);
  tampered.envelope.back() ^= 0x01;
  ASSERT_EQ(warm(session.get(), kSessionKeyA, tampered, kSessionAad), Error::bad_tag);
  std::vector<unsigned char> out(gcm::decrypt_out_len(valid.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(kSessionKeyA), span_of(valid.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then: a failure does not poison the session
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(kSessionTextTwo.data(), kSessionTextTwo.size()));
}

TEST(DecryptSession, GivenSessionWarmedWithKeyA_WhenEnvelopeUnderKeyB_ThenPlaintextMatches) {
  // Given: key A is scheduled; the next row was written under key B
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  const Sealed under_a = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  const Sealed under_b = seal_random(kSessionKeyB, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(under_a.err, Error::ok);
  ASSERT_EQ(under_b.err, Error::ok);
  ASSERT_EQ(warm(session.get(), kSessionKeyA, under_a, kSessionAad), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(under_b.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(kSessionKeyB), span_of(under_b.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then: the session re-scheduled for B rather than reusing A
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(kSessionTextTwo.data(), kSessionTextTwo.size()));
}

TEST(DecryptSession, GivenSessionWarmedWithKeyA_WhenEnvelopeOfAOpenedWithKeyB_ThenBadTag) {
  // Given: a stale schedule for A would make this succeed; the key compare must not
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  const Sealed under_a = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  const Sealed under_a_again = seal_random(kSessionKeyA, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(under_a.err, Error::ok);
  ASSERT_EQ(under_a_again.err, Error::ok);
  ASSERT_EQ(warm(session.get(), kSessionKeyA, under_a, kSessionAad), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(under_a_again.envelope.size()) + 1, 0xFF);
  size_t out_len = 0;
  // When
  const Error err = gcm::decrypt_with_session(session.get(), span_of(kSessionKeyB),
                                              span_of(under_a_again.envelope), span_of(kSessionAad),
                                              out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::bad_tag);
  EXPECT_TRUE(all_zero(out.data(), kSessionTextTwo.size()));
}

TEST(DecryptSession, GivenSessionWarmedWithAes256_WhenEnvelopeUnderAes128_ThenPlaintextMatches) {
  // Given: the suite changes between rows, not only the key bytes
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  const Sealed under_256 = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  const Sealed under_128 = seal_random(kSessionKey128, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(under_256.err, Error::ok);
  ASSERT_EQ(under_128.err, Error::ok);
  ASSERT_EQ(warm(session.get(), kSessionKeyA, under_256, kSessionAad), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(under_128.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(kSessionKey128), span_of(under_128.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(kSessionTextTwo.data(), kSessionTextTwo.size()));
}

TEST(DecryptSession, GivenWarmSession_WhenKeyIsThirtyOneBytes_ThenBadKeyLen) {
  // Given
  SessionPtr session = new_session();
  ASSERT_NE(session, nullptr);
  const Sealed under_a = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  ASSERT_EQ(under_a.err, Error::ok);
  ASSERT_EQ(warm(session.get(), kSessionKeyA, under_a, kSessionAad), Error::ok);
  const std::vector<unsigned char> short_key(31, 0xA1);
  std::vector<unsigned char> out(gcm::decrypt_out_len(under_a.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(short_key), span_of(under_a.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then: rejected before any cipher work, whatever the session holds
  EXPECT_EQ(err, Error::bad_key_len);
}

TEST(DecryptSession, GivenNullSession_WhenDecryptWithSession_ThenOpensslError) {
  // Given
  const Sealed under_a = seal_random(kSessionKeyA, kSessionTextOne, kSessionAad);
  ASSERT_EQ(under_a.err, Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(under_a.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(nullptr, span_of(kSessionKeyA), span_of(under_a.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::openssl);
}

TEST(UnsupportedSuite, GivenA23ByteKey_WhenEncryptRandom_ThenBadKeyLen) {
  // Given: one byte short of AES-192, the boundary a folding implementation would blur
  const std::vector<unsigned char> key(23, 0x44);
  const std::vector<unsigned char> plaintext = {'z'};
  std::vector<unsigned char> sealed(gcm::encrypt_out_len(plaintext.size()), 0);
  size_t sealed_len = 0;
  // When
  const Error err = gcm::encrypt_random(span_of(key), span_of(plaintext), Bytes{nullptr, 0},
                                        sealed.data(), &sealed_len);
  // Then: never rounded to a neighbouring suite
  EXPECT_EQ(err, Error::bad_key_len);
}

}  // namespace

// --- What the decrypt session retains, observed through the test seam ------------------

namespace {

TEST(DecryptSession, GivenWarmSession_WhenValidEnvelopeOpened_ThenKeyIsRetained) {
  // Given
  const std::vector<unsigned char> key(kSessionKeyA.begin(), kSessionKeyA.end());
  const Sealed sealed = seal_random(key, {0x01, 0x02, 0x03}, {});
  ASSERT_EQ(sealed.err, Error::ok);
  SessionPtr session = new_session();
  ASSERT_EQ(warm(session.get(), key, sealed, {}), Error::ok);
  // When
  const Error err = warm(session.get(), key, sealed, {});
  // Then
  EXPECT_EQ(err, Error::ok);
  EXPECT_TRUE(gcm::decrypt_session_has_key(session.get()));
}

TEST(DecryptSession, GivenWarmSession_WhenTagBitFlipped_ThenKeyIsForgotten) {
  // Given
  const std::vector<unsigned char> key(kSessionKeyA.begin(), kSessionKeyA.end());
  const Sealed sealed = seal_random(key, {0x01, 0x02, 0x03}, {});
  ASSERT_EQ(sealed.err, Error::ok);
  Sealed tampered = sealed;
  tampered.envelope.back() ^= 0x01;
  SessionPtr session = new_session();
  ASSERT_EQ(warm(session.get(), key, sealed, {}), Error::ok);
  // When
  const Error err = warm(session.get(), key, tampered, {});
  // Then: a failed Final is never trusted for the next row
  EXPECT_EQ(err, Error::bad_tag);
  EXPECT_FALSE(gcm::decrypt_session_has_key(session.get()));
}

TEST(DecryptSession, GivenWarmSession_WhenKeyLengthIsWrong_ThenKeyIsRetained) {
  // Given
  const std::vector<unsigned char> key(kSessionKeyA.begin(), kSessionKeyA.end());
  const Sealed sealed = seal_random(key, {0x01, 0x02, 0x03}, {});
  ASSERT_EQ(sealed.err, Error::ok);
  const std::vector<unsigned char> short_key(key.begin(), key.begin() + 31);
  SessionPtr session = new_session();
  ASSERT_EQ(warm(session.get(), key, sealed, {}), Error::ok);
  // When
  const Error err = warm(session.get(), short_key, sealed, {});
  // Then: the pre-check rejects the row before the session is consulted, and the
  //       schedule for the valid key stays for the next row
  EXPECT_EQ(err, Error::bad_key_len);
  EXPECT_TRUE(gcm::decrypt_session_has_key(session.get()));
}

TEST(DecryptSession, GivenFreshSession_WhenNothingOpened_ThenNoKeyIsHeld) {
  // Given
  SessionPtr session = new_session();
  // When
  const bool held = gcm::decrypt_session_has_key(session.get());
  // Then
  EXPECT_FALSE(held);
}

}  // namespace

// --- Cache hits where something other than the key changes between rows -----------------

namespace {

TEST(DecryptSession, GivenWarmSessionWithAad_WhenNextRowHasNoAad_ThenPlaintextMatches) {
  // Given: a row with AAD opened through the session, then a row sealed without AAD
  const std::vector<unsigned char> key(kSessionKeyA.begin(), kSessionKeyA.end());
  const Sealed with_aad = seal_random(key, kSessionTextOne, kSessionAad);
  const Sealed without_aad = seal_random(key, kSessionTextTwo, {});
  ASSERT_EQ(with_aad.err, Error::ok);
  ASSERT_EQ(without_aad.err, Error::ok);
  SessionPtr session = new_session();
  ASSERT_EQ(warm(session.get(), key, with_aad, kSessionAad), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(without_aad.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When: the kept context opens the no-AAD row
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(key), span_of(without_aad.envelope),
                                gcm::Bytes{nullptr, 0}, out.data(), &out_len);
  // Then: nothing of the previous row's AAD is carried into this one
  EXPECT_EQ(err, Error::ok);
  EXPECT_EQ(std::vector<unsigned char>(out.begin(), out.begin() + out_len), kSessionTextTwo);
}

TEST(DecryptSession, GivenWarmSessionWithoutAad_WhenNextRowHasAad_ThenPlaintextMatches) {
  // Given
  const std::vector<unsigned char> key(kSessionKeyA.begin(), kSessionKeyA.end());
  const Sealed without_aad = seal_random(key, kSessionTextOne, {});
  const Sealed with_aad = seal_random(key, kSessionTextTwo, kSessionAad);
  ASSERT_EQ(without_aad.err, Error::ok);
  ASSERT_EQ(with_aad.err, Error::ok);
  SessionPtr session = new_session();
  ASSERT_EQ(warm(session.get(), key, without_aad, {}), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(with_aad.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(key), span_of(with_aad.envelope),
                                span_of(kSessionAad), out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::ok);
  EXPECT_EQ(std::vector<unsigned char>(out.begin(), out.begin() + out_len), kSessionTextTwo);
}

TEST(DecryptSession, GivenWarmSessionOnShortRow_WhenNextRowIsLonger_ThenPlaintextMatches) {
  // Given: a 3-byte row, then a 300-byte row under the same key
  const std::vector<unsigned char> key(kSessionKeyA.begin(), kSessionKeyA.end());
  const std::vector<unsigned char> longer(300, 0x5A);
  const Sealed short_row = seal_random(key, kSessionTextTwo, {});
  const Sealed long_row = seal_random(key, longer, {});
  ASSERT_EQ(short_row.err, Error::ok);
  ASSERT_EQ(long_row.err, Error::ok);
  SessionPtr session = new_session();
  ASSERT_EQ(warm(session.get(), key, short_row, {}), Error::ok);
  std::vector<unsigned char> out(gcm::decrypt_out_len(long_row.envelope.size()) + 1, 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::decrypt_with_session(session.get(), span_of(key), span_of(long_row.envelope),
                                gcm::Bytes{nullptr, 0}, out.data(), &out_len);
  // Then: the message length counters of the previous row are gone with its nonce
  EXPECT_EQ(err, Error::ok);
  EXPECT_EQ(std::vector<unsigned char>(out.begin(), out.begin() + out_len), longer);
}

}  // namespace
