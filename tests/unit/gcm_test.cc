/* SPDX-License-Identifier: GPL-2.0-only */
/* AES-256-GCM: NIST known-answer tests, round trips, tampering and the failure
   semantics of spec/envelope.md §4. */

#include "gcm.h"

#include <cctype>
#include <cstring>
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
  EXPECT_EQ(out[0], gcm::kVersionDet);
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
    out.push_back({v, KeyLenEntry::random});
    out.push_back({v, KeyLenEntry::det});
    out.push_back({v, KeyLenEntry::decrypt});
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
  EXPECT_EQ(first[0], gcm::kVersionRandom);
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
  const std::vector<unsigned char> key(gcm::kKeyLen, 0x77);
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
  const std::vector<unsigned char> key(gcm::kKeyLen, 0x41);
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
  const std::vector<unsigned char> key(gcm::kKeyLen, 0x41);
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
  const std::vector<unsigned char> key(gcm::kKeyLen, 0x01);
  std::vector<unsigned char> out(gcm::encrypt_out_len(0), 0);
  size_t out_len = 0;
  // When
  const Error err =
      gcm::encrypt_det(span_of(key), Bytes{nullptr, 0}, Bytes{nullptr, 0}, out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(out_len, gcm::kGcmOverhead);
}

}  // namespace
