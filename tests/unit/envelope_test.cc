/* SPDX-License-Identifier: GPL-2.0-only */
/* Envelope parsing: the densest edge-case surface in the project, and the only
   file that can be tested with no cryptography at all. */

#include "envelope.h"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "vectors.h"

namespace {

using gcm::Bytes;
using gcm::Error;
using gcm::ParsedEnvelope;

Bytes span_of(const std::vector<unsigned char> &v) { return Bytes{v.data(), v.size()}; }

std::vector<unsigned char> gcm_envelope(unsigned char version, size_t body_len) {
  std::vector<unsigned char> env(gcm::envelope_len(body_len), 0xAB);
  env[0] = version;
  return env;
}

TEST(EnvelopeParse, GivenEmptyInput_WhenParse_ThenBadEnvelope) {
  // Given
  const Bytes empty{nullptr, 0};
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(empty, &parsed);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

TEST(EnvelopeParse, GivenV2Envelope_WhenParse_ThenOffsetsMatchSpec) {
  // Given: 0x02 || nonce(12) || ct(5) || tag(16)
  const std::vector<unsigned char> env = gcm_envelope(gcm::kVersionRandom, 5);
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(parsed.version, gcm::kVersionRandom);
  EXPECT_EQ(parsed.nonce.data, env.data() + 1);
  EXPECT_EQ(parsed.nonce.size, gcm::kNonceLen);
  EXPECT_EQ(parsed.body.data, env.data() + 13);
  EXPECT_EQ(parsed.body.size, 5u);
  EXPECT_EQ(parsed.tag.data, env.data() + 18);
  EXPECT_EQ(parsed.tag.size, gcm::kTagLen);
}

TEST(EnvelopeParse, GivenV3EnvelopeWithEmptyBody_WhenParse_ThenBodyIsEmptyAndTagPresent) {
  // Given: the 29-byte minimum
  const std::vector<unsigned char> env = gcm_envelope(gcm::kVersionDet, 0);
  ASSERT_EQ(env.size(), gcm::kMinGcmLen);
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(parsed.version, gcm::kVersionDet);
  EXPECT_EQ(parsed.body.size, 0u);
  EXPECT_EQ(parsed.tag.size, gcm::kTagLen);
}

/* A v3-looking envelope of `size` bytes, filled with junk. Built here rather than
   in the test body, which must not branch on its own input (testing rule). */
std::vector<unsigned char> truncated_envelope(size_t size) {
  std::vector<unsigned char> env(size, 0xAB);
  if (!env.empty()) env[0] = gcm::kVersionDet;
  return env;
}

class TruncatedGcm : public ::testing::TestWithParam<size_t> {};

TEST_P(TruncatedGcm, GivenTruncatedEnvelope_WhenParse_ThenBadEnvelopeAndNoUnderflow) {
  // Given: fewer than 29 bytes, which would underflow a naive size - 29
  const std::vector<unsigned char> env = truncated_envelope(GetParam());
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

INSTANTIATE_TEST_SUITE_P(Boundaries, TruncatedGcm, ::testing::Values(0u, 1u, 12u, 13u, 17u, 28u),
                         [](const ::testing::TestParamInfo<size_t> &info) {
                           return "len" + std::to_string(info.param);
                         });

class UnknownVersion : public ::testing::TestWithParam<int> {};

TEST_P(UnknownVersion, GivenReservedVersionByte_WhenParse_ThenBadEnvelope) {
  // Given: a well-sized envelope carrying a version we never assigned
  std::vector<unsigned char> env = gcm_envelope(gcm::kVersionDet, 4);
  env[0] = static_cast<unsigned char>(GetParam());
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

/* 0x04-0x07 all left this list as their suites landed (design A10). 0x08 leads
   now: it is the first unassigned byte, and the one most likely to rot into a
   silent accept if the suite table ever grows by accident. */
INSTANTIATE_TEST_SUITE_P(Reserved, UnknownVersion,
                         ::testing::Values(0x00, 0x08, 0x09, 0x7F, 0x80, 0xFF),
                         [](const ::testing::TestParamInfo<int> &info) {
                           char buf[8];
                           std::snprintf(buf, sizeof(buf), "v%02x", info.param);
                           return std::string(buf);
                         });

TEST(EnvelopeParse, GivenLegacyEnvelope_WhenParse_ThenIvIsSixteenBytesAndTagEmpty) {
  // Given: 0x01 || iv(16) || two CBC blocks
  std::vector<unsigned char> env(1 + 16 + 32, 0xCD);
  env[0] = gcm::kVersionLegacyCbc;
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(parsed.nonce.size, gcm::kIvLen);
  EXPECT_EQ(parsed.body.size, 32u);
  EXPECT_EQ(parsed.tag.size, 0u);
  EXPECT_EQ(parsed.tag.data, nullptr);
}

TEST(EnvelopeParse, GivenLegacyBodyNotBlockAligned_WhenParse_ThenBadEnvelope) {
  // Given: 17 bytes of body, not a multiple of the 16-byte block
  std::vector<unsigned char> env(1 + 16 + 17, 0xCD);
  env[0] = gcm::kVersionLegacyCbc;
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

TEST(EnvelopeParse, GivenLegacyShorterThanMinimum_WhenParse_ThenBadEnvelope) {
  // Given: version + iv but no ciphertext block
  std::vector<unsigned char> env(1 + 16, 0xCD);
  env[0] = gcm::kVersionLegacyCbc;
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(env), &parsed);
  // Then
  EXPECT_EQ(err, Error::bad_envelope);
}

/* 01 02 .. 0c, so a wrong offset shows up as a shifted sequence. */
std::array<unsigned char, gcm::kNonceLen> counting_nonce() {
  std::array<unsigned char, gcm::kNonceLen> nonce{};
  for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<unsigned char>(i + 1);
  return nonce;
}

TEST(EnvelopeHeader, GivenVersionAndNonce_WhenWriteGcmHeader_ThenThirteenBytesWritten) {
  // Given
  const std::array<unsigned char, gcm::kNonceLen> nonce = counting_nonce();
  unsigned char out[gcm::kGcmOverhead] = {0};
  // When
  const size_t offset = gcm::write_gcm_header(gcm::kVersionDet, nonce.data(), out);
  // Then
  EXPECT_EQ(offset, gcm::kVersionLen + gcm::kNonceLen);
  EXPECT_EQ(out[0], gcm::kVersionDet);
  EXPECT_EQ(gcm_test::to_hex(out + 1, gcm::kNonceLen),
            gcm_test::to_hex(nonce.data(), gcm::kNonceLen));
}

TEST(EnvelopeConstants, GivenSpecConstants_WhenRead_ThenMatchEnvelopeSpec) {
  // Given / When: the constants other implementations mirror
  // Then: spec/envelope.md §2
  EXPECT_EQ(gcm::kVersionLegacyCbc, 0x01);
  EXPECT_EQ(gcm::kVersionRandom, 0x02);
  EXPECT_EQ(gcm::kVersionDet, 0x03);
  EXPECT_EQ(gcm::kVersionRandom128, 0x04);
  EXPECT_EQ(gcm::kVersionDet128, 0x05);
  EXPECT_EQ(gcm::kVersionRandom192, 0x06);
  EXPECT_EQ(gcm::kVersionDet192, 0x07);
  EXPECT_EQ(gcm::kKeyLen256, 32u);
  EXPECT_EQ(gcm::kKeyLen192, 24u);
  EXPECT_EQ(gcm::kKeyLen128, 16u);
  EXPECT_EQ(gcm::kNonceLen, 12u);
  EXPECT_EQ(gcm::kTagLen, 16u);
  EXPECT_EQ(gcm::kGcmOverhead, 29u);
  EXPECT_EQ(gcm::kMinCbcLen, 33u);
  EXPECT_EQ(gcm::envelope_len(0), 29u);
  EXPECT_EQ(gcm::envelope_len(9), 38u);
}

TEST(EnvelopeError, GivenEachErrorCode_WhenErrorName_ThenStableNameWithoutData) {
  // Given / When / Then: names are for tests and messages, never data-carrying
  EXPECT_STREQ(gcm::error_name(Error::ok), "ok");
  EXPECT_STREQ(gcm::error_name(Error::bad_envelope), "bad_envelope");
  EXPECT_STREQ(gcm::error_name(Error::bad_tag), "bad_tag");
  EXPECT_STREQ(gcm::error_name(Error::bad_key_len), "bad_key_len");
  EXPECT_STREQ(gcm::error_name(Error::rng), "rng");
  EXPECT_STREQ(gcm::error_name(Error::openssl), "openssl");
}

/* The bad_envelope vectors that parse() itself must reject. The "with-aad" cases
   are excluded because their envelope is structurally valid: decrypt() rejects them
   once it sees a non-empty AAD on a v1 envelope. Filtering happens here, not in a
   test body (testing rule). */
std::vector<gcm_test::Vector> structurally_bad_vectors() {
  std::vector<gcm_test::Vector> out;
  for (const gcm_test::Vector &v : gcm_test::vectors_where("bad_envelope")) {
    if (v.id.find("with-aad") == std::string::npos) out.push_back(v);
  }
  return out;
}

class StructurallyBadVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(StructurallyBadVector, GivenSpecBadEnvelopeVector_WhenParse_ThenBadEnvelope) {
  // Given
  const gcm_test::Vector &v = GetParam();
  ParsedEnvelope parsed{};
  // When
  const Error err = gcm::parse(span_of(v.envelope), &parsed);
  // Then
  EXPECT_EQ(err, Error::bad_envelope) << v.id;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, StructurallyBadVector,
                         ::testing::ValuesIn(structurally_bad_vectors()),
                         [](const ::testing::TestParamInfo<gcm_test::Vector> &info) {
                           std::string name = info.param.id;
                           for (char &c : name) {
                             if (!std::isalnum(static_cast<unsigned char>(c))) c = '_';
                           }
                           return name;
                         });

// --- the suite table (design A10) --------------------------------------------

TEST(Suite, GivenEachKeyLength_WhenLookedUp_ThenItsOwnVersionBytes) {
  // Given / When
  const gcm::Suite *wide = gcm::suite_for_key_len(gcm::kKeyLen256);
  const gcm::Suite *middle = gcm::suite_for_key_len(gcm::kKeyLen192);
  const gcm::Suite *narrow = gcm::suite_for_key_len(gcm::kKeyLen128);
  // Then
  ASSERT_NE(wide, nullptr);
  ASSERT_NE(middle, nullptr);
  ASSERT_NE(narrow, nullptr);
  EXPECT_EQ(wide->version_random, gcm::kVersionRandom);
  EXPECT_EQ(wide->version_det, gcm::kVersionDet);
  EXPECT_EQ(middle->version_random, gcm::kVersionRandom192);
  EXPECT_EQ(middle->version_det, gcm::kVersionDet192);
  EXPECT_EQ(narrow->version_random, gcm::kVersionRandom128);
  EXPECT_EQ(narrow->version_det, gcm::kVersionDet128);
}

class UnsupportedKeyLen : public ::testing::TestWithParam<size_t> {};

TEST_P(UnsupportedKeyLen, GivenAKeyLengthNoSuiteHas_WhenLookedUp_ThenNullptr) {
  // Given / When
  const gcm::Suite *suite = gcm::suite_for_key_len(GetParam());
  // Then: nullptr is how a wrong key length is detected, so it must never be a
  // default. Every suite length is bracketed from both sides, so a suite that
  // silently widened what it accepts would show up here.
  EXPECT_EQ(suite, nullptr);
}

INSTANTIATE_TEST_SUITE_P(Lengths, UnsupportedKeyLen,
                         ::testing::Values(size_t{0}, size_t{1}, size_t{15}, size_t{17}, size_t{23},
                                           size_t{25}, size_t{31}, size_t{33}, size_t{64}),
                         [](const ::testing::TestParamInfo<size_t> &info) {
                           return "len" + std::to_string(info.param);
                         });

TEST(Suite, GivenAVersionByteNoSuiteOwns_WhenLookedUp_ThenNullptr) {
  // Given / When / Then: 0x01 is legacy CBC and has no GCM suite; 0x08 is the
  // first unassigned byte now that all three suites have landed.
  EXPECT_EQ(gcm::suite_for_version(0x00), nullptr);
  EXPECT_EQ(gcm::suite_for_version(gcm::kVersionLegacyCbc), nullptr);
  EXPECT_EQ(gcm::suite_for_version(0x08), nullptr);
  EXPECT_EQ(gcm::suite_for_version(0x09), nullptr);
  EXPECT_EQ(gcm::suite_for_version(0xFF), nullptr);
}

TEST(Envelope, GivenAnAes128Envelope_WhenParsed_ThenSameLayoutAsAes256) {
  // Given: 0x04 with the same 29-byte overhead
  std::vector<unsigned char> env(gcm::kGcmOverhead + 3, 0x5A);
  env[0] = gcm::kVersionRandom128;
  gcm::ParsedEnvelope parsed{};
  // When
  const gcm::Error err = gcm::parse(gcm::Bytes{env.data(), env.size()}, &parsed);
  // Then
  ASSERT_EQ(err, gcm::Error::ok);
  EXPECT_EQ(parsed.version, gcm::kVersionRandom128);
  EXPECT_EQ(parsed.nonce.size, gcm::kNonceLen);
  EXPECT_EQ(parsed.body.size, 3u);
  EXPECT_EQ(parsed.tag.size, gcm::kTagLen);
}

}  // namespace
