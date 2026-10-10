/* SPDX-License-Identifier: GPL-2.0-only */
/* The cached deterministic path (design A11) must be byte-identical to the one-call
   encrypt_det, which the spec vectors pin. These cases are what makes the benchmark
   number a measurement of the same construction rather than of a different one. */

#include "gcm.h"

#include <cctype>
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

std::string vector_name(const ::testing::TestParamInfo<gcm_test::Vector> &info) {
  return sanitize(info.param.id);
}

/* Filtered once, here: nonce_key_hex is optional in the schema and a test body
   must not branch on its input (testing rule). */
std::vector<gcm_test::Vector> det_vectors_with_nonce_key() {
  std::vector<gcm_test::Vector> out;
  for (const gcm_test::Vector &v : gcm_test::vectors_where("ok", "det")) {
    if (v.has_nonce_key) out.push_back(v);
  }
  return out;
}

/* Seals through the fresh, uncached path. The expected value in the key-change
   cases comes from here rather than from a re-implementation (testing rule). */
std::vector<unsigned char> fresh_envelope(const std::vector<unsigned char> &key,
                                          const std::vector<unsigned char> &plaintext) {
  std::vector<unsigned char> out(gcm::encrypt_out_len(plaintext.size()), 0);
  size_t out_len = 0;
  const Error err =
      gcm::encrypt_det(span_of(key), span_of(plaintext), Bytes{nullptr, 0}, out.data(), &out_len);
  EXPECT_EQ(err, Error::ok);
  out.resize(out_len);
  return out;
}

bool all_zero(const unsigned char *data, size_t size) {
  unsigned char acc = 0;
  for (size_t i = 0; i < size; ++i) acc |= static_cast<const volatile unsigned char *>(data)[i];
  return acc == 0;
}

// --- byte-identical to the spec vectors ---------------------------------------

class DetSessionVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(DetSessionVector, GivenSpecVector_WhenEncryptDetWithSession_ThenEnvelopeMatchesByteForByte) {
  // Given
  const gcm_test::Vector &v = GetParam();
  gcm::DetSession session{};
  std::vector<unsigned char> out(gcm::encrypt_out_len(v.plaintext.size()), 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::encrypt_det_with_session(&session, span_of(v.key), span_of(v.plaintext),
                                                  span_of(v.aad), out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok) << v.id;
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(v.envelope.data(), v.envelope.size()));
  gcm::det_session_clear(&session);
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, DetSessionVector,
                         ::testing::ValuesIn(gcm_test::vectors_where("ok", "det")), vector_name);

class DetSessionNonceKeyVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(DetSessionNonceKeyVector, GivenSpecVector_WhenSealedOnce_ThenCachedNonceKeyIsTheSpecOne) {
  // Given
  const gcm_test::Vector &v = GetParam();
  gcm::DetSession session{};
  std::vector<unsigned char> out(gcm::encrypt_out_len(v.plaintext.size()), 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::encrypt_det_with_session(&session, span_of(v.key), span_of(v.plaintext),
                                                  span_of(v.aad), out.data(), &out_len);
  // Then: what the cache holds is exactly spec/envelope.md §3's nonce_key for this key
  ASSERT_EQ(err, Error::ok) << v.id;
  EXPECT_EQ(session.key_len, v.key.size());
  EXPECT_EQ(gcm_test::to_hex(session.key, session.key_len),
            gcm_test::to_hex(v.key.data(), v.key.size()));
  EXPECT_EQ(gcm_test::to_hex(session.nonce_key, gcm::kHmacLen),
            gcm_test::to_hex(v.nonce_key.data(), v.nonce_key.size()));
  gcm::det_session_clear(&session);
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, DetSessionNonceKeyVector,
                         ::testing::ValuesIn(det_vectors_with_nonce_key()), vector_name);

// --- cache hit and cache replacement ------------------------------------------

TEST(DetSession, GivenSameKeyAndPlaintext_WhenSealedTwiceThroughOneSession_ThenIdentical) {
  // Given
  const gcm_test::Vector &v = gcm_test::vector_by_id("det-korean-hong");
  gcm::DetSession session{};
  std::vector<unsigned char> first(gcm::encrypt_out_len(v.plaintext.size()), 0);
  std::vector<unsigned char> second(first.size(), 0);
  size_t first_len = 0;
  size_t second_len = 0;
  // When
  ASSERT_EQ(gcm::encrypt_det_with_session(&session, span_of(v.key), span_of(v.plaintext),
                                          span_of(v.aad), first.data(), &first_len),
            Error::ok);
  ASSERT_EQ(gcm::encrypt_det_with_session(&session, span_of(v.key), span_of(v.plaintext),
                                          span_of(v.aad), second.data(), &second_len),
            Error::ok);
  // Then: the second call is a cache hit and still produces the spec envelope
  EXPECT_EQ(gcm_test::to_hex(first.data(), first_len), gcm_test::to_hex(second.data(), second_len));
  EXPECT_EQ(gcm_test::to_hex(second.data(), second_len),
            gcm_test::to_hex(v.envelope.data(), v.envelope.size()));
  gcm::det_session_clear(&session);
}

/* The second key differs in content only, in length only, or in both — each is a
   separate way the CRYPTO_memcmp / key_len check must miss. */
struct KeyChange {
  const char *name;
  size_t first_len;
  unsigned char first_fill;
  size_t second_len;
  unsigned char second_fill;
};

class DetSessionKeyChange : public ::testing::TestWithParam<KeyChange> {};

TEST_P(DetSessionKeyChange, GivenKeyChangedBetweenCalls_WhenSealed_ThenMatchesFreshPathForNewKey) {
  // Given: a session warmed on the first key
  const KeyChange &c = GetParam();
  const std::vector<unsigned char> first_key(c.first_len, c.first_fill);
  const std::vector<unsigned char> second_key(c.second_len, c.second_fill);
  const std::vector<unsigned char> plaintext = {'E', 'M', 'R', '-', '0', '0', '1'};
  const std::vector<unsigned char> expected = fresh_envelope(second_key, plaintext);
  gcm::DetSession session{};
  std::vector<unsigned char> warm(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> out(warm.size(), 0);
  size_t warm_len = 0;
  size_t out_len = 0;
  ASSERT_EQ(gcm::encrypt_det_with_session(&session, span_of(first_key), span_of(plaintext),
                                          Bytes{nullptr, 0}, warm.data(), &warm_len),
            Error::ok);
  // When
  const Error err = gcm::encrypt_det_with_session(&session, span_of(second_key), span_of(plaintext),
                                                  Bytes{nullptr, 0}, out.data(), &out_len);
  // Then: the cache was replaced, not reused
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(expected.data(), expected.size()));
  EXPECT_NE(gcm_test::to_hex(out.data(), out_len), gcm_test::to_hex(warm.data(), warm_len));
  EXPECT_EQ(session.key_len, second_key.size());
  EXPECT_EQ(gcm_test::to_hex(session.key, session.key_len),
            gcm_test::to_hex(second_key.data(), second_key.size()));
  gcm::det_session_clear(&session);
}

INSTANTIATE_TEST_SUITE_P(
    Changes, DetSessionKeyChange,
    ::testing::Values(KeyChange{"content256", gcm::kKeyLen256, 0x11, gcm::kKeyLen256, 0x22},
                      KeyChange{"length256to128", gcm::kKeyLen256, 0x11, gcm::kKeyLen128, 0x11},
                      KeyChange{"length128to192", gcm::kKeyLen128, 0x11, gcm::kKeyLen192, 0x11}),
    [](const ::testing::TestParamInfo<KeyChange> &info) { return info.param.name; });

TEST(DetSession, GivenKeysDifferingInTheLastByte_WhenSealed_ThenNotACacheHit) {
  // Given: the whole key is compared, not a prefix
  const std::vector<unsigned char> first_key(gcm::kKeyLen256, 0x11);
  std::vector<unsigned char> second_key(gcm::kKeyLen256, 0x11);
  second_key.back() = 0x12;
  const std::vector<unsigned char> plaintext = {'x'};
  const std::vector<unsigned char> expected = fresh_envelope(second_key, plaintext);
  gcm::DetSession session{};
  std::vector<unsigned char> warm(gcm::encrypt_out_len(plaintext.size()), 0);
  std::vector<unsigned char> out(warm.size(), 0);
  size_t warm_len = 0;
  size_t out_len = 0;
  ASSERT_EQ(gcm::encrypt_det_with_session(&session, span_of(first_key), span_of(plaintext),
                                          Bytes{nullptr, 0}, warm.data(), &warm_len),
            Error::ok);
  // When
  const Error err = gcm::encrypt_det_with_session(&session, span_of(second_key), span_of(plaintext),
                                                  Bytes{nullptr, 0}, out.data(), &out_len);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(out.data(), out_len),
            gcm_test::to_hex(expected.data(), expected.size()));
  EXPECT_NE(gcm_test::to_hex(out.data(), out_len), gcm_test::to_hex(warm.data(), warm_len));
  gcm::det_session_clear(&session);
}

// --- failure semantics and cleansing ------------------------------------------

class DetSessionBadKeyLen : public ::testing::TestWithParam<size_t> {};

TEST_P(DetSessionBadKeyLen, GivenKeyOfWrongLength_WhenEncryptDetWithSession_ThenBadKeyLen) {
  // Given: a length no suite has (design A1, A10), and an empty session
  const std::vector<unsigned char> key(GetParam(), 0x11);
  const std::vector<unsigned char> plaintext = {'x'};
  gcm::DetSession session{};
  std::vector<unsigned char> out(gcm::encrypt_out_len(plaintext.size()), 0);
  size_t out_len = 0;
  // When
  const Error err = gcm::encrypt_det_with_session(&session, span_of(key), span_of(plaintext),
                                                  Bytes{nullptr, 0}, out.data(), &out_len);
  // Then: rejected before the cache is touched
  EXPECT_EQ(err, Error::bad_key_len);
  EXPECT_EQ(session.key_len, 0u);
  EXPECT_TRUE(all_zero(session.key, sizeof(session.key)));
  EXPECT_TRUE(all_zero(session.nonce_key, sizeof(session.nonce_key)));
}

INSTANTIATE_TEST_SUITE_P(Lengths, DetSessionBadKeyLen,
                         ::testing::Values(0u, 1u, 15u, 17u, 23u, 25u, 31u, 33u, 64u),
                         [](const ::testing::TestParamInfo<size_t> &info) {
                           return "len" + std::to_string(info.param);
                         });

TEST(DetSession, GivenWarmSessionAndWrongKeyLength_WhenSealed_ThenCacheIsKept) {
  // Given: a wrong length is a per-row SQL error and must not evict a valid cache
  const gcm_test::Vector &v = gcm_test::vector_by_id("det-korean-hong");
  const std::vector<unsigned char> bad_key(31, 0x11);
  gcm::DetSession session{};
  std::vector<unsigned char> out(gcm::encrypt_out_len(v.plaintext.size()), 0);
  size_t out_len = 0;
  ASSERT_EQ(gcm::encrypt_det_with_session(&session, span_of(v.key), span_of(v.plaintext),
                                          span_of(v.aad), out.data(), &out_len),
            Error::ok);
  // When
  const Error err = gcm::encrypt_det_with_session(&session, span_of(bad_key), span_of(v.plaintext),
                                                  span_of(v.aad), out.data(), &out_len);
  // Then
  EXPECT_EQ(err, Error::bad_key_len);
  EXPECT_EQ(session.key_len, v.key.size());
  EXPECT_EQ(gcm_test::to_hex(session.key, session.key_len),
            gcm_test::to_hex(v.key.data(), v.key.size()));
  gcm::det_session_clear(&session);
}

TEST(DetSession, GivenWarmSession_WhenCleared_ThenKeyCopyAndNonceKeyAreZero) {
  // Given
  const gcm_test::Vector &v = gcm_test::vector_by_id("det-korean-hong");
  gcm::DetSession session{};
  std::vector<unsigned char> out(gcm::encrypt_out_len(v.plaintext.size()), 0);
  size_t out_len = 0;
  ASSERT_EQ(gcm::encrypt_det_with_session(&session, span_of(v.key), span_of(v.plaintext),
                                          span_of(v.aad), out.data(), &out_len),
            Error::ok);
  ASSERT_FALSE(all_zero(session.nonce_key, sizeof(session.nonce_key)));
  // When
  gcm::det_session_clear(&session);
  // Then
  EXPECT_EQ(session.key_len, 0u);
  EXPECT_TRUE(all_zero(session.key, sizeof(session.key)));
  EXPECT_TRUE(all_zero(session.nonce_key, sizeof(session.nonce_key)));
}

}  // namespace
