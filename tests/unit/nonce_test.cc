/* SPDX-License-Identifier: GPL-2.0-only */
/* Deterministic nonce derivation: the property the join keys depend on, and the
   one place where a collision would be a GCM catastrophe. */

#include "nonce.h"

#include <cstdlib>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "gcm.h"
#include "vectors.h"

namespace {

using gcm::Bytes;
using gcm::Error;

Bytes span_of(const std::vector<unsigned char> &v) { return Bytes{v.data(), v.size()}; }

/* testing.md: 100k samples on every PR, 1M nightly. A floor keeps an empty or
   nonsensical environment value from turning the collision check into a test over
   zero samples, which would pass without proving anything. */
size_t collision_iterations() {
  constexpr size_t kFloor = 1000;
  constexpr size_t kDefault = 100000;
  const char *env = std::getenv("GCM_COLLISION_N");
  if (env == nullptr) return kDefault;
  const size_t requested = static_cast<size_t>(std::strtoul(env, nullptr, 10));
  return requested < kFloor ? kFloor : requested;
}

/* Two fixtures rather than one with a skip inside: nonce_key_hex is optional in
   the vector schema, and a test body must not branch on its own input
   (testing rule). Each list is filtered once, here, outside any test. */
std::vector<gcm_test::Vector> det_vectors_with_nonce_key() {
  std::vector<gcm_test::Vector> out;
  for (const gcm_test::Vector &v : gcm_test::vectors_where("ok", "det")) {
    if (v.has_nonce_key) out.push_back(v);
  }
  return out;
}

std::vector<gcm_test::Vector> det_vectors_with_nonce() {
  std::vector<gcm_test::Vector> out;
  for (const gcm_test::Vector &v : gcm_test::vectors_where("ok", "det")) {
    if (v.has_nonce) out.push_back(v);
  }
  return out;
}

class DetNonceKeyVector : public ::testing::TestWithParam<gcm_test::Vector> {};
class DetNonceVector : public ::testing::TestWithParam<gcm_test::Vector> {};

TEST_P(DetNonceKeyVector, GivenSpecVector_WhenDeriveNonceKey_ThenMatchesVector) {
  // Given
  const gcm_test::Vector &v = GetParam();
  unsigned char nonce_key[gcm::kHmacLen] = {0};
  // When
  const Error err = gcm::derive_nonce_key(span_of(v.key), nonce_key);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(nonce_key, sizeof(nonce_key)),
            gcm_test::to_hex(v.nonce_key.data(), v.nonce_key.size()));
}

TEST_P(DetNonceVector, GivenSpecVector_WhenDeriveDetNonce_ThenMatchesStoredNonce) {
  // Given
  const gcm_test::Vector &v = GetParam();
  ASSERT_TRUE(v.has_nonce);
  unsigned char nonce[gcm::kNonceLen] = {0};
  // When
  const Error err = gcm::derive_det_nonce(span_of(v.key), span_of(v.plaintext), nonce);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_EQ(gcm_test::to_hex(nonce, sizeof(nonce)),
            gcm_test::to_hex(v.nonce.data(), v.nonce.size()));
}

std::string vector_param_name(const ::testing::TestParamInfo<gcm_test::Vector> &info) {
  std::string name = info.param.id;
  for (char &c : name) {
    if (!std::isalnum(static_cast<unsigned char>(c))) c = '_';
  }
  return name;
}

INSTANTIATE_TEST_SUITE_P(SpecVectors, DetNonceKeyVector,
                         ::testing::ValuesIn(det_vectors_with_nonce_key()), vector_param_name);
INSTANTIATE_TEST_SUITE_P(SpecVectors, DetNonceVector, ::testing::ValuesIn(det_vectors_with_nonce()),
                         vector_param_name);

TEST(DetNonce, GivenTheLabel_WhenRead_ThenItIsTheSpecString) {
  // Given / When / Then: the server uses this exact byte string (spec §3)
  EXPECT_EQ(std::string(gcm::kDetNonceLabel, gcm::kDetNonceLabelLen), "mysql-gcm/v1/det-nonce");
  EXPECT_EQ(gcm::kDetNonceLabelLen, 22u);
}

TEST(DetNonce, GivenSameKeyAndPlaintext_WhenDerivedTwice_ThenIdentical) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x2A);
  const std::vector<unsigned char> plaintext = {'h', 'e', 'l', 'l', 'o'};
  unsigned char first[gcm::kNonceLen] = {0};
  unsigned char second[gcm::kNonceLen] = {0};
  // When
  ASSERT_EQ(gcm::derive_det_nonce(span_of(key), span_of(plaintext), first), Error::ok);
  ASSERT_EQ(gcm::derive_det_nonce(span_of(key), span_of(plaintext), second), Error::ok);
  // Then
  EXPECT_EQ(gcm_test::to_hex(first, sizeof(first)), gcm_test::to_hex(second, sizeof(second)));
}

TEST(DetNonce, GivenDifferentPlaintexts_WhenDerived_ThenNoncesDiffer) {
  // Given
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x2A);
  const std::vector<unsigned char> a = {'a'};
  const std::vector<unsigned char> b = {'b'};
  unsigned char na[gcm::kNonceLen] = {0};
  unsigned char nb[gcm::kNonceLen] = {0};
  // When
  ASSERT_EQ(gcm::derive_det_nonce(span_of(key), span_of(a), na), Error::ok);
  ASSERT_EQ(gcm::derive_det_nonce(span_of(key), span_of(b), nb), Error::ok);
  // Then
  EXPECT_NE(gcm_test::to_hex(na, sizeof(na)), gcm_test::to_hex(nb, sizeof(nb)));
}

TEST(DetNonce, GivenDifferentKeys_WhenDerivedForSamePlaintext_ThenNoncesDiffer) {
  // Given
  const std::vector<unsigned char> key_a(gcm::kKeyLen256, 0x01);
  const std::vector<unsigned char> key_b(gcm::kKeyLen256, 0x02);
  const std::vector<unsigned char> plaintext = {'x'};
  unsigned char na[gcm::kNonceLen] = {0};
  unsigned char nb[gcm::kNonceLen] = {0};
  // When
  ASSERT_EQ(gcm::derive_det_nonce(span_of(key_a), span_of(plaintext), na), Error::ok);
  ASSERT_EQ(gcm::derive_det_nonce(span_of(key_b), span_of(plaintext), nb), Error::ok);
  // Then
  EXPECT_NE(gcm_test::to_hex(na, sizeof(na)), gcm_test::to_hex(nb, sizeof(nb)));
}

class BadKeyLen : public ::testing::TestWithParam<size_t> {};

TEST_P(BadKeyLen, GivenKeyOfWrongLength_WhenDeriveNonceKey_ThenBadKeyLen) {
  // Given: a length no suite has; never folded or padded (design A1, A10).
  // 16 is not here any more -- it is a valid AES-128 key -- and 24 is, because
  // AES-192 has version bytes allocated but no implementation.
  const std::vector<unsigned char> key(GetParam(), 0x11);
  unsigned char out[gcm::kHmacLen] = {0};
  // When
  const Error err = gcm::derive_nonce_key(span_of(key), out);
  // Then
  EXPECT_EQ(err, Error::bad_key_len);
}

INSTANTIATE_TEST_SUITE_P(Lengths, BadKeyLen,
                         ::testing::Values(0u, 1u, 15u, 17u, 24u, 31u, 33u, 64u),
                         [](const ::testing::TestParamInfo<size_t> &info) {
                           return "len" + std::to_string(info.param);
                         });

/* Derives a nonce for `n` pseudo-random plaintexts and returns the distinct ones.
   The loop lives here and not in the test body (testing rule); the seed is fixed so
   a failure is reproducible. */
std::set<std::string> distinct_nonces(size_t n) {
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x5C);
  std::mt19937_64 rng(20260928);
  std::set<std::string> seen;
  for (size_t i = 0; i < n; ++i) {
    const uint64_t value = rng();
    const unsigned char *bytes = reinterpret_cast<const unsigned char *>(&value);
    unsigned char nonce[gcm::kNonceLen] = {0};
    if (gcm::derive_det_nonce(span_of(key), Bytes{bytes, sizeof(value)}, nonce) != Error::ok) {
      return {};  // reported by the size assertion below
    }
    seen.insert(gcm_test::to_hex(nonce, sizeof(nonce)));
  }
  return seen;
}

TEST(DetNonce, GivenManyDistinctPlaintexts_WhenDerived_ThenNoNonceCollision) {
  // Given: N pseudo-random plaintexts (GCM_COLLISION_N; 100k in PR CI, 1M nightly)
  const size_t n = collision_iterations();
  // When
  const std::set<std::string> seen = distinct_nonces(n);
  // Then
  EXPECT_EQ(seen.size(), n) << "nonce collision at N=" << n;
}

TEST(Hmac, GivenEmptyMessage_WhenHmacSha256_ThenSucceedsWithFullLength) {
  // Given: empty plaintext is legal and must not hit a null-pointer path
  const std::vector<unsigned char> key(gcm::kKeyLen256, 0x33);
  unsigned char out[gcm::kHmacLen] = {0};
  // When
  const Error err = gcm::hmac_sha256(span_of(key), Bytes{nullptr, 0}, out);
  // Then
  ASSERT_EQ(err, Error::ok);
  EXPECT_NE(gcm_test::to_hex(out, sizeof(out)), std::string(2 * gcm::kHmacLen, '0'));
}

}  // namespace
