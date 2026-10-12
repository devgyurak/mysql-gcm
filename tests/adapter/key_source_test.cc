/* SPDX-License-Identifier: GPL-2.0-only */
/* src/key_source — the calling account and the keyring read behind the *_kr functions
 * (docs/design.md amendment A13) — called directly against stub services
 * (service_stubs.h).
 *
 * This is the layer where each thing the keyring service can report is produced on demand:
 * no keyring, an absent entry, an entry of the wrong type or size, a failing read. A real
 * keyring cannot be made to do most of these, and none of them needs a UDF to observe.
 */

#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "envelope.h"
#include "key_source.h"
#include "service_stubs.h"

namespace {

using gcm::CallerAccount;
using gcm::KeySource;
using gcm_adapter::details_for;
using gcm_adapter::fail;
using gcm_adapter::FailureRule;

const std::string kAccount = "app@%";
const std::string kId = "patient_name_v1";
const std::string kKey32(
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    32);
/* What the output buffer holds before a read, so that "not written" is observable. */
constexpr unsigned char kUntouched = 0xa5;

class KeySourceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    gcm_adapter::install();
    gcm_adapter::reset();
    gcm_adapter::clear_key_source();
    gcm_adapter::set_caller("app", "%");
    gcm_adapter::put_keyring_entry(kAccount, kId, "AES", kKey32);
    std::memset(out_, kUntouched, sizeof(out_));
    ASSERT_EQ(gcm::caller_account(&account_), KeySource::ok);
    gcm_adapter::reset();
  }

  void TearDown() override {
    gcm_adapter::reset();
    gcm_adapter::clear_key_source();
  }

  std::string out() const {
    return std::string(reinterpret_cast<const char *>(out_), sizeof(out_));
  }

  CallerAccount account_{};
  unsigned char out_[gcm::kKeyLen256];
  size_t out_len_ = 99;
};

const std::string kUntouchedBuffer(gcm::kKeyLen256, static_cast<char>(kUntouched));

TEST_F(KeySourceTest, GivenASession_WhenTheCallerIsRead_ThenUserAtHostNulTerminated) {
  // Given: the stubs report priv_user "app" and priv_host "%"
  CallerAccount account{};

  // When
  const KeySource result = gcm::caller_account(&account);

  // Then
  EXPECT_EQ(result, KeySource::ok);
  EXPECT_EQ(std::string(account.text, account.len), kAccount);
  EXPECT_EQ(account.text[account.len], '\0');
}

/* Callers that are not one account. */
struct NoCaller {
  const char *name;
  std::string user;
  std::string host;
  const char *failing_method;
  const char *failing_detail;
};

class NoAccount : public KeySourceTest, public ::testing::WithParamInterface<NoCaller> {};

TEST_P(NoAccount, GivenNoUsableCallerAccount_WhenTheCallerIsRead_ThenNoAccountAndAnEmptyName) {
  // Given
  gcm_adapter::set_caller(GetParam().user, GetParam().host);
  fail(FailureRule{GetParam().failing_method, GetParam().failing_detail, 0, true});
  CallerAccount account{};

  // When
  const KeySource result = gcm::caller_account(&account);

  // Then
  EXPECT_EQ(result, KeySource::no_account);
  EXPECT_EQ(account.len, 0u);
  EXPECT_EQ(account.text[0], '\0');
}

INSTANTIATE_TEST_SUITE_P(
    KeySource, NoAccount,
    ::testing::Values(
        NoCaller{"AnAnonymousAccount", "", "%", "nothing_fails", ""},
        NoCaller{"NoSession", "app", "%", "current_thread_get", ""},
        NoCaller{"NoSecurityContext", "app", "%", "security_context_get", ""},
        NoCaller{"NoPrivUser", "app", "%", "security_option_get", "priv_user"},
        NoCaller{"NoPrivHost", "app", "%", "security_option_get", "priv_host"},
        /* The buffer holds kMaxAccountLen bytes of user@host. These sit on its edges: a user
           that leaves no room for the '@', one byte less with a one-byte host, and a host one
           byte too long for a one-byte user. */
        NoCaller{"AUserNameFillingTheBuffer", std::string(gcm::kMaxAccountLen, 'u'), "",
                 "nothing_fails", ""},
        NoCaller{"AUserNameLeavingNoRoomForTheHost", std::string(gcm::kMaxAccountLen - 1, 'u'), "h",
                 "nothing_fails", ""},
        NoCaller{"AHostOneByteTooLong", "u", std::string(gcm::kMaxAccountLen - 1, 'h'),
                 "nothing_fails", ""},
        NoCaller{"ANulInTheUserName", std::string("ap\0p", 4), "%", "nothing_fails", ""},
        NoCaller{"ANulInTheHost", "app", std::string("%\0x", 3), "nothing_fails", ""}),
    [](const ::testing::TestParamInfo<NoCaller> &info) { return info.param.name; });

TEST_F(KeySourceTest, GivenTheLongestAccountThatFits_WhenTheCallerIsRead_ThenItIsReturnedWhole) {
  // Given: user@host of exactly kMaxAccountLen bytes
  const std::string user(gcm::kMaxAccountLen - 2, 'u');
  gcm_adapter::set_caller(user, "h");
  CallerAccount account{};

  // When
  const KeySource result = gcm::caller_account(&account);

  // Then
  EXPECT_EQ(result, KeySource::ok);
  EXPECT_EQ(std::string(account.text, account.len), user + "@h");
}

/* The key lengths a suite has: the length of the entry selects it (design A10). */
class UsableKey : public KeySourceTest, public ::testing::WithParamInterface<size_t> {};

TEST_P(UsableKey, GivenAnAesEntryOfASuiteLength_WhenFetched_ThenItsBytesUnderTheCallersAccount) {
  // Given
  const std::string id = "candidate";
  const std::string key(GetParam(), 'k');
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", key);

  // When
  const KeySource result = gcm::fetch_key(id.c_str(), account_, out_, &out_len_);

  // Then: the key, asked for under (id, account), through one reader that is released
  EXPECT_EQ(result, KeySource::ok);
  EXPECT_EQ(out_len_, GetParam());
  EXPECT_EQ(out().substr(0, GetParam()), key);
  EXPECT_EQ(details_for("keyring_init"), std::vector<std::string>{id});
  EXPECT_EQ(gcm_adapter::extra_for("keyring_init"), kAccount);
  EXPECT_EQ(details_for("keyring_deinit").size(), 1u);
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
}

INSTANTIATE_TEST_SUITE_P(KeySource, UsableKey,
                         ::testing::Values(gcm::kKeyLen128, gcm::kKeyLen192, gcm::kKeyLen256));

/* The conditions that share one answer, so that an entry of another type or an odd length
   is not revealed (design A13). */
struct UnusableEntry {
  const char *name;
  const char *account;
  const char *type;
  size_t value_len;
};

class UnusableKey : public KeySourceTest, public ::testing::WithParamInterface<UnusableEntry> {};

TEST_P(UnusableKey, GivenAnEntryThatIsNotAUsableKey_WhenFetched_ThenNoUsableKeyAndNothingWritten) {
  // Given
  const std::string id = "candidate";
  gcm_adapter::put_keyring_entry(GetParam().account, id, GetParam().type,
                                 std::string(GetParam().value_len, 'k'));

  // When
  const KeySource result = gcm::fetch_key(id.c_str(), account_, out_, &out_len_);

  // Then: the same answer for every row of the table, nothing handed back, reader released
  EXPECT_EQ(result, KeySource::no_usable_key);
  EXPECT_EQ(out_len_, 0u);
  EXPECT_EQ(out(), kUntouchedBuffer);
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
}

INSTANTIATE_TEST_SUITE_P(
    KeySource, UnusableKey,
    ::testing::Values(UnusableEntry{"AnotherAccountsKey", "other@%", "AES", 32},
                      UnusableEntry{"ASecret", "app@%", "SECRET", 32},
                      UnusableEntry{"ALowerCaseType", "app@%", "aes", 32},
                      UnusableEntry{"ALongerTypeName", "app@%", "AES2", 32},
                      UnusableEntry{"AnEightByteAesEntry", "app@%", "AES", 8},
                      UnusableEntry{"AThirtyThreeByteAesEntry", "app@%", "AES", 33},
                      UnusableEntry{"AnEmptyAesEntry", "app@%", "AES", 0}),
    [](const ::testing::TestParamInfo<UnusableEntry> &info) { return info.param.name; });

TEST_F(KeySourceTest, GivenAnEntryOfTheWrongSize_WhenFetched_ThenItsBytesAreNeverRequested) {
  // Given
  const std::string id = "big_secret";
  gcm_adapter::put_keyring_entry(kAccount, id, "SECRET", std::string(4096, 's'));

  // When
  gcm::fetch_key(id.c_str(), account_, out_, &out_len_);

  // Then: decided on the lengths alone — the secret is not copied out of the keyring
  EXPECT_EQ(details_for("keyring_fetch_length").size(), 1u);
  EXPECT_TRUE(details_for("keyring_fetch").empty());
}

/* The keyring service calls that can fail. The stub's failing fetch writes into the
   buffer it was given before it reports failure, the way a real one may. */
class KeyringFailure : public KeySourceTest, public ::testing::WithParamInterface<const char *> {};

TEST_P(KeyringFailure, GivenAKeyringCallFails_WhenFetched_ThenUnavailableAndNothingWritten) {
  // Given
  fail(FailureRule{GetParam(), "", 0, true});

  // When
  const KeySource result = gcm::fetch_key(kId.c_str(), account_, out_, &out_len_);

  // Then: nothing the failing call wrote reaches the caller, and no reader is left open
  EXPECT_EQ(result, KeySource::unavailable);
  EXPECT_EQ(out_len_, 0u);
  EXPECT_EQ(out(), kUntouchedBuffer);
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
}

INSTANTIATE_TEST_SUITE_P(KeySource, KeyringFailure,
                         ::testing::Values("keyring_init", "keyring_fetch_length",
                                           "keyring_fetch"));

/* The second call disagreeing with the first, which the real reader's lock is supposed to
   prevent and the adapter checks for anyway. */
struct Disagreement {
  const char *name;
  const char *type;
  size_t value_len;
};

class FetchDisagrees : public KeySourceTest, public ::testing::WithParamInterface<Disagreement> {};

TEST_P(FetchDisagrees,
       GivenFetchDeliversSomethingElse_WhenFetched_ThenNoUsableKeyAndNothingWritten) {
  // Given: the length call describes the 32 byte AES entry, the fetch delivers this instead
  gcm_adapter::override_next_keyring_fetch(GetParam().type, std::string(GetParam().value_len, 's'));

  // When
  const KeySource result = gcm::fetch_key(kId.c_str(), account_, out_, &out_len_);

  // Then: what was fetched is judged again, not what was announced
  EXPECT_EQ(result, KeySource::no_usable_key);
  EXPECT_EQ(out_len_, 0u);
  EXPECT_EQ(out(), kUntouchedBuffer);
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
}

INSTANTIATE_TEST_SUITE_P(KeySource, FetchDisagrees,
                         ::testing::Values(Disagreement{"AnotherTypeOfTheSameLength", "SEC", 32},
                                           Disagreement{"AShorterValue", "AES", 20}),
                         [](const ::testing::TestParamInfo<Disagreement> &info) {
                           return info.param.name;
                         });

}  // namespace
