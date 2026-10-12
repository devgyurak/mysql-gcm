/* SPDX-License-Identifier: GPL-2.0-only */
/* The *_kr functions (docs/design.md amendment A13), driven through the real UDF entry
 * points against stub services (service_stubs.h).
 *
 * What a real server cannot show is here: how many times the keyring is read, that a
 * failure is latched, the account changing between rows, and the fetched key surviving a
 * bad tag — none of which the file keyring of the integration suite can be made to produce
 * on demand. The key source on its own is in key_source_test.cc; what a real server *can*
 * show (accounts, definer routines, bound parameters, the result charset) is in
 * tests/integration/6*_kr_*.sql.
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <mysql/udf_registration_types.h>

#include "envelope.h"
#include "key_source.h"
#include "service_stubs.h"

extern "C" {
bool gcm_encrypt_kr_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_encrypt_kr_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                         unsigned char *is_null, unsigned char *error);
void gcm_encrypt_kr_deinit(UDF_INIT *initid);
bool gcm_encrypt_det_kr_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_encrypt_det_kr_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                             unsigned char *is_null, unsigned char *error);
void gcm_encrypt_det_kr_deinit(UDF_INIT *initid);
bool gcm_decrypt_kr_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_decrypt_kr_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                         unsigned char *is_null, unsigned char *error);
void gcm_decrypt_kr_deinit(UDF_INIT *initid);
bool gcm_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_decrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                      unsigned char *is_null, unsigned char *error);
void gcm_decrypt_deinit(UDF_INIT *initid);
}

namespace {

using gcm_adapter::details_for;
using gcm_adapter::error_messages;
using gcm_adapter::fail;
using gcm_adapter::FailureRule;

using RowFn = char *(*)(UDF_INIT *, UDF_ARGS *, char *, unsigned long *, unsigned char *,
                        unsigned char *);

const std::string kAccount = "app@%";
const std::string kId = "patient_name_v1";
const std::string kKey32(
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    32);
const std::string kName = "\xed\x99\x8d\xea\xb8\xb8\xeb\x8f\x99";  // 홍길동
const std::string kNoUsableKey = "no usable AES key under this id for the calling account";
const std::string kUnavailable = "the keyring is unavailable or the read failed";
const std::string kInvalidId =
    "the key id must be 1 to 255 bytes without a NUL byte and the same on every row";
const std::string kNoAccount =
    "the calling account could not be established or changed during the statement";

/* A (value, key id) call. A null pointer is SQL NULL, as the server passes it. */
struct Args {
  UDF_ARGS args{};
  Item_result types[2] = {STRING_RESULT, STRING_RESULT};
  char *values[2] = {nullptr, nullptr};
  unsigned long lengths[2] = {0, 0};
  char maybe_null[2] = {0, 0};

  Args(const std::string *value, const std::string *id) {
    args.arg_count = 2;
    args.arg_type = types;
    args.args = values;
    args.lengths = lengths;
    args.maybe_null = maybe_null;
    set(0, value);
    set(1, id);
  }

  void set(unsigned index, const std::string *text) {
    values[index] = text == nullptr ? nullptr : const_cast<char *>(text->data());
    lengths[index] = text == nullptr ? 0 : static_cast<unsigned long>(text->size());
  }
};

/* What one row call gave back, copied out so that a later call cannot overwrite it. */
struct Row {
  bool returned = false;
  std::string text;
  unsigned char is_null = 0;
  unsigned char error = 0;
};

Row call(RowFn fn, UDF_INIT *item, Args *args) {
  Row row;
  unsigned long length = 0;
  const char *out = fn(item, &args->args, nullptr, &length, &row.is_null, &row.error);
  row.returned = out != nullptr;
  row.text = row.returned ? std::string(out, length) : std::string();
  return row;
}

class KrUdf : public ::testing::Test {
 protected:
  void SetUp() override {
    gcm_adapter::install();
    gcm_adapter::reset();
    gcm_adapter::forget_registrations();
    gcm_adapter::clear_key_source();
    gcm_adapter::set_caller("app", "%");
    gcm_adapter::put_keyring_entry(kAccount, kId, "AES", kKey32);
    ASSERT_EQ(gcm_adapter::component_init(), 0);
    gcm_adapter::reset();
  }

  void TearDown() override {
    gcm_adapter::reset();
    gcm_adapter::component_deinit();
    gcm_adapter::reset();
    gcm_adapter::forget_registrations();
    gcm_adapter::clear_key_source();
  }

  /* One deterministic envelope of `plaintext` under kId, through its own item. */
  std::string seal(const std::string &plaintext) {
    Args args(&plaintext, &kId);
    UDF_INIT item{};
    char message[512] = {};
    EXPECT_FALSE(gcm_encrypt_det_kr_init(&item, &args.args, message)) << message;
    const Row row = call(gcm_encrypt_det_kr_udf, &item, &args);
    EXPECT_TRUE(row.returned);
    gcm_encrypt_det_kr_deinit(&item);
    gcm_adapter::reset();
    return row.text;
  }

  char message_[512] = {};
};

TEST_F(KrUdf, GivenAKeyUnderTheCallersAccount_WhenSealedAndOpenedById_ThenRoundTrip) {
  // Given
  const std::string envelope = seal(kName);
  Args args(&envelope, &kId);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_decrypt_kr_udf, &opener, &args);

  // Then
  EXPECT_EQ(row.error, 0);
  EXPECT_EQ(row.text, kName);
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
  gcm_decrypt_kr_deinit(&opener);
}

TEST_F(KrUdf, GivenAKeyInTheKeyring_WhenSealedById_ThenTheKeyArgumentFunctionOpensIt) {
  // Given: the envelope format is the one the key-argument functions use
  const std::string envelope = seal(kName);
  Args args(&envelope, &kKey32);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_init(&opener, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_decrypt_udf, &opener, &args);

  // Then
  EXPECT_EQ(row.error, 0);
  EXPECT_EQ(row.text, kName);
  EXPECT_EQ(static_cast<unsigned char>(envelope[0]), gcm::kVersionDet);
  gcm_decrypt_deinit(&opener);
}

TEST_F(KrUdf, GivenOneItem_WhenThreeRowsAreSealed_ThenTheKeyringIsReadOnce) {
  // Given
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row first = call(gcm_encrypt_kr_udf, &item, &args);
  const Row second = call(gcm_encrypt_kr_udf, &item, &args);
  const Row third = call(gcm_encrypt_kr_udf, &item, &args);

  // Then: one read for the UDF_INIT, under the caller's account, and no reader left open
  EXPECT_TRUE(first.returned);
  EXPECT_TRUE(second.returned);
  EXPECT_TRUE(third.returned);
  EXPECT_EQ(details_for("keyring_init"), std::vector<std::string>{kId});
  EXPECT_EQ(gcm_adapter::extra_for("keyring_init"), kAccount);
  EXPECT_EQ(details_for("keyring_deinit").size(), 1u);
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenInit_WhenNoRowHasRun_ThenTheKeyringIsNotTouched) {
  // Given
  Args args(&kName, &kId);
  UDF_INIT item{};

  // When: init only — where a prepared statement's parameter is not visible yet
  const bool failed = gcm_encrypt_kr_init(&item, &args.args, message_);

  // Then
  EXPECT_FALSE(failed) << message_;
  EXPECT_TRUE(details_for("keyring_init").empty());
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenANullKeyId_WhenARowRuns_ThenNullAndNeitherAccountNorKeyringIsRead) {
  // Given
  Args args(&kName, nullptr);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_FALSE(row.returned);
  EXPECT_EQ(row.is_null, 1);
  EXPECT_EQ(row.error, 0);
  EXPECT_TRUE(details_for("security_context_get").empty());
  EXPECT_TRUE(details_for("keyring_init").empty());
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenANullRowThenAKeyId_WhenTheSecondRowRuns_ThenItReadsTheKeyThen) {
  // Given
  Args null_row(&kName, nullptr);
  Args real_row(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &real_row.args, message_)) << message_;
  const Row first = call(gcm_encrypt_kr_udf, &item, &null_row);

  // When
  const Row second = call(gcm_encrypt_kr_udf, &item, &real_row);

  // Then: "the first row" means the first whose arguments are all non-NULL
  EXPECT_EQ(first.is_null, 1);
  EXPECT_TRUE(second.returned);
  EXPECT_EQ(details_for("keyring_init").size(), 1u);
  gcm_encrypt_kr_deinit(&item);
}

/* The three conditions that share one answer, so that an entry of another type or an odd
   length is not revealed (design A13). */
struct UnusableEntry {
  const char *name;
  const char *account;
  const char *type;
  size_t value_len;
};

class KrUnusableKey : public KrUdf, public ::testing::WithParamInterface<UnusableEntry> {};

TEST_P(KrUnusableKey, GivenAnEntryThatIsNotAUsableKey_WhenUsed_ThenTheOneNoUsableKeyError) {
  // Given
  const std::string id = "candidate";
  gcm_adapter::put_keyring_entry(GetParam().account, id, GetParam().type,
                                 std::string(GetParam().value_len, 'k'));
  Args args(&kName, &id);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then: the same message for every row of the table, and the reader released
  EXPECT_FALSE(row.returned);
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(row.is_null, 0);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kNoUsableKey});
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
  gcm_encrypt_kr_deinit(&item);
}

INSTANTIATE_TEST_SUITE_P(
    KrUdf, KrUnusableKey,
    ::testing::Values(UnusableEntry{"AnotherAccountsKey", "other@%", "AES", 32},
                      UnusableEntry{"ASecret", "app@%", "SECRET", 32},
                      UnusableEntry{"ALowerCaseType", "app@%", "aes", 32},
                      UnusableEntry{"ALongerTypeName", "app@%", "AES2", 32},
                      UnusableEntry{"AnEightByteAesEntry", "app@%", "AES", 8},
                      UnusableEntry{"AThirtyThreeByteAesEntry", "app@%", "AES", 33},
                      UnusableEntry{"AnEmptyAesEntry", "app@%", "AES", 0}),
    [](const ::testing::TestParamInfo<UnusableEntry> &info) { return info.param.name; });

TEST_F(KrUdf, GivenAnEntryOfTheWrongSize_WhenUsed_ThenItsBytesAreNeverFetched) {
  // Given
  const std::string id = "big_secret";
  gcm_adapter::put_keyring_entry(kAccount, id, "SECRET", std::string(4096, 's'));
  Args args(&kName, &id);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  call(gcm_encrypt_kr_udf, &item, &args);

  // Then: decided on the lengths alone — the secret is not copied out of the keyring
  EXPECT_EQ(details_for("keyring_fetch_length").size(), 1u);
  EXPECT_TRUE(details_for("keyring_fetch").empty());
  gcm_encrypt_kr_deinit(&item);
}

/* The keyring service calls that can fail, each of which must read as "unavailable" and
   leave no reader open. */
class KrKeyringFailure : public KrUdf, public ::testing::WithParamInterface<const char *> {};

TEST_P(KrKeyringFailure, GivenAKeyringCallFails_WhenARowRuns_ThenUnavailableAndNoReaderLeftOpen) {
  // Given
  fail(FailureRule{GetParam(), "", 0, true});
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_FALSE(row.returned);
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kUnavailable});
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
  gcm_encrypt_kr_deinit(&item);
}

INSTANTIATE_TEST_SUITE_P(KrUdf, KrKeyringFailure,
                         ::testing::Values("keyring_init", "keyring_fetch_length",
                                           "keyring_fetch"));

/* Every kind of key-source failure, each followed by a row that would succeed on its own.
   `first_id` and `first_user` are what the failing row is called with; the row after it
   uses the good id as the good account. */
struct LatchCase {
  const char *name;
  const char *first_id;
  const char *first_user;
  const char *failing_method;
  const std::string *message;
};

class Latch : public KrUdf, public ::testing::WithParamInterface<LatchCase> {};

TEST_P(Latch, GivenARowFailedOnTheKeySource_WhenAGoodRowFollows_ThenTheSameErrorAndNoKeyringRead) {
  // Given: one row that fails, with the failure injected only for that row
  const std::string first_id = GetParam().first_id;
  gcm_adapter::set_caller(GetParam().first_user, "%");
  fail(FailureRule{GetParam().failing_method, "", 1, true});
  Args first_row(&kName, &first_id);
  Args good_row(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &first_row.args, message_)) << message_;
  ASSERT_EQ(call(gcm_encrypt_kr_udf, &item, &first_row).error, 1);
  const size_t reads_before = details_for("keyring_init").size();

  // When: a row that names a good key as a good account
  gcm_adapter::set_caller("app", "%");
  const Row second = call(gcm_encrypt_kr_udf, &item, &good_row);

  // Then: the failure is latched for the UDF_INIT — same error, and the keyring is left alone
  EXPECT_FALSE(second.returned);
  EXPECT_EQ(second.error, 1);
  EXPECT_EQ(error_messages(), (std::vector<std::string>{*GetParam().message, *GetParam().message}));
  EXPECT_EQ(details_for("keyring_init").size(), reads_before);
  gcm_encrypt_kr_deinit(&item);
}

INSTANTIATE_TEST_SUITE_P(
    KrUdf, Latch,
    ::testing::Values(
        LatchCase{"Unavailable", "patient_name_v1", "app", "keyring_init", &kUnavailable},
        LatchCase{"NoUsableKey", "nothing_stored_here", "app", "nothing_fails", &kNoUsableKey},
        LatchCase{"InvalidId", "", "app", "nothing_fails", &kInvalidId},
        LatchCase{"NoAccount", "patient_name_v1", "", "nothing_fails", &kNoAccount}),
    [](const ::testing::TestParamInfo<LatchCase> &info) { return info.param.name; });

TEST_F(KrUdf, GivenAKeyWasReadThenAFailureLatched_WhenTheFirstIdReturns_ThenStillRefused) {
  // Given: a good row, then a row naming another id
  const std::string other = "another_key";
  Args good_row(&kName, &kId);
  Args other_row(&kName, &other);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &good_row.args, message_)) << message_;
  ASSERT_TRUE(call(gcm_encrypt_kr_udf, &item, &good_row).returned);
  ASSERT_EQ(call(gcm_encrypt_kr_udf, &item, &other_row).error, 1);

  // When: the original id comes back
  const Row third = call(gcm_encrypt_kr_udf, &item, &good_row);

  // Then: the key that was read is not used again in this UDF_INIT
  EXPECT_FALSE(third.returned);
  EXPECT_EQ(third.error, 1);
  EXPECT_EQ(details_for("keyring_init").size(), 1u);
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenFetchDisagreesWithFetchLength_WhenARowRuns_ThenNoUsableKey) {
  // Given: the length call describes a 32 byte AES entry, the fetch returns a SEC entry
  gcm_adapter::override_next_keyring_fetch("SEC", std::string(32, 's'));
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then: what was fetched is judged again, not what was announced
  EXPECT_FALSE(row.returned);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kNoUsableKey});
  EXPECT_EQ(gcm_adapter::open_keyring_readers(), 0);
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenFetchReturnsADifferentLength_WhenARowRuns_ThenNoUsableKey) {
  // Given: announced as 32 bytes, delivered as 20
  gcm_adapter::override_next_keyring_fetch("AES", std::string(20, 'k'));
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_FALSE(row.returned);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kNoUsableKey});
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenAnAes192Key_WhenSealedAndOpenedById_ThenRoundTripAsVersion07) {
  // Given
  const std::string id = "key_192";
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", std::string(24, 'k'));
  gcm_adapter::set_sysvar_value("gcm.min_key_bytes", "24");
  Args seal_args(&kName, &id);
  UDF_INIT sealer{};
  ASSERT_FALSE(gcm_encrypt_det_kr_init(&sealer, &seal_args.args, message_)) << message_;
  const Row sealed = call(gcm_encrypt_det_kr_udf, &sealer, &seal_args);
  gcm_encrypt_det_kr_deinit(&sealer);
  ASSERT_TRUE(sealed.returned);
  Args open_args(&sealed.text, &id);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &open_args.args, message_)) << message_;

  // When
  const Row opened = call(gcm_decrypt_kr_udf, &opener, &open_args);

  // Then: the length of the keyring entry selects the suite, as a key argument's does
  EXPECT_EQ(opened.text, kName);
  EXPECT_EQ(static_cast<unsigned char>(sealed.text[0]), 0x07);
  gcm_decrypt_kr_deinit(&opener);
}

/* Ids the component refuses before it asks the keyring anything. */
class InvalidId : public KrUdf, public ::testing::WithParamInterface<std::string> {};

TEST_P(InvalidId, GivenAnIdThatIsNotAnId_WhenUsed_ThenInvalidIdAndTheKeyringIsNotAsked) {
  // Given
  const std::string id = GetParam();
  Args args(&kName, &id);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kInvalidId});
  EXPECT_TRUE(details_for("keyring_init").empty());
  gcm_encrypt_kr_deinit(&item);
}

INSTANTIATE_TEST_SUITE_P(KrUdf, InvalidId,
                         ::testing::Values(std::string(), std::string(256, 'k'),
                                           std::string("a\0b", 3)));

TEST_F(KrUdf, GivenTheLongestId_WhenUsed_ThenTheKeyringIsAskedForExactlyThatId) {
  // Given
  const std::string id(255, 'k');
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", kKey32);
  Args args(&kName, &id);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_TRUE(row.returned);
  EXPECT_EQ(details_for("keyring_init"), std::vector<std::string>{id});
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenAKeyWasRead_WhenALaterRowNamesAnotherId_ThenRefusedWithoutAReading) {
  // Given
  const std::string other = "another_key";
  gcm_adapter::put_keyring_entry(kAccount, other, "AES", kKey32);
  Args first_row(&kName, &kId);
  Args second_row(&kName, &other);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &first_row.args, message_)) << message_;
  ASSERT_TRUE(call(gcm_encrypt_kr_udf, &item, &first_row).returned);

  // When
  const Row second = call(gcm_encrypt_kr_udf, &item, &second_row);

  // Then: one key id per UDF_INIT, even when the other id names a perfectly good key
  EXPECT_EQ(second.error, 1);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kInvalidId});
  EXPECT_EQ(details_for("keyring_init"), std::vector<std::string>{kId});
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenAKeyWasRead_WhenTheAccountChangesBetweenRows_ThenRefused) {
  // Given
  gcm_adapter::put_keyring_entry("other@%", kId, "AES", kKey32);
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;
  ASSERT_TRUE(call(gcm_encrypt_kr_udf, &item, &args).returned);

  // When: the same item is called as a different account
  gcm_adapter::set_caller("other", "%");
  const Row second = call(gcm_encrypt_kr_udf, &item, &args);

  // Then: the key read for app@% is not used on behalf of other@%
  EXPECT_FALSE(second.returned);
  EXPECT_EQ(second.error, 1);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kNoAccount});
  EXPECT_EQ(details_for("keyring_init").size(), 1u);
  gcm_encrypt_kr_deinit(&item);
}

/* Callers that are not one account. */
struct NoCaller {
  const char *name;
  std::string user;
  std::string host;
  const char *failing_method;
  const char *failing_detail;
};

class KrNoAccount : public KrUdf, public ::testing::WithParamInterface<NoCaller> {};

TEST_P(KrNoAccount, GivenNoUsableCallerAccount_WhenARowRuns_ThenNoAccountAndTheKeyringIsNotAsked) {
  // Given
  gcm_adapter::set_caller(GetParam().user, GetParam().host);
  fail(FailureRule{GetParam().failing_method, GetParam().failing_detail, 0, true});
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(error_messages(), std::vector<std::string>{kNoAccount});
  EXPECT_TRUE(details_for("keyring_init").empty());
  gcm_encrypt_kr_deinit(&item);
}

INSTANTIATE_TEST_SUITE_P(
    KrUdf, KrNoAccount,
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

TEST_F(KrUdf, GivenStrictOffAndOneItem_WhenRowsAreGoodBadGood_ThenPlainNullPlainOnOneRead) {
  // Given: seal() clears the stubs' overrides, so strict goes OFF after it
  const std::string good = seal(kName);
  gcm_adapter::set_sysvar_value("gcm.strict", "OFF");
  std::string bad = good;
  bad.back() = static_cast<char>(bad.back() ^ 0x01);
  Args good_row(&good, &kId);
  Args bad_row(&bad, &kId);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &good_row.args, message_)) << message_;

  // When: three rows through the one item
  const Row first = call(gcm_decrypt_kr_udf, &opener, &good_row);
  const Row second = call(gcm_decrypt_kr_udf, &opener, &bad_row);
  const Row third = call(gcm_decrypt_kr_udf, &opener, &good_row);

  // Then: the fetched key survives the bad tag, so the third row needs no second read
  EXPECT_EQ(first.text, kName);
  EXPECT_FALSE(second.returned);
  EXPECT_EQ(second.is_null, 1);
  EXPECT_EQ(second.error, 0);
  EXPECT_EQ(third.text, kName);
  EXPECT_EQ(third.error, 0);
  EXPECT_EQ(details_for("keyring_init").size(), 1u);
  gcm_decrypt_kr_deinit(&opener);
}

TEST_F(KrUdf, GivenStrictOn_WhenATamperedEnvelopeIsOpened_ThenATagErrorNotNull) {
  // Given
  std::string bad = seal(kName);
  bad.back() = static_cast<char>(bad.back() ^ 0x01);
  Args args(&bad, &kId);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_decrypt_kr_udf, &opener, &args);

  // Then
  EXPECT_FALSE(row.returned);
  EXPECT_EQ(row.is_null, 0);
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(error_messages(), std::vector<std::string>{"authentication tag verification failed"});
  gcm_decrypt_kr_deinit(&opener);
}

TEST_F(KrUdf, GivenStrictOnAndATagError_WhenAGoodRowFollows_ThenTheKeyIsReadAgain) {
  // Given: one item; its first row is a tampered envelope and raises
  const std::string good = seal(kName);
  std::string bad = good;
  bad.back() = static_cast<char>(bad.back() ^ 0x01);
  Args good_row(&good, &kId);
  Args bad_row(&bad, &kId);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &good_row.args, message_)) << message_;
  ASSERT_EQ(call(gcm_decrypt_kr_udf, &opener, &bad_row).error, 1);

  // When: execution continues past the error to a good row
  const Row second = call(gcm_decrypt_kr_udf, &opener, &good_row);

  // Then: the error row gave the key up, so this row fetched it again — the key does not
  //       wait in memory for a deinit the server may never call after an error
  EXPECT_EQ(second.text, kName);
  EXPECT_EQ(second.error, 0);
  EXPECT_EQ(details_for("keyring_init").size(), 2u);
  gcm_decrypt_kr_deinit(&opener);
}

TEST_F(KrUdf, GivenAnAes128Key_WhenUsedToSealUnderTheDefaultFloor_ThenRefusedByTheFloor) {
  // Given
  const std::string id = "short_key";
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", std::string(16, 'k'));
  Args args(&kName, &id);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then: the message names the floor, a public setting, and not the length of the entry
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(error_messages(),
            std::vector<std::string>{"the key is below gcm.min_key_bytes = 32; decryption of "
                                     "existing data is unaffected"});
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(KrUdf, GivenAnAes128KeyAndAnAes256Envelope_WhenOpened_ThenNoLengthInTheMessage) {
  // Given
  const std::string envelope = seal(kName);
  const std::string id = "short_key";
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", std::string(16, 'k'));
  Args args(&envelope, &id);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_decrypt_kr_udf, &opener, &args);

  // Then
  EXPECT_EQ(row.error, 1);
  EXPECT_EQ(error_messages(),
            std::vector<std::string>{"the key's length does not match the envelope version"});
  gcm_decrypt_kr_deinit(&opener);
}

TEST_F(KrUdf, GivenTheLongestAccountThatFits_WhenARowRuns_ThenTheKeyringIsAskedUnderIt) {
  // Given: user@host of exactly kMaxAccountLen bytes
  const std::string user(gcm::kMaxAccountLen - 2, 'u');
  const std::string account = user + "@h";
  gcm_adapter::set_caller(user, "h");
  gcm_adapter::put_keyring_entry(account, kId, "AES", kKey32);
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;

  // When
  const Row row = call(gcm_encrypt_kr_udf, &item, &args);

  // Then
  EXPECT_TRUE(row.returned);
  EXPECT_EQ(gcm_adapter::extra_for("keyring_init"), account);
  gcm_encrypt_kr_deinit(&item);
}

/* Only the release is observable here. That the fetched key is wiped before it is freed
   (free_state in src/udf_glue.cc) is confirmed by reading, not by this case: seeing it
   would need a seam in src/, which the architecture rule does not allow for a test. */
TEST_F(KrUdf, GivenAnItemThatReadAKey_WhenDeinit_ThenItsStateIsReleased) {
  // Given
  Args args(&kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;
  ASSERT_TRUE(call(gcm_encrypt_kr_udf, &item, &args).returned);

  // When
  gcm_encrypt_kr_deinit(&item);

  // Then
  EXPECT_EQ(item.ptr, nullptr);
}

}  // namespace
