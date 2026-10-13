/* SPDX-License-Identifier: GPL-2.0-only */
/* Usage counting for the key-id functions and gcm_key_usage (docs/design.md amendment
 * A14), driven through the real UDF entry points against stub services.
 *
 * The table itself is tests/unit/usage_test.cc. What is pinned here is the wiring: what a
 * call adds, *when* it becomes visible — once, when the instance ends, in deinit or in the
 * row that raises — and that the answer is for the calling account only.
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <mysql/udf_registration_types.h>

#include "service_stubs.h"
#include "udf_glue.h"

extern "C" {
bool gcm_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_encrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                      unsigned char *is_null, unsigned char *error);
void gcm_encrypt_deinit(UDF_INIT *initid);
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
bool gcm_key_usage_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *gcm_key_usage_udf(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                        unsigned char *is_null, unsigned char *error);
void gcm_key_usage_deinit(UDF_INIT *initid);
}

namespace {

using RowFn = char *(*)(UDF_INIT *, UDF_ARGS *, char *, unsigned long *, unsigned char *,
                        unsigned char *);

const std::string kAccount = "app@%";
const std::string kId = "patient_name_v1";
const std::string kKey32(32, 'k');
const std::string kName = "\xed\x99\x8d\xea\xb8\xb8\xeb\x8f\x99";  // 홍길동, 9 bytes

/* A call of one or two string arguments. A null pointer is SQL NULL. */
struct Args {
  UDF_ARGS args{};
  Item_result types[2] = {STRING_RESULT, STRING_RESULT};
  char *values[2] = {nullptr, nullptr};
  unsigned long lengths[2] = {0, 0};
  char maybe_null[2] = {0, 0};

  Args(unsigned count, const std::string *first, const std::string *second) {
    args.arg_count = count;
    args.arg_type = types;
    args.args = values;
    args.lengths = lengths;
    args.maybe_null = maybe_null;
    set(0, first);
    set(1, second);
  }

  void set(unsigned index, const std::string *text) {
    values[index] = text == nullptr ? nullptr : const_cast<char *>(text->data());
    lengths[index] = text == nullptr ? 0 : static_cast<unsigned long>(text->size());
  }
};

/* The counts part of an answer, as the function writes it. `since` is the wall clock at
   init and `complete` is the table's business, so cases compare what precedes them. */
std::string counts(unsigned long long random, unsigned long long det, unsigned long long bytes,
                   unsigned long long tag_failures) {
  return "{\"random_seals\":" + std::to_string(random) + ",\"det_seals\":" + std::to_string(det) +
         ",\"bytes_sealed\":" + std::to_string(bytes) +
         ",\"tag_failures\":" + std::to_string(tag_failures) + ",\"since\":";
}

class Usage : public ::testing::Test {
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

  /* gcm_key_usage(id) as the current caller: the answer text, or "" for NULL or an error. */
  std::string usage_of(const std::string &id) {
    Args args(1, &id, nullptr);
    UDF_INIT item{};
    char message[512] = {};
    char buffer[256] = {};
    unsigned long length = 0;
    unsigned char is_null = 0;
    unsigned char error = 0;
    EXPECT_FALSE(gcm_key_usage_init(&item, &args.args, message)) << message;
    const char *out = gcm_key_usage_udf(&item, &args.args, buffer, &length, &is_null, &error);
    const std::string answer = out == nullptr ? std::string() : std::string(out, length);
    gcm_key_usage_deinit(&item);
    return answer;
  }

  /* One row of `fn` over (value, id) through `item`; the envelope or plaintext it returned. */
  std::string row(RowFn fn, UDF_INIT *item, const std::string &value, const std::string &id) {
    Args args(2, &value, &id);
    unsigned long length = 0;
    unsigned char is_null = 0;
    unsigned char error = 0;
    const char *out = fn(item, &args.args, nullptr, &length, &is_null, &error);
    last_error_ = error;
    return out == nullptr ? std::string() : std::string(out, length);
  }

  /* A whole instance of gcm_encrypt_kr sealing `value` once under `id`: init, row, deinit. */
  std::string seal_once(const std::string &value, const std::string &id) {
    Args args(2, &value, &id);
    UDF_INIT item{};
    EXPECT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;
    const std::string envelope = row(gcm_encrypt_kr_udf, &item, value, id);
    gcm_encrypt_kr_deinit(&item);
    return envelope;
  }

  char message_[512] = {};
  unsigned char last_error_ = 0;
};

TEST_F(Usage, GivenNothingSealed_WhenUsageIsRead_ThenZerosAndValidShape) {
  // Given: a key that exists and has not been used

  // When
  const std::string answer = usage_of(kId);

  // Then: the whole shape, once — the other cases compare the counts part only
  EXPECT_EQ(answer.rfind(counts(0, 0, 0, 0), 0), 0u) << answer;
  EXPECT_NE(answer.find(",\"complete\":true}"), std::string::npos) << answer;
}

TEST_F(Usage, GivenAnInstanceHasSealedTwoRows_WhenItHasNotEnded_ThenNothingIsVisibleYet) {
  // Given: two rows through one instance, which is still open
  Args args(2, &kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;
  row(gcm_encrypt_kr_udf, &item, kName, kId);
  row(gcm_encrypt_kr_udf, &item, kName, kId);

  // When
  const std::string answer = usage_of(kId);

  // Then: counts are folded when the instance ends, not per row
  EXPECT_EQ(answer.rfind(counts(0, 0, 0, 0), 0), 0u) << answer;
  gcm_encrypt_kr_deinit(&item);
}

TEST_F(Usage, GivenAnInstanceSealedTwoRows_WhenItEnds_ThenTwoSealsAndTheirPlaintextBytes) {
  // Given
  Args args(2, &kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;
  row(gcm_encrypt_kr_udf, &item, kName, kId);
  row(gcm_encrypt_kr_udf, &item, kName, kId);

  // When
  gcm_encrypt_kr_deinit(&item);

  // Then: 2 seals of 9 plaintext bytes each
  const std::string answer = usage_of(kId);
  EXPECT_EQ(answer.rfind(counts(2, 0, 18, 0), 0), 0u) << answer;
}

TEST_F(Usage, GivenADeterministicSeal_WhenItsInstanceEnds_ThenItIsCountedAsDeterministic) {
  // Given
  Args args(2, &kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_det_kr_init(&item, &args.args, message_)) << message_;
  row(gcm_encrypt_det_kr_udf, &item, kName, kId);

  // When
  gcm_encrypt_det_kr_deinit(&item);

  // Then
  const std::string answer = usage_of(kId);
  EXPECT_EQ(answer.rfind(counts(0, 1, 9, 0), 0), 0u) << answer;
}

TEST_F(Usage, GivenStrictOffAndATamperedRow_WhenTheInstanceEnds_ThenOneTagFailureAndNoSeal) {
  // Given
  std::string bad = seal_once(kName, kId);
  bad.back() = static_cast<char>(bad.back() ^ 0x01);
  gcm_adapter::set_sysvar_value("gcm.strict", "OFF");
  Args args(2, &bad, &kId);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &args.args, message_)) << message_;
  row(gcm_decrypt_kr_udf, &opener, bad, kId);

  // When
  gcm_decrypt_kr_deinit(&opener);

  // Then: the seal that made the envelope, and the failure to open it — NULL or not
  const std::string answer = usage_of(kId);
  EXPECT_EQ(answer.rfind(counts(1, 0, 9, 1), 0), 0u) << answer;
}

TEST_F(Usage, GivenStrictOnAndATamperedRow_WhenTheRowRaises_ThenTheFailureIsVisibleBeforeDeinit) {
  // Given
  std::string bad = seal_once(kName, kId);
  bad.back() = static_cast<char>(bad.back() ^ 0x01);
  Args args(2, &bad, &kId);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &args.args, message_)) << message_;

  // When: the row raises, and deinit has not been called
  row(gcm_decrypt_kr_udf, &opener, bad, kId);

  // Then: folded in the error row — the server does not always call deinit after one
  const std::string answer = usage_of(kId);
  EXPECT_EQ(last_error_, 1);
  EXPECT_EQ(answer.rfind(counts(1, 0, 9, 1), 0), 0u) << answer;
  gcm_decrypt_kr_deinit(&opener);
}

/* Decryption errors that are not a tag mismatch. Only bad_tag counts: a malformed envelope
   or a key of the wrong suite is corrupt data or misconfiguration, not a forgery attempt. */
struct NotATagFailure {
  const char *name;
  std::string envelope;
  size_t key_len;
};

class UsageNotATagFailure : public Usage, public ::testing::WithParamInterface<NotATagFailure> {};

TEST_P(UsageNotATagFailure, GivenADecryptionErrorThatIsNotATagMismatch_WhenRead_ThenNoTagFailure) {
  // Given: a key of the parameter's length under its own id, and the parameter's envelope
  const std::string id = "decrypt_key";
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", std::string(GetParam().key_len, 'k'));
  Args args(2, &GetParam().envelope, &id);
  UDF_INIT opener{};
  ASSERT_FALSE(gcm_decrypt_kr_init(&opener, &args.args, message_)) << message_;

  // When
  row(gcm_decrypt_kr_udf, &opener, GetParam().envelope, id);
  gcm_decrypt_kr_deinit(&opener);

  // Then: an error, and nothing counted
  const std::string answer = usage_of(id);
  EXPECT_EQ(last_error_, 1);
  EXPECT_EQ(answer.rfind(counts(0, 0, 0, 0), 0), 0u) << answer;
}

INSTANTIATE_TEST_SUITE_P(
    Usage, UsageNotATagFailure,
    ::testing::Values(
        /* bad_envelope: a version byte and nothing else */
        NotATagFailure{"ATruncatedEnvelope", std::string("\x02", 1), 32},
        /* bad_key_len: a well-formed AES-256 envelope opened with an AES-128 key */
        NotATagFailure{"AKeyOfAnotherSuite", std::string("\x02", 1) + std::string(28, 'x'), 16}),
    [](const ::testing::TestParamInfo<NotATagFailure> &info) { return info.param.name; });

TEST_F(Usage, GivenAKeyBelowTheFloor_WhenSealingIsRefused_ThenNothingIsCountedUnderIt) {
  // Given: an AES-128 key and the default floor of 32
  const std::string id = "short_key";
  gcm_adapter::put_keyring_entry(kAccount, id, "AES", std::string(16, 'k'));

  // When: the key is read, and then refused by the floor
  seal_once(kName, id);

  // Then: a refusal is not a seal and makes no row
  const std::string answer = usage_of(id);
  EXPECT_EQ(last_error_, 1);
  EXPECT_EQ(answer.rfind(counts(0, 0, 0, 0), 0), 0u) << answer;
}

TEST_F(Usage, GivenTheComponentHasStoppedCounting_WhenUsageIsRead_ThenAnErrorNotZeros) {
  // Given: the table has been released, as after a completed unload
  ASSERT_EQ(gcm_adapter::component_deinit(), 0);
  gcm_adapter::reset();

  // When
  const std::string answer = usage_of(kId);

  // Then: zeros would claim nothing was counted
  EXPECT_TRUE(answer.empty());
  EXPECT_EQ(gcm_adapter::error_messages(),
            std::vector<std::string>{"usage counting is not available"});
}

TEST_F(Usage, GivenARowRaisedAndFolded_WhenDeinitFollows_ThenNothingIsCountedTwice) {
  // Given: two good rows, then one that raises (another key id), all in one instance
  const std::string other = "another_key";
  Args args(2, &kName, &kId);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_kr_init(&item, &args.args, message_)) << message_;
  row(gcm_encrypt_kr_udf, &item, kName, kId);
  row(gcm_encrypt_kr_udf, &item, kName, kId);
  row(gcm_encrypt_kr_udf, &item, kName, other);

  // When
  gcm_encrypt_kr_deinit(&item);

  // Then: the two seals once, under the name the key was read under
  const std::string answer = usage_of(kId);
  EXPECT_EQ(answer.rfind(counts(2, 0, 18, 0), 0), 0u) << answer;
  EXPECT_EQ(usage_of(other).rfind(counts(0, 0, 0, 0), 0), 0u);
}

TEST_F(Usage, GivenAnotherAccountSealedUnderTheSameId_WhenWeRead_ThenWeSeeOnlyOurOwn) {
  // Given: other@% has a key under the same id and seals with it
  gcm_adapter::put_keyring_entry("other@%", kId, "AES", kKey32);
  gcm_adapter::set_caller("other", "%");
  seal_once(kName, kId);
  seal_once(kName, kId);

  // When: app@% seals once and reads
  gcm_adapter::set_caller("app", "%");
  seal_once(kName, kId);
  const std::string ours = usage_of(kId);

  // Then: the name is (account, key id)
  EXPECT_EQ(ours.rfind(counts(1, 0, 9, 0), 0), 0u) << ours;
}

TEST_F(Usage, GivenTheSameKeyBytesPassedAsAnArgument_WhenSealed_ThenNothingIsCounted) {
  // Given: the key-argument function, with the very bytes the keyring holds under kId
  Args args(2, &kName, &kKey32);
  UDF_INIT item{};
  ASSERT_FALSE(gcm_encrypt_init(&item, &args.args, message_)) << message_;
  row(gcm_encrypt_udf, &item, kName, kKey32);

  // When
  gcm_encrypt_deinit(&item);

  // Then: the key-argument functions have no name to count under (design A14)
  const std::string answer = usage_of(kId);
  EXPECT_EQ(answer.rfind(counts(0, 0, 0, 0), 0), 0u) << answer;
}

TEST_F(Usage, GivenAKeyIdWithNoKey_WhenSealingFailsAndUsageIsRead_ThenZeros) {
  // Given: a key-source failure, which counts nothing and makes no row
  const std::string absent = "nothing_stored_here";
  seal_once(kName, absent);

  // When
  const std::string answer = usage_of(absent);

  // Then
  EXPECT_EQ(answer.rfind(counts(0, 0, 0, 0), 0), 0u) << answer;
}

TEST_F(Usage, GivenUsageWasCounted_WhenUsageIsRead_ThenTheKeyringIsNotTouched) {
  // Given
  seal_once(kName, kId);
  gcm_adapter::reset();

  // When
  usage_of(kId);

  // Then: gcm_key_usage reads the component's table and nothing else
  EXPECT_TRUE(gcm_adapter::details_for("keyring_init").empty());
}

TEST_F(Usage, GivenANullKeyId_WhenUsageIsRead_ThenNullWithoutAnError) {
  // Given
  Args args(1, nullptr, nullptr);
  UDF_INIT item{};
  char buffer[256] = {};
  unsigned long length = 0;
  unsigned char is_null = 0;
  unsigned char error = 0;
  ASSERT_FALSE(gcm_key_usage_init(&item, &args.args, message_)) << message_;

  // When
  const char *out = gcm_key_usage_udf(&item, &args.args, buffer, &length, &is_null, &error);

  // Then
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(is_null, 1);
  EXPECT_EQ(error, 0);
}

/* Ids gcm_key_usage refuses, as the key-id functions do. */
class UsageInvalidId : public Usage, public ::testing::WithParamInterface<std::string> {};

TEST_P(UsageInvalidId, GivenAnIdThatIsNotAnId_WhenUsageIsRead_ThenAnErrorNamingNoId) {
  // Given
  const std::string id = GetParam();

  // When
  const std::string answer = usage_of(id);

  // Then
  EXPECT_TRUE(answer.empty());
  EXPECT_EQ(gcm_adapter::error_messages(),
            std::vector<std::string>{"the key id must be 1 to 255 bytes without a NUL byte"});
}

INSTANTIATE_TEST_SUITE_P(Usage, UsageInvalidId,
                         ::testing::Values(std::string(), std::string(256, 'k'),
                                           std::string("a\0b", 3)));

TEST_F(Usage, GivenAnAnonymousCaller_WhenUsageIsRead_ThenAnErrorAndNoAnswer) {
  // Given
  gcm_adapter::set_caller("", "%");

  // When
  const std::string answer = usage_of(kId);

  // Then
  EXPECT_TRUE(answer.empty());
  EXPECT_EQ(gcm_adapter::error_messages(),
            std::vector<std::string>{"the calling account could not be established"});
}

TEST_F(Usage, GivenTwoArguments_WhenInit_ThenRefusedWithTheUsage) {
  // Given
  Args args(2, &kId, &kId);
  UDF_INIT item{};

  // When
  const bool failed = gcm_key_usage_init(&item, &args.args, message_);

  // Then
  EXPECT_TRUE(failed);
  EXPECT_STREQ(message_, "gcm_key_usage(key_id) needs 1 argument");
}

}  // namespace
