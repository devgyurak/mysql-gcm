/* SPDX-License-Identifier: GPL-2.0-only */
/* The table of usage counts (docs/design.md amendment A14): the component's one piece of
   shared, mutable state. It has no server dependency, so everything about it — the bound,
   saturation, and folds from several threads at once — is pinned here. */

#include "usage.h"

#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace {

using gcm::UsageAnswer;
using gcm::UsageCounts;
using gcm::UsageName;

constexpr int64_t kStart = 1760000000;

UsageName name_of(const std::string &account, const std::string &key_id) {
  return UsageName{account.data(), account.size(), key_id.data(), key_id.size()};
}

void fold(const std::string &account, const std::string &key_id, const UsageCounts &delta) {
  gcm::usage_fold(name_of(account, key_id), delta);
}

UsageAnswer read(const std::string &account, const std::string &key_id) {
  UsageAnswer answer{};
  EXPECT_TRUE(gcm::usage_read(name_of(account, key_id), &answer));
  return answer;
}

/* One fold of one random seal under each of `count` distinct key ids of one account. */
void fold_distinct_names(const std::string &account, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    fold(account, "key_" + std::to_string(i), UsageCounts{1, 0, 0, 0});
  }
}

/* Every slot of the table, taken by full shares of distinct accounts. */
void fill_table_with_accounts() {
  for (size_t a = 0; a < gcm::kMaxUsageNames / gcm::kMaxUsageNamesPerAccount; ++a) {
    fold_distinct_names("account_" + std::to_string(a) + "@%", gcm::kMaxUsageNamesPerAccount);
  }
}

/* As fill_table_with_accounts, leaving exactly one account's share of slots free. */
void fill_table_with_accounts_but_one_share() {
  for (size_t a = 0; a + 1 < gcm::kMaxUsageNames / gcm::kMaxUsageNamesPerAccount; ++a) {
    fold_distinct_names("account_" + std::to_string(a) + "@%", gcm::kMaxUsageNamesPerAccount);
  }
}

/* `threads` threads, each folding one random seal `folds` times under a name of its own —
   so rows are being added while others are folded — with one more thread reading throughout.
   Returns the number of reads that reported a count above what any writer could have made. */
size_t fold_distinct_names_from_threads_while_reading(const std::string &account, size_t threads,
                                                      size_t folds) {
  size_t impossible_reads = 0;
  std::thread reader([&account, &impossible_reads, folds] {
    for (size_t i = 0; i < folds; ++i) {
      if (read(account, "thread_0").counts.random_seals > folds) ++impossible_reads;
    }
  });
  std::vector<std::thread> workers;
  for (size_t t = 0; t < threads; ++t) {
    workers.emplace_back([&account, t, folds] {
      for (size_t i = 0; i < folds; ++i) {
        fold(account, "thread_" + std::to_string(t), UsageCounts{1, 0, 0, 0});
      }
    });
  }
  for (std::thread &worker : workers) worker.join();
  reader.join();
  return impossible_reads;
}

/* `threads` threads, each folding one random seal of one byte `folds` times. */
void fold_from_threads(const std::string &account, const std::string &key_id, size_t threads,
                       size_t folds) {
  std::vector<std::thread> workers;
  for (size_t t = 0; t < threads; ++t) {
    workers.emplace_back([&account, &key_id, folds] {
      for (size_t i = 0; i < folds; ++i) fold(account, key_id, UsageCounts{1, 0, 1, 0});
    });
  }
  for (std::thread &worker : workers) worker.join();
}

class Usage : public ::testing::Test {
 protected:
  void SetUp() override {
    gcm::usage_deinit();
    ASSERT_EQ(gcm::usage_init(kStart), 0);
  }
  void TearDown() override { gcm::usage_deinit(); }
};

TEST_F(Usage, GivenNothingCounted_WhenANameIsRead_ThenZerosWithTheStartTime) {
  // Given: a table that has only just been initialised

  // When
  const UsageAnswer answer = read("app@%", "k1");

  // Then
  EXPECT_EQ(answer.counts.random_seals, 0u);
  EXPECT_EQ(answer.counts.det_seals, 0u);
  EXPECT_EQ(answer.counts.bytes_sealed, 0u);
  EXPECT_EQ(answer.counts.tag_failures, 0u);
  EXPECT_EQ(answer.since, kStart);
  EXPECT_TRUE(answer.complete);
}

TEST_F(Usage, GivenTwoFoldsUnderOneName_WhenRead_ThenEachFieldIsTheirSum) {
  // Given
  fold("app@%", "k1", UsageCounts{3, 1, 100, 0});
  fold("app@%", "k1", UsageCounts{2, 4, 50, 7});

  // When
  const UsageAnswer answer = read("app@%", "k1");

  // Then
  EXPECT_EQ(answer.counts.random_seals, 5u);
  EXPECT_EQ(answer.counts.det_seals, 5u);
  EXPECT_EQ(answer.counts.bytes_sealed, 150u);
  EXPECT_EQ(answer.counts.tag_failures, 7u);
}

TEST_F(Usage, GivenTheSameKeyIdUnderTwoAccounts_WhenRead_ThenTheyAreTwoRows) {
  // Given: the name is (account, key id), not the key id
  fold("app@%", "k1", UsageCounts{3, 0, 0, 0});
  fold("batch@%", "k1", UsageCounts{40, 0, 0, 0});

  // When
  const UsageAnswer app = read("app@%", "k1");
  const UsageAnswer batch = read("batch@%", "k1");

  // Then
  EXPECT_EQ(app.counts.random_seals, 3u);
  EXPECT_EQ(batch.counts.random_seals, 40u);
}

TEST_F(Usage, GivenTwoNamesThatConcatenateAlike_WhenRead_ThenTheyAreTwoRows) {
  // Given: "ab" + "c" and "a" + "bc" must not meet in one row
  fold("ab", "c", UsageCounts{1, 0, 0, 0});
  fold("a", "bc", UsageCounts{20, 0, 0, 0});

  // When
  const UsageAnswer first = read("ab", "c");
  const UsageAnswer second = read("a", "bc");

  // Then
  EXPECT_EQ(first.counts.random_seals, 1u);
  EXPECT_EQ(second.counts.random_seals, 20u);
}

TEST_F(Usage, GivenACountNearTheLimit_WhenMoreIsFolded_ThenItSaturatesInsteadOfWrapping) {
  // Given
  fold("app@%", "k1", UsageCounts{UINT64_MAX - 1, 0, UINT64_MAX, 0});

  // When
  fold("app@%", "k1", UsageCounts{5, 0, 5, 0});

  // Then: a count never wraps round to a small number
  const UsageAnswer answer = read("app@%", "k1");
  EXPECT_EQ(answer.counts.random_seals, UINT64_MAX);
  EXPECT_EQ(answer.counts.bytes_sealed, UINT64_MAX);
}

TEST_F(Usage, GivenAFoldOfAllZeros_WhenTheAccountsShareIsThenFilled_ThenThatFoldTookNoRow) {
  // Given: a zero delta under a name of its own, then exactly as many names as one account may have
  fold("app@%", "nothing_counted", UsageCounts{0, 0, 0, 0});
  fold_distinct_names("app@%", gcm::kMaxUsageNamesPerAccount);

  // When
  const UsageAnswer answer = read("app@%", "key_0");

  // Then: every real name fitted, so the zero fold did not use a slot
  EXPECT_TRUE(answer.complete);
  EXPECT_EQ(answer.counts.random_seals, 1u);
}

TEST_F(Usage, GivenAnAccountsShareIsFull_WhenItFoldsANewName_ThenItIsNotCountedAndItIsTold) {
  // Given
  fold_distinct_names("app@%", gcm::kMaxUsageNamesPerAccount);

  // When
  fold("app@%", "one_too_many", UsageCounts{9, 0, 0, 0});

  // Then: the use is in no row, and every answer to this account says so
  const UsageAnswer overflowed = read("app@%", "one_too_many");
  const UsageAnswer existing = read("app@%", "key_0");
  EXPECT_EQ(overflowed.counts.random_seals, 0u);
  EXPECT_FALSE(overflowed.complete);
  EXPECT_FALSE(existing.complete);
}

TEST_F(Usage, GivenOneAccountFilledItsShare_WhenAnotherAccountCountsAndReads_ThenItIsUnaffected) {
  // Given: one account has used up everything it may, and gone over
  fold_distinct_names("greedy@%", gcm::kMaxUsageNamesPerAccount + 10);

  // When: a different account counts under a name of its own
  fold("app@%", "k1", UsageCounts{3, 0, 0, 0});

  // Then: it is counted, and nothing in its answer says another account overflowed
  const UsageAnswer answer = read("app@%", "k1");
  EXPECT_EQ(answer.counts.random_seals, 3u);
  EXPECT_TRUE(answer.complete);
}

TEST_F(Usage, GivenAnAccountsShareIsFull_WhenAnExistingNameIsFolded_ThenItStillCounts) {
  // Given
  fold_distinct_names("app@%", gcm::kMaxUsageNamesPerAccount);

  // When
  fold("app@%", "key_0", UsageCounts{4, 0, 0, 0});

  // Then: names are never evicted, and a full share keeps counting the names it has
  const UsageAnswer answer = read("app@%", "key_0");
  EXPECT_EQ(answer.counts.random_seals, 5u);
  EXPECT_TRUE(answer.complete);
}

TEST_F(Usage, GivenTheWholeTableIsFull_WhenAnAccountWithNoRowFolds_ThenThatAccountIsTold) {
  // Given: as many accounts as it takes, each filling its share
  fill_table_with_accounts();

  // When: an account that has no row yet tries to count
  fold("late@%", "k1", UsageCounts{2, 0, 0, 0});

  // Then: it is told, and an account that has its rows is not
  const UsageAnswer late = read("late@%", "k1");
  const UsageAnswer settled = read("account_0@%", "key_0");
  EXPECT_EQ(late.counts.random_seals, 0u);
  EXPECT_FALSE(late.complete);
  EXPECT_TRUE(settled.complete);
}

TEST_F(Usage,
       GivenTheWholeTableIsFull_WhenAnAccountWithRowsLosesAName_ThenItIsToldAndOthersAreNot) {
  // Given: the table one slot short of full, with app@% holding two names
  fill_table_with_accounts_but_one_share();
  fold_distinct_names("app@%", 2);
  fold_distinct_names("filler@%", gcm::kMaxUsageNamesPerAccount - 2);

  // When: app@% is well inside its own share but the table has no slot left
  fold("app@%", "one_more", UsageCounts{5, 0, 0, 0});

  // Then: app@% is told from its own rows, and an account that lost nothing is not
  const UsageAnswer app = read("app@%", "key_0");
  const UsageAnswer other = read("account_0@%", "key_0");
  EXPECT_FALSE(app.complete);
  EXPECT_TRUE(other.complete);
}

TEST_F(Usage, GivenARowlessAccountLostAUse_WhenAnotherRowlessAccountReads_ThenItIsToldToo) {
  // Given: the documented exception — a full table and an account with no row losing a use
  fill_table_with_accounts();
  fold("late@%", "k1", UsageCounts{2, 0, 0, 0});

  // When: an account that has never counted anything reads
  const UsageAnswer bystander = read("bystander@%", "k1");

  // Then: the table cannot tell the two apart, so it does not claim completeness to either
  EXPECT_FALSE(bystander.complete);
}

TEST_F(Usage, GivenEightThreadsFoldingUnderOneName_WhenRead_ThenNoFoldWasLost) {
  // Given
  fold_from_threads("app@%", "k1", 8, 5000);

  // When
  const UsageAnswer answer = read("app@%", "k1");

  // Then
  EXPECT_EQ(answer.counts.random_seals, 40000u);
  EXPECT_EQ(answer.counts.bytes_sealed, 40000u);
}

TEST_F(Usage,
       GivenEightThreadsEachAddingItsOwnName_WhenAnotherReadsThroughout_ThenEveryRowIsWhole) {
  // Given: rows being added and folded at once, with a reader in the middle of it
  const size_t impossible = fold_distinct_names_from_threads_while_reading("app@%", 8, 2000);

  // When
  const UsageAnswer first = read("app@%", "thread_0");
  const UsageAnswer last = read("app@%", "thread_7");

  // Then: no lost update, no torn read, and nothing was pushed out
  EXPECT_EQ(impossible, 0u);
  EXPECT_EQ(first.counts.random_seals, 2000u);
  EXPECT_EQ(last.counts.random_seals, 2000u);
  EXPECT_TRUE(last.complete);
}

TEST_F(Usage, GivenDeterministicSealsAndTagFailuresNearTheLimit_WhenMoreIsFolded_ThenTheySaturate) {
  // Given
  fold("app@%", "k1", UsageCounts{0, UINT64_MAX - 1, 0, UINT64_MAX});

  // When
  fold("app@%", "k1", UsageCounts{0, 5, 0, 1});

  // Then: every field saturates, not only the two the other case covers
  const UsageAnswer answer = read("app@%", "k1");
  EXPECT_EQ(answer.counts.det_seals, UINT64_MAX);
  EXPECT_EQ(answer.counts.tag_failures, UINT64_MAX);
}

TEST_F(Usage, GivenCountingAlreadyStarted_WhenInitIsCalledAgain_ThenCountsAndStartTimeAreKept) {
  // Given
  fold("app@%", "k1", UsageCounts{3, 0, 0, 0});

  // When
  const int status = gcm::usage_init(kStart + 999);

  // Then
  const UsageAnswer answer = read("app@%", "k1");
  EXPECT_EQ(status, 0);
  EXPECT_EQ(answer.counts.random_seals, 3u);
  EXPECT_EQ(answer.since, kStart);
}

TEST_F(Usage, GivenCountingStopped_WhenFoldedAndRead_ThenBothAreRefused) {
  // Given
  gcm::usage_deinit();

  // When
  fold("app@%", "k1", UsageCounts{3, 0, 0, 0});
  UsageAnswer answer{};
  const bool counting = gcm::usage_read(name_of("app@%", "k1"), &answer);

  // Then
  EXPECT_FALSE(counting);
}

TEST_F(Usage, GivenCountingStoppedAndStartedAgain_WhenRead_ThenItStartsFromZeroAtTheNewTime) {
  // Given
  fold("app@%", "k1", UsageCounts{3, 0, 0, 0});
  gcm::usage_deinit();

  // When
  ASSERT_EQ(gcm::usage_init(kStart + 60), 0);

  // Then
  const UsageAnswer answer = read("app@%", "k1");
  EXPECT_EQ(answer.counts.random_seals, 0u);
  EXPECT_EQ(answer.since, kStart + 60);
  EXPECT_TRUE(answer.complete);
}

}  // namespace
