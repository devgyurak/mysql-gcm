/* SPDX-License-Identifier: GPL-2.0-only */
#include "usage.h"

#include <cstdlib>
#include <cstring>
#include <mutex>

namespace gcm {
namespace {

struct Row {
  char *name; /* account, a NUL, key id — unambiguous because neither part has one */
  size_t name_len;
  size_t account_len;
  UsageCounts counts;
  /* Set on every row of an account once a name of that account did not fit. Kept
     in the rows so that recording it needs no memory and cannot fail. */
  bool account_lost;
};

/* What one pass over the table learns about an account. */
struct AccountView {
  Row *row;     /* the row of the name asked for, or nullptr */
  size_t names; /* rows this account has */
  bool lost;    /* a name of this account did not fit */
};

/* Everything below is guarded by g_mutex. It is taken once per UDF_INIT to fold
   and once per gcm_key_usage call to read, never on the row path of an
   encryption or a decryption (architecture rule §5). */
std::mutex g_mutex;
Row *g_rows = nullptr; /* kMaxUsageNames slots; nullptr means not counting */
size_t g_row_count = 0;
int64_t g_since = 0;

/* An account that has no row and lost a use has nowhere to keep that fact, so it
   is kept here, for all such accounts at once. It can only become true when the
   whole table is full or memory ran out — see usage_read for what it costs. */
bool g_rowless_account_lost = false;

bool is_zero(const UsageCounts &c) {
  return c.random_seals == 0 && c.det_seals == 0 && c.bytes_sealed == 0 && c.tag_failures == 0;
}

/* The callers bound both parts — an account by kMaxAccountLen and a key id by
   kMaxKeyIdLen (src/key_source.h), and neither is empty — so this cannot overflow
   and a name is at most a few kilobytes. The module does not re-check: it has no
   server dependency to take those constants from. */
size_t joined_len(const UsageName &name) { return name.account_len + 1 + name.key_id_len; }

bool matches(const Row &row, const UsageName &name) {
  return row.name_len == joined_len(name) &&
         std::memcmp(row.name, name.account, name.account_len) == 0 &&
         row.name[name.account_len] == '\0' &&
         std::memcmp(row.name + name.account_len + 1, name.key_id, name.key_id_len) == 0;
}

/* A row's name starts with its account, so the first argument may be a row name. */
bool same_account(const char *account, size_t account_len, const UsageName &name) {
  return account_len == name.account_len && std::memcmp(account, name.account, account_len) == 0;
}

/* A linear search, on purpose: it runs once per UDF_INIT under a bound of 1024
   short comparisons, and a table that never rehashes has nothing to get wrong. */
AccountView look(const UsageName &name) {
  AccountView view{nullptr, 0, false};
  for (size_t i = 0; i < g_row_count; ++i) {
    Row &row = g_rows[i];
    if (!same_account(row.name, row.account_len, name)) continue;
    ++view.names;
    view.lost = view.lost || row.account_lost;
    if (matches(row, name)) view.row = &row;
  }
  return view;
}

/* Records that a use by this account is in no row. No allocation: the mark goes on
   the account's own rows, or, for an account without any, on the one shared flag. */
void note_lost(const UsageName &name, size_t names_of_account) {
  if (names_of_account == 0) {
    g_rowless_account_lost = true;
    return;
  }
  for (size_t i = 0; i < g_row_count; ++i) {
    Row &row = g_rows[i];
    if (same_account(row.name, row.account_len, name)) row.account_lost = true;
  }
}

Row *add(const UsageName &name, size_t names_of_account) {
  if (g_row_count == kMaxUsageNames || names_of_account >= kMaxUsageNamesPerAccount) return nullptr;
  const size_t len = joined_len(name);
  char *joined = static_cast<char *>(std::malloc(len)); /* len >= 1: the separator */
  if (joined == nullptr) return nullptr;
  std::memcpy(joined, name.account, name.account_len);
  joined[name.account_len] = '\0';
  std::memcpy(joined + name.account_len + 1, name.key_id, name.key_id_len);

  Row *row = &g_rows[g_row_count++];
  row->name = joined;
  row->name_len = len;
  row->account_len = name.account_len;
  row->counts = UsageCounts{0, 0, 0, 0};
  /* An account that lost a use while it had no row — which only a failed
     allocation can cause, since a full table stays full — is one of the accounts
     the shared flag stands for. Its first row takes the mark over, so that getting
     a row later does not turn `complete` back to true. This can mark an account
     that lost nothing; saying "incomplete" too often is the safe direction. */
  row->account_lost = names_of_account == 0 && g_rowless_account_lost;
  return row;
}

}  // namespace

uint64_t usage_saturating_add(uint64_t a, uint64_t b) {
  const uint64_t sum = a + b;
  return sum < a ? UINT64_MAX : sum;
}

int usage_init(int64_t now) {
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows != nullptr) return 0;
  g_rows = static_cast<Row *>(std::calloc(kMaxUsageNames, sizeof(Row)));
  if (g_rows == nullptr) return 1;
  g_row_count = 0;
  g_rowless_account_lost = false;
  g_since = now;
  return 0;
}

void usage_deinit() {
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows == nullptr) return;
  for (size_t i = 0; i < g_row_count; ++i) std::free(g_rows[i].name);
  std::free(g_rows);
  g_rows = nullptr;
  g_row_count = 0;
}

void usage_fold(const UsageName &name, const UsageCounts &delta) {
  if (is_zero(delta)) return;
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows == nullptr) return;

  const AccountView view = look(name);
  Row *row = view.row != nullptr ? view.row : add(name, view.names);
  if (row == nullptr) {
    /* No room in the account's share or in the table, or no memory for the name.
       The use is in no row, and this account's answers say so from here on. */
    note_lost(name, view.names);
    return;
  }
  row->counts.random_seals = usage_saturating_add(row->counts.random_seals, delta.random_seals);
  row->counts.det_seals = usage_saturating_add(row->counts.det_seals, delta.det_seals);
  row->counts.bytes_sealed = usage_saturating_add(row->counts.bytes_sealed, delta.bytes_sealed);
  row->counts.tag_failures = usage_saturating_add(row->counts.tag_failures, delta.tag_failures);
}

bool usage_read(const UsageName &name, UsageAnswer *out) {
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows == nullptr) return false;
  const AccountView view = look(name);
  out->counts = view.row != nullptr ? view.row->counts : UsageCounts{0, 0, 0, 0};
  out->since = g_since;
  /* An account with rows is answered from its own rows alone. An account with none
     cannot be told apart from the rowless account that lost a use, so once that has
     happened every rowless account is told its answer may be incomplete. This is
     the one way one account's use shows in another's answer, and it needs the whole
     table to be full, or memory to have run out. */
  out->complete = !view.lost && !(view.names == 0 && g_rowless_account_lost);
  return true;
}

}  // namespace gcm
