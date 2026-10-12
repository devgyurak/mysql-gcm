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
};

/* What one pass over the table learns about an account. */
struct AccountView {
  Row *row;     /* the row of the name asked for, or nullptr */
  size_t names; /* rows this account has */
};

/* Everything below is guarded by g_mutex. It is taken once per UDF_INIT to fold
   and once per gcm_key_usage call to read, never on the row path of an
   encryption or a decryption (architecture rule §5). */
std::mutex g_mutex;
Row *g_rows = nullptr; /* kMaxUsageNames slots; nullptr means not counting */
size_t g_row_count = 0;
int64_t g_since = 0;

/* Accounts that lost a name, by account. Small and bounded like the table: an
   account that does not fit here either is covered by g_unlisted_account_lost. */
struct LostAccount {
  char *account;
  size_t account_len;
};
LostAccount *g_lost = nullptr; /* kMaxUsageNames slots */
size_t g_lost_count = 0;
bool g_unlisted_account_lost = false;

uint64_t saturating_add(uint64_t a, uint64_t b) {
  const uint64_t sum = a + b;
  return sum < a ? UINT64_MAX : sum;
}

bool is_zero(const UsageCounts &c) {
  return c.random_seals == 0 && c.det_seals == 0 && c.bytes_sealed == 0 && c.tag_failures == 0;
}

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
  AccountView view{nullptr, 0};
  for (size_t i = 0; i < g_row_count; ++i) {
    Row &row = g_rows[i];
    if (!same_account(row.name, row.account_len, name)) continue;
    ++view.names;
    if (matches(row, name)) view.row = &row;
  }
  return view;
}

bool lost_a_name(const UsageName &name) {
  for (size_t i = 0; i < g_lost_count; ++i) {
    if (same_account(g_lost[i].account, g_lost[i].account_len, name)) return true;
  }
  return false;
}

/* Records that a use by this account is in no row. */
void note_lost(const UsageName &name) {
  if (lost_a_name(name)) return;
  char *copy = nullptr;
  if (g_lost_count < kMaxUsageNames) {
    copy = static_cast<char *>(std::malloc(name.account_len == 0 ? 1 : name.account_len));
  }
  if (copy == nullptr) {
    /* Not even room to remember which account. Every account without a row of
       its own is then told its answer may be incomplete — the one case in which
       one account's answer depends on others, and it takes more accounts than
       the table has slots for to get here. */
    g_unlisted_account_lost = true;
    return;
  }
  std::memcpy(copy, name.account, name.account_len);
  g_lost[g_lost_count++] = LostAccount{copy, name.account_len};
}

Row *add(const UsageName &name, size_t names_of_account) {
  if (g_row_count == kMaxUsageNames || names_of_account >= kMaxUsageNamesPerAccount) return nullptr;
  const size_t len = joined_len(name);
  char *joined = static_cast<char *>(std::malloc(len == 0 ? 1 : len));
  if (joined == nullptr) return nullptr;
  std::memcpy(joined, name.account, name.account_len);
  joined[name.account_len] = '\0';
  std::memcpy(joined + name.account_len + 1, name.key_id, name.key_id_len);

  Row *row = &g_rows[g_row_count++];
  row->name = joined;
  row->name_len = len;
  row->account_len = name.account_len;
  row->counts = UsageCounts{0, 0, 0, 0};
  return row;
}

}  // namespace

int usage_init(int64_t now) {
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows != nullptr) return 0;
  g_rows = static_cast<Row *>(std::calloc(kMaxUsageNames, sizeof(Row)));
  g_lost = static_cast<LostAccount *>(std::calloc(kMaxUsageNames, sizeof(LostAccount)));
  if (g_rows == nullptr || g_lost == nullptr) {
    std::free(g_rows);
    std::free(g_lost);
    g_rows = nullptr;
    g_lost = nullptr;
    return 1;
  }
  g_row_count = 0;
  g_lost_count = 0;
  g_unlisted_account_lost = false;
  g_since = now;
  return 0;
}

void usage_deinit() {
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows == nullptr) return;
  for (size_t i = 0; i < g_row_count; ++i) std::free(g_rows[i].name);
  for (size_t i = 0; i < g_lost_count; ++i) std::free(g_lost[i].account);
  std::free(g_rows);
  std::free(g_lost);
  g_rows = nullptr;
  g_lost = nullptr;
  g_row_count = 0;
  g_lost_count = 0;
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
    note_lost(name);
    return;
  }
  row->counts.random_seals = saturating_add(row->counts.random_seals, delta.random_seals);
  row->counts.det_seals = saturating_add(row->counts.det_seals, delta.det_seals);
  row->counts.bytes_sealed = saturating_add(row->counts.bytes_sealed, delta.bytes_sealed);
  row->counts.tag_failures = saturating_add(row->counts.tag_failures, delta.tag_failures);
}

bool usage_read(const UsageName &name, UsageAnswer *out) {
  const std::lock_guard<std::mutex> lock(g_mutex);
  if (g_rows == nullptr) return false;
  const AccountView view = look(name);
  out->counts = view.row != nullptr ? view.row->counts : UsageCounts{0, 0, 0, 0};
  out->since = g_since;
  out->complete = !lost_a_name(name) && !(view.names == 0 && g_unlisted_account_lost);
  return true;
}

}  // namespace gcm
