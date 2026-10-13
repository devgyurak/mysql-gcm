/* SPDX-License-Identifier: GPL-2.0-only */
/* The component's table of usage counts for the key-id functions (docs/design.md
   amendment A14): how many seals, how many plaintext bytes and how many tag
   failures this server has seen under each key name since it started counting.

   This is the component's one piece of shared, mutable state. It holds names and
   integers — never key bytes, and nothing derived from them. It has no server
   dependency, so tests/unit covers it, concurrency included.

   What a count is NOT: a key's usage. It is a lower bound on one term of the
   budget amendment A8 asks for — see the amendment before reading it as more. */

#ifndef MYSQL_GCM_USAGE_H
#define MYSQL_GCM_USAGE_H

#include <cstddef>
#include <cstdint>

namespace gcm {

/* Counts are 64-bit and saturate: a count never wraps to a small number. */
struct UsageCounts {
  uint64_t random_seals;
  uint64_t det_seals;
  uint64_t bytes_sealed; /* plaintext bytes of the seals above */
  uint64_t tag_failures; /* decryptions that ended in a tag mismatch */
};

struct UsageAnswer {
  UsageCounts counts;
  /* When counting began: the value given to usage_init. */
  int64_t since;
  /* False once a name of *this account* did not fit. From then on some use by
     this account is in no row. An account filling its own share is not visible
     to, and costs nothing for, any other. The one exception: once the *whole*
     table is full and an account with no row at all has lost a use, every account
     with no row is told false, because the table has nowhere to keep which. */
  bool complete;
};

/* Names are never evicted — evicting one would make its count go backwards — so
   the table is bounded, per account and in total, and an account is told when one
   of its names did not fit. The per-account bound is what keeps one account from
   using up the table: it takes kMaxUsageNames / kMaxUsageNamesPerAccount accounts
   acting together to fill it. */
inline constexpr size_t kMaxUsageNames = 1024;
inline constexpr size_t kMaxUsageNamesPerAccount = 64;

/* A name is (account, key id): the keyring namespace of amendment A13. Neither
   part may be empty or contain a NUL byte; the callers have checked both. The
   account is the string A13 builds, so its one ambiguity carries over: 'a@b'@'c'
   and 'a'@'b@c' are one account here as they are one keyring namespace. */
struct UsageName {
  const char *account;
  size_t account_len;
  const char *key_id;
  size_t key_id_len;
};

/* a + b, or UINT64_MAX when that would wrap. Shared so that the counters an
   instance keeps before folding saturate the same way the table does. */
uint64_t usage_saturating_add(uint64_t a, uint64_t b);

/* Starts counting from zero, at time `now` (Unix seconds). Returns 0 on success
   and 1 when the table cannot be allocated. Calling it again while counting is a
   no-op that returns 0: the counts and `since` are kept. */
int usage_init(int64_t now);

/* Stops counting and releases the table. Folds and reads after this are refused
   until usage_init is called again. */
void usage_deinit();

/* Adds `delta` to the row of `name`, creating it if there is room. One lock, no
   allocation unless the name is new. A delta of all zeros does nothing and does
   not create a row, so a name appears only once something was counted under it.
   Safe from any thread. Does nothing when not counting. */
void usage_fold(const UsageName &name, const UsageCounts &delta);

/* The row of `name`; zeros when there is none. False when not counting. Safe
   from any thread. */
bool usage_read(const UsageName &name, UsageAnswer *out);

}  // namespace gcm

#endif  // MYSQL_GCM_USAGE_H
