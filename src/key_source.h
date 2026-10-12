/* SPDX-License-Identifier: GPL-2.0-only */
/* Where the *_kr functions get their key: the server's keyring, read under the
   calling account (docs/design.md amendment A13).

   A server adapter: it talks to MySQL services and holds no cryptography. The
   core never includes this file (architecture rule §1). */

#ifndef MYSQL_GCM_KEY_SOURCE_H
#define MYSQL_GCM_KEY_SOURCE_H

#include <cstddef>

#include "envelope.h"

namespace gcm {

/* The four outcomes design A13 distinguishes, and no more. `no_usable_key` is one
   answer for three conditions on purpose — no entry under this id for this
   account, an entry that is not type AES, an entry whose length no suite has — so
   that an entry of another type or an odd length is not revealed. */
enum class KeySource {
  ok,
  unavailable,   /* no keyring loaded, or the reader failed */
  no_usable_key, /* absent, not AES, or not 16/24/32 bytes */
  invalid_id,    /* empty, too long, a NUL byte, or not the first row's id */
  no_account,    /* no session, an anonymous account, or one that changed */
};

/* A key id is at most this many bytes, after the server converted the argument to
   utf8mb4. The bound is this component's: it keeps the id in a fixed buffer. */
inline constexpr size_t kMaxKeyIdLen = 255;

/* priv_user@priv_host, the keyring namespace of the server's own keyring_udf
   functions. The server caps a user name at 32 characters of its three-byte system
   charset (96 bytes) and a host at 255 bytes; this is sized for four bytes per
   character in both, so it holds any account the server can report with room to
   spare. A user name containing '@' makes the string ambiguous ('a@b'@'c' and
   'a'@'b@c' are one namespace) — inherited from keyring_udf, see design A13. */
inline constexpr size_t kMaxAccountLen = 4 * 32 + 1 + 4 * 255;

struct CallerAccount {
  char text[kMaxAccountLen + 1]; /* NUL-terminated for the keyring service */
  size_t len;
};

/* The account the current statement runs as. Inside a SQL SECURITY DEFINER routine
   that is the definer; inside a view it is the invoker (design A13). Touches no
   keyring, so it is safe on the row path. `no_account` for a thread without a
   session, a failed service call, an anonymous account, or a name that does not
   fit. */
KeySource caller_account(CallerAccount *out);

/* Reads the key stored under (`key_id`, `account`) into `out`, which must hold
   kKeyLen256 bytes. `key_id` is NUL-terminated and already validated.

   Returns the key as stored. gcm.min_key_bytes is not applied here — it is an
   encryption-side SQL policy and belongs to the UDF (architecture rule §2).

   One reader object, released before returning on every path: it holds a read lock
   on the server's global keyring lock from its init to its deinit, so it is never
   kept across rows. Anything fetched that is not returned is wiped. */
KeySource fetch_key(const char *key_id, const CallerAccount &account, unsigned char *out,
                    size_t *out_len);

}  // namespace gcm

#endif  // MYSQL_GCM_KEY_SOURCE_H
