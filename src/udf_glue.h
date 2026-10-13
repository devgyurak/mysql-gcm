/* SPDX-License-Identifier: GPL-2.0-only */
/* Shared UDF plumbing for udf_encrypt.cc and udf_decrypt.cc: argument checks,
   per-invocation buffers, charset tagging and Error -> server error conversion.

   No cryptography lives here (component-src rule); it calls gcm.h. */

#ifndef MYSQL_GCM_UDF_GLUE_H
#define MYSQL_GCM_UDF_GLUE_H

#include <cstddef>

#include <mysql/udf_registration_types.h>

#include "gcm.h"
#include "key_source.h"
#include "usage.h"

namespace gcm {

/* The *_kr functions only (design A13): the key read from the keyring on the first
   row, with the id and the account it was read under. One per UDF item, never
   shared, wiped in free_state and — with the A11 states, the result buffer and the
   spent latch — by every row that raises an error (design A16). Unlike the two A11
   states below it survives a bad_tag that gcm.strict=OFF turns into NULL — the next
   row still has to decrypt, and reading again would let a planted corrupt row cost
   one keyring read per row. Zeroed by calloc. */
struct KeyHold {
  bool loaded;
  /* A key-source failure is latched: later rows raise it again without touching
     the keyring. KeySource::ok (zero) means none. */
  KeySource failure;
  size_t key_len;
  unsigned char key[kKeyLen256];
  size_t id_len;
  char id[kMaxKeyIdLen + 1];
  CallerAccount account;
};

/* Hung off UDF_INIT::ptr, one per UDF item. Nothing is shared between items: the
   same UDF runs concurrently in many sessions (component-src rule). Everything in
   here lives from init to deinit — one execution of one statement; a prepared
   statement with a UDF is re-prepared per EXECUTE — which is the lifetime design A11
   grants the two crypto sessions. */
struct UdfState {
  bool strict;          /* gcm.strict, read once in init (design A5) */
  size_t min_key_bytes; /* gcm.min_key_bytes, read once in init (design A10) */
  unsigned char *out;   /* result bytes; holds plaintext for gcm_decrypt */
  size_t capacity;
  /* Set by the row that raised an error, which has given up every secret in this
     state and released what it held (design A16). Covers all six functions: the
     A11 context, the A11 nonce key, the fetched key and the result buffer. The
     server makes no further row call after an error; a call made anyway — only a
     test can make one — is refused instead of using the released state. Zeroed by
     calloc. */
  bool spent;
  /* gcm_decrypt only: the scheduled context and its key copy (design A11).
     nullptr for the encrypt UDFs; freed and cleansed in free_state. */
  DecryptSession *decrypt;
  /* gcm_encrypt_det only: the cached nonce_key and the key copy it is valid for
     (design A11). Zeroed by calloc in init_state, cleansed in free_state. */
  DetSession det;
  /* The *_kr functions only: the fetched key (design A13). Unused otherwise. */
  KeyHold kr;
  /* The *_kr functions only: what this instance has done under kr's name and not
     yet folded into the component's table (design A14). Plain integers, touched by
     one thread; fold_usage moves them to the table and zeroes them. */
  UsageCounts used;
};

/* Every helper below follows the UDF init convention: true means failure, with
   a reason written to `msg`. */

/* Forces every argument to STRING_RESULT and checks the argument count. */
bool init_args(UDF_ARGS *args, char *msg, const char *usage, unsigned min_args, unsigned max_args);

/* utf8mb4 for a decrypted result so MySQL's native LIKE works on it; binary for
   an envelope (design §5.3). */
bool init_result_charset(UDF_INIT *initid, char *msg, const char *charset);

/* Lets the server convert an argument instead of doing it by hand. */
bool init_argument_charset(UDF_ARGS *args, char *msg, unsigned index, const char *charset);
bool init_argument_collation(UDF_ARGS *args, char *msg, unsigned index, const char *collation);

bool init_state(UDF_INIT *initid, char *msg);
/* Folds any usage not yet folded (design A14), then wipes and releases. */
void free_state(UDF_INIT *initid);

/* Moves the instance's counts into the component's table under the name its key
   was read under, and zeroes them — so calling it twice counts once. One lock, and
   none at all when there is nothing to fold. Called when the instance ends: from
   free_state, and from the row that raises an error, because the server does not
   always call deinit after one (design A14). */
void fold_usage(UdfState *state);

/* Gives up every secret this instance holds and marks it spent (design A16): the
   fetched key, the A11 context, the A11 nonce key and the result buffer, at once,
   without waiting for deinit. Every row callback of every crypto UDF calls this
   before it returns, and nothing is lost by it — the server does not enter the row
   callback again once the function has raised, and deinit cannot be relied on,
   because a loadable function that raises while an outer one is being initialised
   never gets its deinit (design A13, "Implementation notes"); what it held would stay
   in memory, unwiped, for the life of the server. A row that ends in a NULL — a NULL
   argument, or gcm.strict=OFF on a bad tag — is not an error and does not call this.

   This covers the instance that raised. One the server abandons *without* an error —
   the same leak drops those too (design A16, "What the rule does not reach") — keeps
   what it held, keyring key included; the component never regains control of it. */
void give_up_secrets(UdfState *state);

/* The refusal such a call gets when it is made anyway: true when it refused, after
   raising. Only a test can reach this (the server stops calling a function that
   reported an error). */
bool refuse_if_spent(UdfState *state, const char *func);

/* Gives the state its decrypt session (design A11). Call after init_state;
   free_state releases it. True on allocation failure, after releasing the state. */
bool init_decrypt_session(UDF_INIT *initid, char *msg);

/* Grows state->out to at least `need` bytes. The old buffer is wiped before
   release — it may still hold plaintext. True on allocation failure. */
bool reserve(UdfState *state, size_t need);

/* The largest argument the envelope maths and OpenSSL's int-typed lengths accept.
   MySQL caps a string argument at max_allowed_packet long before this, but the
   architecture rule asks for the bound to be checked rather than assumed. */
inline constexpr size_t kMaxArgLen = static_cast<size_t>(2147483647) - kGcmOverhead;

/* True when an argument is too long to process; the caller raises and gives up. */
inline bool too_long(size_t len) { return len > kMaxArgLen; }

/* utf8mb4 spends at most four bytes on one character. */
inline constexpr unsigned long kMaxUtf8mb4BytesPerChar = 4;

/* The result width to declare for an envelope over an argument whose *pre-conversion*
   length is `arg_len` bytes.

   Two things make this more than `arg_len + 29`:

   1. The plaintext argument is requested as utf8mb4, and the server converts it before
      the UDF sees it. `args->lengths[0]` at init is the width in the argument's own
      charset, so a latin1 VARCHAR(1) reports 1 while the converted value is 2 bytes and
      the envelope is 31 — one byte more than a naive `1 + 29`. Measured on 8.4 and
      9.4: materialising that result fails with ER_DATA_TOO_LONG under strict SQL mode
      and, worse, truncates to 30 bytes with only warning 1265 when strict mode is off,
      leaving ciphertext that no longer authenticates. Every charset spends at least one
      byte per character, so `arg_len` bounds the character count and four times it
      bounds the converted length. That over-declares for an argument that is already
      utf8mb4; a too-wide result costs a wider temporary field, a too-narrow one
      destroys data.
   2. udf_handler::fix_fields does `func->max_length = min<uint32>(initid.max_length,
      MAX_BLOB_WIDTH)`, and the cast to uint32 happens *first*, so a LONGTEXT argument
      (4294967295) plus the overhead would wrap to 28 — below the 29 byte minimum
      envelope. Hence the saturation rather than plain arithmetic. The server narrows
      whatever is returned here to MAX_BLOB_WIDTH anyway. */
inline unsigned long envelope_max_length(unsigned long arg_len) {
  constexpr unsigned long kUint32Max = 0xFFFFFFFFUL;
  if (arg_len > kUint32Max / kMaxUtf8mb4BytesPerChar) return kUint32Max;
  const unsigned long converted = arg_len * kMaxUtf8mb4BytesPerChar;
  if (converted > kUint32Max - static_cast<unsigned long>(kGcmOverhead)) return kUint32Max;
  return converted + static_cast<unsigned long>(kGcmOverhead);
}

/* A NULL in any argument yields SQL NULL with no cryptographic work
   (spec/envelope.md §4 rule 3). */
bool any_arg_is_null(const UDF_ARGS *args);

/* Borrowed views of arguments; an absent optional argument is an empty AAD. */
Bytes arg_bytes(const UDF_ARGS *args, unsigned index);
Bytes optional_arg_bytes(const UDF_ARGS *args, unsigned index);

/* Raises the server error for `err`. Carries lengths and nothing else: no key,
   plaintext, nonce, tag or ciphertext bytes (spec/envelope.md §4 rule 4). */
void raise(const char *func, Error err, size_t key_len, size_t envelope_len);

/* Same, for conditions that are not an Error — `detail` must be a fixed string,
   never assembled from argument bytes. */
void raise_message(const char *func, const char *detail);

/* Reports an argument that exceeds kMaxArgLen. Carries lengths only. */
void raise_too_long(const char *func, size_t len);

/* Reports a key that is shorter than gcm.min_key_bytes. Distinct from
   bad_key_len: the key is a valid length for a suite, and the server policy is
   what refuses it, so the message has to say that rather than claim the length
   is wrong (design A10). Carries lengths only. */
/* Not for the *_kr functions: there the length belongs to a keyring entry and must
   not appear in a message (design A13). udf_kr.cc reports the floor alone. */
void raise_below_floor(const char *func, size_t key_len, size_t floor);

}  // namespace gcm

#endif  // MYSQL_GCM_UDF_GLUE_H
