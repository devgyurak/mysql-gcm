/* SPDX-License-Identifier: GPL-2.0-only */
/* Shared UDF plumbing for udf_encrypt.cc and udf_decrypt.cc: argument checks,
   per-invocation buffers, charset tagging and Error -> server error conversion.

   No cryptography lives here (component-src rule); it calls gcm.h. */

#ifndef MYSQL_GCM_UDF_GLUE_H
#define MYSQL_GCM_UDF_GLUE_H

#include <cstddef>

#include <mysql/udf_registration_types.h>

#include "gcm.h"

namespace gcm {

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
  /* gcm_decrypt only: the scheduled context and its key copy (design A11).
     nullptr for the encrypt UDFs; freed and cleansed in free_state. */
  DecryptSession *decrypt;
  /* gcm_encrypt_det only: the cached nonce_key and the key copy it is valid for
     (design A11). Zeroed by calloc in init_state, cleansed in free_state. */
  DetSession det;
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
void free_state(UDF_INIT *initid);

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
void raise_below_floor(const char *func, size_t key_len, size_t floor);

}  // namespace gcm

#endif  // MYSQL_GCM_UDF_GLUE_H
