/* SPDX-License-Identifier: GPL-2.0-only */
/* gcm_encrypt_kr, gcm_encrypt_det_kr and gcm_decrypt_kr: the three functions that
   take a key id and use the key stored under it in the keyring for the calling
   account (docs/design.md amendment A13).

   Same envelopes, same core entry points and same SQL semantics as the functions
   in udf_encrypt.cc and udf_decrypt.cc. What differs is where the key comes from,
   and that no message here carries the key id, the account, or the length or type
   of a keyring entry. */

#include <cstddef>
#include <cstdio>
#include <cstring>

#include <mysql/udf_registration_types.h>

#include "gcm.h"
#include "key_source.h"
#include "udf_glue.h"

namespace {

using gcm::Bytes;
using gcm::Error;
using gcm::KeyHold;
using gcm::KeySource;
using gcm::UdfState;

const char *describe(KeySource failure) {
  switch (failure) {
    case KeySource::unavailable:
      return "the keyring is unavailable or the read failed";
    case KeySource::no_usable_key:
      return "no usable AES key under this id for the calling account";
    case KeySource::invalid_id:
      return "the key id must be 1 to 255 bytes without a NUL byte and the same on every row";
    case KeySource::no_account:
      return "the calling account could not be established or changed during the statement";
    case KeySource::ok:
      break;
  }
  return "the key source failed";
}

/* Forgets the fetched key without latching anything. Every row that raises an error
   does this before it returns, and does not wait for deinit: the server does not
   always call deinit after an error — a loadable function that is an argument of
   another one and fails while the outer one is being initialised never gets it
   (design A13, "Implementation notes") — and a key left for a deinit that never
   comes would stay in memory, unwiped, for the life of the server. An error
   normally ends the statement; one that continues past it (INSERT IGNORE, a
   handler) reads the keyring again on its next row. */
void forget_key(KeyHold *hold) {
  gcm::wipe(hold->key, sizeof(hold->key));
  hold->key_len = 0;
  hold->loaded = false;
}

/* Latches and raises. Every key-source failure is an error whatever gcm.strict
   says, and stays the answer for the rest of this UDF_INIT (design A13). */
bool fail_key(const char *func, KeyHold *hold, KeySource failure) {
  forget_key(hold);
  hold->failure = failure;
  gcm::raise_message(func, describe(failure));
  return true;
}

/* Puts the key for this row in *key. True on failure, after raising.

   The order is the amendment's: id and account are checked on every row, and the
   keyring is read on the first row that gets this far — not in init, where a
   prepared statement's `?` is not visible yet. Reading the account touches no
   keyring. */
bool resolve_key(const char *func, UdfState *state, Bytes id, Bytes *key) {
  KeyHold *hold = &state->kr;
  if (hold->failure != KeySource::ok) return fail_key(func, hold, hold->failure);

  if (id.size == 0 || id.size > gcm::kMaxKeyIdLen || std::memchr(id.data, '\0', id.size)) {
    return fail_key(func, hold, KeySource::invalid_id);
  }
  gcm::CallerAccount account;
  if (gcm::caller_account(&account) != KeySource::ok) {
    return fail_key(func, hold, KeySource::no_account);
  }

  if (hold->loaded) {
    /* Neither is secret, so a plain comparison. */
    if (id.size != hold->id_len || std::memcmp(id.data, hold->id, id.size) != 0) {
      return fail_key(func, hold, KeySource::invalid_id);
    }
    if (account.len != hold->account.len ||
        std::memcmp(account.text, hold->account.text, account.len) != 0) {
      return fail_key(func, hold, KeySource::no_account);
    }
  } else {
    std::memcpy(hold->id, id.data, id.size);
    hold->id[id.size] = '\0';
    hold->id_len = id.size;
    hold->account = account;
    const KeySource fetched = gcm::fetch_key(hold->id, hold->account, hold->key, &hold->key_len);
    if (fetched != KeySource::ok) return fail_key(func, hold, fetched);
    hold->loaded = true;
  }

  *key = Bytes{hold->key, hold->key_len};
  return false;
}

/* gcm::raise names the key length for bad_key_len. Here that length is a property
   of a keyring entry, so this path says what disagreed and nothing more. */
void raise_core(const char *func, Error err, size_t envelope_len) {
  if (err == Error::bad_key_len) {
    gcm::raise_message(func, "the key's length does not match the envelope version");
    return;
  }
  gcm::raise(func, err, 0, envelope_len);
}

using EncryptFn = Error (*)(UdfState *state, Bytes key, Bytes plaintext, Bytes aad,
                            unsigned char *out, size_t *out_len);

Error seal_random(UdfState *, Bytes key, Bytes plaintext, Bytes aad, unsigned char *out,
                  size_t *out_len) {
  return gcm::encrypt_random(key, plaintext, aad, out, out_len);
}

Error seal_det(UdfState *state, Bytes key, Bytes plaintext, Bytes aad, unsigned char *out,
               size_t *out_len) {
  return gcm::encrypt_det_with_session(&state->det, key, plaintext, aad, out, out_len);
}

bool encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *msg, const char *usage,
                  bool deterministic) {
  if (gcm::init_args(args, msg, usage, 2, 3)) return true;

  /* The id is text and is converted to utf8mb4, which is what the server's
     keyring_udf functions ask for theirs — so a non-ASCII id names the same entry
     from either side. Plaintext and AAD as in udf_encrypt.cc. */
  if (gcm::init_argument_charset(args, msg, 0, "utf8mb4")) return true;
  if (gcm::init_argument_charset(args, msg, 1, "utf8mb4")) return true;
  if (gcm::init_argument_charset(args, msg, 2, "binary")) return true;
  if (gcm::init_result_charset(initid, msg, "binary")) return true;

  initid->maybe_null = true;
  /* As gcm_encrypt_det: a constant lookup on a UNIQUE index is what the variant is
     for. The consequence is that the keyring read can happen while the statement
     is optimised, in the caller's session (design A13). */
  initid->const_item = deterministic;
  initid->max_length = gcm::envelope_max_length(args->lengths[0]);
  return gcm::init_state(initid, msg);
}

char *encrypt_row(const char *func, EncryptFn seal, UDF_INIT *initid, UDF_ARGS *args,
                  unsigned long *length, unsigned char *is_null, unsigned char *error) {
  auto *state = reinterpret_cast<UdfState *>(initid->ptr);

  /* Before anything else: a NULL argument gives NULL with no keyring access and
     no id check (spec/envelope.md §4 rule 3). */
  if (gcm::any_arg_is_null(args)) {
    *is_null = 1;
    return nullptr;
  }

  const Bytes plaintext = gcm::arg_bytes(args, 0);
  const Bytes aad = gcm::optional_arg_bytes(args, 2);
  Bytes key{nullptr, 0};
  if (resolve_key(func, state, gcm::arg_bytes(args, 1), &key)) {
    *error = 1;
    return nullptr;
  }

  /* design A10: the floor is an encryption-side policy and applies to a keyring
     key exactly as to an argument. The message names the floor, which is a public
     setting, and not the key's length. */
  if (key.size < state->min_key_bytes) {
    char detail[160];
    snprintf(detail, sizeof(detail),
             "the key is below gcm.min_key_bytes = %zu; decryption of existing data is "
             "unaffected",
             state->min_key_bytes);
    gcm::raise_message(func, detail);
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }

  if (gcm::too_long(plaintext.size) || gcm::too_long(aad.size)) {
    gcm::raise_too_long(func, plaintext.size > aad.size ? plaintext.size : aad.size);
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }
  if (gcm::reserve(state, gcm::encrypt_out_len(plaintext.size))) {
    gcm::raise_message(func, "out of memory");
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }

  size_t out_len = 0;
  const Error err = seal(state, key, plaintext, aad, state->out, &out_len);
  if (err != Error::ok) {
    raise_core(func, err, 0);
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }

  *length = static_cast<unsigned long>(out_len);
  return reinterpret_cast<char *>(state->out);
}

constexpr const char kRandomUsage[] =
    "gcm_encrypt_kr(plaintext, key_id [, aad]) needs 2 or 3 arguments";
constexpr const char kDetUsage[] =
    "gcm_encrypt_det_kr(plaintext, key_id [, aad]) needs 2 or 3 arguments";
constexpr const char kDecryptUsage[] =
    "gcm_decrypt_kr(ciphertext, key_id [, aad]) needs 2 or 3 arguments";

}  // namespace

extern "C" {

bool gcm_encrypt_kr_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return encrypt_init(initid, args, message, kRandomUsage, false);
}

char *gcm_encrypt_kr_udf(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length,
                         unsigned char *is_null, unsigned char *error) {
  return encrypt_row("gcm_encrypt_kr", seal_random, initid, args, length, is_null, error);
}

void gcm_encrypt_kr_deinit(UDF_INIT *initid) { gcm::free_state(initid); }

bool gcm_encrypt_det_kr_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return encrypt_init(initid, args, message, kDetUsage, true);
}

/* Deterministic: reveals equality of plaintexts and MUST NOT be used for free
   text (spec/envelope.md §2.2). Every condition on a deterministic key applies to
   a keyring key too — one AAD convention per key, an independent key per mode. */
char *gcm_encrypt_det_kr_udf(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length,
                             unsigned char *is_null, unsigned char *error) {
  return encrypt_row("gcm_encrypt_det_kr", seal_det, initid, args, length, is_null, error);
}

void gcm_encrypt_det_kr_deinit(UDF_INIT *initid) { gcm::free_state(initid); }

bool gcm_decrypt_kr_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (gcm::init_args(args, message, kDecryptUsage, 2, 3)) return true;

  if (gcm::init_argument_charset(args, message, 0, "binary")) return true;
  if (gcm::init_argument_charset(args, message, 1, "utf8mb4")) return true;
  if (gcm::init_argument_charset(args, message, 2, "binary")) return true;

  /* utf8mb4, for the same reason as gcm_decrypt: native LIKE '%길%' (design §5.3). */
  if (gcm::init_result_charset(initid, message, "utf8mb4")) return true;

  initid->maybe_null = true;
  initid->const_item = false;
  initid->max_length = args->lengths[0];
  if (gcm::init_state(initid, message)) return true;
  return gcm::init_decrypt_session(initid, message);
}

char *gcm_decrypt_kr_udf(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length,
                         unsigned char *is_null, unsigned char *error) {
  static constexpr char kFunc[] = "gcm_decrypt_kr";
  auto *state = reinterpret_cast<UdfState *>(initid->ptr);

  if (gcm::any_arg_is_null(args)) {
    *is_null = 1;
    return nullptr;
  }

  const Bytes envelope = gcm::arg_bytes(args, 0);
  const Bytes aad = gcm::optional_arg_bytes(args, 2);
  Bytes key{nullptr, 0};
  if (resolve_key(kFunc, state, gcm::arg_bytes(args, 1), &key)) {
    *error = 1;
    return nullptr;
  }

  if (gcm::too_long(envelope.size) || gcm::too_long(aad.size)) {
    gcm::raise_too_long(kFunc, envelope.size > aad.size ? envelope.size : aad.size);
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }
  if (gcm::reserve(state, gcm::decrypt_out_len(envelope.size) + 1)) {
    gcm::raise_message(kFunc, "out of memory");
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }

  size_t out_len = 0;
  const Error err =
      gcm::decrypt_with_session(state->decrypt, key, envelope, aad, state->out, &out_len);

  /* The one failure gcm.strict governs. The core has wiped the output and
     forgotten its scheduled copy of the key. With strict OFF this row is a NULL and
     not an error, so the fetched key in state->kr stays and the next row decrypts
     without another keyring read (design A13). With strict ON it is an error like
     any other and falls through to the forget below. */
  if (err == Error::bad_tag && !state->strict) {
    *is_null = 1;
    return nullptr;
  }
  if (err != Error::ok) {
    raise_core(kFunc, err, envelope.size);
    forget_key(&state->kr);
    *error = 1;
    return nullptr;
  }

  *length = static_cast<unsigned long>(out_len);
  return reinterpret_cast<char *>(state->out);
}

void gcm_decrypt_kr_deinit(UDF_INIT *initid) { gcm::free_state(initid); }

}  // extern "C"
