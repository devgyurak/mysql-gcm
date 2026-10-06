/* SPDX-License-Identifier: GPL-2.0-only */
/* gcm_encrypt and gcm_encrypt_det: argument checks, buffers and error mapping.
   The envelope and the cryptography live in gcm.cc (component-src rule). */

#include <cstddef>

#include <mysql/udf_registration_types.h>

#include "gcm.h"
#include "udf_glue.h"

namespace {

using gcm::Bytes;
using gcm::Error;
using gcm::UdfState;

using EncryptFn = Error (*)(Bytes key, Bytes plaintext, Bytes aad, unsigned char *out,
                            size_t *out_len);

bool encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *msg, const char *usage,
                  bool deterministic) {
  if (gcm::init_args(args, msg, usage, 2, 3)) return true;

  /* Let the server convert the plaintext to utf8mb4 rather than doing charset
     work by hand, so the bytes sealed here are exactly what gcm_decrypt hands
     back tagged utf8mb4 (component-src rule). Key and AAD stay opaque. */
  if (gcm::init_argument_charset(args, msg, 0, "utf8mb4")) return true;
  if (gcm::init_argument_charset(args, msg, 1, "binary")) return true;
  if (gcm::init_argument_charset(args, msg, 2, "binary")) return true;

  /* BLOB, not VARCHAR: spec/envelope.md §1. */
  if (gcm::init_result_charset(initid, msg, "binary")) return true;

  initid->maybe_null = true; /* a NULL argument propagates */
  /* Only the deterministic variant may be folded. Same key, plaintext and AAD give
     the same envelope, so with constant arguments the server is free to evaluate it
     once — which is what turns `WHERE indexed_col = gcm_encrypt_det('EMR-001', @k)`
     into an index lookup instead of a scan, the whole point of the variant
     (spec/envelope.md §2.2). gcm_encrypt must never claim this: it draws a fresh
     nonce per call (design §6). Measured on 8.4: the lookup becomes type=const on the
     unique key, a prepared statement re-executed with different parameters still
     returns different envelopes, and a column argument is still evaluated per row. */
  initid->const_item = deterministic;
  initid->max_length = gcm::envelope_max_length(args->lengths[0]);
  return gcm::init_state(initid, msg);
}

char *encrypt_row(const char *func, EncryptFn seal, UDF_INIT *initid, UDF_ARGS *args,
                  unsigned long *length, unsigned char *is_null, unsigned char *error) {
  auto *state = reinterpret_cast<UdfState *>(initid->ptr);

  if (gcm::any_arg_is_null(args)) {
    *is_null = 1;
    return nullptr;
  }

  const Bytes plaintext = gcm::arg_bytes(args, 0);
  const Bytes key = gcm::arg_bytes(args, 1);
  const Bytes aad = gcm::optional_arg_bytes(args, 2);

  /* design A10: the suite follows the key length, so a key that was truncated in
     transit is a *valid* key for a weaker suite and would seal successfully. The
     floor is what puts that check back, and it is an encryption-side policy — a
     SQL policy, so it lives here and not in the core (architecture rule §2).
     gcm_decrypt deliberately does not consult it. */
  /* Only for a key whose length a suite actually has. A 5-byte key is not a
     policy violation, it is not a key — letting the floor answer first would
     report "below gcm.min_key_bytes" for a length no setting could ever allow. */
  if (gcm::suite_for_key_len(key.size) != nullptr && key.size < state->min_key_bytes) {
    gcm::raise_below_floor(func, key.size, state->min_key_bytes);
    *error = 1;
    return nullptr;
  }

  /* Checked before the envelope size is computed, so that addition cannot wrap. */
  if (gcm::too_long(plaintext.size) || gcm::too_long(aad.size)) {
    gcm::raise_too_long(func, plaintext.size > aad.size ? plaintext.size : aad.size);
    *error = 1;
    return nullptr;
  }

  if (gcm::reserve(state, gcm::encrypt_out_len(plaintext.size))) {
    gcm::raise_message(func, "out of memory");
    *error = 1;
    return nullptr;
  }

  size_t out_len = 0;
  const Error err = seal(key, plaintext, aad, state->out, &out_len);
  if (err != Error::ok) {
    /* Encryption failures are always errors — gcm.strict only governs tag
       verification (spec/envelope.md §4). */
    gcm::raise(func, err, key.size, 0);
    *error = 1;
    return nullptr;
  }

  *length = static_cast<unsigned long>(out_len);
  return reinterpret_cast<char *>(state->out);
}

constexpr const char kRandomUsage[] = "gcm_encrypt(plaintext, key [, aad]) needs 2 or 3 arguments";
constexpr const char kDetUsage[] = "gcm_encrypt_det(plaintext, key [, aad]) needs 2 or 3 arguments";

}  // namespace

extern "C" {

bool gcm_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return encrypt_init(initid, args, message, kRandomUsage, false);
}

char *gcm_encrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length,
                      unsigned char *is_null, unsigned char *error) {
  return encrypt_row("gcm_encrypt", gcm::encrypt_random, initid, args, length, is_null, error);
}

void gcm_encrypt_deinit(UDF_INIT *initid) { gcm::free_state(initid); }

bool gcm_encrypt_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  return encrypt_init(initid, args, message, kDetUsage, true);
}

/* Deterministic: same key, plaintext and AAD give the same envelope, which is
   what makes join keys and UNIQUE work. It reveals equality of plaintexts and
   MUST NOT be used for free text (spec/envelope.md §2.2). */
char *gcm_encrypt_det_udf(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length,
                          unsigned char *is_null, unsigned char *error) {
  return encrypt_row("gcm_encrypt_det", gcm::encrypt_det, initid, args, length, is_null, error);
}

void gcm_encrypt_det_deinit(UDF_INIT *initid) { gcm::free_state(initid); }

}  // extern "C"
