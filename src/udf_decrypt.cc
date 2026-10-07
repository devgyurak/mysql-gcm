/* SPDX-License-Identifier: GPL-2.0-only */
/* gcm_decrypt: argument checks, the utf8mb4 result tag that makes native LIKE
   work, and the one place gcm.strict changes an outcome.
   The envelope and the cryptography live in gcm.cc (component-src rule). */

#include <cstddef>

#include <mysql/udf_registration_types.h>

#include "gcm.h"
#include "udf_glue.h"

namespace {

using gcm::Bytes;
using gcm::Error;
using gcm::UdfState;

constexpr const char kUsage[] = "gcm_decrypt(ciphertext, key [, aad]) needs 2 or 3 arguments";

}  // namespace

extern "C" {

bool gcm_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (gcm::init_args(args, message, kUsage, 2, 3)) return true;

  /* All three inputs are opaque bytes; only the *result* is text. */
  if (gcm::init_argument_charset(args, message, 0, "binary")) return true;
  if (gcm::init_argument_charset(args, message, 1, "binary")) return true;
  if (gcm::init_argument_charset(args, message, 2, "binary")) return true;

  /* The whole point of the project: tagging the result utf8mb4 lets MySQL's own
     collation drive LIKE '%길%' instead of reimplementing it in C (design §5.3).
     If this is skipped or set to binary, Korean partial match silently returns 0. */
  if (gcm::init_result_charset(initid, message, "utf8mb4")) return true;

  initid->maybe_null = true; /* NULL arguments, and gcm.strict=OFF on tag failure */
  initid->const_item = false;
  /* No conversion widening here, unlike the encrypt side: the ciphertext argument is
     requested as `binary`, so the server hands it over byte for byte, and a plaintext
     is always shorter than the envelope it came from. */
  initid->max_length = args->lengths[0];
  if (gcm::init_state(initid, message)) return true;
  /* design A11: one EVP context and key schedule per UDF item instead of per row.
     On failure the glue releases the state allocated above, since the server skips
     deinit after a failed init. */
  return gcm::init_decrypt_session(initid, message);
}

char *gcm_decrypt_udf(UDF_INIT *initid, UDF_ARGS *args, char *, unsigned long *length,
                      unsigned char *is_null, unsigned char *error) {
  auto *state = reinterpret_cast<UdfState *>(initid->ptr);

  if (gcm::any_arg_is_null(args)) {
    *is_null = 1;
    return nullptr;
  }

  const Bytes envelope = gcm::arg_bytes(args, 0);
  const Bytes key = gcm::arg_bytes(args, 1);
  const Bytes aad = gcm::optional_arg_bytes(args, 2);

  if (gcm::too_long(envelope.size) || gcm::too_long(aad.size)) {
    gcm::raise_too_long("gcm_decrypt", envelope.size > aad.size ? envelope.size : aad.size);
    *error = 1;
    return nullptr;
  }

  if (gcm::reserve(state, gcm::decrypt_out_len(envelope.size) + 1)) {
    gcm::raise_message("gcm_decrypt", "out of memory");
    *error = 1;
    return nullptr;
  }

  size_t out_len = 0;
  const Error err =
      gcm::decrypt_with_session(state->decrypt, key, envelope, aad, state->out, &out_len);

  /* The only failure gcm.strict governs. The core has already wiped the output
     buffer and forgotten the key, so no unauthenticated plaintext can leave either
     way (spec/envelope.md §4 rule 1). */
  if (err == Error::bad_tag && !state->strict) {
    *is_null = 1;
    return nullptr;
  }
  if (err != Error::ok) {
    /* bad_envelope and bad_key_len stay errors under strict=OFF: corrupt data
       and misconfiguration are not hidden by a setting (§4 rule 2). */
    gcm::raise("gcm_decrypt", err, key.size, envelope.size);
    *error = 1;
    return nullptr;
  }

  *length = static_cast<unsigned long>(out_len);
  return reinterpret_cast<char *>(state->out);
}

void gcm_decrypt_deinit(UDF_INIT *initid) { gcm::free_state(initid); }

}  // extern "C"
