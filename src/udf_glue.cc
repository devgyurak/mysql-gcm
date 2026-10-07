/* SPDX-License-Identifier: GPL-2.0-only */
#include "udf_glue.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/mysql_runtime_error_service.h>
#include <mysql/components/services/udf_metadata.h>
#include <mysqld_error.h>

#include "gcm.h"
#include "sysvar.h"

extern REQUIRES_SERVICE_PLACEHOLDER(mysql_udf_metadata);

namespace gcm {
namespace {

/* The buffer the server hands an init function is MYSQL_ERRMSG_SIZE bytes. That macro
   lives in mysql_com.h, which a component must not include — my_io.h behind it fails
   the build outright on 9.x with "This header shall not be included in components" —
   so the value is mirrored here instead of being pulled in. */
constexpr size_t kInitMsgLen = 512;

}  // namespace

bool init_args(UDF_ARGS *args, char *msg, const char *usage, unsigned min_args, unsigned max_args) {
  if (args->arg_count < min_args || args->arg_count > max_args) {
    snprintf(msg, kInitMsgLen, "%s", usage);
    return true;
  }
  /* The key check cannot move here: an argument need not be constant, so its
     length is only known per row (component-src rule). */
  for (unsigned i = 0; i < args->arg_count; ++i) args->arg_type[i] = STRING_RESULT;
  return false;
}

bool init_result_charset(UDF_INIT *initid, char *msg, const char *charset) {
  if (mysql_service_mysql_udf_metadata->result_set(initid, "charset",
                                                   const_cast<char *>(charset))) {
    snprintf(msg, kInitMsgLen, "cannot set the result charset to %s", charset);
    return true;
  }
  return false;
}

bool init_argument_charset(UDF_ARGS *args, char *msg, unsigned index, const char *charset) {
  if (index >= args->arg_count) return false;
  if (mysql_service_mysql_udf_metadata->argument_set(args, "charset", index,
                                                     const_cast<char *>(charset))) {
    snprintf(msg, kInitMsgLen, "cannot set argument %u charset to %s", index, charset);
    return true;
  }
  return false;
}

bool init_argument_collation(UDF_ARGS *args, char *msg, unsigned index, const char *collation) {
  if (index >= args->arg_count) return false;
  if (mysql_service_mysql_udf_metadata->argument_set(args, "collation", index,
                                                     const_cast<char *>(collation))) {
    snprintf(msg, kInitMsgLen, "cannot set argument %u collation to %s", index, collation);
    return true;
  }
  return false;
}

bool init_state(UDF_INIT *initid, char *msg) {
  auto *state = static_cast<UdfState *>(std::calloc(1, sizeof(UdfState)));
  if (state == nullptr) {
    snprintf(msg, kInitMsgLen, "out of memory");
    return true;
  }
  /* Read once per statement, not per row: see sysvar.h. Both are read for every
     UDF; gcm_decrypt ignores the floor, which is the point — raising the policy
     must never lock out data written under a lower one (design A10). */
  state->strict = strict_enabled();
  state->min_key_bytes = min_key_bytes();
  initid->ptr = reinterpret_cast<char *>(state);
  return false;
}

void free_state(UDF_INIT *initid) {
  auto *state = reinterpret_cast<UdfState *>(initid->ptr);
  if (state == nullptr) return;
  if (state->out != nullptr) {
    wipe(state->out, state->capacity);  // the last plaintext lives here
    std::free(state->out);
  }
  std::free(state);
  initid->ptr = nullptr;
}

bool reserve(UdfState *state, size_t need) {
  if (state->capacity >= need) return false;

  /* Grown, never realloc'd: realloc may copy and free the old block, which
     would leave an unwiped copy of the plaintext behind. */
  auto *fresh = static_cast<unsigned char *>(std::calloc(need, 1));
  if (fresh == nullptr) return true;
  if (state->out != nullptr) {
    wipe(state->out, state->capacity);
    std::free(state->out);
  }
  state->out = fresh;
  state->capacity = need;
  return false;
}

bool any_arg_is_null(const UDF_ARGS *args) {
  for (unsigned i = 0; i < args->arg_count; ++i) {
    if (args->args[i] == nullptr) return true;
  }
  return false;
}

Bytes arg_bytes(const UDF_ARGS *args, unsigned index) {
  return Bytes{reinterpret_cast<const unsigned char *>(args->args[index]), args->lengths[index]};
}

Bytes optional_arg_bytes(const UDF_ARGS *args, unsigned index) {
  if (index >= args->arg_count) return Bytes{nullptr, 0};
  return arg_bytes(args, index);
}

void raise(const char *func, Error err, size_t key_len, size_t envelope_len) {
  char detail[192];
  switch (err) {
    case Error::bad_key_len:
      snprintf(detail, sizeof(detail),
               "key must be %zu bytes (AES-256), %zu (AES-192) or %zu (AES-128), and on "
               "decryption must match the envelope version; got %zu",
               kKeyLen256, kKeyLen192, kKeyLen128, key_len);
      break;
    case Error::bad_envelope:
      snprintf(detail, sizeof(detail), "malformed or unsupported envelope (length %zu)",
               envelope_len);
      break;
    case Error::bad_tag:
      snprintf(detail, sizeof(detail), "authentication tag verification failed");
      break;
    case Error::rng:
      snprintf(detail, sizeof(detail), "the CSPRNG failed");
      break;
    case Error::openssl:
    case Error::ok:
      snprintf(detail, sizeof(detail), "an OpenSSL operation failed");
      break;
  }
  raise_message(func, detail);
}

void raise_below_floor(const char *func, size_t key_len, size_t floor) {
  char detail[192];
  snprintf(detail, sizeof(detail),
           "key of %zu bytes is below gcm.min_key_bytes = %zu; decryption of existing "
           "data is unaffected",
           key_len, floor);
  raise_message(func, detail);
}

void raise_too_long(const char *func, size_t len) {
  char detail[192];
  snprintf(detail, sizeof(detail), "argument is %zu bytes, above the %zu byte limit", len,
           kMaxArgLen);
  raise_message(func, detail);
}

void raise_message(const char *func, const char *detail) {
  /* ER_UDF_ERROR is "%s UDF failed; %s". */
  mysql_error_service_printf(ER_UDF_ERROR, 0, func, detail);
}

}  // namespace gcm
