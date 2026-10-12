/* SPDX-License-Identifier: GPL-2.0-only */
/* gcm_key_usage: what the key-id functions have counted under one of the caller's
   key names (docs/design.md amendment A14).

   It reads the component's own table and nothing else — no keyring, no key. The
   answer is for the calling account only, the boundary amendment A13 already has.
   Read the amendment before treating a number here as a key's usage: it is one
   input to that, counted on this server since `since`. */

#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include <mysql/udf_registration_types.h>

#include "key_source.h"
#include "udf_glue.h"
#include "usage.h"

namespace {

constexpr char kFunc[] = "gcm_key_usage";
constexpr const char kUsage[] = "gcm_key_usage(key_id) needs 1 argument";

/* The longest answer: six labels and five 20-digit numbers. The server's result
   buffer for a string function is 255 bytes, which this stays well inside. */
constexpr unsigned long kMaxAnswerLen = 200;

}  // namespace

extern "C" {

bool gcm_key_usage_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (gcm::init_args(args, message, kUsage, 1, 1)) return true;
  /* The id as the key-id functions take it, so one spelling names one row. */
  if (gcm::init_argument_charset(args, message, 0, "utf8mb4")) return true;
  if (gcm::init_result_charset(initid, message, "utf8mb4")) return true;

  initid->maybe_null = true; /* a NULL argument propagates */
  /* Never folded: the answer changes as statements finish. */
  initid->const_item = false;
  initid->max_length = kMaxAnswerLen;
  return false;
}

char *gcm_key_usage_udf(UDF_INIT *, UDF_ARGS *args, char *result, unsigned long *length,
                        unsigned char *is_null, unsigned char *error) {
  if (args->args[0] == nullptr) {
    *is_null = 1;
    return nullptr;
  }
  const char *id = args->args[0];
  const size_t id_len = args->lengths[0];
  if (id_len == 0 || id_len > gcm::kMaxKeyIdLen || std::memchr(id, '\0', id_len) != nullptr) {
    gcm::raise_message(kFunc, "the key id must be 1 to 255 bytes without a NUL byte");
    *error = 1;
    return nullptr;
  }

  gcm::CallerAccount account;
  if (gcm::caller_account(&account) != gcm::KeySource::ok) {
    gcm::raise_message(kFunc, "the calling account could not be established");
    *error = 1;
    return nullptr;
  }

  gcm::UsageAnswer answer{};
  if (!gcm::usage_read(gcm::UsageName{account.text, account.len, id, id_len}, &answer)) {
    gcm::raise_message(kFunc, "usage counting is not available");
    *error = 1;
    return nullptr;
  }

  /* Numbers and fixed labels only: nothing from the argument or the account goes
     into the text, so there is nothing to escape. */
  const int written =
      snprintf(result, kMaxAnswerLen + 1,
               "{\"random_seals\":%" PRIu64 ",\"det_seals\":%" PRIu64 ",\"bytes_sealed\":%" PRIu64
               ",\"tag_failures\":%" PRIu64 ",\"since\":%" PRId64 ",\"complete\":%s}",
               answer.counts.random_seals, answer.counts.det_seals, answer.counts.bytes_sealed,
               answer.counts.tag_failures, answer.since, answer.complete ? "true" : "false");
  *length = static_cast<unsigned long>(written);
  return result;
}

void gcm_key_usage_deinit(UDF_INIT *) {}

}  // extern "C"
