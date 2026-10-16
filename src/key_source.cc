/* SPDX-License-Identifier: GPL-2.0-only */
#include "key_source.h"

#include <cstring>

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/keyring_reader_with_status.h>
#include <mysql/components/services/mysql_current_thread_reader.h>
#include <mysql/components/services/security_context.h>
#include <mysql/mysql_lex_string.h>

#include "gcm.h"

extern REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_thd_security_context);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_security_context_options);
extern REQUIRES_SERVICE_PLACEHOLDER(keyring_reader_with_status);

namespace gcm {
namespace {

/* The only keyring type accepted. keyring_key_generate('id', 'AES', n) stores it. */
constexpr char kAesType[] = "AES";
constexpr size_t kAesTypeLen = sizeof(kAesType) - 1;

}  // namespace

KeySource caller_account(CallerAccount *out) {
  out->len = 0;
  out->text[0] = '\0';

  MYSQL_THD thd = nullptr;
  if (mysql_service_mysql_current_thread_reader->get(&thd) || thd == nullptr) {
    return KeySource::no_account;
  }
  Security_context_handle ctx = nullptr;
  if (mysql_service_mysql_thd_security_context->get(thd, &ctx) || ctx == nullptr) {
    return KeySource::no_account;
  }
  MYSQL_LEX_CSTRING user{nullptr, 0};
  MYSQL_LEX_CSTRING host{nullptr, 0};
  if (mysql_service_mysql_security_context_options->get(ctx, "priv_user", &user) ||
      mysql_service_mysql_security_context_options->get(ctx, "priv_host", &host)) {
    return KeySource::no_account;
  }
  /* An anonymous account is not one principal (design A13). */
  if (user.str == nullptr || user.length == 0) return KeySource::no_account;
  /* An empty host is passed through, as keyring_udf does: "user@". */
  if (host.str == nullptr) host.length = 0;
  /* `>=`, not `>`: the '@' needs a byte too, and with `>` a user name of exactly
     kMaxAccountLen would make the subtraction below wrap. */
  if (user.length >= kMaxAccountLen || host.length > kMaxAccountLen - user.length - 1) {
    return KeySource::no_account;
  }
  /* The keyring service takes a C string, so an embedded NUL would silently name
     a different, shorter account. */
  if (std::memchr(user.str, '\0', user.length) != nullptr ||
      (host.length != 0 && std::memchr(host.str, '\0', host.length) != nullptr)) {
    return KeySource::no_account;
  }

  std::memcpy(out->text, user.str, user.length);
  out->text[user.length] = '@';
  if (host.length != 0) std::memcpy(out->text + user.length + 1, host.str, host.length);
  out->len = user.length + 1 + host.length;
  out->text[out->len] = '\0';
  return KeySource::ok;
}

KeySource fetch_key(const char *key_id, const CallerAccount &account, unsigned char *out,
                    size_t *out_len) {
  *out_len = 0;

  /* The caller has validated the id. This is for a caller that has not: the
     server's keyring asserts on an empty id in a debug build. */
  if (key_id == nullptr || key_id[0] == '\0') return KeySource::invalid_id;

  my_h_keyring_reader_object reader = nullptr;
  if (mysql_service_keyring_reader_with_status->init(key_id, account.text, &reader)) {
    return KeySource::unavailable;
  }
  /* Success with no reader object is how the service says "no such entry". */
  if (reader == nullptr) return KeySource::no_usable_key;

  KeySource result = KeySource::ok;
  size_t key_len = 0;
  size_t type_len = 0;
  unsigned char key[kKeyLen256];
  char type[kAesTypeLen + 1] = {0};

  if (mysql_service_keyring_reader_with_status->fetch_length(reader, &key_len, &type_len)) {
    result = KeySource::unavailable;
  } else if (suite_for_key_len(key_len) == nullptr || type_len != kAesTypeLen) {
    /* Decided on the lengths alone, so this component never asks the reader for
       the bytes of an entry of another type or size. What a keyring backend loads
       into its own memory to answer the length call is the backend's business. */
    result = KeySource::no_usable_key;
  } else if (mysql_service_keyring_reader_with_status->fetch(reader, key, sizeof(key), &key_len,
                                                             type, sizeof(type), &type_len)) {
    result = KeySource::unavailable;
  } else if (suite_for_key_len(key_len) == nullptr || type_len != kAesTypeLen ||
             std::memcmp(type, kAesType, kAesTypeLen) != 0) {
    /* The lengths are checked again because they come from a second call. The
       server's reader holds its read lock from init to deinit, so the entry should
       not change in between — this is what happens if that is ever not so. */
    result = KeySource::no_usable_key;
  } else {
    std::memcpy(out, key, key_len);
    *out_len = key_len;
  }

  wipe(key, sizeof(key));
  /* Released here, on every path, never kept: see the header. A failed release
     leaves nothing this component can act on, so its result is not consulted and
     a key that was fetched successfully is still returned. */
  (void)mysql_service_keyring_reader_with_status->deinit(reader);
  return result;
}

}  // namespace gcm
