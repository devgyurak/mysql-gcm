/* SPDX-License-Identifier: GPL-2.0-only */
#include "envelope.h"

#include <cstring>

namespace gcm {
namespace {

/* The suite table (design A10). AES-256 is first because it is the default and
   the overwhelmingly common case, so the common lookup is one comparison. */
constexpr Suite kSuites[] = {
    {kKeyLen256, kVersionRandom, kVersionDet},
    {kKeyLen192, kVersionRandom192, kVersionDet192},
    {kKeyLen128, kVersionRandom128, kVersionDet128},
};

}  // namespace

const Suite *suite_for_key_len(size_t key_len) {
  for (const Suite &suite : kSuites) {
    if (suite.key_len == key_len) return &suite;
  }
  return nullptr;
}

const Suite *suite_for_version(unsigned char version) {
  for (const Suite &suite : kSuites) {
    if (suite.version_random == version || suite.version_det == version) return &suite;
  }
  return nullptr;
}

const char *error_name(Error err) {
  switch (err) {
    case Error::ok:
      return "ok";
    case Error::bad_envelope:
      return "bad_envelope";
    case Error::bad_tag:
      return "bad_tag";
    case Error::bad_key_len:
      return "bad_key_len";
    case Error::rng:
      return "rng";
    case Error::openssl:
      return "openssl";
  }
  return "unknown";
}

Error parse(Bytes envelope, ParsedEnvelope *out) {
  if (out == nullptr) return Error::bad_envelope;
  if (envelope.data == nullptr || envelope.size < kVersionLen) return Error::bad_envelope;

  const unsigned char version = envelope.data[0];
  if (suite_for_version(version) != nullptr) {
    /* Compare before subtracting: `size - kGcmOverhead` on a short envelope
       would wrap around on size_t and hand out a huge body. */
    if (envelope.size < kMinGcmLen) return Error::bad_envelope;
    const size_t body_len = envelope.size - kGcmOverhead;
    out->version = version;
    out->nonce = Bytes{envelope.data + kVersionLen, kNonceLen};
    out->body = Bytes{envelope.data + kVersionLen + kNonceLen, body_len};
    out->tag = Bytes{envelope.data + kVersionLen + kNonceLen + body_len, kTagLen};
    return Error::ok;
  }

  if (version == kVersionLegacyCbc) {
    if (envelope.size < kMinCbcLen) return Error::bad_envelope;
    const size_t body_len = envelope.size - kVersionLen - kIvLen;
    if (body_len % kCbcBlockLen != 0) return Error::bad_envelope;
    out->version = version;
    out->nonce = Bytes{envelope.data + kVersionLen, kIvLen};
    out->body = Bytes{envelope.data + kVersionLen + kIvLen, body_len};
    out->tag = Bytes{nullptr, 0};  // design A3: v1 has no tag
    return Error::ok;
  }

  return Error::bad_envelope;  // reserved version: never silently accepted
}

size_t write_gcm_header(unsigned char version, const unsigned char *nonce, unsigned char *out) {
  out[0] = version;
  std::memcpy(out + kVersionLen, nonce, kNonceLen);
  return kVersionLen + kNonceLen;
}

}  // namespace gcm
