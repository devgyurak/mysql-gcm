/* SPDX-License-Identifier: GPL-2.0-only */
#include "vectors.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace gcm_test {
namespace {

std::vector<unsigned char> from_hex(const std::string &hex) {
  if (hex.size() % 2 != 0) throw std::runtime_error("odd-length hex: " + hex);
  std::vector<unsigned char> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    out.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string vectors_path() {
  const char *env = std::getenv("GCM_TEST_VECTORS");
  if (env != nullptr) return env;
  return std::string(GCM_REPO_ROOT) + "/spec/test-vectors.json";
}

std::vector<Vector> load() {
  const std::string path = vectors_path();
  std::ifstream in(path);
  if (!in) {
    std::fprintf(stderr, "cannot open %s (set GCM_TEST_VECTORS to override)\n", path.c_str());
    std::abort();  // a missing vector file is a failure, not a skip
  }
  nlohmann::json doc;
  in >> doc;

  std::vector<Vector> out;
  for (const auto &item : doc.at("vectors")) {
    Vector v;
    v.id = item.at("id").get<std::string>();
    v.kind = item.at("kind").get<std::string>();
    v.key = from_hex(item.at("key_hex").get<std::string>());
    v.aad = from_hex(item.at("aad_hex").get<std::string>());
    v.plaintext = from_hex(item.at("plaintext_hex").get<std::string>());
    v.envelope = from_hex(item.at("envelope_hex").get<std::string>());
    v.expect = item.at("expect").get<std::string>();
    if (item.contains("nonce_key_hex")) {
      v.nonce_key = from_hex(item.at("nonce_key_hex").get<std::string>());
      v.has_nonce_key = true;
    }
    if (item.contains("nonce_hex")) {
      v.nonce = from_hex(item.at("nonce_hex").get<std::string>());
      v.has_nonce = true;
    }
    out.push_back(std::move(v));
  }
  if (out.empty()) {
    std::fprintf(stderr, "%s contains no vectors\n", path.c_str());
    std::abort();
  }
  return out;
}

}  // namespace

const std::vector<Vector> &all_vectors() {
  static const std::vector<Vector> vectors = load();
  return vectors;
}

std::vector<Vector> vectors_where(const std::string &expect, const std::string &kind) {
  std::vector<Vector> out;
  for (const Vector &v : all_vectors()) {
    if (v.expect == expect && (kind.empty() || v.kind == kind)) out.push_back(v);
  }
  return out;
}

const Vector &vector_by_id(const std::string &id) {
  for (const Vector &v : all_vectors()) {
    if (v.id == id) return v;
  }
  std::fprintf(stderr, "no vector with id %s\n", id.c_str());
  std::abort();
}

std::string to_hex(const unsigned char *data, size_t size) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 0x0f]);
  }
  return out;
}

}  // namespace gcm_test
