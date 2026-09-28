/* SPDX-License-Identifier: GPL-2.0-only */
/* Loader for spec/test-vectors.json, the single source of vectors for this suite.
   The generator in scripts/gen-vectors.py writes that file and re-checks it; no
   language-specific client consumes it (docs/design.md amendment A4). A missing or
   unreadable file is a test failure, never a skip (testing rule). */

#ifndef MYSQL_GCM_TESTS_VECTORS_H
#define MYSQL_GCM_TESTS_VECTORS_H

#include <string>
#include <vector>

namespace gcm_test {

struct Vector {
  std::string id;
  std::string kind;  // nist | random | det | legacy
  std::vector<unsigned char> key;
  std::vector<unsigned char> nonce_key;  // empty when absent
  std::vector<unsigned char> nonce;      // empty when absent
  std::vector<unsigned char> aad;
  std::vector<unsigned char> plaintext;
  std::vector<unsigned char> envelope;
  std::string expect;  // ok | bad_tag | bad_envelope | bad_key_len
  bool has_nonce_key = false;
  bool has_nonce = false;
};

/* All vectors, in file order. Aborts the process if the file is missing. */
const std::vector<Vector> &all_vectors();

/* Vectors filtered by `expect`, and by kind when `kind` is not empty. */
std::vector<Vector> vectors_where(const std::string &expect, const std::string &kind = "");

/* Single vector by id; fails the test if absent. */
const Vector &vector_by_id(const std::string &id);

std::string to_hex(const unsigned char *data, size_t size);

}  // namespace gcm_test

#endif  // MYSQL_GCM_TESTS_VECTORS_H
