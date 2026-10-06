---
paths:
  - "src/**"
  - "tests/unit/**"
  - "**/*.cc"
  - "**/*.h"
---
<!-- Generated from .agents/rules/stack-cpp.md by scripts/agents-sync.py — edit the source. -->
# C++ / CMake / OpenSSL conventions

- C++17, with the same flags as the server tree. No dependence on exceptions or RTTI. `-Werror`.
- Manage OpenSSL handles with RAII wrappers, following the
  `std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>` pattern. Raw `new`/`delete` and
  direct `malloc` are confined to the `initid->ptr` result buffer, paired in `deinit`.
- Return errors as `enum class GcmError { ok, bad_envelope, bad_tag, key_unavailable, openssl_failure, ... }`.
  No string errors — that is how data ends up in a message.
- Bytes are `std::span<const unsigned char>`, or a `const unsigned char *, size_t` pair where C++20 is
  not available. Do not move binary data around in a `std::string`.
- Constants live in one place (`envelope.h`) as `constexpr`: `kVersionRandom`, `kVersionDet`,
  `kNonceLen=12`, `kTagLen=16`.
- Static analysis: `clang-tidy` (`bugprone-*, cert-*, clang-analyzer-*, performance-*`) and
  `clang-format` (based on the Google style, copying the server tree's `.clang-format`). Enforced in CI.
  - **One deliberate deviation**: `ColumnLimit` is **100**, not the server tree's 80. This repository's
    code is written to 100, and refolding it to 80 splits the EVP calls and the longer signatures badly
    enough to bury real changes in mechanical diff. The same note is at the head of `.clang-format`.
    Do not revert it; if you want to change it, do the whole reformat as its own commit.
- The deviation is acceptable because the goal is not to contribute this code to the upstream server
  tree. Every other setting stays identical to that tree.
- Header include order: own header → C standard → C++ standard → OpenSSL → MySQL service headers. The
  allowed dependencies and the boundary around server headers follow `architecture.md`.
- Comments say **why** only, and cite the design document section
  (`// design.md §5.5: tag failure must not degrade to NULL`).
