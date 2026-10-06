# mysql-gcm — AGENTS.md

An open-source project that adds AES-256-GCM encryption and decryption functions to MySQL 8.0+ as a
server **component**. Codex, Cursor and OpenCode read this file directly; Claude Code reads it through
the import in `CLAUDE.md`. The full rationale is `docs/design.md` (including amendment A1).
**To change the design, amend that document first and then change the code.**

## 1. One-line summary

MySQL has no GCM in `block_encryption_mode` (measured on 8.4 and 9.4; MariaDB is the same).
The builtins cannot be overridden, so this **registers functions under new names as a component**,
**takes the key as a SQL argument** exactly as `AES_ENCRYPT` does, and **tags the decrypted result with
a charset** so partial-match search survives through MySQL's native `LIKE`.

## 2. Public surface (a change updates `docs/design.md`, `spec/` and the server tests in the same PR)

```
gcm_encrypt(plaintext, key [, aad])       -> BLOB     random nonce (RAND_bytes, 12 B)
gcm_encrypt_det(plaintext, key [, aad])   -> BLOB     deterministic — joins, UNIQUE and exact match only
gcm_decrypt(ciphertext, key [, aad])      -> VARCHAR  tagged charset utf8mb4 → native LIKE works
```

- `key`: 32 binary bytes (AES-256) or 16 (AES-128). Any other length is an error (`AES_ENCRYPT`'s key
  folding is not reproduced). **The key length selects the suite and nothing else does** (amendment
  A10). AES-192 is allocated but not implemented, so 24 bytes is an error.
- Deterministic nonce: `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`,
  `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`.
- Envelope (the normative definition is `spec/envelope.md`):

```
0x01  legacy CBC (dual-read only; never produced)
0x02  AES-256-GCM random        : 0x02 || nonce(12) || ciphertext || tag(16)
0x03  AES-256-GCM deterministic : 0x03 || nonce(12) || ciphertext || tag(16)
0x04  AES-128-GCM random        : same layout (amendment A10)
0x05  AES-128-GCM deterministic : same layout (amendment A10)
0x06  0x07  allocated to AES-192, NOT implemented -- rejected as bad_envelope
```

  The deterministic nonce is an HMAC of the plaintext and therefore cannot be recomputed at decryption
  time, so it is **stored** in the envelope (settled by amendment A2).
- sysvars: `gcm.strict` (GLOBAL + SESSION, default ON) — on a tag mismatch, ON gives an error and OFF
  gives NULL; the session scope is 9.0+ only (amendment A5). And `gcm.min_key_bytes` (GLOBAL, default
  32) — the smallest key the two encryption functions accept, which is what keeps a truncated key
  from silently selecting AES-128; decryption ignores it (amendment A10). In my.cnf both take the
  `loose_` prefix.
- Withdrawn (amendment A1): keyring integration, `gcm.key_id`, `gcm.nonce_key_id`, `gcm_key_id()`. If
  asked for one, turn it back into a proposal to amend the design.

## 3. Repository layout

```
AGENTS.md / CLAUDE.md          Agent instructions (this file is the source)
.agents/rules/                 Rule sources, shared across tools
.agents/skills/                Skill sources, shared across tools
docs/design.md                 The design document (the source of rationale, including amendment A1)
docs/design-KO.md              Its Korean translation. The English file above is canonical
docs/ops-constraints.md        Operational constraints — also duplicated on the README's first screen
spec/envelope.md               The settled envelope and failure semantics (Phase 1)
spec/test-vectors.json         NIST CAVP GCM KAT plus the project's own vectors. The common reference for the server tests
src/                           The component (C++17)
  CMakeLists.txt               MYSQL_ADD_COMPONENT — copied into the server tree as components/gcm and built there
  component.cc                 DECLARE_COMPONENT, the REQUIRES_SERVICE list, init/deinit (including registration rollback)
  udf_encrypt.cc udf_decrypt.cc   The UDF glue — argument validation, charset tagging and error translation only
  udf_glue.{h,cc}              Arguments, buffers and error translation shared by the two UDF glues (no crypto logic)
  gcm.{h,cc}                   The OpenSSL EVP wrapper (no server header dependency → unit testable)
  envelope.{h,cc}              Envelope encoding and decoding (does not depend on OpenSSL either)
  nonce.{h,cc}                 The synthetic nonce and the nonce_key derivation (EVP_MAC HMAC-SHA256)
  sysvar.{h,cc}                Registering and reading gcm.strict — the session scope is 9.0+ only (amendment A5)
tests/unit/                    GoogleTest — gcm/envelope/nonce, linking libcrypto alone with no server
tests/integration/             Real-server SQL scenarios on docker (sql + expected)
mysql-test/suite/gcm/          MTR .test/.result (run from a server source tree build)
tests/e2e/                     compose: mysql (ROW) + replica + a Python SQL runner → LIKE / replication / dual-read
tests/load/                    Load: decrypt + LIKE over 10k/100k/300k rows, with a regression gate against AES_DECRYPT
tests/bench/                   Core micro-benchmarks (Google Benchmark) — ratios against bare EVP. No server
tests/adapter/                 The component install and uninstall paths — failure injected through stub services, inside the build image
scripts/                       dev-up.sh, build-in-docker.sh, verify.sh, verify.sql, mtr.sh, agents-sync.sh
  bench.sh                     Builds and runs the core micro-benchmarks and the ratio gate
  adapter-tests.sh             Verifies the install and uninstall paths against stub services (reusing the build image)
  unit-in-docker.sh            Runs the unit tests on the same GCC and ubuntu as CI (catching what the host clang lets through)
  smoke-image.sh               Starts and queries the release server image (component installed, major, Korean LIKE, strict)
  check-action-pins.py         Checks that every action in the workflows is pinned by SHA
  gen-vectors.py               The internal vector generation and verification tool (cryptography; not a shipped API)
  check-architecture.py        Checks the core dependency and test entry point boundaries (amendment A6)
docker/                        build.Dockerfile (a configured server source tree) + build-component.sh + versions.json
docs/perf.md                   Accumulated load measurements — replacing design §1.2's estimates with measured numbers
CHANGELOG.md                   Changes per release. An envelope change comes with a compatibility note
.github/workflows/             CI (lint · unit · build matrix · integration (smoke) · mtr and adapter (path-filtered)
                               · e2e · load (nightly) · bench (on merges) · release (on tags))
```

## 4. Build and verification commands (the skills hold the detail)

| Purpose | Command | Skill |
|---|---|---|
| Start a development server | `scripts/dev-up.sh 8.4` | `dev-container` |
| Build the component (in a server source tree) | `scripts/build-in-docker.sh 8.4` | `mysql-component` |
| Unit tests | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` | `unit-tests` |
| Integration smoke | `scripts/verify.sh 8.4` (installs the .so in a container, then diffs the SQL scenarios) | `integration-tests` |
| MTR | `scripts/mtr.sh 8.4` (`GCM_RECORD=1` re-records the `.result` files) | `integration-tests` |
| E2E | `docker compose -f tests/e2e/compose.yml up --exit-code-from runner` | `e2e-load-tests` |
| Load | `python tests/load/run.py --rows 300000 --baseline aes` | `e2e-load-tests` |
| Micro-benchmarks | `scripts/bench.sh [--gate]` | `.agents/rules/testing.md` |
| Adapter (install/uninstall) | `scripts/adapter-tests.sh 8.4` | `.agents/rules/testing.md` |
| Vector reproducibility | `python scripts/gen-vectors.py --check` (after installing `scripts/requirements.txt`) | `unit-tests` |
| Architecture boundaries | `python3 scripts/check-architecture.py` | `.agents/rules/architecture.md` |

If a command does not exist yet (Phase S), **create it as that skill prescribes**. Do not introduce a
different build method on your own.

## 5. Absolute rules (the full text is in `.agents/rules/`)

**Crypto (`crypto-safety.md`, always applies)**
- Fetch by name with `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)`. Never call the `EVP_aes_256_gcm()`
  symbol directly.
- Use the libcrypto the server has loaded. No static linking and no bundling of another version.
- Never put a key, plaintext or nonce in a log, an error message or an assertion string.
  `OPENSSL_cleanse` the key and plaintext buffers.
- A tag verification failure is an error when `gcm.strict=ON`. Do not swallow it as NULL. Never return
  unauthenticated plaintext.
- The key length is exactly 32 bytes. Do not make it fit by folding, padding or hashing.
- Do not put a key in a repository file, a configuration file, an environment variable or a test
  fixture (the spec vectors excepted).

**Architecture (`architecture.md`)**
- The direction is server adapter → core (`gcm` → `envelope`/`nonce`). The core does not depend on
  MySQL.
- SQL policy lives in the UDFs and server version differences in the adapters. Keep the component,
  `UDF_INIT` and operation lifetimes distinct, and do not expose a test bypass through SQL.

**Component (`component-src.md`)**
- The legacy UDF plugin API (`mysql_declare_plugin`, `CREATE FUNCTION ... SONAME`) is forbidden.
  Components and the `udf_registration` service only.

**Tests (`testing.md`)**
- Every test is **GWT (Given-When-Then)**, with given/when/then visible in the name too.
- Do not add logic or branching such as `if`, `else`, `for` or `while` to a test case body. Split the
  cases per condition or use the framework's parameterisation.
- A behaviour-change PR brings unit *and* integration tests. An envelope or nonce change updates
  `spec/test-vectors.json` and comes with the server vector tests.
- The Korean partial-match integration test `LIKE '%길%'` must never be deleted (it is the reason the
  project exists).

**Product scope and the Python tooling (amendment A4)**
- What ships is the MySQL component and its SQL API. Do not build a Python or Java encryption
  client/SDK.
- Applications call the SQL functions through their existing MySQL driver. Driver integration is out of
  scope.
- Python is used only for vector generation and verification and for the SQL E2E and load runners.
  Vector generation uses `cryptography` only; hand-rolled crypto primitives are forbidden.
- `scripts/gen-vectors.py` is an internal tool and exposes no public encrypt/decrypt/parse API. The E2E
  runner does its encryption and decryption through the server's SQL functions.

**Review (`code-review.md`)**
- Comment priorities are **P1 (blocks the merge) / P2 (resolve before merge) / P3 (optional)**, plus
  `Q` for a question.
- A PR touching the crypto, envelope or sysvar paths needs a `crypto-reviewer` pass and two human
  reviewers.

## 6. Current phase and roadmap

Current: **Phase 4 (distribution) — waiting to tag 0.1.0**. Phases S, 1, 2 and 3 are complete and the
results are in `docs/design.md` §8. The load baseline was settled from three CI runner measurements and
is recorded in `docs/perf.md` and `tests/load/baseline.json`, and the release pipeline was verified
end-to-end with a dry run (`gh workflow run release.yml -f version=...`). What remains is the tag itself
and the Docker Hub secrets. The MTR `.result` files were recorded with `scripts/mtr.sh 8.4` and are in
`mysql-test/suite/gcm/r/` (against 8.4 — the other majors were not recorded).

| Phase | Deliverable | Done when |
|---|---|---|
| S spike | A minimal component passing `scripts/verify.sql` | 32-byte key argument validation · `SET SESSION gcm.strict` · Korean LIKE · `Created_tmp_disk_tables` observed · `EVP_CIPHER_fetch` succeeds — results recorded in `docs/design.md` §8 |
| 1 spec | `spec/envelope.md`, `spec/test-vectors.json` | The byte format and failure semantics the implementation and tests will follow are settled |
| 2 implementation | `src/`, `tests/unit`, `mysql-test/suite/gcm`, `tests/integration` | CI green, including the nonce collision boundary test |
| 3 SQL E2E | SQL usage examples, `tests/e2e` | The server SQL round trip, Korean LIKE, replication and dual-read checks pass |
| 4 distribution | The build matrix, README, `docs/ops-constraints.md`, the load baseline | Release artifacts plus checksums and an SBOM |
| 5 upstream | A feature request | Optional |

## 7. Where each tool's agent configuration lives

There is one source for each concept and the rest are adapters **generated by
`scripts/agents-sync.sh`**. Edit the source, re-run the script, and CI (`lint.yml`) checks with
`--check` that no adapter is stale. Never edit a generated file.

| Concept | Source | Claude Code | Codex | Cursor | OpenCode |
|---|---|---|---|---|---|
| Project instructions | `AGENTS.md` | `CLAUDE.md` (`@AGENTS.md`) | native, plus nested `AGENTS.md` | native | native |
| Path rules | `.agents/rules/*.md` | `.claude/rules/*.md` (generated, preserving `paths:` and the body) | nested `AGENTS.md` referencing the source | `.cursor/rules/*.mdc` (generated, with an `@` reference) | `opencode.json` `instructions` referencing the source |
| Skills | `.agents/skills/*/SKILL.md` | `.claude/skills` → symlink | native | `.cursor/skills` → symlink | native (discovers `.agents/skills`) |
| Subagents | `.claude/agents/*.md` | native | `.codex/agents/*.toml` (generated, read-only via `sandbox_mode`) | `.cursor/agents` → symlink | `.opencode/agents/*.md` (generated, read-only via `permission`) |
| Permissions and hooks | `.claude/settings.json` + `.claude/hooks/guard.sh` | native | `sandbox_mode` (per agent) | — | `opencode.json` `permission` (global) plus per-agent `permission` |

## 8. When to use a skill or a subagent

| Situation | Use |
|---|---|
| Before touching component sources, a service API or the build | the `mysql-component` and `sysvar-config` skills |
| Writing or changing EVP, envelope or nonce code | the `gcm-crypto` skill → then the `crypto-reviewer` subagent |
| When a server API signature is uncertain | the `component-api-researcher` subagent (no guessing — check the headers) |
| Writing tests | the `unit-tests` / `integration-tests` / `e2e-load-tests` skills |
| When core performance is a concern | `scripts/bench.sh --gate` → numbers go in `docs/perf.md`. A gate change needs its justification in the PR |
| Local verification, the Phase S checks | the `dev-container` skill → the `verify-runner` subagent |
| Generating or verifying vectors | the `unit-tests` skill, plus `crypto-reviewer` for a change to the crypto construction |
| Reviewing a PR | the `code-review` skill → the `code-reviewer` subagent (plus `crypto-reviewer`) |
| CI and release workflows | the `ci-release` skill |
| Checking a per-stack convention | `.agents/rules/stack-*.md` |

## 9. How to work

- Read the relevant section of `docs/design.md` before starting. If you need a judgement that differs
  from the design, propose a document amendment instead of writing the code.
- Confirm an unfamiliar MySQL or OpenSSL API **against the headers and the official documentation**. Do
  not guess a signature and ship code that does not compile.
- Commits: Conventional Commits (`feat(component): ...`, `fix(crypto): ...`, `test(mtr): ...`,
  `ci: ...`, `docs: ...`). One commit, one concern.
- PRs: fill in every item of `.github/PULL_REQUEST_TEMPLATE.md`. Split a diff over 400 net lines.
- **English first.** Everything committed — code, comments, commit messages, PR descriptions,
  documents, specs — is written in English. A document may carry a translation named
  `{document}-{LANG}.md` (`README-KO.md`, `docs/design-KO.md`); the English file is canonical and both
  change in the same PR. Only those two documents are translated — not the rules, the skills or
  `spec/`. Korean strings in tests are **data** (`'홍길동'`, `LIKE '%김%'`) and are never translated.
  Full rule: `.agents/rules/docs.md`. **Conversation with the user is in Korean**, which is a separate
  matter from what gets committed.
- Managed MySQL, proxies, key management systems themselves and keyring integration are out of scope.
  If asked for one, turn it back into a proposal to amend the design.
