<h1 align="center">mysql-gcm</h1>

<p align="center">
  <strong>AES-256-GCM for MySQL — as a server component, with server-side <code>LIKE</code> on the plaintext.</strong>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README-KO.md">한국어</a>
</p>

<p align="center">
  <img alt="MySQL 8.0 | 8.4 | 9.x" src="https://img.shields.io/badge/MySQL-8.0%20%7C%208.4%20%7C%209.x-4479A1?logo=mysql&logoColor=white">
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white">
  <img alt="OpenSSL 3" src="https://img.shields.io/badge/OpenSSL-3.x-721412?logo=openssl&logoColor=white">
  <img alt="status: Phase 2" src="https://img.shields.io/badge/status-Phase%202%20(implementation)-orange">
  <a href="LICENSE"><img alt="license: GPLv2" src="https://img.shields.io/badge/license-GPLv2-blue"></a>
</p>

`gcm_encrypt`, `gcm_encrypt_det` and `gcm_decrypt` are registered as a MySQL **component** (not a
legacy UDF plugin). The decrypted value is charset-tagged `utf8mb4`, so MySQL's own collation drives
`LIKE '%길%'` **inside the server** — keeping partial-match search on encrypted columns, which is the
reason this project exists. On a developer machine at 100,000 rows the server-side filter measures
**41 ms p95**, where `docs/design.md` §1.2 estimates ~1.1 s for pulling the same candidate set into
the application and decrypting it there. Those are indicative numbers, not a release baseline —
`docs/perf.md` says what was measured and on what.

> **Status: Phase 2 (implementation).** Builds in-tree against MySQL 8.0, 8.4 and 9.x, installs, and
> passes unit, integration, MTR, E2E and load suites. **Not released**: no published artifacts, no
> load baseline on reference hardware, no legal sign-off on the license. See `docs/design.md`.

## Read this first — operational constraints

These are properties of the approach, not a bug list, and none of them can be fixed by the component.
Full text and rationale: `docs/ops-constraints.md` and `docs/design.md` §6 with amendments A7, A8.

| Theme | Constraints |
|---|---|
| **Topology** — replication, promotion, sharding | 1, 14, 15 |
| **Keys and nonces** — budget, rotation, AAD policy, recovery | 7, 11, 12 |
| **Query behaviour** — optimizer, what determinism leaks | 5, 6 |
| **Data and versions** — legacy envelopes, charset, sysvar scope, argument shape | 8, 9, 10 |
| **Environment** — logs, managed services, my.cnf | 2, 3, 4 |
| **Scope of assurance** — what is checked and what is not | 13 |

1. **`gcm_encrypt` is non-deterministic**, so **ROW binlog is required**. Under statement-based
   replication a replica would compute a different nonce. Non-deterministic functions also cannot be
   used in generated columns or indexes.
2. **Keys and plaintext are SQL arguments**, so they can reach the general log, the slow log,
   `performance_schema.events_statements_*` and an SBR binlog. Search patterns like `'%김%'` are
   plaintext fragments too. This is the same exposure as `AES_ENCRYPT`; control log access.
3. **Self-managed MySQL only.** Managed services (RDS, Aurora, Cloud SQL) do not expose `plugin_dir`.
4. **Use `loose_` in my.cnf** (`loose_gcm.strict=ON`). Without the prefix the server refuses to start
   before the component is installed.
5. **The functions are opaque to the optimizer.** `WHERE gcm_decrypt(col, @k) LIKE '%김%'` scans the
   candidate set; selectivity has to come from other predicates.
6. **`gcm_encrypt_det` reveals equality of plaintexts.** It exists for join keys, UNIQUE constraints
   and exact-match lookups. Never use it for free text.
7. **One AAD convention per key.** `gcm_encrypt_det` derives its nonce from the plaintext alone, so
   the same plaintext under one key with two different AADs reuses a (key, nonce) pair and lets an
   observer of both values forge tags for that nonce. All deterministic calls using that key must
   use identical AAD bytes (or always empty AAD), across every server, column and application.
   Different AAD domains require different keys; ciphertext equality joins require the same key and AAD.
8. **Legacy `0x01` (CBC) envelopes are accepted but unauthenticated, and their plaintext must
   already be UTF-8.** Dual-read exists to migrate; a wrong key can return garbage rather than an
   error. Reject `0x01` once the migration is done. Because the result is tagged `utf8mb4` for every
   version and a v1 envelope never passed through the converting encryption path, a latin1 `Müller`
   returns as ill-formed bytes and `LIKE '%ller%'` silently yields 0. Convert the legacy column to
   `utf8mb4` before prefixing `0x01 || iv`. The conversion only applies to *character* arguments, so
   `gcm_encrypt(UNHEX('ff'), @k)` produces an ill-formed result on `0x02`/`0x03` too — encrypt text,
   not raw bytes, if the value has to be searchable.
9. **`gcm.strict` has no SESSION scope before MySQL 9.0.** Component system variables gained session
   scope in 9.0.0, so on 8.0 and 8.4 it is GLOBAL-only and `SET SESSION gcm.strict` is rejected by
   the server. The ON/OFF semantics are the same everywhere.
10. **Pass a stored value, not a freshly computed expression.** MySQL 8.0 and 8.4 hand a loadable
    function a stale view of some computed string arguments from the second row of a statement on, so
    `gcm_encrypt_det(CONCAT(name, id), @k)` can silently seal the wrong bytes. A column, a literal, a
    user variable or a bound parameter is always safe — that is what a driver sends. If you must
    compute in SQL, materialise the value first; `CAST` alone is not enough. Details and the
    per-version measurements: `docs/design.md` amendment A7.
11. **Define a per-key usage budget and rotation plan before deployment.** Account for encryption
    across all servers, columns and applications sharing a key. Have the limits reviewed for the
    nonce mode, message sizes and acceptable risk; this project has not established a universal
    safe usage limit. The component does not track usage or rotate keys. Rotation changes
    deterministic ciphertexts, so plan JOIN/UNIQUE migrations and retain access to keys needed by backups.
12. **Treat retries and recovery as part of nonce management.** Copying or restoring an existing
    envelope is not a new encryption. Calling `gcm_encrypt` again creates a fresh random nonce;
    deterministic retries reproduce the result only with the same key, plaintext and AAD. Never
    change only the AAD for a deterministic retry. Do not roll back key-usage accounting with a
    database restore. If cumulative usage or RNG-state safety is uncertain after recovery or process
    cloning, stop new writes with that key. Restore and verify safe RNG state across all writers
    before resuming with a freshly and independently generated key; key replacement alone does not
    repair duplicated RNG state.
13. **Security rules are not runtime monitoring.** The component validates inputs and authentication
    tags, but does not detect nonce reuse, enforce a cross-call AAD policy, or enforce key-usage limits.
    Development guard hooks restrict agent commands; they do not monitor production encryption.
    Deterministic encryption leaks equality, frequency and length; passing vectors or sampled
    collision tests is not a security proof. Review this construction and its deployment assumptions
    independently before production use. See [NIST SP 800-38D, §8 and Appendices A/B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
14. **Installing the component is not replicated.** `INSTALL COMPONENT` writes to one server's
    `mysql.component` and nowhere else. Install it on every server that answers decryption queries
    and on every replica that could be promoted, and make sure the application can supply the key
    there too. ROW binlog carries the ciphertext, nonce and tag as bytes, so a replica never
    re-encrypts — which is what makes replication safe here, and also why the replica still needs the
    component to *read* those values. MySQL reference:
    [replication formats](https://dev.mysql.com/doc/refman/8.4/en/replication-formats.html),
    [component loading](https://dev.mysql.com/doc/refman/8.4/en/component-loading.html).
15. **Sharding: route on a stable identifier, never on ciphertext.** A random-nonce value differs on
    every call, so it cannot be a routing key; a deterministic value is stable, but using it as the
    shard key turns key rotation into a resharding job. Moving rows between shards needs no
    re-encryption — the destination decrypts with the original key and AAD. Comparing deterministic
    ciphertext across shards requires the same key, plaintext *and* AAD, so item 7 applies across
    shard boundaries. Count new encryption calls across every shard that shares a key; copying
    existing ciphertext is not a new encryption. `gcm_decrypt(...) LIKE '%김%'` cannot select a shard
    on its own: without a routing predicate every shard is queried and each decrypts its own
    candidates. Whether a given sharding proxy forwards loadable-function calls and preserves the
    result charset has to be verified with that combination — this project validates self-managed
    MySQL servers only.

## Support matrix

| MySQL | Built and tested against | `gcm.strict` scope | Constraint 10 reproduces for |
|:--|:--|:--|:--|
| **8.0** | 8.0.43 | GLOBAL | `REPEAT(str, int_col)`-shaped arguments |
| **8.4** | 8.4.11 | GLOBAL | `CONCAT(str, int_col)`-shaped arguments |
| **9.x** | 9.4.0 | GLOBAL **+ SESSION** | neither shape |

Patch versions, image digests and source checksums live in `docker/versions.json`. A component links
against the server it was built for: **one artifact per MySQL major, per architecture.**

## Install

```sh
scripts/verify.sh 8.4          # build, install, and replay the integration scenarios
```

Or take the published server image, which is an official `mysql` image with the component already
in `plugin_dir` and installed on first start:

```sh
docker run -d -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
  devgyurak/mysql-gcm-server:mysql8.4 --loose_gcm.strict=ON --binlog-format=ROW
```

Tags are `<version>-mysql<major>` and `mysql<major>` (multi-arch, amd64 + arm64). There is no
`latest`: which major it would mean is ambiguous. The init step only runs on a **fresh** data
directory — against an existing volume, run `INSTALL COMPONENT 'file://component_gcm'` yourself, and
remember that it is per server (constraint 14).

That is the fast path. The individual steps:

```sh
scripts/build-in-docker.sh 8.4            # -> build/8.4/component_gcm.so
docker cp build/8.4/component_gcm.so mysql-dev-8.4:"$(
  docker exec mysql-dev-8.4 mysql -uroot -N -e 'SELECT @@plugin_dir')"/component_gcm.so
docker exec mysql-dev-8.4 mysql -uroot -e "INSTALL COMPONENT 'file://component_gcm'"
```

`plugin_dir` differs between images (`/usr/lib64/mysql/plugin/` on the Oracle Linux based ones), so
ask the server rather than hardcoding it.

### Verifying a release download

A release carries six tarballs (three majors x amd64/arm64), `SHA256SUMS`, a signature and
certificate for it, and an SPDX SBOM. The signature is keyless, so what you verify is *which
workflow in which repository produced the checksums* — there is no long-lived key of ours to
trust or to leak:

```sh
gh release download v0.1.0 -R devgyurak/mysql-gcm
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/devgyurak/mysql-gcm/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf component_gcm-0.1.0-mysql8.4-amd64.tar.gz     # -> component_gcm.so
```

Then copy the `.so` into that server's `plugin_dir` and install it, as above. Match the major: a
component built for 8.4 does not load into 9.x.

## Functions

| Function | Envelope | Returns | Use it for |
|:--|:--|:--|:--|
| `gcm_encrypt(plaintext, key [, aad])` | `0x02` — random 96-bit nonce | `BLOB` | everything that is only read back |
| `gcm_encrypt_det(plaintext, key [, aad])` | `0x03` — synthetic nonce | `BLOB` | join keys, `UNIQUE`, exact match |
| `gcm_decrypt(ciphertext, key [, aad])` | reads `0x01`, `0x02`, `0x03` | `VARCHAR` tagged `utf8mb4` | reading, and `LIKE` on the plaintext |

`key` must be **exactly 32 bytes**; any other length is an error on *every* call. The `AES_ENCRYPT`
key-folding behaviour is deliberately not reproduced. Tag verification failure raises an error while
`gcm.strict` is ON (the default) and returns NULL when it is OFF — a malformed envelope or a wrong
key length is *always* an error, because `gcm.strict=OFF` must never hide corruption.

```sql
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');  -- fixture key

INSERT INTO patients (name_enc) VALUES (gcm_encrypt('홍길동', @k));
SELECT id FROM patients WHERE gcm_decrypt(name_enc, @k) LIKE '%길%';   -- server-side partial match
```

### Envelope

Normative byte layout, failure codes and test vectors: **`spec/envelope.md`**.

```
0x02  random nonce  ·  0x03  deterministic                    total = plaintext + 29 bytes
┌─────────┬───────────────────┬──────────────────────┬──────────────────┐
│ version │ nonce             │ ciphertext           │ tag              │
│ 1       │ 12                │ n                    │ 16               │
│ 02 / 03 │ RAND_bytes / HMAC │ AES-256-GCM          │ GCM, 128-bit     │
└─────────┴───────────────────┴──────────────────────┴──────────────────┘
  deterministic nonce = HMAC-SHA256(HMAC-SHA256(key, "mysql-gcm/v1/det-nonce"), plaintext)[0..12)

0x01  legacy CBC, decrypt only, NOT authenticated              total = 17 + 16k bytes
┌─────────┬───────────────────┬─────────────────────────────────────────┐
│ 01      │ IV 16             │ AES-256-CBC + PKCS#7        (no tag)    │
└─────────┴───────────────────┴─────────────────────────────────────────┘
  a migration prefixes an existing AES_ENCRYPT value — no re-encryption (constraint 8)
```

## Tests

Every layer runs against a real server except the unit suite, which links libcrypto only.

| Layer | What it proves | Command |
|:--|:--|:--|
| **unit** — 1,434 cases, ASan + UBSan | NIST CAVP KAT, every spec vector, envelope boundaries, key wiping, nonce-collision sampling | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` |
| **integration** — 10 scenarios × 3 majors | Korean `LIKE`, strict semantics and its per-version scope, NULL and size edges, v1 dual-read, the 8.x argument defect | `scripts/verify.sh 8.0` · `8.4` · `9` |
| **MTR** — 7 tests | the same surface inside the server's own harness, plus ROW replication and the SBR divergence | `scripts/mtr.sh 8.4` |
| **E2E** — 7 scenarios | primary + replica + an independent shard, over SQL only | `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner` |
| **load** | p95 against the `AES_DECRYPT` baseline, with a regression gate | `python tests/load/run.py --rows 300000 --concurrency 1,8,32 --gate tests/load/baseline.json` |

Latest measurements and the gate: `docs/perf.md`.

## Layout

```
src/            component: component.cc, udf_*.cc, sysvar.cc + the server-independent core
                (gcm, envelope, nonce — no MySQL headers, so tests/unit links them directly)
spec/           envelope.md (normative) + test-vectors.json (NIST CAVP + project vectors)
docs/           design.md (rationale, amendments A1–A8) · ops-constraints.md · perf.md
tests/          unit (GoogleTest) · integration (SQL + expected) · e2e (compose) · load
mysql-test/     MTR suite gcm/
docker/         build image per MySQL major + versions.json
scripts/        build-in-docker.sh · dev-up.sh · verify.sh · mtr.sh · gen-vectors.py
```

## Application access and development tools

Applications call these SQL functions through their existing MySQL driver. The project ships a
server component, not a Python or Java encryption SDK; no driver integration is required.

Python is used only for development tooling and SQL test runners. To check the committed test
vectors, install `scripts/requirements.txt` and run `python scripts/gen-vectors.py --check`.
This internal generator uses public fixture keys and fixed nonces; it is not an application API.

## Working on this repo with an AI agent

`AGENTS.md` is the entry point for Codex, Cursor and OpenCode; `CLAUDE.md` for Claude Code. Skills
live in `.agents/skills`, rules in `.agents/rules`, subagents in `.claude/agents`; the Cursor,
OpenCode and Codex adapters are generated from them by `scripts/agents-sync.sh` (CI runs `--check`).

## License

**GPLv2** — see [LICENSE](LICENSE). A MySQL component links against the server's GPLv2 headers,
so GPLv2 is the compatible choice; `docs/design.md` §7 records the reasoning. Sources carry
`SPDX-License-Identifier: GPL-2.0-only`.
