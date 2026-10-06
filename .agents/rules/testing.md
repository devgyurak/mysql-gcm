---
paths:
  - "tests/**"
  - "mysql-test/**"
  - "spec/test-vectors.json"
---
# Testing rules — GWT and the pyramid

```
        e2e / load        Slow. Nightly and release gate. Real server, SQL + replication
       bench (gbench)     Core micro-benchmarks. Merges to develop/main + nightly. No server
      adapter (gtest)     The component install/uninstall paths. Stub services, no server
     integration / MTR    Real-server SQL scenarios. Smoke is required on every PR; MTR on core changes
   unit (gtest)  The server-independent core plus vectors. Seconds. PR gate, and run locally before committing
```

## GWT (Given-When-Then) — mandatory at every layer
- **Body**: mark the three blocks with comments or `echo` and keep them in order. No second When after
  the Then — one test, one action.
- **No branching or looping**: do not add logic such as `if`, `else`, `for` or `while` to a test case
  body. Split the expected results per condition into separate cases, and express multiple inputs with
  the test framework's parameterisation. Do not reimplement the algorithm under test to compute an
  expected value inside the test.
- **Name**: make given/when/then visible.
  - gtest: `TEST(Envelope, GivenEmptyInput_WhenParsed_ThenBadEnvelope)`
  - MTR / SQL scenarios: `--echo # Given: ...`, `--echo # When: ...`, `--echo # Then: ...` at the top
    of the file. They land in the `.result`, where they tell a reviewer the intent.
- **Given** only builds state (keys, loading vectors, tables, sysvars). **When** is a single call.
  **Then** is assertions only. A test with no assertion is not a test.
- Reuse one GWT across multiple inputs through parameterisation (`TEST_P` and friends). No copy-paste.

```cpp
TEST(Envelope, GivenEmptyInput_WhenParsed_ThenBadEnvelope) {
  // Given
  const gcm::Bytes input{nullptr, 0};
  gcm::ParsedEnvelope parsed{};
  // When
  const gcm::Error error = gcm::parse(input, &parsed);
  // Then
  EXPECT_EQ(error, gcm::Error::bad_envelope);
}
```

```sql
--echo # Given: a deterministic envelope of a Korean name and strict mode ON
SET @k = UNHEX('000102...1f'); SET SESSION gcm.strict = ON;
SET @c = gcm_encrypt_det('홍길동', @k);
--echo # When: decrypted value is filtered with native LIKE
SELECT gcm_decrypt(@c, @k) LIKE '%길%' AS hit;
--echo # Then: hit = 1 (see .result)
```

## Common
- Every vector lives in one place, `spec/test-vectors.json`. The C++ and server tests read every case
  from that file, and the internal generator confirms reproducibility with `--check`. Never copy a
  value out of it.
- No real keys and no PHI in a fixture. Vector keys are the public NIST vectors or the `00..1f`
  pattern.
- For a non-deterministic function (`gcm_encrypt`), verify **properties** rather than a value: the
  length, the version byte, that two calls differ, and that decryption round-trips.
- Flakiness is not tolerated. No retry decorators. Mock anything time-dependent.

## Unit (`tests/unit`)
- Subject: the server-independent core in `gcm.cc`, `envelope.cc` and `nonce.cc`. Runs without a server
  and preserves the dependency boundary in `architecture.md`. The strict-dependent translation to a SQL
  error or NULL is verified by the integration tests.
- Required cases: NIST CAVP GCM KAT / empty plaintext / with and without AAD / a one-bit tag flip / a
  one-bit nonce flip / truncated envelopes (lengths 0, 1, 12, 28) / an unknown version / key lengths 0,
  16, 31, 33 / deterministic same input → same output / deterministic different input → different nonce
  / the nonce_key derivation vector / a buffer zeroed after the key is cleansed.
- Deterministic nonce collision bound: zero duplicate nonces over random plaintexts (100k in PR CI, 1M
  nightly).

## Adapter (`tests/adapter`)
- Subject: `component.cc`, `sysvar.cc` and `udf_*.cc` — the files `tests/unit` cannot take. They
  include server headers, so the suite runs **inside the build image**
  (`scripts/adapter-tests.sh <major>`). No server is started.
- The services are stubs and **can be made to fail per call**. `REQUIRES_SERVICE_PLACEHOLDER` is an
  ordinary pointer, so the test points it at a stub struct — no test entry point is added to `src/`
  (architecture §6, enforced by `check-architecture.py`).
- Whether the crypto handles are still live is read **through `gcm::encrypt_random`**. Do not add a
  dedicated accessor.
- It runs on all three majors: the code `GCM_HAS_SESSION_SYSVAR` compiles, and the set of stubs it
  needs, differ.
- Sanitizers **off** by default: these are control-flow tests, and ASan is the one configuration where
  the loader passes `RTLD_NODELETE`, so looking at the subject of amendment A9 under it leads to the
  wrong conclusion.
- What it covers: registration order (init registers the variable after the functions, and deinit also
  takes it last), rollback, keeping resources when a release is refused, and deinit's re-registration.
- **To pin an ordering, assert the whole call sequence.** An assertion that only checks *which* calls
  happened cannot see two of them swapped — a mutation reversing deinit's variable-last order passed
  exactly that way.
- **Confirm non-vacuity by mutation, and do not believe someone else's claim that a mutation is
  caught.** A review once said a mutation was covered, that claim went into the documentation
  unverified, and it turned out to be false. Run the mutation yourself.
- It is path-filtered, so **do not make it a required check**: it does not report on a PR that misses
  the filter, and a required check that does not report blocks merges forever (`stack-ci-docker.md`).

## Integration (`tests/integration`, `mysql-test/suite/gcm`)
- SQL scenarios against a real server (docker, MySQL 8.0/8.4/9.x) with the component installed, diffed
  against expected output.
- **Never delete these**: `gcm_decrypt(gcm_encrypt_det('홍길동',@k),@k) LIKE '%길%'` → 1. Case
  insensitivity, `LIKE '%kim%'` (utf8mb4_general_ci). Join equality,
  `gcm_encrypt_det(a,@k) = gcm_encrypt_det(a,@k)`.
- NULL propagation, a wrong argument count, a wrong key length, a tag failure under each of
  `gcm.strict` ON and OFF, `SET SESSION gcm.strict` session scope, and that changing GLOBAL does not
  affect an existing session.
- Print `SHOW STATUS LIKE 'Created_tmp_disk_tables'` before and after to record whether `gcm_decrypt`
  caused a disk temporary table (design §5.3).
- MTR runs from `mtr.yml` only on PRs and merges that touch `src/**`, `mysql-test/**`, `spec/**` or the
  build tooling (measured at 49–63 minutes). It catches things only the server's own harness catches —
  an unexpected line in the error log fails it. The smoke suite (`verify.sh` across three majors)
  stays a required check on every PR.
- MTR: produce a `.result` with `--record`, read the diff by eye, then commit it. A test cleans up
  after itself with `INSTALL`/`UNINSTALL COMPONENT`, and resets a global sysvar with
  `SET GLOBAL ... = DEFAULT`.

## Benchmarks (`tests/bench`)
- Subject: `gcm.cc`, `nonce.cc`, `envelope.cc`, measured in-process without a server or SQL. **Not a
  replacement for the load tests** — `load` exercises the whole SQL path but has enough variance to
  miss a regression under 20%, and it cannot say what got slower.
- The unit of measurement is a **ratio**: measure a bare OpenSSL EVP call (`ref/*`) in the same process
  and divide by it. Absolute nanoseconds are not comparable on a shared runner and are never used as a
  gate — the same approach `load` takes with `AES_DECRYPT`. Cases with no reference (nonce derivation,
  envelope parsing) are recorded without a ratio gate.
- Sizes are 16 B / 256 B / 4 KiB / 64 KiB. The small end is dominated by per-call fixed cost (the EVP
  context, the key schedule, the HMAC) and the large end by throughput. The `load` fixture holds only
  Korean names, so it measures the small end alone.
- **Every case must confirm the operation succeeded.** A failure path returns early, so without that
  check you are measuring code that does nothing and reporting an excellent number for it. The same
  applies to the reference side — if the reference fails silently, every ratio looks like a regression.
- Built `RelWithDebInfo` with sanitizers off (a separate CMake project from `tests/unit`). A number
  measured under ASan has nothing to do with what ships.
- The GWT naming rule does not apply: these are measurements, not assertions. The success check above
  takes its place.
- **Runs on merges, not on PRs**: pushes to `main` and `develop` that touch `src/**` or
  `tests/bench/**`, plus nightly. A number measured on every PR is read by nobody and costs four
  minutes. The accepted cost is that a regression can land on develop first — `main` only advances by a
  merge from develop and the benchmark runs on both sides, so it surfaces before a tag. **Do not put it
  in the required checks** (a required check that does not report on a PR blocks merges forever). The
  thresholds live in `tests/bench/baseline.json` and the measurements accumulate in `docs/perf.md`.

## E2E (`tests/e2e`)
- compose: mysql (ROW binlog) + replica + a Python runner. Scenarios: store encrypted via SQL → server
  decrypt + LIKE / SQL encrypt-decrypt round trip / v1 (CBC) dual-read / identical value on the replica
  / an AAD mismatch rejected.
- An E2E failure is not classified as "an environment problem". If it cannot be reproduced, attach the
  logs and open an issue.

## Load (`tests/load`)
- Measured: `gcm_decrypt(col,@k) LIKE '%김%'` p50/p95 at 10k/100k/300k rows, 1/8/32 concurrent
  sessions, the ratio against the same query with `AES_DECRYPT`, server RSS, and the increase in
  `Created_tmp_disk_tables`.
- The promise (in the docs and the README): p95 within **1.2x** of `AES_DECRYPT`, and serial p95 under
  **1.0 s** at 300k rows.
- The actual gate (`tests/load/baseline.json`): a p95 ratio of **1.10**. Measurements land at 0.80–0.95,
  so 1.2 would pass even if the per-row cost doubled. The reason for not tightening it further is not
  caution but measured noise — the worst of six CI runs was 0.947, and all of the loose values are on
  the one-session axis (40 samples; 8 and 32 sessions accumulate 320 and 1280, and their run-to-run
  spread is 1.06x and 1.04x). The absolute 1.0 s gate stays a promise rather than a gate because on a
  shared runner it would fail for reasons unrelated to this code (measured 235–266 ms).
- p95 is nearest-rank (`ceil(0.95n)`). Reduce the sample count and p95 collapses onto the maximum,
  where a single request moves the gate.
- To **raise** a threshold, state the hardware, the server version and the reason the regression is
  accepted in the PR, and update `docs/perf.md` in the same PR.
- Nightly plus `workflow_dispatch`. Not run per PR.
