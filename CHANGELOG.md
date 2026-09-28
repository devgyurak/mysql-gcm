# Changelog

Notable changes per release. Envelope-format changes get their own entry with a compatibility note
(`ci-release` skill release checklist).

## Unreleased

### Added
- Component implementation: `component.cc`, `udf_encrypt.cc`, `udf_decrypt.cc`, `udf_glue.{h,cc}`,
  `sysvar.{h,cc}` and the in-tree `src/CMakeLists.txt`. Registers `gcm_encrypt`, `gcm_encrypt_det`
  and `gcm_decrypt` through the `udf_registration` service, tags the decrypted result `utf8mb4`
  through `mysql_udf_metadata`, and registers `gcm.strict` through
  `component_sys_variable_register`. Installation rolls back on any partial registration.
- Build tooling: `docker/build.Dockerfile` (a cached, configured MySQL source tree per major),
  `docker/versions.json`, `docker/build-component.sh`, `scripts/build-in-docker.sh`.
- Local verification: `scripts/dev-up.sh`, `scripts/verify.sh`, `scripts/verify.sql`.
- Integration suite `tests/integration/` — ten scenarios, recorded and reviewed per major.
- MTR suite `mysql-test/suite/gcm/` — signature, envelope, Korean LIKE, strict semantics, NULL and
  boundary sizes, v1 dual-read, and ROW-binlog replication.
- E2E suite `tests/e2e/` — compose primary + replica + a SQL-only Python runner, six scenarios.
- Load harness `tests/load/run.py` with the gate in `tests/load/baseline.json`
  (p95 within 1.2x of `AES_DECRYPT`, and under 1s at the largest row count serially). First
  indicative measurements are in `docs/perf.md`; the release baseline is still empty on purpose.
- `scripts/mtr.sh` to build the server in a container and run the MTR suite, with `GCM_RECORD=1`
  for regenerating `.result`.
- `.clang-format`: the MySQL 8.4 config with `ColumnLimit` raised to 100 to match this codebase.

### Fixed
- `tests/unit/CMakeLists.txt` never called `enable_testing()`, so no `CTestTestfile.cmake` was
  written and `ctest` reported "No tests were found" **while exiting 0** — the unit gate in CI was
  passing without running anything. All 1400 tests run now.
- Two GoogleTest fixtures were both named `DetVector` (in `gcm_test.cc` and `nonce_test.cc`), which
  aborted the whole binary at startup with "Attempted redefinition of test suite". The nonce one is
  now `DetNonceVector`.

### Released
- **License is GPLv2** (`GPL-2.0-only`), settled rather than pending: `LICENSE` carries the full text,
  sources carry an SPDX header, and `docs/design.md` §7 records why GPLv2 is the compatible choice for
  something that links the server's GPLv2 headers.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) and `.github/CODEOWNERS`.
- Release pipeline: a tag `v*` on `main` builds 3 majors × 2 architectures, publishes the tarballs,
  `SHA256SUMS` and an SBOM to a GitHub Release, and pushes `mysql-gcm-server` images to Docker Hub —
  an official `mysql` image per major with the component preinstalled and installed on first start
  (`docker/server.Dockerfile`). Multi-arch tags `<version>-mysql<major>` and `mysql<major>`.
  Tests still use unmodified official images, so no gate depends on that release image.

### Fixed in review
- `gcm_encrypt*` sized its result field from the argument's *pre-conversion* length. The plaintext
  argument is requested as utf8mb4 and the server widens it first, so a latin1 `VARCHAR(1)` holding
  `é` reports `lengths[0] = 1` while the envelope is 31 bytes. Materialising that result failed with
  `ER_DATA_TOO_LONG` under strict SQL mode and, without it, **stored a 30-byte truncated envelope
  that no longer authenticates** — warning 1265 was the only signal. Every charset spends at least
  one byte per character, so the declared width is now `4 × lengths[0] + 29`; both SQL modes are
  pinned in the integration and MTR edge cases.
- `gcm_encrypt*` sized its result field as `args->lengths[0] + 29`, but the server narrows
  `initid->max_length` with `min<uint32>(...)`, so a LONGTEXT argument (4294967295) wrapped to 28 —
  below the 29 byte minimum envelope. `CREATE TABLE ... AS SELECT gcm_encrypt(longtext_col, @k)`
  failed with `ERROR 1406 Data too long`, and in a non-strict SQL mode it would have truncated
  silently. `envelope_max_length()` now saturates.
- `seal()` passed `ct + len` to `EVP_EncryptFinal_ex`, where `len` had been overwritten by the AAD
  pass with the AAD length. With an empty plaintext and an AAD longer than the tag the pointer was
  past the end of the output buffer. GCM's Final writes nothing, so nothing was corrupted, but the
  AAD length is caller-controlled and the invariant is now restored with a separate counter.
- `gcm_encrypt_det` now declares `const_item`, so `WHERE indexed_col = gcm_encrypt_det('x', @k)`
  becomes an index lookup (`type=const`) instead of a scan — the point of the deterministic variant.
  `gcm_encrypt` keeps `const_item = false`; it draws a fresh nonce per call.
- Argument lengths are bounded before any envelope arithmetic, with a length-specific error.
- `integration.yml` and `e2e.yml` downloaded the component from `build.yml`, which
  `actions/download-artifact@v4` cannot do across workflow runs — both gates would have failed to
  find the artifact. Each workflow now builds the component itself; the configured server tree is a
  cached image, so that is cheap. `release.yml` had the same flaw.
- `load.yml` ran `scripts/verify.sh`, which uninstalls the component on the way out, and then called
  the functions. It now reinstalls and passes the container's port through.
- The nightly 1,000,000-sample deterministic-nonce collision run was configured on the load job,
  which never runs the unit binary, so it ran nowhere. It is a scheduled `unit.yml` job now.
- `e2e.yml` switched only the component when a different MySQL major was selected, leaving the server
  image at the 8.4 default — so a 9.x build was being tested against an 8.4 server. The server image
  now comes from `docker/versions.json` for the selected major.
- `release.yml` packaged a single architecture from one runner, dropping arm64 from the release. It
  now builds a (major × arch) matrix and the packaging job asserts that six archives were produced.
- `OpenVector` in the unit suite never consumed the deterministic vectors, so their decryption path
  was unverified even though `spec/envelope.md` §6 requires it for every `ok` vector.
- `docker/versions.json` carries the source tarball SHA-256 and the compiler each server tree
  expects; the Dockerfile verifies the tarball and takes the toolset as a build argument.

### Documented
- `docs/design.md` amendment A5: `gcm.strict` has SESSION scope only from MySQL 9.0.0. Component
  sysvars ignore `PLUGIN_VAR_THDLOCAL` before that and reading a session value has no service, so the
  variable is registered GLOBAL-only on 8.0 and 8.4.
- `docs/design.md` amendment A7: MySQL 8.0 and 8.4 corrupt some *computed* string arguments to a
  loadable function from the second row of a statement onward. Callers must pass a stored value;
  `tests/integration/91_server_udf_arg_defect.sql` pins the behaviour per version.
- `docs/design.md` §8: the Phase S questions are answered on real servers — Korean `LIKE` works
  through the charset tag on all three majors (so `decrypt_like` is not needed), and
  `Created_tmp_disk_tables` did not increase.
- `docs/design.md` amendment A8 and `spec/envelope.md` §2.3: deployment topology. ROW binlog carries
  ciphertext, nonce and tag as bytes and a replica never re-encrypts, while `INSTALL COMPONENT` is
  *not* replicated — both now asserted in `gcm_replication.test`, which also shows the primary and
  replica diverging under `binlog_format=STATEMENT`. Sharding guidance (route on a stable identifier,
  one AAD convention per key across shards, no re-encryption when moving rows) is exercised by
  `tests/e2e/scenarios/cross_shard_determinism.py` against an independent second server.
- `spec/envelope.md` §2.3: a v1 envelope's plaintext MUST already be UTF-8. `gcm_decrypt` tags every
  result `utf8mb4`, and a v1 envelope never went through the converting encryption path, so a latin1
  `Müller` returns ill-formed and `LIKE '%ller%'` yields 0 with no error. Pinned in both the
  integration and MTR dual-read cases, together with the correct migration.
