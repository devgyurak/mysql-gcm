---
name: integration-tests
description: Writing and running the real-server (docker) SQL smoke scenarios (tests/integration, scripts/verify.sh) and the MTR suite (mysql-test/suite/gcm). Use it when verifying SQL behaviour with the component installed in a server.
---

# integration-tests

Two layers. Both are GWT (`--echo # Given/When/Then`).

| Layer | Location | When | Needs |
|---|---|---|---|
| SQL smoke | `tests/integration/<case>.sql` + `<case>.expected` | local loop, PR CI | the official `mysql:<ver>` image plus the `.so` |
| MTR | `mysql-test/suite/gcm/t/*.test`, `r/*.result` | PR CI (the server-tree build job), releases | a server source tree build |

## SQL smoke
`scripts/verify.sh <ver>` (with `GCM_RECORD=1` it re-records the `.expected` files):
1. `scripts/dev-up.sh <ver>` (reusing a server that is already up), then ask `SELECT @@plugin_dir` for
   the path and `docker cp` into it
2. `UNINSTALL`, then `INSTALL COMPONENT 'file://component_gcm'`, so a rebuilt `.so` is definitely the
   one picked up
3. Give each case a clean schema (`gcm_it`) and run it with
   `mysql --default-character-set=utf8mb4 -D gcm_it -N --force`. Capture stdout and stderr
   **separately**, append the errors after stdout as a `--- errors, in statement order ---` section,
   then diff against the `.expected`. Any difference exits 1.
4. Record the before/after difference in `Created_tmp_disk_tables` to `build/<ver>/tmp_disk.txt`, then
   `UNINSTALL`.

**Why not `2>&1`**: the client block-buffers stdout and does not buffer stderr, so the interleaving
depends on where the buffer boundaries fall — which would violate the no-flakiness rule. `--force` is
needed because some cases expect an error.

Case files (the name is the intent):
```
00_install_and_signature.sql        wrong argument count; key lengths 5, 31, 33 as errors
10_roundtrip_random.sql             round trip, a different envelope per row, length = pt+29, AAD round trip
11_roundtrip_det.sql                equality, length = pt+29, byte-match against spec §5.1, joins and UNIQUE
20_korean_like.sql                  ★ gcm_decrypt(...) LIKE '%길%' = 1, prefix and suffix match, case-insensitive ci, table search
30_strict_semantics.sql             version-independent: tag failure errors, envelope errors ignore strict, AAD mismatch
31_strict_scope.sql                 per-major-expected — GLOBAL vs SESSION (amendment A5)
40_null_and_edge.sql                NULL propagation, the empty string (29 B), 64 KB, boundary-length round trips
50_dual_read_v1.sql                 a 0x01 envelope matches AES_DECRYPT, AAD rejected, reading all three versions mixed
90_tmp_disk_observation.sql         a decrypt + ORDER BY + GROUP BY workload (the counter is recorded in tmp_disk.txt)
91_server_udf_arg_defect.sql        per-major-expected — pins the amendment A7 server defect
```
**per-major `.expected`**: write `per-major-expected` in the first three lines of a case and
`verify.sh` compares against `<case>.<major>.expected`. Only behaviour that legitimately differs per
version belongs here (currently 31 and 91). Every other case must produce the **same output** on 8.0,
8.4 and 9.

Produce an `.expected` by running the case, **read it through by eye**, then commit it. In review, a
changed `.expected` has to be explained. Keep ciphertext and plaintext bytes out of the expected files
— an error that prints a value, such as a UNIQUE violation message, is replaced by `INSERT IGNORE`
plus an assertion on the row count.

## MTR
- Location: `mysql-test/suite/gcm/{t,r,include}`. `scripts/mtr.sh` **copies** it to
  `$MYSQL_SRC/mysql-test/suite/gcm` (no symlink, because the mount is read-only).
- Shared includes: `include/gcm_install.inc` (`INSTALL COMPONENT` plus the public fixture key
  `SET @k = UNHEX('0001..1f')`) and `include/gcm_uninstall.inc` (which includes
  `SET GLOBAL gcm.strict = DEFAULT`).
- Test skeleton:
```
--source suite/gcm/include/gcm_install.inc
--echo # Given: a deterministic envelope of a Korean name
SET @c = gcm_encrypt_det('홍길동', @k);
--echo # When: filtered with native LIKE
SELECT gcm_decrypt(@c, @k) LIKE '%길%' AS hit;
--echo # Then: hit must be 1
--source suite/gcm/include/gcm_uninstall.inc
```
- Expect errors with `--error ER_UDF_ERROR` (the component has no error code of its own and raises
  `ER_UDF_ERROR`), and a wrong argument count with `--error ER_CANT_INITIALIZE_UDF`. Both are server
  symbols, so there is no need to write the numbers.
- Run: `scripts/mtr.sh <major>` (it builds the server in a container, copies the suite in and runs it).
  To record results: `GCM_RECORD=1 scripts/mtr.sh <major>` copies the `.result` back into the
  repository, so **read the diff by eye** before committing. Never commit a hand-written `.result`.
- Replication cases: `--source include/master-slave.inc` plus
  `include/have_binlog_format_row.inc`, confirming under ROW binlog that a `gcm_encrypt` value is
  byte-identical on the replica — the test that grounds the SBR risk.
- A full server build uses a lot of memory. Lower the parallelism (`GCM_MTR_JOBS`) and turn off group
  replication (`-DWITHOUT_GROUP_REPLICATION=1`), which the gcm suite does not use.

## Done when
- [ ] `20_korean_like` passes (without it the project misses its purpose)
- [ ] The smoke suite passes on 8.0, 8.4 and 9.x, with identical output outside the per-major cases
- [ ] Every MTR `.result` is a `--record` output and the reason it changed is in the PR description
