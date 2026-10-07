---
name: e2e-load-tests
description: Writing and running the docker compose E2E suite (SQL round trip, replication, dual-read) and the load tests (decrypt + LIKE over 10k/100k/300k rows, with a regression gate against AES_DECRYPT). Use it when working in tests/e2e or tests/load.
---

# e2e-load-tests

## E2E — `tests/e2e`
`compose.yml` services: `mysql-primary` (ROW binlog, `--loose_gcm.strict=ON`), `mysql-replica`, and
`runner` (python:3.12 with `PyMySQL`, which only executes SQL). The `.so` is mounted from the build
artifact volume.

Scenarios (`tests/e2e/scenarios/*.py`, each with a GWT docstring and function names that show
given/when/then):
| File | Given | When | Then |
|---|---|---|---|
| `sql_write_like.py` | three rows of Korean names inserted with SQL `gcm_encrypt_det` | `gcm_decrypt(col,@k) LIKE '%길%'` | only the matching ids |
| `sql_roundtrip.py` | a row inserted with SQL `gcm_encrypt` | select the `gcm_decrypt` result | the original value, its length and charset |
| `replica_consistency.py` | random and deterministic values inserted on the primary | SELECT on the replica after waiting for the GTID | byte-identical, and `LIKE` works on the replica |
| `dual_read_v1.py` | a row holding a 0x01 CBC envelope | `gcm_decrypt` | matches `AES_DECRYPT`; an AAD is rejected |
| `aad_mismatch.py` | encrypted with AAD 'a' | decrypt with AAD 'b' | `ER_UDF_ERROR`, while the same AAD succeeds |
| `strict_scope_global.py` | 8.0 and 8.4 (no session scope) | `SET GLOBAL` / `SET SESSION` | GLOBAL applies, SESSION gives 1229 |
| `strict_scope_session.py` | 9.0+ (session scope exists) | `SET SESSION ... = OFF` in one session only | the other session still errors |

**The runner does the version branching.** It picks one of the `strict_scope_*` scenarios from the
server version; the scenario bodies contain no `if` (the testing rule). Wait for replication with
`WAIT_FOR_EXECUTED_GTID_SET` — no sleeping, no polling. Credentials come from environment variables
only (compose supplies `REPL_PASSWORD`). The runner only executes SQL and never encrypts or decrypts
anything itself (amendment A4).

Run: `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner --abort-on-container-exit`.
The `.so` named by `GCM_SO` (default `build/8.4/...`) is mounted read-only into both servers'
`plugin_dir`.

## Load — `tests/load`
`run.py --rows {10000,100000,300000} --concurrency 1,8,32 --baseline aes [--suite aes256|aes192|aes128] --out result.json`
1. Given: N rows in `patients(id, name_gcm VARBINARY, name_cbc VARBINARY, name_plain VARCHAR utf8mb4)`
   from a seeded Korean-name generator, with the **same plaintext** in all three columns. The CBC
   column is written with the builtin `AES_ENCRYPT` under `block_encryption_mode = 'aes-256-cbc'` —
   that is the baseline being compared against.
2. When: `gcm_decrypt(name_gcm,@k) LIKE '%김%'` and `AES_DECRYPT(name_cbc,@k,@iv) LIKE '%김%'`, after 3
   warm-ups, 40 measured iterations, with one thread per concurrent session and a connection per
   thread. Two more variants locate the cost: `plain` (`name_plain LIKE '%김%'`, the scan + collation
   LIKE floor with no UDF) and `gcm_nolike` (`CHAR_LENGTH(gcm_decrypt(...)) > 0`, the UDF decrypt
   without a LIKE on its result). All variants are **interleaved per iteration**, with the leading
   variant rotating by one each round — measuring all of one and then all of the other attributes
   drift to the variant.
3. Then: p50/p95/max in ms per variant, the `gcm/aes` ratio, a `decomposition` per concurrency (the
   p95 floor, `gcm_nolike − plain` as the UDF + decrypt + tagging share, `gcm − gcm_nolike` as the
   LIKE-on-UDF-result share, each in ms and as a percentage of `gcm`, plus the decrypt share per row
   in ns), and the increase in `Created_tmp_disk_tables`, as JSON on stdout with a human summary on
   stderr. With `--gate tests/load/baseline.json`, exceeding a threshold exits 1; the gate reads
   `gcm` against `aes` only.

`--suite` selects the key length for the GCM column (32, 24 or 16 bytes of the fixture key); the
`AES_DECRYPT` baseline stays `aes-256-cbc` so the suites' ratios share a denominator. The runner lowers
`gcm.min_key_bytes` only while it writes the rows and restores the previous value — decryption, which
is what gets timed, ignores the setting. `load.yml` takes `suite` as a dispatch input; the nightly
measures `aes256`.

p95 is **nearest-rank** (`ceil(0.95n)`). With 20 samples, `int(len*0.95)` is one rank too high and
equals the maximum, which looks steadier while measuring something else.

The gate lives in one place, `tests/load/baseline.json`: `max_p95_ratio` is **1.10** and
`max_p95_ms_at_largest_serial` is 1000. The documentation promises 1.2x, and the gate is deliberately
tighter than the promise — the reason, and why it is not tighter still, is in that file's `_comment`.
Raising either number needs the hardware, the server version and the justification in the PR.

Results accumulate per version in `docs/perf.md` — the goal being to replace design §1.2's estimates
with measurements. Fill the baseline from a release build on known hardware; never freeze a development
laptop's numbers into a gate.

## Done when
- [ ] All E2E scenarios green, with compose propagating failure through `--exit-code-from`
- [ ] The load JSON uploaded as a CI artifact and the gate working through the exit code
