# Performance

Measured numbers for the server-side decrypt + `LIKE` path, accumulated per release. The goal is to
replace the estimates in `docs/design.md` §1.2 with measurements.

Produced by `tests/load/run.py`, which times

```sql
SELECT COUNT(*) FROM patients WHERE gcm_decrypt(name_gcm, @k) LIKE '%김%';
SELECT COUNT(*) FROM patients WHERE AES_DECRYPT(name_cbc, @k, @iv) LIKE '%김%';   -- baseline
```

over the same plaintexts in two columns, after 3 warm-up runs, 20 measured runs per session.

## Gate

`tests/load/baseline.json`: p95 within **1.2x** of the `AES_DECRYPT` baseline, and p95 at 300k rows
with one session under **1000 ms**. The nightly `load` workflow enforces it with `--gate` and uploads
the JSON as an artifact. Moving either number needs a PR that states the hardware, the server version
and why the regression is acceptable.

## Results

### Developer-machine run (indicative only — NOT the baseline)

Docker on an arm64 macOS laptop, MySQL 8.4.11 in a container, `RelWithDebInfo` component build.
Recorded to prove the harness and the gate work end to end, and to sanity-check the premise of
`docs/design.md` §1.2. Do not treat these as the release baseline: the host is shared and noisy.

| Rows | Sessions | gcm p50 | gcm p95 | aes p50 | aes p95 | p95 ratio | tmp disk delta |
|---|---|---|---|---|---|---|---|
| 10,000 | 1 | 3.97 ms | 4.43 ms | 3.83 ms | 4.08 ms | 1.086 | 0 |
| 10,000 | 8 | 10.49 ms | 13.42 ms | 13.27 ms | 14.96 ms | 0.897 | 0 |
| 100,000 | 1 | 35.08 ms | 41.38 ms | 37.59 ms | 48.49 ms | 0.853 | 0 |
| 100,000 | 8 | 108.63 ms | 115.90 ms | 129.93 ms | 137.88 ms | 0.841 | 0 |
| 100,000 | 32 | 365.75 ms | 534.33 ms | 431.15 ms | 653.43 ms | 0.818 | 0 |

Two things worth reading off this:

* **AES-256-GCM is not slower than the CBC builtin here** — at every measured point the ratio is at
  or below 1.09, and above one session it is consistently below 0.9. GCM needs no padding and its
  authentication is cheap next to the row scan, so the cost that matters is the scan, which both
  variants pay identically. The 1.2x gate has real headroom.
* **`Created_tmp_disk_tables` did not move**, including at 32 concurrent sessions, which is the
  question `docs/design.md` §5.3 raised about plaintext reaching disk-based temporary tables. It is
  an observation over this workload, not a guarantee: a query that adds a sort or a large grouping
  can still spill, so the counter stays in the JSON output on every run.

For scale: §1.2 estimated ~1.1 s to pull and decrypt 100,000 candidate rows in the application. The
same filter server-side measures 41 ms p95 on this machine.

### Release baseline

Empty on purpose. The gate numbers must come from a release build on known, unshared hardware, or
they would encode laptop noise. Populate this section from the nightly `load` workflow artifact
(Phase 4) and update `tests/load/baseline.json` in the same PR.
