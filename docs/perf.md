# Performance

Measured numbers for the server-side decrypt + `LIKE` path, accumulated per release. The goal is to
replace the estimates in `docs/design.md` §1.2 with measurements.

Produced by `tests/load/run.py`, which times

```sql
SELECT COUNT(*) FROM patients WHERE gcm_decrypt(name_gcm, @k) LIKE '%김%';
SELECT COUNT(*) FROM patients WHERE AES_DECRYPT(name_cbc, @k, @iv) LIKE '%김%';   -- baseline
```

over the same plaintexts in two columns, after 3 warm-up runs, 20 measured runs per session. Each
session alternates the two variants per iteration, and alternates which of the pair goes first, so
neither a slow period on the host nor a warm cache can favour one of them. The consequence to keep in
mind when reading the concurrency axis: at 8 or 32 sessions the server sees a *mixture* of GCM and
`AES_DECRYPT` work, not 8 or 32 concurrent GCM queries. That is the right shape for a ratio and the
wrong shape for an absolute capacity number.

p95 is the nearest-rank percentile — the smallest sample at or above rank `ceil(0.95n)`. It used to be
computed one rank too high, which at 20 samples is the maximum, so a "p95" at one session was really
the worst single request of twenty.

## Gate

Two numbers in `tests/load/baseline.json`, and they do different jobs.

**The promise** is p95 within **1.2x** of the `AES_DECRYPT` baseline, and p95 at 300k rows with one
session under **1000 ms** (`docs/design.md` Phase 4). That is what this component claims about itself.

**The enforced regression gate** is p95 within **1.05x** of `AES_DECRYPT`. It is tighter than the
promise on purpose: the measured ratio is 0.87–0.91, so a 1.2 gate has 30% of dead space in it and a
doubling of per-row cost would pass unnoticed. The ratio is also the metric that survives a shared
runner — it normalises away machine speed, and its own run-to-run spread was 1.04x — so it is the one
worth tightening. The absolute 1000 ms ceiling stays where the promise put it, because tightening an
absolute number on a GitHub runner buys sensitivity by trading it for failures that say nothing about
this code.

The nightly `load` workflow enforces both with `--gate` and uploads the JSON as an artifact. Raising
either number needs a PR that states the hardware, the server version and why the regression is
acceptable, and updates this file in the same change.

## Results

### Developer-machine run (indicative only — NOT the baseline, and a previous harness)

Docker on an arm64 macOS laptop, MySQL 8.4.11 in a container, `RelWithDebInfo` component build.
Recorded to prove the harness and the gate work end to end, and to sanity-check the premise of
`docs/design.md` §1.2. Do not treat these as the release baseline: the host is shared and noisy.

These numbers also came from the **earlier harness**, which measured every GCM session and then every
AES session and computed p95 one rank too high. They are not comparable point-for-point with the
release baseline below; they are kept because they are what the design's §1.2 premise was first
checked against.

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
  variants pay identically, and the release baseline below confirms it on CI hardware.
* **`Created_tmp_disk_tables` did not move**, including at 32 concurrent sessions, which is the
  question `docs/design.md` §5.3 raised about plaintext reaching disk-based temporary tables. It is
  an observation over this workload, not a guarantee: a query that adds a sort or a large grouping
  can still spill, so the counter stays in the JSON output on every run.

For scale: §1.2 estimated ~1.1 s to pull and decrypt 100,000 candidate rows in the application. The
same filter server-side measures 41 ms p95 on this machine.

### Release baseline — 0.1.0

The reference environment is the one CI actually uses, so the gate is checked against the same class
of machine that produced it: **`ubuntu-24.04` GitHub-hosted runner, MySQL 8.4.11 in the official
container, `RelWithDebInfo` component, 300,000 rows of which 29,918 match `'%김%'`.** Three
consecutive `load` workflow runs, 20 measured iterations per session after 3 warm-ups, GCM and
`AES_DECRYPT` interleaved on each connection.

| Sessions | gcm p95 | aes p95 | p95 ratio |
|---|---|---|---|
| 1 | 244.3 / 266.3 / 252.0 ms | 275.6 / 292.2 / 277.3 ms | 0.886 / 0.911 / 0.909 |
| 8 | 911.1 / 983.4 / 1008.1 ms | 1020.3 / 1124.7 / 1126.9 ms | 0.893 / 0.874 / 0.895 |
| 32 | 3589.9 / 3927.4 / 3920.8 ms | 4092.5 / 4480.1 / 4413.7 ms | 0.877 / 0.877 / 0.888 |

Three values per cell, one per run, in run order. What the three runs establish:

* **Every ratio is below 0.92**, and the widest spread of a ratio across runs is 1.04x. That is what
  makes the 1.05 gate safe to enforce — and it is only visible because the two variants are
  interleaved on the same connection. Measuring all GCM sessions and then all AES sessions, as the
  harness first did, let one slow period on a shared runner land entirely on one variant and reported
  1.247 at eight sessions while the neighbouring points sat near 0.84.
* **Absolute p95 varies by up to 1.11x between runs** on identical inputs, which is the runner, not
  the component. An absolute gate has to carry that; a ratio gate does not.
* **`Created_tmp_disk_tables` did not move in any run**, at any session count — the question
  `docs/design.md` §5.3 raised about plaintext reaching disk-based temporary tables. It remains an
  observation about this workload, not a guarantee; a query that adds a sort or a large grouping can
  still spill, so every run keeps the counter in its JSON.
* **300k rows scanned, decrypted and matched in 244 ms serially.** `docs/design.md` §1.2 estimated
  ~1.1 s for pulling 100,000 candidate rows into the application and decrypting them there.

Reproduce with `gh workflow run load.yml -f rows=300000`, or locally with
`python tests/load/run.py --rows 300000 --concurrency 1,8,32 --baseline aes --gate tests/load/baseline.json`.
