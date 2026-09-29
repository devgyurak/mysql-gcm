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

**The enforced regression gate** is p95 within **1.10x** of `AES_DECRYPT`. It is tighter than the
promise because the measured ratio is 0.80–0.95: a 1.2 gate has a quarter of its range in dead space,
and per-row cost could double without tripping it. It is not tighter *still* because of measured
noise rather than caution — see the baseline below, where the worst of nine observations is 0.947 and
every one of the loose ones is at a single session. 1.10 clears that by 16% and sits roughly 26% above
the centre of the distribution, so it fails on a regression and not on one unlucky request.

The absolute **1000 ms** ceiling stays where the promise put it. Observed: 235–266 ms. It is an
absolute number on a shared runner whose hardware is not ours to pin, so tightening it would buy
sensitivity at the price of failures that say nothing about this code. The ratio normalises machine
speed away, which is why the sensitivity belongs there.

The nightly `load` workflow enforces both with `--gate` and uploads the JSON as an artifact. Raising
either number needs a PR that states the hardware, the server version and why the regression is
acceptable, and updates this file in the same change.

## Core micro-benchmarks

`tests/bench` measures `gcm.cc`, `nonce.cc` and `envelope.cc` in process, with no server and no
SQL, and divides each case by a bare-OpenSSL equivalent measured in the same run
(`tests/bench/bench_support.h`). It is not a substitute for the load suite; it answers what the
load suite structurally cannot:

* **Resolution.** The load ratio's run-to-run spread is 1.19x, which is why its gate sits at 1.10
  and why a regression under roughly 20% is invisible to it. A ratio taken in process against a
  reference on the same core is far steadier, so a change of a few percent is legible.
* **Attribution.** When the load ratio moves, nothing says whether it was sealing, opening, nonce
  derivation, envelope parsing, buffer handling or the server. Each of those has its own case here.
* **Sizes the fixture never produces.** The load rows are Korean names, so every load number is
  from the small end. 4 KiB and 64 KiB are measured only here.
* **Cost.** Seconds, with no server, so it can run per pull request if it ever needs to.

Run it with `scripts/bench.sh` (add `--gate` once the baseline has ceilings). The reference
environment is `ubuntu-24.04` with GCC and the distribution's OpenSSL 3, which is what
`bench.yml` runs on; on any other host the script reproduces that in a container, because a ratio
compared against a baseline recorded elsewhere means nothing.

### Developer-machine run (indicative — the CI baseline is not recorded yet)

Docker `ubuntu:24.04` on an arm64 macOS laptop. AES and SHA instruction sets differ between this
and an x86-64 runner, so the ratios will move; the shape of the findings should not.

| Case | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `open` / bare EVP open | 0.998 | 0.997 | 1.019 | 1.017 |
| `seal_random` / bare EVP seal | 2.411 | 2.189 | 1.646 | 1.061 |
| `seal_det` / bare EVP seal | 4.155 | 3.990 | 3.928 | 3.561 |

Three things fell out of the first run:

* **The decrypt path adds nothing measurable.** `open` sits within 2% of a bare EVP decrypt at
  every size — and that is the path every row of a `LIKE` query goes through, which is the
  operation the whole project exists to make viable.
* **`gcm_encrypt` costs a constant ~425 ns over a bare seal**, invisible at 64 KiB and a factor of
  2.4 at 16 bytes. That is `RAND_bytes(12)`, and it is the price of a fresh nonce rather than
  overhead to remove.
* **`gcm_encrypt_det` costs 3.6–4.2x a bare seal, and it is the HMAC, not the cipher.** Two
  HMAC-SHA256 passes per call (`spec/envelope.md` §3) come to ~900 ns at 16 bytes against a
  ~300 ns seal, and at 64 KiB HMAC-SHA256 is still slower per byte than AES-GCM
  (19.4 µs vs 7.9 µs for the same 64 KiB), so the ratio stays near 3.6 rather than converging to
  one. Anyone choosing between the two variants for a write-heavy column should know the
  deterministic one is several times the cost, and no document said so before this ran.

`envelope/parse` is 1.21–1.23 ns and identical across v1, v2 and v3, which is the invariant that
case exists to hold: parsing reads a version byte and computes offsets, and must never start
scanning the body.

### An optimisation this found, and why it is not taken here

`derive_nonce_key` — `HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")` — measures 455 ns and depends on
**nothing but the key**, yet `encrypt_det` recomputes it on every call: it is roughly half of the
896 ns that deterministic nonce derivation costs at 16 bytes, and about a third of `seal_det`.
Caching it per `UDF_INIT` would be a ~36% cut to the deterministic encrypt path at small sizes.

It is deliberately not done in this change. The key arrives as a per-row SQL argument, so a cache
has to hold a copy of the key to know whether it is still valid — and holding derived key material
and a key copy across rows is exactly what `crypto-safety.md` pushes against ("복사본을 만들었다면
사용 직후 `OPENSSL_cleanse`"). That is a design decision with a security dimension, so it belongs in
`docs/design.md` as an amendment before it belongs in `src/`. Recording the measurement is the
useful half; this file is where the argument would start.

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

The reference environment is the one CI uses, so the gate is checked against the same class of machine
that produced it: **`ubuntu-24.04` GitHub-hosted runner, MySQL 8.4.11 in the official container,
`RelWithDebInfo` component, 300,000 rows of which 29,918 match `'%김%'`.** Three consecutive `load`
workflow runs, 40 measured iterations per session after 3 warm-ups, GCM and `AES_DECRYPT` interleaved
per iteration with the order alternating.

| Sessions | gcm p50 | gcm p95 | aes p95 | p95 ratio | ratio spread |
|---|---|---|---|---|---|
| 1 | 233 / 245 / 234 ms | 235 / 255 / 238 ms | 295 / 269 / 277 ms | 0.799 / 0.947 / 0.859 | 1.19x |
| 8 | 930 / 1004 / 995 ms | 1007 / 1073 / 1061 ms | 1147 / 1154 / 1180 ms | 0.878 / 0.930 / 0.899 | 1.06x |
| 32 | 3736 / 4000 / 4009 ms | 3882 / 4172 / 4161 ms | 4412 / 4555 / 4557 ms | 0.880 / 0.916 / 0.913 | 1.04x |

Three values per cell, one per run, in run order. What the runs establish:

* **GCM is faster than the CBC builtin at every measured point** — every ratio is below 0.95. The
  authenticated cipher is not what this costs; the row scan is, and `AES_DECRYPT` pays the same one.
* **The ratio is only as stable as the number of samples behind it.** One session means 40 samples,
  where 8 and 32 sessions accumulate 320 and 1280, and the spread follows exactly that: 1.19x, 1.06x,
  1.04x. This is why the gate is 1.10 rather than 1.05. An earlier set of three runs at 20 samples
  spread the one-session ratio 0.809–0.928 for the same reason, and before that the same code reported
  the *maximum* of 20 as "p95", which happened to look steadier while measuring something else.
* **Interleaving is what makes any of this comparable.** Measuring every GCM session and then every AES
  session let one slow period on a shared runner land entirely on one variant: the nightly reported
  1.247 at eight sessions while its neighbours sat near 0.84.
* **`Created_tmp_disk_tables` did not move in any run**, at any session count — the question
  `docs/design.md` §5.3 raised about plaintext reaching disk-based temporary tables. It stays an
  observation about this workload rather than a guarantee: a query that adds a sort or a large grouping
  can still spill, so every run keeps the counter in its JSON.
* **300,000 rows scanned, decrypted and matched in 255 ms p95 serially**, worst of three runs.
  `docs/design.md` §1.2 estimated ~1.1 s for pulling 100,000 candidate rows into the application and
  decrypting them there.

Reproduce with `gh workflow run load.yml -f rows=300000`, or locally with
`python tests/load/run.py --rows 300000 --concurrency 1,8,32 --baseline aes --gate tests/load/baseline.json`.
