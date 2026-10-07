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
  and why a regression under roughly 20% is invisible to it. In process against a work-matched
  reference the spread is 1.025x, so the gate here — also 1.10 — catches a ~7% regression.
* **Attribution.** When the load ratio moves, nothing says whether it was sealing, opening, nonce
  derivation, envelope parsing, buffer handling or the server. Each of those has its own case here.
* **Sizes the fixture never produces.** The load rows are Korean names, so every load number is
  from the small end. 4 KiB and 64 KiB are measured only here.
* **Cost.** Seconds, with no server. It still runs on the merge rather than on every pull request —
  a ratio on each PR is four minutes and a number nobody reads — but the option is there if a
  change ever makes per-PR measurement worth it.

Run it with `scripts/bench.sh --gate`. Keep the default measurement budget when gating: at
`GCM_BENCH_MIN_TIME=0.05s` the same machine that produced 1.02 produced 1.11, which is the gate
failing on the budget rather than on the code. The reference
environment is `ubuntu-24.04` with GCC and the distribution's OpenSSL 3, which is what
`bench.yml` runs on; on any other host the script reproduces that in a container, because a ratio
compared against a baseline recorded elsewhere means nothing.

### Reference baseline

`ubuntu-24.04` GitHub-hosted runner, GCC, the distribution's OpenSSL 3, `RelWithDebInfo`, three
consecutive `bench` workflow runs. **Every gated ratio is the case divided by a straight-line
implementation of the same algorithm**, so ~1.0 means this project's structure — envelope bytes,
error mapping, buffer handling, `OPENSSL_cleanse` — costs nothing measurable.

| Case | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `open` | 1.016 / 1.007 / 1.019 | 1.025 / 1.018 / 1.029 | 1.007 / 1.008 / 1.012 | 1.006 / 1.000 / 1.002 |
| `seal_random` | 0.996 / 1.011 / 0.996 | 1.002 / 0.986 / 1.011 | 1.014 / 1.006 / 1.008 | 1.012 / 1.005 / 1.006 |
| `seal_det` | 1.009 / 1.011 / 1.012 | 1.013 / 1.019 / 1.013 | 1.009 / 1.010 / 1.003 | 1.003 / 1.003 / 0.999 |

An arm64 macOS laptop running the same suite in the container measures 0.965–1.020 across the twelve,
with absolute times about 2.2x faster than the runner (`open` at 64 KiB: 7,857 ns against 17,070 ns).
Different instruction sets, a 2.2x speed difference, and the ratio moves by 2%. That is the point of a
work-matched reference: it is a property of this code rather than of the machine. Only the un-gated
"against a plain seal" numbers below move with hardware.

All twelve land between **0.986 and 1.029**, with a run-to-run spread of **1.025x**. The gate is
therefore 1.10 — 7% above the worst observation and about double the observed variance — which makes
this the finest-grained gate in the project: it fails on a ~7% structural regression where the load
gate cannot see anything under ~20%.

That any of this is gateable is a property of the references, and it was not true of the first
version, which divided all three encrypt cases by a bare seal. The clearest way to see why is to put
the runner's own speed next to the ratio it produced — three runs, same workflow, same
`ubuntu-24.04` label:

| Bare 64 KiB seal on that runner | 4,565 ns | 6,541 ns | 17,058 ns |
|---|---|---|---|
| `seal_det` / bare seal, 64 KiB | 9.673 | 6.803 | 3.590 |

The runner fleet varies by **3.7x** on AES-GCM throughput, and the old ratio tracked it inversely and
almost exactly. The absolute HMAC numbers over those same runs held to 1.15x, so nothing about the
measured code was moving: the quotient was reporting how that CPU's SHA throughput compares to its
AES throughput. Matching each reference to its case's work mix collapsed the spread to 1.025x.

One limit worth stating rather than glossing: all four runs with the new references landed on the
slower end of the fleet (implied bare seal 17,065–18,937 ns), so the work-matched metric has not yet
been *observed* across that 3.7x spread. The arm64 cross-check below is what currently stands in for
it — different instruction sets, absolute times 2.2x apart, ratios within 0.965–1.029 — and a run
that lands on a fast runner will either confirm it or be the most interesting bench failure this
project has had.

### Per suite (amendment A10)

Every gated case runs once per suite — `aes256`, `aes192`, `aes128` — and each divides by a reference
running the **same cipher**, so the gated ratio stays what it was: this project's structure over a
straight-line implementation of the same algorithm. The ceiling is 1.10 for all three, because the
claim is the same; the suites share every line of code except the fetched cipher. What the suites cost
*relative to each other* is a separate, un-gated number (`*_vs_aes256` in `ratios.json`).

The initial developer-machine measurements used an arm64 laptop running the reference container,
with other containers resident, for two consecutive runs. They are a rehearsal of the gate, not its
baseline. The first run put four cases over the gate, **three of them AES-256**
(`seal_det/aes256/256` at 1.553). Host contention is a possible explanation, not a demonstrated cause.
The second run produced:

| Gated ratio, min–max over the four sizes | `aes256` | `aes192` | `aes128` |
|---|---|---|---|
| `open` | 0.918–0.976 | 0.947–1.031 | 0.837–1.028 |
| `seal_random` | 0.975–1.049 | 0.953–1.013 | 0.951–1.002 |
| `seal_det` | 0.877–1.123 | 0.858–0.956 | 0.971–1.065 |

One ratio still breached the gate: `seal_det/aes256/16` at 1.123. The new suites passed in this run.
The existing CI measurements and these laptop runs are different environments; the earlier CI spread
cannot be used as an uncertainty bound for this host.

**Observed core times, not a finding of equal performance.** The `gcm` side of AES-192 and AES-128
divided by AES-256, second developer-machine run:

| vs `aes256` | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `open/aes192` | 1.07 | 1.00 | 1.00 | 0.97 |
| `open/aes128` | 1.05 | 0.99 | 1.00 | 1.06 |
| `seal_random/aes192` | 1.01 | 0.99 | 1.06 | 1.16 |
| `seal_random/aes128` | 1.05 | 0.99 | 1.02 | 1.05 |
| `seal_det/aes192` | 0.85 | 0.98 | 0.96 | 0.98 |
| `seal_det/aes128` | 0.81 | 1.03 | 0.99 | 0.99 |

The ratios range from 0.81 to 1.16: differences are visible, but two runs do not establish how much is
repeatable. Hardware acceleration alone does not imply that key-size differences are negligible.
The deterministic construction performs the same two HMAC operations for every suite, but the
relative cost of that work and the cipher still depends on the machine and input size. These core
measurements do not determine SQL query latency.

#### First CI per-suite core run

[Run 37572643103](https://github.com/devgyurak/mysql-gcm/actions/runs/37572643103), 2026-10-07,
commit `e420a5b`, on the `ubuntu-24.04` reference runner passed all 36 ceilings. The run artifact
contains the raw `results.json` and derived `ratios.json`.

| Gated ratio, min–max over the four sizes | `aes256` | `aes192` | `aes128` |
|---|---|---|---|
| `open` | 1.003–1.028 | 1.005–1.038 | 0.995–1.026 |
| `seal_random` | 1.004–1.011 | 0.998–1.016 | 0.997–1.006 |
| `seal_det` | 1.003–1.017 | 1.003–1.016 | 1.001–1.019 |

The un-gated suite-to-AES-256 ratios in this run range from 0.919 to 1.012. At 64 KiB, AES-128
`open` took 0.919 times the AES-256 time and `seal_random` took 0.931 times it. This is evidence
against a blanket claim that smaller suites never save time on hardware with AES acceleration.
It is one run, not a repeatability estimate; the remaining repeated measurements are tracked in #18.

A subsequent local review run at `e420a5b` plus the review fixes used the standard
`scripts/bench.sh --gate` settings (0.5 seconds per case, one repetition). It failed three of the
36 ceilings: `seal_random/aes128/256` at 1.105, `seal_det/aes256/4096` at 1.109 and
`seal_det/aes192/16` at 1.263. The cause has not been isolated. The 1.10 ceilings remain unchanged;
the earlier CI pass does not make this local failure a pass or establish that it is only noise.

`envelope/parse` for the four A10 versions measured 1.5–2.1 ns against 1.3–1.4 ns for v2 and v3 on
the developer-machine run. The suite table order is AES-256, AES-192, AES-128, so lookup position
differs between suites; these timings alone do not isolate the cost of that lookup.

### What determinism costs

Reported, never gated: each encrypt variant against a **plain** seal. This is the number to read when
choosing between `gcm_encrypt` and `gcm_encrypt_det`, and it is exactly the number that moves with the
machine, which is why it cannot be a threshold.

| Against a plain seal | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `gcm_encrypt` | 2.74–3.17 | 2.56–3.00 | 1.64–1.78 | 1.07–1.08 |
| `gcm_encrypt_det` | 4.87–4.90 | 4.65–4.83 | 3.96–4.04 | 3.56–3.60 |

* **`gcm_encrypt` pays a constant ~450 ns for `RAND_bytes(12)`** — a factor of ~3 on a 16-byte value,
  ~7% at 64 KiB. The price of a fresh nonce, not overhead to remove.
* **`gcm_encrypt_det` costs roughly 3.5–5x a plain seal, and the cost is HMAC rather than the
  cipher.** Two HMAC-SHA256 passes (`spec/envelope.md` §3) dominate at every size measured here.
  Nothing in this project's documentation said the deterministic variant was several times the cost
  before these benchmarks ran; it is worth knowing before putting it on a write-heavy column.
* **The ratio's direction with size depends on the CPU.** On these runs it falls from 4.9 to 3.6, and
  on a different `ubuntu-24.04` runner with faster AES it *rose* from 5.6 to 9.7 — AES-GCM has
  hardware acceleration nearly everywhere while SHA-256 often does not, so the balance between them
  varies by machine. Treat "several times a plain seal" as the durable statement and re-measure on
  the hardware you care about.

`envelope/parse` is ~2.2–3.1 ns and equal across v1, v2 and v3, which is the invariant that case
exists to hold: parsing reads a version byte and computes offsets, and must never begin scanning the
body. It is recorded rather than ratio-gated — there is no OpenSSL operation to divide it by, and an
absolute ceiling of a few nanoseconds on a shared runner would be a coin toss, not a gate.

### An optimisation this found, and why it is not taken here

`derive_nonce_key` — `HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")` — measures 830–1120 ns on the
reference runner and depends on **nothing but the key**, yet `encrypt_det` recomputes it on every
call: roughly half of deterministic nonce derivation at small sizes, and around 40% of `seal_det`.
Caching it per `UDF_INIT` is a real saving on the deterministic encrypt path.

It is deliberately not done. The key arrives as a per-row SQL argument, so a cache must also hold a
copy of the key to know whether it is still valid — and keeping derived key material plus a key copy
alive across rows is precisely what `crypto-safety.md` pushes against. That is a design decision with
a security dimension, so per `AGENTS.md` §9 it belongs in `docs/design.md` as an amendment before it
belongs in `src/`. Recording the measurement is the useful half; this is where the argument would
start.

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

* **GCM was faster than the CBC builtin at every point in these three runs** — every ratio is below
  0.95. That comparison does not isolate scanning from cryptographic work or establish which dominates.
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

### Per suite — developer-machine run (indicative only, NOT a baseline)

The same question one layer up: does the suite change what `gcm_decrypt(col) LIKE` costs? Docker on an
arm64 macOS laptop, MySQL 8.4.11, the component from `develop` after #17, 100,000 rows of which 9,928
match `'%김%'`, 40 measured iterations per session after 3 warm-ups, one run per suite. Each suite's
`AES_DECRYPT` baseline is `aes-256-cbc` whatever the suite — the question is what each costs against the
builtin a deployment uses today, and a fixed denominator is what lets the three rows be read against
each other.

| Suite | Sessions | gcm p50 | gcm p95 | aes p50 | aes p95 | p95 ratio |
|---|---:|---:|---:|---:|---:|---:|
| `aes256` | 1 | 41.6 ms | 44.5 ms | 38.3 ms | 42.2 ms | 1.053 |
| `aes192` | 1 | 37.6 ms | 45.8 ms | 39.1 ms | 45.4 ms | 1.010 |
| `aes128` | 1 | 36.0 ms | 42.7 ms | 36.9 ms | 45.8 ms | 0.933 |
| `aes256` | 8 | 98.4 ms | 123.8 ms | 127.5 ms | 155.7 ms | 0.795 |
| `aes192` | 8 | 91.3 ms | 110.7 ms | 126.6 ms | 143.1 ms | 0.773 |
| `aes128` | 8 | 98.3 ms | 111.5 ms | 125.3 ms | 140.7 ms | 0.792 |

`Created_tmp_disk_tables` did not move for any suite.

The raw GCM p95 spread (maximum divided by minimum, minus one) is 7.3% at one session and 11.8% at
eight. The CBC-normalized ratios have a different spread: 12.9% and 2.8%, respectively. The baseline
algorithm is fixed, but its measured time is not; those quantities must not be interchanged.
One run per suite gives no estimate of this host's run-to-run variation. The older CI spread is not
an uncertainty bound for these laptop measurements, and neither table isolates row-scan cost from
cryptographic work. Profiling or an experiment that separates those costs is needed for that claim.

### First CI per-suite SQL runs

On 2026-10-07, commit `e420a5b`, each suite completed one `load.yml` dispatch on a separate
GitHub-hosted `ubuntu-24.04` runner: MySQL 8.4.11, 300,000 rows, 29,918 matches, 40 measured iterations
per session after three warm-ups. All three passed the unchanged load gate, and each reported zero
additional disk temporary tables. The separate machines mean absolute times cannot rank the suites.

| Suite / run | Sessions | GCM p95 (ms) | AES-256-CBC p95 (ms) | p95 ratio |
|---|---:|---:|---:|---:|
| [aes256](https://github.com/devgyurak/mysql-gcm/actions/runs/37572651145) | 1 | 120.472 | 160.354 | 0.751 |
| aes256 | 8 | 522.388 | 599.893 | 0.871 |
| aes256 | 32 | 1950.099 | 2185.321 | 0.892 |
| [aes192](https://github.com/devgyurak/mysql-gcm/actions/runs/37572645828) | 1 | 236.918 | 269.222 | 0.880 |
| aes192 | 8 | 1094.004 | 1185.938 | 0.922 |
| aes192 | 32 | 4310.471 | 4661.917 | 0.925 |
| [aes128](https://github.com/devgyurak/mysql-gcm/actions/runs/37572648637) | 1 | 139.712 | 167.183 | 0.836 |
| aes128 | 8 | 563.286 | 618.817 | 0.910 |
| aes128 | 32 | 2081.892 | 2337.002 | 0.891 |

Repeated runs for all three suites remain necessary to characterize variability; #18 tracks that
work. Reproduce with `gh workflow run load.yml -f suite=aes192` (or `aes128` / `aes256`). A smaller
suite does not get a looser gate: every run is checked against the existing 1.10 CBC-relative p95 ceiling.
