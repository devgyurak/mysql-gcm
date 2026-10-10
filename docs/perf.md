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

A limit this file used to state: every run with the new references had landed on the slower end of
the fleet (implied bare seal 17,065–18,937 ns), so the work-matched metric had not been *observed*
across that 3.7x spread, and only the arm64 cross-check below stood in for it. That changed on
2026-10-07: [run 37576902281](https://github.com/devgyurak/mysql-gcm/actions/runs/37576902281)
landed on a fast runner — bare 64 KiB seal **6,529 ns**, 2.6x faster than the three runs beside it at
17,070–17,080 ns — and its thirty-six gated ratios stayed within **1.001–1.034**. The quotient did
not move with the machine, which is the property the references were redesigned to have.

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

#### CI per-suite core runs

Four `bench` runs on the `ubuntu-24.04` reference runner on 2026-10-07, all on the same benchmark
code: [37572643103](https://github.com/devgyurak/mysql-gcm/actions/runs/37572643103) (`e420a5b`),
[37574295361](https://github.com/devgyurak/mysql-gcm/actions/runs/37574295361) (`fd4dfb0`),
[37576703159](https://github.com/devgyurak/mysql-gcm/actions/runs/37576703159) (the merge of #20)
and [37576902281](https://github.com/devgyurak/mysql-gcm/actions/runs/37576902281) (dispatched on
`develop`). Every run passed all 36 ceilings. Each artifact holds the raw `results.json` and the
derived `ratios.json`.

| Gated ratio, min–max over four sizes × four runs | `aes256` | `aes192` | `aes128` |
|---|---|---|---|
| `open` | 0.998–1.030 | 1.001–1.044 | 0.978–1.037 |
| `seal_random` | 1.000–1.014 | 0.998–1.016 | 0.997–1.019 |
| `seal_det` | 0.993–1.023 | 1.001–1.026 | 0.982–1.024 |

All 144 observations fall between **0.978 and 1.044** — the band the twelve AES-256 ratios occupied
over the original three baseline runs (0.986–1.029), widened by 0.008 at the bottom and 0.015 at the
top with four times the observations (144 against 12 cases × 3 runs = 36). The fourth run is the one that landed on a fast runner (bare 64 KiB seal
6,529 ns against 17,070–17,080 ns for the other three) and its ratios sit inside the same band, which
is the cross-fleet confirmation the reference baseline above was waiting for.

The un-gated suite-to-AES-256 ratios, over the same four runs (min–max):

| vs `aes256` | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `open/aes192` | 0.979–1.022 | 0.976–1.009 | 0.961–1.007 | 0.933–0.969 |
| `open/aes128` | 0.978–0.998 | 0.961–0.988 | 0.911–0.951 | 0.864–0.931 |
| `seal_random/aes192` | 0.992–1.009 | 0.995–1.007 | 0.979–0.984 | 0.943–0.969 |
| `seal_random/aes128` | 0.995–0.999 | 0.994–1.001 | 0.962–0.966 | 0.890–0.947 |
| `seal_det/aes192` | 1.000–1.001 | 0.997–1.008 | 0.992–0.997 | 0.990–1.014 |
| `seal_det/aes128` | 0.999–1.003 | 0.995–1.000 | 0.982–0.992 | 0.978–0.982 |

Across all six rows, the observed range by size is **0.978–1.022 at 16 B, 0.961–1.009 at 256 B,
0.911–1.007 at 4 KiB and 0.864–1.014 at 64 KiB**: the smaller suites' advantage, where there is one,
grows with the size, and AES-128 `open` is 7–14% cheaper than AES-256 at 64 KiB. The 64 KiB column is
also where the runs disagree most, and the widest value (0.864) was observed on the fast runner; these
runs do not separate per-call setup from block processing, so the cause of that difference is not
established. `seal_det` stays within 0.978–1.014 at every size, consistent with a cost dominated by
HMAC-SHA256, which the key length does not touch. The smallest size measured is 16 bytes; a Korean
name in the load fixture is 9, which these benchmarks did not measure directly.

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

### Per-statement reuse (amendment A11): what the context and the nonce key cost per row

The first version of this file recorded an optimisation and declined to take it: `derive_nonce_key`
depends on nothing but the key yet `encrypt_det` recomputed it on every row, and caching it meant
holding a copy of the key across rows, which `crypto-safety.md` did not allow without an amendment.
Amendment A11 is that amendment. It also covers the larger case the same reasoning had hidden:
`gcm_decrypt` built an `EVP_CIPHER_CTX` and ran the key schedule on every row, and at the size of a
name that setup *was* the cost.

**Where the time was.** Two control queries were added to the load runner, both with the predicate
`CHAR_LENGTH(x) > 0`, which is true for every row, so both count the same rows: `plain_len` over a
plaintext utf8mb4 column and `gcm_len` over `gcm_decrypt(...)`. The queries run in an order where
every query is preceded by every other equally often. Their differences are **differences of p95
between queries**, not execution times of components, and they bracket rather than attribute.

On the laptop, 100,000 rows, one session, three runs with the pre-A11 component: `plain_len` p95
6.7–11.5 ms (13–24% of the `gcm` query's p95), `gcm_len − plain_len` 38.4–39.0 ms (73–85%), and
`gcm − gcm_len` −1.8 to 7.4 ms, i.e. not distinguishable from zero. Divided over the rows, the
`gcm_len − plain_len` difference is 384–391 ns per row, beside a bare 16-byte `open` of about 280 ns
in the same container. That is consistent with the per-call cipher setup being most of what the
decrypting call adds, and it is what made the context worth keeping; it does not by itself prove
where inside the call the time goes.

**Core, container on the laptop, one run** (the reference for each reused path keeps the same state
across calls, so the gated ratio stays structure over algorithm; `*_vs_*` is what the reuse saves):

| aes256 | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `open` (fresh context per call) | 333 ns | 325 ns | 843 ns | 8,547 ns |
| `open_session` (context kept) | 143 ns | 165 ns | 742 ns | 9,882 ns |
| `open_session` / `open` | **0.43** | 0.51 | 0.88 | 1.16 (one run; not established whether noise or a regression) |
| `seal_det` (nonce key per call) | 1,599 ns | 1,689 ns | 3,636 ns | 32,734 ns |
| `seal_det_session` (nonce key kept) | 1,051 ns | 1,123 ns | 3,022 ns | 32,472 ns |
| `seal_det_session` / `seal_det` | **0.66** | 0.67 | 0.83 | 0.99 |

AES-192 and AES-128 show the same shape (`open_session`/`open` 0.38–0.45 at 16 B). The saving is
the per-call setup, so it is a constant: around 190 ns on a decrypt and around 550 ns on a
deterministic seal, dominant on a name and invisible on 64 KiB.

**The gate, and why `open_session` has a wider ceiling at the small sizes.** The structure around
one open — the envelope parse, the suite lookups, the constant-time compare of the key copy — costs
the same few tens of nanoseconds whether the algorithm under it costs ~600 ns (a fresh context, on
the CI runner) or ~200 ns (a kept one), so the same structure is a larger ratio over the cheaper
reference. Three CI `bench` runs on 2026-10-07 (commit `1aa0ba7`;
[37582494590](https://github.com/devgyurak/mysql-gcm/actions/runs/37582494590),
[37582537352](https://github.com/devgyurak/mysql-gcm/actions/runs/37582537352),
[37583117389](https://github.com/devgyurak/mysql-gcm/actions/runs/37583117389)) set the ceilings:

| Gated ratio, min–max over three suites × three runs | 16 B | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|---|
| `open_session` | 1.114–1.193 | 1.081–1.162 | 1.007–1.224 | 0.914–1.007 |
| `seal_det_session` | 1.016–1.053 | 1.025–1.067 | 0.960–1.093 | 0.939–1.006 |
| `open` (one call, for comparison) | 1.030–1.044 | 0.987–1.061 | 1.008–1.126 | 0.975–1.016 |

`open_session` is 1.30 at 16 and 256 B — the ~9% headroom over the worst observation that the 1.10
ceilings have over theirs — and 1.15 at 4 KiB; `seal_det_session` never exceeded 1.093 and is 1.15
up to 4 KiB; both are 1.10 at 64 KiB. The one-call `open`, which an earlier version of this PR had
pushed to 1.11–1.13 at 16 and 256 B with a heap session and two context resets per call, is back
inside 1.10 there.

**Not absorbed, then explained (#24).** The third run landed on a runner about five times faster
than the usual class (bare 64 KiB seal 3,237 ns against ~17,000) and there three values broke their
ceilings: `open_session/aes256/4096` 1.224, `seal_det/aes256/256` 1.118 and `open/aes192/4096`
1.126. No ceiling was widened to absorb them; #24 investigated, recorded below.

### Runner classes, and why the gate now uses five interleaved repetitions (#24)

`bench.yml` now records each runner's CPU. Thirty-four CI runs on 2026-10-07 met six classes:

| CPU | bare 64 KiB seal |
|---|---:|
| AMD EPYC 7763 (Zen 3) | ~17,000 ns |
| AMD EPYC 9V74 (Zen 4) | ~6,500 ns, once ~18,900 |
| Intel Xeon Platinum 8370C (Ice Lake) | ~5,900 ns |
| Intel Xeon Platinum 8573C (Emerald Rapids) | ~4,800–5,800 ns |
| Intel Xeon 6973P-C (Granite Rapids) | ~4,200 ns |
| AMD EPYC 9V45 (Zen 5) | ~3,000–3,250 ns |

What the runs showed, in order:

- **A11 did not regress the one-call paths.** On the three CPU classes that both a pre-A11 and a
  post-A11 branch landed on (Zen 3, Zen 4, Emerald Rapids), the one-call ratios matched: 1.02–1.045
  either side.
- **The breaches came from the harness, not the code.** With five repetitions but run in
  registration order, two of twelve post-A11 runs still failed — on Zen 5 and Granite Rapids — and
  broke ceilings even at 64 KiB (`seal_det_session/aes128/65536` 1.146), where the structure under
  test is a negligible share; other runs on the same CPU models passed. Benchmarks ran in
  registration order, so every `gcm/*` case was measured before every `ref/*` reference, minutes
  apart, and a case's repetitions ran back to back: a slow stretch on a shared runner landed on one
  side of a ratio, and the median of contiguous repetitions could not remove it. `gate.py` also kept
  only the last repetition of each case, so asking for repetitions bought nothing; it now uses the
  median.
- **With repetitions randomly interleaved** (`--benchmark_enable_random_interleaving`), eight runs —
  three of them on Zen 5, the class that produced #24 — passed every ceiling, and no 64 KiB ratio
  exceeded 1.05. The worst `open_session` values were 1.236 at 16 B and 1.09 at 4 KiB on Zen 5,
  inside 1.30 and 1.15.

So the gate runs five interleaved repetitions and judges the medians (`bench.yml` default, and
`scripts/bench.sh --gate`). The bench step takes ~9.5 minutes instead of ~2.5; it runs on merges and
nightly only. No ceiling changed. Granite Rapids did not come up in the interleaved runs, so it has
one failing non-interleaved sample and no interleaved one; that is the gap still open.

The first container run on the laptop, before any of this, had measured `open_session` at
1.04–1.40 and put two one-call cases over 1.10; those numbers set nothing.

**SQL, MySQL 8.4.11 on the laptop, 100,000 rows, three runs each way** — the same server, the same
load runner with the balanced order, the `develop` component and then the A11 component. Ranges over
the three runs; the host was running other containers throughout, recorded per run in the artifacts:

| | Sessions | gcm p95 | `AES_DECRYPT` p95 | p95 ratio | `gcm_len − plain_len` per row |
|---|---:|---:|---:|---:|---:|
| before | 1 | 45.8–52.5 ms | 49.0–61.0 ms | 0.800–0.975 | 384–391 ns |
| after | 1 | 17.9–21.6 ms | 41.3–53.5 ms | **0.393–0.473** | 114–123 ns |
| before | 8 | 110.2–113.7 ms | 126.7–130.3 ms | 0.864–0.881 | 1,010–1,017 ns |
| after | 8 | 26.5–43.0 ms | 143.2–171.0 ms | **0.185–0.252** | 154–223 ns |

At one session the per-row difference falls from ~385 to ~120 ns, close to the bare kept-context
open in the core benchmark. At eight sessions it falls by ~800–860 ns, much more than the ~190 ns the
serial benchmark accounts for. The other columns did **not** stay where they were at eight sessions:
in the after runs `plain_len` rose from 9.9–10.4 to 11.5–18.8 ms and `AES_DECRYPT` from 126.7–130.3
to 143.2–171.0 ms, on a host whose load differed between the runs (recorded per run). Part of the
eight-session ratio's fall therefore comes from its denominator rising; the GCM query's own p95
falling from 110.2–113.7 to 26.5–43.0 ms does not depend on that. At one session `AES_DECRYPT`
measured 49.0–61.0 ms before and 41.3–53.5 ms after, overlapping.
**The cause of the larger eight-session gain is not isolated by these measurements.** One hypothesis is
contention among threads in OpenSSL 3's per-call context setup, which keeping the context would
avoid; nothing here separates that from other explanations, and the observed gain is what this
section reports. The same shape was seen on MySQL 9.4 during the prototype (1.06 → 0.48 at one
session, 1.27 → 0.26 at eight). 32 sessions have not been measured with A11; the CI `load` runs are
the reference-runner numbers, and the nightly's own ratio will say whether the 1.10 gate's centre
has moved.

**What a smaller value gains and a larger one does not.** On a 64 KiB value the kept context
measured 0.99 against a fresh one in the CI runs and 1.16 in one laptop run; with the setup a small
share of a cipher-dominated call, no gain is expected there, and whether the laptop's 1.16 is noise
or a regression is not established by one run. Everything in
this section is about values the size of a name, which is what the load fixture and the project's
reason to exist are.

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

### CI per-suite SQL runs — three per suite

The README's chart is drawn from these nine runs by `scripts/plot-perf.py`, from
`docs/assets/perf/load-ratios.json`; change the table, the JSON and the SVGs together (lint runs
`plot-perf.py --check`).

On 2026-10-07 each suite completed three `load.yml` dispatches, each on its own GitHub-hosted
`ubuntu-24.04` runner: MySQL 8.4.11, 300,000 rows, 29,918 matches, 40 measured iterations per session
after three warm-ups, the first run on commit `e420a5b` and the other two on `develop` after #20
merged. All nine passed the unchanged load gate, and every run reported zero additional disk temporary
tables. Three values per cell, in run order; the links are the runs.

| Suite | Sessions | GCM p95 (ms) | AES-256-CBC p95 (ms) | p95 ratio | ratio spread |
|---|---:|---:|---:|---:|---:|
| `aes256` [1](https://github.com/devgyurak/mysql-gcm/actions/runs/37572651145) [2](https://github.com/devgyurak/mysql-gcm/actions/runs/37576805707) [3](https://github.com/devgyurak/mysql-gcm/actions/runs/37576899175) | 1 | 120 / 247 / 264 | 160 / 273 / 275 | 0.751 / 0.905 / 0.960 | 1.28x |
| `aes256` | 8 | 522 / 1,010 / 1,022 | 600 / 1,143 / 1,146 | 0.871 / 0.884 / 0.891 | 1.02x |
| `aes256` | 32 | 1,950 / 3,887 / 3,900 | 2,185 / 4,393 / 4,402 | 0.892 / 0.885 / 0.886 | 1.01x |
| `aes192` [1](https://github.com/devgyurak/mysql-gcm/actions/runs/37572645828) [2](https://github.com/devgyurak/mysql-gcm/actions/runs/37576799151) [3](https://github.com/devgyurak/mysql-gcm/actions/runs/37576837466) | 1 | 237 / 235 / 183 | 269 / 286 / 223 | 0.880 / 0.823 / 0.820 | 1.07x |
| `aes192` | 8 | 1,094 / 986 / 817 | 1,186 / 1,096 / 945 | 0.922 / 0.900 / 0.865 | 1.07x |
| `aes192` | 32 | 4,310 / 3,845 / 3,271 | 4,662 / 4,302 / 3,720 | 0.925 / 0.894 / 0.879 | 1.05x |
| `aes128` [1](https://github.com/devgyurak/mysql-gcm/actions/runs/37572648637) [2](https://github.com/devgyurak/mysql-gcm/actions/runs/37576802634) [3](https://github.com/devgyurak/mysql-gcm/actions/runs/37576868446) | 1 | 140 / 164 / 238 | 167 / 197 / 290 | 0.836 / 0.832 / 0.821 | 1.02x |
| `aes128` | 8 | 563 / 727 / 983 | 619 / 870 / 1,137 | 0.910 / 0.835 / 0.864 | 1.09x |
| `aes128` | 32 | 2,082 / 2,936 / 3,799 | 2,337 / 3,411 / 4,460 | 0.891 / 0.861 / 0.852 | 1.05x |

What the nine runs establish, and what they do not:

* **Every suite is under the gate in every run.** The 27 ratios span 0.751–0.960, the worst being
  AES-256 at one session — a ratio difference of 0.140 below the 1.10 ceiling.
* **The milliseconds are the runner, not the suite.** The same suite's one-session GCM p95 ranges
  from 120 to 264 ms (AES-256) and from 140 to 238 ms (AES-128) across its three runs, because each
  run lands on whichever machine the fleet provides, and the `AES_DECRYPT` column moves with it. A
  ranking of the suites by p95 would change order from run to run; a ranking by ratio does not
  separate them.
* **The ratio spreads match what the AES-256 baseline already showed**: wide at one session (40
  samples), narrow at 8 and 32 (320 and 1,280). AES-256's one-session spread here, 1.28x, is wider
  than the 1.19x of the 0.1.0 baseline, driven by the first run's 0.751 on a fast machine.
* **At 8 and 32 sessions the three suites overlap**: AES-256 0.871–0.892, AES-192 0.865–0.925,
  AES-128 0.835–0.910. AES-128 is the lowest on average and AES-192 the highest, but every suite's
  range contains values from the others', so these runs do not rank the suites. Three runs per suite
  is the same sample this file accepts for the release baseline and no more; they bound the spread,
  they do not prove the suites equal.
* **Nothing here separates scanning from decrypting.** That decomposition needs a plaintext column
  measured in the same run, which `tests/load/run.py` does not do yet.

Reproduce with `gh workflow run load.yml -f suite=aes192` (or `aes128` / `aes256`). A smaller suite
does not get a looser gate: every run is checked against the existing 1.10 CBC-relative p95 ceiling.
