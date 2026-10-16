# Keyed n-gram tokens for partial match — what the index leaks (issue #38)

> This is the method and the results of the experiment that design amendment A17 **pre-registered**
> before it was run. The protocol — threat model, data, attacks, metrics, baselines, variants and
> adoption criteria — is in `docs/design.md` A17 and was frozen at the protocol commit (there was no
> PR 1 review before the experiment ran). This document reports
> against it; it does not move the criteria. No component code exists for any of this, and none may
> until A17's Outcome block is filled and the amendment is restated as adopted or declined.

## The question

Constraint 5: the functions are opaque to the optimizer, so `WHERE gcm_decrypt(col, @k) LIKE '%김%'`
scans and decrypts every candidate row. Issue #38 proposes a keyed n-gram token in a side table with
an ordinary index to narrow the candidates first, with the real decryption as the final filter. The
tokens are deterministic, so the side table exposes the frequency of every n-gram, which rows share
one, and their co-occurrence inside a row. The question is not whether it leaks — it does — but how
much, against what, and at what utility.

## Method

**The token function is modelled, not computed.** Whatever the PRF is, an attacker who can read the
table sees the same `(row, token)` graph, so the harness models it as a seeded **random injection** of
the n-gram space truncated to `b` bits. That is the whole point of the amendment's Python allowance:
the experiment measures leakage with an ideal tokeniser, and performs **no cryptographic operation
and holds no key material** (`tests/leakage/`, never shipped).

**Data.** Only aggregates are committed, each with its source, licence and retrieval date
(`tests/leakage/data/`):

| Language | Surnames | Given names |
|---|---|---|
| Korean | Statistics Korea (KOSIS) 2015 census, top 60 (김 21.5%, top-60 mass 0.981) — **authoritative** | a **modelled** prior: common names per cohort and sex with a Zipf decay, because the Supreme Court statistics are not machine-readable here |
| Latin | US Census 2010, top 60 — **authoritative** | SSA baby names, 1990 cohort, top 60 per sex — **authoritative** |

**Adversary.** S1 — a stolen snapshot with the token table, the ciphertext lengths and public
statistics. A17 registered S2 (the same, plus the birth-year and sex columns as a conditional prior),
but **the harness implements S1 only**: it uses one unconditional prior and does not condition on a
row's columns, so attacks 1 and 2 are S1 attacks and the reported leakage is a **lower bound of S2**.
Of A17's four forms of incompleteness, **two are implemented**: top-K truncation and Dirichlet noise
(α = 50.0); **regional skew and cohort mismatch are not** (`--prior-cohort` defaults to the data
cohort). S3 (known or injected rows) is attack 3. S4 (the log reader) is argued,
not simulated: the search key and the search pattern reach the server logs, and the Korean bigram space
is ~1.2×10⁸, so a holder of the key can enumerate every token. The outcome is total by construction,
and it is why a construction that keeps the search key off the server (C1) removes one whole adversary.

**Attacks.**

1. Frequency rank / maximum-likelihood matching (SciPy's Hungarian on the top-K tokens).
2. Co-occurrence graph matching (cosine similarity of token and n-gram profiles).
3. Known-row seeding for m ∈ {1, 10, 100, 1%} (run at m = 10).
4. Row reconstruction, as retrieval: rank prior names by token-set overlap and take top-1 / top-5.
   **This is a metric computed from the attack-1 mapping, not an independent predictor**, so it is not
   a separate row in the matrix; the bigram-path `reconstruct` function is exercised only by the
   known-answer test, not by the retrieval scorer.

Each attack is validated by a known-answer test and a no-token control, so a broken attack fails
instead of reporting "no leakage". **The evidence is not uniform**: attacks 1 and 3 have full-recovery
known-answer tests and the at-scale V7 control falls to B0 (top-1 0.015 ≈ B0 0.015); attack
2's known-answer test checks only that it matches every observed token (its recovery on that fixture is
0, because the fixture has tied frequencies), and attack 2 has no separate no-token control. The
attacks still demonstrably work at scale (17–32% Korean), but the safety net is weaker than A17
promised. Not attempted: simulated annealing, query-recovery attacks and learning-based attacks.

**Baselines.** B0 (length and prior only: the surname floor, ~21%) and B1 / B1′ (whole-name and split
`gcm_encrypt_det` equality). Every number below is read as an increment over them. **Token recovery
is occurrence-weighted by row frequency** — a token's weight is the number of rows that contain it, the
quantity the side table itself exposes — not by its raw count within a row (which is deduplicated).

## Results

**In one line: on Korean — the language that decides it — the attack recovers 20.7% of n-grams under
the S1 attacks (a lower bound of the registered S2) (17.3–31.7% across attacks), 1.7–3.2× the
registered ceiling.
The index is declined. The numbers are below.**

### Variants (attack 3, an S3 adversary) — leakage beside utility

N = 300k, 20 seeds; the attacker's prior is truncated to the top 40 and noised (**α = 50.0**) —
incomplete side knowledge. Attack 3 seeds from 10 known rows, which A17 classifies as **S3**, not the
S1/S2 the criteria are judged on; the S1 attacks are in the next table and are the primary evidence.
"Candidate fraction" is the mean fraction of rows a token query still returns; "answered" is the
fraction of the four-part query mix (whole name, given name, surname, one syllable) the index can
answer.

**Korean**

| Variant | Candidate fraction | Answered | Token recovery (weighted) | Full-name top-1 | Unique rows |
|---|---|---|---|---|---|
| V0 PRF, no truncation | 0.053 | 1.00 | 0.317 ± 0.030 | 0.194 | 0.0025 |
| V1 bigrams | 0.012 | 0.50 | 0.182 ± 0.036 | 0.081 | 0.0025 |
| V2 trigrams | 0.0025 | 0.25 | 0.055 ± 0.017 | 0.060 | 0.0025 |
| V3 b=8 | 0.064 | 1.00 | 0.267 ± 0.065 | 0.108 | 0.0025 |
| V3 b=12 | 0.054 | 1.00 | 0.309 ± 0.031 | 0.182 | 0.0025 |
| V3 b=16 | 0.053 | 1.00 | 0.318 ± 0.033 | 0.197 | 0.0025 |
| V7 no tokens | 1.000 | 0.00 | 0.000 ± 0.000 | 0.015 | 0.000 |

**Latin**

| Variant | Candidate fraction | Answered | Token recovery (weighted) | Full-name top-1 | Unique rows |
|---|---|---|---|---|---|
| V0 PRF, no truncation | 0.039 | 1.00 | 0.362 ± 0.026 | 0.176 | 0.006 |
| V1 bigrams | 0.019 | 0.75 | 0.417 ± 0.041 | 0.168 | 0.006 |
| V2 trigrams | 0.018 | 0.74 | 0.141 ± 0.030 | 0.057 | 0.006 |
| V3 b=8 | 0.067 | 1.00 | 0.119 ± 0.043 | 0.021 | 0.006 |
| V3 b=12 | 0.041 | 1.00 | 0.281 ± 0.020 | 0.129 | 0.006 |
| V3 b=16 | 0.040 | 1.00 | 0.348 ± 0.028 | 0.165 | 0.006 |
| V7 no tokens | 1.000 | 0.00 | 0.000 ± 0.000 | 0.001 | 0.000 |

**V4 (homophonic) and V5 (padding) are in `results.json` but are not reported above: neither was
validly evaluated.** V5's rows are padded to a fixed length with shared dummies that the attack table
strips, so it is V3-16 (the untruncated V0 vs the 16-bit map differ only by collisions) by construction
and its row records storage cost only. V4's utility is fine — the harness answers a V4 query by asking
for all h homophones, and its candidate fraction matches V0's — but the **attack was not adapted to
homophones**: a one-to-one assignment can recover only one of the h tokens of an n-gram, and the
committed 6.0% is what that gets. An adapted spot check in review (one n-gram to h tokens) measured
about 20.9% on Korean, above the ceiling; it is a review measurement, not a pre-registered one. On that
basis no V4 claim is made, and the decision rests on V0.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/leakage/leakage-utility-dark.svg">
  <img src="docs/assets/leakage/leakage-utility-light.svg" width="100%"
       alt="Scatter of the reported variants, leakage (occurrence-weighted token recovery) against utility (mean candidate fraction a token query returns), for Korean and Latin; down and left is better. V0 and its truncations sit top-left. V4 and V5 are not plotted — they were not validly evaluated.">
</picture>

### Attacks on V0

| Language | Attack | Token recovery (weighted) | Full-name top-1 | Full-name top-5 |
|---|---|---|---|---|
| ko | 1 frequency (S1) | 0.207 ± 0.042 | 0.107 | 0.208 |
| ko | 2 co-occurrence (S1) | 0.173 ± 0.051 | 0.071 | 0.180 |
| ko | 3 seeding, m = 10 (S3) | **0.317 ± 0.030** | 0.194 | 0.307 |
| latin | 1 frequency (S1) | 0.102 ± 0.011 | 0.008 | 0.039 |
| latin | 2 co-occurrence (S1) | 0.265 ± 0.027 | 0.071 | 0.189 |
| latin | 3 seeding, m = 10 (S3) | **0.362 ± 0.026** | 0.176 | 0.283 |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/leakage/naming-attacks-dark.svg">
  <img src="docs/assets/leakage/naming-attacks-light.svg" width="100%"
       alt="Grouped bars of occurrence-weighted token recovery for attacks 1-3 on V0, Korean and Latin. Attack 3 (known-row seeding) is highest on both; all are well above the 10 percent ceiling on Korean.">
</picture>

**Baselines.** Korean B0 surname accuracy 0.212, B0 whole-name top-1 0.015; B1 distinct whole names
7,343 of 300k (unique fraction 0.002); B1′ distinct surnames 79 (unique 0.000) and given names 100
(unique 0.000). Latin B0 surname 0.008, top-1 0.001; B1 distinct whole names 9,639 (unique 0.006);
B1′ 80 surnames, 139 given names.

### Against the registered criteria

The A17 criteria are judged on the snapshot adversary at **N = 300k**. **The decision is on Korean,
the language the issue is filed for**, and is reported per language (a Latin-only index is not the
requirement, and the b = 8 variant that looks best on Latin saturates its 256-token space):

- **The attacks implement S1, not S2.** A17 registered S2 (a conditional prior from the birth-year
  and sex columns); the harness uses one unconditional prior and does not condition on those columns,
  so attacks 1 and 2 are **S1** attacks. S2 can only recover more, so the measured leakage is a lower
  bound of S2 and the decline is conservative. Recorded as a deviation from the protocol, not a
  pass.
- **Leakage ceiling — occurrence-weighted token recovery ≤ B1 + 10 pp.** B1 exposes only the equality
  of the whole value and recovers no n-gram, so the ceiling is 10 pp. **Under the S1 attacks alone,
  Korean V0 is 20.7% (attack 1) and 17.3% (attack 2)** — 1.7–2.1× the ceiling. The stronger S3 attack 3
  raises it to 31.7%, and Latin V0 is 10.2% (attack 1), 26.5% (attack 2) and 36.2% (attack 3). So the
  ceiling fails under the registered adversary on Korean, not only under the stronger S3 attack. V2
  (trigrams) falls to 5.5% Korean but answers only 25% of the query mix, i.e. it is no longer an index
  for the motivating queries.
- **Surname accuracy and unique-row fraction.** The token table's unique-row fraction is 0.0025 against
  B1′'s 0.000 — a technical fail, but marginal next to the token failure, which decides on its own.
- **Utility floor — p95 ≤ 0.5 × the scan at 1 and 32 sessions.** The harness measures candidate-set
  size, not query latency, so the floor is **not demonstrated**; the V0 candidate fraction (5.3% Korean,
  3.9% Latin; 0.2–6.7% across variants) shows the index does narrow candidates. This does not change the
  outcome: the leakage ceiling fails under S1 first.

**Which registered criteria were measured.** A17 froze more than the decline needs; the record says
plainly what was and was not run, so nothing is implied to have passed.

| Criterion | Status |
|---|---|
| Token recovery ≤ B1 + 10 pp (S2) | **measured on S1** (a lower bound of S2), **fails on Korean** |
| Full-name top-1/top-5 ≤ B1 + 5 pp | measured for the token attacks (top-1 0.194 Korean at V0); **B1's own top-1/top-5 not measured** |
| Surname accuracy ≤ B1 + 10 pp | **not measured** as an attack metric (B0 is 0.212 Korean) |
| Unique-row fraction ≤ 1.5 × B1′ | measured (0.002 vs 0.000) — a marginal fail |
| Utility p95 floor at 1 and 32 sessions | **not measured** (candidate-set size is reported instead) |
| N ∈ {5k, 50k, 300k, 1M} | only **N = 300k** run |

One finding also stands on its own:

- **The motivating query is the index's worst case.** `'%김%'` selects ~21% of a Korean column (김 is
  21.5% of the census), which is no selectivity worth an index — the very query the issue is filed
  for is the one the index helps the least with.

## Normalisation — the invariant the index must not break

The designated final filter must never miss a row the index should have offered. `tests/leakage/collation/normalisation.sql`
checks, with **plain SQL only**, over a declared repertoire (Korean syllables and jamo, Latin-1 and
extended Latin, a ligature, full width, case/accent variants) plus every substring of every haystack,
for each `(h, q)` where `h LIKE '%q%'` is true whether the token from `q` is contained in the token set
of `h`, **and** whether every n-gram of `q` (orders 1–3) is found in `h` — the index's actual
invariant, not just whole-string containment. Two candidate normalisations were compared on a clean
server of each major (`scripts/leakage-collation.sh`, which asserts the recorded result and runs in
CI):

| Major | N1 `utf8mb4_0900_bin` | N2 `WEIGHT_STRING` | N2 n-gram violations |
|---|---|---|---|
| 8.0.43 | **6 counterexamples** | 0 | 0 |
| 8.4.11 | **6 counterexamples** | 0 | 0 |
| 9.4.0 | **6 counterexamples** | 0 | 0 |

The N1 counterexamples are identical on all three: `CAFÉ`/`café`, `CAFÉ`/`CAFE`, `Ångström`/`ANGSTR`,
`Müller`/`Ü`, `ＡＢＣ`/`ABC`, `Seoul`/`SEOUL`. **A binary token normalisation misses rows the final
filter matches**, so it is not a viable answer to question 4; letting MySQL normalise (N2) holds both
containment checks over this 15-string repertoire. The repertoire is deliberately small; it is not a
proof that N2 holds everywhere, only that it does here while N1 does not. This is the direct
measurement the issue asked for, and it is why the `utf8mb4_general_ci` label in design §5.3 is
corrected to the version-dependent truth in this amendment's Outcome PR.

## What this does and does not show

- It measures leakage **given an ideal tokeniser**. It does not measure the security of any concrete
  PRF, and cannot: that is a separate argument, made where a construction is chosen.
- It assumes an S2 snapshot. S4 is total by construction and is not measured; active tampering, memory
  scraping and query recovery are out of scope. Because S4 is not simulated, this experiment cannot
  rank C1 (key off the server) against C3/C4 on the log axis.
- **The Korean token frequency is dominated by the modelled given names, not the authoritative
  surnames** — 서 (16,848) and 준 (11,997) outrank 김 (10,861) — so the Korean recovery figure is
  substantially a property of the modelled given-name prior. The decline holds, but the Korean margin
  is more model-dependent than a census-derived one would be; the Latin side is fully authoritative.
- **Truncation at b = 8 saturates** the 256-token space on a 300k-row Korean column, so V3-8's low
  recovery is a saturation artefact, not evidence of safety.

- **This is a scoped design review, not a human cryptographic audit** (constraint 13). The result feeds
  the A17 Outcome block and the independent review; it decides nothing on its own.

## Reproduce

```
python -m unittest discover -s tests/leakage -p 'test_*.py'      # the harness and its known-answers
python tests/leakage/experiment.py --out docs/assets/leakage/results.json --resume   # the committed result (slow; rewrites per key)
python scripts/plot-leakage.py --check                          # the charts match the data
scripts/leakage-collation.sh 8.0|8.4|9                          # the normalisation differential
```