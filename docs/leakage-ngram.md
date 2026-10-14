# Keyed n-gram tokens for partial match — what the index leaks (issue #38)

> This is the method and the results of the experiment that design amendment A17 **pre-registered**
> before it was run. The protocol — threat model, data, attacks, metrics, baselines, variants and
> adoption criteria — is in `docs/design.md` A17 and was frozen when PR 1 merged. This document reports
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

**Adversary.** S1/S2 — a stolen snapshot with the token table, the ciphertext lengths, and (for S2)
other plaintext columns (birth year, sex) that make the name prior conditional — with incomplete side
knowledge. Of A17's four forms of incompleteness, **two are implemented**: top-K truncation and
Dirichlet noise (α = 50.0); **regional skew and cohort mismatch are not** (`--prior-cohort` defaults to
the data cohort), so the prior is closer to the data than registered and the reported leakage is a
conservative **upper bound**. S3 (known or injected rows) is attack 3. S4 (the log reader) is argued,
not simulated: the search key and the search pattern reach the server logs, and the Korean bigram space
is ~1.2×10⁸, so a holder of the key can enumerate every token. The outcome is total by construction,
and it is why a construction that keeps the search key off the server (C1) removes one whole adversary.

**Attacks.**

1. Frequency rank / maximum-likelihood matching (SciPy's Hungarian on the top-K tokens).
2. Co-occurrence graph matching (cosine similarity of token and n-gram profiles).
3. Known-row seeding for m ∈ {1, 10, 100, 1%} (run at m = 10).
4. Row reconstruction, as retrieval: rank prior names by token-set overlap and take top-1 / top-5.
   **This is a metric on the attack-1 token mapping, not an independent predictor**, so its row in the
   attack table equals attack 1's; the bigram-path `reconstruct` function is exercised only by the
   known-answer test, not by the retrieval scorer.

Each attack is validated by a known-answer test and a no-token control, so a broken attack fails
instead of reporting "no leakage". **The evidence is not uniform**: attacks 1 and 3 have full-recovery
known-answer tests and the at-scale V7 control falls exactly to B0 (top-1 0.021 ≈ B0 0.022); attack
2's known-answer test checks only that it matches every observed token (its recovery on that fixture is
0, because the fixture has tied frequencies), and attacks 2–4 have no separate no-token control. The
attacks still demonstrably work at scale (25–39% Korean), but the safety net is weaker than A17
promised. Not attempted: simulated annealing, query-recovery attacks and learning-based attacks.

**Baselines.** B0 (length and prior only: the surname floor, ~21%) and B1 / B1′ (whole-name and split
`gcm_encrypt_det` equality). Every number below is read as an increment over them.

## Results

**In one line: on Korean — the language that decides it — every variant useful enough to answer the
query mix recovers n-grams far above the registered ceiling, under both the pre-registered S2 attacks
and the stronger S3 attack 3. The index is declined. The numbers are below.**

### Variants (attack 3, an S3 adversary) — leakage beside utility

N = 300k, 20 seeds; the attacker's prior is truncated to the top 40 and noised (**α = 50.0**) —
incomplete side knowledge. Attack 3 seeds from 10 known rows, which A17 classifies as **S3**, not the
S2 the criteria are judged on; the S2 attacks are in the next table and are the primary evidence.
"Candidate fraction" is the mean fraction of rows a token query still returns; "answered" is the
fraction of the four-part query mix (whole name, given name, surname, one syllable) the index can
answer.

**Korean**

| Variant | Candidate fraction | Answered | Token recovery (weighted) | Full-name top-1 | Unique rows |
|---|---|---|---|---|---|
| V0 uni+bi+tri | 0.074 | 1.00 | 0.388 ± 0.027 | 0.241 | 0.001 |
| V1 bigrams | 0.019 | 0.50 | 0.250 ± 0.032 | 0.127 | 0.001 |
| V2 trigrams | 0.003 | 0.25 | 0.090 ± 0.023 | 0.099 | 0.001 |
| V3 b=8 | 0.084 | 1.00 | 0.357 ± 0.050 | 0.156 | 0.001 |
| V3 b=12 | 0.074 | 1.00 | 0.395 ± 0.038 | 0.242 | 0.001 |
| V3 b=16 | 0.074 | 1.00 | 0.388 ± 0.027 | 0.241 | 0.001 |
| V4 homophonic | 0.074 | 1.00 | 0.309 ± 0.040 | 0.188 | 0.001 |
| V5 padding | 0.074 | 1.00 | 0.388 ± 0.027 | 0.241 | 0.001 |
| V7 no tokens | 1.000 | 0.00 | 0.000 ± 0.000 | 0.021 | 0.000 |

**Latin**

| Variant | Candidate fraction | Answered | Token recovery (weighted) | Full-name top-1 | Unique rows |
|---|---|---|---|---|---|
| V0 uni+bi+tri | 0.047 | 1.00 | 0.146 ± 0.035 | 0.000 | 0.000 |
| V1 bigrams | 0.013 | 0.75 | 0.155 ± 0.029 | 0.000 | 0.000 |
| V2 trigrams | 0.013 | 0.75 | 0.061 ± 0.008 | 0.000 | 0.000 |
| V3 b=8 | 0.073 | 1.00 | 0.079 ± 0.036 | 0.000 | 0.000 |
| V3 b=12 | 0.048 | 1.00 | 0.129 ± 0.032 | 0.000 | 0.000 |
| V3 b=16 | 0.047 | 1.00 | 0.146 ± 0.035 | 0.000 | 0.000 |
| V4 homophonic | 0.047 | 1.00 | 0.021 ± 0.010 | 0.000 | 0.000 |
| V5 padding | 0.047 | 1.00 | 0.146 ± 0.035 | 0.000 | 0.000 |
| V7 no tokens | 1.000 | 0.00 | 0.000 ± 0.000 | 0.000 | 0.000 |

### Attacks on V0

| Language | Attack | Token recovery (weighted) | Full-name top-1 | Full-name top-5 |
|---|---|---|---|---|
| ko | 1 frequency | 0.255 ± 0.026 | 0.141 | 0.245 |
| ko | 2 co-occurrence | 0.274 ± 0.084 | 0.135 | 0.261 |
| ko | 3 seeding (m = 10) | **0.388 ± 0.027** | 0.241 | 0.360 |
| ko | 4 reconstruction | 0.255 ± 0.026 | 0.141 | 0.245 |
| latin | 1 frequency | 0.015 ± 0.006 | 0.000 | 0.000 |
| latin | 2 co-occurrence | 0.091 ± 0.008 | 0.000 | 0.000 |
| latin | 3 seeding (m = 10) | **0.146 ± 0.035** | 0.000 | 0.000 |
| latin | 4 reconstruction | 0.015 ± 0.006 | 0.000 | 0.000 |

**Baselines.** Korean B0 surname accuracy 0.219, B0 whole-name top-1 0.022; B1 distinct whole names
4,705 of 300k (unique fraction 0.001); B1′ distinct surnames 60 (unique 0.000) and given names 80
(unique 0.000). Latin B0 surname 0.048, top-1 0.000; B1 distinct whole names 7,140 (unique 0.000);
B1′ 19 surnames, 7,020 given names.

### Against the registered criteria

The A17 criteria are judged on **S2** — attack 1 (frequency) and attack 2 (co-occurrence) — at
**N = 300k**. **The decision is on Korean, the language the issue is filed for**, and is reported per
language (a Latin-only index is not the requirement, and the b = 8 variant that looks best on Latin
saturates its 256-token space):

- **Leakage ceiling — occurrence-weighted token recovery ≤ B1 + 10 pp.** B1 exposes only the equality
  of the whole value and recovers no n-gram, so the ceiling is 10 pp. **Under the S2 attacks alone,
  Korean V0 is 25.5% (attack 1) and 27.4% (attack 2)** — 2.5–2.7× the ceiling. The stronger S3 attack 3
  raises it to 38.8%, and the best homophonic variant (V4) is still 30.9% Korean. So the ceiling fails
  under the pre-registered adversary, not only under the stronger one. V2 (trigrams) falls to 9.0%
  Korean but answers only 25% of the query mix, i.e. it is no longer an index for the motivating
  queries.
- **Surname accuracy and unique-row fraction.** The token table's unique-row fraction is 0.001 against
  B1′'s 0.000 — a technical fail, but marginal next to the token failure, which decides on its own.
- **Utility floor — p95 ≤ 0.5 × the scan at 1 and 32 sessions.** The harness measures candidate-set
  size, not query latency, so the floor is **not demonstrated**; the V0 candidate fraction (7.4% Korean,
  4.7% Latin; 0.3–8.4% across variants) shows the index does narrow candidates. This does not change the
  outcome: the leakage ceiling fails under S2 first.

**Which registered criteria were measured.** A17 froze more than the decline needs; the record says
plainly what was and was not run, so nothing is implied to have passed.

| Criterion | Status |
|---|---|
| Token recovery ≤ B1 + 10 pp (S2) | **measured, fails on Korean** |
| Full-name top-1/top-5 ≤ B1 + 5 pp | measured for the token attacks (top-1 0.241 Korean at V0); **B1's own top-1/top-5 not measured** |
| Surname accuracy ≤ B1 + 10 pp | **not measured** as an attack metric (B0 is 0.219 Korean) |
| Unique-row fraction ≤ 1.5 × B1′ | measured (0.001 vs 0.000) — a marginal fail |
| Utility p95 floor at 1 and 32 sessions | **not measured** (candidate-set size is reported instead) |
| N ∈ {5k, 50k, 300k, 1M} | only **N = 300k** run |

Two findings also stand on their own:

- **The motivating query is the index's worst case.** `'%김%'` selects ~21% of a Korean column (김 is
  21.5% of the census), which is no selectivity worth an index — the very query the issue is filed
  for is the one the index helps the least with.
- **Homophonic tokens (V4) are the only variant that trades leakage for utility without losing the
  index**, halving Latin recovery (0.146 → 0.021) and cutting Korean recovery from 38.8% to 30.9% at
  an unchanged candidate fraction — but not below the ceiling, so it is a mitigation, not a fix. (V4's
  homophone is derived from the token's position in the row, a model of a per-occurrence token rather
  than a per-value salt; a real scheme would not tie the homophone to the position, so this is an
  approximation.)
- **V5 (padding) is a null here, not a test of the variant.** The attack table strips the reserved
  dummy namespace, so V5 ≡ V0 by construction and its row only records storage cost. The padding
  variant is not actually evaluated.

## Normalisation — the invariant the index must not break

The designated final filter must never miss a row the index should have offered. `tests/leakage/collation/normalisation.sql`
checks, with **plain SQL only**, over a declared repertoire (Korean syllables and jamo, Latin-1 and
extended Latin, a ligature, full width, case/accent variants) plus every substring of every haystack,
for each `(h, q)` where `h LIKE '%q%'` is true whether the token from `q` is contained in the token set
of `h`. Two candidate normalisations were compared on a clean server of each major
(`scripts/leakage-collation.sh`; `integration.yml` runs it per major, so the result is re-checked in
CI):

| Major | N1 `utf8mb4_0900_bin` | N2 `WEIGHT_STRING` |
|---|---|---|
| 8.0.43 | **6 counterexamples** | 0 |
| 8.4.11 | **6 counterexamples** | 0 |
| 9.4.0 | **6 counterexamples** | 0 |

The N1 counterexamples are identical on all three: `CAFÉ`/`café`, `CAFÉ`/`CAFE`, `Ångström`/`ANGSTR`,
`Müller`/`Ü`, `ＡＢＣ`/`ABC`, `Seoul`/`SEOUL`. **A binary token normalisation misses rows the final
filter matches**, so it is not a viable answer to question 4; letting MySQL normalise (N2) holds the
invariant over this 15-string repertoire. The repertoire is deliberately small; it is not a proof
that N2 holds everywhere, only that it does here while N1 does not. This is the direct measurement the
issue asked for, and it is why the `utf8mb4_general_ci` label in design §5.3 is corrected to the
version-dependent truth in this amendment's Outcome PR.

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