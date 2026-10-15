# SQL recipes that reduce the rows decrypted

`WHERE gcm_decrypt(col, @k) LIKE '%q%'` is opaque to the optimizer: whoever matches has to be
decrypted row by row, and `T ≈ rows scanned × (row read + UDF/decrypt + LIKE)`. The per-row cost is
the authenticated decrypt itself and there is no bounded saving left inside it (see
[performance](perf.md)), so **the only lever is the number of rows the server decrypts**. These four
SQL recipes reduce it without changing `src/` and without adding leakage beyond what is noted. The
fifth is the honest floor: a *complete* result still costs a full scan.

Nothing here is a new function or a design change. The optimizer and `LIKE` behaviour were then
pinned by tests: [`tests/integration/21_like_pushdown.sql`](../tests/integration/21_like_pushdown.sql)
on 8.0/8.4/9 and `mysql-test/suite/gcm/t/gcm_pushdown.test` on 8.4. The numbers below are
**indicative, from a developer machine** (Docker on an arm64 macOS laptop, MySQL 8.4.11, the component
after amendment A11, 300,000 rows unless noted); absolute milliseconds moved by up to ~2× between
sessions on the same host. What reproduced exactly across re-runs are the plan properties — rows
decrypted, plan shapes and plan switches.

## 1. Scope first

Put the search behind an indexed plaintext predicate — institution, department, date range — so the
UDF runs only on in-scope rows. The gain tracks the scope's selectivity: at 1,000 scopes, 1.73 ms p95
against 72.4 ms for the full scan, because 323 rows are decrypted instead of 300,000.

```sql
SELECT id FROM patients
 WHERE dept_id = ? AND gcm_decrypt(name_enc, @k) LIKE '%김%';
```

## 2. Index shape `(scope, id, envelope)`

```sql
ALTER TABLE patients ADD INDEX ix_scope_search (dept_id, id, name_enc);
```

The index is **covering** — the decrypting UDF never reads the wide row, so the wide-row cost
disappears — **and** ordered by `id` within the scope, so early termination (recipe 3) still works.

Do **not** index `(dept_id, name_enc)`: it cannot serve the `ORDER BY id` inside the scope. Measured on
8.0.46, 8.4.11 and 9.4.0 (30,000 rows, 10 scopes, 1 KiB padding), the optimizer then takes one of two
worse paths, and **which one depends on the statistics**, so re-measure rather than assume:

- **primary reverse scan** (this fixture): the decrypting call runs only on the in-scope rows the scan
  passes — about the same ~553 as the covering index — but the **wide row is read 5,530 times**.
- **scope index + sort** (a fixture that differed only in the name distribution): no wide-row read, but
  the scope is a `ref` access, so the UDF is then the filter's only condition and **the whole scope is
  decrypted** — 3,000 rows here against 553.

The covering `(dept_id, id, name_enc)` index avoids both: 553 ordered index entries, no wide-row read,
no sort, and its early termination is a genuine reduction in decryptions. So keep one shape, not both —
an existing `(scope, envelope)` index should be dropped rather than left beside the new one.

Two limits. An envelope column above the **3,072-byte index-key limit** cannot be indexed at all, so
this does not work for very wide values. And the covering scan is only covering while the buffer pool
holds the index — budget roughly **31 MiB per 300,000 rows** at a 38-byte envelope, and check
`innodb_buffer_pool_size` against the table before trusting any wide-row figure. With a pool smaller
than the table the non-covering case measured ~470 ms; that is I/O, not the bytes the UDF skips.

## 3. Lists: a bounded window plus `LIMIT`

```sql
SELECT id FROM patients
 WHERE dept_id = ?
   AND id < @cursor AND id >= @cursor - 20000
   AND gcm_decrypt(name_enc, @k) LIKE '%김%'
 ORDER BY id DESC LIMIT 50;
-- next page: @cursor = last id if 50 rows came back, else @cursor - 20000
```

A common pattern stops after about `k / p` rows — 453 rows for 50 matches at `p ≈ 10%`, ~1 ms against
~80 ms for the full scan — and a rare or absent needle costs at most one window per request. Under
concurrency the gap widens: the study puts a 32-session full scan at ~1.3 s p95 against ~6–8 ms for
early termination (#77; the committed `tests/load/recipes.py` is single-session and does not reproduce
those concurrency figures). The window bounds the worst case; it does not make an absent needle cheap.

**An exact `COUNT(*)` still needs a full scan** (recipe 5): the UI has to do without an exact total.

## 4. Type-ahead: run recipe 3 per keystroke

Run the bounded window once per keystroke, on **committed text only** — after `compositionend`, or a
debounce, not while a Hangul IME is mid-composition. Refining *inside* the previous result
(`WHERE id IN (...previous ids...) AND ...`) is valid **only** when all of these hold, otherwise it
silently drops rows:

- **the new needle contains the previous one as a substring.** A Hangul IME passes through states
  that are not extensions of each other (`김` → `김ㄱ` → `김기` → `김길`; `'김길동' LIKE '%김기%'` is 0),
  so between them the refinement is invalid and the full recipe 3 has to run. The monotonicity this
  guard relies on is checked, plain SQL, in `tests/leakage/collation/normalisation.sql`.
- **the previous result was complete** — not a `LIMIT` page or a window from recipe 3. Refining a
  page is refining a sample.
- **the id list is below `range_optimizer_max_mem_size`** (default 8 MiB, ~36,000 values). Above it
  the server emits `Warning 3170`, drops the range plan and reads the whole table: the margin over a
  rescan fell from ~4× at 35,000 ids to ~1.1–1.5× at 100,000 (1,000,000-row fixture). Detect 3170
  and fall back to recipe 3.

**The refinement also widens the log surface.** The id list is sent back in the statement text, so it
reaches the general log, the slow log and `performance_schema.events_statements_*` beside the pattern —
more than a plain `LIKE` leaves (`docs/ops-constraints.md` item 2). If that matters, do not refine; run
recipe 3 again.

## 5. A complete result stays a full scan

An export or an exact total decrypts every candidate. Shrink it with recipes 1 and 2, and limit how
many run concurrently; do not expect a bounded cost.

## Indicative measurements

Developer machine, one session unless noted (see the caveat above). `p` is the match rate of the
needle.

| Recipe | Case | Recipe p95 | Full scan p95 | Rows decrypted |
|---|---|---:|---:|---:|
| Early termination `LIMIT 50` | `'%김%'` p ≈ 9.97% | 1.0–1.7 ms | ~81 ms | 453 vs 300,000 |
| | `'%김길%'` p ≈ 0.99% | 1.6–3.1 ms | 66–84 ms | 4,530 |
| | `'%없음%'` (absent) | 77–106 ms | 50–83 ms | 300,000 — no help |
| Window 10k / 20k / 50k | `'%없음%'` | grows with the window | | 10,000 / 20,000 / 50,000 |
| Scope (`INDEX (dept_id)`) | 10 / 100 / 1,000 scopes | 21.6–26.0 / 4.8–5.5 / 1.7–2.7 ms | 63–101 ms | 29,913 / 2,998 / 323 |
| Covering vs non-covering | ~1 KiB rows, ~30,000 in scope, pool > table | 8.9–9.0 ms vs 37–39 ms p50 | | 29,913 |

Reading the plans these numbers come from:

- **Index condition pushdown applies to a loadable function**, so a single-step `SELECT *` through
  the scope index reads the wide row only where the UDF matches; an explicit two-step fetch was slower
  and is not needed. On that path a tampered row still raises `ER_UDF_ERROR` under `gcm.strict=ON`.
  The behaviour is pinned by `tests/integration/21_like_pushdown.sql`; the plan shape, by
  `mysql-test/suite/gcm/t/gcm_pushdown.test`.
- Two reading caveats — what `EXPLAIN ANALYZE`'s child iterator counts, and why the per-row residual
  is not attributed to any one cause — belong with the measurements and are in
  [`docs/perf.md`](perf.md).

## Rejected

| Idea | Why not |
|---|---|
| Verify the tag only on matching rows | A tampered non-matching row would pass silently — breaks `gcm.strict` |
| A `gcm_contains()` matcher | Reimplements collation; `LIKE` itself costs ~0 |
| Binary collation for Hangul-only patterns | ~0 gain for A17's N1 counterexamples |
| Cache decrypted values in a temporary table | TempTable can spill plaintext to disk |
| Generated column / functional index on `gcm_decrypt` | Not permitted for loadable functions, and stores plaintext |
| Explicit two-step fetch | ICP already does it, faster |
| Per-row decrypt optimisation | No bounded saving left (above) |
| A keyed n-gram token index | Leaks n-gram frequency and co-occurrence — declined in amendment A17, [`leakage-ngram.md`](leakage-ngram.md) |

## See also

- [`docs/ops-constraints.md`](ops-constraints.md) item 5 — the one-paragraph summary and the A17
  decision.
- [`docs/perf.md`](perf.md) — the measurements this page's numbers feed into, and the load gate.
- [`tests/load/recipes.py`](../tests/load/recipes.py) — the study harness behind these numbers; it
  records the plan, the rows into the filter and the sizes per recipe.
- [`docs/leakage-ngram.md`](leakage-ngram.md) — why the index direction is closed.
