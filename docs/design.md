# MySQL GCM encryption functions (component) — design and procedure

> **Language.** English · [한국어](design-KO.md)
>
> This is the canonical document. [`design-KO.md`](design-KO.md) is its Korean translation and follows
> it; where the two disagree, this file is right (`.agents/rules/docs.md`). Changing the design changes
> both documents in the same PR.

> ## Amendment A17 (2026-10-14) — a keyed n-gram token index for partial match: a pre-registered leakage experiment
>
> **Status: declined (2026-10-14) — the experiment was run and the index is not adopted; no file under
> `src/`, `spec/` or the vectors changed, and issue #38 closes with no implementation PR.** The
> protocol below was **pre-registered** before the experiment ran, so the criteria could not be moved
> once the result was seen; the result and the review are in the **Outcome** block at the end. That
> review is a **scoped design review, not a human cryptographic audit** (constraint 13). The experiment
> used Python only, under the A4 extension this amendment records ("Python scope").
>
> ### Why this is registered before it is run
>
> The project rule is that the design is amended before the code (`docs/design.md` §0,
> `.agents/rules/architecture.md` §2). For an experiment the same rule means the *criteria* come
> before the *result*, or the result decides them. The numbers in "Adoption criteria" are therefore
> starting values, confirmed in the PR 1 review and **frozen once PR 1 merges**: after that they change
> only by an amendment that says why, never because a result was inconvenient. A result that fails
> them is a "declined" outcome, and declining is a successful outcome for the issue.
>
> ### The problem, and why the motivating query is the worst case
>
> Constraint 5: the functions are opaque to the optimizer, so `WHERE gcm_decrypt(col, @k) LIKE '%김%'`
> scans and decrypts every candidate row. Measured on 300k rows: a serial p95 of 235–255 ms, ~1 s at 8
> sessions and ~4 s at 32 (`docs/perf.md`). Issue #38 proposes a two-stage search — keyed n-gram
> tokens in a side table with an ordinary index narrow the candidates, and the real decryption stays
> the final filter, so a token collision costs time and never returns a wrong row.
>
> **The motivating query is the index's worst case.** `'%김%'` matches about a fifth of a real Korean
> name column (김 alone is ~21% of the population). A unigram index over such a column leaks the most
> and helps the least: the token `김` selects ~21% of rows, which is no selectivity worth an index. Any
> adopted variant is judged on the whole query mix, not on the one query that motivated the issue.
>
> ### Threat model — who sees what
>
> A deterministic keyed n-gram token is the same token for the same n-gram, so an attacker who reads
> the table sees a labelled graph of (row, token) edges. Four adversaries are in scope:
>
> - **S1 — snapshot.** A stolen backup, dump or replica: the token table, the ciphertext column (whose
>   length the GCM envelope already exposes), the plaintext columns that are not encrypted, and public
>   name statistics. The base case.
> - **S2 — S1 plus a conditional prior.** S1 plus other plaintext columns (birth year, sex) that make
>   the name prior conditional. The adoption criteria are judged on this adversary, because a real
>   table has these columns.
> - **S3 — S1 plus m known or injected rows.** S1 plus m rows whose plaintext the adversary knows or
>   chose (a patient who registers under a name the adversary picked, or a leaked sample), for
>   m ∈ {1, 10, 100, 1% of N}.
> - **S4 — the log reader.** The search key and the search pattern reach the server logs
>   (constraint 2), and the Korean bigram space is ~1.2×10⁸, so a holder of the search key can
>   enumerate every token. **Not simulated — argued**, because the outcome is total by construction.
>   S4 is why question 6 (component or recipe?) matters: a construction that never puts the search key
>   on the server removes the log exposure.
>
> **Leakage outside the token multiset, listed so it is not forgotten:** physical and insertion order
> (and therefore a row's first token, which for a name is the surname), the `ROW` binlog and the undo
> log (change history), `mysql.innodb_index_stats` and index page fill (which tokens are hot), a buffer
> pool dump, and any join back to `patient_id`.
>
> **Out of scope, deliberately:** active tampering, memory scraping, and volume/access-pattern query
> recovery. They are real, and they are not what this experiment measures.
>
> ### What is modelled, and what is not
>
> Whatever the PRF is, the adversary sees the same (row, token) graph, so the simulation models the
> token function as a **random injection** — an injective relabelling of the n-gram space — truncated
> to `b` bits, which behaves as a random function for `b` below the space's entropy. **No
> cryptographic operation is performed and the harness holds no key material.** This keeps the
> extension to A4's Python scope as small as it can be and stops `tests/leakage/` from becoming a
> second reference tokeniser the shipped component would then have to agree with.
>
> **The limit of that model:** it assumes an ideal token function. It does not measure the security of
> any concrete PRF, and cannot — that is a separate argument, made where a construction is chosen. The
> experiment measures **leakage from the token structure given an ideal tokeniser**, which is the view
> the adoption decision needs.
>
> ### Data
>
> Only aggregates are committed, each with its source, licence and retrieval date; the licences are
> checked before the data is committed.
>
> - Korean surnames: Statistics Korea, 2015 Population and Housing Census (KOSIS).
> - Korean given names by birth year and sex: the Supreme Court's birth registration statistics.
> - Latin surnames: the US Census 2010 surname list (public domain).
> - Latin given names: US Social Security Administration baby names (public domain).
>
> N ∈ {5k, 50k, 300k, 1M}, seeds ≥ 20, and the adversary's knowledge is deliberately incomplete:
> regional skew, cohort mismatch, top-K truncation and Dirichlet noise. Every recovery rate is
> reported against the total-variation distance between the generator and the adversary's prior, so a
> rate under a *perfect* prior is not mistaken for a rate under a realistic one.
>
> ### Attacks (a citation is checked against its source before it is written into A17)
>
> 1. **Frequency rank / maximum-likelihood matching** as an assignment problem.
> 2. **Co-occurrence graph matching** under the n-gram uniqueness constraints (a bigram always
>    co-occurs with its own unigrams; the most frequent token in a row is the surname).
> 3. **Known-row seeding** for m ∈ {1, 10, 100, 1%}.
> 4. **Row reconstruction:** token multiset → name, ordering the bigrams into a path.
>
> **Not attempted:** simulated annealing, query-recovery attacks, and learning-based attacks. Each
> attack implementation is itself validated by a **known-answer test** on small data where the ground
> truth is planted: the attack must recover 100% there and fall to the B0 level on a control with no
> tokens.
>
> ### Metrics and baselines
>
> - **Leakage:** token recovery (unique and occurrence-weighted), per-row surname accuracy, full-name
>   top-1 and top-5, and attack-independent structural metrics (the distribution of rows sharing an
>   identical token set, and the unique-row fraction).
> - **B0 — length and prior only.** The surname floor (~21%).
> - **B1 — whole-name `gcm_encrypt_det`** (equality of the whole value only).
> - **B1′ — split surname/given-name `gcm_encrypt_det`.**
>
> Every result is reported as an increment over B0 and B1, never in isolation. "The attack failed" is
> not evidence of safety: the attack-independent metrics and the full-knowledge ceiling are reported
> together with the attack results.
>
> ### Variants — every leakage number stands beside a utility number
>
> Utility is reported **with** leakage: the candidate-set blow-up a token query produces, the fraction
> of queries the index can answer without a scan, and the storage cost. Leakage without utility is not
> a result.
>
> - **V0** unigrams + bigrams + trigrams.
> - **V1** bigrams only (strings shorter than 2 characters fall back to a scan).
> - **V2** trigrams only.
> - **V3** truncation at b ∈ {8, 12, 16} bits.
> - **V4** homophonic (per-value multiple) tokens.
> - **V5** dummy padding.
> - **V6** per-row salt / Bloom (structurally impossible for this index — recorded, not simulated).
> - **V7** no tokens (B1′ + scan) — the "decline" comparator.
>
> There is no real workload, so the query model is stated explicitly as three mixes: whole name, given
> name alone, surname alone, and a single syllable.
>
> ### Normalisation — the invariant the index must not break
>
> **The designated final filter must never miss a row the index should have offered.** If a token is
> computed on a normalised form the final `LIKE` does not use, the index silently drops rows the
> decryption would have matched — the failure is missing results, not a slow query. Three candidate
> answers:
>
> - **N1 — binary fixed:** `COLLATE utf8mb4_0900_bin LIKE`, giving up case- and accent-insensitivity.
> - **N2 — let MySQL normalise** via `WEIGHT_STRING` (a hypothesis; to be verified).
> - **N3 — a coarser key** (case-folded, accent-stripped) with a documented narrowing.
>
> PR 6 verifies this on real 8.0/8.4/9.x servers with **plain SQL only** — no component function and no
> C++ — over a declared repertoire (Korean syllables and jamo variants, Latin-1 and extended, full
> width) plus random multi-character pairs: there must be **zero** rows where `h LIKE '%q%'` holds while
> `tokens(q) ⊄ tokens(h)`. A non-zero count is recorded as it stands, not blamed on the environment.
> The measured comparison collation is `utf8mb4_0900_ai_ci` (`tests/integration/20_korean_like.expected`),
> which is **not** the `utf8mb4_general_ci` that §5.3 names as the worked example; this amendment's
> Outcome PR corrects that wording to the version-dependent truth instead of a label.
>
> ### Candidate constructions (question 6: the component, or a recipe?)
>
> - **C0 — decline** (V7 documented). The baseline outcome.
> - **C1 — application recipe.** The search key never reaches the server; the cost is per-language
>   segmentation and normalisation drift, and it sits in tension with A4.
> - **C2 — no new function.** `SUBSTRING(gcm_encrypt_det(@g, @search_key), 2, 12)`: the deterministic
>   nonce is a 96-bit PRF, but this freezes the envelope layout as API and reuses the deterministic
>   label, so its separation rests on key independence alone.
> - **C3 — a scalar function** `gcm_search_token(bytes, key)` over 16 bytes, with its own label and a
>   `_kr` form to keep the key out of the logs.
> - **C4 — the issue's JSON function** (highest cost).
>
> **A component function is chosen only if the selected construction cannot be expressed in SQL or in
> the application.** The default is to add no shipped surface.
>
> ### Adoption criteria (registered values — frozen at the protocol commit, before the experiment)
>
> Judged on **S2** (the snapshot adversary with a conditional prior), incomplete side knowledge,
> N = 300k, over ≥ 20 seeds. The experiment implemented **S1**, a lower bound of S2; see Outcome.
>
> **Leakage ceiling** against B1:
>
> - occurrence-weighted **token** recovery ≤ B1 token recovery + 10 pp;
> - **surname** accuracy ≤ B1 surname accuracy + 10 pp;
> - **full-name top-1** ≤ B1 top-1 + 5 pp, and **top-5** ≤ B1 top-5 + 5 pp;
> - unique-row fraction ≤ 1.5 × B1′'s.
>
> **Utility floor** under the three-mix query model, with recall 100%:
>
> - p95 ≤ 0.5 × the scan's p95 at **1 session and at 32 sessions** (≥ 2×);
> - the fraction of queries the index can answer without a scan is reported, not thresholded.
>
> A reviewer may change these numbers before PR 1 merges; no one changes them after.
>
> ### Python scope — the A4 extension
>
> A4 limits Python to vector generation and verification, the SQL E2E and load runners, and drawing
> documentation charts from committed measurements. A17 **adds one narrow allowance:**
>
> > leakage simulation over synthetic data, performing no cryptographic operation and shipped nowhere.
>
> `tests/leakage/` is therefore a fourth Python site, and the last one. It builds no
> encrypt/decrypt/parse API, holds no key bytes (it needs none — the token function is modelled
> directly), and is imported by nothing that ships. `AGENTS.md` §5 and `.agents/rules/stack-python.md`
> carry the same wording, so the rule and this amendment do not drift. The earlier chart allowance was
> added to the rule alone and left A4's body stale; this amendment corrects that for its own case by
> naming the extension inside A4 rather than only in the rule.
>
> ### Experiment harness conventions
>
> - Location `tests/leakage/` — not shipped, the same shape as `tests/load` and `tests/bench`.
>   `scripts/check-architecture.py` reads only `src/` and `docker/`, so it is untouched.
> - `ruff` (all rules) and `mypy --strict` — added to the explicit file list in `lint.yml`, which is
>   what makes mypy check them — plus one `unittest discover` line. Test names are GWT, and case bodies
>   contain no `if`/`for`/`while`.
> - Randomness is seeded and marked: `random.Random(seed)  # noqa: S311 - synthetic names, not key
>   material` (the precedent is `tests/load/run.py:104`). There are no key bytes to leak.
> - `run.py` takes `argparse`, writes results as JSON on stdout and a summary on stderr. The full run
>   is not in CI (it is slow); the result JSON is committed with its seed and command, and CI runs a
>   small smoke only.
> - The assignment problem is beyond pure Python at this N, so `numpy`/`scipy` are pinned exactly in
>   `tests/leakage/requirements.txt` and applied to the top-K tokens only; the rest is greedy matching.
> - Charts follow `scripts/plot-perf.py`'s deterministic SVG settings (`hashsalt`, path fonts,
>   `Date: None`) in `scripts/plot-leakage.py --check`, emitted under `docs/assets/leakage/`, the only
>   asset path the site copies.
>
> ### Outcome — the result, and the recommendation
>
> **The experiment is reported in [`leakage-ngram.md`](leakage-ngram.md).** The author's analysis, put
> before the independent review recorded in the table below:
>
> - **The harness implements S1, not the registered S2.** It uses one unconditional prior and does not
>   condition on the birth-year and sex columns, so attacks 1 and 2 are S1 attacks and the measured
>   leakage is a **lower bound of S2**. Recorded as a deviation, not a pass.
> - **The leakage ceiling fails on Korean under the S1 attacks alone.** Against B1 (whole-value
>   equality only) the ceiling is B1 + 10 pp. Korean V0 recovers **20.7% (attack 1) and 17.3% (attack
>   2)** occurrence-weighted, and 31.7% under the stronger S3 attack 3; Latin V0 is 10.2%, 26.5% and
>   36.2%. That is 1.7–2.1× the ceiling on the S1 attacks, not a rounding. The decision is on Korean,
>   the language the issue is filed for.
> - **The variants that fall under the ceiling stop being an index.** V2 (trigrams) reaches 5.5% Korean
>   but answers only 25% of the query mix; V7 (no tokens) recovers nothing and is the B1′ baseline it
>   exists to be compared against.
> - **The motivating query is the worst case.** `'%김%'` selects ~21% of the column, which is no
>   selectivity worth an index.
> - **V4 (homophonic) and V5 (padding) were not validly evaluated** and carry no claim. V5's shared
>   dummies are stripped by the attack table. V4's utility is fine, but **the attack was not adapted to
>   homophones** (a one-to-one assignment recovers only one of the h tokens of an n-gram); an adapted
>   spot check in review measured about 20.9% on Korean, above the ceiling, so no V4 claim is made. Both
>   are recorded in `results.json` and explained, not reported, in the results document.
> - **Normalisation is answerable, but not by a binary key** — N2 (`WEIGHT_STRING`) holds both the
>   whole-string and the n-gram containment checks; N1 has 6 counterexamples on every major measured.
>
> **Recommendation: decline (C0).** No construction in C1–C4 makes the index narrow the motivating
> query enough to be worth a deterministic n-gram side table that leaks this much, and the project
> does not reimplement collation for an unproven index (§5.3). Record the reason, close issue #38 with
> no implementation PR, and point constraint 5 at the study.
>
> **The first reviewer's verdict, in its own words (2026-10-14, on the first harness):** "decline
> (C0) — concur with the author. The Korean occurrence-weighted token recovery exceeds the frozen
> ceiling under every variant that answers the query mix (38.8% at V0 vs a 10 pp ceiling), and it still
> fails under the strict S2-only attacks (attack 1 = 25.5%, attack 2 = 27.4%); the motivating query
> `'%김%'` is the index's own worst case; the utility floor is not demonstrated; and no construction
> C1–C4 changes the structural leakage that fails."
>
> That verdict was on the **first harness**, whose tail-draw, Latin-name-format and V0-truncation
> defects a later code review found; the fixes and the re-run are recorded in `leakage-ngram.md`, and
> the corrected Korean figures are 20.7% / 17.3% (S1) and 31.7% (S3). The quote is left as it was
> given; the reviewer did not see the corrected numbers.
>
> | | Decision | Conditions | Reviewer | Date |
> |---|---|---|---|---|
> | A17 (first) | **decline (C0)** — adopt none of C1–C4, on the first harness | Apply the review's P1/P2 corrections to `leakage-ngram.md` (the noise parameter, the S2/S3 caption, the Latin coverage, the attack-4 wording, and which criteria went unmeasured) | crypto-reviewer — scoped AI design review, separate from the author; **not a human audit** | 2026-10-14 |
> | A17 (second) | **decline (C0) upheld** on the corrected harness and result; declaring V4/V5 not-validly-evaluated instead of re-measuring is honest and sufficient | Sync the rewritten English Outcome into `design-KO.md`, remove or mark V4/V5 in the chart and its caption, and fix the chart subtitle to "Attacks 1-3" | crypto-reviewer — scoped AI design review, separate from the author; **not a human audit** | 2026-10-14 |
>
> Each review is a scoped design review of the amendment, the results document and the harness at the
> revision it was given; none measured a PRF, and none is a human cryptographic audit.
>
> **No code, spec or vector change follows from A17**, and issue #38 closes with no implementation PR.
> Constraint 5 points at [`leakage-ngram.md`](leakage-ngram.md). Revisiting the index would be a new
> amendment: a construction that answers the collation invariant (N2), a stated and bounded leakage,
> and its own pre-registered experiment.

> ## Amendment A16 (2026-10-13) — a row that raises gives up every secret, in all six functions
>
> **Status: implemented and merged (issue #43; PRs #53 and #54, 2026-10-13, merged by the repository
> owner after the reviews recorded below).** The rule is `give_up_secrets` in `src/udf_glue.cc`,
> called by every row callback of all six functions; the refusal is `refuse_if_spent` beside it.
> Pinned: `tests/adapter/udf_kr_test.cc` (the wipes, the refusal, and the two paths that were
> unpinned until the second review) and `tests/integration/nested` (cases 20 to 26, per major).
> Measured: `scripts/bench.sh --gate` on the merge, and the ASan/UBSan adapter run recorded on #54.
> The server cause is read in `docs/upstream-udf-handler-leak.md`. **This revision — made while it
> was still proposed — widened what the amendment *says*: the review of the whole #51–#55 stack
> measured that the same server defect also drops instances that raise **nothing**, so the guarantee
> is scoped to the row that raised and the limit is stated rather than implied.** A13 gave the three
> `_kr` functions this
> rule. This gives it to the three key-argument functions as well, and says why the cost is zero.
>
> A13's "The key copy" already requires it of a `_kr` row that raises: the fetched key, the A11
> context, the A11 nonce key and the result buffer are given up at once, not at `deinit`. It stopped
> there because the function that needed it most was the one holding a key the statement's text does
> not contain. **The reason is not specific to those three functions.** A13 recorded the shape that
> shows it, and the sweep added for #43 pins it — `tests/integration/nested`, in the PR that precedes
> this one, which is also where A13's "not pinned by a committed case" sentence is corrected: when a
> loadable function raises while the server is evaluating it as the argument of another one — which
> needs the *inner* call to take a prepared-statement parameter, the one condition A13 names — that
> function's `deinit` is not called, not at the end of the statement, not on `DEALLOCATE PREPARE`,
> not when the session ends; and afterwards `UNINSTALL COMPONENT` is refused until the server
> restarts. What that `UDF_INIT` held would have stayed in memory, unwiped, for the life of the
> server — which is what the rule below exists to prevent for the instance that raises.
>
> **The decision.** Every row callback of all six crypto functions — `gcm_encrypt`,
> `gcm_encrypt_det` and `gcm_decrypt`, and the three `_kr` forms — gives up, before it returns an
> error to the server:
>
> - the key fetched from the keyring (a `_kr` function only, A13);
> - the A11 states: the scheduled `EVP_CIPHER_CTX` with its key schedule behind `gcm_decrypt`, and
>   the cached nonce key with the key copy it is valid for behind `gcm_encrypt_det` (`gcm_encrypt`
>   keeps neither);
> - the result buffer, which at that moment may still hold the previous row's output — plaintext
>   for the two decrypt functions, an envelope for the four encrypt ones.
>
> The instance is then **spent**: a further call on it raises instead of using a released session. (A
> NULL argument still yields SQL NULL — the NULL check comes first and consults no session,
> spec/envelope.md §4 rule 3.) The latch is what makes the wipe observable, because no such call can
> be made except by a test (the reason is read in the sources, not pinned — see the paragraph below).
>
> **Why the cost is zero.** A11's invariant list lets a pre-check failure leave the schedule intact,
> on the grounds that "a wrong-length key on one row is that row's SQL error, not a reason to
> discard a valid schedule". That a wrong-length key is that row's SQL error is exactly why
> discarding it costs nothing: the row's error ends the execution. **Read in the 8.0.43, 8.4.11 and
> 9.4.0 sources rather than pinned by a test**: `udf_handler::get_arguments` returns early on the
> handler's error flag, so the row callback is not entered again after it has reported an error, and
> the wipe runs while that statement is ending. No success path changes — a row that succeeds keeps
> the context and the nonce key for the next row exactly as A11 says. Nothing here rests on the
> three majors behaving alike in the nested shape: they do not (A13, "Implementation notes", case
> `20`), and the rule is what makes that difference irrelevant to what the instance that raised
> leaves in memory — not to what an instance the server abandons *without* an error keeps.
>
> **What it does not cover, deliberately.**
>
> - **A `bad_tag` that `gcm.strict=OFF` turns into NULL does not wipe.** The row succeeded as far as
>   the server is concerned and the statement continues, so the session is still wanted. A11's rule
>   already applies there: the core discards the copy, the context and the nonce key on the failure,
>   and only a `_kr` function keeps its fetched key, because the next row must still decrypt (A13).
>   The result buffer is left alone too: the statement has not ended, and whatever ends it wipes —
>   `deinit` on success, A16 on an error row. What the buffer may hold past the current row's output
>   is the previous row's output of that same statement, not a secret the statement's end leaves
>   behind.
> - **`deinit` is still the normal exit** and still cleanses everything (A11). A16 removes the
>   reliance on `deinit` from the error path only.
> - **The row that raised, and only it.** The rule fires from a row callback, so it can cover only
>   an instance whose row reports an error. The same server defect also drops instances that raise
>   *nothing* — a sibling of the function that raised, a key-id instance that sealed successfully,
>   any function a failed re-prepare abandons — and the component never regains control of those, so
>   what they hold stays, a fetched keyring key included. No row callback can close that; whether it
>   could be reduced at the price of the cross-row reuse A11 and A13 exist for is an open question,
>   and this amendment states the limit rather than implying a guarantee it cannot give. Cases `23`
>   to `25` of `tests/integration/nested` pin the three shapes; `26` is the `const_item` variant of
>   `20`, the control that says constness is not the trigger.
> - **It does not fix the server defect.** A leaked instance is still leaked, and `UNINSTALL
>   COMPONENT` is still refused until a restart. What A16 guarantees is that the leaked per-instance
>   state **of an instance whose row raised** holds no key material, no plaintext and no usable
>   context; the server's own argument buffers are outside the component's reach, as A11 already
>   says. The defect is issue #43, pinned by `tests/integration/nested` and summed up in operational
>   constraint 18; a fix would be the server's.
> - **`init` failures are not part of it.** A9's rollback already frees what `init` allocated; A16 is
>   about the row callback.
>
> **What A11 loses.** Its invariant list says the pre-checks "leave it intact … untouched by a
> `bad_key_len` pre-check". That sentence is replaced above: the pre-checks still do not touch it
> while the call runs, and the call then raises, which does. Nothing else in A11 changes — not the
> byte layout, not the measurements, not the threat model.
>
> **Review record.** An independent `crypto-reviewer` pass (2026-10-13, this PR) read the six row
> callbacks, `udf_glue`, `gcm`, `nonce`, `key_source`, `spec/envelope.md` and `crypto-safety.md`
> against this draft. It found the enumerated secret set complete for component-owned state, and the
> "cost is zero" argument sound — no shape in the repository enters one `UDF_INIT`'s row callback
> again after an error. Four things it raised are fixed above: the result buffer holds an envelope,
> not plaintext, in the encoding functions; the `get_arguments` claim and the uniformity of the three
> majors are source reads, now marked as such, and the major difference in the nested shape is named
> rather than smoothed over; the NULL path's result buffer now says why it is not wiped; and the
> guarantee is scoped to the per-instance state. Three are left to the implementation PR and are in
> the table below: `architecture.md` §3 and §5 and `docs/ops-constraints.md` 18 still tie the wipe to
> the `_kr` functions; `spec/envelope.md` states the rule only inside §4.2, so §4 has to carry it for
> all six; and `tests/adapter/udf_kr_test.cc` asserts on the latch where it lives today. It did not
> review the server-side claim — that is the next PR's subject — and this is not a human
> cryptographic review.
>
> **Second review (2026-10-13, the whole #51–#55 stack).** It measured a wider scope than the record
> above assumed: a *sibling* function, a key-id instance that raised nothing (whose seal is then
> never counted) and a re-prepare invalidated by `ALTER TABLE` — no nesting, no parameter, no error —
> all leak the same way. The guarantee above is therefore scoped to the instance whose row raised,
> the limit is stated, and `tests/integration/nested` gained cases `23` to `26` for the shapes.
>
> **Impact, for the implementation PR:**
>
> | Area | Change |
> |---|---|
> | `src/udf_glue.{h,cc}` | A13's `give_up_secrets` moves here from `udf_kr.cc`; its `spent` latch is lifted from the keyring state (`KeyHold`) to the per-instance state, so one rule and one message serve all six functions |
> | `src/udf_encrypt.cc`, `src/udf_decrypt.cc` | call it before every error they raise |
> | `src/udf_kr.cc` | uses the moved helper; its own behaviour does not change, its tests do (next row) |
> | `tests/adapter/udf_kr_test.cc` | its assertions on `spent` follow the field to `UdfState`; the new cases go here |
> | `src/usage.cc` | unchanged: the error row still folds what the instance counted (A14) |
> | `spec/envelope.md` | the error-path rule moves into §4 and becomes normative for the three key-argument functions (§4.2 rule 7 currently states it only for the key-id ones). One sentence; no byte layout and no vector change |
> | `architecture.md` §3, §5 | both still say a `_kr` function's key is what a raising row wipes; they have to say all six |
> | `docs/design.md` A13's "Implementation notes" and its KO mirror | the defect's scope is corrected there: the nesting, the bound parameter and the error are incidental, and cases `23` to `26` pin the wider shapes (done in the PR that records the sweep) |
> | `docs/ops-constraints.md` 18, `README.md`/`README-KO.md` 18 | constraint 18 is restated around the real trigger — a prepared statement whose re-prepare fails after a function has been fixed — and says that an instance abandoned *without* an error keeps what it holds, this amendment's rule notwithstanding (done in the same PR) |
> | `CHANGELOG.md` | a Documented entry, as A15 has |
> | `crypto-safety.md` (key handling), `.agents/rules/code-review.md`, `AGENTS.md` §5 | the wipe is unconditional on the error path, for all six |

> ## Amendment A15 (2026-10-13) — a key version in the envelope: rotation and dual-read for the key-id functions
>
> **Status: proposed (issue #34, the part amendment A13 deferred). Nothing is implemented by this
> amendment, and it changes the envelope, so nothing may be implemented from it until it has had the
> `crypto-reviewer` pass and two human reviewers.** It adds a version byte and a header. **It does
> not change what is authenticated or how the deterministic nonce is derived** — earlier drafts
> did, and "Why the header is not authenticated" below records what they proposed, why the first
> was unsafe, and why the smaller design is the one proposed, on a reviewer's recommendation. No
> draft of this amendment has had a human cryptographic review.
>
> **This proposes to drop one of the three things A13 said such an amendment would need.** A13's
> "Out of scope" listed "an
> authenticated id, a bound on which ids a stored value may name, and an answer to the per-row
> lookup". The bound and the per-row lookup are answered below (the id comes from the statement;
> at most four keys per `UDF_INIT`). The authenticated id is **not** provided: the header is not
> authenticated, for the reasons in "Why the header is not authenticated", and that section says
> what follows from it. Every security statement in this amendment is the author's and an
> automated reviewer's reasoning; none has had an independent cryptographic review.
>
> A13 made the key a keyring entry named by id. It left rotation where it was: an application that
> wants to move a column to a new key has to know, row by row, which key sealed it, and A13 refuses
> a key id that varies by row, so even reading a half-rotated column takes one statement per key.
> This amendment lets a row say which version of its key sealed it.
>
> ```
> gcm_encrypt_krv(plaintext, key_id, key_version [, aad])      -> BLOB
> gcm_encrypt_det_krv(plaintext, key_id, key_version [, aad])  -> BLOB
> gcm_decrypt_krv(ciphertext, key_id [, aad])                  -> VARCHAR (utf8mb4)
> gcm_envelope_key_version(ciphertext)                         -> BIGINT, NULL if the envelope has none
> ```
>
> ### The envelope
>
> ```
> 0x10 || suite(1) || key_version(4, big-endian) || nonce(12) || ciphertext || tag(16)
> ```
>
> - **One new version byte, `0x10`, the "extended header".** What `0x02`–`0x07` say in one byte —
>   which cipher, which nonce mode — moves into the `suite` byte, which **takes the same six values
>   with the same meanings** (`0x02` AES-256 random … `0x07` AES-192 deterministic). There is no
>   second table to keep in step, and adding a suite later (issue #37) adds one `suite` value under
>   `0x10` instead of a new pair of version bytes for every combination. The proposal to #37 is
>   that new suites exist only under the extended header.
> - **`key_version`** is an unsigned 32-bit number, 1 to 4294967295, most significant byte first.
>   Zero is not a version. (`spec/envelope.md` §2 says multi-byte fields have no endianness; this
>   is the first that does, and the spec has to say so.)
> - Overhead is 34 bytes instead of 29, and 34 is the shortest well-formed `0x10` envelope.
> - `0x02`–`0x07` and `0x01` are untouched and stay readable. A build that predates this amendment
>   rejects `0x10` as a reserved version (`spec/envelope.md` §2.6), which is the failure the spec has
>   always promised: **0.1.0 cannot read these envelopes**, so a column must not be written with
>   `_krv` while an older component may still have to read it. (Because the header is not
>   authenticated, replacing the six header bytes by the `suite` byte alone yields an envelope an old
>   build would open. That is not a supported way to read these values and nothing promises it will
>   keep working.)
> - **Only `gcm_decrypt_krv` reads `0x10`.** `gcm_decrypt` and `gcm_decrypt_kr` reject it with
>   `bad_envelope`, in the new build too: the key that opens it is named by the header, and those
>   functions are handed a key or one entry.
> - The `suite` byte must agree with the length of the key, as the version byte must today; a
>   mismatch is `bad_key_len`. An unknown `suite` — `0x01` included — or a `key_version` of zero is
>   `bad_envelope`.
>
> ### Decisions
>
> - **The key for version N of `key_id` is the keyring entry `key_id` + `.v` + N** (`patient_name.v2`),
>   for the calling account, with A13's rules for everything else: type `AES`, 16, 24 or 32 bytes,
>   the length selecting the suite, `gcm.min_key_bytes` on encryption only. N is written in ASCII
>   decimal with no sign and no leading zero. The convention is the component's;
>   `SELECT keyring_key_generate('patient_name.v2', 'AES', 32)` makes a version.
> - **A `_krv` `key_id` must not itself match `\.v[0-9]+$`** — on its `utf8mb4` bytes,
>   case-sensitively, whatever the digits are (`a.v0` and `a.v01` are refused too) — and is 1 to 243
>   bytes (`.v` and up to ten digits bring the entry id to A13's 255). Without the rule, the
>   unversioned fallback of `_krv(…, 'a.v1')` would be the very entry that is version 1 of `a`: one
>   id's plain key would be another id's version.
>   An A13 id that ends that way, or is longer than 243 bytes, cannot be used with `_krv`.
>   **The entry is still an ordinary keyring entry**: the A13 functions reach the same key as
>   `'patient_name.v2'` — `gcm_decrypt_kr` opens with it and `gcm_encrypt_kr` seals plain
>   `0x02`–`0x07` envelopes with it. The
>   component does not prevent that, and it is not a nonce reuse: the two families derive and
>   authenticate identically, so the same key, plaintext and AAD give the same nonce, ciphertext
>   and tag in both. "One AAD convention per key" (constraint 7) therefore spans both families for
>   such an entry.
> - **Encryption names the version.** There is no "current version": the component does not
>   enumerate the keyring to find the highest, and a setting that says which is current would be the
>   `gcm.key_id` that A1 withdrew. Which version writers use is the application's configuration.
>   `key_version` is taken, like every argument of these functions, as a string (requested as
>   `utf8mb4` and compared as bytes, so a full-width digit is not a digit), and parsed strictly:
>   ASCII digits only, no sign, no space, no leading zero, at most ten digits, a value
>   from 1 to 4294967295. The strings `'02'`, `' 2'`, `'2.5'`, `'0'` and `'4294967296'` are errors, and
>   NULL gives NULL. The rule is about the string the function receives, and the server decides what
>   that is for a non-string argument. Observed with the A13 functions, by hand, on 8.0.46, 8.4.11
>   and 9.4.0: the literals `2`, `02`, `2e0` and `0x32` all arrive as `'2'`, `TRUE` as `'1'`, `2.0`
>   as `'2.0'` and `-2` as `'-2'`. So `TRUE` would be taken as version 1 and `0x32` as version 2 —
>   harmless, but worth knowing; pass the version as a plain integer or a string of digits. Like the id, it must be the same on
>   every row of a `UDF_INIT`: an encryption call site uses one key.
> - **Decryption takes it from the envelope.** `gcm_decrypt_krv(ciphertext, key_id)` reads `suite`
>   and `key_version` from the row. Whoever can write the column therefore chooses the version — but
>   only among the versions of the `key_id` the statement names, under the calling account. A stored
>   value cannot name another key id or another account's key.
> - **It reads A13's envelopes too, but not the legacy one.** For `0x02`–`0x07`, which carry no
>   version, `gcm_decrypt_krv` uses the entry `key_id` itself — A13's key. So a column written with
>   `gcm_encrypt_kr` is read by `gcm_decrypt_krv` unchanged, and can be rotated row by row into
>   versioned envelopes. **`0x01` is refused with `bad_envelope`**: it is unauthenticated CBC, and a
>   new function has no installed base to keep it for. Accepting it would let whoever can write the
>   column replace an authenticated value with an unauthenticated one — and not only by guessing
>   past the padding check (about one time in 256): in CBC the IV is part of the stored value, so
>   given a CBC row under the same key bytes, XOR-ing a difference into its IV XORs the same
>   difference into the first plaintext block with certainty — to chosen values, if that block is
>   known. The padding is untouched when the plaintext is sixteen bytes or more; for a shorter one
>   the padding shares that block and survives only if the difference avoids it. It is a downgrade the existing functions carry for
>   migration's sake (A3) and this one need not. A CBC column is migrated through `gcm_decrypt_kr` first.
> - **Every key still in the keyring is still accepted.** A reader opens any version whose entry
>   exists, and the unversioned entry `key_id` if that exists. Rotating after a compromise therefore protects nothing until
>   the old entry is removed, and until then whoever can write the column can put an old envelope
>   back. This amendment has no "minimum version" argument; whether it needs one is an open
>   question.
> - **At most four keys per `UDF_INIT`.** A13 allows one keyring read per `UDF_INIT`. A statement
>   over a half-rotated column needs more than one key, so this is widened to a small table: up to
>   four distinct keys (versions, and the unversioned entry if a row needs it — it counts as one of
>   the four), each read once, on the first row that
>   needs it, and held as A13 holds its one. The lifetime rules are A13's, applied to all of them:
>   a row that raises an error wipes every held key, with the A11 states and the result buffer, and
>   so does `deinit`; a `bad_tag` that `gcm.strict=OFF` turns into NULL keeps all of them, while the scheduled context
>   is reset, as A11 requires after any cipher failure. There is
>   still **one** scheduled decryption context (A11): a row whose key differs from the previous
>   row's reschedules it from a held key — no keyring read, but the per-row setup cost A11 removed
>   comes back for a column whose versions alternate. A14's fold becomes up to four names under one
>   lock. **A row that needs a fifth is an error**, not an
>   eviction: evicting would let whoever can write the column make every row cost a keyring read by
>   alternating versions. Two is the steady state of a rotation; four leaves room for one that
>   overlaps the next. A version that names no usable entry is A13's *no usable key*, and an error is
>   final for the `UDF_INIT`, so a made-up version costs one read and one failed statement.
>   **That is also a way to break reads**: one planted row with a version that has no entry fails
>   every statement that scans it, with `gcm.strict` OFF as well — the same class as a malformed
>   envelope today, which strict does not soften either. (It is an error and not that row's NULL
>   for A13's reason: a key that cannot be had is misconfiguration, and `gcm.strict` has one
>   meaning.) The "fifth key" error needs five versions that all exist, so it arises only where at
>   least that many entries are still in the keyring. So that the row can be found, these two errors **do name the
>   `key_version`**: it is a header field read from the stored value and not a keyring fact —
>   `spec/envelope.md` §4 rule 4 already allows lengths and the version byte in a message, though
>   today's messages carry lengths only. The
>   finder is `WHERE gcm_envelope_key_version(col) NOT IN (…)`. A column that legitimately holds five
>   versions cannot be scanned in one statement until some of it is re-sealed.
> - **`gcm_envelope_key_version(ciphertext)`** parses the six header bytes with the same code the
>   decryptor uses and needs no key: the version for a well-formed extended-header envelope, NULL
>   for a well-formed `0x01`–`0x07` one, an error for anything else (shorter than its minimum, an
>   unknown version byte or `suite`, a `key_version` of zero). The result is the loadable-function
>   integer type, a signed 64-bit `BIGINT`, which holds every version. **It is not authenticated.**
>   It tells which rows *claim* a version, which is what a re-seal job needs; it cannot prove that
>   no row still depends on a key. Before an old entry is deleted, every row has to be opened — a
>   tag check — and not merely inspected, because a rewritten header would hide a row from this
>   function. **And opened with `gcm.strict = ON`, or with the NULL results counted**: with strict
>   OFF a row whose header was edited to another version fails its tag silently, as a NULL, the
>   scan finishes without an error, and the operator deletes the very entry that row needs.
> - **Usage counts (A14) are per version, and use up names faster.** A14 defines the name as
>   (account, `key_id`); for these functions it is (account, **entry id**), so `patient_name.v2` is
>   read with `gcm_key_usage('patient_name.v2')`, and each version has its own row — closer to "per key" than A14 could
>   get, since a new version is a new name, provided each version is a newly generated key. A14 bounds an account at 64 names and never evicts one,
>   so a long rotation history counts against that bound.
> - Everything else is A13's: the account boundary, definer routines, NULL, failure semantics, an
>   error releasing every secret of the instance, no message naming an id, an account or an entry.
>   A definer routine over `_krv` adds one thing to A13's oracle: its callers learn which versions
>   exist.
>
> ### Why the header is not authenticated
>
> **Decision: the six header bytes are not part of the associated data, and the deterministic nonce
> is derived exactly as today** — one label, `HMAC-SHA256(nonce_key, plaintext)[:12]`, the caller's
> AAD the only associated data, and `spec/envelope.md` §3's "the AAD is not an input to the nonce"
> unchanged. The header is as unauthenticated as the version byte of `0x02`–`0x07` already is.
> Under the header, the bytes of a `0x10` envelope are those of the `0x02`–`0x07` envelope the same
> key, plaintext and AAD would give.
>
> - **What that leaves open, exactly.** Whoever can write the column can edit the header, or rewrap
>   a `0x10` envelope as a `0x02`–`0x07` one and back. **No plaintext is forged and none is
>   revealed** (the author's and an automated reviewer's reasoning; not independently reviewed). If the entry the edited header points to holds *different* key bytes, the tag fails,
>   as for any wrong key; if it holds the *same* key bytes — one key stored under two versions, or
>   as `id` and `id.v1` — the value opens to the plaintext it always held. What an edit can do:
>   1. **misreport the version** to `gcm_envelope_key_version`, which is not authenticated in any
>      design; the rule above — open every row before deleting an entry — assumes it can be lied to;
>   2. **flip the random/deterministic marker** in `suite`, which the decryptor ignores, exactly as
>      it ignores the difference between `0x02` and `0x03` today;
>   3. **give one value several stored encodings that all open** — another same-bytes version, the
>      other marker, the unversioned form. So a `UNIQUE` index and ciphertext equality hold only
>      against writers who cannot write the column: a copied deterministic row with an edited header
>      is a duplicate the index does not see and a lookup does not find. That is already true of
>      `0x02`/`0x03`; the header adds more ways to do it;
>   4. **fail the statement**: a `suite` of another key length is `bad_key_len`, whatever
>      `gcm.strict` says.
>
>   And a writer who can see outcomes learns, by trying, whether two entries hold the same key bytes
>   (the value opens, or the tag fails) and each version's key length — an addition to the oracle
>   described above.
> - **Replay is the caller's AAD to prevent, as it is today.** An envelope can be copied into another
>   row or another column sealed under the same key bytes, and it opens there. Binding a value to its
>   row or column is what the caller's AAD is for — in random mode; constraint 7 forbids a per-row
>   AAD for deterministic values. Nothing in this amendment changes that.
> - **No new (key, nonce) reuse arises** (again by that reasoning, and not independently reviewed).
>   "Key" here means key *bytes*. Under the same bytes, the
>   same plaintext gives the same nonce, and with the same AAD the same ciphertext and tag: one
>   message, however many headers it is stored under. A different plaintext gives a different nonce
>   up to the 96-bit truncation `spec/envelope.md` §3 already accepts. The caller's obligation is the
>   existing one, and its reach has to be said plainly: **constraint 7 and the usage budget span
>   every version, id and family that hold the same key bytes.** Storing the A13 key again as
>   `id.v1` and adopting a new AAD convention with it would break constraint 7. Each version SHOULD
>   be an independently generated key, which makes every same-bytes case above disappear.
> - **What the earlier drafts did.** The first put the header into the associated data and left the
>   nonce as it was. That is unsafe: the same key bytes under two versions would seal the same
>   plaintext with the same key and nonce and *different* associated data, the pair §3 forbids, and
>   `crypto-reviewer` blocked it. The second also hashed the header into the nonce, under a second
>   derivation label, which removes that reuse; it passed the automated `crypto-reviewer` with
>   comments, on the assumption that HMAC-SHA256 is a PRF, and had no human or independent review.
>   It is not what is proposed, for three reasons a reviewer gave:
>   - what it protects against exists only where two entries hold the same key bytes, and there it
>     prevents the edits listed above, none of which forges or reveals a plaintext;
>   - it changes the associated data, adds a second label, needs new vectors for every suite, alters
>     A12's cross-suite linkage, and leaves a confusion of its own (an A13 envelope whose caller AAD
>     begins with the header bytes) — a larger surface in the part of the project that has had no
>     independent cryptographic review;
>   - either form can be added later as a further version byte, so the choice is which to commit to
>     before any independent review: the one that leaves the cipher code as it is.
> - **If an independent review asks for header binding**, it is added as a further version byte —
>   `0x11`, "extended header, authenticated" — with the header in the associated data *and* hashed
>   into the deterministic nonce under a second label; the one without the other is the unsafe first
>   draft. `0x10` envelopes would stay readable, and stay editable in the ways listed above until
>   they are re-sealed.
> - A deterministic value is equal to another, as stored bytes, only within one key, one suite, **one
>   version** and one envelope family, because the header is part of the stored value. The bytes
>   after the header are equal whenever key bytes, plaintext and AAD are — so equal plaintexts stay
>   linkable across versions and families that share key bytes, or whose keys are zero-extensions of
>   one another. Because the derivation is unchanged, A12's observation carries over as it stands:
>   a key and its zero-extension derive one nonce key, across versions, ids and families as across
>   suites. "Pad the 16-byte key to 32 and call it version 2" is the resizing of one key into
>   another that A12 and constraint 11 forbid.
>
> ### What rotation then looks like
>
> ```sql
> -- 0. every reader of the column already calls gcm_decrypt_krv (it reads the A13 rows too)
> SELECT keyring_key_generate('patient_name.v2', 'AES', 32);            -- 1. a new version
> -- 1b. the SAME key bytes are in the keyring of every server that reads the column, under the
> --     same id and account, before step 2 (constraint 14). Generating it again on each server
> --     gives different bytes under one name.
> -- 2. writers switch to version 2; readers cope with both:
> SELECT id FROM patients WHERE gcm_decrypt_krv(name_enc, 'patient_name') LIKE '%길%';
> -- 3. re-seal the rest, in batches, WITH gcm.strict = ON. Read every warning below this block
> --    first: the nested call is not a tested shape on 8.0/8.4 (A7), and strict OFF loses rows.
> UPDATE patients
>    SET name_enc = gcm_encrypt_krv(gcm_decrypt_krv(name_enc, 'patient_name'), 'patient_name', 2)
>  WHERE name_enc IS NOT NULL
>    AND (gcm_envelope_key_version(name_enc) IS NULL OR gcm_envelope_key_version(name_enc) < 2)
>    AND gcm_decrypt_krv(name_enc, 'patient_name') IS NOT NULL    -- never write a NULL back
>  LIMIT 1000;
> ```
>
> **Step 3 destroys data if it runs with `gcm.strict = OFF` and without that last predicate** — and,
> independently of strict, if the nested call turns out to be one of the shapes A7 corrupts (below). A row whose tag fails — corrupted, or
> with its header edited to a version that holds other key bytes — then decrypts to NULL, sealing
> NULL gives NULL, and the `UPDATE` writes NULL over a ciphertext that its real version could still
> have opened; `name_enc IS NOT NULL` then hides the row from every later batch. With the default
> `gcm.strict = ON` the same row is an error and the batch stops, which is what a re-seal wants.
> **Re-seal only with `gcm.strict = ON`.** But that setting is GLOBAL-only before MySQL 9.0 (A5)
> and is read per statement, so checking it and then running is a race with whoever changes it —
> and the natural moment to change it is exactly when a batch has stopped on a failing row, whose
> error names no row, and someone turns strict off to find it with `… IS NULL`. Hence the last
> predicate. **What it does is keep a NULL from being written, not make the job complete**: with
> strict ON a row whose tag fails is still an error and the batch stops; with strict OFF that row
> is skipped, and skipped again by every later batch, so it stays behind on its old version. A row
> naming a version with no entry is an error under either setting. **Count the rows the job left
> behind** before calling the rotation done, and **stop the job before turning strict off to look
> for a failing row.** On MySQL 9.0 and later the race can be removed altogether:
> `SET SESSION gcm.strict = ON` in the session that runs the job.
>
> The predicate has a price: the statement now has two instances of `gcm_decrypt_krv`, so each row
> is decrypted twice, the keyring is read once per instance, and a tag failure is counted by A14 in
> the `WHERE` instance.
>
> **The statement is a sketch, not a tested recipe for these functions**, which do not exist yet.
> Two things are known about its shape:
>
> - It passes the result of one loadable function as the plaintext argument of another. Amendment
>   A7 found that MySQL 8.0 and 8.4 hand a loadable function a stale view of some *computed* string
>   arguments. For this shape, with the A13 functions that do exist — `gcm_encrypt_kr(gcm_decrypt_kr(c, id), id)`
>   in an `INSERT … SELECT` and in an `UPDATE`, in both row orders, over eight rows of very
>   different lengths including the empty string — every row came back intact on 8.0.46, 8.4.11 and
>   9.4.0 (the servers of the pinned images; the 8.0 image runs 8.0.46 while the component is built
>   against the 8.0.43 tree). That is one observation on three servers, run by hand with no committed test behind it,
>   and not a guarantee across shapes; binary (non-UTF-8) plaintexts, which pass through a `utf8mb4`
>   result into a `utf8mb4` argument in this shape, were not tried; the
>   implementation has to pin it per major as `91_server_udf_arg_defect` pins A7, and until it does
>   the conservative form is constraint 10's: decrypt into a real table and seal from it.
> - It assumes the column holds no legacy `0x01` rows: the finder answers NULL for them, the
>   statement would select them, and `gcm_decrypt_krv` refuses them. Migrate those through
>   `gcm_decrypt_kr` first.
>
> A key id containing a dot was tried with `component_keyring_file` on the same three servers
> (`it_dot.v2`, generated, sealed and opened through the A13 functions) and behaved like any other
> — again by hand, with no committed test.
>
> The component does none of these steps itself. It does not rotate, schedule, or decide that a key
> is old; A8's "the operator plans the rotation" stands. What changes is that the plan no longer
> needs a second column or a statement per key.
>
> ### What it does not solve
>
> - **Deterministic columns.** Equality holds within one key version. During a rotation a `UNIQUE`
>   index does not see two versions of one value as duplicates, and a join on ciphertext misses rows
>   on the other version. A deterministic column has to be rotated as one migration, as A8 already
>   says; the version in the envelope only makes its progress visible.
> - **Old keys.** A version cannot be removed from the keyring while any row or backup still carries
>   it. `gcm_envelope_key_version` says which rows claim to; only opening them — with
>   `gcm.strict = ON`, or counting the NULLs — proves it; backups are the operator's to know. Every server that reads the column needs every version it may meet in
>   its own keyring (constraint 14).
> - **Constraint 2.** The plaintext and the `LIKE` pattern are still in the statement.
> - **The nested-call defect (#43)** applies to these functions as to the others, and the re-seal
>   statement above nests one inside another — with literals, which is not the shape #43 was
>   observed in. #43 is about the *inner* call taking a prepared-statement parameter, and the
>   implemented `_kr` functions answer it: `tests/integration/nested/17_kr_reseal_chain` prepares
>   `gcm_decrypt_kr(gcm_encrypt_kr(gcm_decrypt_kr(c, ?), ?), ?)` with every key id bound, and it
>   round-trips on 8.0, 8.4 and 9 with the component uninstalling cleanly afterwards — the column
>   argument of the innermost call keeps the server from evaluating it early. What is still untried
>   is `gcm_decrypt_krv` and `gcm_envelope_key_version` with a bound `key_version`: those do not
>   exist yet, and the PR that implements them has to pin that shape per major the way A7's
>   finding is pinned.
>
> ### Open questions for review
>
> 1. ~~Authenticate the header and hash it into the nonce, or neither?~~ **Proposed, on a
>    reviewer's recommendation: neither** — see "Why the header is not authenticated". What stays open is whether an
>    independent cryptographic review, when there is one, wants the authenticated form added as
>    `0x11`.
> 2. **Four keys per `UDF_INIT`** — the number, and error rather than eviction.
> 3. **Four bytes of `key_version`.** Two would do for any real rotation history and save two bytes a
>    row; four costs nothing to reason about.
> 4. **The `.v` naming convention**, which makes `key_id` values containing `.v<digits>` at the end
>    ambiguous to a human reader though not to the component.
> 5. **Whether the unversioned fallback belongs in `gcm_decrypt_krv`** or should be a separate,
>    explicit migration step; and **whether readers need a minimum-version argument**, so that an
>    old key stops being accepted before its entry is deleted.
> 6. **Issue #37**: whether new suites are extended-header only.
> 7. **Whether `gcm_decrypt_krv` should refuse a second key whose bytes equal one it already holds**
>    (a constant-time comparison among at most four). It would remove every same-bytes case within a
>    statement, at the cost of failing the "version 1 is the key we already had" shortcut loudly.
>
> **Sequencing.** After A13 and A14. Not backward compatible for readers: see "0.1.0 cannot read
> these envelopes" above. It needs its own release note and a `spec/envelope.md` version bump.
>
> **Impact, for the implementation PRs:**
>
> | Area | Change |
> |---|---|
> | `spec/envelope.md`, `spec/test-vectors.json` | v4: the `0x10` layout and its big-endian field (§2 says there is none), the `suite` values and the key-length rule of §2.5 restated for them, the reserved range of §2.6, that the header is not authenticated, §1's "nothing else distinguishes them", §4.2's "one key per statement instance" and its rules 5–7 for the four-key table, messages that may carry `key_version` (§4 rule 4). §3 is unchanged. Project vectors for every suite under the extended header: each is an existing `0x02`–`0x07` vector's nonce, ciphertext and tag behind a six-byte header, so the cryptographic content is already pinned by the existing vectors and the NIST KAT |
> | `src/envelope.{h,cc}`, `src/gcm.{h,cc}` | parsing and building the header, and the entry points that write and read an envelope carrying it. **No change to the cipher calls, the associated data, or `src/nonce.{h,cc}`** |
> | `src/udf_*.cc`, `src/udf_glue`, `src/key_source` | the four functions; strict parsing of `key_version`; up to four held keys per instance and their wiping; messages that say "suite" where they mean the `suite` byte (today's "does not match the envelope version" and the `suite_for_version` name would otherwise blur "version `0x03`" and "suite `0x03`") |
> | `spec/envelope.md` §4.3, `src/usage`, `src/udf_usage.cc`, `docs/ops-constraints.md` 19 | the usage name for these functions is (account, entry id), and how a version's count is read |
> | `tests/unit`, `tests/adapter`, `tests/integration`, `mysql-test` | vectors; a changed header (fails under a different key, opens under the same key bytes — both pinned); mixed-version statements; the fifth key; the unversioned fallback; a rotation end to end |
> | `crypto-safety.md`, `architecture.md` | "lengths and the version byte are as far as it goes" widened to the `suite` and `key_version` of a stored header; the widened key table (up to four fetched keys per instance) — which is a cross-row value keyed on (account, entry id) and so has to be named as an exception to the blocked pattern "a cross-row cache keyed on anything but the full key bytes". The grounds differ from A13's one key: there the id is the caller's whole input, here the stored header chooses among entries, which is why the table is bounded and a fifth key is an error; the other blocked patterns. The label rule and "AAD is not an input to the nonce" are unchanged |
> | README, `docs/ops-constraints.md`, `AGENTS.md`, `CHANGELOG.md` | the functions, the compatibility note, rotation guidance including "re-seal only with `gcm.strict = ON`" and "open every row with `gcm.strict = ON`, or count the NULLs, before deleting an old entry". `AGENTS.md` §2 ("withdrawn … a key id or key version in the envelope") and §9 ("out of scope: … a key version in the envelope") both become wrong when this is implemented and change with it |

> ## Amendment A14 (2026-10-12) — per-key usage counts for the key-id functions
>
> **Status: implemented and merged (issue #35; PRs #44, #45 and #46, 2026-10-13, merged by the
> repository owner after the reviews recorded on those PRs).** The table is in `src/usage`, the
> function in `src/udf_usage.cc`, the counting and the fold in `src/udf_kr.cc` and
> `src/udf_glue.cc`. Pinned: the table in
> `tests/unit` (18 cases, threads included); the wiring in `tests/adapter/udf_usage_test.cc`;
> `tests/integration/63_kr_usage` on 8.0, 8.4 and 9.4; `mysql-test/suite/gcm/t/gcm_kr_usage` on
> 8.4; and on a server with no keyring, where the function still answers. Pinned since: the counts
> lost by an instance the server abandons without de-initialising it, which
> `tests/integration/nested/24_nonraising_kr_inner` produces — the seal inside the leaked instance
> is not in the answer, and the instance's own figures never fold (issue #43).
>
> Amendment A8 and operational constraints 11 and 13 tell every deployment to set a usage budget per
> key and then say "the component does not count uses", so the operator has no number to compare the
> budget with. Amendment A13 gave a key a name the component may publish. This adds a count under
> that name, and one function to read it.
>
> ```
> gcm_key_usage(key_id)  -> VARCHAR (utf8mb4), a JSON object as text
>   {"random_seals":N,"det_seals":N,"bytes_sealed":N,"tag_failures":N,"since":T,"complete":true}
> ```
>
> **What the number is, and it is less than it looks.** A row is *the calls this server has made
> through the key-id functions under this name since it started counting*. It is **one input** to
> the budget A8 asks for, not the budget, and the documentation says so wherever the number appears.
> `random_seals` is a lower bound on the nonces drawn under the key those bytes are. `det_seals` is
> not a bound on anything: it counts **calls**, so a repeated lookup
> (`WHERE c = gcm_encrypt_det_kr(?, 'id')`) and an evaluation folded at optimisation each add one
> though they seal no new message. (Measured in the implementation: a lookup with a constant
> argument adds three per statement on 8.0, 8.4 and 9.4.)
>
> - The budget is about key **bytes**; the count is about a **name**. The same bytes under another id
>   or another account are counted separately. An id whose entry was removed and generated again is
>   a new key under an old name, and the count carries on. The component cannot tell either case
>   without keeping something derived from the key bytes. A11 rejected a hash of the key even as a
>   cache key, and this amendment does not introduce a retained key-derived value either.
> - **The key-argument functions are not counted at all**: they have no name to count under. A
>   deployment that uses both families has a count that is not the total, and
>   `keyring_key_fetch` lets an application move a keyring key into that uncounted family.
> - Other servers are other counts. A replica under ROW replication calls no function and counts
>   nothing; copying or restoring an envelope is not a seal.
> - It starts again from zero when the server restarts or the component is reinstalled. A reader
>   detects the reset by **`since` changing or a count being smaller than the one it last read**,
>   not by `since` alone: `since` has one-second resolution and follows the wall clock, so a
>   reinstall within the same second leaves it unchanged, and a clock stepped backwards can make
>   it earlier. The ledger A8 asks the operator to keep holds the previous value to compare with.
> - Counts held by an instance that neither raises an error nor is de-initialised are lost. Issue
>   #43 shows the server skipping `deinit` in one shape (observed on 8.0, 8.4 and 9 —
>   `tests/integration/nested`); the fold in the error row covers the case where the instance
>   itself raised, and nothing covers the rest.
>
> ### Decisions
>
> - **The name is (calling account, key id)** — A13's namespace, `priv_user@priv_host` and the id.
>   `gcm_key_usage` answers for the caller's own account only, which is the boundary A13 already has
>   and needs no new privilege. There is no cross-account view; an operator reads it as each account,
>   or through a `SQL SECURITY DEFINER` routine with the id hard-coded, as for A13 — and such a
>   routine shows its callers the definer's volume and tag failures, which is a decision for
>   whoever writes it.
> - **It reads no keyring.** The function looks up a name in the component's own table. It does not
>   check that the id names a key: a name with no counts answers zeros. `key_id` is validated as in
>   A13 (1 to 255 bytes after conversion to `utf8mb4`, no NUL); a NULL argument gives NULL.
> - **What is counted.** `random_seals` and `det_seals`: successful calls of `gcm_encrypt_kr` and
>   `gcm_encrypt_det_kr`. `bytes_sealed`: the plaintext bytes of those calls, as sealed — after the
>   conversion to `utf8mb4`, without the AAD. `tag_failures`: `gcm_decrypt_kr` calls that ended in a
>   tag mismatch, with `gcm.strict` ON or OFF — forgery attempts count against the GCM bound too
>   (NIST SP 800-38D), and it is the one number here that can show an attack; it also counts an
>   honest mistake, such as opening a value under the wrong key id. Successful decryptions and failed
>   seals are not counted. A call counts when it returns, whether or not the statement later fails or
>   its transaction rolls back. Counts are 64-bit and saturate.
> - **When a name gets a row.** Only when a `_kr` function folds a non-zero count, which it can only
>   have after the keyring gave it a usable key under that name. `gcm_key_usage` never creates a
>   row, and neither does a key-source failure, a floor refusal or a NULL argument. So a row cannot
>   be made for a name that has no key.
> - **`since`** is the Unix time, in seconds, at which the component began counting (its
>   initialisation). **`complete`** is false once a name of **the caller's account** did not fit —
>   see below — and then some use by that account is in no row. It says nothing about any other
>   account.
> - **One fold per `UDF_INIT`, nothing per row.** A `_kr` function counts in its own `UDF_INIT`
>   state, in plain integers, and folds them into the component's table when the instance ends: in
>   `deinit`, and in the row that raises an error, because the server was observed not to call
>   `deinit` after one (issue #43). The counters are zeroed by the fold, so an error row followed by
>   a normal `deinit` does not count twice, and an instance with nothing to fold takes no lock. The
>   fold uses the account and the id recorded when the key was read, not a fresh look at the caller.
>   So a statement's own counts are not visible while it runs, and a `gcm_key_usage` call in the same
>   statement as the seals it would count sees the earlier value. **The exception is A13's:** through
>   a definer stored *function* the server makes a `UDF_INIT` per row, so that shape takes the
>   table's lock once per row, on top of the keyring read it already costs.
> - **No persistence, no thresholds.** Issue #35 proposed both. A count persisted by the component is
>   rolled back by a restore, which A8 warns about, and the server offers no shutdown notification
>   to a component on 8.0. A refusing threshold without persistence is undone by a restart and would
>   look like enforcement while being none. The durable ledger and the alert are the operator's
>   monitoring system reading this function — which is where A8 already puts the ledger.
> - **No new server service**, no envelope change, no change to the core.
>
> ### The component's first shared state
>
> Until now the component held nothing between calls but the fetched algorithms and its two system
> variables. The table of counts is shared, mutable, and lives from component init to deinit.
> `architecture.md` §3 asks for a stated lifetime and synchronisation for any such state:
>
> - **Contents:** names (account and key id — not secret, and already visible in
>   `performance_schema.keyring_keys`) and integers. **No key bytes and nothing derived from them.**
> - **Synchronisation:** one mutex, taken once per `UDF_INIT` to fold and once per `gcm_key_usage`
>   call to read. Never on the row path of an encryption or decryption.
> - **Bound:** at most 64 names per account and 1024 in total. A use under a name that does not fit
>   is not attributed, and `complete` turns false in that account's answers from then on. The
>   per-account bound is what keeps one account from switching counting off for the others: an
>   account that fills its share loses its own later names and changes nothing in anyone else's
>   answer. The whole table fills when sixteen accounts each hold their 64 names — which needs no
>   collusion, only that many busy accounts. From then on every new name is lost: an account that
>   has rows is told `complete: false` when it loses one, and an account with no row at all is told
>   `false` as soon as any rowless account has lost a use, because the table has nowhere to keep
>   which one. That last case is the one way another account's use shows in an answer. Names are never evicted: evicting would make a
>   count go backwards.
> - **Lifetime:** created in init before any function is registered, released in deinit after every
>   function is unregistered. An instance the server never de-initialises (issue #43) has already
>   folded in the row that raised.
> - **Where it lives:** a module with no server dependency, so `tests/unit` covers it, concurrency
>   included.
>
> ### What stays as it was
>
> The component still does not hold a budget, rotate a key, detect a repeated nonce, or enforce an AAD
> policy (constraint 13). A8's instruction to sum **every** use of a key across servers, columns and
> applications stands; this gives one of the numbers to sum.
>
> **Sequencing.** After the key-id functions (A13), in the same minor release. Backward compatible:
> one more function.
>
> **Impact, for the implementation PRs:**
>
> | Area | Change |
> |---|---|
> | `src/` | the table of counts as a server-free module; the counters in the per-instance state and the fold in `deinit` and on the error row; the `gcm_key_usage` UDF; init and deinit of the table in `component.cc` |
> | `spec/envelope.md` | the function's argument contract and the meaning of each field |
> | `tests/unit`, `tests/adapter` | the table (folding, the bound, concurrent folds); when a count becomes visible, the error-row fold, account isolation, that the key-argument functions add nothing |
> | `tests/integration`, `mysql-test` | counts after seals of each kind and after a tag failure, on every major |
> | `architecture.md` §1, §3 and §5, `crypto-safety.md` (operational responsibility: "do not assume the component counts per-key usage") | the module, the component-level state and its rules; that the table holds no key material; what may and may not be assumed from a count |
> | README, `docs/ops-constraints.md` 11 and 13 and a new item, §6's A8 entry, A13's "the component still counts nothing", `AGENTS.md`, `CHANGELOG.md` | the function, and what is now counted and what still is not |

> ## Amendment A13 (2026-10-12) — functions that take a key id and read the key from the keyring
>
> **Status: implemented and merged (issue #34; PRs #39, #40, #42 and #41, 2026-10-12, merged by the
> repository owner after the reviews recorded on those PRs).** It changes
> key handling and widens what amendment A11 lets a `UDF_INIT` keep. "Implementation notes" at the
> end of this amendment records what the implementation pinned, what it only observed, and one
> server defect it ran into (issue #43).
>
> Amendment A1 withdrew the keyring design and left the door open: "the keyring approach can be
> revisited later as an optional feature (something like `gcm_encrypt_kr`)". This is that revisit. It
> **adds** three functions and changes none of the existing three; taking the key as a SQL argument
> stays the default and stays supported.
>
> ```
> gcm_encrypt_kr(plaintext, key_id [, aad])       -> BLOB     random nonce
> gcm_encrypt_det_kr(plaintext, key_id [, aad])   -> BLOB     deterministic
> gcm_decrypt_kr(ciphertext, key_id [, aad])      -> VARCHAR  charset tagged (utf8mb4)
> ```
>
> **What it closes, and what it does not.** Operational constraint 2 has two halves. With these
> functions the *key* is not an argument of the encryption and decryption statements, so those
> statements no longer carry it into the general log, the slow log,
> `performance_schema.events_statements_*` or the binlog. A key created with `keyring_key_generate`
> never appears in a statement at all. **Importing an existing key does, once**:
> `keyring_key_store('id', 'AES', <key>)` is a statement with the key in it, and `keyring_key_fetch`
> returns the key to any session of the account that owns it. The *plaintext* argument and a
> `LIKE '%김%'` pattern are still in the statement. Constraint 2 shrinks; it does not go away.
>
> ### Decisions
>
> - **The envelope does not change.** The functions produce `0x02`–`0x07` exactly as
>   `spec/envelope.md` defines them, `gcm_decrypt_kr` reads everything `gcm_decrypt` reads — the legacy
>   `0x01` envelope included, through the same core path and with A3's conditions — and no vector
>   changes. A row written by `gcm_encrypt(…, key)` is
>   readable by `gcm_decrypt_kr(…, id)` when the keyring holds the same key bytes under `id`, and the
>   reverse. That is the migration path and a server test pins it.
> - **The key id is an explicit argument of all three functions.** Issue #34 proposed reading the id
>   from the envelope on decryption. That is deferred (see "Out of scope"): it needs new version
>   bytes, lets whoever can write the column choose the key, and makes the keyring lookup per row.
> - **The key is read through `keyring_reader_with_status`**, with the keyring `auth_id` set to the
>   caller's `priv_user@priv_host`. This is the namespace the server's own general-purpose keyring
>   functions (`keyring_udf`) use, so `SELECT keyring_key_generate('id', 'AES', 32)` creates a key
>   these functions can use and whose bytes were never in a statement. The component does not create,
>   store or remove keys.
> - **Authorisation is that namespace.** MySQL has no privilege for invoking a loadable function and
>   the keyring reader service checks none, so "who may call" cannot be the boundary. "Which key" is:
>   an account can use only the keys stored under its own `priv_user@priv_host`. No dynamic privilege
>   is registered. Two differences from `keyring_udf` are deliberate and stated: its functions also
>   demand the global `EXECUTE` privilege and these do not (reading one's own key is the whole
>   function); and the `user@host` string is ambiguous for an account name containing `@`, which is
>   inherited from `keyring_udf` rather than fixed here, since fixing it would leave its keys
>   unreachable. An account with an empty `priv_user` (anonymous) is refused: it is not one principal.
>   The namespace is a *string*, with what follows from that and has not been tried: an account
>   dropped and created again under the same name reaches the old account's keys, `RENAME USER`
>   leaves them behind, and under a proxy the name is whatever `priv_user` reports. And whoever may
>   create a routine with another account as its definer (`SET_USER_ID` on 8.0, `SET_ANY_DEFINER`
>   from 8.2) can use that account's keys; that privilege is already equivalent to being the account.
> - **Sharing a key between accounts** goes through a stored routine with `SQL SECURITY DEFINER`:
>   inside it the security context is the definer's, so the definer's keys are used. A view does
>   **not** do this — a function in a view runs as the invoker, whatever the view's `SQL SECURITY`.
>   Such a routine is an oracle for its callers over whatever it lets them choose, so it **hard-codes
>   the key id and the AAD**; neither is a parameter. And its shape matters (observed below): a
>   stored *function* gets a new `UDF_INIT` on every invocation, so `SELECT f(col) FROM t` reads the
>   keyring once per row; a stored *procedure* that contains the whole statement reads it once.
> - **When a call fails with *no usable key*, diagnose as the same account**: `SELECT CURRENT_USER()`
>   gives the namespace (`app@localhost` and `app@%` are different ones), and
>   `keyring_key_type_fetch('id')` and `keyring_key_length_fetch('id')` give what is stored — both
>   need the global `EXECUTE` privilege. The component's message will not say which it was.
> - **The key must be of keyring type `AES` — compared exactly, in that case — and 16, 24 or 32
>   bytes.** The length selects the suite and
>   nothing else does (A10). `gcm.min_key_bytes` applies to the two encryption functions and never to
>   `gcm_decrypt_kr`, exactly as for the existing functions.
> - **The key id** is 1 to 255 bytes with no NUL byte, after the server has converted the argument to
>   `utf8mb4` — which is what `keyring_udf` asks for its own string arguments (read in
>   `plugin/keyring_udf/keyring_udf.cc`, all three trees), so a non-ASCII id names the same entry from
>   either side. The bound is this component's, chosen to keep the id in a fixed buffer.
> - **At most one keyring read per `UDF_INIT`, on the first row whose arguments are all non-NULL.**
>   Not in `init`: see the observation below. Every later row of that `UDF_INIT` must bring the same
>   id bytes; a different id is an error. An id that varies by row (a column) is therefore refused on
>   the second distinct value. The id is not secret and is compared with `memcmp`. The account the
>   key was read under is recorded with it and compared on every row as well — reading the security
>   context touches no keyring — so "the account does not change within a `UDF_INIT`" is enforced
>   rather than assumed; a change is an error. The order on a row is: NULL check, id and account
>   check, the keyring read if this is the first such row, then the core. The read asks for the
>   entry's lengths first and for its bytes only when they are those of an `AES` entry of a suite
>   length, so this component never requests the bytes of an entry it will not use. How many
>   `UDF_INIT`s a statement has is the server's decision, not the component's — see the stored
>   function above. Pass the id as a literal, a user variable or a bound parameter: a *computed* id
>   is subject to the 8.0/8.4 argument defect of A7 like any other argument.
> - **A NULL argument gives SQL NULL** with no keyring access and no id check
>   (`spec/envelope.md` §4 rule 3).
> - **Every key-source failure is an error regardless of `gcm.strict`,** and `gcm.strict` keeps its
>   one meaning — a tag mismatch. There are four, and no more are distinguished:
>   *keyring unavailable* (the reader's `init` or a fetch failed); *no usable key* (no entry under
>   this id for this account, or an entry that is not type `AES` with a length of 16, 24 or 32 —
>   **one message for all three**, so that entries of another type or an odd length are not
>   revealed); *invalid id* (empty — which the server's keyring also asserts on in a debug build —
>   over 255 bytes, a NUL byte, or different from the first row's);
>   *no caller account*, which includes an account that changed between rows. No message carries
>   the key id, the account, or the length or type of a keyring entry. **This narrows an oracle and
>   does not close it**: a definer routine that took the id as a parameter would still tell its
>   callers which ids name a usable AES key and how long it is — through the `gcm.min_key_bytes`
>   refusal, through the key-length error a crafted envelope of another suite draws, through
>   *keyring unavailable* differing from *no usable key*, and through timing, which nothing here
>   equalises. That is why such a routine hard-codes it.
> - **An error is final for the `UDF_INIT`.** The server does not call a function's row callback
>   again once it has reported an error — `udf_handler::get_arguments` returns on the handler's
>   error flag; read in the 8.0.43, 8.4.11 and 9.4.0 sources — so no row follows a key-source
>   failure, or any other error, in the same `UDF_INIT`. The implementation records the failure as
>   well, so that a call made anyway is refused rather than served.
> - **`gcm_encrypt_det_kr` declares `const_item`, as `gcm_encrypt_det` does** — a constant lookup on a
>   UNIQUE index is what the variant is for. The consequence is that the keyring read can happen
>   while the statement is being optimised, in the caller's session and under the caller's account.
>   Whether `EXPLAIN` of a statement holding a constant `gcm_encrypt_det_kr` call reads the keyring
>   was not observed.
> - **The functions are always registered.** "Optional" means using them is: the component installs
>   and the existing functions work on a server with no keyring, where a `_kr` call raises
>   *keyring unavailable*. Observed on 8.4 only so far; that it holds on 8.0 and 9.4 is a gate for
>   the implementation PR, not something this amendment has established.
>
> ### The key copy: what A11 is widened to allow
>
> A11 lets a `UDF_INIT` hold a key copy only beside `gcm_decrypt`'s scheduled context or
> `gcm_encrypt_det`'s nonce key. A `_kr` function needs one more: **the key fetched from the keyring
> (at most 32 bytes), with the id and the account it was fetched under, held in the per-instance
> state from the first row to `deinit`.** It differs from A11's copies in two ways, and both are deliberate.
>
> - It is not a second copy of an argument the server already holds for the statement: no argument
>   buffer and no text of *this* statement contains the key. The component's copies — this one, and
>   A11's scheduled context and nonce key derived from it — are what the statement adds to the
>   keyring's own memory, and a core dump taken mid-statement contains them.
> - **It survives a `bad_tag` that `gcm.strict=OFF` turns into NULL.** A11 cleanses its copy on
>   every failure of the cipher operation, and that still happens: the scheduled context and its
>   copy, and the cached nonce key, are discarded exactly as A11 says, by the unchanged core. The
>   fetched key is kept, because the next row must still decrypt. **A row in which one of these
>   functions raises an error — a `bad_tag` under `gcm.strict=ON` included — gives up every secret
>   its `UDF_INIT` holds at once**: the fetched key, and the two A11 states and the result buffer
>   with it, because an error the core raises from a pre-check (a malformed envelope, a suite
>   mismatch) leaves its scheduled context and nonce key as they were. It does not wait for
>   `deinit`: no row follows an error (above), so nothing is lost, and the server does not always
>   call `deinit` after one. Giving the key up on the NULL path too would let whoever planted corrupt rows cause one keyring read per row with no error to stop
>   the statement, which on an external backend may be a network call per row.
>
> **What this contradicts, stated rather than left to a reviewer to find.** A11 rejects "a cache keyed
> on anything other than the full key bytes", `crypto-safety.md` lists it as a blocked pattern, and
> `architecture.md` §5 says nothing else is carried from one row to the next and that a row callback
> does not touch a file or the network repeatedly. `crypto-safety.md` also opens its key handling
> with "the key arrives only as the UDF argument `key`", and `AGENTS.md` §9 lists keyring
> integration as out of scope. The fetched key is a cross-row value keyed on
> *(calling account, key id)*, and its one read happens in the row callback. The grounds for the
> exception: A11's rule exists because a caller-supplied key can change between rows while a
> cheaper-to-compare proxy for it stays the same; here the id *is* the caller's whole input, there
> are no key bytes to compare until the keyring has been read, and comparing by re-reading is the
> per-row backend call this design avoids. Both halves of the cache key are compared on every row,
> the id and the account. The read is once per `UDF_INIT`. **Through a definer stored function that
> is once per row**, since the server gives each invocation its own `UDF_INIT`: an accepted breach
> of §5 for that one shape, listed with the operational constraints below. These rule texts are
> amended by the implementation PR to name this exception and no other.
>
> The conditions: the copy belongs to one `UDF_INIT` and is never shared across threads or instances;
> it is cleansed in `deinit` and when `init` fails after allocating; the reader object is released
> immediately after the fetch, never kept across rows (it holds a read lock on the server's global
> keyring lock from its `init` to its `deinit`), and if that release fails the result is ignored —
> there is nothing to do about it — and a key already fetched is still used; the fetch buffer is
> cleansed on every path. Nothing
> is cached across `UDF_INIT`s, so a key removed from or replaced in the keyring is picked up by
> the next `UDF_INIT` that reads it. **That is not a promise that one statement sees one key.** It
> is usually the next execution of the statement, but a definer stored function gets a `UDF_INIT`
> per row — so a key replaced while such a statement runs can take effect on its next row, and a
> deterministic column filled by such a scan can come out sealed under two keys. How fresh the answer is on a
> backend that caches is that backend's property, not this component's.
>
> The core (`gcm`, `envelope`, `nonce`) does not change. Reading the keyring and the caller's account
> is a server adapter (`architecture.md` §1), and the `_kr` functions call the same core entry points
> as the existing three.
>
> ### Observed on 2026-10-12 with a throwaway probe component
>
> Servers 8.0.46, 8.4.11 and 9.4.0 (the pinned images), the probe built against the 8.0.43, 8.4.11
> and 9.4.0 trees. **Observed once, and the tables below are still only an observation**: that
> throwaway probe was not committed, and no committed test reproduces these rows. A smaller probe is
> committed instead, as `tests/probe`, and what it pins is the *consequence* of the first table — a
> call the server evaluates before its bound parameter has a value, and the instance that is then
> never de-initialised — in `tests/integration/nested/20`–`22` (see "Implementation notes"). The
> three versions gave the same output for every row of the three tables.
>
> | What the function is called with | What `init` sees | What the row function sees |
> |---|---|---|
> | a literal, a user variable, a stored-procedure variable, `CONCAT` of literals, `(SELECT 'k')` | the value | the value |
> | a `?` of a prepared statement (`EXECUTE … USING @v`) | **a null pointer, length 0** | the value |
> | a column | a null pointer, length = the column width | the value |
> | a NULL literal | a null pointer, length 0 | NULL |
>
> So `init` cannot tell a bound parameter from a NULL literal, and "the id must be resolved in `init`"
> would refuse the way applications normally send it. Hence the first-row read above.
>
> | Caller and context | `auth_id` the component reads under | A key the definer `root@%` owns |
> |---|---|---|
> | `app@%` calling directly | `app@%` | absent |
> | `app@%` through a `SQL SECURITY DEFINER` function defined by `root@%` | `root@%` | found |
> | `app@%` through a `SQL SECURITY INVOKER` function | `app@%` | absent |
> | `app@%` through a `SQL SECURITY DEFINER` view defined by `root@%` | `app@%` | absent |
>
> | A five-row scan calling the function… | `UDF_INIT`s created |
> |---|---|
> | directly in the select list | 1 |
> | inside a stored *function* called in the select list | 5 — one per row |
> | directly, with the whole `SELECT` inside a stored *procedure* | 1 |
> | under `EXPLAIN` (function in a `WHERE` comparison) | 1, and no row call |
>
> Keys created with `keyring_key_generate` (`AES`, 16 and 32 bytes) and `keyring_key_store`
> (`SECRET`, 8 bytes) were read back with their length and type. An absent id returns from the
> reader's `init` with success and a null reader object, and left no line in the error log at the
> default `log_error_verbosity` of 2. At 3 the keyring component logs a note for it that carries
> the data id and the auth id (`ER_NOTE_KEYRING_COMPONENT_READ_DATA_NOT_FOUND`; read in the 8.4.11
> source, not run) — so with verbose error logging a key id and the account that asked for it reach
> the error log, from the server's keyring and not from this component. An
> account without the global `EXECUTE` privilege was refused by `keyring_key_generate` and could
> still reach the reader. On a server with no keyring loaded — **8.4 only** — the reader's `init`
> returned failure and `INSTALL COMPONENT` had succeeded. Triggers and events were not tried.
>
> Read in the 8.0.43, 8.4.11 and 9.4.0 sources, not run: the service header is identical in all
> three and was introduced in 8.0.24 — on an older 8.0 a hard `REQUIRES_SERVICE` on it cannot be
> satisfied and `INSTALL COMPONENT` would fail, which was not tried: the component is built and
> tested against 8.0.43, and nothing older is supported; `mysql_thd_security_context`,
> `mysql_security_context_options` and `mysql_current_thread_reader` have the same signatures in all
> three; the server registers a default implementation of the reader service in all three, which is
> why requiring it should not block an install on 8.0 and 9.4 either; the server's reader wrapper
> takes a read lock on its global keyring lock in `init` and holds it until `deinit`; a failed
> backend read surfaces as `fetch_length` or `fetch` returning failure with no error code, so the
> component cannot tell "backend unreachable" from any other fetch failure and does not claim to.
>
> ### Which keyring, and the §3 prerequisite
>
> The original §3 called the keyring backend a prerequisite and ruled `component_keyring_file` "not
> viable". That verdict was about one goal, and there are two:
>
> - **Keeping the key out of the encryption and decryption statements** — this does not depend on
>   where the keyring stores its data, so the file keyring is enough. This is what the amendment
>   claims, and the file keyring is the only one it has been tried with.
> - **Surviving a stolen data directory or backup** — needs the key off the database host, so an
>   external backend. §3 stands for this goal: with `component_keyring_file` the key sits beside the
>   data, and this amendment does not claim otherwise.
>
> Oracle's MySQL Community distribution ships no external backend: the 8.4 manual lists
> `component_keyring_file` as its only keyring (the 8.0 image also carries the legacy `keyring_file`
> plugin), and the external ones are in MySQL Enterprise Edition
> ([manual](https://dev.mysql.com/doc/refman/8.4/en/keyring.html)).
> The project's CI can therefore exercise the file keyring and nothing else. Behaviour with an
> Enterprise backend, and with Percona Server's keyring components, is **untested** and is not
> claimed as supported. A backend that does not cache makes the one read per `UDF_INIT` a backend
> call per statement.
>
> ### Operational constraints this adds
>
> - Keyring contents are not replicated, exactly as the component is not (constraint 14). Every
>   server that runs a `_kr` function needs the key under the same id **and the same account**.
> - `gcm_encrypt_kr` and `gcm_encrypt_det_kr` both need ROW binlog. The existing `gcm_encrypt_det`
>   gives the same bytes wherever it is replayed; a `_kr` function replayed on a replica would
>   resolve the id in the replica's keyring under whatever account the applier runs as. Not tested;
>   do not rely on it.
> - **Sharing through a definer stored *function* costs one keyring read per row**, each taking the
>   server's global keyring read lock, and on a backend that does not cache, one backend call per
>   row. `WHERE f(col) LIKE '%길%'` over a shared key is exactly that shape. Prefer one account per
>   application with its own keys; where a key must be shared, put the whole statement in a definer
>   procedure, and measure before using the function shape on a large scan.
> - Key-usage accounting (A8, constraints 11–13) is unchanged by this amendment: the component
>   counts nothing here. (Amendment A14 later adds a count of calls per key name.)
>   A key reachable by id from several accounts or servers is one key for the usage budget.
> - **Every condition on a deterministic key still applies, and a keyring makes two of them easier to
>   break.** A12 requires an independent, full-length CSPRNG key per suite and security domain:
>   `keyring_key_generate` gives one, `keyring_key_store` accepts whatever it is handed, padded or
>   low-entropy keys included, and the component cannot tell. And "one AAD convention per key"
>   (constraint 7) and "independent keys for the random and the deterministic mode" (A12) are about
>   the key *bytes*: a key several accounts reach through a routine, or that `keyring_key_fetch`
>   hands to an application which then passes it to `gcm_encrypt_det`, is still one key with one AAD
>   convention across all of them.
> - A key generated in the keyring exists nowhere else. Backing up the keyring, and keeping old keys
>   for old data, is the operator's responsibility as before — and now the only copy is theirs.
>
> ### Out of scope, deliberately
>
> - **A key id or key version in the envelope**, and with it rotation and dual-read without the
>   application's help. It needs new version bytes (to be allocated together with issue #37), an
>   authenticated id, a bound on which ids a stored value may name, and an answer to the per-row
>   lookup that `architecture.md` §5 forbids. Its own amendment.
> - A dynamic privilege, per-key grants, and any function that writes to the keyring.
> - Per-key usage counters (issue #35), which this makes possible by giving a key a name.
> - `tests/e2e`: a replica with its own keyring is a separate piece of test infrastructure.
>
> ### Implementation notes (2026-10-12)
>
> **Pinned by committed tests.**
>
> - `tests/integration/60_kr_roundtrip`, `61_kr_key_source` and `62_kr_accounts` run on 8.0, 8.4 and
>   9.4 with one expected output each: the round trip and Korean `LIKE '%길%'`, interoperation with
>   the key-argument functions in both directions and identical deterministic bytes, the floor, a
>   legacy `0x01` envelope, the one "no usable key" error for an absent id, a `SECRET` and an 8-byte
>   `AES` entry, invalid ids, NULL arguments, an id that varies by row, a key id sent as a bound
>   parameter, `gcm.strict=OFF` over a good, a tampered and a good row in one statement, and the
>   account table above — another account's id, a definer function, an invoker function, a definer
>   view.
> - `scripts/verify-bare.sh` starts a server with **no keyring** on each major and checks that the
>   component installs, the key-argument functions work, each `_kr` function raises *keyring
>   unavailable* with `gcm.strict` ON and OFF, and the component uninstalls afterwards. This closes
>   the gate the decisions above left open, on 8.0.46, 8.4.11 and 9.4.0.
> - `tests/adapter/key_source_test.cc` calls the key source directly and
>   `tests/adapter/udf_kr_test.cc` drives the UDFs, both against stub services, for what a real
>   server cannot be made to show: one keyring read per `UDF_INIT` and none in `init`, no reader
>   left open on any path, each keyring call failing, a fetch that disagrees with the length call,
>   the latch for each kind of failure, the account changing between rows, the fetched key
>   surviving a `bad_tag` that `gcm.strict=OFF` turns into NULL, and a row that raises an error
>   wiping every secret of its item — the fetched key, the scheduled context, the cached nonce
>   key and the result buffer, each asserted on the item's state.
> - `mysql-test/suite/gcm/t/gcm_kr`, recorded on 8.4: the round trip, `LIKE`, interoperation and
>   `gcm.strict` ON and OFF across the rows of one statement, under MTR's check that nothing
>   unexpected reaches the error log.
>
> **Observed, not pinned.** The `UDF_INIT` counts in the third table and the argument-visibility
> rows of the first come from the throwaway probe's counter and are not reproduced by a committed
> test. A committed probe (`tests/probe`, built by `scripts/build-probe.sh`) counts its own `init`
> and `deinit` calls instead, and pins the consequence of the first table — the leaked instance of
> a nested call — in `tests/integration/nested/20`–`22`. The wipe on the error path is pinned; the
> wipe in `deinit` is established by reading `free_state`, since after `deinit` the memory is
> released and there is nothing left for a test to look at.
>
> **A server defect found on the way, not specific to these functions, pinned per major.** A
> **prepared statement whose re-prepare at `EXECUTE` fails** after a loadable function has been fixed
> abandons that function's `UDF_INIT`: its de-initialisation function is never called — not at the
> end of the statement, not on `DEALLOCATE PREPARE`, not when the session ends — and the component
> cannot be uninstalled until the server restarts. Every function the statement had already fixed is
> dropped, whichever component it belongs to.
>
> The trigger is the failed *re-prepare*, not a failure of the statement in general: case `25`'s
> control is the same prepared form with the failing column first, so its re-prepare fails before the
> function is ever fixed — it adds one `init` and its own `deinit`, and nothing is kept. A prepared
> statement is what puts the handler in the (re)prepare state that `udf_handler::cleanup()` returns
> early from; a plain statement's fix failure was not observed to leak. Until #55's cause was read,
> the shape issue #43 was filed with (the table below) was described as needing the nesting and a
> bound parameter.
>
> The cause was read from the 8.0.43, 8.4.11 and 9.4.0 sources and is recorded, with a
> self-contained reproducer, in `docs/upstream-udf-handler-leak.md`: `udf_handler::fix_fields`
> defers its own RAII release as soon as the handler is worth keeping, which leaves
> `udf_handler::cleanup()` as the only way back — and that one returns early while the statement is
> being (re)prepared, because the handler is meant to survive into the execution that a failing
> prepare never reaches.
>
> The first shape found, and the one issue #43 was filed with, is a function that is an argument of
> another and takes a prepared-statement parameter: the outer function's `init` evaluates the inner
> call before the parameter has its value, the inner sees an empty string, and
> `PREPARE … 'SELECT gcm_decrypt(gcm_encrypt(?, ?), ?)'` fails on `EXECUTE` with a 0-byte key (the
> `_kr` form fails with *invalid id*). Nesting, the bound parameter and the raising are all
> **incidental** — what the leak needs is the failed re-prepare — and three cases added after the first
> review show it: a *sibling* function in the same select list, a key-id instance that raises
> nothing at all, and a plain `ALTER TABLE` re-prepare with no nesting and no parameter.
>
> `tests/integration/nested/*.sql` are run by `scripts/verify-nested.sh <major>` on a throwaway
> server — a case that triggers the defect leaves the component unable to uninstall for every case
> after it, so it cannot live in `scripts/verify.sh` — and their expected output is recorded per
> major. Measured on the pinned images (8.0.46, 8.4.11 and 9.4.0). The per-major difference is
> always the same one: on 8.0 the failing statement's *outer* function runs its own `init` — and
> leaks it — where 8.4 and 9 abort before it, so the cases that contain an outer function's `init`
> (`20`, `23`, `24`, `26`) show it in their counts, and the other cases are identical across the
> three:
>
> | Case | Shape | Result |
> |---|---|---|
> | `10_prepared_decrypt_of_encrypt` | `gcm_decrypt(gcm_encrypt(?, ?), ?)`, prepared | the inner sees a 0-byte key; `UNINSTALL COMPONENT` refused afterwards |
> | `11_prepared_decrypt_of_det` | the same, inner deterministic | same |
> | `12_literal_det_bad_key`, `13_literal_encrypt_bad_key` | a literal inner whose key is one byte | inner key error; uninstall succeeds |
> | `14_user_variable` | the inner plaintext in a user variable | round-trips; uninstall succeeds |
> | `15_row_time_column_failure` | the inner key from a column, failing on the second row | row-time error; uninstall succeeds |
> | `16_outer_init_fails` | the outer's own `init` fails over a successful `_kr` inner | argument-count error; uninstall succeeds |
> | `17_kr_reseal_chain` | A15's re-seal shape with `?` in every key-id position | round-trips; uninstall succeeds |
> | `20_probe_nested_bound` | the test-only probe instead of the crypto functions, prepared inner, two `EXECUTE`s | the inner's `init` runs twice with no deinit and the uninstall is refused; on 8.0 the outer leaks too |
> | `21_probe_nested_literal`, `22_probe_direct_bound` | the probe with literals, or a `?` on a direct call | every `init` paired with its `deinit`; uninstall succeeds |
> | `23_sibling_leak` | a sibling function beside one whose inner raises, no nesting | the sibling's `init` has no `deinit`; uninstall refused |
> | `24_nonraising_kr_inner` | a key-id seal that succeeds inside an outer function, another item raising | the seal is never counted and the instance that holds the key is never de-initialised; `UNINSTALL COMPONENT gcm` refused |
> | `25_ddl_reprepare` | `PREPARE … 'SELECT probe_outer(d), c FROM t'`, then `ALTER TABLE … DROP COLUMN c` and a second `EXECUTE` | `probe_outer` reaches two `init`s and one `deinit` — the failed re-prepare kept the handler it had fixed — and the control, the same prepared form with the failing column first, adds one `init` and its own `deinit` |
> | `26_probe_nested_bound_const` | case `20` with the probe's `const_item` variant | the same counts as `20` |
>
> Two consequences are worth separating, because the component can act on only one of them:
>
> - **The leaked instance is held for the life of the server.** Nothing to change in the component:
>   it is the server's, and the fix belongs in `sql/item_func.cc` (the two points are named in
>   `docs/upstream-udf-handler-leak.md`).
> - **The instance may hold secrets.** Amendment A16 gives up the secrets of the instance that
>   *raises* an error; one the server abandons **without** an error keeps what it holds, a key
>   fetched from the keyring included. Case `24` measures the visible half of that (the seal is
>   never counted); whether the component could do more — at the price of the cross-row reuse
>   A11 and A13 exist for — is an open design question, and A16 states the limit rather than
>   implying a guarantee it cannot give.
>
> Operational constraint 18 carries the rule for users.
>
> **Sequencing.** After 0.1.0, as an optional feature of the next minor release. Adding functions is
> backward compatible: no envelope a released build wrote or reads is affected.
>
> **Impact, for the implementation PRs:**
>
> | Area | Change |
> |---|---|
> | `src/` | a keyring-and-caller adapter; the three `_kr` UDFs reusing `udf_glue`'s argument and buffer handling and the unchanged core, with messages of their own (the shared ones carry a key length); the per-instance key copy; three more service requirements in `component.cc`, with `mysql_current_thread_reader` required on every version |
> | `spec/envelope.md` | the argument contract and failure semantics of the three functions. No byte layout and no vector changes |
> | `tests/adapter` | stubs for the new services; every key-source failure injected |
> | `tests/integration`, `mysql-test` | round trip, Korean `LIKE '%길%'`, interoperation with the key-argument functions, account isolation, a definer routine, a bound parameter, an id that varies by row, the floor |
> | `scripts/dev-up.sh`, `scripts/verify.sh`, `scripts/verify-bare.sh` | the test servers load `component_keyring_file` and `keyring_udf`; a second check runs on a server with no keyring |
> | `crypto-safety.md` (key handling, failure semantics, blocked patterns), `architecture.md` §1, §3 and §5 | the widened key-copy rule, the module and lifetime rows, and the one cross-row value keyed on (account, key id) |
> | README, `docs/ops-constraints.md`, `AGENTS.md`, `CHANGELOG.md` | the function table, constraints 2 and 14, what verbose keyring logging records, and the "withdrawn" note of A1 narrowed to `gcm.key_id`, `gcm.nonce_key_id` and `gcm_key_id()` |

> #### The server cause, read from the sources (2026-10-13)
>
> The defect above was diagnosed from the 8.0.43, 8.4.11 and 9.4.0 sources and cross-checked against
> the probe's counts. The full account — the code, the per-major difference and a self-contained
> reproducer — is `docs/upstream-udf-handler-leak.md`, a draft that is not submitted anywhere.
> In one paragraph: the leaked handler is one the statement had already fixed, and the release path,
> `udf_handler::cleanup()`, returns early while the statement is being (re)prepared — by design, so
> that the handler survives into the execution that a failing (re)prepare never reaches. The first
> shape found, and the one issue #43 was filed with, fails while the *outer* function's `init` is
> running: `udf_handler::call_init_func` evaluates a constant argument by calling
> `args[i]->val_str(...)`, and
> for an argument that is itself a loadable function that is the inner function's row callback — with
> the bound parameter still valueless, which is the empty string the inner sees. The inner's
> `udf_handler` was already fixed, and its RAII release was **deferred** (`udf_fun_guard.defer()`,
> because the handler is meant to survive into execution), so from then on only
> `udf_handler::cleanup()` can release it; that one returns early while the statement is being
> (re)prepared, by design, so the execution it was keeping the handler for never arrives and nothing
> releases it. The `usage_count` that `find_udf()` took therefore stays,
> `mysql_udf_registration::udf_unregister` only succeeds at `usage_count == 1` (the idle state of a
> component-registered function), and the component's de-initialisation fails — which is the ER 3538
> `UNINSTALL` error in the table above. The de-initialisation function of the leaked handler is never
> called. 8.0.43 leaks the *outer* function's handler as well as the inner's, because its
> `call_init_func` does not check `thd->is_error()` after evaluating a constant argument where 8.4.11
> and 9.4.0 do; that is why the probe's outer-init count is 2 on 8.0 and 0 on the other two.
>
> This is a source read plus the probe's counts, not a pinned test. No fix was attempted on either
> side of the boundary: the server would have to give the handler back on the abort path, and the
> component's part of the consequence is amendment A16 (a row that raises gives up every secret
> rather than waiting for a `deinit` that does not come).

> ## Amendment A12 (2026-10-07) — Cross-suite nonce-key linkage, and deterministic AES-128: analysis for review
>
> **Status: decisions recorded on 2026-10-07 by Codex (AI design reviewer).** The analysis and
> recommendations below are the proposal author's input; the separate Decision block records the
> review requested in issue #22. This is a scoped AI assessment, not a human cryptographic audit,
> a proof of the construction, or approval of a production deployment. No runtime behaviour changes.
>
> ### Question 1 — the suites share one nonce-key derivation
>
> **What is exposed, exactly.** `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")` for every
> suite. HMAC zero-pads a key shorter than its 64-byte block ([RFC 2104 §2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)),
> so a key `K` and `K ‖ 0ᵐ` are one HMAC key. Where both are suite lengths — 16 and 24, 16 and 32,
> 24 and 32 — they derive the same `nonce_key` and so the same deterministic nonce for a given
> plaintext. `tests/unit/nonce_test.cc` (`CrossSuiteZeroExtension`) pins this for all three pairs:
> the stored nonces are equal and the ciphertext and tag differ.
>
> Consequence: anyone who can read a column sealed under `K` and a column sealed under `K ‖ 0ᵐ` can
> see which rows hold equal plaintexts *across the two columns*. That is the equality leakage the
> deterministic variant already accepts under one key, extended to a second key. It is **not** GCM's
> catastrophic case — the AES keys differ, so this is not nonce reuse under one AES key — and
> it directly reveals equality, not key bytes. Known values or an encryption oracle in one domain
> can identify matching plaintexts in the other; accepting linkage includes accepting that inference.
>
> **When it can occur.** This structural HMAC-key equivalence occurs when one key is a zero-extension
> of the other; accidental HMAC or truncated-nonce collisions remain possible. For one independently
> uniform pair, the relation has probability 2⁻¹⁹² for 16/24 bytes and 2⁻²⁵⁶ for 16/32 or 24/32:
> both the prefix and zero tail must match. The 2⁻⁶⁴ figure is only the probability of an eight-byte
> zero tail, not of an independent pair matching. Truncation — the failure A10's floor guards against —
> does not produce it: truncating a 32-byte key gives its *prefix*, and the prefix's zero-extension is a
> different key unless the dropped bytes were zero. What does produce it is an application that
> fits a short key to a longer suite by padding with zeros — exactly the folding and padding that
> `crypto-safety.md` forbids inside the component, but which the component cannot stop a caller
> from doing before the call.
>
> **Options.**
>
> - **(a) Accept, under a stated key-generation assumption.** Keys for different suites are generated
>   independently; no key is ever derived from another by padding. Document it as an operational
>   constraint. Cost: none in code; relies on every deployment honouring it.
> - **(b) Separate the suites in the derivation.** Make the suite an input — a per-suite label, or the
>   version byte in the HMAC message. Cost: a `spec/envelope.md` version bump and new deterministic
>   version bytes. Not for decryption — an existing envelope stores its nonce and decrypts whatever
>   the label becomes — but because `spec/envelope.md` §7 freezes the derivation label and the version
>   bytes, so a new derivation is a new version, never a redefinition of `0x05` or `0x07`; and because
>   the version byte is how a reader tells which derivation reproduces a value. And deterministic
>   continuity breaks — a value sealed before and after the change no longer compares equal, so every
>   join and `UNIQUE` column under AES-128 or AES-192 has to be re-encrypted on both sides together.
>   `0x03` could keep today's label and lose nothing.
> - **(c) Refuse zero-tailed keys on encryption.** A key whose length is a suite's and whose trailing
>   bytes make it a zero-extension of a shorter suite's key — a 24-byte key ending in eight zero
>   bytes, or a 32-byte key ending in eight or sixteen — is refused by the two encryption functions,
>   with its own error, the way a key below `gcm.min_key_bytes` is. Decryption is unaffected, so data
>   already written stays readable, as with the floor.
>
>   *What it guarantees.* No two keys the policy **accepts from then on** stand in a zero-extension
>   relation, so it removes this structural source of cross-suite linkage between subsequent writes.
>   It does not undo a relation that already exists in stored data: if rows were written under `K32 = K16 ‖ 0¹⁶` before
>   the policy, and `K16` is still accepted afterwards, new writes under `K16` produce the same nonces
>   as those old rows — the equality follows from HMAC's key normalisation (RFC 2104 §2), not from when
>   the row was written. So existing long-key data stays linkable to new short-key writes, not only to
>   other existing data.
>
>   *What it costs a deployment already using such a key.* No envelope byte and no derivation changes,
>   but the deterministic *workload* under that key stops: `WHERE col = gcm_encrypt_det(?, key)`,
>   every new join value and every new `UNIQUE` insert under it become errors. Decryptability is not
>   the same as continuing deterministic operation. Moving off the refused key is a key change, with
>   the migration of every column that has to compare equal (A8). Implementation cost: a few lines in
>   the UDF layer and a constant-time check of at most 16 bytes per row; it refuses keys a CSPRNG
>   produces with probability about 2⁻⁶⁴. The new refusal and its dedicated error are a behaviour
>   contract and go into `spec/envelope.md` in the implementing PR, under §7's rules for a
>   documentation change that adds a failure condition without touching the byte layout.
>
> **Recommendation: (c), with (a)'s assumption written into `docs/ops-constraints.md` as well.** It is
> the only option that stops new zero-extension pairs from forming without trusting every deployment
> or changing the derivation. It is not free for a deployment already using a zero-tailed key (above),
> and it does not unlink data already written under one. Open for the reviewer: whether that residual
> linkage, between existing long-key data and new writes under its short form, is acceptable or calls
> for refusing the short form too when a zero-extended form is known to have been used — which the
> component cannot know, so it would be an operational rule; and whether the check belongs in the UDF
> layer (SQL policy, like the floor) or the core (a key-validity rule).
>
> ### Question 2 — whether `gcm_encrypt_det` should accept a 128-bit key
>
> **What does not depend on key size.** The deterministic nonce is HMAC-SHA256 truncated to 96 bits,
> so the probability that two *distinct* plaintexts under one key get the same nonce — the
> catastrophic case, which can expose GHASH's authentication key and enable forgery under that key — is
> about n²/2⁹⁷ for n distinct plaintexts whatever the suite. §5.2's calculation is unchanged.
> The construction fits neither IV construction of [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
> §8.2 exactly: it is not the deterministic (fixed field + invocation counter) construction and not
> the RBG-based one, so §8's uniqueness requirement holds only probabilistically and §8.3's
> invocation limits do not transfer directly. That is true for AES-256 as much as for AES-128, and
> a usage budget per key is owed in either case (A8).
>
> **What does depend on it.** The margin of the key itself: AES-128 has 128-bit classical strength
> and less margin than AES-256 against multi-target attacks across many keys and against
> long-horizon threats. No practical attack on AES-128 is known and none is claimed. What makes the
> question sharper *for the deterministic variant* is lifetime: deterministic keys back joins and
> `UNIQUE` columns, so rotating one means re-encrypting every column that has to compare equal, at
> once. Deterministic keys therefore tend to live longer and seal more than random-nonce keys, which
> is exactly where a smaller margin matters most.
>
> **Options.** (i) Offer it as today, behind `gcm.min_key_bytes`; (ii) offer it with stated
> conditions; (iii) refuse `gcm_encrypt_det` with a 16-byte key (decryption of existing `0x05`
> unaffected).
>
> **Recommendation: (ii).** Keep it available — interoperability with a peer that mandates AES-128 is
> a real need, and no ground was found that requires removing it — with these conditions recorded in
> the README and `docs/ops-constraints.md`: one fixed AAD convention per key (A8); a per-key usage
> budget summed across every writer, and a retention period, both set by the deployment's security
> review — no number is proposed here, because A8 forbids presenting one as universal; a rotation plan
> that covers re-encrypting both sides of every join; and AES-256 as the recommended suite for any
> deterministic column whose retention is long or open-ended. `gcm.min_key_bytes = 32` stays the
> default; it is an admission policy, not a usage limit, and the conditions above do not depend on it.
>
> ### Decision — scoped review of issue #22
>
> | | Decision | Conditions | Reviewer | Date |
> |---|---|---|---|---|
> | Q1 | **(a): accept the shared derivation under independent key generation.** Do not add (c)'s refusal. | Q1 conditions below; no guarantee of cross-suite domain separation. | Codex (AI design review, separate from the proposal author) | 2026-10-07 |
> | Q2 | **(ii): retain deterministic AES-128 with explicit deployment conditions.** Keep the default floor at 32. | Q2 conditions below; this is availability, not deployment approval. | Codex (AI design review, separate from the proposal author) | 2026-10-07 |
>
> **Q1 rationale and conditions.** Generate full-length keys independently with a CSPRNG for each
> suite and each separate security domain; never pad, truncate or otherwise resize another key.
> Establish this provenance before writing. If related forms have already been used, stop new
> encryption under **both** forms and migrate all dependent JOIN/UNIQUE columns to independent keys;
> preserve old keys only for required reads. Previously exposed linkage, including backups and
> attacker-held copies, cannot be undone. (c) cannot enforce provenance or prevent old-long/new-short
> linkage, yet breaks deterministic lookups and even random writes under a refused key. Those costs
> do not justify it within this threat model. If separation must hold even for caller-selected
> related keys, (a) is insufficient: choose (b) in a new amendment with new versions and a migration.
>
> **Q2 rationale and conditions.** A 128-bit key does not by itself invalidate the construction;
> nor does the 96-bit collision estimate establish its safety. Before enabling AES-128, the operator's
> security review must approve equality/frequency/length leakage and chosen-plaintext lookup exposure,
> and record the following for each key (the nonce conditions apply to every suite):
>
> - One fixed AAD byte string, across all writers. Use an independent key for random encryption and
>   for other protocols; otherwise a separate analysis must include cross-mode nonce collisions.
> - A numerical usage budget and accepted risk, aggregated across servers, columns, queries and
>   applications. Include lookup/oracle calls, message/AAD lengths and forgery attempts. Under the
>   HMAC-as-PRF assumption, `d` distinct plaintext byte strings give collision probability at most
>   `d(d-1)/2^97` in the ideal model; total encryption calls conservatively bound `d`. Identical
>   retries add no distinct value, but deleted rows and restored databases do not erase past usage.
>   This is one risk term, not a universal safe limit or proof of this composed construction.
> - A finite encryption-use period and a separately stated confidentiality/retention horizon,
>   including backups. Prefer AES-256 for long or open-ended retention; it does not remove nonce
>   limits. No deployment-specific number of calls or years is approved by this review.
> - Rotate before the budget or encryption-use period expires; stop writes immediately on suspected
>   compromise, AAD-policy violation, nonce collision, or uncertain usage/RNG history. Restore safe
>   RNG state before generating independent replacement keys. Coordinate every equality-dependent
>   column and lookup at cutover; keep old keys read-only for required history. Rotation cannot
>   restore confidentiality or integrity of copies already exposed under an unsafe key.
>
> **Evidence and limits.** RFC 2104 §2 explains Q1; the six `CrossSuiteZeroExtension` cases reproduce
> it. [SP 800-38D §8 and Appendix B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
> inform nonce and authentication risk; this synthetic IV is not either §8.2 construction, and this
> review claims no NIST conformance. [SP 800-57 Part 1 Rev. 5 §5.3 and §5.6](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
> inform cryptoperiod and key-strength assessment. Unit tests (6,493) and the existing 8.4 integration
> smoke pass; these verify behaviour, not cryptographic security. The full construction, A11's memory
> retention/timing, and production configurations remain outside this review. These choices require
> only the accompanying operational documentation; no new envelope, SQL error or implementation PR.

> ## Amendment A11 (2026-10-07) — Per-statement reuse of the decrypt context and the deterministic nonce key
>
> **Status: implemented and merged (PR #23, 2026-10-07, merged by the repository owner after the
> reviews recorded on that PR).** The two retained states live in `UdfState` (`src/udf_glue.h`),
> implemented in `src/gcm.cc` and `src/nonce.{h,cc}` and driven from the row callbacks in
> `src/udf_*.cc`. Pinned: `tests/unit` (`gcm_test.cc`, `det_session_test.cc`) and `tests/adapter`
> (one state per `init`, and the key checks); `docs/perf.md` carries the CI measurements that replace
> the prototype numbers below, which are kept for the shape of the saving, not its size. Amendment
> A16 later replaced the sentence about a pre-check leaving the schedule intact and rewrote the
> exposure paragraph at the end of this amendment; both now point at A16.
>
> §8 left one item open on purpose: `derive_nonce_key` depends only on the key, `encrypt_det`
> recomputes it on every row, and caching it per `UDF_INIT` means **keeping a copy of the key between
> rows**, which `crypto-safety.md` does not allow without an amendment and a security review. This is
> that amendment, widened to the one other place where the same key is scheduled afresh on every row:
> the EVP context behind `gcm_decrypt`.
>
> **The decision.** A `UDF_INIT` — the lifetime of one UDF item from its `init` to its `deinit`, which
> is **one execution of one statement** and is always driven by one thread — may hold, in its
> per-instance state:
>
> (Confirmed in the 8.0.43, 8.4.11 and 9.4.0 sources rather than assumed: `func_init` runs from
> `udf_handler::fix_fields` and `func_deinit` from `Item_udf_func::cleanup()` at the end of that
> execution; a prepared statement that references a UDF is re-prepared on every `EXECUTE`
> (`Prepared_statement::execute_loop`, `has_udf()`), so the pair never spans two executions. A scalar
> UDF's handler is never copy-constructed — that path exists for aggregate UDFs only, which this
> component does not register — and an `Item` belongs to one statement arena of one `THD`.)
>
> - (a) for `gcm_decrypt`: one `EVP_CIPHER_CTX` whose key schedule is set, together with a copy of the
>   key bytes it was scheduled with (at most 32 bytes) and the suite it belongs to;
> - (b) for `gcm_encrypt_det`: a copy of the key bytes (at most 32 bytes) and the derived 32-byte
>   `nonce_key = HMAC-SHA256(key, label)`.
>
> `gcm_encrypt` (random nonce) gets no cache. Reusing its EVP context is a possible later measurement
> and is not decided here.
>
> **The invariants.** The implementation enforces every one of them and the unit tests pin them:
>
> - The stored key copy is compared with the incoming key by `CRYPTO_memcmp` (constant time). The
>   length and the suite are public and may short-circuit the comparison; the bytes may not.
> - The copy is replaced only when the bytes or the suite differ, and the old copy is
>   `OPENSSL_cleanse`d before it is replaced.
> - On **every** failure of the cipher operation — an OpenSSL error at any step, and `bad_tag` — the
>   copy is cleansed and the context is forgotten. The next row starts from scratch and never trusts a
>   context that has just reported an error. The pre-checks that return *before* the context is
>   consulted — a key length no suite has, a malformed envelope — do not touch it while the call runs
>   (a wrong-length key on one row is that row's SQL error, not a reason to discard a valid schedule
>   *mid-call*), and the call then raises, which gives up the copy, the context, the nonce key and the
>   result buffer at once (amendment A16, above). The nonce-key cache follows the same rule: forgotten
>   on an HMAC failure, and given up by the row that raises.
> - `deinit` cleanses both.
> - When the key is forgotten, the context is reset as well: the key schedule inside the
>   `EVP_CIPHER_CTX` is key-equivalent material and does not outlive the copy it was made from.
> - The state is never shared across threads, and one `UDF_INIT` is driven by one thread.
> - Nothing about the bytes written or accepted changes. `spec/envelope.md`'s byte layout is
>   untouched; its one sentence saying `nonce_key` is derived "per call" is corrected to "when the
>   key changes within one `UDF_INIT`", which §7 allows without a version bump. The existing vector
>   tests, run through the reusing paths, prove the outputs byte-identical.
> - A row that rebuilds the context takes longer than a row that reuses it. What that difference can
>   reveal, and to whom, depends on where the key comes from — see the threat model below.
>
> **Why.** The time is where the per-row setup is, not in the cipher:
>
> - Core: a 16-byte `open` goes from 353 to 170 ns. At that size the per-call `EVP_CIPHER_CTX_new`,
>   the two `Init` calls (the second of which runs the key schedule) and the free *are* the cost.
> - SQL: `gcm_decrypt(col) LIKE` over 100,000 rows on MySQL 9.4. p95 at one session 49.6 → 23.2 ms,
>   at eight sessions 126.4 → 27.2 ms; the ratio to `AES_DECRYPT` 1.06 → 0.48 and 1.27 → 0.26. The
>   eight-session gain (about 1 µs per row) is far larger than the serial bench predicts (about
>   180 ns per row). One hypothesis is contention among threads in OpenSSL 3's per-call context
>   setup; these measurements do not isolate the cause, and the observed gain is what this
>   amendment relies on, not the explanation.
> - Deterministic: one HMAC per row removed, about 0.75 µs per call measured server-side with
>   `BENCHMARK()` on MySQL 8.0 (2.29 → 1.52 µs). It helps only a statement in which one function item
>   is evaluated over many rows — `INSERT … SELECT`, `UPDATE`, a join. A multi-row `INSERT … VALUES`
>   gains nothing, because each expression in it is its own `UDF_INIT`.
> - Two control queries added to the load runner, with one predicate so they count the same rows,
>   put the p95 difference between a scan and a scan that also calls `gcm_decrypt` at 73–85% of the
>   `gcm_decrypt(col) LIKE` query's p95 on the laptop (384–391 ns per row, beside a ~280 ns bare
>   open). These are differences between queries, not component timings; they say the decrypting
>   call is most of the query, not exactly where inside it the time goes.
>
> **Exposure, stated honestly.** What changes is the *retention* of key material. Before A11 a key
> copy and its derived material lived for one operation, one row. After it, the **last key used**
> by a UDF item — its copy, its schedule in the context, and for the deterministic variant its
> `nonce_key` — lives until a row reaches the cipher with a different key or suite, a cipher
> operation fails, or the item's `deinit` at the end of the execution. Two kinds of row leave the
> previous key in place without using the cipher: a NULL argument, and a legacy `0x01` envelope that
> opens (one that fails raises, and a row that raises gives the whole state up — amendment A16,
> above). Every other row that does not reach the cipher for real raises — an over-long argument, a
> malformed envelope, a key length no suite has — and a row that raises gives the whole state up
> (A16, above). Inside the execution the bound is unchanged — the next row, or the row that raises,
> ends the retention — but an instance the *server* abandons without calling `deinit` **and without
> an error** does not end at all: it keeps what it holds, this copy included, for the life of the
> server. That is the defect of issue #43, pinned by
> `tests/integration/nested/24_nonraising_kr_inner`, and neither A11
> nor A16 can close it from inside a row callback. How much the retention adds depends on where the
> key comes from, and the two cases are not the same:
>
> - **A key the caller supplies as a constant for the statement** — a literal, a user variable, a
>   bound parameter. This is the usage the README documents. The server already holds that key for
>   the whole execution, in the argument buffer and in the statement text that §6 lists as reaching
>   the general and slow logs, and the caller already knows it. A11 adds a second in-memory
>   location for the same duration; a core dump taken mid-statement contains the key either way.
> - **A key computed per row** — read from a column, derived by an expression, or supplied by a
>   view or a stored routine running with definer rights, where the caller may not be allowed to
>   learn it. Here the server holds each row's key only while that row is evaluated, and A11 keeps
>   the most recent one past its row, up to the end of the execution. That is an added retention
>   of up to one key per UDF item per execution, which this amendment accepts — it is bounded by
>   the statement, cleansed on every exit, and never shared — and names rather than hides.
>
> **Timing.** A row whose key matches the previous row's is faster than one that rebuilds the
> context (on the measured hardware ~120 ns against ~300 ns at the core). In the first case above
> the caller chose every key, so the difference tells them nothing. In the second, it is in
> principle a signal of *whether consecutive rows used the same key* — never key bytes — to someone
> who can time row evaluation. A client does not see only the statement's total duration: a
> streaming result (`mysql_use_result`) delivers rows as they are produced,
> so the arrival time of each row is observable, and with it, in principle, a per-row difference.
> How precisely depends on the execution plan, on buffering in the server and the network, and on
> the driver; a filter that returns few rows, or a sort or aggregate, hides most of it. No attack
> that distinguishes the hit and miss times has been demonstrated, and none is claimed. The threat
> model A11 accepts is therefore: **an attacker who can already submit statements and observe their
> results as they arrive may learn whether consecutive evaluated rows used the same key, not what
> any key is.** That includes rows the attacker chooses to place next to each other: with `WHERE`
> and `ORDER BY` over a view whose key differs per row, a caller decides which two rows are
> evaluated consecutively, and a per-row clock such as `SYSDATE(6)` in the select list, or row
> arrival times, gives a per-row duration to average over repeated queries. So the signal is not
> only "how often keys change" but, in principle, **whether two rows the attacker picks share a
> key**. This is a hypothesis about what could be measured, not a measured result. A deployment where even that matters — definer-rights
> routines that pick keys per row for callers who must not learn their grouping — should not rely on
> this amendment's acceptance and should keep such keys out of per-row expressions. The risks this
> amendment also names:
>
> - The copy lives through the whole execution, including the idle time between the rows the
>   function is evaluated on, not only while an operation is in flight.
> - A server crash skips `deinit`, so the copy is never cleansed. Neither is the server's own
>   argument buffer.
> - A bug that reused the state across threads would be a correctness bug and a secrecy bug at once.
>   The single-threaded `UDF_INIT` model is the assumption this rests on, and this PR's adapter tests
>   pin that one state is created per `init`.
>
> Precedent: the `UDF_INIT` state already holds the `gcm.strict` and `gcm.min_key_bytes` snapshots
> for exactly this lifetime (A5, A10). What is new is that the retained state is secret.
>
> **Rejected.** A cache that outlives a `UDF_INIT` or lives in a global — its lifetime is unbounded
> and it would need locking on the row path. And a cache keyed on anything other than the full key
> bytes: not a hash of the key, not its length, not the address of the argument buffer.
>
> **Impact:**
>
> | Area | Change |
> |---|---|
> | `.agents/rules/architecture.md` §3, §5 | The `UDF_INIT` row gains the two retained states; the operation row keeps the EVP *operation* and the transient secrets; cross-row reuse is confined to this amendment |
> | `.agents/rules/crypto-safety.md` | The key-copy rule gains this one exception, with its invariants; a copy that outlives its `UDF_INIT`, or a cache keyed on anything but the full key bytes, is a blocked pattern |
> | `src/gcm.{h,cc}`, `src/nonce.{h,cc}`, `src/udf_*.cc` | The reusing decrypt path and the cached nonce-key path, hung off the `UDF_INIT` state |
> | `tests/unit`, `tests/adapter` | The invariants above; the vectors through the reusing paths; one state per `init` |
> | `docs/perf.md` | The CI measurements that replace the prototype numbers quoted here |

> ## Amendment A10 (2026-10-06) — AES-128-GCM and AES-192-GCM
>
> **Status: implemented in full.** All three suites ship — `0x02`/`0x03` (AES-256), `0x06`/`0x07`
> (AES-192) and `0x04`/`0x05` (AES-128) — with `gcm.min_key_bytes` defaulting to 32, so anything below
> AES-256 stays opt-in. `spec/envelope.md` is at v3. The NIST CAVP KAT is imported for every suite:
> 2,250 cases, 750 per suite, of which 191 / 190 / 196 are authentication failures.
>
> Adding AES-192 tested this amendment's own claim that a suite is "one row in the table plus one
> `EVP_CIPHER_fetch`". It held: four files, seventeen lines. Everything else — parsing, the version
> and key-length agreement check, the nonce derivation, the error message, the floor — was already
> driven from the table. What was *not* free was the test and document surface, where a dozen places
> asserted that AES-192 was unimplemented and each had to be flipped deliberately.
>
> **Decided here, and why, since shipping `0x05` means deciding them:**
>
> - **`gcm_encrypt_det` is offered for AES-128.** The deterministic nonce is HMAC-SHA256 truncated to
>   96 bits regardless of suite, so the §5.2 collision bound does not move with key size, and the
>   construction's exposure — equality, frequency, length — is the same one AES-256 already has. What
>   a 128-bit key changes is the cipher's own margin, which is a key-strength decision the operator
>   makes by choosing the key length, not one this component should make for them by withholding a
>   variant. Withholding it would also be incoherent: `gcm_encrypt` at 128 bits would still be
>   available, and a deployment that wanted determinism would be pushed to a *worse* answer, such as
>   a hash column.
> - **The suites share one derivation label, and that is accepted rather than changed.** An earlier
>   draft justified this by saying per-suite labels would make `0x03` and `0x05` incomparable; that is
>   wrong and is withdrawn. They already differ from the version byte onward and never compare equal —
>   `tests/adapter` and the MTR case both assert it — and giving only the *new* `0x05` its own label
>   would leave every existing `0x03` envelope reproducible.
>
>   The actual reason is narrower. The label exists to separate the encryption key from the HMAC key,
>   which it does for every suite, and `crypto-safety.md` requires it to be **one constant in one
>   place**. A second label means a label-per-suite mapping in exactly the file that rule says must not
>   grow one, bought for a separation nothing has yet shown a need for: the suites are already
>   separated by having different keys, with the single documented exception that a short key and its
>   zero-extension derive the same nonce key (RFC 2104 §2). That exception is not itself an attack —
>   the two AES keys differ, and GCM's catastrophic case is one nonce under one key — and it is
>   recorded in `spec/envelope.md` §2.5 as something implementations must not rely on.
>
>   If the security review finds a need, a per-suite label costs **no existing `0x03` data** — that is
>   the scope of the claim, and it narrows the moment `0x05` ships. From then on, changing the label
>   breaks the deterministic reproducibility of `0x05` data exactly as it would for `0x03`: the same
>   plaintext stops reproducing the stored envelope, so joins, UNIQUE and exact match on those columns
>   stop matching. It would need its own version bytes and a migration, which is the general rule in
>   `spec/envelope.md` §7 and not a special case. The window in which this is cheap is before `0x05`
>   is in anyone's data, which is now.
>
> **Still open, for the security review this amendment asks for:** whether the shared label should
> become per-suite in a future spec version, and the four `gcm.min_key_bytes` contract points — of
> which three are answered by the implementation (encryption only, GLOBAL-only, fail closed to 32)
> and the fourth, the violation error, is a message distinct from `bad_key_len`. The review is to
> confirm those choices, not to discover them.
>
> §2 and amendment A1 fix the suite at AES-256-GCM: `EVP_CIPHER_fetch("AES-256-GCM")` is the only
> cipher fetched for sealing, and the key is exactly 32 bytes, checked on every call. This amendment
> adds **AES-128-GCM and AES-192-GCM alongside it**. AES-256-GCM stays the default and the
> recommendation; the smaller key sizes exist for interoperability and compliance, not for speed.
>
> **The performance gain has not been measured.** AES-128 runs fewer rounds than AES-256, so the cipher
> itself is cheaper, but this project has no number for how much of that survives at the SQL level and
> should not quote one. The load results in `docs/perf.md` compare GCM against the CBC builtin and say
> nothing about AES-128 against AES-256. Nor does a ratio near 0.9 between two ciphers establish how
> much of the query the cipher accounts for: two ciphers of similar cost give the same ratio whether
> that cost is large or small, so the row scan may or may not dominate and these numbers do not say
> which.
>
> The measurement splits in two, and neither half answers the other's question. **`tests/bench` measures
> the core difference between the suites** — it runs without a server, so it cannot speak to SQL at all.
> **A load scenario measures the end-to-end SQL difference.** Both should exist before any performance
> claim is made for the smaller suites.
>
> **The suite is selected by key length, and by nothing else.** 16 bytes → AES-128-GCM, 24 → AES-192,
> 32 → AES-256. No new function argument, no new sysvar, no change to the call shape.
>
> That is the central decision, and the trade-off it takes has to be stated precisely.
>
> An explicit selector — `gcm_encrypt(plaintext, key, suite)` — would **not** create a cross-call
> consistency obligation of the kind A8 has to impose on AAD. The AES key lengths are fixed by
> [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), so the component would reject any (suite, key
> length) pair that disagrees — AES-128 with a 32-byte key is an immediate error, with no folding and no
> truncation. There is exactly one valid key length per suite, so one key could not be used at two
> strengths, and no new rule would land on the operator.
>
> What length inference actually buys is API simplicity: the call shape does not change, and there is no
> fourth argument for an application to get wrong. What it gives up is the **cross-check** — the chance
> to compare the suite the caller intended against the key that actually arrived. "I meant AES-256 and
> my key was truncated to 16 bytes" is a disagreement between intent and key, and a selector turns it
> into an error; length inference has no stated intent to compare against. That is the same problem as
> the cost section below, seen from the other side, and the two are to be read together.
>
> Length inference is still the choice here, on the condition that the truncation guard is kept rather
> than dropped: `gcm.min_key_bytes`, defaulting to 32, preserves that guard for a deployment that leaves
> the default alone. It is **not** equivalent to what a selector would give. A minimum-length policy is a
> server-wide floor, not per-call verification of what a caller intended, and a mixed deployment that has
> to lower the floor to accommodate one application loses the guard for all of them — see the contract
> points below. If the mitigation is not adopted at all, this decision should be revisited in favour of
> the selector rather than shipped without either.
>
> **Envelope: four new version bytes.** `spec/envelope.md` §7 freezes the existing bytes — a new format
> is a new version byte, never a redefinition — so `0x02` and `0x03` keep meaning exactly AES-256-GCM.
>
> ```
> 0x02  AES-256-GCM random          (unchanged)
> 0x03  AES-256-GCM deterministic   (unchanged)
> 0x04  AES-128-GCM random
> 0x05  AES-128-GCM deterministic
> 0x06  AES-192-GCM random
> 0x07  AES-192-GCM deterministic
> ```
>
> The layout of each is identical to `0x02`/`0x03` — `version(1) || nonce(12) || ciphertext || tag(16)`,
> so plaintext + 29 bytes. Only the version byte and the key length differ. The even/odd split of
> random/deterministic that `0x02`/`0x03` started continues, which is a readability property and not
> something an implementation may rely on: the mapping is a table, not arithmetic.
>
> Recording the suite in the envelope is not strictly necessary — the key the caller supplies at
> decryption already determines it — but the envelope stays **self-describing**, which is the same
> choice A2 made when it stored the deterministic nonce rather than recomputing it. Migration, audit
> and key-rotation tooling can tell what produced a row without holding the key.
>
> **The version byte determines the expected key length, and a mismatch is `bad_key_len`.** Decrypting
> a `0x02` envelope with a 16-byte key is an error naming the mismatch, not a tag failure. What it buys
> is exactly one distinction: **the key length the envelope requires disagrees with the key length
> supplied**, told apart from a failed tag. Without it the same situation reports `bad_tag` and points an
> operator at data corruption. It is not a truncation detector — the cost section below gives the case
> where a truncated key goes unnoticed, and a corrupted version byte raises this same error.
>
> **What does not change:**
>
> - The deterministic nonce derivation and its label.
>   `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")` stays byte for byte, for every key length,
>   and the label is frozen by `spec/envelope.md` §7.
>
>   Changing it would **not** break decryption of existing data. A2 stores the nonce in the envelope
>   precisely so decryption never recomputes it. What it would break is that re-encrypting the same
>   input stops reproducing the existing ciphertext — which is the entire value of the deterministic
>   variant, so what is at stake is JOIN, UNIQUE and exact-match continuity. Keep the label; the reason
>   is continuity, not decryptability.
>
>   HMAC-SHA256 accepts a key of any length, so no new derivation is mechanically required. It does
>   **not** follow that different key lengths are separated from one another.
>   [RFC 2104 §2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2) zero-pads a key shorter than
>   the 64-byte block, so a 16-byte key `K` and the 32-byte key `K ‖ 0¹⁶` derive the **identical** nonce
>   key, and therefore the identical nonce for the same plaintext. Verified rather than assumed. That
>   pair is not itself a GCM nonce reuse — the two AES keys differ, and GCM's catastrophic case is one
>   nonce under one key — but "different lengths separate the domains" is not an argument that is
>   available, and whether the new suites need explicit domain separation belongs to the security review
>   below rather than to this amendment.
> - The tag length (16) and the nonce length (12), for all three suites.
> - The strict semantics, the failure codes, and the AAD rules.
> - The legacy `0x01` CBC path, which stays AES-256-CBC and decrypt-only (see the open question below).
> - Deterministic JOIN and UNIQUE behaviour. Ciphertext is comparable only under the same key, and a key
>   has exactly one length, so the existing "same key, same AAD" requirement already covers it. No new
>   operational rule follows from this amendment.
>
> **The cost, stated plainly.** Today `key.size != 32` is an error, which means a key that was truncated
> in transit — by a client bug, a bad environment variable, a mis-sliced buffer — fails loudly. After
> this amendment, a 32-byte key truncated to 16 is a *valid AES-128 key*, and `gcm_encrypt` will seal
> with it and report success. The data is encrypted at a lower strength than intended and nothing says
> so.
>
> **Nor is it reliably caught later.** Decryption only reveals it when someone reads with the key that
> was intended: a writer and a reader both using the same truncated 16-byte key agree with the `0x04`
> envelope and both keep succeeding indefinitely. The mismatch surfaces the first time the original
> 32-byte key is used against that row, which may be a backup restore, a migration, or never.
>
> The `bad_key_len` distinction above is still worth having, but read it for what it is: a statement
> that the envelope and the supplied key disagree about length. It is not evidence that a key was
> truncated — a corrupted version byte produces the same signal.
>
> This is the real price of the feature and it cannot be designed away while the key length is the
> selector. Two mitigations are possible and the choice between them is **not settled here**:
>
> 1. A sysvar — `gcm.min_key_bytes` (default 32, settable to 24 or 16) — so a deployment that does not
>    intend to use the smaller suites refuses them at the server. This keeps the current behaviour as
>    the default: an installation that does nothing sees no change, and a truncated key still fails
>    loudly. The cost is one more sysvar and the 8.0/8.4 GLOBAL-only scope problem of amendment A5.
>
>    Adopting it means settling its contract first, and these are not implementation details:
>
>    - **It applies to new encryption, not to decryption of existing data.** Otherwise raising the
>      policy from 16 to 32 locks out exactly the rows that have to be read in order to be re-encrypted.
>    - **Administrator policy, or a mistake guard?** If a session can lower it at will it is the latter
>      and must not be described as the former. A5 already constrains the answer, since the variable is
>      GLOBAL-only on 8.0 and 8.4.
>    - **On a GLOBAL-only server, lowering it for one application removes the guard for every
>      application on that server.** The default protects an existing deployment; it cannot express a
>      mixed deployment's intent.
>    - **The error raised on a policy violation, and the behaviour when the setting cannot be read**,
>      both have to be decided. Fail closed is the established pattern for the second (A5).
> 2. Nothing in the component, with the expectation documented as an operational constraint.
>
> Option 1 is the recommendation, precisely because it makes this amendment **opt-in** rather than a
> silent weakening of an existing deployment's guarantees. It needs a security review before it is
> settled, as amendment A8 requires for anything touching key policy.
>
> **Out of scope, deliberately:** the legacy `0x01` CBC envelope stays AES-256-CBC. A deployment
> currently running `block_encryption_mode = 'aes-128-cbc'` therefore still cannot dual-read its data,
> which is a real gap and a separate question — it concerns reading existing `AES_ENCRYPT` output, not
> producing GCM. If it is wanted it needs its own amendment and its own version bytes, and it should be
> decided on migration evidence rather than bundled here.
>
> **Sequencing.** Planned to land after 0.1.0 was tagged, as 0.2.0. *Revised 2026-10-10:* 0.1.0 had
> not been tagged when this amendment, A11 and A12 were implemented, and the commit prepared for it
> carries two component defects fixed since — the unsynchronised `gcm.strict` read on 8.0 and 8.4,
> and an init rollback that freed cipher handles it might not own. Tagging that commit would publish
> known defects, so 0.1.0 is cut from the later state and includes `0x04`–`0x07`. Nothing had been
> published, so no released component rejects these version bytes. Adding them stays backward
> compatible: every `0x02`/`0x03` envelope decodes unchanged, and an older build would reject
> `0x04`–`0x07` with `bad_envelope` as `spec/envelope.md` §2.4 requires.
>
> **Impact, for the implementation PRs:**
>
> | Area | Change |
> |---|---|
> | `spec/envelope.md` | v2: the four new version bytes, the key-length-per-version table, the `bad_key_len` rule on mismatch |
> | `spec/test-vectors.json` | NIST CAVP KAT for AES-128-GCM and AES-192-GCM at IVlen 96 / Taglen 128, plus project vectors for the new version bytes |
> | `src/gcm.{h,cc}` | fetch three ciphers in `crypto_init`, select by key length, release all three in `crypto_deinit` |
> | `src/envelope.{h,cc}` | the new version constants and their key lengths; parsing is otherwise unchanged |
> | `src/udf_glue.cc` | accept {16, 24, 32}; the error message currently names 32 |
> | `src/nonce.cc` | the key length check; the derivation itself is unchanged |
> | `src/sysvar.{h,cc}` | `gcm.min_key_bytes`, if mitigation 1 is adopted |
> | `tests/unit` | KAT for all three suites; key lengths 0, 15, 17, 23, 25, 31, 33; version/key mismatch |
> | `tests/adapter` | `crypto_init` partial-fetch failure now has three handles to roll back |
> | `tests/integration`, `mysql-test` | round trip and Korean LIKE per suite; the mismatch error |
> | `tests/bench` | the three suites against their own bare-EVP references |
> | README, `docs/ops-constraints.md` | the truncated-key exposure, and which suite each version byte is |
>
> **Open questions this amendment does not answer:**
>
> - Mitigation 1 or 2 (above), pending security review — and, if 1, the four contract points listed with
>   it.
> - **Whether the new suites need explicit domain separation in the nonce derivation.** The label is
>   shared across all three, and the zero-padding property above means a short key and its zero-extension
>   derive the same nonce key. No attack follows from that pair on its own, but the question belongs to
>   the same security review rather than to an implementation PR. *Decided conditionally in A12 Q1 (scoped AI review of issue #22).*
> - Whether `gcm_encrypt_det` should be offered at all for AES-128. The deterministic nonce is
>   HMAC-SHA256 truncated to 96 bits regardless of suite, so the collision bound in §5.2 is unchanged by
>   key size — but the argument for using a 128-bit key in a construction whose whole point is long-term
>   stored ciphertext deserves to be made explicitly rather than inherited. *Decided conditionally in A12 Q2 (scoped AI review of issue #22).*
> - Whether to expose the suite in SQL at all, for example a `gcm_envelope_version(ciphertext)` helper.
>   That is a new public function and belongs to its own amendment.

> ## Amendment A9 (2026-10-02, settled) — registrations that survive a failed install, and registration order
>
> When `gcm_component_init()` returns 1 during `INSTALL COMPONENT`, the loader rolls back and its scope
> guard calls the scheme's `unload`, which performs a **`dlclose()`**. `RTLD_NODELETE` is passed to
> `dlopen` **only in ASan/LSan builds** (`components/libminchassis/dynamic_loader_scheme_file.cc`,
> confirmed in the 8.4.11 tree).
>
> So any registration whose release was refused during the rollback points into an **unmapped
> segment**.
>
> - A UDF whose release was refused: `udf_unregister` leaves a function that is in use in `udf_hash`
>   **under its real name** (`sql_udf.cc`). So not only a session that already resolved it, but **a new
>   session calling that name**, jumps into unmapped code. It does require knowing the name and calling
>   it.
> - A sysvar whose release was refused: the dictionary holds `&g_strict` in unmapped memory, and it is
>   reachable **by enumeration alone** — `SHOW VARIABLES`, `performance_schema.global_variables`. Nobody
>   has to name it.
>
> The asymmetry that matters, then, is not "was it already resolved" but **naming versus
> enumeration**. The variable is far easier to reach.
>
> Decisions:
>
> - **This cannot be fixed through the component API.** No service asks the loader to keep the library
>   mapped, and there is no way to refuse the unload from `init`. Do not write that it was solved in
>   code.
> - **Reduce the exposure with registration order.** `gcm.strict` is registered **after** all three
>   UDFs. Then at the rollback point of the failure that can actually happen — `udf_register` failing
>   partway — the variable does not exist yet, which makes the second case above **structurally
>   impossible**. The remaining exposure is `sysvar_register()` itself failing, and that rolls back only
>   the UDFs.
> - The cost is a **short window** where the functions exist and the variable does not. A call landing
>   in that window reads an unregistered variable, the service fails, and `strict_enabled()` returns
>   `true` — strict **ON**, the fail-closed direction. The window is inside `INSTALL COMPONENT`.
> - **Do not release the crypto handles when a release was refused.** This does not prevent the crash
>   above. The point is to avoid adding a second defect to a broken install, and to take the same
>   position as `gcm_component_deinit`, where a refused `UNINSTALL` leaves the component loaded and the
>   same reasoning **actually** holds.
> - **An ASan build makes this conclusion look backwards**, because `RTLD_NODELETE` applies in exactly
>   that case. "Confirming" this question under a sanitizer gives the wrong answer. That is why
>   sanitizers are off by default in `tests/adapter`.
> - **deinit is not the mirror of init.** init registers the variable last, and deinit *also* releases
>   it last (so not LIFO). That is deliberate: deinit has to be able to **refuse and put things back**
>   when a function is in use, and releasing the variable first would leave the component with no
>   variable at the point of refusal. Handling the functions first means the refusal happens before
>   anything touches the variable. Do not "fix" this into symmetry. The order is pinned by
>   `GivenAFunctionStillInUse_WhenDeinit_ThenTheVariableIsStillRegistered` and
>   `GivenEverythingUnregisters_WhenDeinit_ThenTheVariableGoesLast`. The latter asserts the **whole call
>   sequence** — an assertion that only checks which calls happened cannot see two of them swapped, and
>   that mutation did in fact pass an earlier version of this file.
> - The registration order and the rollback branches are pinned by `tests/adapter/lifecycle_test.cc`
>   against stub services. Confirmed by mutation testing: reversing the order, releasing resources
>   unconditionally, making `strict_enabled()` fail open, reverting to an unlocked direct read of
>   `g_strict`, removing `mac_deinit()` or the CBC release, and removing deinit's `was_present` guard —
>   the suite fails on all seven.

> ## Amendment A8 — operational responsibility for keys and nonces, and the limits of the security claim
>
> The component takes the key as a SQL argument and performs nonce generation and authentication
> checks, but it does **not** implement per-key usage accounting, automatic key rotation, nonce
> duplicate detection or AAD policy enforcement. Before deployment, the operator has to decide how to
> sum the encryption usage of every server, column and application that shares a key, set a usage limit
> and rotation criteria, and have that security-reviewed. Consider the collision analysis of the random
> and deterministic modes together with message lengths and forgery attempts. This project has not
> established a per-key usage figure that is safe for every deployment.
> Reference: [NIST SP 800-38D §8 and appendices A/B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
>
> The AAD for deterministic encryption must be the same byte string — or always empty — across
> **every deterministic call that uses a given key**, not per column. Separate keys for separate AAD
> domains. Columns joined on ciphertext equality must share key and AAD, and because equality between
> old and new ciphertext does not survive a key rotation, design the migration alongside it.
>
> Copying, duplicating or restoring an envelope that already exists is not a new encryption call.
> Calling `gcm_encrypt` again encrypts under a new nonce; calling the deterministic variant again
> reproduces the existing result when key, plaintext and AAD are all the same. Do not change only the
> AAD on a retry. A backup restore does not roll back the key usage ledger. If after a restore or a
> process clone you cannot be confident about the RNG state or the accumulated usage, stop new writes
> under that key. Recover and verify the RNG state of every writer, then resume with a new key
> generated independently and safely. Rotating a key does not by itself resolve a duplicated RNG state.
> Keys needed to decrypt historical data and backups are retained by an external key management
> procedure.
>
> Passing the test vectors and a sample nonce collision test prove neither compliance with an
> operational limit nor the safety of the deterministic construction. The security guard hook only
> restricts development commands; it does not monitor crypto usage in production. This amendment states
> operational premises and changes nothing about the SQL API, the envelope, the nonce derivation or the
> vectors.

> ## Amendment A8 (2026-09-28) — deployment topology: ROW replication and sharding
>
> The function surface and the envelope stay as they are; this records **how this component is deployed
> in a replicated or sharded configuration**. The conclusion first: a primary plus a ROW replica per
> shard fits this design naturally. There are conditions to meet, and operations rather than code meets
> them.
>
> **Replication — the encryption result is carried as-is**
>
> - Under `binlog_format=ROW`, the ciphertext, nonce and tag the primary stored are replicated
>   verbatim; the replica does not re-run the encryption. STATEMENT format makes the two sides diverge
>   because of the random nonce, so ROW is mandatory (§6 item 1). Reference:
>   <https://dev.mysql.com/doc/refman/8.4/en/replication-formats.html>
>   Measured: `tests/e2e/scenarios/replica_consistency.py` and
>   `mysql-test/suite/gcm/t/gcm_replication.test` confirm byte equality on both sides, decryption on
>   the replica, and Korean `LIKE` on the replica (passing on 8.4 and 9.4).
> - **Installing the component is not replicated.** `INSTALL COMPONENT` is recorded only in that
>   server's `mysql.component`. It has to be installed **on each** server that serves decryption
>   queries and each server that may be promoted to primary, and the application has to be able to
>   deliver the key to those servers too. Reference:
>   <https://dev.mysql.com/doc/refman/8.4/en/component-loading.html>
>   This is why the MTR replication test sources `gcm_install.inc` on both the primary and the replica.
>
> **Sharding — routing and key policy are what matter**
>
> | Item | The principle to apply |
> |---|---|
> | Shard selection | Route on a stable identifier such as `tenant_id`. Random-nonce ciphertext (`0x02`) differs on every call even for the same plaintext, so it cannot be a routing key. Deterministic ciphertext (`0x03`) is stable, but using it as the shard key turns key rotation into a resharding job |
> | Moving data between shards | Existing ciphertext can be moved **as-is** (no re-encryption). The destination must also decrypt with the original key and AAD |
> | Comparing deterministic ciphertext | Getting the same ciphertext across shards requires the same key, plaintext *and* AAD. The "one AAD per key" rule from §6 applies across shard boundaries — a different AAD per shard turns the same plaintext into different envelopes and breaks cross-shard comparison |
> | Key usage | When several shards share a key, the volume of **new encryption calls has to be summed across all of them**. Moving existing ciphertext is not a new encryption. The deterministic variant's nonce collision bound (§5.2) is reasoned about on that sum as well |
> | Partial-match search | `gcm_decrypt(...) LIKE '%길%'` alone cannot select a shard. Without a routing predicate, several shards are queried and each decrypts its own candidate rows — the cost scales with the number of shards |
>
> **Out of scope**: whether a particular sharding middleware (a proxy or router) forwards
> loadable-function calls verbatim and preserves the result charset **has to be verified with that
> combination.** This repository verifies only self-managed MySQL servers (§0 scope). The proxy approach
> is already out of scope per §0.

> ## Amendment A7 (2026-09-28, settled) — do not pass a computed SQL expression as an argument (an 8.0/8.4 server defect)
>
> When a **computed string expression** is passed as an argument to a loadable function, MySQL 8.0 and
> 8.4 hand over a stale view of that argument **from the second row of a statement onwards**. The same
> expression passed to a builtin always produces the correct value, and the same corruption is observed
> with the component replaced by a build that merely echoes its argument back — meaning it can neither
> be detected nor repaired from inside the component. It does not reproduce on 9.4.0.
>
> Measured (`tests/integration/91_server_udf_arg_defect.sql` pins it per version):
>
> | Argument expression | 8.0.43 | 8.4.11 | 9.4.0 |
> |---|---|---|---|
> | `CONCAT(col, int_col)` · `CONCAT_WS(...)` · a `LOWER(...)` wrapping either | correct | **byte 0 corrupted** | correct |
> | `REPEAT('a', int_col)` | **length inflated** | correct | correct |
> | `CAST(<computed> AS CHAR)` | correct | **corrupted at 16 bytes** | correct |
> | a column · a literal · a user variable · a bind parameter | correct | correct | correct |
>
> The origin is `udf_handler::get_and_convert_string` in `sql/item_func.cc`. It takes the `String` the
> argument Item returned, copies it **shallowly** (`buffers[index] = *res`) and then calls
> `c_ptr_safe()`; if that Item points into a nested Item's buffer, the pointer and length go stale. That
> 8.4's corruption appears at a 16-byte boundary matches `String`'s reallocation boundary.
>
> Decisions:
>
> - **Do not attempt a workaround in code.** Asking the server to perform a conversion by requesting a
>   different collation (`argument_set(args, "collation", 0, "utf8mb4_bin")`) makes 8.4's `CONCAT`
>   corruption disappear, but inflates `REPEAT`'s **length**, which is worse (more bytes get sealed).
>   Confirmed by measurement. So `udf_encrypt.cc` requests only the charset the contract requires
>   (`utf8mb4`).
> - **Document it as an operational constraint** (§6, `docs/ops-constraints.md` item 10, the README).
>   The call shapes that are safe on every version are a column, a literal, a user variable and a bind
>   parameter — that is, **materialised values**. The normal path, an application sending bind
>   parameters through its driver, is unaffected.
> - If a value has to be computed in SQL, write it to a **real table** first
>   (`CREATE TEMPORARY TABLE ... AS SELECT`, or a separate statement) and then call with the stored
>   column. **A derived table does not work**: under the default `derived_merge=on` the optimizer merges
>   the derived table's expression into the outer query, so it ends up computed per row after all.
>   Measured on 8.4.11 — `FROM (SELECT CONCAT(nm,id) AS v FROM t) d` corrupts rows 2 and 3, while the
>   same query with `/*+ NO_MERGE(d) */` or `derived_merge=off` is correct. Those two work because they
>   force materialisation, but they are optimizer hints that a future version may ignore. A real table
>   is not. `CAST` alone is not enough either (8.4, at 16 bytes).
> - `gcm_decrypt`'s envelope argument is in the same class, but there the failure surfaces as a
>   `bad_tag` or `bad_envelope` error rather than silent data corruption. `gcm_encrypt*` is the
>   dangerous side.
> - When the server is fixed, case 91's expectation flips from 0 to 1 and CI surfaces it. That is when
>   this amendment and the constraint are lifted.

> ## Amendment A6 — module boundaries and resource lifetimes
>
> The distribution scope (A4) and the SQL and envelope contracts stay as they are; this records the
> implementation's boundaries in `.agents/rules/architecture.md`. The server adapters call the core, but
> the core (`gcm`, `envelope`, `nonce`) does not depend on MySQL services, configuration or SQL errors.
> SQL NULL, charset and the strict error translation belong to the UDF layer, the byte format to
> envelope, the authentication result to gcm, and server version differences to the component and
> sysvar layers.
>
> Resources are divided into component, `UDF_INIT` and operation lifetimes. `UDF_INIT` is not the same
> as a whole session. (Amendment A11 adds two secret-bearing resources to the `UDF_INIT` lifetime —
> `gcm_decrypt`'s scheduled EVP context and `gcm_encrypt_det`'s derived nonce key, each with its key
> copy — under invariants stated there.) A failed registration rolls back; a failed release keeps the resources that are in
> use and tracks state so that nothing already released is released twice. Do not repeat configuration
> lookups, algorithm fetches or file and network access on the row-processing path. The fixed-nonce test
> entry point is not exposed in SQL, and experimental code that bypasses encryption is excluded from
> what ships. Keep the existing file layout and do not add a general backend layer.
>
> Implementations consulted: the server/crypto wrapper separation and registration state tracking in
> [Percona's Encryption UDF](https://github.com/percona/percona-server/blob/8.4/components/encryption_udf/encryption_udf_component.cc),
> the operation/backend boundary in
> [MySQL keyring operations](https://dev.mysql.com/doc/dev/mysql-server/8.4.9/operations_8h_source.html),
> and the SQL argument, result and error translation in
> [pgcrypto's SQL entry points](https://github.com/postgres/postgres/blob/REL_17_STABLE/contrib/pgcrypto/pgcrypto.c).
> These are design references, not grounds for adopting another project's API, exception policy or
> features.

> ## Amendment A5 (2026-09-28, settled) — the SESSION scope of `gcm.strict` exists only on MySQL 9.0+
>
> Amendment A1 put `gcm.strict` at GLOBAL + SESSION. Measurement against the server sources shows that
> **the session scope for a component sysvar is implemented only from 9.0.0**. Passing
> `PLUGIN_VAR_THDLOCAL` on 8.0/8.4 makes registration succeed while reading the value becomes an
> out-of-bounds read.
>
> Evidence (measured against the tags `mysql-8.0.43`, `mysql-8.4.11` and `mysql-9.4.0`):
>
> - `PLUGIN_VAR_THDLOCAL` appears in `sql/server_component/component_sys_var_service.cc` zero times in
>   8.0.43 and 8.4.11 and eleven times in 9.4.0. The 8.x `register_variable` branches on type using only
>   `flags & PLUGIN_VAR_WITH_SIGN_TYPEMASK` (`0x00ff`), so THDLOCAL (`0x0100`) falls out and the GLOBAL
>   path, which uses a global bool pointer, runs.
> - But `sys_var_pluginvar` **decides the scope from that same flag** (`sql/sql_plugin_var.h`), and
>   value access in `real_value_ptr()` interprets `*(int *)(plugin_var + 1)` as a **byte offset** into
>   session storage (`sql/sql_plugin_var.cc`). On the 8.x component path that slot holds the address of
>   a global → an OOB read. **Do not pass THDLOCAL on 8.0/8.4.**
> - `mysql_system_variable_reader`, the only service that reads a session value, is also new in 9.0.0
>   (`include/mysql/components/services/mysql_system_variable.h`: absent in 8.4.11, present in 9.4.0).
>   `component_sys_variable_register::get_variable` is **GLOBAL only** per both its header comment and
>   its implementation (`OPT_GLOBAL` hardcoded), so it cannot read a session value.
> - 9.x precedent: `components/test/test_session_var_service.cc` and
>   `mysql-test/suite/service_sys_var_registration/{t,r}/session_var_service.*`.
>
> Decisions:
>
> ```
> MySQL 9.0+     gcm.strict : GLOBAL + SESSION   (PLUGIN_VAR_BOOL | PLUGIN_VAR_THDLOCAL)
> MySQL 8.0/8.4  gcm.strict : GLOBAL only        (PLUGIN_VAR_BOOL)
> ```
>
> - The branch is at **compile time** (`MYSQL_VERSION_ID`). The `SERVICE_TYPE` declaration for
>   `mysql_system_variable_reader` is itself absent from the 8.x headers, so a runtime probe would not
>   build; and since `REQUIRES_SERVICE` is a hard load dependency, those two services have to be left
>   out of the REQUIRES list on an 8.x build.
> - On 8.0/8.4 the server rejects `SET SESSION gcm.strict` with `ER_INCORRECT_GLOBAL_LOCAL_VAR`. State
>   it in the §6 operational constraints and in the README.
> - **The tag failure semantics do not change** (ON = error, OFF = NULL). What changes is only which
>   scope can change that value. If the service call fails, assume strict ON (fail closed).
> - The value is read once per statement (`Udf_func_init`), never per row. The reader goes through a
>   `LOCK_system_variables_hash` read lock, a hash lookup and a number-to-string conversion, so a
>   per-row call would show up immediately in the load gate. `SET SESSION` only takes effect at a
>   statement boundary, so the semantics are exact too.

> ## Amendment A4 — what ships is the MySQL component and the SQL interface
>
> No separate Python or Java encryption client is offered as a product. Applications call
> `gcm_encrypt` / `gcm_encrypt_det` / `gcm_decrypt` as SQL through their existing MySQL driver. There is
> no need to integrate this project's crypto implementation into a driver.
>
> Python is used only as a development tool, for vector generation and verification and for running the
> SQL-based E2E and load suites. `scripts/gen-vectors.py` generates and verifies vectors for fixed
> inputs with `cryptography` and offers no reusable encryption client API or package. This scope
> amendment changes nothing about the envelope, the SQL API or the byte values of existing vectors. The
> C++ unit tests and the SQL integration tests verify the server behaviour, and the obligation to prove
> equivalence of, ship and maintain compatibility for per-language clients is removed.

> ## Amendment A2 (2026-09-28, settled) — the deterministic envelope also stores the nonce
>
> Open issue A2 is settled as follows. §2.2 defined the deterministic envelope as
> `version || ct || tag` and said the nonce would be "recomputed", but since the nonce is an HMAC of
> the plaintext, **at decryption time the plaintext is unknown and it cannot be recomputed**. So the
> deterministic envelope stores the 12 nonce bytes as well.
>
> ```
> 0x02  GCM random        : 0x02 || nonce(12) || ciphertext || tag(16)
> 0x03  GCM deterministic : 0x03 || nonce(12) || ciphertext || tag(16)   # the nonce is derived, and stored
> ```
>
> - Determinism and equality are unchanged (the same key, plaintext and AAD give the same envelope
>   bytes end to end). Joins and UNIQUE are unaffected.
> - Cost: +12 bytes per deterministic value. §2.2's "actual growth of 0–16 bytes" is corrected to
>   **"plaintext + 29 bytes"**.
> - Decryption uses the stored nonce directly. Recomputing and comparing is not required — the GCM tag
>   has already authenticated it.
> - The AES-GCM-SIV alternative is not adopted: it is tied to OpenSSL 3.2+, which would constrain the
>   server's OpenSSL. The precedent is HashiCorp Vault Transit's convergent encryption v2, which also
>   stores the nonce.
> - The normative definition is `spec/envelope.md` (FINAL). The server implementation, the vector
>   generator and the tests follow that document.

> ## Amendment A3 (2026-09-28) — defining the v1 legacy CBC envelope
>
> §2.2 only said that the version byte supports a CBC→GCM dual read; v1's byte layout was blank. For
> the implementation and the tests it is defined as follows. **It is decrypt-only, and the component
> never produces v1.**
>
> ```
> 0x01  legacy CBC : 0x01 || iv(16) || AES-256-CBC(PKCS#7) ciphertext
> ```
>
> - Migration only prefixes the existing `AES_ENCRYPT` value with the version byte and the IV — there is
>   no re-encryption. MySQL uses a 32-byte key directly as the AES-256 key (`my_aes_create_key`'s XOR
>   folding is the identity when the input length equals the key length), so `gcm_decrypt` and
>   `AES_DECRYPT` give the same result for the same key.
> - **v1 is not authenticated.** Even with the wrong key, a padding that happens to validate can return
>   garbage plaintext. That is a property of the legacy data and it disappears once it is migrated to
>   v2/v3. State the limitation in `spec/envelope.md` and the README.
> - v1 takes no AAD. Decrypting a v1 envelope with a non-empty AAD is a `bad_envelope` error.
> - `gcm.strict` has no effect on the v1 path (there is no tag). A length or padding error is always an
>   error.

> ## Amendment A1 (2026-09-28) — how the key is delivered: keyring → SQL argument
>
> Contrary to the initial design (§2.1, §2.3, §3, §5.4 and the keyring item in Phase S), **the key is
> taken as a SQL argument, exactly as MySQL's existing `AES_ENCRYPT(str, key_str)` does.** What follows
> replaces §2.
>
> ```
> gcm_encrypt(plaintext, key [, aad])       -> BLOB     random nonce
> gcm_encrypt_det(plaintext, key [, aad])   -> BLOB     deterministic
> gcm_decrypt(ciphertext, key [, aad])      -> VARCHAR  charset tagged (utf8mb4)
> ```
>
> - `key` is **exactly 32 bytes** (AES-256) of binary. Any other length is an error.
>   `AES_ENCRYPT`'s key folding (XOR) is not reproduced — it is how a weak key gets accepted silently.
> - The deterministic variant's nonce key is derived by domain separation rather than taking another
>   argument (settled in Phase 1):
>   `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`,
>   `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`.
> - The only sysvar left is `gcm.strict` (GLOBAL + SESSION, default ON), written `loose_gcm.strict` in
>   my.cnf. `gcm.key_id`, `gcm.nonce_key_id` and `gcm_key_id()` are withdrawn.
> - The dependency on `keyring_reader_with_status` and the §3 keyring backend prerequisite become **out
>   of scope**. §5.4's "do not put the key in my.cnf" still holds (the application keeps the key and
>   passes it per query).
> - The cost: the key bytes appear in the SQL statement, so they can reach the general log, the slow
>   log, `performance_schema.events_statements_*` and an SBR binlog. This is **the same exposure surface
>   as running `AES_ENCRYPT` today**, and it is added to the §6 operational constraints. The keyring
>   approach can be revisited later as an optional feature (something like `gcm_encrypt_kr`).
>   *Revisited in A13.*
> - In the Phase S checklist, "reads the key from the keyring" is removed and replaced by "validates a
>   32-byte key argument, and `SET SESSION gcm.strict` works".

A design document for building a server component that adds AES-256-GCM encryption and decryption
functions to MySQL. It is written on the assumption that this will be split out as its own
open-source project.

It is an optional part of stage 2 of an encryption roadmap (CBC→GCM). The move to GCM is possible
without it, but server-side search (`LIKE`) is lost in that case — see §1.

> Related documents in the original project: `.agents/docs/value-column-encryption.md` (the roadmap)
> and `.agents/docs/ope-removal.md` (stage 0). They are not part of this repository.

## 0. Goal and scope

| Item | Content |
|---|---|
| Goal | Add GCM encryption and decryption functions to MySQL, integrate with my.cnf, and keep `LIKE` search after decryption |
| Form | A MySQL 8.0+ component (not a legacy UDF plugin — §5.1) |
| Target | Self-managed MySQL only. Managed offerings (RDS, Aurora, Cloud SQL) cannot install it |
| Out of scope | The proxy approach, per-language encryption clients and SDKs, DB driver integration, key management systems themselves |

## 1. Why this is needed

### 1.1 MySQL does not support GCM (settled)

The permitted values of `block_encryption_mode` are only
`aes-{128,192,256}-{ECB,CBC,CFB1,CFB8,CFB128,OFB}` — no AEAD mode. There is no argument slot for an
authentication tag or AAD either.

Measured by setting `SET SESSION block_encryption_mode` directly in a container:

| Mode | MySQL 8.4.11 | MySQL 9.4.0 |
|---|---|---|
| aes-256-cbc / -ecb / -cfb128 / -ofb | accepted | accepted |
| aes-256-gcm | rejected | rejected |
| aes-256-gcm-siv / -siv / -ctr / -xts | rejected | rejected |

```
ERROR 1231 (42000): Variable 'block_encryption_mode' can't be set to the value of 'aes-256-gcm'
```

The documentation lists the same set from 8.0 through 8.4 to 9.7. There is no path where upgrading
MySQL solves this. MariaDB has only ECB/CBC/CTR, so it is a limit of the whole family.

### 1.2 Losing server-side decryption means partial-match search stops working

Partial-match search over patient names and EMR IDs currently works through server-side
`AES_DECRYPT + LIKE`. Moving it into the application means decrypting every candidate on every
request.

| Candidate patients | Application-side read + decrypt (measured at 10.6 µs/row) |
|---|---|
| 10,000 | 117 ms |
| 100,000 | ~1.1 s |
| 300,000 | ~3.2 s |

Three seconds per search request does not work. Server-side has no row transfer and no Python object
construction, and the crypto runs at C speed, so the cost structure is fundamentally different — and
production already runs that way, which makes it a proven path.

> If partial match can be given up (reduced to prefix or exact match), this component is not needed.
> That product decision is a precondition.

### 1.3 The existing open-source options do not work

| Project | State |
|---|---|
| crypsi-mysql-udf | Offers an AES-GCM UDF, but has 0 stars and 36 commits, requires OpenSSL 1.1.1 (EOL), takes the key as a SQL argument, has no deterministic mode, and has an unclear license |
| lib_mysqludf_aes256 | An AES-256 extension, not GCM |
| Acra (Apache 2.0) | AES-256-GCM through a proxy. Search is exact-match only in CE, prefix match is Enterprise, and there is no partial match or range. Being a SQL-parsing proxy, it is a risk for queries with many CTEs |

Acra's feature boundary independently confirms our diagnosis — a commercial product in this space does
not offer partial match either.

## 2. What is being built

> Superseded: amendment A1 for the key handling, A2 and A3 for the envelope. The original text is kept
> because those amendments are written as deltas against it and are unreadable without it. **This is
> not the current design** — `gcm_key_id()`, the function surface with no key argument, and the
> deterministic envelope that stores no nonce are all withdrawn.

### 2.1 Function surface

The builtins cannot be overridden, so new names are required. Adding a mode to
`block_encryption_mode` is not possible either.

```
gcm_encrypt(plaintext [, aad])       -> BLOB      random nonce
gcm_encrypt_det(plaintext [, aad])   -> BLOB      deterministic (joins, UNIQUE, exact match)
gcm_decrypt(ciphertext [, aad])      -> VARCHAR   charset tagged (§5.3)
gcm_key_id()                         -> VARCHAR   the current key id (for observability)
```

`gcm_encrypt_det` is not optional. Without it, every place that uses an encrypted column as a join key
breaks (94 sites in vc-backend, 37 in vc-report, 88 in vc-sync, by pattern count). With the
deterministic variant, those sites need no change.

```
nonce = HMAC-SHA256(nonce_key, plaintext)[:12]     # synthetic nonce, no need to store it
ct    = AES-256-GCM(key, nonce, plaintext, aad)
```

### 2.2 The ciphertext envelope

```
random nonce  : version(1) || nonce(12) || ciphertext || tag(16)
deterministic : version(1) || ciphertext || tag(16)        # the nonce is recomputed
```

- Returns BLOB, not VARCHAR — MySQL's behaviour when filtering binary data in a text form is ambiguous
  (Acra added explicit casting for the same reason)
- The version byte supports a CBC (v1) → GCM (v2) dual read during the transition
- PKCS7 padding disappears, so the actual growth is 0–16 bytes (for the deterministic variant)

### 2.3 my.cnf integration

Registering a sysvar through `component_sys_variable_register` makes it settable from my.cnf and the
command line.

```ini
[mysqld]
# key ids only. Never the key bytes (§5.4)
loose_gcm.key_id       = vc_phi_v1
loose_gcm.nonce_key_id = vc_phi_nonce_v1
loose_gcm.strict       = ON
```

| sysvar | Scope | Description |
|---|---|---|
| gcm.key_id | GLOBAL + SESSION | The keyring data id. The session scope is what makes rotation and a dual-read transition possible |
| gcm.nonce_key_id | GLOBAL + SESSION | The HMAC key id for the synthetic nonce (separate from the encryption key) |
| gcm.strict | GLOBAL + SESSION | On a tag mismatch, ON = error / OFF = NULL |

The key is looked up by Data ID through `keyring_reader_with_status`, so the key bytes never appear in
SQL. That is how crypsi's flaw is avoided.

## 3. A prerequisite decision — the keyring backend (before the spike)

> **Out of scope** as of amendment A1. Kept because A1 is written against this section. Revisited
> by amendment A13, which keeps this section's verdict for the goal it was about.

This decision determines whether the project is justified at all.

Today the application holds the key and passes it in SQL. The keyring approach puts the key on the DB
host.

The real benefit of encryption, as the roadmap states it, is "preventing value disclosure if the DB
files or a backup leak". But putting the key on the same host with `component_keyring_file` means
whoever took the data files took the key too — and that benefit disappears.

| Backend | Verdict |
|---|---|
| component_keyring_file | Not viable. It destroys the benefit above. Development and test only |
| component_keyring_vault / a KMS keyring | A necessary condition |

If an external keyring cannot be run in production, this whole direction has to be reconsidered.
"Start with keyring_file and change it later" is a dangerous plan.

## 4. Procedure

### Phase S — the spike (1–2 days, before the spec)

Build a minimal component that answers the risky unknowns in one go. The spec depends on the result,
so do not reorder this.

- [ ] A component skeleton registers one UDF through `mysql_service_udf_registration`
- [ ] It reads `loose_gcm.key_id` from my.cnf as a sysvar
- [ ] It reads the key for that id from the keyring (`keyring_reader_with_status`)
- [ ] The `gcm_decrypt` return value is charset-tagged, so Korean `LIKE '%김%'` works through the native
      collation ← this is where the need for decrypt_like is decided (§5.3)
- [ ] Observe `Created_tmp_disk_tables` — whether plaintext reaches a disk-based temporary table (§5.3)
- [ ] `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)` succeeds on the build and runtime OpenSSL
      combination

Local verification:

```sh
# put the built .so into plugin_dir
docker cp component_gcm.so mysql-dev:/usr/lib/mysql/plugin/
docker exec -i mysql-dev mysql -uroot <<'SQL'
INSTALL COMPONENT 'file://component_gcm';
SELECT gcm_key_id();
SELECT HEX(gcm_encrypt_det('홍길동'));
SELECT gcm_decrypt(gcm_encrypt_det('홍길동'));
SELECT gcm_decrypt(gcm_encrypt_det('홍길동')) LIKE '%길%';   -- must be 1
SHOW STATUS LIKE 'Created_tmp_disk_tables';
SQL
```

### Phase 1 — the spec (after folding in the spike results)

- Settle the envelope format, the function surface, the sysvars and the failure semantics
- Test vectors — NIST CAVP GCM KAT plus the project's own. They are the common reference for the C++
  core and the SQL tests
- The list of operational constraints to document (§6)

### Phase 2 — implementation and tests

- OpenSSL EVP, fetched by name (never the `EVP_aes_256_gcm()` symbol directly — it binds to the build's
  OpenSSL)
- `OPENSSL_cleanse` the key buffers. No key or plaintext in an error message
- An MTR (mysql-test) `.test`/`.result` suite
- A nonce collision boundary test for the deterministic variant

### Phase 3 — the SQL usage flow and E2E verification

Verify the usage flow of calling the SQL functions through an existing MySQL driver. It covers
encrypted storage → server-side decryption and Korean `LIKE`, ROW replication, the legacy CBC dual
read, an AAD mismatch, and session strict isolation. The Python runner only executes SQL and checks
results; it does no encryption or decryption.

### Phase 4 — build, distribution and documentation

- The build matrix: MySQL major version × platform (amd64/arm64, glibc/musl) × OpenSSL — a component's
  ABI is coupled to the server version
- Put the §6 operational constraints on the README's first screen

### Phase 5 — upstream (optional, with low expectations)

Precedent: WL#6781 "Support multiple AES Encryption modes" is what added today's mode list. The
channel exists.

That said, `AES_ENCRYPT(str, key, iv, kdf, salt, info)` has no slot for a tag or AAD, so this needs a
new family of functions rather than an extension of the existing one, which makes acceptance unlikely.
Filing a feature request costs almost nothing.

## 5. Design decisions and rationale

### 5.1 Why a component (and not a legacy UDF plugin)

The component infrastructure has clear service boundaries and is the recommended path for new
extensions. Decisively, it gives access to the keyring service and the sysvar registration service —
with a legacy UDF the only option is to take the key as a function argument, which is what crypsi
does.

### 5.2 Why the deterministic variant is mandatory

The encrypted columns are the schema's join backbone.

```
Patient.encrypted_emr_id      == Encounter.encrypted_patient_id
Encounter.encrypted_emr_id    == Score.encrypted_encounter_id
Encounter.encrypted_emr_id    == UserPin.encrypted_encounter_id
```

And `uq_emr_location_natural_key (site, ward, room, bed)` is a UNIQUE that only holds because room and
bed are deterministic AES. Offering the random nonce alone breaks all of that.

On the safety of the synthetic nonce: GCM is catastrophic if two different plaintexts get the same
nonce, but a collision in HMAC-SHA256 truncated to 96 bits is on the order of 10⁻¹⁵ at ten million
values. The same plaintext getting the same nonce is the intended determinism. The AAD does have to be
identical across every deterministic call under one key (amendment A8). Equality, frequency and length
information are exposed, and this collision calculation alone proves neither the safety of the whole
construction nor a per-key operational limit. A separate security review is required.

Precedent: HashiCorp Vault Transit's convergent encryption is the same construction.

### 5.3 Why decrypt_like is not built first

From MySQL 8.0.19, the `mysql_udf_metadata` service can set the charset and collation of a return
value. That makes MySQL's native `LIKE` usable as-is.

```sql
WHERE gcm_decrypt(encrypted_name) LIKE '%김%'   -- under the column's collation
```

Writing decrypt_like instead would mean reproducing the column collation's case-insensitivity and
accent/width behaviour in C, all the way through CJK. Removing OPE was where we were burned
once by Python's code-point order differing from MySQL's collation. Do not reproduce it; use MySQL's.
The collation is the column's, and on 8.0+ the default utf8mb4 collation is `utf8mb4_0900_ai_ci`
(measured — `tests/integration/20_korean_like.expected`), not the older `utf8mb4_general_ci` this
section once named as the worked example. Amendment A17 measured what that means for an index built on
top of the comparison: a binary normalisation misses rows the collation matches
(`docs/leakage-ngram.md`).

> There is one legitimate reason to want decrypt_like, and it is security rather than performance. If
> `gcm_decrypt(col)` goes through a temporary table or a filesort, plaintext reaches a disk-based temp.
> A fused function that returns only a boolean never lets plaintext out of memory. Decide after
> observing whether it actually happens, via `Created_tmp_disk_tables` in Phase S.

### 5.4 Why the key does not go in my.cnf

It is exposed to everyone who can read the file, it ends up in configuration management, backups and
images, and it may even be visible through `SHOW VARIABLES`. The way MySQL's own InnoDB TDE does it is
the right answer — key ids in my.cnf, key bytes in the keyring.

### 5.5 A tag mismatch is not degraded to NULL

The existing `AES_DECRYPT` returns NULL on failure, so "wrong key" and "no data" are
indistinguishable. For an AEAD that removes the meaning of authentication. `gcm.strict=ON` is the
default and it raises an error.

## 6. Operational constraints — these must be stated in the README

- The random-nonce function is non-deterministic → dangerous under statement-based replication.
  `INSERT ... VALUES(gcm_encrypt(...))` produces different values on the primary and the replica. ROW
  binlog is mandatory
- Non-deterministic functions cannot be used in a generated column or an index
- Plaintext ends up in the server logs. The encryption calls take plaintext as a SQL argument, so it
  reaches the general log, the slow log, `performance_schema.events_statements_*` and an SBR binlog.
  The search pattern (`'%김%'`) is a fragment of plaintext PHI too. This is a fundamental limit of the
  UDF approach and cannot be avoided
- It cannot be installed on managed MySQL (no access to `plugin_dir`)
- A component sysvar has no effect until the component is installed. Written in my.cnf without the
  `loose_` prefix, the first startup can fail
- A UDF is opaque to the optimizer. Selectivity depends on the other predicates (scope and status
  filters)
- (Amendment A17) A keyed n-gram token side table to give `LIKE` an index **was researched and
  declined**: the deterministic tokens leak n-gram frequencies and co-occurrence, and on Korean the
  experiment recovered 20.7% of Korean n-grams under the S1 attack (17.3% for the second S1 attack and
  31.7% under the stronger S3 attack 3), far
  above the ceiling. See [`leakage-ngram.md`](leakage-ngram.md). The motivating `LIKE '%김%'` is the
  index's worst case (~21% selectivity), and a binary token key does not respect the collation.
- (Amendment A2) `gcm_encrypt_det`'s nonce is a function of the plaintext alone. **Encrypting the same
  plaintext under one key with two different AADs reuses the (key, nonce) pair**, and an attacker who
  sees both values can recover the GHASH subkey and forge tags for that nonce. Confidentiality is
  unaffected (the plaintext is the same, so the keystream does not cover two plaintexts). The
  operational rule: fix the AAD to one value across every deterministic call that uses a given key. No
  exceptions across servers, columns or applications, and a different AAD domain gets a different key.
  The random variant is not subject to this AAD constraint. The rationale and wording are in
  `spec/envelope.md` §3.
- (Amendment A3) `gcm_decrypt` accepts the legacy `0x01` (CBC) envelope and **that path is not
  authenticated**. Once the dual-read migration is finished, the application rejects `0x01`.
- (Amendment A1) Because the key is passed as a SQL argument, the key bytes can end up in the general
  log, the slow log, `performance_schema` and an SBR binlog. The same exposure surface as
  `AES_ENCRYPT`. Disabling the general log and setting `log_raw=OFF` for the slow log do not help (the
  UDF arguments are literals), so the answer is access control over the logs
- (Amendment A5) `gcm.strict` is **GLOBAL only** below MySQL 9.0. On 8.0 and 8.4,
  `SET SESSION gcm.strict` is rejected with `ER_INCORRECT_GLOBAL_LOCAL_VAR`. The tag failure semantics
  (ON = error, OFF = NULL) are the same on every version
- (Amendment A7) **Do not pass a computed SQL expression directly as an argument to `gcm_encrypt*`.**
  On 8.0 and 8.4 the server hands over a stale argument from the second row onwards and can silently
  seal the wrong plaintext. Use a column, a literal, a user variable or a bind parameter, and if a
  value must be computed in SQL, materialise it first (`CAST` alone is not enough)
- (Amendment A8) **Installing the component is not replicated.** Run `INSTALL COMPONENT` on each
  server that serves decryption queries and each replica that may be promoted, and make sure the
  application can deliver the key to those servers too. ROW binlog carries the ciphertext, nonce and
  tag verbatim, so the replica does not re-encrypt
- (Amendment A8) **In a sharded deployment, random ciphertext cannot be a routing key**, and
  `gcm_decrypt(...) LIKE` alone cannot select a shard. Route on a stable identifier. The "one AAD per
  key" rule applies across shard boundaries, and comparing deterministic ciphertext across shards
  requires the same key, plaintext and AAD. Whether a sharding middleware forwards UDF calls and
  preserves the charset must be verified for that combination

- (Amendment A8) Sum the usage across every server, column and application that shares a key, and have
  the per-key usage budget and rotation criteria security-reviewed before deployment. The component
  does not hold a budget or rotate automatically. For the key-id functions it publishes a count per
  key name (`gcm_key_usage`, amendment A14), which is one input to this sum and not the sum.
- (Amendment A8) Copying or restoring an envelope is not a new encryption. Distinguish the conditions
  for re-encryption and for a deterministic retry, and do not let a database restore roll back the
  accumulated usage. If the usage history or the safety of the RNG state is uncertain, stop writing;
  recover and verify the RNG state of every writer, then resume with a safely generated new key.
- (Amendment A8) A key rotation comes with migrating the JOIN/UNIQUE use of deterministic ciphertext
  and retaining keys for historical data and backups. The guard hook, the vectors and the sample
  collision test provide neither nonce-reuse detection in production nor a proof of safety.

## 7. License — GPLv2 (settled)

**Conclusion: GPLv2** (2026-09-28). The full GPLv2 text goes in `LICENSE`, and the sources carry
`SPDX-License-Identifier: GPL-2.0-only`.

Rationale: the MySQL server is GPLv2 (with the FOSS exception) and a component links against the
server headers. If it is judged a derivative work, distributing under GPLv2 is the safe choice. The
route to Apache/MIT was considered and not taken. OpenSSL 3 is Apache-2.0, and combining it with
GPLv2 is the same configuration MySQL's own FOSS exception addresses — we use the libcrypto the server
has already loaded and neither bundle nor statically link our own (crypto-safety), so the shape is the
same as a MySQL distribution. It is `GPL-2.0-only`, not "or later": MySQL is GPLv2-only, so we claim no
forward compatibility.

## 8. Established facts / open questions

### Confirmed

| Item | Evidence |
|---|---|
| **A keyed n-gram token index for `LIKE` was researched and declined** — it leaks n-gram frequency and co-occurrence; on Korean, 20.7% / 17.3% occurrence-weighted token recovery under the S1 attacks and 31.7% under the stronger S3 attack, against a B1 + 10 pp ceiling | amendment A17 — `docs/leakage-ngram.md`; experiment PRs #59–#66 |
| **N2 (`WEIGHT_STRING`) holds the collation invariant an n-gram index needs; a binary key (N1) does not** — 6 counterexamples (case, accent, full width) on 8.0.43, 8.4.11 and 9.4.0 over the declared repertoire, none under prefix-extension monotonicity, and the repertoire now carries Hangul IME composition states | amendment A17 — `tests/leakage/collation`, `scripts/leakage-collation.sh` |
| MySQL 8.4.11 and 9.4.0 reject GCM/GCM-SIV/SIV/CTR/XTS | measured in a container |
| The mode list is unchanged across the 8.0 → 9.7 documentation | the dev.mysql.com reference |
| MariaDB has only ECB/CBC/CTR | the MariaDB documentation |
| A component can register UDFs | `mysql_service_udf_registration` (WL#8020) |
| A component can look up a key in the keyring | `keyring_reader_with_status` |
| A UDF return value's charset can be set (8.0.19+) | `mysql_udf_metadata` (WL#12370) |
| `AES_ENCRYPT` supports a KDF (hkdf/pbkdf2_hmac) from 8.0.30+ | the 8.0 reference — for information |
| `udf_registration`, `mysql_udf_metadata`, `component_sys_variable_register`/`_unregister`, `mysql_runtime_error` and `mysql_current_thread_reader` are present in 8.0.43, 8.4.11 and 9.4.0 | measured in `include/mysql/components/services/` across the three tags |
| The services behind the `_kr` functions have the same signatures in 8.0.43, 8.4.11 and 9.4.0: `keyring_reader_with_status` (introduced in 8.0.24), `mysql_thd_security_context` and `mysql_security_context_options` (in the tree at 8.0.4), `mysql_current_thread_reader` (present at 8.0.43; the release that introduced it was not established) | amendment A13 — read in `include/mysql/components/services/` across the three trees |
| **The SESSION scope for a component sysvar, and `mysql_system_variable_reader`, are 9.0.0+ only** | amendment A5 — measured in `component_sys_var_service.cc` and `mysql_system_variable.h` across the three tags |
| `CONFIGURE_COMPONENTS()` globs `components/*`, so placing the sources in `components/gcm` and re-running configure builds in-tree | `cmake/component.cmake` |
| On the RHEL9 family, the compiler the server source requires is gcc-toolset-12 for 8.0/8.4 and **gcc-toolset-14 for 9.x** | the `ALTERNATIVE_PATHS` (`LINUX_RHEL9` branch) in each tag's `CMakeLists.txt`. Measured: with toolset-13, configuring 9.4.0 fails with "Could not find devtoolset compiler/linker". `rhel9_toolset` in `docker/versions.json` is the source of this value |
| 8.0 needs an external boost (1.77); 8.4 and 9.x bundle it in `extra/boost` | each tag's `cmake/boost.cmake` |
| **Korean partial match works through native LIKE** — `gcm_decrypt(gcm_encrypt_det('홍길동',@k),@k) LIKE '%길%'` = 1, `CHARSET()` = `utf8mb4`, and prefix, suffix and case-insensitive `LIKE '%kim%'` are also 1 | Phase S measurements on 8.0.43, 8.4.11 and 9.4.0 (`scripts/verify.sql`, `tests/integration/20_korean_like.sql`) → **decrypt_like is unnecessary** |
| `Created_tmp_disk_tables` increased by 0 for a `gcm_decrypt` + `ORDER BY` + `GROUP BY` combination | Phase S measurements on 8.0.43, 8.4.11 and 9.4.0 (`build/<ver>/tmp_disk.txt`). A small-scale observation, and still to be re-confirmed at volume. `tests/load` reports the same counter as `created_tmp_disk_tables_delta`, but around its own `gcm_decrypt(col,@k) LIKE` query rather than this ORDER BY + GROUP BY one, so it does not confirm this row |
| `EVP_CIPHER_fetch("AES-256-GCM")` and `EVP_MAC_fetch("HMAC")` succeed on all three versions | `INSTALL COMPONENT` succeeding is itself the evidence (a failed fetch in init fails the install) |
| The deterministic envelope matches `spec/envelope.md` §5.1 and §5.2 byte for byte | Phase S measurements on all three versions (`tests/integration/11_roundtrip_det.sql`, `40_null_and_edge.sql`) |
| A key that is not 32 bytes is rejected on every call (0, 5, 31, 33, 64) | `tests/unit`, `tests/integration/00_install_and_signature.sql` |
| **Passing a computed string expression as an argument makes 8.0 and 8.4 corrupt the value** | amendment A7 — measured on all three versions (`tests/integration/91_server_udf_arg_defect.sql`) |
| The MTR suite `mysql-test/suite/gcm` passes in an 8.4.11 server tree and the `.result` files are `--record` output | measured with `scripts/mtr.sh 8.4`. The replication cases use `include/rpl/*`, an 8.4+ path |
| Under ROW binlog the ciphertext bytes are identical on the primary and the replica, and under STATEMENT the random variant **diverges** | measured in `gcm_replication.test` — the server warns that SBR is unsafe and the replica re-runs the function, producing a different nonce |
| `INSTALL COMPONENT` is not replicated | the same test — after UNINSTALL on the replica, reading a replicated row gives `ER_SP_DOES_NOT_EXIST` |
| Two independent servers (shards) produce the same deterministic envelope for the same key, plaintext and AAD, and a different one when the AAD differs | measured in `tests/e2e/scenarios/cross_shard_determinism.py` (8.4) |
| If a v1 envelope's plaintext is not utf8mb4, the result becomes an invalid string and `LIKE` silently returns 0 | measured on 8.4 (latin1 `Müller` → `4DFC6C6C6572`, `LIKE '%ller%'` = 0). Recorded as a MUST in `spec/envelope.md` §2.3 |
| Declaring `const_item` on `gcm_encrypt_det` makes a constant lookup use a UNIQUE index (`type=const`) | measured in `gcm_envelope.test`. Re-executing a PREPARE with a different parameter does not cache the value |
| Binary (non-UTF-8) plaintext keeps its bytes even though utf8mb4 is requested | measured in `gcm_null_and_edge.test` — the `binary` → `utf8mb4` conversion copies the bytes |
| **`args->lengths[i]` is the length *before* conversion** — the plaintext argument is requested as utf8mb4, so the server widens it before handing it to the component. A latin1 `VARCHAR(1)` holding `é` has lengths[0]=1 while the envelope is 31 bytes | measured on 8.4 and 9.4: materialising the result gives `ER_DATA_TOO_LONG` in strict mode, and in non-strict mode it is **truncated to 30 bytes on store and decryption fails** (with only warning 1265). Since every charset is at least one byte per character, `lengths[0]` bounds the character count, and utf8mb4 is at most 4 bytes per character → declare `4 × lengths[0] + 29`. `gcm_null_and_edge` pins both modes |
| `initid->max_length` is narrowed by the server with `min<uint32>(...)`, so it is **truncated to uint32 first** | `udf_handler::fix_fields` in `sql/item_func.cc`. Adding 29 to a LONGTEXT argument (4294967295) wraps to 28, truncating the envelope below its minimum length — measured on 8.4 as `ERROR 1406 Data too long`. `envelope_max_length()` in `udf_glue.h` prevents it with saturating arithmetic and `gcm_null_and_edge.test` pins it |
| A component cannot include `mysql_com.h` | the `my_io.h` behind it raises `#error This header shall not be included in components`. It surfaced as a failure in the 9.4.0 build while 8.0 and 8.4 passed silently — only building all three catches it |
| `component_sys_variable_register::register_variable` **copies** the `def_val` from the `*_CHECK_ARG` | `sql/server_component/component_sys_var_service.cc`: `sysvar_bool->def_val = bool_arg->def_val` (into a my_malloc'd struct). So passing a stack-local check-arg is safe |
| **The per-call EVP context setup, not the cipher, is most of a small decryption**, and the p95 difference between a scan and a scan that also calls `gcm_decrypt` is 73–85% of a `gcm_decrypt(col) LIKE` query (a difference between queries, not a component timing) | amendment A11 — developer-machine prototypes: a 16-byte `open` 353 → 170 ns with a reused context; p95 over 100k rows on 9.4 49.6 → 23.2 ms (1 session) and 126.4 → 27.2 ms (8 sessions); the plaintext-column baseline in `tests/load`. CI numbers to follow in `docs/perf.md` |

### Open (to be answered in Phase S)

- ~~Whether charset tagging makes Korean `LIKE` work per the native collation~~ → **confirmed** (the
  table above). decrypt_like will not be built
- ~~Whether `gcm_decrypt` leaves plaintext in a disk temporary table~~ → an increase of 0 at small
  scale (the table above). Large volumes continue to be observed through
  `created_tmp_disk_tables_delta` in `tests/load`
- Whether the production MySQL is self-managed (the ECR image circumstantially suggests so, but it is
  unconfirmed)
- ~~Whether an external keyring (Vault/KMS) can be run in production~~ → **out of scope** as of
  amendment A1
- The load baseline: whether `gcm_decrypt` + LIKE p95 is within 1.2x of `AES_DECRYPT` (10k/100k/300k,
  1/8/32 concurrent). Settled for 0.1.0 from three measurements on a CI runner (ubuntu-24.04, 8.4.11,
  300k rows, 40 samples per session): a ratio of 0.80–0.95 and a serial p95 of 235–255 ms. The gate
  enforces 1.10, derived from the measurements rather than from the 1.2x promise — the rationale and
  the tables are in `docs/perf.md`. `tests/load/run.py --gate` is the gate and the results accumulate
  in `docs/perf.md`
- ~~The load baseline — numbers from a release build on known hardware~~ → **confirmed**: measured three
  times on a CI runner, with the gate in `tests/load/baseline.json` derived from those values
  (`docs/perf.md`, "Release baseline — 0.1.0")
- ~~Where the per-row cost comes from~~ → **confirmed** (`tests/bench`, `docs/perf.md`): the decryption
  path shows no measurable overhead against bare EVP (0.97–1.03), and the structural cost of the
  envelope, error translation, buffer management and cleansing combined is under 10% on all three
  encryption paths. The deterministic variant costing 3.5–5x a plain seal is the two HMAC passes, not
  implementation overhead.
- ~~`derive_nonce_key` depends only on the key, yet `encrypt_det` recomputes it on every call
  (about 40% of `seal_det` for a small plaintext). Caching it per `UDF_INIT` would be a meaningful
  saving, but since the key is a per-row argument, deciding whether the cache is valid requires
  **keeping a copy of the key between rows** — which runs head-on into the key handling in
  `crypto-safety.md`. Doing this for performance means raising it as an amendment and getting a
  security review.~~ → **decided by amendment A11**: a `UDF_INIT` may keep the key copy beside the
  derived nonce key, and beside `gcm_decrypt`'s scheduled EVP context, under the invariants stated
  there (constant-time compare, cleanse before replacement, forget on any error, cleanse in deinit,
  never shared). The prototype measurements are in A11; the CI numbers go in `docs/perf.md`. The
  security review A11 asks for is still owed.

## 9. References

- MySQL: Keyring component services
- WL#4102 Service registry and component infrastructure
- WL#8020 Add a UDF registration service
- WL#12370 Extend the UDF API to handle character sets
- WL#6781 Support multiple AES Encryption modes
- Extending MySQL: Adding a Loadable Function
- Keyring Component Installation
