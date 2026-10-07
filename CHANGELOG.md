# Changelog

Notable changes per release. Envelope-format changes get their own entry with a compatibility note
(`ci-release` skill release checklist).

## Unreleased

### Measured
- **The two smaller suites, at the core and at the SQL level.** `tests/bench` now runs every gated
  case once per suite, each against a reference running the same cipher, so the 1.10 ceiling applies
  to AES-192 and AES-128 as it does to AES-256 — the claim is the same, and the suites share every line
  of code except the fetched cipher. `gate.py` additionally reports each suite against AES-256, un-gated,
  because that number is a property of the machine. `tests/load/run.py --suite` and `load.yml`'s
  `suite` input measure the SQL path with a 24- or 16-byte key, lowering `gcm.min_key_bytes` only
  while the rows are written and against the same `aes-256-cbc` baseline so the ratios share a
  denominator.
- **Four CI core runs and three CI load runs per suite, with the limits of what they show.** All
  144 gated core ratios fall between 0.978 and 1.044, the band the AES-256 baseline occupied; one of
  the four runs landed on a runner 2.6x faster than the others and its ratios stayed in the band,
  which is the first cross-fleet confirmation of the work-matched references. Against AES-256 the
  smaller suites are within about 2% at 16 and 256 bytes and AES-128 decryption is 7–14% cheaper at
  64 KiB. At the SQL level all 27 load ratios are 0.751–0.960 and pass the gate; at 8 and 32 sessions
  the three suites' ranges overlap, so the runs bound the spread without ranking the suites or
  separating scan cost from decryption. `docs/perf.md` has every run.
- `envelope/parse` for the four A10 version bytes is recorded alongside v1–v3: 1.5–2.1 ns against
  1.3–1.4 on the developer machine; the measurement does not isolate lookup cost.
- **Review fixes:** benchmark fixtures preserve unsupported key lengths instead of silently clamping
  them to AES-256. The load runner restores the previous minimum key policy after successful or
  failed fixture loading, with regression tests run by PR CI; a load requiring a longer key does not
  raise an already lower policy.

### Changed
- **CI stops rebuilding a MySQL server on every MTR run.** `images.yml` publishes two images per
  major to GHCR — `mysql-gcm-build` (a configured source tree) and `mysql-gcm-mtr` (that plus a
  compiled server, 8.4 only) — and `scripts/image-ref.sh` resolves local → registry → build for every
  consumer.

  The measurement that prompted it: `mtr` ran 49–63 minutes, of which the suite itself is **16
  seconds**. `scripts/mtr.sh` called `cmake --build` with no `--target`, so it compiled the whole tree,
  3,441 object files. Pruning targets was checked and rejected: by object count the tree is 26% bundled
  third-party, 24% storage engines, 20% `sql/`, and the router — the one clearly droppable piece — is
  **8%**. There is no target list that makes a server build cheap.

  **The tag carries a hash of the inputs**, not just the MySQL version: `build.Dockerfile`,
  `build-component.sh` and that major's `versions.json` entry. Before this the tag was
  `<major>-<patch>`, so editing the Dockerfile produced a byte-different image under a name that was
  already cached — harmless while every run built its own, and a correctness hole the moment a run can
  pull one somebody else built. A changed input yields a tag that does not exist and every consumer
  falls back to building, so a stale image can never be served.

  A published image is a **cache, never a dependency**: the scripts work with no network and no
  registry. Only amd64 jobs opt in, because the images are built on `ubuntu-24.04` and an emulated pull
  on `build.yml`'s arm64 half would be slower than the build it replaced. The `mtr` job also stops
  running `build-in-docker.sh` first: it produced a `.so` the job never used, since `mtr.sh` builds the
  component inside the MTR container.

  The figures above for the published path are projections from image sizes and typical GHCR pull
  rates, not measurements. They go in `docs/perf.md` once real runs exist.

- **AES-192-GCM**, completing amendment A10. Envelope versions `0x06` (random) and `0x07`
  (deterministic), byte-for-byte the layout of the other four. All three suites now ship, selected by
  key length and nothing else: 32 → AES-256, 24 → AES-192, 16 → AES-128. `spec/envelope.md` is at v3.

  **The default does not move.** `gcm.min_key_bytes` stays at 32, so a server that is left alone still
  refuses anything below AES-256; `24` now permits AES-192 and AES-256 while still refusing AES-128.

  This tested A10's own claim that adding a suite is "one row in the table plus one
  `EVP_CIPHER_fetch`". It held — four files, seventeen lines, and parsing, the version/key agreement
  check, the nonce derivation, the error message and the floor all followed from the table. What was
  **not** free was the test and document surface: a dozen places asserted AES-192 was unimplemented
  and each had to be flipped deliberately, which is the honest cost of allocating a version byte
  before implementing it.

  The CAVP KAT is now imported for every suite — 2,250 cases, 750 each, with 191 / 190 / 196
  authentication failures — plus project tamper vectors for `0x07`, which the CAVP decrypt files never
  reach because they are all random-nonce. The generator's list of valid version bytes is now derived
  from the suite table rather than written out, after a hardcoded tuple went stale the moment this
  suite was added and the generator's own verifier was what caught it.

  Review then found two gaps in the coverage this added, both confirmed by mutation before fixing.
  The adapter suite's "are the algorithms still live" probe used a 32-byte key only, so **deleting the
  AES-192 release pair passed all 35 cases** — and the AES-128 pair was equally invisible, which
  follows from the same cause and had been true since that suite landed. The probe takes a key length
  now; each deletion is detected (26 of the 35 adapter cases fail). And the integration case only exercised the floor against
  AES-128, so a policy applied to 16-byte keys alone would have passed; it now covers both encryption
  functions at floor 32, the middle setting of 24 where AES-192 and AES-256 pass and AES-128 does not,
  and a raise back to 32 with existing AES-192 data still decrypting.

  Two latent test defects surfaced while writing this. The tamper fixture appended a constant `0xFF`
  to replace the last tag byte, which is a **no-op when the tag already ends in `0xFF`** — the AES-192
  envelope did, so the case decrypted successfully and claimed to be testing a tag failure. It now
  XORs. And the AES-192 fixture key in the integration case was 20 bytes rather than 24, which the
  key-length error reported before any of it could pass.

- **AES-128-GCM**, alongside AES-256-GCM (`docs/design.md` amendment A10, `spec/envelope.md` v2).
  Envelope versions `0x04` (random) and `0x05` (deterministic), byte-for-byte the layout of
  `0x02`/`0x03` — plaintext + 29 either way. **The key length selects the suite and nothing else
  does**: 32 bytes gives AES-256, 16 gives AES-128. No new argument, no selector, no change to the
  call shape.

  **It is off by default.** `gcm.min_key_bytes` (GLOBAL, default `32`) is the floor the encryption
  functions enforce; a server that is left alone behaves exactly as before and still refuses a short
  key. That floor is the whole reason the feature can ship with length-based selection: a 32-byte key
  truncated in transit is a *valid* AES-128 key, so without it `gcm_encrypt` would seal at a strength
  nobody asked for. Decryption ignores the floor, so raising it again never locks out data written
  while it was lower — which is what makes migrating off AES-128 possible at all.

  On decryption the version byte states the key length it needs, and a disagreement is `bad_key_len`,
  **never `bad_tag`** — a key problem reported as one rather than as suspected data corruption. The
  error says only that the envelope and the key disagree about length; a corrupted version byte gives
  the same signal, and the documentation says so rather than calling it a truncation detector.

  AES-192 is **not** implemented. `0x06` and `0x07` are allocated to it and rejected as
  `bad_envelope`, and a 24-byte key is an error — pinned by tests at three layers, because that is
  the case most likely to rot into a silent accept when the suite table grows.

  The deterministic nonce label is unchanged for every suite. Note that this does not domain-separate
  them: RFC 2104 §2 zero-pads, so `K` and `K ‖ 0¹⁶` derive the same nonce key. Those are different
  AES keys, so it is not a nonce reuse, but no implementation may rely on key length for separation
  and the question is in the security review A10 still asks for.

  Also withdrawn after review: the claim that per-suite derivation labels would make `0x03` and
  `0x05` incomparable. They already differ from the version byte onward, and labelling only the new
  suite would leave existing data reproducible. The real reason for one shared label is that
  `crypto-safety.md` requires it to be a single constant, and a second one buys a separation nothing
  has shown a need for — and that the claim "costs no existing data" is scoped to existing `0x03`
  data, because once `0x05` ships a label change breaks its deterministic reproducibility too. The
  window in which that change is cheap is before `0x05` is in anyone's data.

  Found while implementing, by a test written for it: `sysvar_register` discarded the result of its
  own rollback, so a refused unregister of `gcm.strict` left a variable in the dictionary while the
  crypto handles were freed underneath it — the same shape of defect issue #7 was opened for. The
  result is now reported and the caller keeps the handles.

  The NIST CAVP KAT is imported for both suites — `scripts/import-nist.py` was single-suite and now
  carries the version byte per file. 1,500 KAT cases (750 AES-256 with 191 authentication failures,
  750 AES-128 with 196), plus project tamper vectors for `0x05`, which the CAVP decrypt files do not
  reach because they are all random-nonce. AES-192's CAVP files are deliberately not imported.

  A second review found a **P1 on the uninstall path**: the first fix re-registered the floor when
  `gcm.strict` then refused, and `register_variable` re-applies the startup options — once
  `mysqld_server_started` it reads `argv_cached`, appends the persisted variables and runs
  `handle_options`. A server booted with `loose_gcm.min_key_bytes=16` whose administrator had raised
  it to 32 would have had 16 handed back by a *failed* UNINSTALL, re-allowing AES-128 writes. A
  failed uninstall must never widen a policy. The re-registration is gone: the state flags already
  made the retry work without it, and an absent floor reads as 32, which is strictly narrower than
  anything an operator could have set. The adapter stub now models the option re-application, so the
  test asserts the policy value rather than merely that no re-registration happened.

  Review found four more things, all fixed here. `sysvar_unregister` attempted both unregisters
  unconditionally, so a refused UNINSTALL that had already removed one left **every retry failing**
  on the one that was gone — the stub had been returning success for an absent variable and hiding
  it. It now tracks each variable, removes the floor first so a refusal changes nothing, and
  re-registers it if `gcm.strict` then refuses. `gcm_signature.result` still carried the old
  key-length message and would have failed CI. The floor's failure paths had no test: service
  failure, nine untrusted values, and the GLOBAL scope on 9.x are now pinned. And `spec/envelope.md`
  still said "exactly 32 bytes" in §3 while claiming FINAL v2, and required every `bad_key_len`
  vector to fail encryption — which the new suite-mismatch vectors do not and must not.

- **The documentation and the agent instructions are English.** `AGENTS.md`, `CLAUDE.md`, the three
  nested `AGENTS.md` files, all ten rules in `.agents/rules`, all ten skills and the four subagents
  were Korean; they are now English, and the generated adapters follow from `agents-sync.sh`.
  `docs/design.md` is English with the Korean original preserved as `docs/design-KO.md`, which the
  rule marks as the translation and the English file as canonical.

  Korean that is **test data** is untouched: the fixture names and `LIKE` needles in
  `tests/integration`, `mysql-test/suite/gcm`, `tests/e2e`, `tests/load/run.py`, `scripts/verify.sql`
  and the documents that quote them. Code comments were already English.

  Four stale code samples and two stale inventories were corrected rather than translated as-is, since
  propagating a sample that no longer matches the shipped code is worse than leaving it in Korean: the
  `mysql-component` and `sysvar-config` skills showed `gcm.strict` registered *before* the UDFs (it is
  after them, per A9); `sysvar-config`'s 8.0/8.4 branch showed the `g_strict` direct read fixed in #6
  and a `len >= 3` prefix match that reads "OFFLINE" as off; `e2e-load-tests` said 20 measured runs and
  a 1.2 gate against the real 40 runs and 1.10; the `ci-release` workflow table was missing `mtr`,
  `adapter` and `bench`; and `AGENTS.md` §3 said Phase 2 while §6 said Phase 4.

- **English is the first principle for everything committed**, stated once in
  `.agents/rules/docs.md` and referenced from `AGENTS.md` §9 and `CONTRIBUTING.md`, which each carried
  their own partial version of it. A document may carry a translation named `{document}-{LANG}.md`
  (`README-KO.md`), the English file is canonical, and the two change in the same PR — a translation
  that lags is a documentation bug rather than a second opinion. The allowance stops at two documents,
  `README.md` and `docs/design.md`, because each translation doubles the cost of every change to it;
  the agent rules, the skills and `spec/` are not translated.

  The rule also says explicitly that **Korean in tests and fixtures is data, not prose**: `'홍길동'`,
  `LIKE '%김%'`, `tests/load/run.py`'s `SURNAMES`, and the Korean cases across `tests/integration`,
  `mysql-test/suite/gcm` and `tests/e2e`. A language policy is exactly the kind of instruction that
  gets over-applied, and applying it there would delete the thing under test.

  This replaces the previous plan of a separate English *summary* at `docs/design.en.md`, which was
  never written and used a different naming scheme. `docs/design.md` is still Korean at this commit
  and flips to English with `docs/design-KO.md` beside it in the translation pass that follows.

- **A banner at the top of both READMEs**, stored as `docs/assets/banner.png`. It replaces the `<h1>`
  and the tagline line in `README.md`, since the image already carries both; `README-KO.md` keeps its
  Korean tagline below the banner, because the banner's text is English and a Korean reader would
  otherwise lose it. The alt text carries the tagline in each file's own language, so the page still
  reads correctly with images off or through a screen reader.

  Rendered at `width="720"` rather than full width. The source is 2560×1280, which is the 2x GitHub
  social-preview spec, and at full column width that 2:1 ratio would push the operational constraints
  — which `.agents/rules/docs.md` requires on the first screen — well below the fold.

- **`gcm.strict` is registered after the three functions, not before** (`docs/design.md` amendment
  A9). Registered first, a `udf_register` failure rolled back with the variable still in the server's
  dictionary pointing at `&g_strict` — in memory the loader is about to unmap, since `dlopen` gets
  `RTLD_NODELETE` only in ASan/LSan builds. The asymmetry that matters is **naming versus
  enumeration**: `udf_unregister` leaves a refused function in `udf_hash` under its real name, so a
  *new* session calling it also jumps into the unmapped segment, but a variable is reachable by
  `SHOW VARIABLES` without anyone naming it. Registering last makes that case structurally impossible
  on the failure path that can actually happen.

  The cost is a window inside `INSTALL COMPONENT` where the functions exist and the variable does not.
  A call landing there **fails closed** — verified from the server source in all three majors rather
  than assumed: the access returns an empty optional for an unregistered variable, `value_or(true)`
  makes it a failure, and `strict_enabled()` turns that into strict **ON**.
  `Suppress_not_found_error::YES` means it does not even push a spurious error into that session.

  Three of `tests/adapter`'s cases exist only for this change, and two more assertions strengthen a
  fourth: reverting the ordering fails them. The `sysvar_register`-fails path has its own case where a
  rollback unregister is also refused, so the resource-retention conditional on that path cannot be
  deleted unnoticed either.

### Documented
- `docs/design.md` amendment **A10 (proposed)**: AES-128-GCM and AES-192-GCM alongside AES-256-GCM.
  The suite is selected by key length and nothing else — 16/24/32 bytes — which buys API simplicity and
  gives up the chance to cross-check the intended suite against the key that arrived. Four new envelope
  version bytes (`0x04`–`0x07`), since `spec/envelope.md` §7 freezes the existing ones; the layout and
  the deterministic nonce label are unchanged.

  The amendment states the cost rather than burying it: today a truncated key fails loudly because 32
  bytes is the only valid length, and afterwards a 32-byte key truncated to 16 is a valid AES-128 key
  that `gcm_encrypt` will accept. A `gcm.min_key_bytes` sysvar defaulting to 32 is the recommended
  mitigation — it makes the feature opt-in rather than a silent weakening — but the choice is left open
  pending the security review A8 requires for anything touching key policy.

  Nothing is implemented. The amendment is the design decision and the sequencing note: this is 0.2.0
  work, after the 0.1.0 tag, because it bumps the spec version. The work breakdown and the open
  questions are issue #15.

  Four rationale errors from the first draft were corrected in review, and the conclusions survived all
  four. An explicit selector would **not** have forced a cross-call consistency rule, since FIPS 197
  fixes one key length per suite and a disagreeing pair is simply rejected — so the real trade-off is
  API simplicity against a lost cross-check, which is the truncation problem seen from the other side.
  Changing the nonce label would **not** break decryption, because A2 stores the nonce; it would break
  the reproducibility that JOIN and UNIQUE depend on. Different key lengths do **not** imply different
  nonce keys: RFC 2104 §2 zero-pads, so `K` and `K ‖ 0¹⁶` derive the same one, verified rather than
  argued. And a truncated key is **not** reliably caught on decryption — a writer and reader sharing the
  truncated key agree forever.

- `docs/design.md` amendment **A9**: on a failed install the loader `dlclose()`s the library, so any
  registration that survived a refused rollback points into an unmapped segment. This cannot be fixed
  from inside a component — no service asks the loader to keep the library mapped — so the amendment
  records what the reordering buys, what it does not, and that **an ASan build makes the wrong
  conclusion look right**, which is why the adapter suite keeps sanitizers off. It also records that
  `deinit` is deliberately **not** the mirror of `init`: both touch the variable last, because deinit
  must be able to refuse and put things back, and unregistering the variable first would leave a
  refused uninstall with no variable.

- **A `## Performance` section in both READMEs**, replacing the scattering of figures across the lead
  paragraphs. Two tables: server-side `gcm_decrypt(col) LIKE` p95 against the `AES_DECRYPT` baseline at
  1, 8 and 32 sessions, and what `gcm_encrypt_det` costs over `gcm_encrypt` at four plaintext sizes.
  Every number comes from the three `load` and three `bench` runs already recorded in `docs/perf.md`;
  nothing was re-measured for this. Each decrypt pair is taken from the **same** run — the slowest of
  the three — rather than assembled from the best of each, and the section says outright that the
  ratios travel to other hardware while the milliseconds do not.

### Added
- `tests/adapter` — the component's install and uninstall paths, driven against stub services. The
  layer the project was missing: `unit` covers the server-independent core, `smoke` and `mtr` cover SQL
  behaviour against a real server, and **nothing covered registration order, rollback, or what happens
  to the fetched algorithms when a rollback is refused** — the code where two defects escaped and were
  caught by review rather than by a test.

  Issue #7 deferred this on the grounds that the target could not exist, because `component.cc`
  includes server headers and `tests/unit` excludes them. That was wrong. Every source in `src/`
  compiles standalone with two include paths from a configured MySQL tree, so the suite runs inside the
  build image — `scripts/adapter-tests.sh <major>` — reusing the tree the component build already
  needs.

  No seam was added to shipped code, which `architecture.md` §6 forbids and
  `scripts/check-architecture.py` enforces. `REQUIRES_SERVICE_PLACEHOLDER` expands to an ordinary
  pointer, so the test points those at stub structs; `gcm_component_init`/`deinit` are reached the way
  the loader reaches them, through `mysql_component_t`; and whether the algorithms are live is read
  through the core's public API rather than a new accessor.

  Nineteen cases on 8.0 and 8.4, twenty on 9.x — the extra one asserts that the strict read asks for
  SESSION scope, which only exists where `GCM_HAS_SESSION_SYSVAR` compiles it. The suite runs on all
  three majors because that macro selects different code and needs a different stub set.

  **Two review rounds found seven ways the first version could not detect what it claimed to
  protect**, which is the most useful thing a review can find in a change that adds tests. Each is
  fixed and each now has a mutation that fails: `strict_enabled()` made to fail *open* instead of
  closed; reverting the locked read to a direct `g_strict` load, invisible while the stub answered with
  a constant; dropping `mac_deinit()` or the CBC free from `crypto_deinit()`, which a probe built only
  on `encrypt_random` could not see because `seal` checks one handle; removing deinit's
  `&& was_present` guard; and moving deinit's variable-unregister block to the front, which the cases
  could not see because they checked *which* calls happened and not their order.

  Three structural consequences rather than patches. The stubs model registration **state**, so a case
  asserts a function is gone instead of assuming it and `TearDown` checks rather than hopes. There are
  three handle probes instead of one, each through the narrowest public entry point that touches its
  handle — `derive_det_nonce` for the MAC, because `encrypt_det` derives and *then* seals and so
  reports the cipher handle's state. And ordering is asserted on the **whole call sequence**, because
  nothing weaker can see two calls swapped.

  Comments in this project have now twice claimed coverage that did not exist — the `!register_first`
  branch, and a `docs/design.md` statement I took from a review's list of caught mutations without
  running it. The testing rule says to verify mutations directly and not to believe such a claim.

  `adapter` is deliberately **not** a required check and is not a candidate while it is path-filtered:
  a filtered workflow does not report on a pull request that misses the filter, and a required check
  that does not report blocks the merge button indefinitely.

### Fixed
- **`gcm.strict` was read without synchronisation on MySQL 8.0 and 8.4.** `strict_enabled()` loaded
  `g_strict` — the byte handed to `register_variable` as the variable's storage — directly, while the
  server assigns into it from `update_func_bool()` holding `LOCK_global_system_variables`. That is a
  C++ data race, and the comment that defended it argued from practice ("one aligned byte cannot
  tear") rather than from the memory model, which is not the standard's position and not what a
  sanitizer build reports.

  It now reads through `component_sys_variable_register::get_variable()`, which takes the same mutex
  on the way to `sys_var::value_ptr` — where the server itself asserts ownership of it. That service
  method has existed since **8.0.11** and sits on a service the component already requires, so the fix
  costs no new dependency. `strict_enabled()` runs once per `UDF_INIT` — per statement rather than
  per row (architecture rule §5). That is a structural claim, not a measurement: the bench suite covers
  the server-independent core only, so nothing times this mutex acquisition, and a prepared statement
  or a stored routine pays it per execution.

  The two version branches stay separate rather than being unified on this one call: `get_variable()`
  returns the **GLOBAL** value on every version including 9.x, so using it there would silently ignore
  `SET SESSION gcm.strict` on the one major where session scope exists. 9.x keeps
  `mysql_system_variable_reader`.

  `g_strict` is now write-only from this component's side — it exists because `register_variable`
  needs somewhere to put the value. It stays a plain `bool` because it has to: the server performs a
  non-atomic store through that pointer, so declaring it `std::atomic<bool>` would not have removed
  the race, only hidden the evidence.

  Both read paths now share one `reads_as_off()` helper, so the fail-closed rule — anything that is
  not an explicit `"OFF"` leaves strict **on** — is decided in one place rather than twice.

  `tests/e2e/scenarios/strict_scope_global.py` gains a case where one session turns strict off and a
  *second session on the same server* decrypts. That pins the observable contract; it cannot prove a
  race is gone, and the scenario's docstring says so, but it would catch the read regressing to a
  cached or default value.
- **The component's init rollback freed cipher handles it might not have owned.** On a failed
  `udf_register`, `unregister_first()` discarded every `udf_unregister` result and `gcm_component_init`
  then called `crypto_deinit()` unconditionally — so a function that refused to unregister stayed
  callable while the `EVP_CIPHER` and `EVP_MAC` handles it uses were freed underneath it.
  `unregister_first()` reports whether everything is gone now, and the handles are released only when
  it is, which is the position `gcm_component_deinit` already took. Leaking them until restart is the
  lesser outcome.

  Reaching this needs `udf_register` to fail on a later function *and* an earlier one to be in use,
  which during `INSTALL COMPONENT` means a session that resolved a name registered moments earlier in
  the same init. Narrow enough that it has not been reproduced — it came out of review as a question,
  not a defect — and cheap enough that the asymmetry was not worth keeping.

  Review of this change found that the init rollback still discarded `sysvar_unregister()`'s result —
  the more reachable half of the same defect. A variable left in the dictionary points `&g_strict` into
  memory the loader has already `dlclose()`d, and **any** session reaches it with
  `SELECT @@global.gcm.strict`, where a dangling UDF needs a session that had resolved the name. Both
  results are checked now, and `register_first()` reports failure too, so the asymmetry review started
  from is closed in both directions.

  The same review showed the rationale first written here was wrong, by reading the loader. On a failed
  `INSTALL COMPONENT` the rollback unloads the library, and `dlopen` is given `RTLD_NODELETE` only in
  ASan/LSan builds (verified in the 8.4.11 tree) — so anything still registered points into an unmapped
  segment and its caller dies regardless of what happened to the cipher handles. Keeping them is about
  not adding a second fault to a broken install, not about preventing a crash, and the comment says
  that now. `gcm_component_deinit` is where the original reasoning does hold, because a refused
  `UNINSTALL` leaves the library mapped. An ASan build would have made the wrong claim look correct.

  Two things are deliberately left open and tracked in issue #7: there is no test for the branch that
  decides whether to release the algorithms, because forcing a service failure needs a target that can
  stub the component services and `component.cc` cannot be linked by `tests/unit`; and the underlying
  limitation — a registration that survives a failed install points into a library the loader has
  already unloaded — cannot be fixed from inside a component at all.

  `reads_as_off()` matches `len == 3` rather than a prefix: `>= 3` would have read a future `"OFFLINE"`
  or `"OFF (deprecated)"` as off, which is the one direction the helper exists to get right.

### Added
- `tests/bench` — micro-benchmarks for `gcm.cc`, `nonce.cc` and `envelope.cc`, run by
  `scripts/bench.sh` and by `bench.yml` on a merge to `develop` or `main` that touches the core, plus
  nightly. Deliberately **not** on pull requests: a benchmark on every PR is four minutes and a number
  nobody reads, and the regressions it catches are rare enough that minutes after the merge is soon
  enough. The cost is stated rather than hidden — such a change can land on `develop` before anything
  measures it, though it cannot reach `main` unnoticed, since `main` advances only by merging
  `develop` and the workflow runs on both. Built with sanitizers
  off at the optimisation level the component ships with, which is why it cannot live in
  `tests/unit`.

  The metric is a **ratio against a bare-OpenSSL equivalent measured in the same process**, the same
  trick `tests/load/run.py` uses against `AES_DECRYPT` one layer down: absolute nanoseconds from a
  shared runner are not comparable between runs, a ratio divides the machine out. The load suite can
  only resolve regressions of roughly 20% or more, cannot say *which* part got slower, and never
  measures a plaintext larger than a Korean name; this closes all three gaps in seconds and without
  a server.

  Every case asserts the operation succeeded, including the reference. An error path returns fast, so
  a benchmark without that check happily reports excellent numbers for code that does nothing — and a
  silently failing reference would make every ratio above it look like a regression.


  The gate is **1.10 on every case**, and that one number is the whole claim: this project's structure
  — envelope bytes, error mapping, buffer handling, `OPENSSL_cleanse` — must cost under 10% on top of
  the cryptography it performs. Three reference runs measured all twelve cases between 0.986 and 1.029
  with a 1.025x run-to-run spread, so it fails on a ~7% structural regression where the load gate
  cannot see anything under ~20%.

### Fixed
- **The documented workaround for the 8.x argument defect did not work.** `docs/ops-constraints.md`
  item 10, `docs/design.md` amendment A7 and both READMEs offered "a derived table" as a way to
  materialise a computed value before passing it to `gcm_encrypt*`. With the default
  `derived_merge=on` the optimizer merges the derived table's expression back into the outer query,
  so the argument is computed per row after all — the documentation was recommending a route straight
  into the defect it was warning about, and the result is silently sealing the wrong bytes.

  Measured on 8.4.11 with three rows: `FROM (SELECT CONCAT(nm, id) AS v FROM t) d` round-trips
  `1, 0, 0`; the same query with `/*+ NO_MERGE(d) */` or `optimizer_switch='derived_merge=off'`
  gives `1, 1, 1`, as does a real `CREATE TEMPORARY TABLE ... AS SELECT`. 8.0.46 and 9.4.0 do not
  reproduce this shape. The guidance is now "write it into a real table", with the two forced
  materialisation forms described as what they are: optimizer discretion that happens to work today.

  `tests/integration/91_server_udf_arg_defect.sql` scenario 4 pins all three forms per major, so the
  claim is a recorded measurement rather than a sentence. No existing expectation changed — scenario 3
  always used a real temporary table — and the suite passes on 8.0, 8.4 and 9.
- `tests/bench/gate.py` passed when measurements were **missing**. It checked only the rows present in
  the results file, so a run with every gated case absent — a build that produced nothing, a renamed
  benchmark, a stray `--benchmark_filter` — exited 0 with no ratios to check. Verified: a results file
  reduced to one nonce measurement returned 0 before, and now reports 12 violations. This is the mirror
  of the missing-ceiling check written beside it, which makes missing it the more annoying.
- Re-running an already-released tag would have failed in `package`. `anchore/sbom-action` defaults
  `upload-release-assets` to true, and on a tag push it looks up a release for that tag and attaches
  the SBOM if one exists. A first run finds nothing, because `publish` has not created the release yet
  — but a re-run finds it and tries to upload with the `contents: read` that job now has, after
  everything else has already succeeded. Both of the action's uploads are off now; the SBOM reaches the
  release through `dist/*` like every other file.
- `release.yml` could publish a GitHub Release after `manifest` failed. `package` created the Release
  and depended on `image` but not on `manifest`, so a failure while joining the per-architecture tags
  into the multi-arch tag — the one the README tells people to pull — still shipped six tarballs. That
  is the partial release SECURITY.md promises never happens, and the earlier fix for it stopped one job
  short. Publishing is now its own `publish` job behind `needs: [guard, manifest, package]`.

  Adding `manifest` to `package`'s `needs` would not have worked: `manifest` is conditional on
  publishing, and a skipped dependency skips the dependent, so every dry run would have stopped before
  packaging. `package` now always uploads the signed distribution as an artifact — on a dry run that
  artifact is the deliverable, and on a release it is what `publish` downloads, which is what lets
  publishing wait for `manifest` without rebuilding or re-signing anything.

### Changed
- `mtr` moved out of `integration.yml` into its own `mtr.yml`, so it can be path-filtered. It runs on a
  pull request that touches `src/**`, `mysql-test/**`, `spec/**` or the build tooling, and on a merge to
  `develop` or `main`. Measured runs take **49 to 63 minutes** — it compiles MySQL from source, because
  MTR needs a built `mysqld` and not the configured tree `build.yml` caches — and a documentation-only
  PR was spending one of them to validate a change that cannot affect it.

  It could not simply be filtered in place: `smoke (8.0|8.4|9)` live in the same workflow and **are**
  required checks, so a `paths` filter there would stop them reporting on an unrelated PR and leave the
  merge button blocked forever. The split is what makes the filter safe, and the rule now says so, as a
  general constraint rather than a note about this one job.

  Unlike `bench`, this is not moved to merge-only. MTR is the only gate that runs the component inside
  the server's own harness, which fails a test on an unexpected line in the error log — the reason
  `gcm_replication.test` has to call `mtr.add_suppression`. A crash during shutdown or a component that
  pollutes the log appears there and nowhere else, and for a change under `src/` that is worth the hour.

### Documented
- The READMEs, `CONTRIBUTING.md` and `AGENTS.md` had not caught up with the benchmark layer: the test
  tables, the layout trees and the script inventories all predate it. They list it now, and say that
  it runs on the merge rather than on a pull request so nobody looks for it in their checks.
- `CONTRIBUTING.md`'s clang-format command was broken twice over. It used
  `$(git ls-files ...)`, which zsh does not word-split — a contributor on the default macOS shell
  got `No such file or directory` — and which in bash would split a path containing a space into two
  arguments and silently skip both. It is now `git ls-files -z | xargs -0`, the form `lint.yml`
  actually runs, and it covers `tests/bench` as CI does. Verified by running the documented pipeline
  over all 24 files rather than trusting it.
- `docs/ops-constraints.md` item 6 and both README constraint lists now say that `gcm_encrypt_det`
  costs **3.5–5x a plain seal** and that decryption costs the same for either variant. The constraint
  previously covered only what determinism leaks, which left the cost to be discovered in production
  by whoever put it on a write-heavy column.
- `docs/design.md` records what the benchmarks answered — no measurable overhead on the decrypt path,
  under 10% structural cost on all three encrypt paths — and opens one question rather than burying
  it: `derive_nonce_key` is recomputed per call although it depends only on the key, and caching it
  requires keeping a copy of the key alive across rows, which is a `crypto-safety.md` decision and
  not a performance tweak.
- The pull request template asks whether `scripts/bench.sh --gate` was run, since the benchmark gate
  is no longer on the PR.

### Fixed before it shipped
- The first version of the metric measured the runner rather than the code. One reference — a bare
  seal — served all three encrypt cases, and three runs behind the same `ubuntu-24.04` label put a
  bare 64 KiB seal at 4,565 / 6,541 / 17,058 ns while `seal_det`'s ratio tracked that inversely at
  9.673 / 6.803 / 3.590. The fleet varies by **3.7x** on AES-GCM throughput; the absolute HMAC numbers
  over the same runs held to 1.15x. So the quotient was reporting how that CPU's SHA throughput
  compares to its AES throughput, not anything about this code. Each gated case now divides by a
  straight-line implementation of *the same algorithm*, which collapsed the spread to 1.025x and is
  what made a gate possible at all. Stated as a limit rather than glossed: all four runs with the new
  references landed on the slow end of the fleet, so the cross-architecture check — arm64, absolute
  times 2.2x apart, ratios within 0.965–1.029 — is what currently stands in for observing the metric
  across that 3.7x spread.

### Measured
- The **decrypt path adds nothing measurable** — `open` against an equivalent bare EVP decrypt is
  1.000–1.029 across three runs at every size. That is the path every row of a `LIKE` query takes.
- `gcm_encrypt` and `gcm_encrypt_det` likewise add nothing over a straight-line implementation of what
  they do: 0.986–1.019. There is no hidden per-call work — no fetch that stopped being cached, no
  buffer reallocated per row, no extra copy.
- **`gcm_encrypt_det` costs roughly 3.5–5x a *plain* seal, and the cost is HMAC rather than the
  cipher.** Two HMAC-SHA256 passes (`spec/envelope.md` §3) dominate at every measured size. Nothing in
  the documentation said the deterministic variant was several times the cost; `docs/perf.md` does now,
  which matters for anyone putting it on a write-heavy column.
- **The direction of that ratio with size depends on the CPU.** It fell 4.9 → 3.6 on the reference
  runs and *rose* 5.6 → 9.7 on a different `ubuntu-24.04` runner with faster AES: AES-GCM is
  hardware-accelerated nearly everywhere and SHA-256 often is not, so the balance is a property of the
  machine. "Several times a plain seal" is the durable statement.
- `gcm_encrypt`'s constant ~450 ns is `RAND_bytes(12)` — the price of a fresh nonce, ~3x on a 16-byte
  value and ~7% at 64 KiB.
- `envelope/parse` is ~2.2–3.1 ns and equal across v1, v2 and v3 — the invariant that case exists to
  hold, since parsing must never begin scanning the body.
- `derive_nonce_key` (830–1120 ns) depends on nothing but the key, yet `encrypt_det` recomputes it
  every call: around 40% of `seal_det` at small sizes. Caching it per `UDF_INIT` is a real saving and
  deliberately **not** taken here — the key is a per-row argument, so a cache must also hold a copy of
  the key, and keeping derived key material alive across rows is a `crypto-safety.md` question that
  belongs in `docs/design.md` before it belongs in `src/`. The measurement and the argument are in
  `docs/perf.md`.

## 0.1.0 — 2026-09-29

First release: the component builds, installs and passes every suite on MySQL 8.0, 8.4 and 9.x, and
the envelope format is frozen by `spec/envelope.md` and `spec/test-vectors.json`. Anything sealed by
this version stays readable by later ones — that is what a version byte is for, and v1 dual-read
already demonstrates the mechanism.

### Added
- Component implementation: `component.cc`, `udf_encrypt.cc`, `udf_decrypt.cc`, `udf_glue.{h,cc}`,
  `sysvar.{h,cc}` and the in-tree `src/CMakeLists.txt`. Registers `gcm_encrypt`, `gcm_encrypt_det`
  and `gcm_decrypt` through the `udf_registration` service, tags the decrypted result `utf8mb4`
  through `mysql_udf_metadata`, and registers `gcm.strict` through
  `component_sys_variable_register`. Installation rolls back on any partial registration.
- Build tooling: `docker/build.Dockerfile` (a cached, configured MySQL source tree per major),
  `docker/versions.json`, `docker/build-component.sh`, `scripts/build-in-docker.sh`.
- Local verification: `scripts/dev-up.sh`, `scripts/verify.sh`, `scripts/verify.sql`.
- Integration suite `tests/integration/` — ten scenarios, recorded and reviewed per major.
- MTR suite `mysql-test/suite/gcm/` — signature, envelope, Korean LIKE, strict semantics, NULL and
  boundary sizes, v1 dual-read, and ROW-binlog replication.
- E2E suite `tests/e2e/` — compose primary + replica + a SQL-only Python runner, six scenarios.
- Load harness `tests/load/run.py` with the gate in `tests/load/baseline.json`. The documented promise
  is p95 within 1.2x of `AES_DECRYPT` and under 1s at the largest row count serially; the enforced
  regression gate is 1.10x, derived from the measured baseline in `docs/perf.md`.
- `scripts/mtr.sh` to build the server in a container and run the MTR suite, with `GCM_RECORD=1`
  for regenerating `.result`.
- `.clang-format`: the MySQL 8.4 config with `ColumnLimit` raised to 100 to match this codebase.

### Fixed
- `tests/unit/CMakeLists.txt` never called `enable_testing()`, so no `CTestTestfile.cmake` was
  written and `ctest` reported "No tests were found" **while exiting 0** — the unit gate in CI was
  passing without running anything. All 1400 tests run now.
- Two GoogleTest fixtures were both named `DetVector` (in `gcm_test.cc` and `nonce_test.cc`), which
  aborted the whole binary at startup with "Attempted redefinition of test suite". The nonce one is
  now `DetNonceVector`.

### Released
- **License is GPLv2** (`GPL-2.0-only`), settled rather than pending: `LICENSE` carries the full text,
  sources carry an SPDX header, and `docs/design.md` §7 records why GPLv2 is the compatible choice for
  something that links the server's GPLv2 headers.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) and `.github/CODEOWNERS`.
- Release pipeline: a tag `v*` on `main` builds 3 majors × 2 architectures, publishes the tarballs,
  `SHA256SUMS` and an SBOM to a GitHub Release, and pushes `mysql-gcm-server` images to Docker Hub —
  an official `mysql` image per major with the component preinstalled and installed on first start
  (`docker/server.Dockerfile`). Multi-arch tags `<version>-mysql<major>` and `mysql<major>`.
  Tests still use unmodified official images, so no gate depends on that release image.

### Fixed in review
- `gcm_encrypt*` sized its result field from the argument's *pre-conversion* length. The plaintext
  argument is requested as utf8mb4 and the server widens it first, so a latin1 `VARCHAR(1)` holding
  `é` reports `lengths[0] = 1` while the envelope is 31 bytes. Materialising that result failed with
  `ER_DATA_TOO_LONG` under strict SQL mode and, without it, **stored a 30-byte truncated envelope
  that no longer authenticates** — warning 1265 was the only signal. Every charset spends at least
  one byte per character, so the declared width is now `4 × lengths[0] + 29`; both SQL modes are
  pinned in the integration and MTR edge cases.
- `gcm_encrypt*` sized its result field as `args->lengths[0] + 29`, but the server narrows
  `initid->max_length` with `min<uint32>(...)`, so a LONGTEXT argument (4294967295) wrapped to 28 —
  below the 29 byte minimum envelope. `CREATE TABLE ... AS SELECT gcm_encrypt(longtext_col, @k)`
  failed with `ERROR 1406 Data too long`, and in a non-strict SQL mode it would have truncated
  silently. `envelope_max_length()` now saturates.
- `seal()` passed `ct + len` to `EVP_EncryptFinal_ex`, where `len` had been overwritten by the AAD
  pass with the AAD length. With an empty plaintext and an AAD longer than the tag the pointer was
  past the end of the output buffer. GCM's Final writes nothing, so nothing was corrupted, but the
  AAD length is caller-controlled and the invariant is now restored with a separate counter.
- `gcm_encrypt_det` now declares `const_item`, so `WHERE indexed_col = gcm_encrypt_det('x', @k)`
  becomes an index lookup (`type=const`) instead of a scan — the point of the deterministic variant.
  `gcm_encrypt` keeps `const_item = false`; it draws a fresh nonce per call.
- Argument lengths are bounded before any envelope arithmetic, with a length-specific error.
- `integration.yml` and `e2e.yml` downloaded the component from `build.yml`, which
  `actions/download-artifact@v4` cannot do across workflow runs — both gates would have failed to
  find the artifact. Each workflow now builds the component itself; the configured server tree is a
  cached image, so that is cheap. `release.yml` had the same flaw.
- `load.yml` ran `scripts/verify.sh`, which uninstalls the component on the way out, and then called
  the functions. It now reinstalls and passes the container's port through.
- The nightly 1,000,000-sample deterministic-nonce collision run was configured on the load job,
  which never runs the unit binary, so it ran nowhere. It is a scheduled `unit.yml` job now.
- `e2e.yml` switched only the component when a different MySQL major was selected, leaving the server
  image at the 8.4 default — so a 9.x build was being tested against an 8.4 server. The server image
  now comes from `docker/versions.json` for the selected major.
- `release.yml` packaged a single architecture from one runner, dropping arm64 from the release. It
  now builds a (major × arch) matrix and the packaging job asserts that six archives were produced.
- `OpenVector` in the unit suite never consumed the deterministic vectors, so their decryption path
  was unverified even though `spec/envelope.md` §6 requires it for every `ok` vector.
- `docker/versions.json` carries the source tarball SHA-256 and the compiler each server tree
  expects; the Dockerfile verifies the tarball and takes the toolset as a build argument.

### Documented
- `docs/design.md` amendment A5: `gcm.strict` has SESSION scope only from MySQL 9.0.0. Component
  sysvars ignore `PLUGIN_VAR_THDLOCAL` before that and reading a session value has no service, so the
  variable is registered GLOBAL-only on 8.0 and 8.4.
- `docs/design.md` amendment A7: MySQL 8.0 and 8.4 corrupt some *computed* string arguments to a
  loadable function from the second row of a statement onward. Callers must pass a stored value;
  `tests/integration/91_server_udf_arg_defect.sql` pins the behaviour per version.
- `docs/design.md` §8: the Phase S questions are answered on real servers — Korean `LIKE` works
  through the charset tag on all three majors (so `decrypt_like` is not needed), and
  `Created_tmp_disk_tables` did not increase.
- `docs/design.md` amendment A8 and `spec/envelope.md` §2.3: deployment topology. ROW binlog carries
  ciphertext, nonce and tag as bytes and a replica never re-encrypts, while `INSTALL COMPONENT` is
  *not* replicated — both now asserted in `gcm_replication.test`, which also shows the primary and
  replica diverging under `binlog_format=STATEMENT`. Sharding guidance (route on a stable identifier,
  one AAD convention per key across shards, no re-encryption when moving rows) is exercised by
  `tests/e2e/scenarios/cross_shard_determinism.py` against an independent second server.
- `spec/envelope.md` §2.3: a v1 envelope's plaintext MUST already be UTF-8. `gcm_decrypt` tags every
  result `utf8mb4`, and a v1 envelope never went through the converting encryption path, so a latin1
  `Müller` returns ill-formed and `LIKE '%ller%'` yields 0 with no error. Pinned in both the
  integration and MTR dual-read cases, together with the correct migration.

### Release tooling
- `release.yml` refuses to publish unless the tag is `vMAJOR.MINOR.PATCH`, the tagged commit is
  contained in `main`, and `CHANGELOG.md` has a section for that version. A `workflow_dispatch` dry
  run executes the identical pipeline and publishes nothing, so the release path is exercised before
  a tag exists rather than debugged in public with a tag already pushed.
- Each server image is started and queried before it is pushed (`scripts/smoke-image.sh`: the
  component is installed by the init script, a Korean `LIKE` over a decrypted value hits, the result
  is `utf8mb4`, strict is ON). The suites run against unmodified official images on purpose, so
  nothing else in CI would catch a `.so` installed into the wrong `plugin_dir` or paired with the
  wrong server major.
- `SHA256SUMS` is signed with keyless cosign and verified in the same job. Verification checks which
  workflow in which repository produced the checksums; there is no long-lived key to hold or leak.
  `CONTRIBUTING.md` and both READMEs carry the `cosign verify-blob` invocation.

### Fixed before release
- The unit suite did not compile under GCC: `-Wdangling-reference` fires on
  `const Vector &v = vector_by_id("id")` because the parameter was a `const std::string &` and GCC
  cannot prove the returned reference does not point into the temporary bound to it. With `-Werror`
  that is fatal, and the whole gate was only ever verified under clang on a developer machine.
  `scripts/unit-in-docker.sh` now runs the suite under GCC in a container, which is what CI does.
- `gtest_discover_tests` timed out. Static initialisation parses 783 vectors under ASan — about 24 s
  before `main()` — and discovery pays that once to list the tests and again per case, for 1434
  cases. One `ctest` entry runs the binary once instead: the whole suite in ~41 s.
- Integration failed against a freshly initialised server on 8.4 and 9. While the official image
  initialises an empty data directory it starts a *temporary* server that listens on the socket only,
  so `mysqladmin ping` over the socket reported healthy, the component was installed into that
  server, and the entrypoint then stopped it and started the real one. The healthcheck goes over TCP,
  which excludes the temporary server by construction, and `dev-up.sh` additionally waits for a query
  to answer. It passed locally for weeks because the containers were already initialised.
- The load harness measured every GCM session and then every AES session, so a slow period on a
  shared runner landed on one variant and surfaced as a ratio: the nightly reported 1.247 at eight
  sessions while one and thirty-two sessions were near 0.84. The variants are interleaved per
  iteration on one connection now, under the same ambient load and contention.
- `develop` was absent from the CI push triggers, so a maintainer push — which the branch protection
  deliberately allows — reached it ungated.

### Supply chain
- Every action in every workflow is pinned to a commit SHA with the tag in a trailing comment,
  which the `stack-ci-docker` rule already required and a `TODO` in `build.yml` admitted was not
  done. A tag reference is whatever the owner last pointed it at, and an action runs with this
  workflow's token — in `release.yml`, next to the OIDC identity that signs the artifacts consumers
  verify. `scripts/check-action-pins.py` enforces it and rejects a SHA with no version comment.
- `lint.yml` gained a `workflows` job: the pin check plus actionlint, from a digest-pinned image.
  Nothing had been checking the workflow files, so an expression that was syntactically fine and
  semantically wrong first surfaced as a failed run on the branch it was meant to guard.

### Fixed in pre-release review
- `release.yml` could publish a **partial release**. The `image` matrix pushes each architecture tag
  as it finishes and `fail-fast: false`, while `package` depended only on `build` — so one failing
  entry left some `<version>-mysql<major>-<arch>` tags public, no joined multi-arch tag, and a full
  GitHub Release with six tarballs, contradicting SECURITY.md's "never as a partial release".
  `package` now needs `image`, so nothing appears under a documented name unless every image built and
  passed `scripts/smoke-image.sh`. The trade is deliberate: a Docker Hub outage now fails the release
  instead of degrading it, because re-running a tag is cheap and un-publishing is not. The
  per-architecture tags are documented as components of the multi-arch tag, and a failed attempt can
  leave some behind — delete those before re-running the tag.
- The guard's version check accepted `0.1.0-rc1`, `1.2.3.4` and `1abc.2.3`: a shell glob of
  `[0-9]*.[0-9]*.[0-9]*` constrains almost nothing. A prerelease tag would have shipped as a normal
  release and moved the rolling `mysql<major>` tag onto it. It is `^[0-9]+\.[0-9]+\.[0-9]+$` now.
- The CHANGELOG gate could be satisfied by the wrong section. `grep "^## ${version}\b"` treats `-` as
  a word boundary, so a search for `0.1.0` matched `## 0.1.0-rc1`. The delimiter is explicit now, and
  the version's dots are escaped rather than matching any character.
- `${{ inputs.version }}` was interpolated into a `run:` script, where it is substituted as text before
  bash parses it — `-f version='x"; id; #'` would have executed in the guard job. It arrives through
  the environment now and is validated, which also keeps an empty or slash-bearing value from reaching
  an archive name, an artifact name and an image label.
- The documented `cosign verify-blob` identity matched the repository alone, so it accepted anything
  this repository ever signed — including a dry run, which signs with the same OIDC identity at a
  branch ref and uploads the result as a public build artifact. Consumers now verify
  `…/.github/workflows/release.yml@refs/tags/v`, and the workflow's own check uses the form matching
  the run it is in.
- `SHA256SUMS` did not cover `sbom.spdx.json`: the checksums were computed before the SBOM existed.
  Since `SHA256SUMS` is the only signed file, anything outside it was unsigned.
- `scripts/check-action-pins.sh` only matched `uses:` when a `-` began the line, so
  `- { uses: actions/checkout@v4 }` passed unexamined — in a repository that uses flow style
  throughout. It is `scripts/check-action-pins.py` now: it reads every `uses:` regardless of style,
  covers `.yaml` as well as `.yml`, accepts a `docker://…@sha256:` digest, and fails when it finds no
  references at all rather than reporting success for a wrong path. Verified against flow-style
  violations of both kinds.
- `scripts/smoke-image.sh` claimed to check that the `.so` matches the server in the image but never
  looked at the server version, so a `docker/versions.json` entry mapping a major to the wrong image —
  paired with a `.so` built for that same wrong image — would have passed and published, say, an 8.4
  server as `mysql9`. It takes the expected major and compares `VERSION()`. It also sets
  `--default-character-set=utf8mb4`, without which the Korean literal in the smoke query tested the
  container's locale rather than the component.
- `p95` was the maximum. `int(len * 0.95)` is one rank too high, and at 20 samples per session that is
  the last index — so the reported p95 at one session was the worst single request of twenty, and a
  gate set close to the measured value would have failed whenever one request happened to be 15% slow.
  It is the nearest-rank percentile now, `ceil(0.95n)`.
- The interleaved harness still ran GCM first within every pair, handing one variant whatever the other
  had just warmed or evicted on every iteration. The order alternates.
- `tests/e2e/compose.yml` had no `start_period`, so the retry budget for a TCP healthcheck — which,
  unlike the socket ping it replaced, answers nothing until initialisation finishes — was 30 x 2s for
  four servers starting at once. Compose aborts the run as soon as a dependency goes unhealthy and
  does not wait for recovery.
- `CONTRIBUTING.md` listed "eight `lint` jobs" and claimed 18 required checks; `lint.yml` has seven,
  and the eighteenth is `vectors` from `unit`, which was not mentioned. It now names every required
  check as GitHub reports it, and lists `mtr` among the deliberate exclusions.
- `SECURITY.md` said downgrading is always safe on the data. `spec/envelope.md` §2.4 requires an
  unknown version byte to be rejected, so a downgrade past a release that added one makes those
  envelopes unreadable. Upgrading is the direction that is guaranteed.
- The `unit-tests` skill still offered `gtest_discover_tests` as its CMake pattern, which is what this
  release removed for timing out CI, so the next person following the skill would have reintroduced it.
- No workflow declared a `concurrency` group, so every push to a PR started another `mtr` job — an
  hour-plus MySQL build — without cancelling the superseded one. Four pushes meant four concurrent
  server builds. PR runs now supersede; pushes to `main`, to `develop`, and tag runs never cancel, and
  `load` keeps none so baseline runs can be dispatched in parallel.

### Settled after re-measuring
- The release baseline is three CI runs at **40 samples per session**, not 20. p95 of 20 samples is
  rank 19 of 20, so it tracks whichever single request was unluckiest: three runs put the one-session
  ratio between 0.809 and 0.928, a 1.19x spread. At 40 samples the same axis spreads 0.799–0.947 and
  the 8- and 32-session axes — which accumulate 320 and 1280 samples — settle to 1.06x and 1.04x.
- The enforced gate is **1.10x**, not 1.05x. 1.05 would have sat 11% above the worst of nine
  observations, on the axis with the fewest samples; 1.10 clears it by 16% and still leaves the 1.2x
  promise with room. `docs/perf.md` carries the table and the reasoning, and the testing rule states
  the promise and the gate as two separate things so nobody has to reconcile them.
- The release dry run earned its place twice more. It caught `package` collecting every artifact in the
  run — including the `*.dockerbuild` records that `docker/build-push-action` uploads, one of which
  failed to download and killed a release whose six components had all built and passed their smoke
  tests. Reachable only once `package` started waiting for `image`, which is to say only after the
  partial-release fix. It now downloads `component_gcm-mysql*` and the image job produces no records.
- Verified on the final dry run rather than asserted: `package` starts after all six `image` jobs,
  `SHA256SUMS` covers the SBOM, every checksum matches, and the documented `cosign verify-blob`
  command **rejects** a dry run's artifacts — the certificate names `@refs/heads/...`, so only a tag
  run satisfies the identity consumers are given.
