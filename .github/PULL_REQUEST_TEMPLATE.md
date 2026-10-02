## What / Why
<!-- one paragraph; link design.md section if this touches a decision -->

## Scope
- [ ] Net diff ≤ 400 lines (excluding `.result` / vectors), single concern
- [ ] Touches crypto path (`src/gcm.cc` `envelope.cc` `nonce.cc` `sysvar.cc` `spec/**` vector generation) → 2 human reviewers + `crypto-reviewer` report attached

## Correctness & safety (P1 items — reviewer blocks on these)
- [ ] Envelope offsets/lengths match `spec/envelope.md`
- [ ] Tag failure discards output; `gcm.strict` semantics preserved (ON=error, OFF=NULL)
- [ ] Key length 32 checked per call; no key/plaintext in logs, errors, asserts
- [ ] Only `EVP_CIPHER_fetch` / `EVP_MAC_fetch` by name; no static OpenSSL
- [ ] Resource ownership/lifetimes follow `architecture.md`; init rolls back and failed deinit remains safe to retry
- [ ] Core dependency boundaries preserved; no SQL exposure of test seams or experimental crypto bypass

## Tests (GWT)
- [ ] Unit tests added/updated, Given-When-Then in name and body
- [ ] No added control flow (`if`, `else`, `for`, `while`) in test case bodies; use separate or parameterized cases
- [ ] Integration/MTR case added; `.result` / `.expected` diffs explained below
- [ ] `spec/test-vectors.json` updated if envelope/nonce changed; C++ vector tests updated and generator `--check` passes
- [ ] Korean partial-match case (`LIKE '%길%'`) still present
- [ ] Touches `src/**`? `scripts/bench.sh --gate` run locally — the benchmark gate runs on the
      merge to `develop`, not on this PR, so this is where a structural regression gets caught early

## Compatibility & docs
- [ ] Function surface / sysvar / envelope unchanged, or `docs/design.md` + `spec/` + server tests updated here
- [ ] README ops constraints (design §6) still accurate

## Verification run locally
```
python3 scripts/check-architecture.py →
ctest --test-dir build/unit          → 
scripts/verify.sh 8.4                → 
```
