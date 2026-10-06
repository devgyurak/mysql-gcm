<!-- Generated from .agents/rules/code-review.md by scripts/agents-sync.py — edit the source. -->
# Code review rules

A review asks first whether the change can return the wrong plaintext, leak a key, or kill the server.
Style comes last.

## Priorities (every comment must carry a prefix)
| Prefix | Meaning | Handling |
|---|---|---|
| **P1** | Blocks the merge. Correctness, security, server stability or data compatibility is broken | Cannot merge until resolved. To push back, the author needs evidence and the reviewer's agreement |
| **P2** | Should be resolved before merge. Maintainability, a missing test, a document that disagrees | Resolve as a rule. To defer, leave the issue number in the comment |
| **P3** | Optional. Style, naming, taste | The author's call. May be resolved without a reply |
| **Q** | Question. Checking understanding | After the answer, promote to P1–P3 if warranted |

- Comment format: `P1: <what is wrong and why>. Repro: <conditions>. Suggestion: <code or direction>`.
  "This looks off" is not a review comment.
- An approving comment states what the reviewer actually ran and verified ("confirmed verify.sh passes
  in the 8.4 container").

## Flow
1. Author self-review: read the diff from start to finish and fill in the PR template checklist. Do
   not request review while a box is blank.
2. Automated review (the `code-reviewer` agent, plus `crypto-reviewer` on a crypto path): a
   prerequisite **before** human review, not a substitute for it.
3. Human review: one reviewer for an ordinary PR. Two for the crypto, envelope and sysvar paths
   (`src/gcm.cc`, `envelope.cc`, `nonce.cc`, `sysvar.cc`, `spec/`).
4. Merge conditions: CI green + the required approvals + zero open P1 + zero P2 that has not been
   explicitly deferred.

## Reviewer checklist (the automated reviewers work through it in this order)
**Correctness (P1)**
- [ ] Envelope offsets and length arithmetic match `spec/envelope.md` (off-by-one, the version byte)
- [ ] The tag-failure path discards the output buffer and honours the strict semantics
- [ ] The 32-byte key check runs on every call
- [ ] NULL, empty-string and maximum-length arguments are handled
- [ ] Result charset tagging (`gcm_decrypt`) / BLOB (`gcm_encrypt*`)
- [ ] A session sysvar is actually read as the session value

**Safety (P1)** — grep for the blocked patterns in `crypto-safety.md`, check for keys or plaintext in
logs, check that memory is cleansed

**Server stability (P1)** — safe under concurrent calls, no exceptions, init rolls back on failure, no
leak in deinit (is an ASan/valgrind log attached?)

**Architecture (P1/P2)** — check the dependency direction, where SQL policy lives, resource lifetimes
and the version boundary against `architecture.md`. `python3 scripts/check-architecture.py` passes, and
there is no experimental crypto bypass. Confirm indirect dependencies and any new test entry point in
the code.

**Tests (P2)** — GWT followed; no logic or branching (`if`, `else`, `for`, `while`) added inside a test
case body; unit and integration tests together; vector file updated; the Korean `LIKE` case still
present; any `.result` change is intentional

**Compatibility (P1/P2)** — a change to the envelope, a function signature or a sysvar changes the
server tests, `spec/` and the docs in the same PR; service availability per MySQL version

**Documentation (P2)** — no conflict with a decision in `docs/design.md`; any effect on the operational
constraints (§6) is reflected in the README

**Style (P3)** — the conventions in `stack-*.md`

## PR size
- Over 400 net lines, ask for a split (excluding `.result` files and vector JSON). Do not mix a
  refactor and a behaviour change in one PR.
