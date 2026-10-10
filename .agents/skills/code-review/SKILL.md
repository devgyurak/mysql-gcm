---
name: code-review
description: Reviewing a PR or diff in this repository against the P1/P2/P3 priorities and the reviewer checklist, in order, and reporting in the prescribed format. Use it for "review this", for PR review, and for a self-review request.
---

# code-review

The rule source is `.agents/rules/code-review.md`. Do not reorder the checklist: correctness → safety →
server stability → architecture → tests → compatibility → documentation → style.

## Procedure
1. Fix the scope: `git diff --stat <base>...HEAD`. Over 400 net lines, ask for a split as the first
   comment (P2) and carry on reviewing.
2. If a changed file touches a crypto path (`src/gcm.cc`, `envelope.cc`, `nonce.cc`, `sysvar.cc`,
   `spec/**`, `scripts/gen-vectors.py`), **the parent agent running this skill** starts both
   `code-reviewer` and `crypto-reviewer` and merges the two reports. This repository's reviewers are
   configured not to delegate further, so do not expect this step to happen inside `code-reviewer` —
   when its report says `NEEDS: crypto-reviewer`, the parent runs it.
3. Automated checks, using `rg`, with the scope separated per language. Exit codes: **0 = a match
   (P1 candidate) / 1 = no match (pass) / 2 = the search failed (report it as "check failed", which is
   not a pass)**.
   ```
   python3 scripts/check-architecture.py
   # C++ (src/, tests/unit/): legacy OpenSSL symbols, non-crypto randomness, a key in a std::string, log bypasses
   rg -n --type cpp -e 'EVP_aes_' -e '\bHMAC\(' -e '\b(s?rand)\(' -e 'std::string\s+\w*key' -e 'printf[^;]*key' -e 'general_log|log_raw' src tests/unit
   # Python (scripts/, tests/): primitives outside the allowed library (cryptography's hmac.HMAC is allowed)
   rg -n --type py -e '^\s*(from|import)\s+(Crypto|Cryptodome|nacl|hashlib)\b' -e 'random\.(random|randint|getrandbits)' scripts tests
   ```
   `check-architecture.py` is 0 = pass, non-zero = fail. The 0/1/2 reading above applies to `rg` only.
   For each match, look at the file and line, decide whether it is actually a rule violation, and only
   then raise it as P1 — a match inside a comment or a documentation string, for instance, is not one.
4. Read the diff against each checklist item and record only defects that come with **reproduction
   conditions**. Speculation is a `Q`.
5. Tests: does each changed function have a corresponding test, is it in GWT form, and is every
   `.result` / `.expected` change explained?
6. Run what you can: `ctest --test-dir build/unit`, `scripts/verify.sh 8.4`. Put the results in the
   report, or say "not run".

## Report format
```
## Review: <PR title or branch>
Ran: unit ✅ / verify.sh 8.4 ✅ / crypto-reviewer ✅ (or the reason each was not run)

P1 (N)
- src/envelope.cc:42 — tag offset uses ct_len instead of env_len-16. Repro: a 1-byte plaintext det
  envelope reads one byte past the buffer. Suggestion: `env.size() - kTagLen`.
P2 (N)
- tests/unit/gcm_test.cc — the new `open_v1` function has no test (testing.md, unit section).
P3 (N)
- ...
Q (N)
- ...
Verdict: BLOCK (a P1 exists) | APPROVE-WITH-P2 | APPROVE
```
File:line, what and why, reproduction, suggestion — do not file a comment missing any of the four.
