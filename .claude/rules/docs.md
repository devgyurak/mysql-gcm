---
paths:
  - "docs/**"
  - "spec/**"
  - "README.md"
  - "README-KO.md"
---
<!-- Generated from .agents/rules/docs.md by scripts/agents-sync.py — edit the source. -->
# Documentation and spec rules

## Language

**English first.** Code, comments, commit messages, PR descriptions, documents and specs are written
in English. This is an open-source project: someone who does not read Korean has to be able to use it,
review it and contribute to it from the repository alone.

A document **may** carry a translation for the convenience of developers who prefer another language.
A translation is named `{document}-{LANG}.md` beside the original — `README-KO.md`,
`docs/design-KO.md` — where `{LANG}` is the ISO 639-1 code in **uppercase**, the spelling
`README-KO.md` already established. Keep the language links at the top of translated documents so each
one points at the others.

- **The English file is canonical.** Where the two disagree the English one is right and the
  translation is what needs fixing. A translation is never a second opinion on a decision.
- A translation changes **in the same PR as its original**. One that falls behind is a documentation
  bug, and the lag is invisible until someone acts on the stale half.
- Only two documents are translated, because each one doubles the cost of every change to it:
  `README.md` (the front door) and `docs/design.md` (the rationale). Do **not** translate the agent
  rules, the skills or `spec/`. The allowance exists for human readers; rules and skills are consumed
  by tools, and `spec/` is normative, where two wordings of one byte layout is a defect waiting to
  happen.
- Conversation with the user is in Korean (`AGENTS.md` §9). That is a separate matter from what gets
  committed, and this rule does not change it.
- **Korean in tests and fixtures is data, not prose, and is never translated**: `'홍길동'`,
  `LIKE '%김%'`, `SURNAMES` in `tests/load/run.py`, the Korean cases in `tests/integration`,
  `mysql-test/suite/gcm` and `tests/e2e`. Partial-match search on an encrypted Korean column is why
  this project exists (`testing.md`). Translating those strings would delete the thing under test.

## Documents

- `docs/design.md` is the source of rationale. Where the code and that document disagree, either the
  code is wrong or the document has to be amended first. The §8 "confirmed / unconfirmed" table is
  updated whenever a fact is established, with a link to the evidence.
- README first-screen order: one-line summary → **operational constraints (all of design §6)** →
  support matrix → install → function table. The constraints do not get moved further down.
- `spec/envelope.md` is implementation-language neutral: a byte-offset table, a failure-semantics
  table, and worked hex examples. An implementer must be able to build from that document alone.
- `spec/test-vectors.json` schema:
  `{ "version": 1, "vectors": [ { "id", "kind": "random|det|nist", "key_hex", "nonce_key_hex"?, "nonce_hex"?, "aad_hex", "plaintext_hex", "envelope_hex", "expect": "ok|bad_tag|bad_envelope" } ] }`.
  Adding a field is a minor change; changing the meaning of one is major.
- The license is **settled as GPLv2** (2026-09-28, design §7): full text in `LICENSE`,
  `SPDX-License-Identifier: GPL-2.0-only` in every source file, and a link to `LICENSE` from both
  READMEs. The phrase "pending legal review" is no longer used anywhere. Changing the license means
  amending design §7 first.
