# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a cryptographic or data-integrity flaw.**

Use GitHub's private vulnerability reporting on this repository:
[Report a vulnerability](https://github.com/devgyurak/mysql-gcm/security/advisories/new).
If that is not available to you, email **dev@devgyurak.com**.

Please include:

- the MySQL version (`SELECT VERSION()`) and how the component was installed,
- the envelope version byte involved (`0x01`, `0x02` or `0x03`),
- the shape of the failing statement, and whether the argument was a column, a literal, a
  user variable or a bound parameter — `docs/design.md` amendment A7 explains why that matters,
- whether `gcm.strict` was ON or OFF.

**Never send a real key or real plaintext.** Reproduce with the public fixture key from
`spec/test-vectors.json` (`000102…1f`). If a report cannot be reproduced without production data,
describe the shape instead and we will work out a fixture together.

## What is in scope

- Returning plaintext that was not authenticated, in any code path.
- Key, plaintext, nonce, tag or ciphertext bytes reaching an error message, a log, or an assertion.
- Nonce reuse, or any way to make the deterministic variant produce a colliding nonce for different
  plaintexts under one key.
- Storing an envelope that cannot be decrypted afterwards — truncation, charset conversion, or
  argument marshalling that seals bytes other than the ones supplied.
- A crash, hang or memory-safety fault in the server caused by the component.
- Failure semantics that disagree with `spec/envelope.md` §4, including `gcm.strict=OFF` hiding a
  malformed envelope or a wrong key length.

## What is already known and documented

These are recorded in `docs/ops-constraints.md` and are properties of the approach, not
vulnerabilities to report:

- Keys and plaintext travel as SQL arguments, so they can reach the general log, the slow log,
  `performance_schema` and a statement-based binlog — the same exposure as `AES_ENCRYPT` (item 2).
- `gcm_encrypt_det` reveals equality, frequency and length of plaintexts (items 6 and 13).
- Legacy `0x01` envelopes are unauthenticated by construction, and their plaintext must already be
  UTF-8 (item 8).
- MySQL 8.0 and 8.4 corrupt some *computed* string arguments to a loadable function. This is a server
  defect, pinned per version by `tests/integration/91_server_udf_arg_defect.sql`; the documented
  answer is to pass a stored value (item 10).
- The component does not detect nonce reuse, enforce a cross-call AAD policy, or track key usage
  (items 11 to 13).

## Supported versions

Fixes go to the tip of `main` and to the latest release line, which is `0.1.x`. There is nothing
older to support.

A component is built per MySQL major, so a fix is not available to you until the artifact for *your*
major is republished: a security patch ships as a new tag with all six tarballs and all three Docker
tags rebuilt, never as a partial release. Verify what you install —
`cosign verify-blob` over `SHA256SUMS`, as in [CONTRIBUTING.md](CONTRIBUTING.md#cutting-a-release).

Downgrading is always safe on the data: the envelope carries a version byte, and no release removes
the ability to read an envelope an earlier release wrote (`spec/envelope.md` §2).

**This component has not had an independent cryptographic review** (`docs/ops-constraints.md` item
13). Treat that as the headline caveat when deciding whether to deploy it.
