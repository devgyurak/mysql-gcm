# MySQL GCM encryption functions (component) — design and procedure

> **Language.** English · [한국어](design-KO.md)
>
> This is the canonical document. [`design-KO.md`](design-KO.md) is its Korean translation and follows
> it; where the two disagree, this file is right (`.agents/rules/docs.md`). Changing the design changes
> both documents in the same PR.

> ## Amendment A10 (2026-10-06) — AES-128-GCM and AES-192-GCM
>
> **Status: AES-128 implemented; AES-192 allocated and not implemented.** `0x04` and `0x05` ship,
> `gcm.min_key_bytes` ships with the recommended default of 32, and `spec/envelope.md` is at v2.
> `0x06` and `0x07` stay reserved and are rejected as `bad_envelope`. The NIST CAVP KAT is imported
> for both suites: 750 AES-256 cases (191 authentication failures) and 750 AES-128 (196).
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
> **Sequencing.** This lands after 0.1.0 is tagged, as 0.2.0. The envelope is frozen for 0.1.0 and the
> release pipeline has been dry-run against it; adding version bytes is backward compatible — every
> 0.1.0 envelope still decodes, and a 0.1.0 component rejects `0x04`–`0x07` with `bad_envelope` as
> `spec/envelope.md` §2.4 requires — but it is a spec version bump and does not belong in a release
> that is one tag away.
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
>   the same security review rather than to an implementation PR.
> - Whether `gcm_encrypt_det` should be offered at all for AES-128. The deterministic nonce is
>   HMAC-SHA256 truncated to 96 bits regardless of suite, so the collision bound in §5.2 is unchanged by
>   key size — but the argument for using a 128-bit key in a construction whose whole point is long-term
>   stored ciphertext deserves to be made explicitly rather than inherited.
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
> as a whole session. A failed registration rolls back; a failed release keeps the resources that are in
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

> **Out of scope** as of amendment A1. Kept because A1 is written against this section.

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
WHERE gcm_decrypt(encrypted_name) LIKE '%김%'   -- works through utf8mb4_general_ci
```

Writing decrypt_like instead would mean reproducing utf8mb4_general_ci's case-insensitivity and
Unicode normalisation semantics in C, all the way through CJK. Removing OPE was where we were burned
once by Python's code-point order differing from MySQL's collation. Do not reproduce it; use MySQL's.

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
  does not count usage or rotate automatically.
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
| MySQL 8.4.11 and 9.4.0 reject GCM/GCM-SIV/SIV/CTR/XTS | measured in a container |
| The mode list is unchanged across the 8.0 → 9.7 documentation | the dev.mysql.com reference |
| MariaDB has only ECB/CBC/CTR | the MariaDB documentation |
| A component can register UDFs | `mysql_service_udf_registration` (WL#8020) |
| A component can look up a key in the keyring | `keyring_reader_with_status` |
| A UDF return value's charset can be set (8.0.19+) | `mysql_udf_metadata` (WL#12370) |
| `AES_ENCRYPT` supports a KDF (hkdf/pbkdf2_hmac) from 8.0.30+ | the 8.0 reference — for information |
| `udf_registration`, `mysql_udf_metadata`, `component_sys_variable_register`/`_unregister`, `mysql_runtime_error` and `mysql_current_thread_reader` are present in 8.0.43, 8.4.11 and 9.4.0 | measured in `include/mysql/components/services/` across the three tags |
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
- **Open**: `derive_nonce_key` depends only on the key, yet `encrypt_det` recomputes it on every call
  (about 40% of `seal_det` for a small plaintext). Caching it per `UDF_INIT` would be a meaningful
  saving, but since the key is a per-row argument, deciding whether the cache is valid requires
  **keeping a copy of the key between rows** — which runs head-on into the key handling in
  `crypto-safety.md`. Doing this for performance means raising it as an amendment and getting a
  security review. The measurements and the argument are in `docs/perf.md`.

## 9. References

- MySQL: Keyring component services
- WL#4102 Service registry and component infrastructure
- WL#8020 Add a UDF registration service
- WL#12370 Extend the UDF API to handle character sets
- WL#6781 Support multiple AES Encryption modes
- Extending MySQL: Adding a Loadable Function
- Keyring Component Installation
