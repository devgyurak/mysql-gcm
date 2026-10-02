# Contributing to mysql-gcm

Thanks for looking. This project encrypts data that people cannot afford to lose, so the bar is
"a reviewer can see why this is correct", not "it works on my machine". Everything below exists
because something here can silently destroy ciphertext if it is wrong.

By contributing you agree your work is licensed under [GPLv2](LICENSE) (`GPL-2.0-only`), the same
terms as the rest of the project.

## Before you start

1. Read `docs/design.md` — the section that covers what you are touching, plus the amendments at the
   top. It is the source of rationale; if the code disagrees with it, either the code is wrong or the
   document needs amending **first**.
2. Read `docs/ops-constraints.md`. Several "bugs" are documented constraints of the approach.
3. If you are touching the envelope, `spec/envelope.md` is normative. A byte-format change is a new
   version byte, never a redefinition of an existing one.

Out of scope, by decision rather than by neglect: managed MySQL, proxy-based encryption, language
SDKs and driver integrations, and key management itself (`docs/design.md` §0, amendments A1 and A4).
Please open an issue before writing code in those directions.

## Branch and release flow

```
feature branch ──PR──▶ develop ──PR──▶ main ──tag v*──▶ GitHub Release + Docker Hub images
```

- `develop` is where work lands. Open the PR against `develop`.
- A PR to `develop` needs review from the maintainer (`@devgyurak`, see `.github/CODEOWNERS`).
- `main` takes no direct pushes **from anyone, administrators included**. It advances only by merging
  `develop`.
- A release is a tag `v*` on `main`. That is what publishes artifacts and Docker images; nothing else
  does, and `release.yml` verifies the tag is contained in `main` before it publishes anything.

Both branches require the same 18 checks, under the names GitHub reports them by: the seven `lint`
jobs (`cpp`, `python`, `agents-sync`, `architecture`, `shell`, `secrets`, `workflows`), `cpp-asan` and
`vectors` from `unit`, the six `matrix (<major>, <arch>)` entries from `build`, and `smoke (8.0)`,
`smoke (8.4)`, `smoke (9)` from `integration`.

Two jobs are deliberately **not** required:

- `compose` (E2E) runs only on a PR labelled `e2e`, so requiring it would leave every other PR
  waiting for a check that never reports. Add the label when the change touches replication,
  sharding, dual-read or the runner itself.
- `adapter` runs only when a PR touches `src/**` or `tests/adapter/**`, like `mtr`, because a PR
  that changes neither cannot change its result. It is minutes rather than an hour — the comparable
  `smoke` jobs, which build the image, build the component and run a server, measured 2m52s to
  3m27s — so it is worth adding to the required list once it has reported on `develop` at least
  once. Note that the build image is not cached between CI runs by anything today.
- `bench` does not run on pull requests at all. It runs on the merge — a push to `develop` or
  `main` that touches `src/**` or `tests/bench/**` — plus nightly. A benchmark on every PR is four
  minutes and a number nobody reads, and the regressions it catches are rare enough that minutes
  after the merge is soon enough. It therefore cannot be a required check.
- `mtr` builds the server from source: 49 to 63 minutes measured. It runs on a PR that touches
  `src/**`, `mysql-test/**`, `spec/**` or the build tooling, and on a merge to `develop` or `main`,
  from its own `mtr.yml` — a documentation-only PR cannot change its outcome, so it does not run one.
  A failure there is as blocking in practice as a required check; it just is not allowed to hold the
  merge button hostage for an hour.

Branches also do not have to be up to date before merging: for a repository this size the alternative
is rebasing and re-running a six-entry build matrix for every merge that lands ahead of yours.

Pushing to `develop` runs the same workflows as a PR to it, so a maintainer push — which the
protection deliberately allows — is gated too.

## What a reviewable PR looks like

- **One concern.** Net diff ≤ 400 lines, excluding `.result` files and vector JSON. Refactors go in
  their own PR, separate from behaviour changes.
- **The checklist in `.github/PULL_REQUEST_TEMPLATE.md` filled in.** A box you cannot tick is a
  conversation to have in the PR, not a box to leave blank.
- **Conventional commit subjects**: `feat(component):`, `fix(crypto):`, `test(mtr):`, `docs:`, `ci:`.
  One commit, one concern.
- Prose in English for code, comments, README, `spec/` and commit messages. `docs/design.md` is
  Korean, and `README-KO.md` mirrors `README.md` — change both in the same PR.

## Tests are not optional

The pyramid, and what each layer is for:

| Layer | Runs | Command |
|:--|:--|:--|
| unit (GoogleTest, ASan + UBSan) | no server; the core links libcrypto only | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` |
| integration | a real server, once per major | `scripts/verify.sh 8.0` · `8.4` · `9` |
| MTR | the server's own harness | `scripts/mtr.sh 8.4` |
| E2E | primary + replica + an independent shard | `docker compose -f tests/e2e/compose.yml up --build --exit-code-from runner` |
| load | p95 against the `AES_DECRYPT` baseline | `python tests/load/run.py --rows 300000 --concurrency 1,8,32 --gate tests/load/baseline.json` |
| adapter | the component's install and uninstall paths against stub services, no server | `scripts/adapter-tests.sh 8.4` |
| bench | the core against a same-work reference, no server | `scripts/bench.sh --gate` |

Rules that reviewers will hold you to (`.agents/rules/testing.md`):

- **Given-When-Then**, in the test name and in the body, in that order. One test, one action: no
  second When after a Then.
- **No `if`, `else`, `for` or `while` in a test body.** Split the case or use the framework's
  parameterisation. Data building belongs in a helper, above the tests.
- **Assert a property, not a value, for non-deterministic output** — and make sure the property can
  actually fail. `COUNT(DISTINCT gcm_encrypt('x', @k))` over N rows returns 1 because the server
  folds that constant expression once per aggregate; store the envelopes first, then count.
- **Never delete the Korean partial-match cases.** They are why the project exists.
- `.expected` and `.result` files are generated (`GCM_RECORD=1 scripts/verify.sh <major>`,
  `GCM_RECORD=1 scripts/mtr.sh 8.4`) and then **read by a human** before committing. A PR that
  changes one explains the diff.
- One vector source: `spec/test-vectors.json`. Regenerate with `scripts/gen-vectors.py`; never paste
  values into a test.

## If you touch the cryptographic path

`src/gcm.cc`, `src/envelope.cc`, `src/nonce.cc`, `src/sysvar.cc`, `spec/**` and the vector generator
need, in addition to the above:

- two human reviewers,
- the `crypto-reviewer` report attached to the PR,
- every rule in `.agents/rules/crypto-safety.md` honoured. The short version: fetch algorithms by
  name, never bundle or statically link OpenSSL, the key is exactly 32 bytes checked on every call,
  wipe copies with `gcm::wipe`, and **never** return unauthenticated plaintext or put key, plaintext,
  nonce, tag or ciphertext bytes into an error message, a log or an assertion.

Performance work must not remove a check. If a change alters per-row cost, show the load numbers.

## Local checks before you push

```sh
python3 scripts/check-architecture.py            # module boundaries (design A6)
scripts/agents-sync.sh --check                   # agent adapters are current
python3 scripts/check-action-pins.py             # no workflow uses a mutable action tag
git ls-files -z 'src/*.cc' 'src/*.h' 'tests/unit/*.cc' 'tests/unit/*.h' \
    'tests/bench/*.cc' 'tests/bench/*.h' 'tests/adapter/*.cc' 'tests/adapter/*.h' \
    | xargs -0 clang-format --dry-run --Werror
ruff check . && ruff format --check . && mypy --strict scripts/ tests/load/run.py tests/e2e/ \
    tests/bench/gate.py
shellcheck scripts/*.sh docker/*.sh .claude/hooks/*.sh
python scripts/gen-vectors.py --check
```

CI runs all of these. Nothing here needs network access except the Docker builds.

Two more exist and are not pre-push checks, because both need Docker and neither is fast:
`scripts/unit-in-docker.sh` runs the unit suite under GCC the way CI does — worth it before touching
`tests/unit`, since the host toolchain here is clang and GCC rejects things clang accepts — and
`scripts/bench.sh --gate` measures the core. The benchmark runs in CI on the merge rather than on the
pull request, so running it locally is how you find out before pushing.

## Cutting a release

The maintainer cuts releases. `.github/workflows/release.yml` refuses to publish unless all three
hold:

- the tag is exactly `vMAJOR.MINOR.PATCH` — no prerelease suffix. `v0.2.0-rc1` is refused, because a
  prerelease reaching the publishing path would ship as a normal release *and* move the `mysql<major>`
  tag onto it. A name like `0.2.0-rc1` is for the dry run below, which publishes nothing,
- the tagged commit is contained in `main`, so nothing reaches a release without going through it,
- `CHANGELOG.md` has a `## <version>` section. Release notes are written before the tag by someone
  who decided what the release is, not generated afterwards from commit subjects.

1. Open a PR from `develop` to `main` with the CHANGELOG section for the version filled in.
2. Dry-run the whole pipeline on that branch — it publishes nothing:

   ```sh
   gh workflow run release.yml --ref develop -f version=0.2.0-rc1
   ```

   It builds all six artifacts, builds each server image and **starts it and queries it**
   (`scripts/smoke-image.sh`: component installed, Korean `LIKE` hit, result `utf8mb4`, strict ON),
   signs the checksums, and uploads the lot as a build artifact for inspection.
3. Merge, then tag `main`:

   ```sh
   git tag -a v0.2.0 -m 'v0.2.0' && git push origin v0.2.0
   ```

4. Check what came out: six tarballs, `SHA256SUMS` with its `.sig` and `.pem`, `sbom.spdx.json`, and
   the Docker Hub tags `<version>-mysql<major>` plus the moving `mysql<major>`.

Downloads are verifiable without holding any key of ours — the signature is bound to this
repository's workflow identity, so what you check is *what produced the file*:

```sh
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/devgyurak/mysql-gcm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
```

The image jobs need the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. Without them
those jobs fail and the GitHub Release still publishes; the tarballs do not depend on Docker Hub.

## Reporting a security issue

Full policy: [SECURITY.md](SECURITY.md). In short: do not open a public issue for a cryptographic flaw. Use GitHub's private vulnerability reporting on
this repository. Include the server version, the envelope version byte, and the shape of the failing
query — never a real key or real plaintext.

This component has not had an independent cryptographic review (`docs/ops-constraints.md` item 13).
Reports that point that out are welcome; reports that demonstrate a concrete break are more welcome.

## Working with an AI agent in this repo

`AGENTS.md` (Codex, Cursor, OpenCode) and `CLAUDE.md` (Claude Code) are the entry points. Skills live
in `.agents/skills`, rules in `.agents/rules`, subagents in `.claude/agents`; the per-tool adapters
are **generated** by `scripts/agents-sync.sh`. Edit the originals, re-run the script, and commit
both — CI fails if an adapter is stale. Do not hand-edit anything under `.cursor/`, `.codex/` or
`.opencode/`.
