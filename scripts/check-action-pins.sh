#!/usr/bin/env bash
# Every `uses:` in .github/workflows must name a 40-character commit SHA, with the readable
# tag kept in a trailing comment (stack-ci-docker rule).
#
# A tag reference is mutable. `actions/checkout@v4` is whatever the owner last pointed v4 at,
# and an action runs inside this workflow with its token — in release.yml, alongside an OIDC
# identity that signs the artifacts consumers verify. Pinning by SHA means an upgrade is a
# commit somebody reviews rather than something that happens to a workflow overnight.
#
# Refresh a pin with:
#   gh api repos/<owner>/<action>/commits/<tag> -q .sha
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/check-action-pins.sh

Checks every `uses:` in .github/workflows/*.yml. Fails, listing each offender, if one names
a tag or branch instead of a 40-character commit SHA, or if a pinned SHA has no trailing
`# <tag>` comment saying what it is.
USAGE
  exit 2
}

[ $# -eq 0 ] || usage

cd "$(dirname "$0")/.."

# `uses:` lines only, with the file and line number, and without local (./) references,
# which have no ref to pin. Read in a loop rather than with `mapfile`, which is bash 4 and
# absent from the bash macOS ships.
lines=()
while IFS= read -r line; do
  lines+=("${line}")
done < <(grep -Hn '^[[:space:]]*-\{0,1\}[[:space:]]*uses:' .github/workflows/*.yml \
         | grep -v 'uses:[[:space:]]*\./' || true)

if [ "${#lines[@]}" -eq 0 ]; then
  echo "no 'uses:' lines found under .github/workflows — is the path right?" >&2
  exit 1
fi

unpinned=()
uncommented=()
for line in "${lines[@]}"; do
  ref=${line#*uses:}
  ref=${ref%%#*}
  # shellcheck disable=SC2001  # a glob cannot strip leading and trailing whitespace here
  ref=$(echo "${ref}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  if [[ ! ${ref} =~ @[0-9a-f]{40}$ ]]; then
    unpinned+=("${line}")
  elif [[ ! ${line} =~ \#[[:space:]]*[^[:space:]] ]]; then
    uncommented+=("${line}")
  fi
done

status=0
if [ "${#unpinned[@]}" -gt 0 ]; then
  echo "these actions are referenced by a mutable tag or branch, not a commit SHA:" >&2
  printf '  %s\n' "${unpinned[@]}" >&2
  status=1
fi
if [ "${#uncommented[@]}" -gt 0 ]; then
  echo "these actions are pinned but do not say which version the SHA is:" >&2
  printf '  %s\n' "${uncommented[@]}" >&2
  status=1
fi
[ "${status}" -eq 0 ] || exit "${status}"

echo "action pins: ${#lines[@]} 'uses:' references, all pinned to a commit SHA with a version comment"
