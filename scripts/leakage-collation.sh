#!/usr/bin/env bash
# Collation differential for the n-gram token index (design amendment A17, question 4).
#
# The invariant: the designated final filter must never miss a row the index should have
# offered. If a token is computed on a normalisation the final LIKE does not use, the
# index silently drops rows. This runs the check on a throwaway server with PLAIN SQL
# ONLY — no component function and no C++ — over tests/leakage/collation/normalisation.sql:
# for every (h, q) where `h LIKE '%q%'` is true, the tokenisation of q must be contained in
# that of h, or the pair is a counterexample. Counterexamples are printed as they are; they
# are never blamed on the environment. A counterexample count is a finding for
# docs/leakage-ngram.md, not a failure of this script.
#
#   scripts/leakage-collation.sh 8.0
#   scripts/leakage-collation.sh 8.4
#   scripts/leakage-collation.sh 9
#
# A server of its own, and not a case in scripts/verify.sh: this needs no component and no
# keyring, and it must run on a clean server of each major.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="mysql-collation-${ver}"

image="$(python3 - "${root}/docker/versions.json" "${ver}" <<'PY'
import json
import sys

versions = json.load(open(sys.argv[1]))
key = sys.argv[2]
entry = versions.get(key) or versions.get(key.split(".")[0])
if not entry:
    sys.exit(f"no image known for {key}")
print(entry["image"])
PY
)"

cleanup() {
  docker rm -f -v "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker run -d --name "${name}" \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
  "${image}" \
  --character-set-server=utf8mb4 --collation-server=utf8mb4_0900_ai_ci >/dev/null

mysql() { docker exec -i "${name}" mysql -uroot --default-character-set=utf8mb4 "$@"; }

deadline=$((SECONDS + 300))
until mysql -N -e 'SELECT 1' </dev/null >/dev/null 2>&1; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "${name} did not become ready; last log lines:" >&2
    docker logs --tail 40 "${name}" >&2
    exit 1
  fi
  sleep 2
done

echo "== ${name}: collation differential (A17) ==" >&2
output="$(mysql -t < "${root}/tests/leakage/collation/normalisation.sql")"
echo "${output}"

# The recorded result is a gate, not a printout: N1 (binary) must keep its counterexamples
# and N2 (WEIGHT_STRING) must have none. A change here is a finding to investigate, not a
# number to update silently.
n1="$(echo "${output}" | awk -F'|' '/\| summary \| N1 binary/ {gsub(/ /, "", $4); print $4}')"
n2="$(echo "${output}" | awk -F'|' '/\| summary \| N2 weight/ {gsub(/ /, "", $4); print $4}')"
n2gram="$(echo "${output}" | awk -F'|' '/\| summary \| N2 n-gram violations/ {gsub(/ /, "", $4); print $4}')"
echo "N1=${n1} N2=${n2} N2_ngram=${n2gram}" >&2
if [ "${n1}" != "6" ] || [ "${n2}" != "0" ] || [ "${n2gram}" != "0" ]; then
  echo "collation differential changed: expected N1=6 N2=0 N2_ngram=0," \
    "got N1=${n1} N2=${n2} N2_ngram=${n2gram}" >&2
  exit 1
fi
