#!/usr/bin/env bash
# Integration check on a server with NO keyring component: the component must install,
# the key-argument functions must work, and the key-id functions must fail cleanly
# (docs/design.md amendment A13). scripts/verify.sh cannot show this, because the
# development server it uses has a keyring loaded.
#
# Uses a throwaway container, started and removed here, so it never touches the
# development server or its data.
#
#   scripts/verify-bare.sh 8.4
#   GCM_RECORD=1 scripts/verify-bare.sh 8.4    # rewrite .expected (review the diff!)
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="mysql-bare-${ver}"
so="${root}/build/${ver}/component_gcm.so"
outdir="${root}/build/${ver}"

[ -f "${so}" ] || {
  echo "missing ${so} — run scripts/build-in-docker.sh ${ver} first" >&2
  exit 1
}

image="$(
  python3 - "${root}/docker/versions.json" "${ver}" <<'PY'
import json, sys

path, major = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    versions = json.load(fh)
if major not in versions:
    sys.exit(f"unknown MySQL major {major!r}; known: {', '.join(versions)}")
print(versions[major]["image"])
PY
)"

cleanup() { docker rm -f "${name}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

# The healthcheck goes over TCP for the reason scripts/dev-up.sh gives: the temporary
# server the image starts while initialising listens on the socket only.
docker run -d --name "${name}" \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
  --health-cmd='mysqladmin ping -h 127.0.0.1 -P 3306 -uroot --silent' \
  --health-interval=2s \
  --health-retries=30 \
  "${image}" --loose_gcm.strict=ON --general_log=OFF >/dev/null

deadline=$((SECONDS + 300))
while [ "$(docker inspect -f '{{.State.Health.Status}}' "${name}")" != healthy ]; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "${name} did not become healthy within 300s; last log lines:" >&2
    docker logs --tail 40 "${name}" >&2
    exit 1
  fi
  sleep 2
done

mysql() { docker exec -i "${name}" mysql -uroot --default-character-set=utf8mb4 "$@"; }
until mysql -N -e 'SELECT 1' >/dev/null 2>&1 </dev/null; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "${name} is healthy but not answering queries" >&2
    exit 1
  fi
  sleep 1
done

# The premise of the whole check. If a later change to dev-up.sh or to the image ever
# gave this server a keyring, the case below would pass for the wrong reason.
keyring_rows="$(mysql -N -e "SELECT COUNT(*) FROM performance_schema.keyring_component_status" </dev/null)"
[ "${keyring_rows}" = 0 ] || {
  echo "${name} has a keyring component loaded; this check needs a server without one" >&2
  exit 1
}

plugin_dir="$(mysql -N -e "SELECT @@plugin_dir" </dev/null | tr -d '\r')"
docker cp "${so}" "${name}:${plugin_dir}/component_gcm.so" >/dev/null
if ! mysql -N -e "INSTALL COMPONENT 'file://component_gcm'" </dev/null; then
  echo "INSTALL COMPONENT failed on a server with no keyring; last log lines:" >&2
  docker logs --tail 40 "${name}" >&2
  exit 1
fi
mysql -N -e "CREATE DATABASE gcm_it" </dev/null

case_file="${root}/tests/integration/bare/kr_unavailable.sql"
expected="${root}/tests/integration/bare/kr_unavailable.expected"
actual="${outdir}/bare_kr_unavailable.actual"

# Streams captured separately and joined, as in scripts/verify.sh: stdout is block
# buffered and stderr is not, so 2>&1 would interleave them unpredictably.
# --loose-commands=ON so the case's `connect` works in a batch on the 9.x client; see
# the same option in scripts/verify.sh.
mysql --loose-commands=ON -D gcm_it -N --force < "${case_file}" \
  > "${actual}.out" 2> "${actual}.err" || true
{
  cat "${actual}.out"
  if [ -s "${actual}.err" ]; then
    echo "--- errors, in statement order ---"
    cat "${actual}.err"
  fi
} > "${actual}"
rm -f "${actual}.out" "${actual}.err"

status=0
if [ "${GCM_RECORD:-0}" = "1" ]; then
  cp "${actual}" "${expected}"
  echo "recorded $(basename "${expected}")" >&2
elif [ ! -f "${expected}" ]; then
  echo "FAIL kr_unavailable: no .expected (GCM_RECORD=1 to create)" >&2
  status=1
elif diff -u "${expected}" "${actual}"; then
  echo "ok   bare/kr_unavailable" >&2
else
  echo "FAIL bare/kr_unavailable" >&2
  status=1
fi

# A failed key-id call must not leave the component unable to unload.
if ! mysql -N -e "UNINSTALL COMPONENT 'file://component_gcm'" </dev/null; then
  echo "FAIL UNINSTALL COMPONENT was refused after the case" >&2
  status=1
fi

exit "${status}"
