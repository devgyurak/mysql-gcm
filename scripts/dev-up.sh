#!/usr/bin/env bash
# Starts (or reuses) a local MySQL container for one major version. Port 0 lets the
# daemon pick a free host port, so several versions run side by side.
#
#   scripts/dev-up.sh 8.4
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="mysql-dev-${ver}"

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

if ! docker inspect "${name}" >/dev/null 2>&1; then
  # binlog_format was removed in MySQL 9.0 (ROW is the only format there); passing
  # it would stop the server from starting.
  server_args=(--loose_gcm.strict=ON --general_log=OFF)
  case "${ver}" in
    9*) : ;;
    *) server_args+=(--binlog_format=ROW) ;;
  esac

  # general_log=OFF even in development: keys and plaintext travel as SQL
  # arguments, so the log would hold them (docs/design.md §6).
  docker run -d --name "${name}" \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
    -p 0:3306 \
    --health-cmd='mysqladmin ping -uroot --silent' \
    --health-interval=2s \
    --health-retries=30 \
    "${image}" "${server_args[@]}" >/dev/null
fi

docker start "${name}" >/dev/null 2>&1 || true

deadline=$((SECONDS + 300))
while [ "$(docker inspect -f '{{.State.Health.Status}}' "${name}")" != healthy ]; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "${name} did not become healthy within 300s; last log lines:" >&2
    docker logs --tail 40 "${name}" >&2
    exit 1
  fi
  sleep 2
done

port="$(docker port "${name}" 3306/tcp | head -1 | cut -d: -f2)"
echo "${name} ready on host port ${port}"
