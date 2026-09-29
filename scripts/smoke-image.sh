#!/usr/bin/env bash
# Smoke-tests a published server image built from docker/server.Dockerfile.
#
# The release pipeline runs this on the image it just built, before that image is pushed.
# Three things are checked, and they are the three ways this image can be wrong while the
# component itself is fine:
#
#   1. the init script actually installed the component on a fresh data directory,
#   2. the .so in plugin_dir matches the server in the image (a mismatched major loads
#      but fails to resolve symbols, or refuses to install),
#   3. native LIKE over a decrypted value still works — the reason the project exists.
#
# Tests do not use this image (stack-ci-docker rule): they copy the .so into an
# unmodified official image, so a component bug can never be mistaken for an image bug.
# This script is the converse check, on the image only.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/smoke-image.sh <image>

  <image>  a locally available image built from docker/server.Dockerfile,
           e.g. devgyurak/mysql-gcm-server:0.1.0-mysql8.4-amd64

Starts the image on a throwaway container and port, asserts the component is installed
and that a Korean partial match over a decrypted value returns a hit, then removes it.
USAGE
  exit 2
}

[ $# -eq 1 ] || usage
image=$1
name="gcm-smoke-$$"

cleanup() {
  docker rm -f "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# TCP healthcheck, not the socket: while the official entrypoint initialises a fresh data
# directory it runs a temporary server that listens on the socket only, so a socket ping
# answers before the init scripts — including ours — have run. Same reason as dev-up.sh.
docker run -d --name "${name}" \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=1 \
  -p 0:3306 \
  --health-cmd='mysqladmin ping -h 127.0.0.1 -P 3306 -uroot --silent' \
  --health-interval=2s \
  --health-retries=60 \
  "${image}" >/dev/null

deadline=$((SECONDS + 300))
while [ "$(docker inspect -f '{{.State.Health.Status}}' "${name}")" != healthy ]; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "${image} did not become healthy within 300s; last log lines:" >&2
    docker logs --tail 60 "${name}" >&2
    exit 1
  fi
  sleep 2
done

probe_deadline=$((SECONDS + 120))
until docker exec "${name}" mysql -uroot -N -e 'SELECT 1' >/dev/null 2>&1; do
  if [ "${SECONDS}" -ge "${probe_deadline}" ]; then
    echo "${image} is healthy but not answering queries; last log lines:" >&2
    docker logs --tail 60 "${name}" >&2
    exit 1
  fi
  sleep 1
done

# The fixture key is the public 00..1f pattern from spec/test-vectors.json, and it is
# fine for it to appear here: it protects nothing (crypto-safety, key handling).
observed=$(docker exec "${name}" mysql -uroot -N -B -e "
SET @k = UNHEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
SELECT (SELECT COUNT(*) FROM mysql.component WHERE component_urn = 'file://component_gcm') AS installed,
       gcm_decrypt(gcm_encrypt_det('홍길동', @k), @k) LIKE '%길%' AS korean_like,
       CHARSET(gcm_decrypt(gcm_encrypt_det('x', @k), @k)) AS result_charset,
       @@GLOBAL.\`gcm\`.\`strict\` AS strict_default;" 2>&1) || {
  echo "the smoke query failed on ${image}:" >&2
  printf '%s\n' "${observed}" >&2
  docker logs --tail 60 "${name}" >&2
  exit 1
}

expected=$'1\t1\tutf8mb4\t1'
if [ "${observed}" != "${expected}" ]; then
  echo "${image} smoke check mismatch" >&2
  echo "  expected: installed korean_like result_charset strict_default = ${expected//$'\t'/ }" >&2
  echo "  observed: ${observed//$'\t'/ }" >&2
  exit 1
fi

echo "${image}: component installed, Korean LIKE hit, result utf8mb4, strict ON by default"
