#!/usr/bin/env bash
# Runs the MTR suite mysql-test/suite/gcm against a server built from source.
#
#   scripts/mtr.sh 8.4                 # run the suite
#   GCM_RECORD=1 scripts/mtr.sh 8.4    # regenerate .result, then review the diff
#
# Unlike scripts/verify.sh, which installs the .so into an official image, MTR needs
# a *built* mysqld. The build image only configures the tree, so the server targets
# are compiled here on first use and then cached in the named container.
#
# The committed .result files are recorded against 8.4. The suite is not portable
# across majors today: the replication case uses the include/rpl/* helpers (8.4+, not
# 8.0) and exercises binlog_format=STATEMENT (removed in 9.0). Per-major behaviour
# that does need covering everywhere lives in tests/integration, which scripts/verify.sh
# runs on 8.0, 8.4 and 9.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Reuse an existing container that already holds a compiled tree by exporting
# GCM_MTR_CONTAINER; otherwise a dedicated one is created and kept for next time.
# CI should cache this container (or a committed image of it) the way the build job
# caches the configured tree — a cold server build is expensive (ci-release skill).
container="${GCM_MTR_CONTAINER:-gcm-mtr-${ver}}"

# Two images can serve this. `mtr` already holds a compiled server, which is what the
# CI job pulls; `build` only has a configured tree and means compiling it here. The
# whole point of the first is that the server build is the job: the suite itself runs
# in about 16 seconds, against roughly an hour of cmake (measured).
mtr_image="$("${root}/scripts/image-ref.sh" "${ver}" mtr || true)"
if [ -n "${mtr_image}" ]; then
  image="${mtr_image}"
  prebuilt=1
else
  image="$("${root}/scripts/image-ref.sh" "${ver}" build)"
  prebuilt=0
fi

if [ "${ver}" != "8.4" ]; then
  echo "warning: the committed .result files were recorded against 8.4;" >&2
  echo "         expect diffs on ${ver} (see the comment at the top of this script)" >&2
fi


# A long-lived container so the compiled server survives between runs.
if ! docker inspect "${container}" >/dev/null 2>&1; then
  docker run -d --name "${container}" --entrypoint sleep "${image}" infinity >/dev/null
fi
docker start "${container}" >/dev/null 2>&1 || true

# Sources go in with `docker cp` rather than a bind mount, so GCM_MTR_CONTAINER can
# point at any container built from this image — including one that already holds a
# compiled server.
docker exec "${container}" sh -c '
  rm -rf "${MYSQL_SRC}/components/gcm" "${MYSQL_SRC}/mysql-test/suite/gcm"
  mkdir -p "${MYSQL_SRC}/components/gcm" "${MYSQL_SRC}/mysql-test/suite"
'
docker cp "${root}/src/." "${container}:/mysql-src/components/gcm/" >/dev/null
docker cp "${root}/mysql-test/suite/gcm" "${container}:/mysql-src/mysql-test/suite/" >/dev/null
# src/ carries AGENTS.md too; the component build only wants sources.
docker exec "${container}" sh -c 'rm -f "${MYSQL_SRC}/components/gcm/AGENTS.md"'

# group_replication is not built: its xcom sources need a generated XDR header that is
# expensive to produce and the gcm suite never touches it.
# A prebuilt image already carries the server, so only the component is compiled --
# the gcm sources changed, the server did not. Without one the whole tree is built,
# which is the hour the mtr image exists to remove.
if [ "${prebuilt}" = "1" ]; then
  docker exec "${container}" sh -c '
    set -eu
    cmake -S "${MYSQL_SRC}" -B "${MYSQL_BUILD}" -DWITHOUT_GROUP_REPLICATION=1 >/dev/null
    cmake --build "${MYSQL_BUILD}" --target component_gcm -- -j "${GCM_MTR_JOBS:-3}"
  '
else
  docker exec "${container}" sh -c '
    set -eu
    cmake -S "${MYSQL_SRC}" -B "${MYSQL_BUILD}" -DWITHOUT_GROUP_REPLICATION=1 >/dev/null
    cmake --build "${MYSQL_BUILD}" -- -j "${GCM_MTR_JOBS:-3}"
  '
fi

record=""
if [ "${GCM_RECORD:-0}" = "1" ]; then
  record="--record"
fi

status=0
docker exec -e "GCM_MTR_RECORD=${record}" "${container}" sh -c '
  cd "${MYSQL_BUILD}/mysql-test"
  # shellcheck disable=SC2086  # deliberately unquoted: empty means "do not record"
  ./mtr --suite=gcm --force --max-test-fail=0 ${GCM_MTR_RECORD} 2>&1
' || status=$?

out="${root}/build/${ver}/mtr"
mkdir -p "${out}"
docker cp "${container}:/mysql-build/mysql-test/var/log" "${out}" 2>/dev/null || true

if [ "${GCM_RECORD:-0}" = "1" ]; then
  # Copy the regenerated .result files back so a human can review the diff before
  # committing them (testing rule).
  docker cp "${container}:/mysql-src/mysql-test/suite/gcm/r" "${root}/mysql-test/suite/gcm/" \
    || echo "no .result files were produced" >&2
fi

exit "${status}"
