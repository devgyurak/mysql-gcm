#!/usr/bin/env bash
# Builds component_gcm for one MySQL major version inside a container that holds a
# pre-configured server source tree (component ABI is bound to the server version,
# so there is one image per major).
#
#   scripts/build-in-docker.sh 8.4   ->  build/8.4/component_gcm.so
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
versions="${root}/docker/versions.json"

# versions.json is the single source of truth for the patch version, the source
# tarball checksum and the compiler the server tree expects (stack-ci-docker).
read -r src_version src_sha256 toolset <<<"$(
  python3 - "${versions}" "${ver}" <<'PY'
import json, sys

path, major = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    versions = json.load(fh)
if major not in versions:
    sys.exit(f"unknown MySQL major {major!r}; known: {', '.join(versions)}")
print(versions[major]["source"], versions[major]["source_sha256"], versions[major]["rhel9_toolset"])
PY
)"

image="mysql-gcm-build:${ver}-${src_version}"
if ! docker image inspect "${image}" >/dev/null 2>&1; then
  echo "building ${image} (configures the MySQL ${src_version} source tree; slow, cached afterwards)" >&2
  docker build \
    -f "${root}/docker/build.Dockerfile" \
    --build-arg "MYSQL_VERSION=${src_version}" \
    --build-arg "MYSQL_SOURCE_SHA256=${src_sha256}" \
    --build-arg "RHEL9_TOOLSET=${toolset}" \
    -t "${image}" \
    "${root}/docker"
fi

out="${root}/build/${ver}"
mkdir -p "${out}"
docker run --rm \
  -v "${root}/src:/gcm-src:ro" \
  -v "${out}:/out" \
  "${image}"

echo "${out}/component_gcm.so"
