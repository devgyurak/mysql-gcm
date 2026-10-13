#!/usr/bin/env bash
# Builds the test-only probe component (tests/probe) for one MySQL major version,
# inside the same configured server-tree image scripts/build-in-docker.sh uses.
#
#   scripts/build-probe.sh 8.4   ->  build/8.4/component_probe.so
#
# The probe is not part of the shipped component. It is copied into the image's
# *ephemeral* server tree as components/probe (exactly as docker/build-component.sh
# does for src/), built with the server's own component macro so its flags match,
# and written beside component_gcm.so for scripts/verify-nested.sh to install on a
# throwaway server. Neither the image nor docker/versions.json is touched.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Same resolution and cache as the component build: local image, then registry,
# then build (scripts/image-ref.sh).
image="$(GCM_IMAGE_REF_ONLY=0 "${root}/scripts/image-ref.sh" "${ver}" build)"

out="${root}/build/${ver}"
mkdir -p "${out}"

docker run --rm \
  -v "${root}/tests/probe:/gcm-probe:ro" \
  -v "${out}:/out" \
  "${image}" bash -euo pipefail -c '
    : "${MYSQL_SRC:?MYSQL_SRC is set by the build image}"
    : "${MYSQL_BUILD:?MYSQL_BUILD is set by the build image}"

    # CONFIGURE_COMPONENTS() globs components/* at configure time, so a copy (not a
    # symlink into a read-only mount) plus a re-configure is what makes the tree see
    # the probe. MYSQL_ADD_COMPONENT also pulls in GenError, which is what generates
    # mysqld_error.h — the probe includes it for ER_UDF_ERROR.
    component_dir="${MYSQL_SRC}/components/probe"
    rm -rf "${component_dir}"
    mkdir -p "${component_dir}"
    cp /gcm-probe/probe.cc /gcm-probe/CMakeLists.txt "${component_dir}/"

    cmake -S "${MYSQL_SRC}" -B "${MYSQL_BUILD}" -G Ninja >/dev/null
    cmake --build "${MYSQL_BUILD}" --target component_probe

    so="${MYSQL_BUILD}/plugin_output_directory/component_probe.so"
    [ -f "${so}" ] || { echo "expected ${so} to exist after the build" >&2; exit 1; }
    cp "${so}" /out/component_probe.so
  '

echo "${out}/component_probe.so"
