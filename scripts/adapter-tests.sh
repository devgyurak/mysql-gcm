#!/usr/bin/env bash
# Runs the component adapter tests (tests/adapter) inside the build image for one MySQL major.
#
#   scripts/adapter-tests.sh 8.4
#
# They have to run in that image because component.cc, sysvar.cc and the UDF glue include server
# headers, and the image is where a configured MySQL tree lives. Unlike the component build this
# produces no artifact — it links those same sources against stub services and asserts on the
# install and uninstall paths.
#
# The image is not built here: it is expensive and scripts/build-in-docker.sh owns it, the same
# split scripts/mtr.sh uses.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
versions="${root}/docker/versions.json"

toolset="$(
  python3 - "${versions}" "${ver}" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    versions = json.load(fh)
major = sys.argv[2]
if major not in versions:
    sys.exit(f"unknown MySQL major {major!r}; known: {', '.join(versions)}")
print(versions[major]["rhel9_toolset"])
PY
)"

# The tag is scripts/image-ref.sh's to compute -- it carries a hash of the image inputs, not just
# the patch version, and this script once assembled the old <major>-<patch> form by hand and
# failed with "build image missing" on every run after the tag changed. GCM_REGISTRY is cleared
# and GCM_IMAGE_REF_ONLY set so this only names the local tag build-in-docker.sh leaves behind,
# without pulling or building anything.
image="$(GCM_REGISTRY='' GCM_IMAGE_REF_ONLY=1 "${root}/scripts/image-ref.sh" "${ver}" build)"
if ! docker image inspect "${image}" >/dev/null 2>&1; then
  echo "build image missing; run scripts/build-in-docker.sh ${ver} first" >&2
  exit 1
fi

# A host build directory, so the pinned GoogleTest tarball is fetched once rather than on every
# run. It is per major because the configured tree it compiles against differs.
out="${root}/build/adapter-${ver}"
mkdir -p "${out}"

# The compiler path is not in the server's CMakeCache: that configure took it from the
# environment, so only CMAKE_CXX_COMPILER_AR records which toolset was used. A fresh CMake
# project has no such cache, and the toolset is not on PATH, so it is passed in explicitly from
# the same versions.json field the image was built with — it differs per major
# (gcc-toolset-12 for 8.x, 14 for 9.x).
docker run --rm \
  -e "GCM_TOOLSET=${toolset}" \
  -v "${root}/src:/gcm-src:ro" \
  -v "${root}/tests/adapter:/gcm-adapter:ro" \
  -v "${out}:/adapter-build" \
  "${image}" bash -euo pipefail -c '
    : "${MYSQL_SRC:?MYSQL_SRC is set by the build image}"
    : "${MYSQL_BUILD:?MYSQL_BUILD is set by the build image}"

    # CMake needs the sources where their relative paths resolve, and the mounts are read-only.
    mkdir -p /work/src /work/tests/adapter
    cp /gcm-src/* /work/src/
    cp /gcm-adapter/* /work/tests/adapter/

    # mysqld_error.h and mysql_version.h are generated, so the configured tree alone is not
    # enough. Building the component target produces them and is cheap against the cached
    # CMakeCache (docker/build-component.sh explains why re-configuring is the only way the
    # component enters the build graph).
    component_dir="${MYSQL_SRC}/components/gcm"
    rm -rf "${component_dir}"
    mkdir -p "${component_dir}"
    cp /work/src/*.cc /work/src/*.h /work/src/CMakeLists.txt "${component_dir}/"
    cmake -S "${MYSQL_SRC}" -B "${MYSQL_BUILD}" -G Ninja >/dev/null
    cmake --build "${MYSQL_BUILD}" --target component_gcm >/dev/null

    cxx="/opt/rh/${GCM_TOOLSET}/root/usr/bin/g++"
    [ -x "${cxx}" ] || { echo "no compiler at ${cxx}" >&2; exit 1; }

    cmake -S /work/tests/adapter -B /adapter-build \
      -DCMAKE_CXX_COMPILER="${cxx}" \
      -DGCM_MYSQL_SRC="${MYSQL_SRC}" \
      -DGCM_MYSQL_BUILD="${MYSQL_BUILD}" \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo
    cmake --build /adapter-build -j"$(nproc)"
    ctest --test-dir /adapter-build --output-on-failure
  '

echo "adapter tests passed for MySQL ${ver}"
