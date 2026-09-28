#!/usr/bin/env bash
# Runs inside the build image (docker/build.Dockerfile). Links the bind-mounted
# component sources into the configured server tree and builds only the component
# target — never the whole server.
#
# Mounts expected:
#   /gcm-src  (ro)  the repository's src/ directory
#   /out      (rw)  where component_gcm.so is written
set -euo pipefail

: "${MYSQL_SRC:?MYSQL_SRC is set by the build image}"
: "${MYSQL_BUILD:?MYSQL_BUILD is set by the build image}"

[ -d /gcm-src ] || { echo "mount the repository's src/ at /gcm-src" >&2; exit 2; }
[ -d /out ] || { echo "mount an output directory at /out" >&2; exit 2; }

# No `scl enable` here on purpose: the configure step in the image already recorded
# the exact compiler paths (which gcc-toolset a server version wants differs per
# version) in CMakeCache.txt, so re-using that cache uses the same toolchain.

# CONFIGURE_COMPONENTS() in cmake/component.cmake globs components/* at configure
# time, so a copy (not a symlink into a read-only mount) plus a re-configure is
# what makes the server tree see this component.
component_dir="${MYSQL_SRC}/components/gcm"
rm -rf "${component_dir}"
mkdir -p "${component_dir}"
cp /gcm-src/*.cc /gcm-src/*.h /gcm-src/CMakeLists.txt "${component_dir}/"

# Re-configure against the cached CMakeCache: cheap, and the only way the new
# components/gcm directory enters the build graph.
cmake -S "${MYSQL_SRC}" -B "${MYSQL_BUILD}" -G Ninja

cmake --build "${MYSQL_BUILD}" --target component_gcm

so="${MYSQL_BUILD}/plugin_output_directory/component_gcm.so"
[ -f "${so}" ] || { echo "expected ${so} to exist after the build" >&2; exit 1; }
cp "${so}" /out/component_gcm.so
echo "built /out/component_gcm.so"
