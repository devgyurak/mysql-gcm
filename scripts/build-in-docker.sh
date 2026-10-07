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

# Resolving the image -- local, registry, or build -- lives in one place so that
# this script and scripts/mtr.sh cannot disagree about which image a tag names.
image="$(GCM_IMAGE_REF_ONLY=0 "${root}/scripts/image-ref.sh" "${ver}" build)"

out="${root}/build/${ver}"
mkdir -p "${out}"
docker run --rm \
  -v "${root}/src:/gcm-src:ro" \
  -v "${out}:/out" \
  "${image}"

echo "${out}/component_gcm.so"
