#!/usr/bin/env bash
# Prints the image reference for one MySQL major and image kind, and resolves it:
# a local image wins, then a registry pull, then a local build.
#
#   scripts/image-ref.sh 8.4 build   -> mysql-gcm-build:8.4-8.4.11-a1b2c3d4
#   scripts/image-ref.sh 8.4 mtr     -> mysql-gcm-mtr:8.4-8.4.11-a1b2c3d4
#
# `build` holds a *configured* server source tree. `mtr` is that plus a *compiled*
# server, which is what makes the MTR job three minutes instead of an hour.
#
# The tag carries a hash of everything that goes into the image, not just the MySQL
# version. Before this, the tag was <major>-<patch> alone, so editing build.Dockerfile
# produced a byte-different image under a name that was already cached -- harmless
# while every run built locally, and a correctness hole the moment a run can pull one
# that somebody else built.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major> <build|mtr>" >&2
  exit 2
}
[ $# -eq 2 ] || usage
ver="$1"
kind="$2"
case "${kind}" in
build | mtr) ;;
*) usage ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

read -r src_version tag_hash <<<"$(
  python3 - "${root}" "${ver}" <<'PY'
import hashlib, json, sys
from pathlib import Path

root, major = Path(sys.argv[1]), sys.argv[2]
versions = json.loads((root / "docker" / "versions.json").read_text(encoding="utf-8"))
if major not in versions:
    sys.exit(f"unknown MySQL major {major!r}; known: {', '.join(versions)}")

# Everything the image is built from. The entry for this major rather than the whole
# file, so bumping 9.x does not invalidate the 8.0 and 8.4 images.
digest = hashlib.sha256()
digest.update(json.dumps(versions[major], sort_keys=True).encode())
for name in ("build.Dockerfile", "build-component.sh"):
    digest.update((root / "docker" / name).read_bytes())
print(versions[major]["source"], digest.hexdigest()[:8])
PY
)"

tag="${ver}-${src_version}-${tag_hash}"
case "${kind}" in
build) name="mysql-gcm-build" ;;
mtr) name="mysql-gcm-mtr" ;;
esac
local_ref="${name}:${tag}"

# GCM_REGISTRY is set by CI (ghcr.io/<owner>). Unset locally, where building once and
# keeping the image is cheaper than a 2 GB pull.
registry="${GCM_REGISTRY:-}"
remote_ref=""
[ -n "${registry}" ] && remote_ref="${registry}/${name}:${tag}"

if [ "${GCM_IMAGE_REF_ONLY:-0}" = "1" ]; then
  echo "${remote_ref:-${local_ref}}"
  exit 0
fi

if docker image inspect "${local_ref}" >/dev/null 2>&1; then
  echo "${local_ref}"
  exit 0
fi

if [ -n "${remote_ref}" ] && docker pull --quiet "${remote_ref}" >/dev/null 2>&1; then
  docker tag "${remote_ref}" "${local_ref}"
  echo "pulled ${remote_ref}" >&2
  echo "${local_ref}"
  exit 0
fi

# Not local, not in the registry: build it. This is the path a PR that edits
# build.Dockerfile takes, and it is slow on purpose -- a changed input must never be
# served a stale image.
if [ "${kind}" = "build" ]; then
  read -r src_sha256 toolset <<<"$(
    python3 - "${root}/docker/versions.json" "${ver}" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    versions = json.load(fh)
entry = versions[sys.argv[2]]
print(entry["source_sha256"], entry["rhel9_toolset"])
PY
  )"
  echo "building ${local_ref} (configures the MySQL ${src_version} tree; slow, cached afterwards)" >&2
  docker build \
    -f "${root}/docker/build.Dockerfile" \
    --build-arg "MYSQL_VERSION=${src_version}" \
    --build-arg "MYSQL_SOURCE_SHA256=${src_sha256}" \
    --build-arg "RHEL9_TOOLSET=${toolset}" \
    -t "${local_ref}" \
    "${root}/docker" >&2
  echo "${local_ref}"
  exit 0
fi

# kind=mtr and nothing to pull: the caller compiles the server itself, so report the
# build image and let scripts/mtr.sh take its slow path.
echo "MTR image ${local_ref} is not available; the server will be compiled locally" >&2
echo ""
