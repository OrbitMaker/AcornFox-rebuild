#!/usr/bin/env bash
set -euo pipefail

# This wrapper only produces or checks a local tar archive.  It never connects
# to a guest/host, creates libvirt resources, or changes network/service state.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  prepare-clean-worker-bundle.sh build --output /absolute/bundle.tar \
    --input payload/name=/absolute/source [--input ...] [--overwrite]
  prepare-clean-worker-bundle.sh validate --archive /absolute/bundle.tar

Every source must be named explicitly. Directories, globs, symlinks, and
credential-like filenames/content are rejected by the builder.
USAGE
}

if [[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]]; then
  usage
  exit 0
fi

case "$1" in
  build|validate) ;;
  *) usage >&2; exit 64 ;;
esac

exec python3 "$repo_root/tools/worker/offline_bundle.py" "$@"
