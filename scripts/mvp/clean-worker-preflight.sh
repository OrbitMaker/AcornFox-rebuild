#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
spec="${1:-$repo_root/deploy/worker/clean-worker-spec.json}"
shift $(( $# > 0 ? 1 : 0 )) || true
exec python3 "$repo_root/tools/worker/validate_clean_worker_spec.py" "$spec" "$@"
