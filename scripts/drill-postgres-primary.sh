#!/usr/bin/env bash
# Compatibility entrypoint used by Makefile; implementation lives in the
# descriptive failover script.
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/drill-postgres-failover.sh" "$@"
