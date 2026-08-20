#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -f config/cluster.env ]]; then
  printf 'Missing config/cluster.env. Copy config/cluster.env.example and set local SSH key paths.\n' >&2
  exit 2
fi

make install
