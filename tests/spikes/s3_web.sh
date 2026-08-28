#!/usr/bin/env bash
set -euo pipefail

npm --prefix web ci
npm --prefix web run generate:api
npm --prefix web run lint
npm --prefix web run typecheck
npm --prefix web test
npm --prefix web run build

test -f web/dist/index.html
test -f web/src/api/generated-schema.ts
node -e "const p=require('./web/package.json'); if (!p.scripts.dev.includes('127.0.0.1') || !p.scripts.preview.includes('127.0.0.1')) process.exit(1)"

printf '%s\n' \
  'lockfile_install=ok' \
  'openapi_generation=ok' \
  'lint=ok' \
  'typecheck=ok' \
  'unit_tests=ok' \
  'production_build=ok' \
  'shared_host_bind=loopback'
