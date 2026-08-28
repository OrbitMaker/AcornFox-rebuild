#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: DATABASE_URL=postgres://... $0 [migrations-directory]" >&2
}

if [[ -z "${DATABASE_URL:-}" ]]; then
  usage
  exit 64
fi

MIGRATIONS_DIR="${1:-migrations/control-plane}"
if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "migration directory not found: $MIGRATIONS_DIR" >&2
  exit 66
fi

command -v psql >/dev/null 2>&1 || {
  echo "psql is required" >&2
  exit 69
}

checksum_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

shopt -s nullglob
migration_files=("$MIGRATIONS_DIR"/[0-9][0-9][0-9][0-9]_*.sql)
if (( ${#migration_files[@]} == 0 )); then
  echo "no migration files found in $MIGRATIONS_DIR" >&2
  exit 65
fi
latest_file=$(basename "${migration_files[$((${#migration_files[@]} - 1))]}" .sql)
latest_version=${latest_file%%_*}
if [[ -n "${OPEN_CARD_REQUIRED_MIGRATION_VERSION:-}" ]]; then
  [[ "$OPEN_CARD_REQUIRED_MIGRATION_VERSION" =~ ^[0-9]{4}$ ]] || { echo "OPEN_CARD_REQUIRED_MIGRATION_VERSION is invalid" >&2; exit 64; }
  [[ "$latest_version" = "$OPEN_CARD_REQUIRED_MIGRATION_VERSION" ]] || { echo "migration directory latest version $latest_version does not match required $OPEN_CARD_REQUIRED_MIGRATION_VERSION" >&2; exit 65; }
fi

for migration in "${migration_files[@]}"; do
  version="$(basename "$migration" .sql)"
  if [[ ! "$version" =~ ^[0-9]{4}_[a-z0-9_]+$ ]]; then
    echo "invalid migration filename: $migration" >&2
    exit 65
  fi
  checksum="$(checksum_file "$migration")"
  applied_checksum="$(
    psql "$DATABASE_URL" -X -Aqt -v ON_ERROR_STOP=1 \
      -c "SELECT checksum FROM schema_migrations WHERE version = '$version'" \
      2>/dev/null || true
  )"

  if [[ -n "$applied_checksum" ]]; then
    if [[ "$applied_checksum" != "$checksum" ]]; then
      echo "checksum mismatch for applied migration $version" >&2
      exit 78
    fi
    continue
  fi

  transaction_file="$(mktemp "${TMPDIR:-/tmp}/open-card-migration.XXXXXX.sql")"
  trap 'rm -f "$transaction_file"' EXIT
  {
    echo 'BEGIN;'
    echo "SELECT pg_advisory_xact_lock(hashtextextended('open-card-control-plane-migrations', 0));"
    cat "$migration"
    printf "INSERT INTO schema_migrations(version, checksum) VALUES ('%s', '%s');\n" "$version" "$checksum"
    echo 'COMMIT;'
  } > "$transaction_file"
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$transaction_file"
  rm -f "$transaction_file"
  trap - EXIT
done

psql "$DATABASE_URL" -X -Aqt -v ON_ERROR_STOP=1 \
  -c "SELECT version || E'\\t' || checksum FROM schema_migrations ORDER BY version;"
