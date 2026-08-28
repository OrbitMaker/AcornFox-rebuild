#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ADMIN_DATABASE_URL:-}" || -z "${DATABASE_HOST:-}" || -z "${DATABASE_PORT:-}" ]]; then
  echo "ADMIN_DATABASE_URL, DATABASE_HOST, and DATABASE_PORT are required" >&2
  exit 64
fi

MIGRATIONS_DIR="${MIGRATIONS_DIR:-migrations/control-plane}"
MIGRATOR="${MIGRATOR:-./scripts/mvp/control-plane-migrate.sh}"
TASK_DB_PREFIX="${OPEN_CARD_TASK_DB_PREFIX:-opencard_mvp_fa8f8eab}"
PRIMARY_DB="${TASK_DB_PREFIX}_m0_gate"
N_MINUS_ONE_DB="${TASK_DB_PREFIX}_m0_nminus1"

database_url() {
  printf 'postgresql://opencard@%s:%s/%s?sslmode=disable' "$DATABASE_HOST" "$DATABASE_PORT" "$1"
}

for database in "$PRIMARY_DB" "$N_MINUS_ONE_DB"; do
  psql "$ADMIN_DATABASE_URL" -X -v ON_ERROR_STOP=1 -v database="$database" <<'SQL' >/dev/null
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'database' AND pid <> pg_backend_pid();
SELECT format('DROP DATABASE IF EXISTS %I', :'database') \gexec
SELECT format('CREATE DATABASE %I OWNER opencard', :'database') \gexec
SQL
done

export DATABASE_URL="$(database_url "$PRIMARY_DB")"
"$MIGRATOR" "$MIGRATIONS_DIR" >/dev/null
"$MIGRATOR" "$MIGRATIONS_DIR" >/dev/null

expected_checksum="$(shasum -a 256 "$MIGRATIONS_DIR/0001_foundation.sql" | awk '{print $1}')"
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c \
  "UPDATE schema_migrations SET checksum = repeat('0', 64) WHERE version = '0001_foundation'" >/dev/null
set +e
"$MIGRATOR" "$MIGRATIONS_DIR" >/dev/null 2>&1
tamper_exit=$?
set -e
if [[ "$tamper_exit" -ne 78 ]]; then
  echo "checksum tamper was not rejected with exit 78" >&2
  exit 1
fi
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c \
  "UPDATE schema_migrations SET checksum = '$expected_checksum' WHERE version = '0001_foundation'" >/dev/null

export DATABASE_URL="$(database_url "$N_MINUS_ONE_DB")"
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE schema_migrations (
    version text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
SQL
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$MIGRATIONS_DIR/0001_foundation.sql" >/dev/null
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c \
  "INSERT INTO schema_migrations(version, checksum) VALUES ('0001_foundation', '$expected_checksum')" >/dev/null
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO applications(id,name) VALUES('app-compat-old','old compatibility fixture');
INSERT INTO environments(id,application_id,name) VALUES('env-compat-old','app-compat-old','old');
INSERT INTO operations(id,environment_id,operation_type,idempotency_key,state)
VALUES('op-compat-old','env-compat-old','deploy','compat-old','pending');
INSERT INTO task_leases(task_id,operation_id,state,payload)
VALUES('task-compat-old','op-compat-old','ready','{"kind":"observe"}'::jsonb);
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,event_type,payload)
VALUES('evt-compat-old','operation','op-compat-old',1,1,'operation.created','{"status":"preparing"}'::jsonb);
SQL
"$MIGRATOR" "$MIGRATIONS_DIR" >/dev/null

legacy_defaults="$(psql "$DATABASE_URL" -X -Aqt -v ON_ERROR_STOP=1 -c \
  "SELECT t.wire_version || ':' || e.payload_version FROM task_leases t CROSS JOIN outbox_events e WHERE t.task_id='task-compat-old' AND e.id='evt-compat-old'")"
if [[ "$legacy_defaults" != "1.0:1.0" ]]; then
  echo "legacy task/event compatibility defaults are wrong: $legacy_defaults" >&2
  exit 1
fi
legacy_reader_count="$(psql "$DATABASE_URL" -X -Aqt -v ON_ERROR_STOP=1 -c \
  "SELECT count(*) FROM task_leases WHERE task_id='task-compat-old' AND state='ready' AND payload->>'kind'='observe'")"
if [[ "$legacy_reader_count" != 1 ]]; then
  echo "legacy task reader no longer works" >&2
  exit 1
fi

psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO applications(id, name) VALUES ('app-old-reader', 'compatibility fixture');
SELECT id, name, version FROM applications WHERE id = 'app-old-reader';
SQL

psql "$DATABASE_URL" -X -v ON_ERROR_STOP=0 <<'SQL' >/dev/null 2>&1 || true
BEGIN;
INSERT INTO applications(id, name) VALUES ('app-rolled-back', 'must not survive');
SELECT * FROM relation_that_does_not_exist;
COMMIT;
SQL

if [[ "$(psql "$DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM applications WHERE id = 'app-rolled-back'")" != 0 ]]; then
  echo "failed migration transaction left a partial row" >&2
  exit 1
fi

printf '%s\n' \
  'empty_to_latest=ok' \
  'repeat_execution=ok' \
  'checksum_tamper_rejected=ok' \
  'n_minus_one_to_latest=ok' \
  'failed_transaction_rollback=ok' \
  'old_reader_compatibility=ok' \
  'legacy_task_event_defaults=ok'
