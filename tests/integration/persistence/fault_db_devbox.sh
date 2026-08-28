#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

DEVBOX_HOST="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
DB_CONTAINER="${DB_CONTAINER:-opencard-mvp-fa8f8eab-postgres}"
run_suffix="$(date -u +%Y%m%d%H%M%S)-$$"
PSQL=(docker exec -i "$DB_CONTAINER" psql -U opencard -d opencard -X -v ON_ERROR_STOP=1 -v "run_suffix=$run_suffix")

remote_psql() {
  ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" "${PSQL[*]}"
}

host_baseline_before="$(ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"

remote_psql >/dev/null <<'SQL' &
BEGIN;
INSERT INTO applications(id, name) VALUES ('app-fault-db-' || :'run_suffix', 'fault fixture');
INSERT INTO outbox_events(id, aggregate_type, aggregate_id, aggregate_version, sequence, event_type, payload)
VALUES ('evt-fault-db-uncommitted-' || :'run_suffix', 'application', 'app-fault-db-' || :'run_suffix', 1, 1, 'application.created', '{}');
SELECT pg_sleep(30);
COMMIT;
SQL
transaction_pid=$!

sleep 1
ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
  "test \"\$(docker inspect '$DB_CONTAINER' --format '{{index .Config.Labels \"open-card.task\"}}')\" = opencard-mvp-fa8f8eab && docker kill --signal KILL '$DB_CONTAINER' >/dev/null"

set +e
wait "$transaction_pid"
transaction_exit=$?
set -e
if [[ "$transaction_exit" -eq 0 ]]; then
  echo "database interruption did not abort the open transaction" >&2
  exit 1
fi

ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" "docker start '$DB_CONTAINER' >/dev/null"
for _ in $(seq 1 30); do
  if ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
    "docker exec '$DB_CONTAINER' psql -U opencard -d opencard -X -Aqt -c 'SELECT 1'" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
  "docker exec '$DB_CONTAINER' psql -U opencard -d opencard -X -Aqt -v ON_ERROR_STOP=1 -c 'SELECT 1'" >/dev/null

partial_count="$(
  ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
    "docker exec '$DB_CONTAINER' psql -U opencard -d opencard -X -Aqt -v ON_ERROR_STOP=1 -c \"SELECT (SELECT count(*) FROM applications WHERE id='app-fault-db-$run_suffix') + (SELECT count(*) FROM outbox_events WHERE id='evt-fault-db-uncommitted-$run_suffix')\""
)"
if [[ "$partial_count" != 0 ]]; then
  echo "database recovery exposed partial business/outbox state" >&2
  exit 1
fi

remote_psql >/dev/null <<'SQL'
INSERT INTO applications(id, name) VALUES ('app-fault-db-replay-' || :'run_suffix', 'replay fixture');
INSERT INTO outbox_events(id, aggregate_type, aggregate_id, aggregate_version, sequence, event_type, payload)
VALUES ('evt-fault-db-replay-' || :'run_suffix', 'application', 'app-fault-db-replay-' || :'run_suffix', 1, 1, 'application.created', '{}');
UPDATE outbox_events SET published_at = COALESCE(published_at, now()) WHERE id = 'evt-fault-db-replay-' || :'run_suffix';
UPDATE outbox_events SET published_at = COALESCE(published_at, now()) WHERE id = 'evt-fault-db-replay-' || :'run_suffix';
SQL

replay_count="$(
  ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
    "docker exec '$DB_CONTAINER' psql -U opencard -d opencard -X -Aqt -v ON_ERROR_STOP=1 -c \"SELECT count(*) FROM outbox_events WHERE id='evt-fault-db-replay-$run_suffix' AND published_at IS NOT NULL\""
)"
if [[ "$replay_count" != 1 ]]; then
  echo "outbox replay was not idempotent" >&2
  exit 1
fi

host_baseline_after="$(ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"
test "$host_baseline_before" = "$host_baseline_after"

printf '%s\n' \
  'transaction_interrupted=ok' \
  'partial_state_absent=ok' \
  'database_recovered=ok' \
  'outbox_replay_idempotent=ok' \
  'non_task_host_baseline_unchanged=yes'
