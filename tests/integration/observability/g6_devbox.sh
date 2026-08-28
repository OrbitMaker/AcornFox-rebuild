#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
devbox_host="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
task_id="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"
local_port="${OPEN_CARD_G6_TUNNEL_PORT:-55435}"
remote_base="/home/ubuntu/$task_id"
db_container="$task_id-postgres"
database_name="opencard_mvp_fa8f8eab_g6_gate"
ssh_args=(-i "$DEVBOX_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8)

test "$task_id" = "opencard-mvp-fa8f8eab"
ssh "${ssh_args[@]}" "$devbox_host" \
  "test -f '$remote_base/.open-card-task-marker' && test \"\$(docker inspect '$db_container' --format '{{index .Config.Labels \"open-card.task\"}}')\" = '$task_id'"
host_baseline_before="$(ssh "${ssh_args[@]}" "$devbox_host" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"
db_password="$(ssh "${ssh_args[@]}" "$devbox_host" "cat '$remote_base/postgres-password'")"
test -n "$db_password"

ssh "${ssh_args[@]}" -o ExitOnForwardFailure=yes -N \
  -L "127.0.0.1:$local_port:127.0.0.1:55432" "$devbox_host" &
tunnel_pid=$!
admin_url="host=127.0.0.1 port=$local_port user=opencard password=$db_password dbname=postgres sslmode=disable"
database_url="host=127.0.0.1 port=$local_port user=opencard password=$db_password dbname=$database_name sslmode=disable"
database_created=0

cleanup() {
  if [[ "$database_created" -eq 1 ]]; then
    psql "$admin_url" -X -v ON_ERROR_STOP=1 -v database="$database_name" <<'SQL' >/dev/null 2>&1 || true
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=:'database' AND pid<>pg_backend_pid();
SELECT format('DROP DATABASE IF EXISTS %I', :'database') \gexec
SQL
  fi
  kill "$tunnel_pid" 2>/dev/null || true
  wait "$tunnel_pid" 2>/dev/null || true
  unset db_password admin_url database_url
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$local_port") 2>/dev/null; then
    exec 3>&-
    break
  fi
  sleep 0.1
done
kill -0 "$tunnel_pid"

psql "$admin_url" -X -v ON_ERROR_STOP=1 -v database="$database_name" <<'SQL' >/dev/null
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=:'database' AND pid<>pg_backend_pid();
SELECT format('DROP DATABASE IF EXISTS %I', :'database') \gexec
SELECT format('CREATE DATABASE %I OWNER opencard', :'database') \gexec
SQL
database_created=1

(
  cd "$repo_root"
  DATABASE_URL="$database_url" ./scripts/mvp/control-plane-migrate.sh
  OPEN_CARD_TEST_DATABASE_URL="$database_url" go test -count=1 -tags integration ./tests/integration/observability -run '^TestG6MetricScaleDedupAndQueryGate$' -v
)

database_size="$(psql "$database_url" -X -Aqt -v ON_ERROR_STOP=1 -c 'SELECT pg_size_pretty(pg_database_size(current_database()))')"
echo "g6_temporary_database_size=$database_size"
cleanup
trap - EXIT INT TERM
database_created=0
echo "g6_temporary_database_removed=yes"

host_baseline_after="$(ssh "${ssh_args[@]}" "$devbox_host" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"
test "$host_baseline_before" = "$host_baseline_after"
echo "non_task_host_baseline_unchanged=yes"
