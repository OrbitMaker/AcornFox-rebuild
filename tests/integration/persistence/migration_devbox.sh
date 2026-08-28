#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
devbox_host="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
task_id="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"
local_port="${OPEN_CARD_DB_TUNNEL_PORT:-55434}"
remote_base="/home/ubuntu/$task_id"
db_container="$task_id-postgres"
ssh_args=(-i "$DEVBOX_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8)

ssh "${ssh_args[@]}" "$devbox_host" \
  "test -f '$remote_base/.open-card-task-marker' && test \"\$(docker inspect '$db_container' --format '{{index .Config.Labels \"open-card.task\"}}')\" = '$task_id'"
db_password="$(ssh "${ssh_args[@]}" "$devbox_host" "cat '$remote_base/postgres-password'")"
test -n "$db_password"

ssh "${ssh_args[@]}" -o ExitOnForwardFailure=yes -N \
  -L "127.0.0.1:$local_port:127.0.0.1:55432" "$devbox_host" &
tunnel_pid=$!
cleanup() {
  kill "$tunnel_pid" 2>/dev/null || true
  wait "$tunnel_pid" 2>/dev/null || true
  unset db_password PGPASSWORD
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

export PGPASSWORD="$db_password"
(
  cd "$repo_root"
  ADMIN_DATABASE_URL="postgresql://opencard@127.0.0.1:$local_port/postgres?sslmode=disable" \
  DATABASE_HOST=127.0.0.1 \
  DATABASE_PORT="$local_port" \
  ./tests/integration/persistence/migration_gate.sh
)
