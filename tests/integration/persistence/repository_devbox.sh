#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
devbox_host="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
task_id="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"
local_port="${OPEN_CARD_DB_TUNNEL_PORT:-55433}"
run_suffix="$(date -u +%Y%m%d%H%M%S)-$$"
remote_base="/home/ubuntu/$task_id"
db_container="$task_id-postgres"

ssh_args=(-i "$DEVBOX_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8)
ssh "${ssh_args[@]}" "$devbox_host" \
  "test -f '$remote_base/.open-card-task-marker' && test \"\$(docker inspect '$db_container' --format '{{index .Config.Labels \"open-card.task\"}}')\" = '$task_id'"

host_baseline_before="$(ssh "${ssh_args[@]}" "$devbox_host" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"

db_password="$(ssh "${ssh_args[@]}" "$devbox_host" "cat '$remote_base/postgres-password'")"
if [[ -z "$db_password" ]]; then
  echo "task database password is empty" >&2
  exit 65
fi

ssh "${ssh_args[@]}" \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=10 \
  -o ServerAliveCountMax=3 \
  -N -L "127.0.0.1:$local_port:127.0.0.1:55432" \
  "$devbox_host" &
tunnel_pid=$!
server_pid=""
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/open-card-repository-e2e.XXXXXX")"

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  kill "$tunnel_pid" 2>/dev/null || true
  wait "$tunnel_pid" 2>/dev/null || true
  rm -rf "$temp_dir"
  unset db_password database_url
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$local_port") 2>/dev/null; then
    exec 3>&-
    break
  fi
  sleep 0.1
done
if ! kill -0 "$tunnel_pid" 2>/dev/null; then
  echo "database tunnel exited before becoming ready" >&2
  exit 69
fi

database_url="host=127.0.0.1 port=$local_port user=opencard password=$db_password dbname=opencard sslmode=disable"
test_pattern="${OPEN_CARD_PERSISTENCE_TEST_PATTERN:-^TestPostgresRepository(ConcurrencyReplayAndLeaseTakeover|QueriesOneHundredThousandEventsUnderGate)$}"
(
  cd "$repo_root"
  DATABASE_URL="$database_url" ./scripts/mvp/control-plane-migrate.sh
  OPEN_CARD_TEST_DATABASE_URL="$database_url" go test -count=1 -tags integration ./tests/integration/persistence -run "$test_pattern" -v
  go build -o "$temp_dir/open-card-server" ./cmd/open-card-server
)

start_server() {
  OPEN_CARD_DATABASE_URL="$database_url" OPEN_CARD_SERVER_ADDR=127.0.0.1:18089 \
    "$temp_dir/open-card-server" >"$temp_dir/server.stdout.log" 2>"$temp_dir/server.stderr.log" &
  server_pid=$!
  for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:18089/readyz >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  echo "control-plane server did not become ready" >&2
  sed -n '1,120p' "$temp_dir/server.stderr.log" >&2
  exit 70
}

stop_server() {
  kill "$server_pid"
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}

start_server
create_response="$(curl -fsS \
  -H 'Content-Type: application/json' \
  -H "Idempotency-Key: repository-sse-restart-$run_suffix" \
  --data '{"name":"repository-sse-restart"}' \
  http://127.0.0.1:18089/api/v1/applications)"
operation_id="$(printf '%s' "$create_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["operation_id"])')"
application_id="$(printf '%s' "$create_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["application"]["id"])')"
stop_server

start_server
list_response="$(curl -fsS http://127.0.0.1:18089/api/v1/applications)"
printf '%s' "$list_response" | APPLICATION_ID="$application_id" python3 -c \
  'import json,os,sys; assert os.environ["APPLICATION_ID"] in {item["id"] for item in json.load(sys.stdin)["items"]}'
set +e
replay_response="$(curl -sN --max-time 2 -H 'Last-Event-ID: evt-0' \
  "http://127.0.0.1:18089/api/v1/operations/$operation_id/events")"
replay_status=$?
set -e
if [[ "$replay_status" -ne 0 && "$replay_status" -ne 28 ]]; then
  echo "SSE replay request failed with curl status $replay_status" >&2
  exit 71
fi
grep -Fq "\"operation_id\":\"$operation_id\"" <<<"$replay_response"
grep -Fq "\"application_id\":\"$application_id\"" <<<"$replay_response"
stop_server
echo "postgres_server_restart_sse_replay=yes"

host_baseline_after="$(ssh "${ssh_args[@]}" "$devbox_host" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"
test "$host_baseline_before" = "$host_baseline_after"
ssh "${ssh_args[@]}" "$devbox_host" \
  "test \"\$(systemctl is-active docker.service)\" = active; test \"\$(systemctl is-active frpc.service)\" = active"
echo "non_task_host_baseline_unchanged=yes"
