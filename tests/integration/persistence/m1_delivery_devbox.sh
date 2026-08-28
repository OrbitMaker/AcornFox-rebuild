#!/usr/bin/env bash
set -euo pipefail

[[ -n "${DEVBOX_SSH_KEY:-}" ]] || { echo 'DEVBOX_SSH_KEY is required' >&2; exit 64; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
host=${DEVBOX_HOST:-ubuntu@192.168.31.64}
task=opencard-mvp-fa8f8eab
port=${OPEN_CARD_DB_TUNNEL_PORT:-55445}
database=${OPEN_CARD_M1_DATABASE:-opencard_mvp_fa8f8eab_m1_delivery_gate}
remote=/home/ubuntu/$task
container=$task-postgres
ssh_args=(-i "$DEVBOX_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8)

ssh "${ssh_args[@]}" "$host" "test -f '$remote/.open-card-task-marker'; test \"\$(docker inspect '$container' --format '{{index .Config.Labels \"open-card.task\"}}')\" = '$task'"
before=$(ssh "${ssh_args[@]}" "$host" "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")
password=$(ssh "${ssh_args[@]}" "$host" "cat '$remote/postgres-password'")
[[ -n "$password" ]]
ssh "${ssh_args[@]}" -o ExitOnForwardFailure=yes -N -L "127.0.0.1:$port:127.0.0.1:55432" "$host" &
tunnel=$!
cleanup() {
  kill "$tunnel" 2>/dev/null || true
  wait "$tunnel" 2>/dev/null || true
  unset password PGPASSWORD
}
trap cleanup EXIT INT TERM
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&-; break; fi
  sleep 0.1
done
kill -0 "$tunnel"
export PGPASSWORD=$password
admin="postgresql://opencard@127.0.0.1:$port/postgres?sslmode=disable"
url="postgresql://opencard@127.0.0.1:$port/$database?sslmode=disable"
psql "$admin" -X -v ON_ERROR_STOP=1 -v database="$database" <<'SQL' >/dev/null
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'database' AND pid <> pg_backend_pid();
SELECT format('DROP DATABASE IF EXISTS %I', :'database') \gexec
SELECT format('CREATE DATABASE %I OWNER opencard', :'database') \gexec
SQL
DATABASE_URL=$url "$repo_root/scripts/mvp/control-plane-migrate.sh" "$repo_root/migrations/control-plane" >/dev/null
OPEN_CARD_TEST_DATABASE_URL=$url go test -count=1 -tags integration ./tests/integration/persistence -run '^TestM1DeliveryPersistsDigestTaskObservationAndServing$' -v

after=$(ssh "${ssh_args[@]}" "$host" "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")
test "$before" = "$after"
printf '%s\n' 'm1_postgres_delivery=PASS' 'digest_task_observation_serving=PASS' 'non_task_host_baseline_unchanged=yes'
