#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ssh_key=${OPEN_CARD_DEVBOX_SSH_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
ssh_target=${OPEN_CARD_DEVBOX_SSH_TARGET:-ubuntu@192.168.31.64}
task_root=/home/ubuntu/opencard-mvp-fa8f8eab
remote_root=$task_root/m5-integration-20260825
database=opencard_mvp_fa8f8eab_m5_20260825
container=opencard-mvp-fa8f8eab-postgres
local_tmp=$(mktemp -d)
facts_local=${OPEN_CARD_M5_DOCKER_FACTS_LOCAL:-}
ssh_args=(-i "$ssh_key" -o BatchMode=yes "$ssh_target")

cleanup() {
  ssh "${ssh_args[@]}" "docker exec -e M5_DB=$database $container sh -lc 'dropdb -U \"\$POSTGRES_USER\" --if-exists \"\$M5_DB\"'" >/dev/null 2>&1 || true
  ssh "${ssh_args[@]}" "test -f '$task_root/.open-card-task-marker' && rm -f '$remote_root/usage.test' '$remote_root/docker-facts.json' && rmdir '$remote_root' 2>/dev/null || true" >/dev/null 2>&1 || true
  rm -rf "$local_tmp"
}
trap cleanup EXIT

cd "$repo_root"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -tags=integration -o "$local_tmp/usage.test" ./tests/integration/usage
ssh "${ssh_args[@]}" "test -f '$task_root/.open-card-task-marker' && mkdir -p '$remote_root' && test ! -e '$remote_root/usage.test'"
scp -q -i "$ssh_key" "$local_tmp/usage.test" "$ssh_target:$remote_root/usage.test"
if [[ -n "$facts_local" ]]; then
  test -f "$facts_local"
  scp -q -i "$ssh_key" "$facts_local" "$ssh_target:$remote_root/docker-facts.json"
fi
ssh "${ssh_args[@]}" "docker exec -e M5_DB=$database $container sh -lc 'createdb -U \"\$POSTGRES_USER\" \"\$M5_DB\"'"

for migration in migrations/control-plane/*.sql; do
  ssh "${ssh_args[@]}" "docker exec -i -e M5_DB=$database $container sh -lc 'psql -q -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d \"\$M5_DB\"'" < "$migration"
done

ssh "${ssh_args[@]}" bash -s -- "$database" "$remote_root" "$container" <<'REMOTE'
set -euo pipefail
database=$1
remote_root=$2
container=$3
pg_user=$(docker exec "$container" sh -lc 'printf %s "$POSTGRES_USER"')
password_file=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" | sed -n 's/^POSTGRES_PASSWORD_FILE=//p')
test -n "$password_file"
pg_password=$(docker exec "$container" cat "$password_file")
facts_env=()
if [[ -f "$remote_root/docker-facts.json" ]]; then
  facts_env=(env OPEN_CARD_M5_DOCKER_FACTS="$remote_root/docker-facts.json")
fi
OPEN_CARD_TEST_DATABASE_URL="postgres://$pg_user:$pg_password@127.0.0.1:55432/$database?sslmode=disable" "${facts_env[@]}" "$remote_root/usage.test" -test.v
printf 'latest_migration='
docker exec -e M5_DB="$database" "$container" sh -lc "psql -U \"\$POSTGRES_USER\" -d \"\$M5_DB\" -Atc \"SELECT CASE WHEN to_regclass('public.m5_usage_raw_facts') IS NOT NULL AND to_regclass('public.m5_usage_bucket_facts') IS NOT NULL AND to_regclass('public.m4_rollout_coordinations') IS NOT NULL THEN '0020' ELSE 'missing' END\""
printf 'm5_tables='
docker exec -e M5_DB="$database" "$container" sh -lc "psql -U \"\$POSTGRES_USER\" -d \"\$M5_DB\" -Atc \"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'm5_usage_%'\""
printf 'usage_rows='
docker exec -e M5_DB="$database" "$container" sh -lc "psql -U \"\$POSTGRES_USER\" -d \"\$M5_DB\" -Atc \"SELECT (SELECT count(*) FROM m5_usage_raw_facts)::text || '|' || (SELECT count(*) FROM m5_usage_bucket_current)::text\""
REMOTE
