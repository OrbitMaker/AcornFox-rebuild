#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ssh_key=${OPEN_CARD_DEVBOX_SSH_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
ssh_target=${OPEN_CARD_DEVBOX_SSH_TARGET:-ubuntu@192.168.31.64}
task_root=/home/ubuntu/opencard-mvp-fa8f8eab
remote_root=$task_root/m6-integration-20260825
database=opencard_mvp_fa8f8eab_m6_20260825
container=opencard-mvp-fa8f8eab-postgres
local_tmp=$(mktemp -d)
ssh_args=(-i "$ssh_key" -o BatchMode=yes "$ssh_target")

cleanup() {
  ssh "${ssh_args[@]}" "docker exec -e M6_DB=$database $container sh -lc 'dropdb -U \"\$POSTGRES_USER\" --if-exists \"\$M6_DB\"'" >/dev/null 2>&1 || true
  ssh "${ssh_args[@]}" "test -f '$task_root/.open-card-task-marker' && rm -f '$remote_root/ai.test' && rmdir '$remote_root' 2>/dev/null || true" >/dev/null 2>&1 || true
  rm -rf "$local_tmp"
}
trap cleanup EXIT

cd "$repo_root"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -tags=integration -o "$local_tmp/ai.test" ./tests/integration/ai
ssh "${ssh_args[@]}" "test -f '$task_root/.open-card-task-marker' && mkdir -p '$remote_root' && test ! -e '$remote_root/ai.test'"
scp -q -i "$ssh_key" "$local_tmp/ai.test" "$ssh_target:$remote_root/ai.test"
ssh "${ssh_args[@]}" "docker exec -e M6_DB=$database $container sh -lc 'createdb -U \"\$POSTGRES_USER\" \"\$M6_DB\"'"
for migration in migrations/control-plane/*.sql; do
  ssh "${ssh_args[@]}" "docker exec -i -e M6_DB=$database $container sh -lc 'psql -q -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d \"\$M6_DB\"'" < "$migration"
done

ssh "${ssh_args[@]}" bash -s -- "$database" "$remote_root" "$container" <<'REMOTE'
set -euo pipefail
database=$1; remote_root=$2; container=$3
pg_user=$(docker exec "$container" sh -lc 'printf %s "$POSTGRES_USER"')
password_file=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" | sed -n 's/^POSTGRES_PASSWORD_FILE=//p')
test -n "$password_file"
pg_password=$(docker exec "$container" cat "$password_file")
OPEN_CARD_TEST_DATABASE_URL="postgres://$pg_user:$pg_password@127.0.0.1:55432/$database?sslmode=disable" "$remote_root/ai.test" -test.v
printf 'latest_migration='
docker exec -e M6_DB="$database" "$container" sh -lc "psql -U \"\$POSTGRES_USER\" -d \"\$M6_DB\" -Atc \"SELECT CASE WHEN to_regclass('public.m6_ai_interventions') IS NOT NULL AND to_regclass('public.m6_rule_registry_events') IS NOT NULL AND to_regclass('public.m6_ai_settings_events') IS NOT NULL THEN '0021' ELSE 'missing' END\""
printf 'm6_ai_tables='
docker exec -e M6_DB="$database" "$container" sh -lc "psql -U \"\$POSTGRES_USER\" -d \"\$M6_DB\" -Atc \"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'm6_ai_%'\""
printf 'm6_rule_tables='
docker exec -e M6_DB="$database" "$container" sh -lc "psql -U \"\$POSTGRES_USER\" -d \"\$M6_DB\" -Atc \"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'm6_rule_%'\""
REMOTE
