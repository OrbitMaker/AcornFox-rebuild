#!/usr/bin/env bash
set -euo pipefail

domain=opencard-mvp-fa8f8eab-build-worker-01
marker=/etc/opencard-mvp-fa8f8eab-clean-worker
offline=/opt/opencard-offline
evidence=/var/lib/opencard-mvp-fa8f8eab/evidence/g7
install_env=(OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="$domain")

wait_url() {
  local url=$1
  for _ in $(seq 1 100); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  echo "health endpoint did not become ready: $url" >&2
  return 1
}

test "$(id -u)" -eq 0
test "$(cat "$marker")" = "$domain"
install -d -m 0750 "$evidence"
db_password=$(cat /etc/open-card/postgres-password)
database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
export OPEN_CARD_DATABASE_URL="$database_url"

for service in open-card-server open-card-agent open-card-buildkit open-card-caddy; do
  test "$(systemctl is-active "$service")" = active
  test "$(systemctl is-enabled "$service")" = enabled
done
wait_url http://127.0.0.1:8080/readyz
wait_url http://127.0.0.1:18481/readyz
curl -fsS http://127.0.0.1:8080/readyz >"$evidence/server-ready.json"
curl -fsS http://127.0.0.1:18481/readyz >"$evidence/caddy-ready.json"
test "$(stat -c %a /etc/open-card/agent.key)" = 600
test "$(stat -c %a /etc/open-card/server.env)" = 600
test "$(readlink /opt/open-card/current)" = releases/release-0.1.0

bad_migrations="$offline/migrations/bad"
python3 - "$offline/migrations/all" "$bad_migrations" <<'PY'
from pathlib import Path
import shutil,sys
source,target=map(Path,sys.argv[1:])
if target.exists(): shutil.rmtree(target)
shutil.copytree(source,target)
(target/'0008_injected_failure.sql').write_text('CREATE TABLE must_rollback(id integer);\nSELECT 1/0;\n',encoding='utf-8')
PY
cat >/usr/local/libexec/opencard-upgrade-health-fail <<EOF
#!/usr/bin/env bash
set -euo pipefail
DATABASE_URL='$database_url' '$offline/g7/control-plane-migrate.sh' '$bad_migrations'
EOF
chmod 0750 /usr/local/libexec/opencard-upgrade-health-fail
set +e
env "${install_env[@]}" "$offline/g7/upgrade.sh" --root / --offline --activate \
  --bundle "$offline/releases/release-0.2.0" \
  --database-dump-command /usr/local/libexec/opencard-pg-dump \
  --health-command /usr/local/libexec/opencard-upgrade-health-fail >"$evidence/upgrade-failure.log" 2>&1
failed_status=$?
set -e
test "$failed_status" -ne 0
grep -Fq 'rolling back release pointer' "$evidence/upgrade-failure.log"
test "$(readlink /opt/open-card/current)" = releases/release-0.1.0
test "$(systemctl is-active open-card-server)" = active
test "$(psql "$database_url" -Atc "SELECT to_regclass('public.must_rollback') IS NULL")" = t

cat >/usr/local/libexec/opencard-upgrade-health-ok <<EOF
#!/usr/bin/env bash
set -euo pipefail
DATABASE_URL='$database_url' '$offline/g7/control-plane-migrate.sh' '$offline/migrations/all'
curl -fsS http://127.0.0.1:8080/readyz >/dev/null
EOF
chmod 0750 /usr/local/libexec/opencard-upgrade-health-ok

upgrade_to() {
  local release=$1 health=$2
  systemctl reset-failed open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service || true
  env "${install_env[@]}" "$offline/g7/upgrade.sh" --root / --offline --activate \
    --bundle "$offline/releases/$release" \
    --database-dump-command /usr/local/libexec/opencard-pg-dump \
    --health-command "$health"
}
upgrade_to release-0.2.0 /usr/local/libexec/opencard-upgrade-health-ok >"$evidence/upgrade-success-1.log"
test "$(readlink /opt/open-card/current)" = releases/release-0.2.0
for round in 2 3; do
  upgrade_to release-0.1.0 /usr/bin/true >"$evidence/downgrade-$round.log"
  test "$(readlink /opt/open-card/current)" = releases/release-0.1.0
  upgrade_to release-0.2.0 /usr/local/libexec/opencard-upgrade-health-ok >"$evidence/upgrade-success-$round.log"
  test "$(readlink /opt/open-card/current)" = releases/release-0.2.0
done

psql "$database_url" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS g7_restore_sentinel(id integer PRIMARY KEY, value text NOT NULL);
INSERT INTO g7_restore_sentinel VALUES(1,'before-backup')
ON CONFLICT(id) DO UPDATE SET value=excluded.value;
SQL
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/backup-control-plane.sh" --root / --reason g7-restore \
  --release-version 0.2.0 --database-dump-command /usr/local/libexec/opencard-pg-dump >"$evidence/backup.log"
metadata=$(python3 - <<'PY'
import json
from pathlib import Path
matches=[]
for path in Path('/var/lib/open-card/backups').glob('*.json'):
    value=json.loads(path.read_text(encoding='utf-8'))
    if value.get('reason')=='g7-restore': matches.append((value.get('created_at',''),path))
assert matches, matches
print(sorted(matches)[-1][1])
PY
)
test -n "$metadata"
cp "$metadata" "$evidence/backup-metadata.json"
psql "$database_url" -v ON_ERROR_STOP=1 -c "UPDATE g7_restore_sentinel SET value='after-backup' WHERE id=1" >/dev/null
systemctl stop open-card-server.service
env "${install_env[@]}" "$offline/g7/restore-control-plane.sh" --root / --backup "$metadata" >"$evidence/restore.log"
test -f /var/lib/open-card/control-plane.sql
sudo -u postgres dropdb --force opencard
sudo -u postgres createdb -O opencard opencard
psql "$database_url" -v ON_ERROR_STOP=1 -f /var/lib/open-card/control-plane.sql >"$evidence/restore-import.log"
test "$(psql "$database_url" -Atc "SELECT value FROM g7_restore_sentinel WHERE id=1")" = before-backup
test "$(psql "$database_url" -Atc 'SELECT count(*) FROM schema_migrations')" -ge 7
systemctl reset-failed open-card-server.service
systemctl start open-card-server.service
wait_url http://127.0.0.1:8080/readyz

systemctl restart open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service
for service in open-card-server open-card-agent open-card-buildkit open-card-caddy; do test "$(systemctl is-active "$service")" = active; done
touch /var/lib/opencard-mvp-fa8f8eab/g7-pre-reboot-complete
printf '%s\n' \
  'g7_pre_reboot=PASS' \
  'offline_install=PASS' \
  'systemd_four_units=active_enabled' \
  'failed_migration=transaction_rollback_and_release_pointer_rollback' \
  'n_minus_one_to_n_rounds=3' \
  'postgres_backup_restore=PASS' \
  'service_restart=PASS'
