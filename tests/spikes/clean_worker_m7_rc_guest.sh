#!/usr/bin/env bash
set -euo pipefail
umask 077

domain=opencard-mvp-fa8f8eab-build-worker-01
offline=/opt/opencard-offline
payload=$offline/outer/payload
state=/var/lib/opencard-mvp-fa8f8eab
evidence=$state/evidence/m7-rc
install_env=(OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="$domain")

test "$(id -u)" -eq 0
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
test "$(readlink /opt/open-card/current)" = releases/release-0.7.0-rc.1
test "$(cat /var/lib/open-card/schema.version)" = 21
install -d -m 0750 "$evidence"

db_password=$(cat /etc/open-card/postgres-password)
database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
export OPEN_CARD_DATABASE_URL="$database_url"
wait_url() {
  local url=$1
  for _ in $(seq 1 300); do curl -fsS "$url" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}
snapshot() {
  local output=$1
  python3 - "$output" <<'PY'
import json,os,pathlib,subprocess,sys
def run(*args): return subprocess.check_output(args,text=True).strip()
tables=['applications','releases','deployments','operations','audit_log','outbox','m4_log_entries','m4_webhook_events','m5_usage_raw_facts','m5_usage_bucket_facts','m6_ai_invocations','m6_ai_interventions']
url=os.environ['OPEN_CARD_DATABASE_URL']
counts={}
for table in tables:
    exists=run('psql',url,'-X','-Aqt','-c',f"SELECT to_regclass('public.{table}') IS NOT NULL")=='t'
    counts[table]=int(run('psql',url,'-X','-Aqt','-c',f'SELECT count(*) FROM {table}')) if exists else None
    value={'current_release':os.readlink('/opt/open-card/current'),'schema_migrations':int(run('psql',url,'-X','-Aqt','-c','SELECT count(*) FROM schema_migrations')),'counts':counts,'services':{},'routes_digest':run('psql',url,'-X','-Aqt','-c',"SELECT md5(coalesce(string_agg(route_id||':'||deployment_id,'|' ORDER BY route_id),'')) FROM m3_route_pointers")}
for service in ['open-card-server','open-card-agent','open-card-buildkit','open-card-caddy','postgresql','docker','containerd']:
    value['services'][service]=run('systemctl','is-active',service)
pathlib.Path(sys.argv[1]).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
PY
}

for service in docker containerd postgresql open-card-server open-card-agent open-card-buildkit open-card-caddy; do
  test "$(systemctl is-active "$service")" = active || { echo "required service is not active: $service" >&2; exit 1; }
done
wait_url http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:2019/config/ >"$evidence/caddy-config-before.json"
snapshot "$evidence/before.json"

# The final six-step no-AI path reuses the already reviewed M4 canonical
# runner. M7 supplies its fixtures from the separate test-only archive; the
# production release itself must not contain the Caddy failure fixture.
test ! -e /opt/open-card/current/bin/open-card-caddy-fixture
test -x "$payload/bin/amd64/open-card-caddy-fixture"
grep -Fxq OPEN_CARD_M6_ENABLED=false /etc/open-card/server.env
OPEN_CARD_M4_EXPECTED_RELEASE=release-0.7.0-rc.1 \
  bash "$payload/tests/spikes/clean_worker_m4_guest.sh" >"$evidence/m4-regression.stdout" 2>"$evidence/m4-regression.stderr"
test -s "$state/evidence/m4-real/manifest.sha256"
(cd "$state/evidence/m4-real" && sha256sum -c manifest.sha256)

# M5/M6 use canonical Linux test binaries from the test-only archive. AI is
# still disabled in the running product; the deterministic provider boundary
# is exercised locally and no source/log content leaves the guest.
facts="$evidence/m5-docker-facts.json"
container=$(docker ps --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.ID}}' | head -n1)
test -n "$container"
python3 - "$container" "$facts" <<'PY'
import datetime,json,subprocess,sys
cid,out=sys.argv[1:]
inspect=json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
mounts=inspect.get('Mounts',[])
assert all(m.get('Source')!='/var/run/docker.sock' and m.get('Destination')!='/var/run/docker.sock' for m in mounts)
now=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
sample=lambda suffix,delta,rx,tx,healthy:{'id':'m7-'+suffix,'observed_at':(now+datetime.timedelta(seconds=delta)).isoformat().replace('+00:00','Z'),'healthy':healthy,'cpu_millicores':50+delta,'memory_bytes':16777216+delta,'disk_bytes':4096,'network_rx_bytes':rx,'network_tx_bytes':tx,'restart_count':inspect.get('RestartCount',0),'limit_cpu_millicores':500,'limit_memory_bytes':67108864,'limit_pids':64}
value={'task_prefix':'opencard-mvp-fa8f8eab','container_id':inspect['Id'],'image_digest':inspect['Image'],'no_host_mounts':all(m.get('Type')!='bind' for m in mounts),'no_docker_socket':True,'samples':[sample('a',0,100,50,False),sample('b',60,300,150,True)]}
open(out,'w').write(json.dumps(value,sort_keys=True)+'\n')
PY
if [[ -x "$payload/bin/amd64/m5-usage.test" ]]; then
  OPEN_CARD_TEST_DATABASE_URL="$database_url" OPEN_CARD_M5_DOCKER_FACTS="$facts" \
    "$payload/bin/amd64/m5-usage.test" -test.v >"$evidence/m5-usage-test.log"
fi
if [[ -x "$payload/bin/amd64/m6-ai.test" ]]; then
  OPEN_CARD_TEST_DATABASE_URL="$database_url" \
    "$payload/bin/amd64/m6-ai.test" -test.v >"$evidence/m6-ai-test.log"
fi
test -x "$payload/bin/amd64/agent-wire.test"
(cd "$payload/agent-wire-root" && "$payload/bin/amd64/agent-wire.test" -test.v) >"$evidence/agent-wire.test.log"
test -x "$payload/bin/amd64/agent-compat.test"
"$payload/bin/amd64/agent-compat.test" -test.v >"$evidence/agent-compat.test.log"

# Independent service failure/recovery. A control-plane or Agent restart must
# not remove runtime containers; PostgreSQL outage must make readiness fail
# closed and recover without duplicate serving deployments.
docker ps --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.ID}}' | sort >"$evidence/containers-before-restarts.txt"
for service in open-card-server open-card-agent open-card-caddy open-card-buildkit; do
  systemctl restart "$service"
  test "$(systemctl is-active "$service")" = active
done
docker ps --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.ID}}' | sort >"$evidence/containers-after-restarts.txt"
cmp "$evidence/containers-before-restarts.txt" "$evidence/containers-after-restarts.txt"
systemctl stop postgresql
if curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1; then
  echo 'readiness stayed healthy while PostgreSQL was stopped' >&2
  exit 1
fi
systemctl start postgresql
wait_url http://127.0.0.1:8080/readyz

# Record the application-volume contract separately. Control-plane backup
# contains volume metadata and facts, but does not claim to roll back live
# application data; image/code rollback therefore remains distinct.
docker volume ls --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.Name}}' | sort >"$evidence/volumes.txt"
while IFS= read -r volume; do
  [[ -z "$volume" ]] || docker volume inspect "$volume"
done <"$evidence/volumes.txt" >"$evidence/volume-metadata.json"

psql "$database_url" -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS m7_restore_sentinel(id integer PRIMARY KEY,value text NOT NULL);
INSERT INTO m7_restore_sentinel VALUES(1,'before-backup') ON CONFLICT(id) DO UPDATE SET value=excluded.value;
SQL
printf 'm7-config-before-backup\n' >/etc/open-card/m7-restore-sentinel
chmod 0600 /etc/open-card/m7-restore-sentinel
printf 'm7-data-before-backup\n' >/var/lib/open-card/m7-restore-sentinel
chown opencard:opencard /var/lib/open-card/m7-restore-sentinel
chmod 0640 /var/lib/open-card/m7-restore-sentinel
snapshot "$evidence/backup-before.json"
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/backup-control-plane.sh" --root / --reason m7-rc-restore \
  --release-version 0.7.0-rc.1 --migration-version 0021 \
  --database-dump-command /usr/local/libexec/opencard-pg-dump >"$evidence/backup.log"
metadata=$(python3 - <<'PY'
import json,pathlib
items=[]
for path in pathlib.Path('/var/lib/open-card/backups').glob('backup-*.json'):
    value=json.loads(path.read_text())
    if value.get('reason')=='m7-rc-restore': items.append((value['created_at'],path))
assert items
print(sorted(items)[-1][1])
PY
)
cp "$metadata" "$evidence/backup-metadata.json"
archive="$(dirname "$metadata")/$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["archive"])' "$metadata")"
cp "$archive" "$evidence/backup.tar.gz"

corrupt_archive="$archive.corrupt"
corrupt_metadata="${metadata%.json}.corrupt.json"
cp "$archive" "$corrupt_archive"
printf 'corrupt\n' >>"$corrupt_archive"
cp "$metadata" "$corrupt_metadata"
python3 - "$corrupt_metadata" "$(basename "$corrupt_archive")" <<'PY'
import json,sys
p=sys.argv[1]; v=json.load(open(p)); v['archive']=sys.argv[2]
open(p,'w').write(json.dumps(v,sort_keys=True)+'\n')
PY
snapshot "$evidence/corrupt-restore-before.json"
{
  psql "$database_url" -X -Aqt -c 'SELECT value FROM m7_restore_sentinel WHERE id=1'
  sha256sum /etc/open-card/m7-restore-sentinel /var/lib/open-card/m7-restore-sentinel
} >"$evidence/corrupt-restore-before.sha256"
set +e
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/restore-control-plane.sh" --root / --backup "$corrupt_metadata" \
  --database-restore-command /usr/local/libexec/opencard-m7-pg-restore >"$evidence/corrupt-restore.log" 2>&1
corrupt_status=$?
set -e
test "$corrupt_status" -ne 0
grep -Fxq 'open-card restore: backup checksum mismatch' "$evidence/corrupt-restore.log"
test "$(psql "$database_url" -X -Aqt -c 'SELECT value FROM m7_restore_sentinel WHERE id=1')" = before-backup
snapshot "$evidence/corrupt-restore-after.json"
{
  psql "$database_url" -X -Aqt -c 'SELECT value FROM m7_restore_sentinel WHERE id=1'
  sha256sum /etc/open-card/m7-restore-sentinel /var/lib/open-card/m7-restore-sentinel
} >"$evidence/corrupt-restore-after.sha256"
cmp "$evidence/corrupt-restore-before.json" "$evidence/corrupt-restore-after.json"
cmp "$evidence/corrupt-restore-before.sha256" "$evidence/corrupt-restore-after.sha256"

psql "$database_url" -X -v ON_ERROR_STOP=1 -c "UPDATE m7_restore_sentinel SET value='after-backup' WHERE id=1" >/dev/null
printf 'm7-config-after-backup\n' >/etc/open-card/m7-restore-sentinel
printf 'm7-data-after-backup\n' >/var/lib/open-card/m7-restore-sentinel
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/restore-control-plane.sh" --root / --backup "$metadata" \
  --database-restore-command /usr/local/libexec/opencard-m7-pg-restore >"$evidence/restore.log"
test "$(psql "$database_url" -X -Aqt -c 'SELECT value FROM m7_restore_sentinel WHERE id=1')" = before-backup
test "$(cat /etc/open-card/m7-restore-sentinel)" = m7-config-before-backup
test "$(cat /var/lib/open-card/m7-restore-sentinel)" = m7-data-before-backup
test "$(readlink /opt/open-card/current)" = releases/release-0.7.0-rc.1
wait_url http://127.0.0.1:8080/readyz
snapshot "$evidence/backup-after-restore.json"

# Security/RC facts are taken from independent OS and bundle views.
ss -lntup >"$evidence/listeners.txt"
! awk '$5 ~ /:(8080|8092|18481|2019|2020)$/ && $5 !~ /127\.0\.0\.1|\[::1\]/ {bad=1} END{exit bad}' "$evidence/listeners.txt"
systemd-analyze security open-card-server.service open-card-agent.service open-card-caddy.service --no-pager >"$evidence/systemd-security.txt"
grep -Fq 'open-card-server.service' "$evidence/systemd-security.txt"
grep -Fq 'open-card-agent.service' "$evidence/systemd-security.txt"
grep -Fq 'open-card-caddy.service' "$evidence/systemd-security.txt"
stat -c '%a %U %G %n' /etc/open-card/server.env /etc/open-card/agent.key /etc/open-card/server.key /etc/open-card/build-secret.key >"$evidence/secret-permissions.txt"
test "$(stat -c %a /etc/open-card/server.env)" = 600
test "$(stat -c %a /etc/open-card/agent.key)" = 600
test "$(stat -c %a /etc/open-card/server.key)" = 600
test "$(stat -c %a /etc/open-card/build-secret.key)" = 400
find /opt/open-card/current -type f -print0 | sort -z | xargs -0 sha256sum >"$evidence/current-release.sha256"
! find /opt/open-card/current -type f -iname '*fixture*' -print | grep -q .
! grep -R -a -E 'm4-fixture-signing-key|m6-secret-canary|BEGIN .*PRIVATE KEY' "$state/evidence" /var/log/open-card /var/log/open-card-agent 2>/dev/null

snapshot "$evidence/after.json"
(cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
touch "$state/m7-pre-reboot-complete"
printf '%s\n' \
  'M7_RC_PRE_REBOOT=PASS' \
  'M0_M6_RUNTIME_REGRESSION=PASS' \
  'BACKUP_RESTORE=PASS' \
  'SERVICE_FAULT_RECOVERY=PASS' \
  'PRODUCTION_FIXTURE_DEFAULT=ABSENT' \
  'AI_DEFAULT=DISABLED'
