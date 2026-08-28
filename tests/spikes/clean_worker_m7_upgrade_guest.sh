#!/usr/bin/env bash
set -euo pipefail
umask 077

round=${1:?round is required}
[[ "$round" =~ ^[123]$ ]]
domain=opencard-mvp-fa8f8eab-build-worker-01
offline=/opt/opencard-offline
state=/var/lib/opencard-mvp-fa8f8eab
evidence="$state/evidence/m7-upgrade-$round"
install_env=(OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="$domain")

test "$(id -u)" -eq 0
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0
install -d -m 0750 "$evidence" /usr/local/libexec

db_password=$(cat /etc/open-card/postgres-password)
database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
export OPEN_CARD_DATABASE_URL="$database_url"
n_minus_one_manifest_sha=$(sha256sum "$offline/releases/release-0.6.0/manifest.json" | awk '{print $1}')
current_manifest_sha=$(sha256sum "$offline/releases/release-0.7.0-rc.1/manifest.json" | awk '{print $1}')

schema_count() {
  psql "$database_url" -X -Aqt -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM schema_migrations'
}
wait_url() {
  local url=$1
  for _ in $(seq 1 200); do curl -fsS "$url" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}

cat >/usr/local/libexec/opencard-m7-migrate <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
directory=${1:?migration directory is required}
: "${OPEN_CARD_DATABASE_URL:?database URL is required}"
DATABASE_URL="$OPEN_CARD_DATABASE_URL" /opt/opencard-offline/g7/control-plane-migrate.sh "$directory"
latest=$(basename "$(find "$directory" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' -print | sort | tail -n1)" | cut -c1-4)
[[ "$latest" =~ ^[0-9]{4}$ ]]
printf '%d\n' "$((10#$latest))" >/var/lib/open-card/schema.version
chown opencard:opencard /var/lib/open-card/schema.version
chmod 0640 /var/lib/open-card/schema.version
printf 'latest_migration=%s\n' "$latest"
EOF
chmod 0750 /usr/local/libexec/opencard-m7-migrate

cat >/usr/local/libexec/opencard-m7-pg-restore <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
expected="postgresql://opencard:$(cat /etc/open-card/postgres-password)@127.0.0.1:5432/opencard?sslmode=disable"
[[ "${1:?database URL is required}" = "$expected" ]]
dump=${2:?dump is required}
[[ -f "$dump" && ! -L "$dump" ]]
systemctl stop open-card-server.service open-card-agent.service
sudo -u postgres dropdb --force --if-exists opencard
sudo -u postgres createdb -O opencard opencard
psql "$expected" -X -v ON_ERROR_STOP=1 -f "$dump" >/dev/null
systemctl start open-card-server.service open-card-agent.service
EOF
chmod 0750 /usr/local/libexec/opencard-m7-pg-restore

cat >/usr/local/libexec/opencard-m7-health-ok <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for _ in $(seq 1 200); do curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && exit 0; sleep 0.1; done
exit 1
EOF
chmod 0750 /usr/local/libexec/opencard-m7-health-ok

# The bootstrap is the first clean offline install. Two exact replays prove
# system-root installation is idempotent without inventing a second release.
for replay in 2 3; do
  env "${install_env[@]}" "$offline/g7/install.sh" --root / --offline --activate \
    --expected-manifest-sha256 "$n_minus_one_manifest_sha" \
    --bundle "$offline/releases/release-0.6.0" >"$evidence/install-replay-$replay.log"
  test "$(readlink /opt/open-card/current)" = releases/release-0.6.0
done

# Exercise the explicit online retrieval path without public networking: the
# server and CA are task-local loopback fixtures and the source release is the
# same checksum-covered N-1 bundle mounted from the offline ISO.
online="$state/m7-online-$round"
install -d -m 0700 "$online"
tar -czf "$online/release.tar.gz" -C "$offline/releases" release-0.6.0
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj /CN=127.0.0.1 \
  -addext subjectAltName=IP:127.0.0.1 -keyout "$online/key.pem" -out "$online/cert.pem" >/dev/null 2>&1
cat >"$online/server.py" <<'PY'
import http.server, ssl
server=http.server.ThreadingHTTPServer(('127.0.0.1',19445),http.server.SimpleHTTPRequestHandler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('cert.pem','key.pem')
server.socket=ctx.wrap_socket(server.socket,server_side=True); server.serve_forever()
PY
(cd "$online" && python3 server.py >server.log 2>&1) &
online_pid=$!
trap 'kill "$online_pid" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 100); do ss -ltnH 'sport = :19445' | grep -q 127.0.0.1:19445 && break; sleep 0.1; done
CURL_CA_BUNDLE="$online/cert.pem" env "${install_env[@]}" "$offline/g7/install.sh" \
  --root / --activate --expected-manifest-sha256 "$n_minus_one_manifest_sha" \
  --url https://127.0.0.1:19445/release.tar.gz >"$evidence/loopback-online-install.log"
kill "$online_pid" >/dev/null 2>&1 || true
wait "$online_pid" 2>/dev/null || true
trap - EXIT
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0

# Tampered and wrong-architecture bundles must fail before the release pointer,
# schema, services or network-visible application state changes.
negative="$state/m7-negative-$round"
install -d -m 0700 "$negative"
cp -a "$offline/releases/release-0.7.0-rc.1" "$negative/tampered"
printf 'tamper\n' >>"$negative/tampered/bin/open-card-server"
set +e
env "${install_env[@]}" "$offline/g7/install.sh" --root / --offline \
  --expected-manifest-sha256 "$current_manifest_sha" --bundle "$negative/tampered" >"$evidence/tampered.log" 2>&1
tampered_status=$?
set -e
test "$tampered_status" -ne 0
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0

cp -a "$offline/releases/release-0.7.0-rc.1" "$negative/forged-manifest"
printf 'forged\n' >>"$negative/forged-manifest/bin/open-card-server"
python3 - "$negative/forged-manifest/manifest.json" "$negative/forged-manifest/bin/open-card-server" <<'PY'
import hashlib,json,sys
p,b=sys.argv[1:]; value=json.load(open(p))
for item in value['files']:
    if item['path']=='bin/open-card-server':
        item['sha256']=hashlib.sha256(open(b,'rb').read()).hexdigest()
open(p,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
set +e
env "${install_env[@]}" "$offline/g7/install.sh" --root / --offline \
  --expected-manifest-sha256 "$current_manifest_sha" --bundle "$negative/forged-manifest" >"$evidence/forged-manifest.log" 2>&1
forged_status=$?
set -e
test "$forged_status" -ne 0
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0

cp -a "$offline/releases/release-0.7.0-rc.1" "$negative/wrong-arch"
python3 - "$negative/wrong-arch/manifest.json" <<'PY'
import json,sys
p=sys.argv[1]; v=json.load(open(p)); v['architecture']='arm64'
open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
wrong_arch_manifest_sha=$(sha256sum "$negative/wrong-arch/manifest.json" | awk '{print $1}')
set +e
env "${install_env[@]}" "$offline/g7/install.sh" --root / --offline \
  --expected-manifest-sha256 "$wrong_arch_manifest_sha" --bundle "$negative/wrong-arch" >"$evidence/wrong-arch.log" 2>&1
wrong_arch_status=$?
set -e
test "$wrong_arch_status" -ne 0
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0

# A transaction-breaking 0021 proves the pointer and N-1 schema stay intact.
bad_migrations="$state/m7-bad-migrations-$round"
cp -a "$offline/migrations/current" "$bad_migrations"
cat >"$bad_migrations/0021_m6_controlled_ai.sql" <<'SQL'
CREATE TABLE m7_injected_partial_write(id integer PRIMARY KEY);
SELECT 1/0;
SQL
set +e
set +e
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/upgrade.sh" --root / --offline --activate \
  --expected-manifest-sha256 "$current_manifest_sha" \
  --bundle "$offline/releases/release-0.7.0-rc.1" \
  --migration-command /usr/local/libexec/opencard-m7-migrate --migration-dir "$bad_migrations" \
  --database-dump-command /usr/local/libexec/opencard-pg-dump \
  --database-restore-command /usr/local/libexec/opencard-m7-pg-restore \
  --health-command /usr/local/libexec/opencard-m7-health-ok >"$evidence/migration-failure.log" 2>&1
migration_failure_status=$?
set -e
test "$migration_failure_status" -ne 0
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0
test "$(schema_count)" = 20
test "$(psql "$database_url" -X -Aqt -c "SELECT to_regclass('public.m7_injected_partial_write') IS NULL")" = t

# Candidate health failure happens after a real 0021 migration. The upgrade
# wrapper must restore both the old pointer and the pre-upgrade PostgreSQL/data
# snapshot; a pointer-only rollback is not accepted.
set +e
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/upgrade.sh" --root / --offline --activate \
  --expected-manifest-sha256 "$current_manifest_sha" \
  --bundle "$offline/releases/release-0.7.0-rc.1" \
  --migration-command /usr/local/libexec/opencard-m7-migrate --migration-dir "$offline/migrations/current" \
  --database-dump-command /usr/local/libexec/opencard-pg-dump \
  --database-restore-command /usr/local/libexec/opencard-m7-pg-restore \
  --health-command /usr/bin/false >"$evidence/health-failure.log" 2>&1
health_failure_status=$?
set -e
test "$health_failure_status" -ne 0
test "$(readlink /opt/open-card/current)" = releases/release-0.6.0
test "$(schema_count)" = 20
wait_url http://127.0.0.1:8080/readyz

set +e
env "${install_env[@]}" OPEN_CARD_DATABASE_URL="$database_url" \
  "$offline/g7/upgrade.sh" --root / --offline --activate \
  --expected-manifest-sha256 "$current_manifest_sha" \
  --bundle "$offline/releases/release-0.7.0-rc.1" \
  --migration-command /usr/local/libexec/opencard-m7-migrate --migration-dir "$offline/migrations/current" \
  --database-dump-command /usr/local/libexec/opencard-pg-dump \
  --database-restore-command /usr/local/libexec/opencard-m7-pg-restore \
  --health-command /usr/local/libexec/opencard-m7-health-ok >"$evidence/upgrade-success.log" 2>&1
upgrade_success_status=$?
set -e
if [[ "$upgrade_success_status" -ne 0 ]]; then
  systemctl --no-pager --full status open-card-server open-card-agent open-card-buildkit open-card-caddy >"$evidence/upgrade-success-systemd.txt" 2>&1 || true
  journalctl -b -u open-card-server -u open-card-agent -u open-card-buildkit -u open-card-caddy --no-pager -n 240 >"$evidence/upgrade-success-journal.txt" 2>&1 || true
  exit "$upgrade_success_status"
fi
test "$(readlink /opt/open-card/current)" = releases/release-0.7.0-rc.1
test "$(schema_count)" = 21
test "$(cat /var/lib/open-card/schema.version)" = 21
wait_url http://127.0.0.1:8080/readyz

set +e
env "${install_env[@]}" "$offline/g7/install.sh" --root / --offline --activate \
  --expected-manifest-sha256 "$n_minus_one_manifest_sha" \
  --bundle "$offline/releases/release-0.6.0" >"$evidence/unauthorized-downgrade.log" 2>&1
downgrade_status=$?
set -e
test "$downgrade_status" -ne 0
test "$(readlink /opt/open-card/current)" = releases/release-0.7.0-rc.1
test "$(schema_count)" = 21

systemctl status open-card-server open-card-agent open-card-buildkit open-card-caddy --no-pager >"$evidence/systemd-status.txt"
psql "$database_url" -X -Aqt -F '|' -c 'SELECT version,checksum FROM schema_migrations ORDER BY version' >"$evidence/migrations.tsv"
sha256sum "$offline/releases/release-0.6.0/manifest.json" "$offline/releases/release-0.7.0-rc.1/manifest.json" >"$evidence/release-manifests.sha256"
printf '{"round":%s,"install_replays":3,"migration_failure_rollback":true,"health_failure_pointer_and_database_rollback":true,"upgrade":"0.6.0-to-0.7.0-rc.1","schema_migrations":21,"tamper_rejected":true,"payload_and_manifest_replacement_rejected":true,"wrong_arch_rejected":true,"unauthorized_downgrade_rejected":true}\n' "$round" >"$evidence/result.json"
(cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
touch "$state/m7-upgrade-round-$round-complete"
printf 'M7_UPGRADE_ROUND_%s=PASS\n' "$round"
