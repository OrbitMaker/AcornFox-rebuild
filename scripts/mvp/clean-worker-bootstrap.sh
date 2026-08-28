#!/usr/bin/env bash
set -euo pipefail

task_id=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
marker=/etc/opencard-mvp-fa8f8eab-clean-worker
offline_root=${1:-/opt/opencard-offline/outer/payload}
rc_mode=${OPEN_CARD_RC_MODE:-0}
bootstrap_release=${OPEN_CARD_BOOTSTRAP_RELEASE:-release-0.4.0}
[[ "$bootstrap_release" =~ ^release-[0-9A-Za-z._+-]+$ ]]
if [[ "$rc_mode" = 1 ]]; then
  test "$bootstrap_release" = release-0.6.0
fi
state_root=/var/lib/opencard-mvp-fa8f8eab
log=$state_root/bootstrap.log

install -d -m 0750 "$state_root"
exec > >(tee -a "$log") 2>&1
test "$(id -u)" -eq 0
test -f "$marker" && test ! -L "$marker"
test "$(cat "$marker")" = "$domain"
test -d "$offline_root" && test ! -L "$offline_root"
required_payload=(debs.tar releases.tar g7-scripts.tar migrations.tar)
if [[ "$rc_mode" = 1 ]]; then
  required_payload+=(m7-fixtures.tar)
else
  required_payload+=(m2-fixtures.tar m3-fixtures.tar m4-fixtures.tar)
fi
for file in "${required_payload[@]}"; do test -f "$offline_root/$file" && test ! -L "$offline_root/$file"; done

install -d -m 0750 /opt/opencard-offline/debs /opt/opencard-offline/releases /opt/opencard-offline/g7 /opt/opencard-offline/migrations
tar -xf "$offline_root/debs.tar" -C /opt/opencard-offline/debs
(
  cd /opt/opencard-offline/debs
  sha256sum -c debs.sha256
)

systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
set +e
dpkg -i /opt/opencard-offline/debs/debs/*.deb
dpkg_status=$?
set -e
if [[ "$dpkg_status" -ne 0 ]]; then
  apt-get -o Acquire::Retries=0 --no-download --fix-broken install -y
fi
test -z "$(dpkg --audit)"
systemctl enable --now qemu-guest-agent.service
systemctl enable --now containerd.service docker.service
systemctl enable --now postgresql.service

tar -xf "$offline_root/releases.tar" -C /opt/opencard-offline/releases
tar -xf "$offline_root/g7-scripts.tar" -C /opt/opencard-offline/g7
tar -xf "$offline_root/migrations.tar" -C /opt/opencard-offline/migrations
install -d -m 0755 /opt/opencard-offline/outer/payload/tests
if [[ "$rc_mode" = 1 ]]; then
  tar -xf "$offline_root/m7-fixtures.tar" -C /opt/opencard-offline/outer/payload
else
  tar -xf "$offline_root/m2-fixtures.tar" -C /opt/opencard-offline/outer/payload
  tar -xf "$offline_root/m3-fixtures.tar" -C /opt/opencard-offline/outer/payload
  tar -xf "$offline_root/m4-fixtures.tar" -C /opt/opencard-offline/outer/payload
fi
for path in /opt/opencard-offline/releases /opt/opencard-offline/g7 /opt/opencard-offline/migrations; do
  test -z "$(find "$path" -type l -print -quit)"
done
test -z "$(find /opt/opencard-offline/outer/payload/tests -type l -print -quit)"
(cd /opt/opencard-offline/outer/payload && sha256sum -c tests/fixtures/m2/manifest.sha256)
(cd /opt/opencard-offline/outer/payload && sha256sum -c tests/fixtures/m3/manifest.sha256)
(cd /opt/opencard-offline/outer/payload && sha256sum -c tests/fixtures/m4/manifest.sha256)

for account in opencard opencard-agent opencard-buildkit opencard-caddy; do
  if ! getent passwd "$account" >/dev/null; then
    useradd --system --user-group --home-dir "/var/lib/$account" --shell /usr/sbin/nologin --no-create-home "$account"
  fi
done
chown root:opencard-buildkit "$state_root"
chmod 0750 "$state_root"
if ! grep -Eq '^opencard-buildkit:' /etc/subuid; then printf '%s\n' 'opencard-buildkit:231072:65536' >>/etc/subuid; fi
if ! grep -Eq '^opencard-buildkit:' /etc/subgid; then printf '%s\n' 'opencard-buildkit:231072:65536' >>/etc/subgid; fi
if [[ ! -f /var/lib/open-card-buildkit-state.img ]]; then
  truncate -s 4G /var/lib/open-card-buildkit-state.img
  mkfs.ext4 -q -L OPENCARD_BK /var/lib/open-card-buildkit-state.img
fi
install -d -m 0700 -o opencard-buildkit -g opencard-buildkit /var/lib/open-card-buildkit
if ! mountpoint -q /var/lib/open-card-buildkit; then
  mount -o loop,nodev,nosuid /var/lib/open-card-buildkit-state.img /var/lib/open-card-buildkit
fi
grep -Fq '/var/lib/open-card-buildkit-state.img /var/lib/open-card-buildkit ext4 loop,nodev,nosuid 0 2' /etc/fstab || \
  printf '%s\n' '/var/lib/open-card-buildkit-state.img /var/lib/open-card-buildkit ext4 loop,nodev,nosuid 0 2' >>/etc/fstab
chown opencard-buildkit:opencard-buildkit /var/lib/open-card-buildkit
chmod 0700 /var/lib/open-card-buildkit
install -d -m 0755 /etc/buildkit
install -d -m 0755 /etc/buildkit/cdi /etc/cdi /var/run/cdi
cat >/etc/buildkit/buildkitd.toml <<'EOF'
debug = false

[worker.oci]
  enabled = true
  snapshotter = "native"
  max-parallelism = 1

[worker.containerd]
  enabled = false
EOF
chmod 0644 /etc/buildkit/buildkitd.toml
cat >/etc/apparmor.d/opencard-rootlesskit <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile opencard-rootlesskit /opt/open-card/releases/*/bin/rootlesskit flags=(unconfined) {
  userns,
}
EOF
apparmor_parser -r /etc/apparmor.d/opencard-rootlesskit

install -d -m 0750 /etc/open-card /var/lib/open-card/evidence
if [[ ! -f /etc/open-card/agent-ca.crt ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 -subj "/CN=Open Card clean worker CA" \
    -keyout /etc/open-card/agent-ca.key -out /etc/open-card/agent-ca.crt >/dev/null 2>&1
  openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=opencard-agent" \
    -keyout /etc/open-card/agent.key -out /etc/open-card/agent.csr >/dev/null 2>&1
  openssl x509 -req -sha256 -days 2 -in /etc/open-card/agent.csr \
    -CA /etc/open-card/agent-ca.crt -CAkey /etc/open-card/agent-ca.key -CAcreateserial \
    -out /etc/open-card/agent.crt >/dev/null 2>&1
	cat >/etc/open-card/server-cert.ext <<'EOF'
subjectAltName=DNS:opencard-control-plane,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
	openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=opencard-control-plane" \
	  -keyout /etc/open-card/server.key -out /etc/open-card/server.csr >/dev/null 2>&1
	openssl x509 -req -sha256 -days 2 -in /etc/open-card/server.csr \
	  -CA /etc/open-card/agent-ca.crt -CAkey /etc/open-card/agent-ca.key -CAcreateserial \
	  -extfile /etc/open-card/server-cert.ext -out /etc/open-card/server.crt >/dev/null 2>&1
fi
chmod 0600 /etc/open-card/agent-ca.key /etc/open-card/agent.key /etc/open-card/server.key
chmod 0644 /etc/open-card/agent-ca.crt /etc/open-card/agent.crt /etc/open-card/server.crt
chown opencard-agent:opencard-agent /etc/open-card/agent.key /etc/open-card/agent.crt /etc/open-card/agent-ca.crt
chown opencard:opencard /etc/open-card/server.key /etc/open-card/server.crt
agent_serial_hex=$(openssl x509 -in /etc/open-card/agent.crt -noout -serial | cut -d= -f2)
agent_serial=$(python3 - "$agent_serial_hex" <<'PY'
import sys
print(int(sys.argv[1], 16))
PY
)
cat >/etc/open-card/agent.env <<'EOF'
OPEN_CARD_INSTANCE_ID=clean-worker
OPEN_CARD_NODE_ID=clean-worker-01
OPEN_CARD_AGENT_VERSION=0.2.0
OPEN_CARD_CONTROL_PLANE_URL=https://127.0.0.1:8092
OPEN_CARD_CONTROL_PLANE_SERVER_NAME=opencard-control-plane
OPEN_CARD_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_AGENT_TLS_CERT=/etc/open-card/agent.crt
OPEN_CARD_AGENT_TLS_KEY=/etc/open-card/agent.key
OPEN_CARD_RUNTIME_ENABLED=true
OPEN_CARD_M2_ENABLED=true
OPEN_CARD_M4_ENABLED=true
OPEN_CARD_WORKER_NETWORK_ISOLATED=true
OPEN_CARD_RUNTIME_TASK_PREFIX=opencard-mvp-fa8f8eab
OPEN_CARD_RUNTIME_NETWORK=opencard-mvp-fa8f8eab-runtime-network
OPEN_CARD_RUNTIME_GROUP_NETWORK=opencard-mvp-fa8f8eab-group-network
OPEN_CARD_RUNTIME_WORK_ROOT=/var/lib/open-card-agent/runtime
OPEN_CARD_OCI_STORE_ROOT=/var/lib/open-card/oci
EOF
chmod 0600 /etc/open-card/agent.env
cat >/etc/open-card/Caddyfile <<'EOF'
{
  admin 127.0.0.1:2019
  auto_https off
}
http://127.0.0.1:18481 {
  reverse_proxy 127.0.0.1:8080
}
EOF
chmod 0644 /etc/open-card/Caddyfile
usermod -a -G opencard opencard-agent
usermod -a -G opencard opencard-caddy
chown root:opencard /etc/open-card
chmod 0750 /etc/open-card
install -d -m 0750 -o opencard-caddy -g opencard-caddy \
  /var/lib/open-card-caddy/.local/share/caddy/locks \
  /var/lib/open-card-caddy/.config/caddy
chown -R opencard-caddy:opencard-caddy /var/lib/open-card-caddy
install -d -m 0700 -o opencard-caddy -g opencard-caddy \
  /var/lib/open-card-caddy/home /var/lib/open-card-caddy/data /var/lib/open-card-caddy/config
cat >/etc/open-card/caddy.env <<'EOF'
HOME=/var/lib/open-card-caddy/home
XDG_DATA_HOME=/var/lib/open-card-caddy/data
XDG_CONFIG_HOME=/var/lib/open-card-caddy/config
EOF
chown root:opencard-caddy /etc/open-card/caddy.env
chmod 0640 /etc/open-card/caddy.env

db_password_file=/etc/open-card/postgres-password
if [[ ! -f "$db_password_file" ]]; then
  openssl rand -hex 24 >"$db_password_file"
fi
chmod 0600 "$db_password_file"
db_password=$(cat "$db_password_file")
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
SELECT 'CREATE ROLE opencard LOGIN PASSWORD ''$db_password'''
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'opencard')\gexec
SELECT 'CREATE DATABASE opencard OWNER opencard'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'opencard')\gexec
SQL
database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
initial_migrations=/opt/opencard-offline/migrations/v1
if [[ "$rc_mode" = 1 ]]; then initial_migrations=/opt/opencard-offline/migrations/n-minus-one; fi
static_runtime_digest="sha256:$(sha256sum "/opt/opencard-offline/releases/$bootstrap_release/bin/open-card-static-server" | awk '{print $1}')"
install -d -m 0750 -o opencard -g opencard /var/lib/open-card/uploads /var/lib/open-card/workspaces /var/lib/open-card/build-work /var/lib/open-card/oci /var/lib/open-card/secrets /var/lib/open-card/secret-materials /var/log/open-card
install -d -m 0750 -o opencard-agent -g opencard-agent /var/lib/open-card-agent/runtime /var/log/open-card-agent
if [[ ! -f /etc/open-card/build-secret.key ]]; then openssl rand 32 >/etc/open-card/build-secret.key; fi
chown opencard:opencard /etc/open-card/build-secret.key
chmod 0400 /etc/open-card/build-secret.key
cat >/etc/open-card/server.env <<EOF
OPEN_CARD_SERVER_ADDR=127.0.0.1:8080
OPEN_CARD_DATABASE_URL=$database_url
OPEN_CARD_AGENT_GATEWAY_ADDR=127.0.0.1:8092
OPEN_CARD_AGENT_IDENTITIES_JSON=[{"certificate_id":"$agent_serial","instance_id":"clean-worker","node_id":"clean-worker-01"}]
OPEN_CARD_SERVER_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_SERVER_AGENT_TLS_CERT=/etc/open-card/server.crt
OPEN_CARD_SERVER_AGENT_TLS_KEY=/etc/open-card/server.key
OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID=clean-worker
OPEN_CARD_AGENT_DISPATCH_NODE_ID=clean-worker-01
OPEN_CARD_M1_ENABLED=true
OPEN_CARD_M2_ENABLED=true
OPEN_CARD_M4_ENABLED=true
OPEN_CARD_M2_REGISTRY_BASE_URL=http://127.0.0.1:45532
OPEN_CARD_RUNTIME_TASK_PREFIX=opencard-mvp-fa8f8eab
OPEN_CARD_SOURCE_UPLOAD_ROOT=/var/lib/open-card/uploads
OPEN_CARD_SOURCE_WORKSPACE_ROOT=/var/lib/open-card/workspaces
OPEN_CARD_BUILD_WORK_ROOT=/var/lib/open-card/build-work
OPEN_CARD_LOG_ROOT=/var/lib/open-card/build-work/m4-logs
OPEN_CARD_OCI_STORE_ROOT=/var/lib/open-card/oci
OPEN_CARD_BUILDKIT_WORKER=clean-worker-rootless
OPEN_CARD_BUILDKIT_COMMAND=/opt/open-card/current/bin/buildctl
OPEN_CARD_BUILDKIT_ADDRESS=unix:///run/open-card-buildkit/buildkitd.sock
OPEN_CARD_STATIC_SERVER_BINARY=/opt/open-card/current/bin/open-card-static-server
OPEN_CARD_STATIC_RUNTIME_DIGEST=$static_runtime_digest
OPEN_CARD_SECRET_ROOT=/var/lib/open-card/secrets
OPEN_CARD_SECRET_MATERIAL_ROOT=/var/lib/open-card/secret-materials
OPEN_CARD_SECRET_MASTER_KEY=/etc/open-card/build-secret.key
OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE=true
EOF
if [[ "$rc_mode" = 1 ]]; then
cat >>/etc/open-card/server.env <<'EOF'
OPEN_CARD_M5_ENABLED=true
OPEN_CARD_M5_STORAGE_CAPACITY_BYTES=8589934592
OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES=536870912
OPEN_CARD_M6_ENABLED=false
OPEN_CARD_M6_WORKSPACE_ROOT=/var/lib/open-card/m6-workspace
EOF
install -d -m 0750 -o opencard -g opencard /var/lib/open-card/m6-workspace /var/lib/open-card/m6-workspace/drafts
fi
chmod 0600 /etc/open-card/server.env
install -d -m 0755 /usr/local/libexec
cat >/usr/local/libexec/opencard-pg-dump <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec pg_dump --no-owner --no-privileges "$1"
EOF
chmod 0750 /usr/local/libexec/opencard-pg-dump

bootstrap_manifest_sha=$(sha256sum "/opt/opencard-offline/releases/$bootstrap_release/manifest.json" | awk '{print $1}')
if [[ "$rc_mode" = 1 ]]; then
  OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL \
  OPEN_CARD_RUNTIME_TASK_PREFIX="$task_id" \
  OPEN_CARD_RUNTIME_NETWORK="$task_id-runtime-network" \
  OPEN_CARD_RUNTIME_GROUP_NETWORK="$task_id-group-network" \
    /opt/opencard-offline/g7/install-host.sh --offline \
    --expected-manifest-sha256 "$bootstrap_manifest_sha" \
    --migration-command /opt/opencard-offline/g7/control-plane-migrate.sh \
    --migration-dir "$initial_migrations" \
    --bundle "/opt/opencard-offline/releases/$bootstrap_release"
else
  DATABASE_URL="$database_url" /opt/opencard-offline/g7/control-plane-migrate.sh "$initial_migrations"
  OPEN_CARD_ALLOW_SYSTEM_ROOT=1 \
  OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="$domain" \
    /opt/opencard-offline/g7/install.sh --root / --offline --activate \
    --expected-manifest-sha256 "$bootstrap_manifest_sha" \
    --bundle "/opt/opencard-offline/releases/$bootstrap_release"
fi

if [[ "$rc_mode" != 1 ]]; then
  DATABASE_URL="$database_url" /opt/opencard-offline/g7/control-plane-migrate.sh \
    /opt/opencard-offline/migrations/all
fi
systemctl restart open-card-buildkit open-card-server open-card-agent

for service in docker containerd postgresql qemu-guest-agent open-card-server open-card-agent open-card-buildkit open-card-caddy; do
  test "$(systemctl is-active "$service")" = active
done
for url in http://127.0.0.1:8080/readyz http://127.0.0.1:18481/readyz; do
  ready=0
  for _ in $(seq 1 50); do
    if curl -fsS "$url" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.1
  done
  test "$ready" = 1
done
cat >>/etc/open-card/server.env <<'EOF'
OPEN_CARD_M3_ENABLED=true
OPEN_CARD_M3_COMPOSITION=fixture
OPEN_CARD_M4_ROLLOUT_ENABLED=true
OPEN_CARD_M4_ROLLOUT_INTERVAL=3s
OPEN_CARD_CADDY_ADMIN_URL=http://127.0.0.1:2019
OPEN_CARD_CADDY_LISTEN=127.0.0.1:18443
EOF

if [[ "${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE:-}" = enabled ]]; then
	cat >>/etc/open-card/server.env <<'EOF'
# Canonical clean-worker M4 log gates use small, bounded task-only thresholds
# so rotation and GC are observable without filling the isolated VM disk.
OPEN_CARD_LOG_MAX_FILE_BYTES=96
OPEN_CARD_LOG_MAX_TOTAL_BYTES=67108864
OPEN_CARD_M4_LOG_COLLECTION_INTERVAL=10s
EOF
  fixture_source=${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_BIN:-/opt/open-card/current/bin/open-card-caddy-fixture}
  test -x "$fixture_source"
  fixture_root="$state_root/caddy-route-fixture"
  fixture_token=/etc/open-card/m4-route-fixture.token
  install -d -m 0700 -o opencard -g opencard "$fixture_root"
  fixture_binary="$fixture_root/open-card-caddy-fixture"
  install -m 0750 -o root -g opencard "$fixture_source" "$fixture_binary"
  sha256sum "$fixture_source" "$fixture_binary" >"$fixture_root/binary.sha256"
  test "$(awk 'NR==1{print $1}' "$fixture_root/binary.sha256")" = "$(awk 'NR==2{print $1}' "$fixture_root/binary.sha256")"
  chown opencard:opencard "$fixture_root/binary.sha256"
  chmod 0640 "$fixture_root/binary.sha256"
  if [[ ! -f "$fixture_token" ]]; then
    umask 077
    openssl rand -hex 32 >"$fixture_token"
  fi
  chown opencard:opencard "$fixture_token"
  chmod 0600 "$fixture_token"
  cat >/etc/systemd/system/open-card-caddy-fixture.service <<EOF
[Unit]
Description=Open Card task-scoped Caddy failure fixture
After=network.target open-card-caddy.service
Requires=open-card-caddy.service

[Service]
Type=simple
User=opencard
Group=opencard
SupplementaryGroups=opencard-buildkit
ExecStart=$fixture_binary --listen 127.0.0.1:2020 --upstream http://127.0.0.1:2019 --token-file $fixture_token --task-prefix $task_id --evidence-file $fixture_root/events.ndjson
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/open-card/m4-route-fixture.token
ReadWritePaths=$fixture_root

[Install]
WantedBy=multi-user.target
EOF
  cat >>/etc/open-card/server.env <<EOF
OPEN_CARD_CADDY_ADMIN_URL=http://127.0.0.1:2020
OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE=enabled
OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_BIN=$fixture_binary
OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_URL=http://127.0.0.1:2020
OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_TOKEN_FILE=$fixture_token
EOF
  systemctl daemon-reload
  systemctl enable --now open-card-caddy-fixture.service
  fixture_ready=0
  for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:2020/__fixture/ready >/dev/null 2>&1; then fixture_ready=1; break; fi
    sleep 0.1
  done
  test "$fixture_ready" = 1
fi
systemctl restart open-card-server
for _ in $(seq 1 50); do
  curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS http://127.0.0.1:8080/readyz >/dev/null
touch "$state_root/bootstrap-complete"
printf '%s\n' \
  'bootstrap=complete' \
  'network_install=offline-only' \
  'credentials=generated-inside-guest' \
  "initial_release=${bootstrap_release#release-}"
