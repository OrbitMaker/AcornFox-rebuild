#!/usr/bin/env bash
set -euo pipefail

# Portable production entry point. The legacy install.sh keeps the task-owned
# clean-worker gate for compatibility; this wrapper provides an explicit,
# operator-visible production confirmation and never enables AI/test fixtures.
usage() {
  cat >&2 <<'USAGE'
usage: install-host.sh (--bundle BUNDLE | --url HTTPS_URL)
                        --expected-manifest-sha256 HEX
                        [--debs-dir DIRECTORY --debs-sha256 MANIFEST]
                        [install.sh options]

This command is intentionally system-root only. It requires an externally
computed manifest digest and the exact OPEN-CARD-INSTALL confirmation token.
USAGE
}
die() { echo "open-card install-host: $*" >&2; exit 1; }
set_env_line() {
  local file=$1 key=$2 value=$3
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

bundle= url= expected= debs_dir= debs_sha256= migration_command= migration_dir= admin_password_file= auth_origin= edge_domain=
offline=0 dry_run=0 skip_prerequisites=0
forward=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) [[ $# -gt 1 ]] || die "--bundle requires a value"; bundle=$2; forward+=(--bundle "$2"); shift 2 ;;
    --url) [[ $# -gt 1 ]] || die "--url requires a value"; url=$2; forward+=(--url "$2"); shift 2 ;;
    --expected-manifest-sha256) [[ $# -gt 1 ]] || die "--expected-manifest-sha256 requires a value"; expected=$2; shift 2 ;;
    --debs-dir) [[ $# -gt 1 ]] || die "--debs-dir requires a value"; debs_dir=$2; shift 2 ;;
    --debs-sha256) [[ $# -gt 1 ]] || die "--debs-sha256 requires a value"; debs_sha256=$2; shift 2 ;;
    --admin-password-file) [[ $# -gt 1 ]] || die "--admin-password-file requires a value"; admin_password_file=$2; shift 2 ;;
    --auth-origin) [[ $# -gt 1 ]] || die "--auth-origin requires a value"; auth_origin=$2; shift 2 ;;
    --edge-domain) [[ $# -gt 1 ]] || die "--edge-domain requires a value"; edge_domain=$2; shift 2 ;;
    --root|--activate) die "$1 is managed by install-host.sh and must not be overridden" ;;
    --test-safe-prefix) die "--test-safe-prefix is not valid for production installation" ;;
    --offline) offline=1; forward+=(--offline); shift ;;
    --dry-run) dry_run=1; forward+=(--dry-run); shift ;;
    --skip-prerequisites) skip_prerequisites=1; shift ;;
    --allow-downgrade) forward+=(--allow-downgrade); shift ;;
    --health-command|--health-cmd|--migration-command|--migration-dir|--database-dump-command|--database-restore-command)
      [[ $# -gt 1 ]] || die "$1 requires a value"; [[ "$1" != "--migration-command" ]] || migration_command=$2; [[ "$1" != "--migration-dir" ]] || migration_dir=$2; forward+=("$1" "$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unsupported option $1" ;;
  esac
done

[[ -n "$bundle" || -n "$url" ]] || die "exactly one --bundle or --url is required"
[[ -z "$bundle" || -z "$url" ]] || die "use either --bundle or --url"
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die "--expected-manifest-sha256 must be 64 hexadecimal characters"
if [[ -n "$url" && "$url" != https://* ]]; then die "--url must use https://"; fi
if [[ -n "$debs_dir" ]]; then [[ "$debs_dir" = /* && -d "$debs_dir" && ! -L "$debs_dir" ]] || die "--debs-dir must be a real absolute directory"; fi
if [[ -n "$debs_sha256" ]]; then [[ "$debs_sha256" = /* && -f "$debs_sha256" && ! -L "$debs_sha256" ]] || die "--debs-sha256 must be a real absolute file"; fi
[[ "${OPEN_CARD_INSTALL_CONFIRMATION:-}" = "OPEN-CARD-INSTALL" ]] || die "production install requires OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL"
[[ "${OPEN_CARD_M6_ENABLED:-false}" != "true" && "${OPEN_CARD_AI_ENABLED:-false}" != "true" ]] || die "production installer refuses AI-enabled environment"
[[ "$EUID" -eq 0 ]] || die "production installation requires root"
[[ -n "$migration_command" && -n "$migration_dir" ]] || die "production install requires --migration-command and --migration-dir"
management_activation=0
if [[ -n "$admin_password_file" || -n "$auth_origin" || -n "$edge_domain" ]]; then
  [[ -n "$admin_password_file" && -n "$auth_origin" && -n "$edge_domain" ]] || die "Edge/auth activation requires --admin-password-file, --auth-origin, and --edge-domain together"
  [[ "$admin_password_file" = /* && -f "$admin_password_file" && ! -L "$admin_password_file" ]] || die "--admin-password-file must be a regular absolute non-symlink file"
  [[ "$(stat -c '%u:%a' "$admin_password_file")" = "0:600" ]] || die "--admin-password-file must be root-owned mode 0600"
  origin_host=$(python3 - "$auth_origin" <<'PY'
import sys
from urllib.parse import urlsplit
value = sys.argv[1]
parsed = urlsplit(value)
if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or value != f"https://{parsed.netloc}":
    raise SystemExit("auth origin must be an exact HTTPS origin")
print(parsed.hostname.lower())
PY
) || die "--auth-origin must be an exact HTTPS origin"
  [[ "$edge_domain" =~ ^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || die "--edge-domain must be a DNS hostname"
  edge_domain=${edge_domain,,}
  [[ "$edge_domain" = "$origin_host" ]] || die "--edge-domain must exactly match the HTTPS origin host"
  management_activation=1
fi
runtime_task_prefix=${OPEN_CARD_RUNTIME_TASK_PREFIX:-opencard-host}
runtime_network=${OPEN_CARD_RUNTIME_NETWORK:-${runtime_task_prefix}-runtime-network}
runtime_group_network=${OPEN_CARD_RUNTIME_GROUP_NETWORK:-${runtime_task_prefix}-group-network}
[[ "$runtime_task_prefix" =~ ^[A-Za-z0-9._-]+$ && "$runtime_network" =~ ^[A-Za-z0-9._-]+$ && "$runtime_group_network" =~ ^[A-Za-z0-9._-]+$ ]] || die "runtime prefixes contain unsafe characters"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
export OPEN_CARD_ALLOW_SYSTEM_ROOT=1
export OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL
export OPEN_CARD_M6_ENABLED=false
export OPEN_CARD_AI_ENABLED=false
expected=$(tr '[:upper:]' '[:lower:]' <<< "$expected")

if [[ -L /opt/open-card/current ]] && (( ! dry_run )); then
  die "existing production installation requires upgrade.sh; root upgrades remain fail-closed pending atomic PostgreSQL restore support"
fi

installer=("$script_dir/install.sh" --root / --activate --expected-manifest-sha256 "$expected")
installer+=("${forward[@]}")
preflight=("$script_dir/install.sh" --root / --dry-run --validate-activation-intent --expected-manifest-sha256 "$expected")
preflight+=("${forward[@]}")
"${preflight[@]}" >/tmp/open-card-install-host-preflight-$$.log 2>&1 || {
  status=$?
  cat "/tmp/open-card-install-host-preflight-$$.log" >&2 || true
  rm -f -- "/tmp/open-card-install-host-preflight-$$.log"
  exit "$status"
}
rm -f -- "/tmp/open-card-install-host-preflight-$$.log"
if (( dry_run )); then
  exit 0
fi

require_command() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }
required_commands=(install useradd getent openssl systemctl)
for command_name in "${required_commands[@]}"; do require_command "$command_name"; done
if (( ! skip_prerequisites )); then
  missing_packages=()
  for command_name in docker psql runuser newuidmap newgidmap; do command -v "$command_name" >/dev/null 2>&1 || missing_packages+=("$command_name"); done
  if (( ${#missing_packages[@]} > 0 )); then
    if (( offline )); then
      [[ -n "$debs_dir" && -n "$debs_sha256" ]] || die "offline prerequisite installation requires --debs-dir and --debs-sha256"
      require_command dpkg
      require_command apt-get
      verified_debs=$(python3 - "$debs_dir" "$debs_sha256" <<'PY'
import hashlib, pathlib, re, sys
root, manifest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
seen = set()
for raw in manifest.read_text(encoding="utf-8").splitlines():
    raw = raw.strip()
    if not raw: continue
    match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", raw)
    if not match: raise SystemExit("invalid deb checksum manifest line")
    digest, relative = match.groups(); path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or not relative.endswith(".deb"): raise SystemExit("unsafe deb checksum path")
    target = root.joinpath(*path.parts)
    if not target.is_file() or target.is_symlink(): raise SystemExit(f"missing or unsafe deb: {relative}")
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    if actual.lower() != digest.lower(): raise SystemExit(f"deb checksum mismatch: {relative}")
    seen.add(relative)
    print(relative)
if not seen: raise SystemExit("deb checksum manifest is empty")
PY
)
      deb_files=()
      while IFS= read -r relative_deb; do
        [[ -z "$relative_deb" ]] || deb_files+=("$debs_dir/$relative_deb")
      done <<< "$verified_debs"
      (( ${#deb_files[@]} > 0 )) || die "offline deb directory contains no packages"
      dpkg -i "${deb_files[@]}" || apt-get -o Acquire::Retries=0 --no-download --fix-broken install -y
      test -z "$(dpkg --audit)" || die "offline deb installation left dpkg in an incomplete state"
    else
      require_command apt-get
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y ca-certificates curl docker.io postgresql postgresql-client util-linux uidmap apparmor apparmor-utils
    fi
  fi
  for command_name in docker psql runuser newuidmap newgidmap; do require_command "$command_name"; done

  for account in opencard opencard-agent opencard-buildkit opencard-caddy opencard-edge; do
    if ! getent passwd "$account" >/dev/null; then
      useradd --system --user-group --home-dir "/var/lib/$account" --shell /usr/sbin/nologin --no-create-home "$account"
    fi
  done
  grep -Eq '^opencard-buildkit:' /etc/subuid || printf '%s\n' 'opencard-buildkit:231072:65536' >>/etc/subuid
  grep -Eq '^opencard-buildkit:' /etc/subgid || printf '%s\n' 'opencard-buildkit:231072:65536' >>/etc/subgid
  install -d -m 0711 -o root -g root /var/lib/open-card
  install -d -m 0750 -o opencard -g opencard /var/log/open-card /var/lib/open-card/uploads /var/lib/open-card/workspaces /var/lib/open-card/build-work /var/lib/open-card/oci /var/lib/open-card/secrets /var/lib/open-card/secret-materials
  install -d -m 0750 -o opencard-agent -g opencard-agent /var/lib/open-card-agent /var/log/open-card-agent /var/lib/open-card-agent/runtime
  install -d -m 0700 -o opencard-buildkit -g opencard-buildkit /var/lib/open-card-buildkit /run/open-card-buildkit
  install -d -m 0750 -o opencard-caddy -g opencard-caddy /var/lib/open-card-caddy /var/log/open-card-caddy
  install -d -m 0750 -o opencard-edge -g opencard-edge /var/lib/open-card-edge /var/log/open-card-edge
  install -d -m 0700 -o opencard-edge -g opencard-edge /var/lib/open-card-edge/home /var/lib/open-card-edge/data /var/lib/open-card-edge/config
  install -d -m 0755 /etc/buildkit /etc/buildkit/cdi /etc/cdi /var/run/cdi
  if [[ ! -f /etc/buildkit/buildkitd.toml ]]; then
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
  fi
  if [[ ! -f /etc/apparmor.d/opencard-rootlesskit ]]; then
    install -d -m 0755 /etc/apparmor.d
    cat >/etc/apparmor.d/opencard-rootlesskit <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile opencard-rootlesskit /opt/open-card/releases/*/bin/rootlesskit flags=(unconfined) {
  userns,
}
EOF
  fi
  if command -v apparmor_parser >/dev/null 2>&1; then apparmor_parser -r /etc/apparmor.d/opencard-rootlesskit || die "failed to load Open Card AppArmor profile"; fi

  install -d -m 0711 -o root -g root /etc/open-card
  install -d -m 0700 -o root -g root /var/lib/open-card/evidence
  if [[ ! -f /etc/open-card/agent-ca.crt ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -subj "/CN=Open Card CA" -keyout /etc/open-card/agent-ca.key -out /etc/open-card/agent-ca.crt >/dev/null 2>&1
    cat >/etc/open-card/agent-cert.ext <<'EOF'
extendedKeyUsage=clientAuth
subjectAltName=DNS:opencard-agent
EOF
    openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=opencard-agent" -keyout /etc/open-card/agent.key -out /etc/open-card/agent.csr >/dev/null 2>&1
    openssl x509 -req -sha256 -days 365 -in /etc/open-card/agent.csr -CA /etc/open-card/agent-ca.crt -CAkey /etc/open-card/agent-ca.key -CAcreateserial -extfile /etc/open-card/agent-cert.ext -out /etc/open-card/agent.crt >/dev/null 2>&1
    cat >/etc/open-card/server-cert.ext <<'EOF'
extendedKeyUsage=serverAuth
subjectAltName=DNS:opencard-control-plane,IP:127.0.0.1
EOF
    openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=opencard-control-plane" -keyout /etc/open-card/server.key -out /etc/open-card/server.csr >/dev/null 2>&1
    openssl x509 -req -sha256 -days 365 -in /etc/open-card/server.csr -CA /etc/open-card/agent-ca.crt -CAkey /etc/open-card/agent-ca.key -CAcreateserial -extfile /etc/open-card/server-cert.ext -out /etc/open-card/server.crt >/dev/null 2>&1
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
  if [[ ! -f /etc/open-card/Caddyfile ]]; then
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
  fi
  chmod 0640 /etc/open-card/server-cert.ext /etc/open-card/agent-cert.ext 2>/dev/null || true
  if [[ ! -f /etc/open-card/agent.env ]]; then
    cat >/etc/open-card/agent.env <<EOF
OPEN_CARD_INSTANCE_ID=opencard-host
OPEN_CARD_NODE_ID=opencard-host-01
OPEN_CARD_AGENT_VERSION=1.1
OPEN_CARD_CONTROL_PLANE_URL=https://127.0.0.1:8092
OPEN_CARD_CONTROL_PLANE_SERVER_NAME=opencard-control-plane
OPEN_CARD_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_AGENT_TLS_CERT=/etc/open-card/agent.crt
OPEN_CARD_AGENT_TLS_KEY=/etc/open-card/agent.key
OPEN_CARD_RUNTIME_ENABLED=true
OPEN_CARD_M1_ENABLED=true
OPEN_CARD_M2_ENABLED=true
OPEN_CARD_M3_ENABLED=true
OPEN_CARD_M3_COMPOSITION=production
OPEN_CARD_G3_CONSOLE_LABEL=console
OPEN_CARD_G3_INGRESS_LABEL=ingress
OPEN_CARD_G3_APPS_LABEL=apps
OPEN_CARD_G3_WILDCARD_PROBE_LABEL=wildcard-probe
OPEN_CARD_M4_ENABLED=true
OPEN_CARD_M4_ROLLOUT_ENABLED=true
OPEN_CARD_M4_ROLLOUT_INTERVAL=3s
OPEN_CARD_M5_ENABLED=true
OPEN_CARD_M6_ENABLED=false
OPEN_CARD_AI_ENABLED=false
OPEN_CARD_WORKER_NETWORK_ISOLATED=true
OPEN_CARD_RUNTIME_TASK_PREFIX=$runtime_task_prefix
OPEN_CARD_RUNTIME_NETWORK=$runtime_network
OPEN_CARD_RUNTIME_GROUP_NETWORK=$runtime_group_network
OPEN_CARD_RUNTIME_WORK_ROOT=/var/lib/open-card-agent/runtime
OPEN_CARD_OCI_STORE_ROOT=/var/lib/open-card/oci
OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID=opencard-host
OPEN_CARD_AGENT_DISPATCH_NODE_ID=opencard-host-01
EOF
    chmod 0600 /etc/open-card/agent.env
  fi
  if [[ ! -f /etc/open-card/server.env ]]; then
    cat >/etc/open-card/server.env <<EOF
OPEN_CARD_SERVER_ADDR=127.0.0.1:8080
OPEN_CARD_AGENT_GATEWAY_ADDR=127.0.0.1:8092
OPEN_CARD_AGENT_IDENTITIES_JSON=[{"certificate_id":"$agent_serial","instance_id":"opencard-host","node_id":"opencard-host-01"}]
OPEN_CARD_SERVER_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_SERVER_AGENT_TLS_CERT=/etc/open-card/server.crt
OPEN_CARD_SERVER_AGENT_TLS_KEY=/etc/open-card/server.key
OPEN_CARD_M1_ENABLED=true
OPEN_CARD_M2_ENABLED=true
OPEN_CARD_M3_ENABLED=true
OPEN_CARD_M3_COMPOSITION=production
OPEN_CARD_G3_CONSOLE_LABEL=console
OPEN_CARD_G3_INGRESS_LABEL=ingress
OPEN_CARD_G3_APPS_LABEL=apps
OPEN_CARD_G3_WILDCARD_PROBE_LABEL=wildcard-probe
OPEN_CARD_M4_ENABLED=true
OPEN_CARD_M4_ROLLOUT_ENABLED=true
OPEN_CARD_M4_ROLLOUT_INTERVAL=3s
OPEN_CARD_M5_ENABLED=true
OPEN_CARD_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_AGENT_TLS_CERT=/etc/open-card/server.crt
OPEN_CARD_AGENT_TLS_KEY=/etc/open-card/server.key
OPEN_CARD_BUILDKIT_WORKER=host-rootless
OPEN_CARD_BUILDKIT_ADDRESS=unix:///run/open-card-buildkit/buildkitd.sock
OPEN_CARD_M6_ENABLED=false
OPEN_CARD_AI_ENABLED=false
OPEN_CARD_RUNTIME_ENABLED=true
OPEN_CARD_RUNTIME_TASK_PREFIX=$runtime_task_prefix
OPEN_CARD_RUNTIME_NETWORK=$runtime_network
OPEN_CARD_RUNTIME_GROUP_NETWORK=$runtime_group_network
OPEN_CARD_RUNTIME_WORK_ROOT=/var/lib/open-card-agent/runtime
OPEN_CARD_OCI_STORE_ROOT=/var/lib/open-card/oci
OPEN_CARD_SOURCE_UPLOAD_ROOT=/var/lib/open-card/uploads
OPEN_CARD_SOURCE_WORKSPACE_ROOT=/var/lib/open-card/workspaces
OPEN_CARD_BUILD_WORK_ROOT=/var/lib/open-card/build-work
OPEN_CARD_LOG_ROOT=/var/lib/open-card/build-work/m4-logs
OPEN_CARD_STATIC_SERVER_BINARY=/opt/open-card/current/bin/open-card-static-server
OPEN_CARD_SECRET_ROOT=/var/lib/open-card/secrets
OPEN_CARD_SECRET_MATERIAL_ROOT=/var/lib/open-card/secret-materials
OPEN_CARD_SECRET_MASTER_KEY=/etc/open-card/build-secret.key
OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID=opencard-host
OPEN_CARD_AGENT_DISPATCH_NODE_ID=opencard-host-01
OPEN_CARD_M2_REGISTRY_BASE_URL=http://127.0.0.1:45532
OPEN_CARD_CADDY_ADMIN_URL=http://127.0.0.1:2019
OPEN_CARD_CADDY_LISTEN=127.0.0.1:18481
EOF
    chmod 0600 /etc/open-card/server.env
  fi

  # These are production control-plane boundaries, not optional provider
  # defaults. Keep an existing installation's server.env explicit as well as
  # populating a newly-created file above.
  set_env_line /etc/open-card/server.env OPEN_CARD_CADDY_ADMIN_URL http://127.0.0.1:2019
  set_env_line /etc/open-card/server.env OPEN_CARD_CADDY_LISTEN 127.0.0.1:18481
  set_env_line /etc/open-card/server.env OPEN_CARD_M4_ROLLOUT_ENABLED true
  set_env_line /etc/open-card/server.env OPEN_CARD_M4_ROLLOUT_INTERVAL 3s

  if [[ ! -f /etc/open-card/build-secret.key ]]; then openssl rand 32 >/etc/open-card/build-secret.key; fi
  chown opencard:opencard /etc/open-card/build-secret.key
  chmod 0400 /etc/open-card/build-secret.key
  if [[ ! -f /etc/open-card/caddy.env ]]; then
    cat >/etc/open-card/caddy.env <<'EOF'
HOME=/var/lib/open-card-caddy/home
XDG_DATA_HOME=/var/lib/open-card-caddy/data
XDG_CONFIG_HOME=/var/lib/open-card-caddy/config
OPEN_CARD_CADDY_LISTEN=127.0.0.1:18481
EOF
    install -d -m 0700 -o opencard-caddy -g opencard-caddy /var/lib/open-card-caddy/home /var/lib/open-card-caddy/data /var/lib/open-card-caddy/config
    chown root:opencard-caddy /etc/open-card/caddy.env
    chmod 0640 /etc/open-card/caddy.env
  fi
  if systemctl list-unit-files docker.service >/dev/null 2>&1; then systemctl enable --now docker.service; fi
  if systemctl list-unit-files postgresql.service >/dev/null 2>&1; then systemctl enable --now postgresql.service; fi
  db_password_file=/etc/open-card/postgres-password
  if [[ ! -f "$db_password_file" ]]; then openssl rand -hex 24 >"$db_password_file"; fi
  chmod 0600 "$db_password_file"
  db_password=$(cat "$db_password_file")
  database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
  if systemctl is-active --quiet postgresql.service; then
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<SQL
SELECT 'CREATE ROLE opencard LOGIN PASSWORD ''$db_password''' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'opencard')\gexec
SELECT 'CREATE DATABASE opencard OWNER opencard' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'opencard')\gexec
SQL
  else
    die "PostgreSQL service is not active; refusing an unbound control plane"
  fi
  if ! grep -q '^OPEN_CARD_DATABASE_URL=' /etc/open-card/server.env; then
    printf 'OPEN_CARD_DATABASE_URL=%s\n' "$database_url" >>/etc/open-card/server.env
  fi
  export OPEN_CARD_DATABASE_URL="$database_url"
  export DATABASE_URL="$database_url"
fi
for command_name in docker psql runuser newuidmap newgidmap; do require_command "$command_name"; done

"${installer[@]}"
installation_id=/var/lib/open-card/installation-id
if [[ ! -e "$installation_id" ]]; then openssl rand -hex 24 >"$installation_id"; fi
[[ -f "$installation_id" && ! -L "$installation_id" ]] || die "installation id is unsafe"
chown root:root "$installation_id" && chmod 0600 "$installation_id"
static_binary=/opt/open-card/current/bin/open-card-static-server
if [[ -x "$static_binary" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then static_digest="sha256:$(sha256sum -- "$static_binary" | awk '{print $1}')"; else static_digest="sha256:$(shasum -a 256 -- "$static_binary" | awk '{print $1}')"; fi
  set_env_line /etc/open-card/server.env OPEN_CARD_STATIC_SERVER_BINARY "$static_binary"
  set_env_line /etc/open-card/server.env OPEN_CARD_STATIC_RUNTIME_DIGEST "$static_digest"
  systemctl restart open-card-server.service >/dev/null 2>&1 || die "server restart after static runtime digest failed"
fi

if (( management_activation )); then
  edge_backup=/var/lib/open-card/backups/edge-preactivate-$(date -u +%Y%m%dT%H%M%SZ)
  install -d -m 0700 "$edge_backup"
  for path in /etc/open-card/server.env /etc/open-card/open-card-edge.Caddyfile /etc/open-card/open-card-edge.env /var/lib/open-card-edge; do
    [[ ! -e "$path" && ! -L "$path" ]] || cp -a -- "$path" "$edge_backup/"
  done
  activation_committed=0
  activation_rollback() {
    local status=$?
    if (( status != 0 && activation_committed == 0 )); then
      set +e
      systemctl disable --now open-card-edge.service >/dev/null 2>&1 || true
      [[ ! -e "$edge_backup/server.env" ]] || cp -a -- "$edge_backup/server.env" /etc/open-card/server.env
      for name in open-card-edge.Caddyfile open-card-edge.env; do
        if [[ -e "$edge_backup/$name" ]]; then cp -a -- "$edge_backup/$name" "/etc/open-card/$name"; else rm -f -- "/etc/open-card/$name"; fi
      done
      if [[ -e "$edge_backup/open-card-edge" ]]; then
        rm -rf -- /var/lib/open-card-edge
        cp -a -- "$edge_backup/open-card-edge" /var/lib/open-card-edge
      fi
      systemctl restart open-card-server.service >/dev/null 2>&1 || true
      echo "open-card install-host: activation failed; restored pre-activation Edge and server configuration" >&2
    fi
    return "$status"
  }
  trap activation_rollback EXIT
  set_env_line /etc/open-card/server.env OPEN_CARD_AUTH_ORIGIN "$auth_origin"
  python3 - "/opt/open-card/current/caddy/open-card-edge.Caddyfile.example" /etc/open-card/.open-card-edge.Caddyfile.next "$edge_domain" <<'PY'
import pathlib, sys
source, target, domain = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
text = source.read_text(encoding="utf-8")
if text.count("console.example.invalid") != 1:
    raise SystemExit("Edge template console hostname is not unique")
target.write_text(text.replace("console.example.invalid", domain), encoding="utf-8")
PY
  install -m 0640 -o root -g opencard-edge /etc/open-card/.open-card-edge.Caddyfile.next /etc/open-card/open-card-edge.Caddyfile
  rm -f -- /etc/open-card/.open-card-edge.Caddyfile.next
  install -m 0640 -o root -g opencard-edge /opt/open-card/current/caddy/open-card-edge.env.example /etc/open-card/open-card-edge.env
  /opt/open-card/current/bin/caddy validate --config /etc/open-card/open-card-edge.Caddyfile --adapter caddyfile
  /opt/open-card/current/bin/caddy adapt --config /etc/open-card/open-card-edge.Caddyfile --adapter caddyfile --validate >/dev/null
  systemctl restart open-card-server.service
  systemctl enable --now open-card-edge.service
  # Bootstrap is intentionally last: earlier Edge/config/service failures can
  # roll back without creating a credential that would block a retry.
  /opt/open-card/current/bin/open-card-admin bootstrap --password-file "$admin_password_file"
  activation_committed=1
  trap - EXIT
else
  systemctl disable --now open-card-edge.service >/dev/null 2>&1 || true
  echo "open-card install-host: core release staged; administrator HTTP and public Edge remain inactive until explicit password-file and HTTPS origin activation"
fi
