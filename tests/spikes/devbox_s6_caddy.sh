#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

DEVBOX_HOST="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
container="opencard-mvp-fa8f8eab-caddy"

ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" "
set -eu
test \"\$(docker inspect '$container' --format '{{index .Config.Labels \"open-card.task\"}}')\" = opencard-mvp-fa8f8eab
test \"\$(docker inspect '$container' --format '{{.State.Status}}')\" = running
test \"\$(curl -fsS http://127.0.0.1:18480/)\" = open-card-caddy-spike-v2
if ss -lntH 'sport = :18481' | grep -q .; then
  echo 'Caddy admin was unexpectedly published on the host' >&2
  exit 1
fi
docker exec '$container' caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
docker exec '$container' wget -qO- http://127.0.0.1:2019/config/ >/dev/null
printf '%s\\n' \\
  'fixture_route=ok' \\
  'config_validation=ok' \\
  'admin_inside_container=ok' \\
  'admin_host_publish=absent' \\
  'public_dns_acme=not_run'
"
