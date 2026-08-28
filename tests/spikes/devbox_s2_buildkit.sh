#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

DEVBOX_HOST="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
container="opencard-mvp-fa8f8eab-buildkit"

ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" "
set -eu
test \"\$(docker inspect '$container' --format '{{index .Config.Labels \"open-card.task\"}}')\" = opencard-mvp-fa8f8eab
test \"\$(docker inspect '$container' --format '{{.HostConfig.Privileged}}')\" = false
test \"\$(docker inspect '$container' --format '{{.State.Status}}')\" = exited
docker logs '$container' 2>&1 | grep -q 'apparmor_restrict_unprivileged_userns'
docker logs '$container' 2>&1 | grep -q 'permission denied'
printf '%s\\n' \\
  'rootless_container_privileged=false' \\
  'rootless_start=blocked' \\
  'blocker=host_user_namespace_policy' \\
  'host_policy_modified=false'
"
