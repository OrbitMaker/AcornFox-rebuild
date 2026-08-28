#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

DEVBOX_HOST="${DEVBOX_HOST:-ubuntu@192.168.31.64}"

ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" '
set -eu
total_running=$(docker ps -q | wc -l | tr -d " ")
task_running=$(docker ps --filter label=open-card.task=opencard-mvp-fa8f8eab -q | wc -l | tr -d " ")
non_task_running=$((total_running - task_running))
test "$non_task_running" -eq 43
test "$task_running" -eq 2
test "$(docker inspect opencard-mvp-fa8f8eab-postgres --format "{{.State.Status}}")" = running
test "$(docker inspect opencard-mvp-fa8f8eab-caddy --format "{{.State.Status}}")" = running
test "$(docker inspect opencard-mvp-fa8f8eab-buildkit --format "{{.State.Status}}")" = exited
for service in docker.service containerd.service frpc.service libvirtd.service; do
  test "$(systemctl is-active "$service")" = active
done
default_route=$(ip route show default)
test -n "$default_route"
printf "%s\n" \
  "non_task_running_containers=$non_task_running" \
  "task_running_containers=$task_running" \
  "task_postgres=running" \
  "task_caddy=running" \
  "task_buildkit=exited" \
  "protected_services=active" \
  "default_route_present=yes"
'
