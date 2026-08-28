#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
devbox_host="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
task_id="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"
remote_base="/home/ubuntu/$task_id"
remote_binary="$remote_base/open-card-agent-docker-facts.test"
local_binary="${TMPDIR:-/tmp}/open-card-agent-docker-facts-$$.test"
ssh_args=(-i "$DEVBOX_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8)

test "$task_id" = "opencard-mvp-fa8f8eab"
ssh "${ssh_args[@]}" "$devbox_host" "test -f '$remote_base/.open-card-task-marker'"
host_baseline_before="$(ssh "${ssh_args[@]}" "$devbox_host" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps -a --format '{{.ID}} {{.Status}} {{.Labels}}' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"

cleanup() {
  unlink "$local_binary" 2>/dev/null || true
  ssh "${ssh_args[@]}" "$devbox_host" "unlink '$remote_binary' 2>/dev/null || true" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

(
  cd "$repo_root"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags integration -o "$local_binary" ./cmd/open-card-agent
)
scp "${ssh_args[@]}" "$local_binary" "$devbox_host:$remote_binary" >/dev/null
ssh "${ssh_args[@]}" "$devbox_host" "chmod 0700 '$remote_binary' && OPEN_CARD_DOCKER_SOCKET=/var/run/docker.sock '$remote_binary' -test.run '^TestAgentReadsRealDockerFactsWithoutMutation$' -test.v"

host_baseline_after="$(ssh "${ssh_args[@]}" "$devbox_host" \
  "cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; ip route show default; docker ps -a --format '{{.ID}} {{.Status}} {{.Labels}}' | sort | sha256sum; sudo -n virsh list --all --name | sort | sha256sum")"
test "$host_baseline_before" = "$host_baseline_after"
echo "docker_read_only_facts=yes"
echo "docker_container_inventory_unchanged=yes"
echo "non_task_host_baseline_unchanged=yes"
