#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
task_id=opencard-mvp-fa8f8eab
host="${OPEN_CARD_DEVBOX_HOST:-ubuntu@192.168.31.64}"
key="${OPEN_CARD_DEVBOX_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}"
remote_repo="/tmp/${task_id}-g7-repo"
remote_work="/tmp/${task_id}-g7"
ssh_args=(-i "$key" -o BatchMode=yes -o ConnectTimeout=10)

[[ -f "$key" ]] || { echo "devbox SSH key is missing" >&2; exit 78; }

cleanup_remote() {
  ssh "${ssh_args[@]}" "$host" "python3 -c 'import pathlib,shutil; paths=[pathlib.Path(\"$remote_repo\"),pathlib.Path(\"$remote_work\")]; [shutil.rmtree(p,ignore_errors=True) for p in paths if p.name.startswith(\"$task_id\")]'" >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT INT TERM

snapshot() {
  ssh "${ssh_args[@]}" "$host" "set -eu
ip route show default | sha256sum
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
virsh list --all --name 2>/dev/null | sort | sha256sum
docker ps -a --format '{{.Names}}' | grep -v '^$task_id' | sort | sha256sum
for service in docker containerd frpc libvirtd; do printf '%s=' \"\$service\"; systemctl is-active \"\$service\" 2>/dev/null || true; done"
}

before=$(snapshot)
cleanup_remote
ssh "${ssh_args[@]}" "$host" "python3 -c 'import pathlib; pathlib.Path(\"$remote_repo\").mkdir(parents=True,exist_ok=True)'"
COPYFILE_DISABLE=1 tar --no-xattrs -czf - \
  tests/spikes/g7_user_fixture.sh \
  scripts/mvp/install.sh \
  scripts/mvp/upgrade.sh \
  scripts/mvp/uninstall.sh \
  scripts/mvp/backup-control-plane.sh \
  scripts/mvp/restore-control-plane.sh \
  deploy/systemd/open-card-server.service \
  deploy/systemd/open-card-agent.service |
  ssh "${ssh_args[@]}" "$host" "tar -xzf - -C '$remote_repo'"

ssh "${ssh_args[@]}" "$host" "set -eu
chmod +x '$remote_repo'/tests/spikes/g7_user_fixture.sh '$remote_repo'/scripts/mvp/*.sh
OPEN_CARD_TASK_ID='$task_id' OPEN_CARD_G7_WORK_ROOT='$remote_work' bash '$remote_repo/tests/spikes/g7_user_fixture.sh'"
cleanup_remote
after=$(snapshot)
[[ "$before" = "$after" ]] || {
  echo "development-host isolation changed" >&2
  diff -u <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
  exit 1
}
remaining=$(ssh "${ssh_args[@]}" "$host" "find /tmp -maxdepth 1 -name '$task_id-g7*' -print | sort")
[[ -z "$remaining" ]] || { echo "task-scoped fixture paths remain: $remaining" >&2; exit 1; }
printf '%s\n' \
  'devbox_user_fixture=pass' \
  'systemd_mutation=none' \
  'libvirt_mutation=none' \
  'network_policy_mutation=none' \
  'apparmor_mutation=none' \
  'task_paths=reclaimed' \
  'isolation_snapshot=unchanged'
