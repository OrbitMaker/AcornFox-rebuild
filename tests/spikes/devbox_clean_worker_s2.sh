#!/usr/bin/env bash
set -euo pipefail

host=${OPEN_CARD_DEVBOX_HOST:-ubuntu@192.168.31.64}
key=${OPEN_CARD_DEVBOX_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
task=/home/ubuntu/opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
network=opencard-mvp-fa8f8eab-build-isolated
ssh_args=(-i "$key" -o BatchMode=yes -o ConnectTimeout=10)
test -f "$key"

ssh "${ssh_args[@]}" "$host" "set -eu
test \"\$(sudo virsh domuuid '$domain')\" = fce4e26d-93b0-5128-a090-969ef73835d4
test \"\$(sudo virsh domstate '$domain')\" = running
test \"\$(sudo virsh dominfo '$domain' | awk '/Autostart:/{print \$2}')\" = disable
test -z \"\$(sudo virsh net-dumpxml '$network' | grep -E '<forward|<ip ' || true)\"
test -z \"\$(sudo virsh dumpxml --inactive '$domain' | grep -E '<filesystem|<hostdev' || true)\"
'$task/clean-worker-host-snapshot.sh' >'$task/s2-host-before.json'
OPEN_CARD_GUEST_EXEC_TIMEOUT=300 '$task/clean-worker-guest-exec.sh' 'bash /opt/opencard-offline/outer/payload/clean_worker_s2_guest.sh'
'$task/clean-worker-host-snapshot.sh' >'$task/s2-host-after.json'
cmp '$task/s2-host-before.json' '$task/s2-host-after.json'
echo s2_host_snapshot=unchanged"
