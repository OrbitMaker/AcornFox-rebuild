#!/usr/bin/env bash
set -euo pipefail

host=${OPEN_CARD_DEVBOX_HOST:-ubuntu@192.168.31.64}
key=${OPEN_CARD_DEVBOX_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
task=/home/ubuntu/opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
ssh_args=(-i "$key" -o BatchMode=yes -o ConnectTimeout=10)
test -f "$key"
pre_b64=$(base64 <"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clean_worker_g7_guest.sh" | tr -d '\n')
post_b64=$(base64 <"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clean_worker_g7_post_reboot_guest.sh" | tr -d '\n')

ssh "${ssh_args[@]}" "$host" "set -eu
test \"\$(sudo virsh domuuid '$domain')\" = fce4e26d-93b0-5128-a090-969ef73835d4
'$task/clean-worker-host-snapshot.sh' >'$task/g7-host-before.json'
'$task/clean-worker-guest-exec.sh' 'install -d -m 0750 /var/lib/opencard-mvp-fa8f8eab/acceptance; printf %s $pre_b64 | base64 -d >/var/lib/opencard-mvp-fa8f8eab/acceptance/g7.sh; printf %s $post_b64 | base64 -d >/var/lib/opencard-mvp-fa8f8eab/acceptance/g7-post.sh; chmod 0750 /var/lib/opencard-mvp-fa8f8eab/acceptance/g7.sh /var/lib/opencard-mvp-fa8f8eab/acceptance/g7-post.sh'
OPEN_CARD_GUEST_EXEC_TIMEOUT=300 '$task/clean-worker-guest-exec.sh' 'bash /var/lib/opencard-mvp-fa8f8eab/acceptance/g7.sh'
boot_before=\$('$task/clean-worker-guest-exec.sh' 'cat /proc/sys/kernel/random/boot_id')
sudo virsh reboot '$domain' --mode agent >/dev/null
for i in \$(seq 1 60); do
  if sudo virsh qemu-agent-command '$domain' '{\"execute\":\"guest-ping\"}' >/dev/null 2>&1; then
    boot_after=\$('$task/clean-worker-guest-exec.sh' 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
    if test -n \"\$boot_after\" && test \"\$boot_after\" != \"\$boot_before\"; then break; fi
  fi
  sleep 2
done
test \"\$(sudo virsh domstate '$domain')\" = running
OPEN_CARD_GUEST_EXEC_TIMEOUT=300 '$task/clean-worker-guest-exec.sh' 'bash /var/lib/opencard-mvp-fa8f8eab/acceptance/g7-post.sh'
'$task/clean-worker-host-snapshot.sh' >'$task/g7-host-after.json'
cmp '$task/g7-host-before.json' '$task/g7-host-after.json'
echo g7_host_snapshot=unchanged"
