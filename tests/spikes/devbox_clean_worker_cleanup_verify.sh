#!/usr/bin/env bash
set -euo pipefail

host=${OPEN_CARD_DEVBOX_HOST:-ubuntu@192.168.31.64}
key=${OPEN_CARD_DEVBOX_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
task=/home/ubuntu/opencard-mvp-fa8f8eab
ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=10 "$host" "set -euo pipefail
'$task/clean-worker-host-snapshot.sh' >'$task/clean-worker-host-cleanup-verification.json'
cmp '$task/clean-worker-host-before.json' '$task/clean-worker-host-cleanup-verification.json'
! sudo virsh dominfo opencard-mvp-fa8f8eab-build-worker-01 >/dev/null 2>&1
! sudo virsh pool-info opencard-mvp-fa8f8eab-build-workers >/dev/null 2>&1
! sudo virsh net-info opencard-mvp-fa8f8eab-build-isolated >/dev/null 2>&1
sudo test ! -e /var/lib/libvirt/images/opencard-mvp-fa8f8eab
test ! -e /sys/class/net/virbr-opencard
test ! -e '$task/clean-worker-offline-source'
test ! -e '$task/clean-worker-offline-iso-root'
test ! -e '$task/opencard-mvp-fa8f8eab-clean-worker-offline-bundle.tar'
test \"\$(docker inspect opencard-mvp-fa8f8eab-postgres --format '{{.State.Running}}')\" = true
test \"\$(docker inspect opencard-mvp-fa8f8eab-caddy --format '{{.State.Running}}')\" = true
printf '%s\n' 'domain=absent' 'volume=absent' 'pool=absent' 'network=absent' 'bridge=absent' 'bundle=absent' 'host_baseline=exact_match' 'postgres_fixture=preserved' 'caddy_fixture=preserved'"
