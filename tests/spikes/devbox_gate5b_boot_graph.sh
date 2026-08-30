#!/usr/bin/env bash
# Creates one isolated Ubuntu 24.04 libvirt guest, exercises the Gate5B boot
# graph, collects sanitized evidence, then restores the devbox host exactly.
set -Eeuo pipefail
umask 077

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
prefix=${OPEN_CARD_G5B_BOOT_PREFIX:-opencard-g5b-20260830-a01}
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
remote=${OPEN_CARD_DEVBOX_HOST:-yanyan-devbox-via-idc}
task=/var/lib/libvirt/images/$prefix
claim=/var/lib/libvirt/images/.${prefix}.claim
domain=$prefix
network=${prefix}-net
pool=${prefix}-pool
bridge=virbr-g5ba01
base=/var/lib/libvirt/images/sealos-cluster/ubuntu-24.04-server-cloudimg-amd64.img
local_tmp=$(mktemp -d "${TMPDIR:-/tmp}/$prefix.XXXXXX")
if [[ -n "${OPEN_CARD_G5B_BOOT_EVIDENCE_DIR:-}" ]]; then
  local_evidence=$OPEN_CARD_G5B_BOOT_EVIDENCE_DIR
else
  local_evidence=$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.evidence.XXXXXX")
fi
mkdir -p "$local_evidence"

cleanup_local() { rm -rf "$local_tmp"; }
cleanup_remote() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$prefix' '$domain' '$network' '$pool' '$task' '$claim' '$bridge'" <<'REMOTE_CLEANUP'
set -Eeuo pipefail
prefix=$1 domain=$2 network=$3 pool=$4 task=$5 claim=$6 bridge=$7
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
[[ "$domain" == "$prefix" && "$network" == "$prefix-net" && "$pool" == "$prefix-pool" && "$task" == "/var/lib/libvirt/images/$prefix" ]]
[[ "$claim" == "/var/lib/libvirt/images/.${prefix}.claim" && "$bridge" == virbr-g5ba01 ]]
claim_text=$(printf 'open-card-g5b-boot-claim-v1\nprefix=%s\ndomain=%s\nnetwork=%s\npool=%s\ntask=%s\nbridge=%s\n' \
  "$prefix" "$domain" "$network" "$pool" "$task" "$bridge")

# A missing claim proves this task created nothing.  A present claim must bind
# every mutable resource exactly; the task marker is deliberately irrelevant.
if ! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"; then
  ! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
  ! sudo -n virsh net-info "$network" >/dev/null 2>&1
  ! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
    ! sudo -n test -e "$task" && ! sudo -n test -L "$task"
  ! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
else
  [[ "$(sudo -n cat "$claim")" == "${claim_text%$'\n'}" ]]
  if sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
    state=$(sudo -n virsh domstate "$domain")
    if [[ "$state" == running || "$state" == paused ]]; then
      sudo -n virsh destroy "$domain" >/dev/null
    fi
    if ! sudo -n virsh undefine "$domain" --managed-save >/dev/null 2>&1; then
      sudo -n virsh undefine "$domain" >/dev/null
    fi
  fi
  if sudo -n virsh net-info "$network" >/dev/null 2>&1; then
    active=$(sudo -n virsh net-info "$network" | awk -F': *' '/^Active:/{print $2}')
    [[ "$active" != yes ]] || sudo -n virsh net-destroy "$network" >/dev/null
    sudo -n virsh net-undefine "$network" >/dev/null
  fi
  if sudo -n virsh pool-info "$pool" >/dev/null 2>&1; then
    active=$(sudo -n virsh pool-info "$pool" | awk -F': *' '/^State:/{print $2}')
    [[ "$active" != running ]] || sudo -n virsh pool-destroy "$pool" >/dev/null
    sudo -n virsh pool-undefine "$pool" >/dev/null
  fi
  sudo -n rm -rf -- "$task"
  sudo -n rm -f -- "$claim"
fi
! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
! sudo -n virsh net-info "$network" >/dev/null 2>&1
! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
! sudo -n test -e "$task" && ! sudo -n test -L "$task"
! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"
! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
printf 'DOMAIN_ABSENT\nNET_ABSENT\nPOOL_ABSENT\nROOT_ABSENT\nBRIDGE_ABSENT\nCLAIM_ABSENT\n'
REMOTE_CLEANUP
}
verify_remote_absence() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$domain' '$network' '$pool' '$task' '$claim' '$bridge'" <<'REMOTE_VERIFY'
set -Eeuo pipefail
domain=$1 network=$2 pool=$3 task=$4 claim=$5 bridge=$6
! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
! sudo -n virsh net-info "$network" >/dev/null 2>&1
! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
! sudo -n test -e "$task" && ! sudo -n test -L "$task"
! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"
! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
printf 'DOMAIN_ABSENT\nNET_ABSENT\nPOOL_ABSENT\nROOT_ABSENT\nBRIDGE_ABSENT\nCLAIM_ABSENT\n'
REMOTE_VERIFY
}
on_exit() {
  local status=$?
  local cleanup_status=0
  local verify_status=0
  set +e
  if (( status != 0 )); then
    mkdir -p "$local_evidence"
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" \
      "sudo -n test -f '$claim' && sudo -n test -d '$task/evidence' && sudo -n tar -C '$task/evidence' -cf - ." \
      2>/dev/null | tar -C "$local_evidence" -xf - 2>/dev/null
    fetch_status=${PIPESTATUS[1]}
    (( fetch_status == 0 )) || printf 'failure_evidence_fetch_status=%s\n' "$fetch_status" >&2
  fi
  cleanup_remote >"$local_evidence/cleanup.txt" || cleanup_status=$?
  if (( cleanup_status != 0 )); then
    printf 'remote_cleanup_failed_status=%s\n' "$cleanup_status" >&2
  fi
  verify_remote_absence >"$local_evidence/cleanup-verify.txt" || verify_status=$?
  if (( verify_status != 0 )); then
    printf 'remote_cleanup_absence_verify_failed_status=%s\n' "$verify_status" >&2
    (( cleanup_status == 0 )) && cleanup_status=$verify_status
  fi
  cleanup_local || cleanup_status=$?
  trap - EXIT
  (( status != 0 )) && exit "$status"
  exit "$cleanup_status"
}
trap on_exit EXIT

for path in \
  tests/spikes/clean_worker_gate5b_boot_guest.sh \
  tests/spikes/devbox_gate5b_boot_graph.sh \
  deploy/systemd/open-card-upgrade-recover.service \
  deploy/systemd/open-card-upgrade-safe.target \
  deploy/systemd/open-card-upgrade-finalize.service \
  deploy/systemd/open-card-edge.service.d/10-upgrade-marker.conf; do
  test -f "$repo_root/$path"
done
cp "$repo_root/tests/spikes/clean_worker_gate5b_boot_guest.sh" "$local_tmp/"
cp "$repo_root/tests/spikes/devbox_gate5b_boot_graph.sh" "$local_tmp/"
mkdir -p "$local_tmp/systemd/open-card-edge.service.d"
cp "$repo_root/deploy/systemd/open-card-upgrade-recover.service" \
  "$repo_root/deploy/systemd/open-card-upgrade-safe.target" \
  "$repo_root/deploy/systemd/open-card-upgrade-finalize.service" "$local_tmp/systemd/"
cp "$repo_root/deploy/systemd/open-card-edge.service.d/10-upgrade-marker.conf" \
  "$local_tmp/systemd/open-card-edge.service.d/"
git -C "$repo_root" rev-parse HEAD >"$local_tmp/source-commit.txt"
(
  cd "$local_tmp"
  sha256sum \
    clean_worker_gate5b_boot_guest.sh \
    devbox_gate5b_boot_graph.sh \
    systemd/open-card-upgrade-recover.service \
    systemd/open-card-upgrade-safe.target \
    systemd/open-card-upgrade-finalize.service \
    systemd/open-card-edge.service.d/10-upgrade-marker.conf
) >"$local_tmp/source-manifest.sha256"
if git -C "$repo_root" diff --quiet -- \
  tests/spikes/clean_worker_gate5b_boot_guest.sh \
  tests/spikes/devbox_gate5b_boot_graph.sh; then
  printf 'harness_worktree=clean\n' >"$local_tmp/harness-binding.txt"
else
  printf 'harness_worktree=dirty\n' >"$local_tmp/harness-binding.txt"
fi
cat "$local_tmp/source-commit.txt" "$local_tmp/source-manifest.sha256" \
  "$local_tmp/harness-binding.txt" >"$local_evidence/source-binding.txt"

# Preflight is read-only.  It records the exact domain/network/pool inventory
# before this task creates anything and rejects a pre-existing prefix.
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$prefix' '$domain' '$network' '$pool' '$task' '$claim' '$bridge' '$base'" <<'REMOTE_CREATE'
set -Eeuo pipefail
prefix=$1 domain=$2 network=$3 pool=$4 task=$5 claim=$6 bridge=$7 base=$8
snapshot() {
  printf '[domains]\n'; sudo -n virsh list --all --name | LC_ALL=C sort
  printf '[networks]\n'; sudo -n virsh net-list --all --name | LC_ALL=C sort
  printf '[pools]\n'; sudo -n virsh pool-list --all --name | LC_ALL=C sort
  printf '[bridge]\n'
  if sudo -n ip link show dev "$bridge" >/dev/null 2>&1; then
    sudo -n ip -d link show dev "$bridge"
  else
    printf 'ABSENT\n'
  fi
}
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
[[ "$domain" == "$prefix" && "$network" == "$prefix-net" && "$pool" == "$prefix-pool" && "$task" == "/var/lib/libvirt/images/$prefix" ]]
[[ "$claim" == "/var/lib/libvirt/images/.${prefix}.claim" && "$bridge" == virbr-g5ba01 ]]
! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
! sudo -n virsh net-info "$network" >/dev/null 2>&1
! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
! sudo -n test -e "$task" && ! sudo -n test -L "$task"
! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"
! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
sudo -n test -f "$base" && ! sudo -n test -L "$base"
claim_text=$(printf 'open-card-g5b-boot-claim-v1\nprefix=%s\ndomain=%s\nnetwork=%s\npool=%s\ntask=%s\nbridge=%s\n' \
  "$prefix" "$domain" "$network" "$pool" "$task" "$bridge")
printf '%s' "$claim_text" | sudo -n tee "$claim" >/dev/null
sudo -n chown root:root "$claim"
sudo -n chmod 0600 "$claim"
[[ "$(sudo -n cat "$claim")" == "${claim_text%$'\n'}" ]]
sudo -n install -d -o root -g root -m 0711 "$task" "$task/volumes"
sudo -n install -d -o root -g root -m 0700 "$task/source" "$task/evidence"
printf '%s\n' "$prefix" | sudo -n tee "$task/.open-card-task-marker" >/dev/null
sudo -n chmod 0600 "$task/.open-card-task-marker"
snapshot | sudo -n tee "$task/host-before.txt" >/dev/null
free -h | sudo -n tee "$task/evidence/host-memory-before.txt" >/dev/null
sudo -n qemu-img info --output=json "$base" | sudo -n tee "$task/evidence/base-image-info.json" >/dev/null
sudo -n ssh-keygen -q -t ed25519 -N '' -f "$task/id_ed25519"
sudo -n tee "$task/network.xml" >/dev/null <<EOF
<network>
  <name>$network</name>
  <bridge name='$bridge' stp='on' delay='0'/>
  <ip address='192.168.254.1' netmask='255.255.255.0'>
    <dhcp><range start='192.168.254.20' end='192.168.254.200'/></dhcp>
  </ip>
</network>
EOF
sudo -n virsh net-define "$task/network.xml"
sudo -n virsh net-start "$network"
sudo -n virsh net-autostart "$network" --disable >/dev/null
sudo -n virsh pool-define-as "$pool" dir --target "$task/volumes"
test "$(sudo -n virsh pool-info "$pool" | awk -F': *' '/^Name:/{print $2}')" = "$pool"
sudo -n virsh pool-build "$pool"
sudo -n virsh pool-start "$pool"
sudo -n virsh pool-autostart "$pool" --disable >/dev/null
sudo -n qemu-img create -f qcow2 -F qcow2 -b "$base" "$task/volumes/$domain.qcow2"
sudo -n qemu-img resize "$task/volumes/$domain.qcow2" 100G
pub=$(sudo -n cat "$task/id_ed25519.pub")
sudo -n tee "$task/user-data" >/dev/null <<EOF
#cloud-config
ssh_pwauth: false
disable_root: true
users:
  - default
ssh_authorized_keys:
  - $pub
write_files:
  - path: /etc/opencard-g5b-boot-guest
    permissions: '0600'
    content: $prefix
runcmd:
  - [systemctl, enable, qemu-guest-agent.service]
EOF
sudo -n tee "$task/meta-data" >/dev/null <<EOF
instance-id: $domain
local-hostname: $domain
EOF
sudo -n cloud-localds "$task/seed.iso" "$task/user-data" "$task/meta-data"
sudo -n chmod 0644 "$task/seed.iso"
sudo -n virt-install --name "$domain" --memory 8192 --vcpus 4 --cpu host-model \
  --disk "path=$task/volumes/$domain.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$task/seed.iso,device=cdrom,readonly=on" \
  --network "network=$network,model=virtio" \
  --channel unix,target_type=virtio,name=org.qemu.guest_agent.0 \
  --os-variant ubuntu24.04 --graphics none --noautoconsole --import --check all=off
sudo -n virsh autostart "$domain" --disable >/dev/null
REMOTE_CREATE

tar -C "$local_tmp" -cf - \
  clean_worker_gate5b_boot_guest.sh \
  devbox_gate5b_boot_graph.sh \
  source-commit.txt \
  source-manifest.sha256 \
  harness-binding.txt \
  systemd | \
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n tar -C '$task/source' -xf -"

# Wait for the no-forward isolated network lease, then use only the task key
# generated under the task root to reach the guest from the devbox host.
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$domain' '$network' '$task' '$prefix'" <<'REMOTE_GUEST'
set -Eeuo pipefail
domain=$1 network=$2 task=$3 prefix=$4
for _ in $(seq 1 180); do
  ip=$(sudo -n virsh net-dhcp-leases "$network" 2>/dev/null | awk '/ipv4/ {sub(/\/.*/,"",$5); print $5; exit}')
  if [[ -n "${ip:-}" && ! -s "$task/known_hosts" ]]; then
    key=$(sudo -n ssh-keyscan -T 3 -t ed25519 "$ip" 2>/dev/null || true)
    if [[ -n "$key" ]]; then
      printf '%s\n' "$key" | sudo -n tee "$task/known_hosts" >/dev/null
      sudo -n chmod 0600 "$task/known_hosts"
    fi
  fi
  if [[ -n "${ip:-}" && -s "$task/known_hosts" ]] && sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=3 ubuntu@"$ip" true 2>/dev/null; then
    printf '%s\n' "$ip" | sudo -n tee "$task/guest-ip" >/dev/null
    break
  fi
  sleep 2
done
test -s "$task/guest-ip"
ip=$(sudo -n cat "$task/guest-ip")
printf 'guest_ip=%s\n' "$ip" | sudo -n tee "$task/evidence/guest-trace.txt" >/dev/null
sudo -n scp -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes -r "$task/source" ubuntu@"$ip":/home/ubuntu/g5b-source
set +e
sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" \
  "sudo OPEN_CARD_G5B_BOOT_PREFIX='$prefix' bash /home/ubuntu/g5b-source/clean_worker_gate5b_boot_guest.sh initial" 2>&1 | \
  sudo -n tee "$task/evidence/guest-initial.txt"
guest_status=${PIPESTATUS[0]}
set -e
if (( guest_status != 0 )); then
  sudo -n install -d -o root -g root -m 0700 "$task/evidence/guest"
  sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" \
    "sudo tar -C /var/lib/open-card/$prefix/evidence -cf - ." | sudo -n tar -C "$task/evidence/guest" -xf - || true
  exit "$guest_status"
fi
printf 'initial_complete\n' | sudo -n tee -a "$task/evidence/guest-trace.txt" >/dev/null
boot_before=$(sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" cat /proc/sys/kernel/random/boot_id)
sudo -n virsh reboot "$domain" --mode acpi >/dev/null
for _ in $(seq 1 180); do
  if sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=3 ubuntu@"$ip" true 2>/dev/null; then
    boot_after=$(sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    [[ -n "$boot_after" && "$boot_after" != "$boot_before" ]] && break
  fi
  sleep 2
done
test -n "${boot_after:-}" && test "$boot_after" != "$boot_before"
sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" \
  "sudo OPEN_CARD_G5B_BOOT_PREFIX='$prefix' bash /home/ubuntu/g5b-source/clean_worker_gate5b_boot_guest.sh post-reboot" 2>&1 | \
  sudo -n tee "$task/evidence/guest-post-reboot.txt" >/dev/null
printf 'post_reboot_complete\n' | sudo -n tee -a "$task/evidence/guest-trace.txt" >/dev/null
sudo -n install -d -o root -g root -m 0700 "$task/evidence/guest"
sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" \
  "sudo tar -C /var/lib/open-card/$prefix/evidence -cf - ." | sudo -n tar -C "$task/evidence/guest" -xf -
printf 'guest_ip=%s\nboot_before=%s\nboot_after=%s\n' "$ip" "$boot_before" "$boot_after" | sudo -n tee "$task/evidence/guest-boot.txt" >/dev/null
REMOTE_GUEST

ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n find '$task/evidence' -maxdepth 3 -type f -printf '%P\\n' | LC_ALL=C sort" >&2
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n test -f '$task/evidence/guest/summary.txt'"
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n tar -C '$task/evidence' -cf - ." | tar -C "$local_evidence" -xf -
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n cat '$task/host-before.txt'" >"$local_evidence/host-before.txt"
cat "$local_evidence/guest/summary.txt"

# Reclaim only resources whose exact claim still binds this task.  The
# cleanup routine verifies the final absence itself and writes its tokens into
# retained local evidence even when the guest marker is absent.
cleanup_remote >"$local_evidence/cleanup.txt"
grep -Fxq DOMAIN_ABSENT "$local_evidence/cleanup.txt"
grep -Fxq NET_ABSENT "$local_evidence/cleanup.txt"
grep -Fxq POOL_ABSENT "$local_evidence/cleanup.txt"
grep -Fxq ROOT_ABSENT "$local_evidence/cleanup.txt"
grep -Fxq BRIDGE_ABSENT "$local_evidence/cleanup.txt"
grep -Fxq CLAIM_ABSENT "$local_evidence/cleanup.txt"

# The final comparison is intentionally a separate read-only SSH call: task
# root is gone, while its baseline was fetched into the local evidence folder.
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "printf '[domains]\\n'; sudo -n virsh list --all --name | LC_ALL=C sort; printf '[networks]\\n'; sudo -n virsh net-list --all --name | LC_ALL=C sort; printf '[pools]\\n'; sudo -n virsh pool-list --all --name | LC_ALL=C sort; printf '[bridge]\\n'; if sudo -n ip link show dev '$bridge' >/dev/null 2>&1; then sudo -n ip -d link show dev '$bridge'; else printf 'ABSENT\\n'; fi" >"$local_evidence/host-after.txt"
cmp "$local_evidence/host-before.txt" "$local_evidence/host-after.txt"
echo "G5B_BOOT_GRAPH=PASS evidence=$local_evidence"
