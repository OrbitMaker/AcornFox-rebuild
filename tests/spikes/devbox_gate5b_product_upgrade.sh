#!/usr/bin/env bash
# Isolated devbox harness for production-wrapper Gate5B product acceptance.
# No VM is started by this task merely because this script is added; when run,
# it uses a NAT-only libvirt network with no host port forwards or cloud
# writes.  Guest egress is limited to package retrieval during this run.
set -Eeuo pipefail
umask 077

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
prefix=${OPEN_CARD_G5B_PRODUCT_PREFIX:-opencard-g5b-20260830-a02}
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
scenario=${OPEN_CARD_G5B_PRODUCT_SCENARIO:-success}
[[ "$scenario" == success || "$scenario" == active-switch-crash ]]
[[ -z "${OPEN_CARD_DEVBOX_HOST+x}" ]] || { echo "OPEN_CARD_DEVBOX_HOST override is forbidden" >&2; exit 2; }
remote=yanyan-devbox-via-idc
domain=$prefix
network=${prefix}-net
pool=${prefix}-pool
bridge=virbr-g5ba02
task=/var/lib/libvirt/images/$prefix
claim=/var/lib/libvirt/images/.${prefix}.claim
base=/var/lib/libvirt/images/sealos-cluster/ubuntu-24.04-server-cloudimg-amd64.img
base_sha=0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe
rc0_rel=output/production/0.8.0-rc.0/amd64
rc1_rel=output/production/0.8.0-rc.1/amd64
rc1_source=21d28c918b02f97b5fb91d2f686d4f195f578e15
local_tmp=$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX")
local_evidence=${OPEN_CARD_G5B_PRODUCT_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.evidence.XXXXXX")}
mkdir -p "$local_evidence"

verify_remote_identity() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" \
    "test \"\$(hostname)\" = ubuntu-MS-7B89 && test \"\$(id -un)\" = ubuntu && test \"\$(sha256sum /etc/machine-id | awk '{print \$1}')\" = f3b9cd9ce170c557efb30595f1afd90756a45ae2889e0b948ce1a6b740ac582f"
}
secret_scan() {
  ! grep -R -a -E 'postgres(ql)?://|OPEN_CARD_DATABASE_URL=|BEGIN [A-Z ]*PRIVATE KEY|password=|g5b[-_](dsn|password|token)[-_]?(canary|sentinel)' "$local_evidence"
}

remote_cleanup() {
  verify_remote_identity
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$prefix' '$domain' '$network' '$pool' '$task' '$claim' '$bridge'" <<'REMOTE'
set -Eeuo pipefail
prefix=$1 domain=$2 network=$3 pool=$4 task=$5 claim=$6 bridge=$7
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
[[ "$domain" = "$prefix" && "$network" = "$prefix-net" && "$pool" = "$prefix-pool" ]]
[[ "$task" = "/var/lib/libvirt/images/$prefix" && "$claim" = "/var/lib/libvirt/images/.${prefix}.claim" && "$bridge" = virbr-g5ba02 ]]
claim_text=$(printf 'open-card-g5b-product-claim-v2\nprefix=%s\ndomain=%s\nnetwork=%s\npool=%s\ntask=%s\nbridge=%s\n' "$prefix" "$domain" "$network" "$pool" "$task" "$bridge")
if ! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"; then
  ! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
  ! sudo -n virsh net-info "$network" >/dev/null 2>&1
  ! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
  ! sudo -n test -e "$task" && ! sudo -n test -L "$task"
  ! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
else
  [[ "$(sudo -n cat "$claim")" = "${claim_text%$'\n'}" ]]
  if sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
    state=$(sudo -n virsh domstate "$domain")
    [[ "$state" != running && "$state" != paused ]] || sudo -n virsh destroy "$domain" >/dev/null
    sudo -n virsh undefine "$domain" --managed-save >/dev/null 2>&1 || sudo -n virsh undefine "$domain" >/dev/null
  fi
  if sudo -n virsh net-info "$network" >/dev/null 2>&1; then
    [[ "$(sudo -n virsh net-info "$network" | awk -F': *' '/^Active:/{print $2}')" != yes ]] || sudo -n virsh net-destroy "$network" >/dev/null
    sudo -n virsh net-undefine "$network" >/dev/null
  fi
  if sudo -n virsh pool-info "$pool" >/dev/null 2>&1; then
    [[ "$(sudo -n virsh pool-info "$pool" | awk -F': *' '/^State:/{print $2}')" != running ]] || sudo -n virsh pool-destroy "$pool" >/dev/null
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
REMOTE
}
remote_absence() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$domain' '$network' '$pool' '$task' '$claim' '$bridge'" <<'REMOTE'
set -Eeuo pipefail
domain=$1 network=$2 pool=$3 task=$4 claim=$5 bridge=$6
! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
! sudo -n virsh net-info "$network" >/dev/null 2>&1
! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
! sudo -n test -e "$task" && ! sudo -n test -L "$task"
! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"
! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
printf 'DOMAIN_ABSENT\nNET_ABSENT\nPOOL_ABSENT\nROOT_ABSENT\nBRIDGE_ABSENT\nCLAIM_ABSENT\n'
REMOTE
}
fetch_remote() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n test -f '$claim' && sudo -n tar -C '$task/evidence' -cf - ." 2>/dev/null | tar -C "$local_evidence" -xf - 2>/dev/null
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n test -f '$claim' && sudo -n cat '$task/host-before.txt'" >"$local_evidence/host-before.txt"
}
on_exit() {
  local code=$? cleanup=0 verify=0 scan=0
  set +e
  (( code == 0 )) || fetch_remote || true
  secret_scan || scan=$?
  remote_cleanup >"$local_evidence/cleanup.txt" || cleanup=$?
  remote_absence >"$local_evidence/cleanup-verify.txt" || verify=$?
  rm -rf -- "$local_tmp"
  trap - EXIT
  (( code != 0 )) && exit "$code"
  (( scan == 0 )) || exit "$scan"
  (( cleanup == 0 )) || exit "$cleanup"
  exit "$verify"
}
for path in tests/spikes/clean_worker_gate5b_product_guest.sh "$rc0_rel/release/manifest.json" "$rc1_rel/release/manifest.json"; do test -f "$repo_root/$path"; done
test "$(git -C "$repo_root" rev-parse "$rc1_source^{commit}")" = "$rc1_source"
git -C "$repo_root" merge-base --is-ancestor "$rc1_source" HEAD
test -z "$(git -C "$repo_root" status --short)"
test "$(sha256sum "$repo_root/$rc1_rel/release/manifest.json" | awk '{print $1}')" = 182c4421ae6fea0706e3bc456afd3b330136186353083d50d4a9107cf9f3f770
test "$(sha256sum "$repo_root/$rc1_rel/open-card-0.8.0-rc.1-production.tar.gz" | awk '{print $1}')" = 93d69e64e6bb6bef4b9648cb2f183a320230204f001c87dd447cd4ca70c1b25d
test "$(sha256sum "$repo_root/$rc1_rel/bundle-manifest.sha256" | awk '{print $1}')" = 28815c1e96816f0ae358dafbd5df8b56f746d48ff4b160bb6953dcded8cd6523
python3 - "$repo_root/tests/spikes/clean_worker_gate5b_product_guest.sh" <<'PY'
import pathlib, sys
source=pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
helper="/opt/open-card/upgrade-tools/open-card-upgrade"
references=[line.strip() for line in source.splitlines() if helper in line]
want='mapfile -t helper_pids < <(pgrep -f "^/opt/open-card/upgrade-tools/open-card-upgrade run --transaction-id $tx ")'
assert references == [want], references
assert "stage-upgrade-substrate" not in source
PY
verify_remote_identity
trap on_exit EXIT
mkdir -p "$local_tmp/candidates"
cp "$repo_root/tests/spikes/clean_worker_gate5b_product_guest.sh" "$local_tmp/"
cp "$repo_root/tests/spikes/devbox_gate5b_product_upgrade.sh" "$local_tmp/"
cp -a "$repo_root/$rc0_rel" "$local_tmp/candidates/rc0"
cp -a "$repo_root/$rc1_rel" "$local_tmp/candidates/rc1"
if command -v xattr >/dev/null 2>&1; then xattr -cr "$local_tmp"; fi
printf '%s\n' "$rc1_source" >"$local_tmp/source-commit.txt"
git -C "$repo_root" rev-parse HEAD >"$local_tmp/harness-commit.txt"
(cd "$local_tmp" && find clean_worker_gate5b_product_guest.sh devbox_gate5b_product_upgrade.sh candidates -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) >"$local_tmp/source-manifest.sha256"
printf 'candidate_source_is_ancestor_of_harness_commit=yes\nharness_worktree=clean\n' >"$local_tmp/harness-binding.txt"
cat "$local_tmp/source-commit.txt" "$local_tmp/harness-commit.txt" "$local_tmp/source-manifest.sha256" "$local_tmp/harness-binding.txt" >"$local_evidence/source-binding.txt"

verify_remote_identity
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$prefix' '$domain' '$network' '$pool' '$task' '$claim' '$bridge' '$base' '$base_sha'" <<'REMOTE_CREATE'
set -Eeuo pipefail
prefix=$1 domain=$2 network=$3 pool=$4 task=$5 claim=$6 bridge=$7 base=$8 base_sha=$9
snapshot() {
  printf '[domains]\n'; sudo -n virsh list --all --name | LC_ALL=C sort
  printf '[networks]\n'; sudo -n virsh net-list --all --name | LC_ALL=C sort
  printf '[pools]\n'; sudo -n virsh pool-list --all --name | LC_ALL=C sort
  printf '[bridge]\n'; sudo -n ip link show dev "$bridge" 2>/dev/null || printf 'ABSENT\n'
}
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
[[ "$domain" = "$prefix" && "$network" = "$prefix-net" && "$pool" = "$prefix-pool" ]]
[[ "$task" = "/var/lib/libvirt/images/$prefix" && "$claim" = "/var/lib/libvirt/images/.${prefix}.claim" && "$bridge" = virbr-g5ba02 ]]
! sudo -n virsh dominfo "$domain" >/dev/null 2>&1
! sudo -n virsh net-info "$network" >/dev/null 2>&1
! sudo -n virsh pool-info "$pool" >/dev/null 2>&1
! sudo -n test -e "$task" && ! sudo -n test -L "$task"
! sudo -n test -e "$claim" && ! sudo -n test -L "$claim"
! sudo -n ip link show dev "$bridge" >/dev/null 2>&1
sudo -n test -f "$base" && ! sudo -n test -L "$base"
[[ "$(sudo -n sha256sum -- "$base" | awk '{print $1}')" = "$base_sha" ]]
claim_text=$(printf 'open-card-g5b-product-claim-v2\nprefix=%s\ndomain=%s\nnetwork=%s\npool=%s\ntask=%s\nbridge=%s\n' "$prefix" "$domain" "$network" "$pool" "$task" "$bridge")
printf '%s' "$claim_text" | sudo -n tee "$claim" >/dev/null
sudo -n chmod 0600 "$claim"
sudo -n install -d -o root -g root -m 0711 "$task" "$task/volumes"
sudo -n install -d -o root -g root -m 0700 "$task/source" "$task/evidence"
snapshot | sudo -n tee "$task/host-before.txt" >/dev/null
free -h | sudo -n tee "$task/evidence/host-memory-before.txt" >/dev/null
printf '%s  %s\n' "$base_sha" "$base" | sudo -n tee "$task/evidence/base-image.sha256" >/dev/null
sudo -n ssh-keygen -q -t ed25519 -N '' -f "$task/id_ed25519"
sudo -n tee "$task/network.xml" >/dev/null <<EOF
<network><name>$network</name><forward mode='nat'/><bridge name='$bridge' stp='on' delay='0'/><ip address='192.168.254.1' netmask='255.255.255.0'><dhcp><range start='192.168.254.20' end='192.168.254.200'/></dhcp></ip></network>
EOF
sudo -n virsh net-define "$task/network.xml"; sudo -n virsh net-start "$network"; sudo -n virsh net-autostart "$network" --disable >/dev/null
sudo -n virsh net-dumpxml "$network" | grep -Eq "<forward[[:space:]][^>]*mode='nat'([[:space:]>])"
! sudo -n virsh net-dumpxml "$network" | grep -Eq '<port[^>]*(protocol|host|guest)='
sudo -n virsh pool-define-as "$pool" dir --target "$task/volumes"; sudo -n virsh pool-build "$pool"; sudo -n virsh pool-start "$pool"; sudo -n virsh pool-autostart "$pool" --disable >/dev/null
sudo -n qemu-img create -f qcow2 -F qcow2 -b "$base" "$task/volumes/$domain.qcow2"; sudo -n qemu-img resize "$task/volumes/$domain.qcow2" 100G
pub=$(sudo -n cat "$task/id_ed25519.pub")
sudo -n tee "$task/user-data" >/dev/null <<EOF
#cloud-config
ssh_pwauth: false
disable_root: true
users: [default]
ssh_authorized_keys: [$pub]
EOF
sudo -n tee "$task/meta-data" >/dev/null <<EOF
instance-id: $domain
local-hostname: $domain
EOF
sudo -n cloud-localds "$task/seed.iso" "$task/user-data" "$task/meta-data"; sudo -n chmod 0644 "$task/seed.iso"
sudo -n virt-install --name "$domain" --memory 8192 --vcpus 4 --cpu host-model --disk "path=$task/volumes/$domain.qcow2,format=qcow2,bus=virtio" --disk "path=$task/seed.iso,device=cdrom,readonly=on" --network "network=$network,model=virtio" --os-variant ubuntu24.04 --graphics none --noautoconsole --import --check all=off
sudo -n virsh autostart "$domain" --disable >/dev/null
REMOTE_CREATE

COPYFILE_DISABLE=1 tar -C "$local_tmp" -cf - clean_worker_gate5b_product_guest.sh devbox_gate5b_product_upgrade.sh candidates source-commit.txt source-manifest.sha256 harness-binding.txt harness-commit.txt | ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "sudo -n tar -C '$task/source' -xf -"
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "bash -s -- '$network' '$task' '$prefix' '$scenario'" <<'REMOTE_GUEST'
set -Eeuo pipefail
network=$1 task=$2 prefix=$3 scenario=$4
[[ "$scenario" == success || "$scenario" == active-switch-crash ]]
for _ in $(seq 1 240); do
  ip=$(sudo -n virsh net-dhcp-leases "$network" 2>/dev/null | awk '/ipv4/ {sub(/\/.*/,"",$5); print $5; exit}')
  if [[ -n "${ip:-}" && ! -s "$task/known_hosts" ]]; then sudo -n ssh-keyscan -T 3 -t ed25519 "$ip" 2>/dev/null | sudo -n tee "$task/known_hosts" >/dev/null || true; sudo -n chmod 0600 "$task/known_hosts"; fi
  if [[ -n "${ip:-}" && -s "$task/known_hosts" ]] && sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=3 ubuntu@"$ip" true 2>/dev/null; then break; fi
  sleep 2
done
test -n "${ip:-}" && test -s "$task/known_hosts"
sudo -n scp -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes -r "$task/source" ubuntu@"$ip":/home/ubuntu/g5b-product-source
run_guest() {
  sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" \
    "sudo OPEN_CARD_G5B_PRODUCT_PREFIX='$prefix' OPEN_CARD_G5B_PRODUCT_SCENARIO='$scenario' bash /home/ubuntu/g5b-product-source/clean_worker_gate5b_product_guest.sh $1"
}
set +e
run_guest initial 2>&1 | sudo -n tee "$task/evidence/guest-initial.txt"
status=${PIPESTATUS[0]}
set -e
sudo -n install -d -o root -g root -m 0700 "$task/evidence/guest"
sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" "sudo tar -C /var/lib/open-card/$prefix/evidence -cf - ." | sudo -n tar -C "$task/evidence/guest" -xf - || true
if (( status != 0 )); then exit "$status"; fi
boot_before=$(sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" cat /proc/sys/kernel/random/boot_id)
sudo -n virsh reboot "$prefix" --mode acpi >/dev/null
for _ in $(seq 1 240); do
  if sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=3 ubuntu@"$ip" true 2>/dev/null; then
    boot_after=$(sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    [[ -n "$boot_after" && "$boot_after" != "$boot_before" ]] && break
  fi
  sleep 2
done
test -n "${boot_after:-}" && [[ "$boot_after" != "$boot_before" ]]
set +e
run_guest post-reboot 2>&1 | sudo -n tee "$task/evidence/guest-post-reboot.txt"
post_status=${PIPESTATUS[0]}
set -e
sudo -n ssh -n -i "$task/id_ed25519" -o BatchMode=yes -o UserKnownHostsFile="$task/known_hosts" -o StrictHostKeyChecking=yes ubuntu@"$ip" "sudo tar -C /var/lib/open-card/$prefix/evidence -cf - ." | sudo -n tar -C "$task/evidence/guest" -xf -
if (( post_status != 0 )); then exit "$post_status"; fi
printf 'boot_before=%s\nboot_after=%s\n' "$boot_before" "$boot_after" | sudo -n tee "$task/evidence/guest-boot.txt" >/dev/null
REMOTE_GUEST

fetch_remote
if [[ "$scenario" == success ]]; then
  grep -Fxq 'marker=absent' "$local_evidence/guest/summary.txt"
  grep -Fxq 'edge=active' "$local_evidence/guest/summary.txt"
  grep -Fxq 'backup_restore=PASS' "$local_evidence/guest/summary.txt"
  grep -Fxq 'post_reboot=PASS' "$local_evidence/guest/post-reboot-summary.txt"
  grep -Fxq 'crash_failure_matrix=PENDING' "$local_evidence/guest/summary.txt"
  grep -Fxq 'public_dns_acme_customer_acceptance=PENDING' "$local_evidence/guest/summary.txt"
else
  grep -Fxq 'crash_recovery=PASS' "$local_evidence/guest/crash-recovery-summary.txt"
  grep -Fxq 'journal_state=ROLLED_BACK' "$local_evidence/guest/crash-recovery-summary.txt"
  grep -Fxq 'candidate_retained=PASS' "$local_evidence/guest/crash-recovery-summary.txt"
fi
remote_cleanup >"$local_evidence/cleanup.txt"
for token in DOMAIN_ABSENT NET_ABSENT POOL_ABSENT ROOT_ABSENT BRIDGE_ABSENT CLAIM_ABSENT; do grep -Fxq "$token" "$local_evidence/cleanup.txt"; done
ssh -o BatchMode=yes -o ConnectTimeout=15 "$remote" "printf '[domains]\\n'; sudo -n virsh list --all --name | LC_ALL=C sort; printf '[networks]\\n'; sudo -n virsh net-list --all --name | LC_ALL=C sort; printf '[pools]\\n'; sudo -n virsh pool-list --all --name | LC_ALL=C sort; printf '[bridge]\\n'; sudo -n ip link show dev '$bridge' 2>/dev/null || printf 'ABSENT\\n'" >"$local_evidence/host-after.txt"
cmp "$local_evidence/host-before.txt" "$local_evidence/host-after.txt"
echo "G5B_PRODUCT_${scenario^^}=PASS evidence=$local_evidence"
