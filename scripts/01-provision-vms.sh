#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/config.sh
source "$SCRIPT_DIR/lib/config.sh"
# shellcheck source=lib/ssh.sh
source "$SCRIPT_DIR/lib/ssh.sh"
# shellcheck source=lib/host.sh
source "$SCRIPT_DIR/lib/host.sh"

oc_require_commands ssh awk sed base64 seq
oc_validate_config
for key in "$DEV_SSH_KEY" "$TEST_SSH_KEY" "$VM_SSH_KEY"; do
  [[ -z $key || -r $key ]] || oc_die "SSH key is not readable: $key"
done

if [[ -z $VM_SSH_PUBLIC_KEY ]]; then
  for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    if [[ -r $candidate ]]; then
      VM_SSH_PUBLIC_KEY="$(sed -n '1p' "$candidate")"
      break
    fi
  done
fi
[[ -n $VM_SSH_PUBLIC_KEY ]] || oc_die "set VM_SSH_PUBLIC_KEY or provide ~/.ssh/id_ed25519.pub"

dns_yaml="$(printf '%s' "$LAN_DNS_SERVERS" | awk -F',' '{for (i = 1; i <= NF; i++) printf "        - %s\n", $i}')"

provision_one() {
  local name=$1
  local host_role=$2
  local host=$3
  local ip=$4
  local mac=$5
  local role=$6
  local nic=$7
  local user_b64 net_b64 meta_b64
  local user_data network_config meta_data

  user_data="$(cat <<EOF
#cloud-config
hostname: $name
fqdn: $name.opencard.internal
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
ssh_authorized_keys:
  - $VM_SSH_PUBLIC_KEY
write_files:
  - path: /etc/modules-load.d/opencard-k8s.conf
    permissions: '0644'
    content: |
      overlay
      br_netfilter
  - path: /etc/sysctl.d/99-opencard-k8s.conf
    permissions: '0644'
    content: |
      net.ipv4.ip_forward = 1
      net.bridge.bridge-nf-call-iptables = 1
      net.bridge.bridge-nf-call-ip6tables = 1
runcmd:
  - [ bash, -c, "swapoff -a || true; sed -ri '/[[:space:]]swap[[:space:]]/s/^/#/' /etc/fstab" ]
  - [ modprobe, overlay ]
  - [ modprobe, br_netfilter ]
  - [ sysctl, --system ]
EOF
  )"
  network_config="$(cat <<EOF
version: 2
ethernets:
  eth0:
    match:
      macaddress: $mac
    set-name: eth0
    dhcp4: false
    addresses:
      - $ip/24
    routes:
      - to: default
        via: $LAN_GATEWAY
    nameservers:
      addresses:
$dns_yaml
EOF
  )"
  meta_data="instance-id: $CLUSTER_NAME-$name
local-hostname: $name
"
  user_b64="$(oc_b64 "$user_data")"
  net_b64="$(oc_b64 "$network_config")"
  meta_b64="$(oc_b64 "$meta_data")"

  oc_info "provisioning $name on $host ($ip, $mac, parent $nic)"
  oc_ssh_root_script "$host" \
    "$name" "$ip" "$mac" "$nic" "$VM_IMAGE_DIR" "$VM_IMAGE_URL" \
    "${VM_IMAGE_SHA256:--}" "$VM_ROOT_SIZE_GB" "$VM_DATA_SIZE_GB" "$VM_MEMORY_MB" \
    "$VM_VCPUS" "$VM_OS_VARIANT" "$user_b64" "$net_b64" "$meta_b64" <<'REMOTE'
set -Eeuo pipefail
name=$1
ip=$2
mac=$3
parent_nic=$4
image_dir=$5
image_url=$6
image_sha256=$7
[[ $image_sha256 == - ]] && image_sha256=
root_size=$8
data_size=$9
memory_mb=${10}
vcpus=${11}
os_variant=${12}
user_b64=${13}
net_b64=${14}
meta_b64=${15}
base="$image_dir/base/noble-server-cloudimg-amd64.img"
root_disk="$image_dir/$name-os.qcow2"
data_disk="$image_dir/$name-data.qcow2"
seed_disk="$image_dir/$name-seed.iso"
mkdir -p "$image_dir/base"
chmod 0755 "$image_dir" "$image_dir/base"

if [[ ! -s $base ]]; then
  tmp="$base.download.$$"
  curl --fail --location --retry 3 --retry-delay 2 --output "$tmp" "$image_url"
  mv -f -- "$tmp" "$base"
fi
if [[ -n $image_sha256 ]]; then
  actual="$(sha256sum "$base" | awk '{print $1}')"
  [[ $actual == "$image_sha256" ]] || { printf 'cloud image checksum mismatch\n' >&2; exit 1; }
fi

if virsh --connect qemu:///system dominfo "$name" >/dev/null 2>&1; then
  xml="$(virsh --connect qemu:///system dumpxml "$name")"
  printf '%s\n' "$xml" | grep -Fq "$mac" || { printf 'existing VM MAC mismatch: %s\n' "$name" >&2; exit 1; }
  printf '%s\n' "$xml" | grep -Fq "$root_disk" || { printf 'existing VM OS disk mismatch: %s\n' "$name" >&2; exit 1; }
  printf '%s\n' "$xml" | grep -Fq "$data_disk" || { printf 'existing VM data disk mismatch: %s\n' "$name" >&2; exit 1; }
  cpu_count="$(virsh --connect qemu:///system dominfo "$name" | awk -F: '$1 ~ /^CPU/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
  [[ $cpu_count == "$vcpus" ]] || { printf 'existing VM CPU mismatch: %s\n' "$name" >&2; exit 1; }
  state="$(virsh --connect qemu:///system domstate "$name" | awk 'NF {print; exit}')"
  [[ $state == running ]] || virsh --connect qemu:///system start "$name"
  virsh --connect qemu:///system autostart "$name"
  exit 0
fi

for disk in "$root_disk" "$data_disk" "$seed_disk"; do
  [[ ! -e $disk ]] || { printf 'refusing to overwrite orphaned disk: %s\n' "$disk" >&2; exit 1; }
done

user_data="$(printf '%s' "$user_b64" | base64 -d)"
net_data="$(printf '%s' "$net_b64" | base64 -d)"
meta_data="$(printf '%s' "$meta_b64" | base64 -d)"
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT
printf '%s\n' "$user_data" > "$tmpdir/user-data"
printf '%s\n' "$net_data" > "$tmpdir/network-config"
printf '%s\n' "$meta_data" > "$tmpdir/meta-data"

qemu-img convert -O qcow2 "$base" "$root_disk"
qemu-img resize "$root_disk" "${root_size}G" >/dev/null
qemu-img create -f qcow2 "$data_disk" "${data_size}G" >/dev/null
cloud-localds --network-config="$tmpdir/network-config" "$seed_disk" "$tmpdir/user-data" "$tmpdir/meta-data"
chmod 0644 "$seed_disk"
virt-install --connect qemu:///system --name "$name" \
  --memory "$memory_mb",maxmemory="$memory_mb" --vcpus "$vcpus",maxvcpus="$vcpus" \
  --cpu host-passthrough --os-variant "$os_variant" --import --noautoconsole \
  --graphics none --network "type=direct,source=$parent_nic,source_mode=bridge,model=virtio,mac=$mac" \
  --disk "path=$root_disk,format=qcow2,bus=virtio" \
  --disk "path=$data_disk,format=qcow2,bus=virtio" \
  --disk "path=$seed_disk,device=cdrom,readonly=on" --boot hd
virsh --connect qemu:///system autostart "$name"
REMOTE

  oc_wait_ssh "$ip" 90 || oc_die "guest SSH did not become ready: $name ($ip)"
}

oc_info "preparing both physical hosts"
oc_host_prepare_packages "$DEV_HOST"
oc_host_prepare_packages "$TEST_HOST"
oc_host_shutdown_legacy "$DEV_HOST" "$LEGACY_DEV_VMS"
oc_host_shutdown_legacy "$TEST_HOST" "$LEGACY_TEST_VMS"

while IFS='|' read -r name host_role host ip mac role; do
  nic="$(oc_host_parent_nic "$host" "$(oc_host_nic_setting "$host_role")")"
  [[ -n $nic ]] || oc_die "could not determine parent NIC on $host"
  provision_one "$name" "$host_role" "$host" "$ip" "$mac" "$role" "$nic"
done <<EOF
$(oc_node_records)
EOF

oc_info "VM provisioning complete; run scripts/02-install-k3s.sh next"
