#!/usr/bin/env bash

# Remote physical-host checks and package preparation.

if [[ -n ${OPENCARD_HOST_LOADED:-} ]]; then
  return 0
fi
OPENCARD_HOST_LOADED=1

oc_host_prepare_packages() {
  local host=${1:?host required}
  oc_info "checking libvirt prerequisites on $host"
  oc_ssh_root_script "$host" <<'REMOTE'
set -Eeuo pipefail
missing=0
for command_name in virsh virt-install qemu-img cloud-localds curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    missing=1
  fi
done
if [[ $missing -eq 1 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates curl cloud-image-utils genisoimage \
    libvirt-clients libvirt-daemon-system qemu-kvm qemu-utils virtinst
fi
command -v virsh >/dev/null 2>&1
command -v virt-install >/dev/null 2>&1
command -v qemu-img >/dev/null 2>&1
command -v cloud-localds >/dev/null 2>&1
virsh --connect qemu:///system uri >/dev/null
[[ -e /dev/kvm ]] || { printf 'missing /dev/kvm\n' >&2; exit 1; }
REMOTE
}

oc_host_parent_nic() {
  local host=${1:?host required}
  local configured=${2:-auto}
  if [[ $configured != auto ]]; then
    printf '%s' "$configured"
    return 0
  fi
  oc_ssh "$host" "ip -o route show default | awk 'NR == 1 {print \\$5}'" | awk 'NF {print; exit}'
}

oc_host_facts() {
  local host=${1:?host required}
  oc_ssh_root_script "$host" <<'REMOTE'
set -Eeuo pipefail
mem_mb="$(awk '/MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo)"
cpu_count="$(nproc)"
image_path=/var/lib/libvirt/images
[[ -d $image_path ]] || image_path=/var/lib
disk_mb="$(df -Pm "$image_path" | awk 'NR == 2 {print $4}')"
if [[ -e /dev/kvm ]]; then kvm=yes; else kvm=no; fi
printf 'mem_mb=%s cpu_count=%s disk_mb=%s kvm=%s\n' "$mem_mb" "$cpu_count" "$disk_mb" "$kvm"
REMOTE
}

oc_host_vm_exists() {
  local host=${1:?host required}
  local name=${2:?name required}
  oc_ssh_root "$host" virsh --connect qemu:///system dominfo "$name" >/dev/null 2>&1
}

oc_host_vm_state() {
  local host=${1:?host required}
  local name=${2:?name required}
  oc_ssh_root "$host" virsh --connect qemu:///system domstate "$name" 2>/dev/null | awk 'NF {print; exit}'
}

oc_host_shutdown_legacy() {
  local host=${1:?host required}
  local names=${2:?explicit legacy VM names required}
  local name state attempt
  for name in $names; do
    if ! oc_host_vm_exists "$host" "$name"; then
      continue
    fi
    oc_warn "legacy Sealos VM $name on $host: disabling autostart and requesting graceful shutdown"
    # Explicitly limited legacy operation: no destroy, undefine, or disk removal.
    oc_ssh_root "$host" virsh --connect qemu:///system autostart "$name" --disable
    state="$(oc_host_vm_state "$host" "$name")"
    if [[ $state == running || $state == paused || $state == 'in shutdown' ]]; then
      oc_ssh_root "$host" virsh --connect qemu:///system shutdown "$name" >/dev/null
      for attempt in $(seq 1 40); do
        state="$(oc_host_vm_state "$host" "$name")"
        [[ $state == 'shut off' ]] && break
        sleep 3
      done
      [[ $state == 'shut off' ]] || oc_die "legacy VM did not shut down gracefully: $host/$name"
    fi
  done
}
