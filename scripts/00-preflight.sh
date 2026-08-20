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
[[ $VM_SSH_PUBLIC_KEY == ssh-*\ * ]] || oc_die "VM_SSH_PUBLIC_KEY does not look like an OpenSSH public key"

oc_info "Open Card preflight: four VMs, 4 vCPU/4096 MiB each, 30+20 GiB disks"
for host in "$DEV_HOST" "$TEST_HOST"; do
  oc_info "checking SSH, passwordless sudo, KVM and libvirt on $host"
  oc_ssh "$host" true >/dev/null || oc_die "cannot connect to $SSH_USER@$host in BatchMode"
  oc_ssh_root "$host" true >/dev/null || oc_die "passwordless sudo is required on $host"
  facts="$(oc_host_facts "$host")"
  oc_info "$host: $facts"
  mem_mb="$(printf '%s\n' "$facts" | sed -n 's/.*mem_mb=\([0-9][0-9]*\).*/\1/p')"
  cpu_count="$(printf '%s\n' "$facts" | sed -n 's/.*cpu_count=\([0-9][0-9]*\).*/\1/p')"
  disk_mb="$(printf '%s\n' "$facts" | sed -n 's/.*disk_mb=\([0-9][0-9]*\).*/\1/p')"
  [[ $cpu_count -ge 4 ]] || oc_die "$host has fewer than 4 host CPUs"
  [[ $mem_mb -ge 5120 ]] || oc_die "$host needs at least 5120 MiB total RAM"
  [[ $disk_mb -ge 51200 ]] || oc_die "$host needs at least 50 GiB free under /var/lib/libvirt/images"
done

dev_facts="$(oc_host_facts "$DEV_HOST")"
test_facts="$(oc_host_facts "$TEST_HOST")"
dev_mem="$(printf '%s\n' "$dev_facts" | sed -n 's/.*mem_mb=\([0-9][0-9]*\).*/\1/p')"
test_mem="$(printf '%s\n' "$test_facts" | sed -n 's/.*mem_mb=\([0-9][0-9]*\).*/\1/p')"
[[ $dev_mem -ge 5120 ]] || oc_die "dev host lacks 1 GiB memory headroom beyond its VM"
[[ $test_mem -ge 13312 ]] || oc_die "test host lacks 1 GiB memory headroom beyond three VMs"

dev_disk="$(printf '%s\n' "$dev_facts" | sed -n 's/.*disk_mb=\([0-9][0-9]*\).*/\1/p')"
test_disk="$(printf '%s\n' "$test_facts" | sed -n 's/.*disk_mb=\([0-9][0-9]*\).*/\1/p')"
[[ $dev_disk -ge 51200 ]] || oc_die "dev host lacks 50 GiB for its VM"
[[ $test_disk -ge 153600 ]] || oc_die "test host lacks 150 GiB for three VMs"

oc_info "preflight passed; run scripts/01-provision-vms.sh next"
