#!/usr/bin/env bash

# Configuration loader and validation for the Open Card PoC.

if [[ -n ${OPENCARD_CONFIG_LOADED:-} ]]; then
  return 0
fi
OPENCARD_CONFIG_LOADED=1

OC_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OC_CONFIG_FILE="${OPENCARD_CONFIG_FILE:-$OC_REPO_ROOT/config/cluster.env}"
if [[ ! -f $OC_CONFIG_FILE ]]; then
  OC_CONFIG_FILE="$OC_REPO_ROOT/config/cluster.env.example"
fi

# shellcheck disable=SC1090
source "$OC_CONFIG_FILE"

: "${CLUSTER_NAME:=opencard}"
: "${SSH_USER:=ubuntu}"
: "${DEV_SSH_KEY:=}"
: "${TEST_SSH_KEY:=}"
: "${VM_SSH_USER:=$SSH_USER}"
: "${VM_SSH_KEY:=}"
: "${VM_SSH_PUBLIC_KEY:=}"
: "${DEV_HOST:=192.168.31.64}"
: "${TEST_HOST:=192.168.31.22}"
: "${DEV_PARENT_NIC:=auto}"
: "${TEST_PARENT_NIC:=auto}"
: "${LAN_CIDR:=192.168.31.0/24}"
: "${LAN_GATEWAY:=192.168.31.1}"
: "${LAN_DNS_SERVERS:=192.168.31.1,1.1.1.1}"
: "${DEV_NODE_NAME:=opencard-dev-01}"
: "${DEV_NODE_IP:=192.168.31.71}"
: "${DEV_NODE_MAC:=52:54:00:4f:43:01}"
: "${TEST_NODE_01_NAME:=opencard-test-01}"
: "${TEST_NODE_01_IP:=192.168.31.72}"
: "${TEST_NODE_01_MAC:=52:54:00:4f:43:02}"
: "${TEST_NODE_02_NAME:=opencard-test-02}"
: "${TEST_NODE_02_IP:=192.168.31.73}"
: "${TEST_NODE_02_MAC:=52:54:00:4f:43:03}"
: "${TEST_NODE_03_NAME:=opencard-test-03}"
: "${TEST_NODE_03_IP:=192.168.31.74}"
: "${TEST_NODE_03_MAC:=52:54:00:4f:43:04}"
: "${VM_ROOT_SIZE_GB:=30}"
: "${VM_DATA_SIZE_GB:=20}"
: "${VM_MEMORY_MB:=4096}"
: "${VM_VCPUS:=4}"
: "${VM_IMAGE_DIR:=/var/lib/libvirt/images/opencard}"
: "${VM_IMAGE_URL:=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
: "${VM_IMAGE_SHA256:=}"
: "${VM_OS_VARIANT:=ubuntu24.04}"
: "${K3S_VERSION:=v1.34.10+k3s1}"
: "${K3S_DISABLE_COMPONENTS:=traefik,servicelb}"
: "${SSH_STRICT_HOST_KEY_CHECKING:=accept-new}"
: "${SSH_CONNECT_TIMEOUT:=10}"

# Explicitly named legacy Sealos domains. No other legacy domain may be
# touched by the provisioning scripts.
LEGACY_DEV_VMS="sealos-worker-02 sealos-worker-03"
LEGACY_TEST_VMS="sealos-cp-01 sealos-worker-01"

oc_node_records() {
  printf '%s\n' \
    "$DEV_NODE_NAME|dev|$DEV_HOST|$DEV_NODE_IP|$DEV_NODE_MAC|server" \
    "$TEST_NODE_01_NAME|test|$TEST_HOST|$TEST_NODE_01_IP|$TEST_NODE_01_MAC|agent" \
    "$TEST_NODE_02_NAME|test|$TEST_HOST|$TEST_NODE_02_IP|$TEST_NODE_02_MAC|agent" \
    "$TEST_NODE_03_NAME|test|$TEST_HOST|$TEST_NODE_03_IP|$TEST_NODE_03_MAC|agent"
}

oc_node_names() {
  oc_node_records | awk -F'|' '{print $1}'
}

oc_validate_config() {
  local number
  local name
  local host_role
  local host
  local ip
  local mac
  local role
  local records
  records="$(oc_node_records)"

  [[ $VM_ROOT_SIZE_GB =~ ^[1-9][0-9]*$ ]] || oc_die "VM_ROOT_SIZE_GB must be a positive integer"
  [[ $VM_DATA_SIZE_GB =~ ^[1-9][0-9]*$ ]] || oc_die "VM_DATA_SIZE_GB must be a positive integer"
  [[ $VM_MEMORY_MB =~ ^[1-9][0-9]*$ ]] || oc_die "VM_MEMORY_MB must be a positive integer"
  [[ $VM_VCPUS =~ ^[1-9][0-9]*$ ]] || oc_die "VM_VCPUS must be a positive integer"
  [[ $VM_ROOT_SIZE_GB -eq 30 && $VM_DATA_SIZE_GB -eq 20 ]] || \
    oc_die "the PoC requires a 30 GiB OS disk plus a 20 GiB data disk per VM"
  [[ $VM_MEMORY_MB -eq 4096 && $VM_VCPUS -eq 4 ]] || \
    oc_die "the PoC requires 4 vCPU and 4096 MiB per VM"
  [[ $K3S_VERSION == v1.34.10+k3s1 ]] || \
    oc_die "K3S_VERSION must remain v1.34.10+k3s1 for this PoC"
  [[ $VM_IMAGE_URL == https://cloud-images.ubuntu.com/noble/* ]] || \
    oc_die "VM_IMAGE_URL must point to the Ubuntu 24.04 (noble) cloud image"

  number=0
  while IFS='|' read -r name host_role host ip mac role; do
    number=$((number + 1))
    [[ -n $name && -n $host_role && -n $host && -n $ip && -n $mac && -n $role ]] || \
      oc_die "node record $number is incomplete"
    [[ $host_role == dev || $host_role == test ]] || oc_die "invalid host role: $host_role"
    [[ $role == server || $role == agent ]] || oc_die "invalid k3s role: $role"
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || oc_die "invalid node IP: $ip"
    [[ $mac =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || oc_die "invalid node MAC: $mac"
    [[ $name != sealos-* ]] || oc_die "new node must not use a legacy Sealos name: $name"
  done <<EOF
$records
EOF

  [[ $number -eq 4 ]] || oc_die "exactly four nodes are required"
  [[ $DEV_HOST != "$TEST_HOST" ]] || oc_die "DEV_HOST and TEST_HOST must be distinct physical hosts"

  # awk provides duplicate checks without requiring Bash 4 associative arrays;
  # this keeps the scripts runnable on the macOS system Bash used by operators.
  if printf '%s\n' "$records" | awk -F'|' '{if (++name[$1] > 1) exit 1}'; then :; else oc_die "duplicate node name"; fi
  if printf '%s\n' "$records" | awk -F'|' '{if (++ip[$4] > 1) exit 1}'; then :; else oc_die "duplicate node IP"; fi
  if printf '%s\n' "$records" | awk -F'|' '{if (++mac[$5] > 1) exit 1}'; then :; else oc_die "duplicate node MAC"; fi
}

oc_host_nic_setting() {
  case "$1" in
    dev) printf '%s' "$DEV_PARENT_NIC" ;;
    test) printf '%s' "$TEST_PARENT_NIC" ;;
    *) return 1 ;;
  esac
}

oc_host_legacy_vms() {
  case "$1" in
    dev) printf '%s' "$LEGACY_DEV_VMS" ;;
    test) printf '%s' "$LEGACY_TEST_VMS" ;;
    *) return 1 ;;
  esac
}

oc_ssh_key_for_host() {
  case "$1" in
    "$DEV_HOST") printf '%s' "$DEV_SSH_KEY" ;;
    "$TEST_HOST") printf '%s' "$TEST_SSH_KEY" ;;
    *) printf '%s' "$VM_SSH_KEY" ;;
  esac
}
