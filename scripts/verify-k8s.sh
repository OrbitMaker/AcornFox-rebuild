#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/config.sh
source "$SCRIPT_DIR/lib/config.sh"
# shellcheck source=lib/ssh.sh
source "$SCRIPT_DIR/lib/ssh.sh"

oc_require_commands ssh awk sed seq
oc_validate_config
oc_wait_ssh "$DEV_NODE_IP" 30 || oc_die "dev guest is not reachable: $DEV_NODE_IP"

names="$(oc_node_names)"
set -- $names
oc_info "verifying four-node k3s cluster on $DEV_NODE_NAME"
oc_ssh_root_script "$DEV_NODE_IP" "$@" <<'REMOTE'
set -Eeuo pipefail
expected_count=$#
nodes="$(k3s kubectl get nodes --no-headers -o custom-columns=NAME:.metadata.name)"
actual_count="$(printf '%s\n' "$nodes" | awk 'NF {count++} END {print count + 0}')"
[[ $actual_count -eq $expected_count ]] || { printf 'node count mismatch: %s != %s\n' "$actual_count" "$expected_count" >&2; exit 1; }
for node in "$@"; do
  printf '%s\n' "$nodes" | grep -Fxq "$node" || { printf 'missing node: %s\n' "$node" >&2; exit 1; }
  ready="$(k3s kubectl get node "$node" -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}' | awk -F= '$1 == "Ready" {print $2; exit}')"
  [[ $ready == True ]] || { printf 'node is not Ready: %s\n' "$node" >&2; exit 1; }
  pressure="$(k3s kubectl get node "$node" -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}')"
  printf '%s\n' "$pressure" | grep -Eq '^MemoryPressure=False$' || { printf 'memory pressure on %s\n' "$node" >&2; exit 1; }
  printf '%s\n' "$pressure" | grep -Eq '^DiskPressure=False$' || { printf 'disk pressure on %s\n' "$node" >&2; exit 1; }
  printf '%s\n' "$pressure" | grep -Eq '^PIDPressure=False$' || { printf 'pid pressure on %s\n' "$node" >&2; exit 1; }
done
version="$(k3s --version | awk 'NR == 1 {print $3}')"
[[ $version == v1.34.10+k3s1 ]] || { printf 'server version mismatch: %s\n' "$version" >&2; exit 1; }
if k3s kubectl -n kube-system get deployment traefik >/dev/null 2>&1; then
  printf 'Traefik must be disabled\n' >&2
  exit 1
fi
if k3s kubectl -n kube-system get service traefik >/dev/null 2>&1; then
  printf 'Traefik service must be disabled\n' >&2
  exit 1
fi
dev_taints="$(k3s kubectl get node "$1" -o jsonpath='{.spec.taints}')"
[[ -z $dev_taints || $dev_taints == '[]' ]] || { printf 'dev node is tainted and not schedulable: %s\n' "$dev_taints" >&2; exit 1; }
k3s kubectl get nodes -o wide
REMOTE

oc_info "k3s verification passed: Ready nodes, no pressure, Traefik absent, dev schedulable"
