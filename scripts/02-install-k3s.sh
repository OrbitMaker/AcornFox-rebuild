#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/config.sh
source "$SCRIPT_DIR/lib/config.sh"
# shellcheck source=lib/ssh.sh
source "$SCRIPT_DIR/lib/ssh.sh"

oc_require_commands ssh awk sed base64 seq
oc_validate_config
oc_wait_ssh "$DEV_NODE_IP" 30 || oc_die "dev guest is not reachable: $DEV_NODE_IP"

disable_yaml="$(printf '%s' "$K3S_DISABLE_COMPONENTS" | awk -F',' '{for (i = 1; i <= NF; i++) printf "  - %s\n", $i}')"
disable_b64="$(oc_b64 "$disable_yaml")"
oc_info "installing k3s server $K3S_VERSION on $DEV_NODE_NAME"
oc_ssh_root_script "$DEV_NODE_IP" "$K3S_VERSION" "$DEV_NODE_IP" "$disable_b64" <<'REMOTE'
set -Eeuo pipefail
version=$1
node_ip=$2
disable_yaml="$(printf '%s' "$3" | base64 -d)"
if command -v k3s >/dev/null 2>&1; then
  installed="$(k3s --version | awk 'NR == 1 {print $3}')"
  [[ $installed == "$version" ]] || { printf 'k3s version mismatch: %s != %s\n' "$installed" "$version" >&2; exit 1; }
fi
install -d -m 0700 /etc/rancher/k3s
cat > /etc/rancher/k3s/config.yaml <<CONFIG
write-kubeconfig-mode: "0644"
node-ip: "$node_ip"
advertise-address: "$node_ip"
tls-san:
  - "$node_ip"
disable:
$disable_yaml
kubelet-arg:
  - "system-reserved=cpu=100m,memory=256Mi"
  - "kube-reserved=cpu=100m,memory=256Mi"
  - "eviction-hard=memory.available<256Mi,nodefs.available<10%"
CONFIG
if ! command -v k3s >/dev/null 2>&1; then
  curl --fail --location --retry 3 https://get.k3s.io | \
    INSTALL_K3S_VERSION="$version" INSTALL_K3S_EXEC=server sh -
fi
systemctl enable --now k3s
for attempt in $(seq 1 60); do
  if k3s kubectl get nodes >/dev/null 2>&1; then
    exit 0
  fi
  sleep 2
done
printf 'k3s API did not become ready\n' >&2
exit 1
REMOTE

token="$(oc_ssh_root "$DEV_NODE_IP" cat /var/lib/rancher/k3s/server/node-token)"
[[ -n $token ]] || oc_die "k3s server did not expose a join token"
token_b64="$(oc_b64 "$token")"

while IFS='|' read -r name host_role host ip mac role; do
  [[ $role == agent ]] || continue
  oc_wait_ssh "$ip" 30 || oc_die "worker guest is not reachable: $ip"
  oc_info "installing k3s agent $K3S_VERSION on $name"
  oc_ssh_root_script "$ip" "$K3S_VERSION" "$DEV_NODE_IP" "$ip" "$token_b64" <<'REMOTE'
set -Eeuo pipefail
version=$1
server_ip=$2
node_ip=$3
token="$(printf '%s' "$4" | base64 -d)"
if command -v k3s >/dev/null 2>&1; then
  installed="$(k3s --version | awk 'NR == 1 {print $3}')"
  [[ $installed == "$version" ]] || { printf 'k3s version mismatch: %s != %s\n' "$installed" "$version" >&2; exit 1; }
fi
install -d -m 0700 /etc/rancher/k3s
if [[ ! -s /etc/rancher/k3s/config.yaml ]]; then
  umask 077
  cat > /etc/rancher/k3s/config.yaml <<CONFIG
server: "https://$server_ip:6443"
token: "$token"
node-ip: "$node_ip"
kubelet-arg:
  - "system-reserved=cpu=100m,memory=256Mi"
  - "kube-reserved=cpu=100m,memory=256Mi"
  - "eviction-hard=memory.available<256Mi,nodefs.available<10%"
CONFIG
fi
unset token
if ! command -v k3s >/dev/null 2>&1; then
  curl --fail --location --retry 3 https://get.k3s.io | \
    INSTALL_K3S_VERSION="$version" INSTALL_K3S_EXEC=agent sh -
fi
systemctl enable --now k3s-agent
REMOTE
done <<EOF
$(oc_node_records)
EOF

mkdir -p "$OC_REPO_ROOT/artifacts/kubernetes"
oc_ssh_root "$DEV_NODE_IP" cat /etc/rancher/k3s/k3s.yaml |
  sed "s#https://127.0.0.1:6443#https://$DEV_NODE_IP:6443#" > "$OC_REPO_ROOT/artifacts/kubeconfig"
chmod 0600 "$OC_REPO_ROOT/artifacts/kubeconfig"

oc_info "k3s installation complete; run scripts/verify-k8s.sh"
