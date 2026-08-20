#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
# shellcheck source=lib/config.sh
source "$ROOT_DIR/scripts/lib/config.sh"
# shellcheck source=lib/ssh.sh
source "$ROOT_DIR/scripts/lib/ssh.sh"
KUBECTL="${KUBECTL:-kubectl}"
HELM="${HELM:-helm}"
CHART_VERSION="v0.7.1"
CHART_URL="${OPEN_LOCAL_SOURCE_URL:-https://github.com/alibaba/open-local/archive/refs/tags/${CHART_VERSION}.tar.gz}"
VALUES_FILE="$ROOT_DIR/components/storage/values.yaml"

for bin in "$KUBECTL" "$HELM" curl tar find xargs; do
  command -v "$bin" >/dev/null || { echo "$bin is required" >&2; exit 1; }
done

tmpdir=""
if [[ -n "${OPEN_LOCAL_CHART:-}" ]]; then
  chart="$OPEN_LOCAL_CHART"
else
  tmpdir="$(mktemp -d)"
  curl -fsSL "$CHART_URL" -o "$tmpdir/open-local.tar.gz"
  tar -xzf "$tmpdir/open-local.tar.gz" -C "$tmpdir"
  chart="$(find "$tmpdir" -type f -path '*/helm/Chart.yaml' -print -quit | xargs dirname)"
fi
[[ -f "$chart/Chart.yaml" ]] || { echo "Open-Local Helm chart was not found: $chart" >&2; exit 1; }
if [[ -n "$tmpdir" ]]; then
  trap 'rm -rf "$tmpdir"' EXIT
fi

"$HELM" upgrade --install open-local "$chart" \
  --namespace kube-system \
  --reset-values \
  --values "$VALUES_FILE" \
  --set-string "agent.kubelet_dir=${OPEN_LOCAL_KUBELET_DIR:-/var/lib/kubelet}" \
  --wait=false

# The v0.7.1 chart assumes one registry prefix for every image. Keep CSI
# sidecars on the Kubernetes mirror and route the Open-Local image through the
# reachable Docker Hub cache before waiting for readiness.
open_local_image=dockerproxy.net/openlocal/open-local:v0.7.1
"$KUBECTL" -n kube-system set image daemonset/open-local-agent \
  agent="$open_local_image" csi-plugin="$open_local_image"
"$KUBECTL" -n kube-system set image deployment/open-local-controller \
  csi-plugin="$open_local_image" controller="$open_local_image"
"$KUBECTL" -n kube-system set image deployment/open-local-scheduler-extender \
  open-local-scheduler-extender="$open_local_image"
"$KUBECTL" -n kube-system patch deployment/open-local-scheduler-extender --type=json -p \
  '[{"op":"replace","path":"/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/0/matchExpressions/0/key","value":"node-role.kubernetes.io/control-plane"}]'

# Bound the upstream CSI node plugin on the 4Gi PoC nodes.
"$KUBECTL" -n kube-system patch daemonset/open-local-agent --type strategic -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"csi-plugin","resources":{"requests":{"cpu":"50m","memory":"128Mi"},"limits":{"cpu":"500m","memory":"512Mi"}}}]}}}}'
"$KUBECTL" -n kube-system rollout status daemonset/open-local-agent --timeout=5m
"$KUBECTL" -n kube-system rollout status deployment/open-local-controller --timeout=5m
"$KUBECTL" -n kube-system rollout status deployment/open-local-scheduler-extender --timeout=5m

echo "Open-Local ${CHART_VERSION} installed; storage smoke PVC is applied by verify-storage.sh."
