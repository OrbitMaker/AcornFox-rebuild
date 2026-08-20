#!/usr/bin/env bash
# Install the low-resource Prometheus/Grafana stack and its PoC scrape targets.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/monitoring}"
NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
RELEASE="${PROMETHEUS_RELEASE:-kube-prometheus-stack}"
CHART_VERSION="${PROMETHEUS_STACK_VERSION:-88.5.2}"
REPO_NAME="${PROMETHEUS_HELM_REPO_NAME:-prometheus-community}"
REPO_URL="${PROMETHEUS_HELM_REPO_URL:-https://prometheus-community.github.io/helm-charts}"
HELM="${HELM:-helm}"
KUBECTL="${KUBECTL:-kubectl}"

mkdir -p "$ARTIFACT_DIR"

capture_state() {
  local exit_code=$?
  set +e
  "$KUBECTL" get pods -n "$NAMESPACE" -o wide >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get prometheus,servicemonitor,podmonitor -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/monitoring-on-failure.yaml" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_state ERR

command -v "$HELM" >/dev/null
command -v "$KUBECTL" >/dev/null
"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"

"$HELM" repo add "$REPO_NAME" "$REPO_URL" --force-update \
  >"$ARTIFACT_DIR/helm-repo-add.txt"
"$HELM" repo update >"$ARTIFACT_DIR/helm-repo-update.txt"

"$KUBECTL" apply -f "$REPO_ROOT/components/monitoring/namespace.yaml" \
  >"$ARTIFACT_DIR/namespace-apply.txt"
"$HELM" upgrade --install "$RELEASE" "$REPO_NAME/kube-prometheus-stack" \
  --namespace "$NAMESPACE" --create-namespace \
  --version "$CHART_VERSION" \
  --values "$REPO_ROOT/components/monitoring/values.yaml" \
  --wait --timeout="${MONITORING_HELM_TIMEOUT:-600s}" \
  >"$ARTIFACT_DIR/helm-upgrade.txt"
printf 'chart=kube-prometheus-stack\nrelease=%s\nversion=%s\nrepo=%s\n' \
  "$RELEASE" "$CHART_VERSION" "$REPO_URL" >"$ARTIFACT_DIR/version.txt"

# Wait for every release-owned Deployment/StatefulSet without assuming chart
# generated names; this remains valid across chart naming changes.
while read -r resource; do
  [[ -z "$resource" ]] || "$KUBECTL" rollout status "$resource" -n "$NAMESPACE" \
    --timeout="${MONITORING_ROLLOUT_TIMEOUT:-300s}" \
    >>"$ARTIFACT_DIR/rollouts.txt"
done < <("$KUBECTL" get deployment,statefulset -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=$RELEASE" -o name)

"$KUBECTL" wait --for=condition=Established \
  crd/podmonitors.monitoring.coreos.com --timeout="${MONITORING_CRD_TIMEOUT:-180s}" \
  >"$ARTIFACT_DIR/podmonitor-crd-ready.txt"
"$KUBECTL" apply -k "$REPO_ROOT/components/monitoring" \
  >"$ARTIFACT_DIR/custom-monitors-apply.txt"

"$KUBECTL" get prometheus -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/prometheus.yaml"
"$KUBECTL" get deployment -n "$NAMESPACE" \
  -l "app.kubernetes.io/name=grafana" -o yaml >"$ARTIFACT_DIR/grafana-deployment.yaml"
"$KUBECTL" get servicemonitor,podmonitor -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/scrape-monitors.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" -o wide >"$ARTIFACT_DIR/pods.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'Monitoring ready: %s %s; Prometheus retention=2d; Alertmanager disabled\n' \
  "$RELEASE" "$CHART_VERSION"
