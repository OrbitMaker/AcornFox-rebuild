#!/usr/bin/env bash
# Verify Prometheus/Grafana readiness and the required metric families.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/monitoring-verify}"
NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
RELEASE="${PROMETHEUS_RELEASE:-kube-prometheus-stack}"
PROM_SERVICE="${PROMETHEUS_SERVICE:-${RELEASE}-prometheus}"
PROM_PORT="${PROMETHEUS_LOCAL_PORT:-19090}"
KUBECTL="${KUBECTL:-kubectl}"
CURL="${CURL:-curl}"

mkdir -p "$ARTIFACT_DIR"
port_forward_pid=""

cleanup() {
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
}
capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get pods -n "$NAMESPACE" -o wide >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get prometheus,servicemonitor,podmonitor -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/monitoring-on-failure.yaml" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  cleanup
  exit "$exit_code"
}
trap capture_failure ERR
trap cleanup EXIT

command -v "$KUBECTL" >/dev/null
command -v "$CURL" >/dev/null
"$KUBECTL" get deployment -n "$NAMESPACE" -l "app.kubernetes.io/name=grafana" \
  -o wide >"$ARTIFACT_DIR/grafana-deployment.txt"
grafana_available="$("$KUBECTL" get deployment -n "$NAMESPACE" \
  -l "app.kubernetes.io/name=grafana" -o jsonpath='{range .items[*]}{.status.availableReplicas}{"\n"}{end}')"
[[ "$grafana_available" =~ ^1$ ]] || {
  echo "Grafana has no available replica" >&2
  exit 1
}

prometheus_name="$("$KUBECTL" get prometheus -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=$RELEASE" -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$prometheus_name" ]] || { echo "Prometheus custom resource not found" >&2; exit 1; }
prometheus_replicas="$("$KUBECTL" get prometheus "$prometheus_name" -n "$NAMESPACE" \
  -o jsonpath='{.spec.replicas}')"
[[ -z "$prometheus_replicas" || "$prometheus_replicas" == "1" ]] || {
  echo "expected one Prometheus replica, got $prometheus_replicas" >&2
  exit 1
}
retention="$("$KUBECTL" get prometheus "$prometheus_name" -n "$NAMESPACE" \
  -o jsonpath='{.spec.retention}')"
[[ "$retention" == "2d" ]] || { echo "expected 2d retention, got $retention" >&2; exit 1; }
"$KUBECTL" get prometheus "$prometheus_name" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/prometheus.yaml"

if "$KUBECTL" get statefulset -n "$NAMESPACE" \
  -l "app.kubernetes.io/name=alertmanager" -o name | grep -q .; then
  echo "Alertmanager workload exists although it is disabled" >&2
  exit 1
fi

"$KUBECTL" port-forward -n "$NAMESPACE" "svc/$PROM_SERVICE" "$PROM_PORT:9090" \
  >"$ARTIFACT_DIR/port-forward.log" 2>&1 &
port_forward_pid=$!

for _ in $(seq 1 "${PROMETHEUS_CONNECT_TIMEOUT_SECONDS:-30}"); do
  if "$CURL" --fail --silent --show-error --max-time 3 \
    "http://127.0.0.1:$PROM_PORT/-/ready" >"$ARTIFACT_DIR/prometheus-ready.txt" 2>&1; then
    break
  fi
  sleep 1
done
"$CURL" --fail --silent --show-error --max-time 5 \
  "http://127.0.0.1:$PROM_PORT/-/ready" >"$ARTIFACT_DIR/prometheus-ready-final.txt"
"$CURL" --fail --silent --show-error --max-time 10 \
  "http://127.0.0.1:$PROM_PORT/api/v1/targets" >"$ARTIFACT_DIR/targets.json"

query_metric() {
  local name="$1"
  local expression="$2"
  local output="$ARTIFACT_DIR/metric-$name.json"
  local response
  for _ in $(seq 1 "${METRIC_WAIT_ATTEMPTS:-12}"); do
    response="$("$CURL" --fail --silent --show-error --max-time 10 -G \
      --data-urlencode "query=$expression" \
      "http://127.0.0.1:$PROM_PORT/api/v1/query" 2>/dev/null || true)"
    printf '%s\n' "$response" >"$output"
    if grep -Eq '"status"[[:space:]]*:[[:space:]]*"success"' "$output" \
      && grep -Eq '"result"[[:space:]]*:[[:space:]]*\[[^]]' "$output"; then
      return 0
    fi
    sleep "${METRIC_WAIT_SECONDS:-5}"
  done
  echo "metric query returned no samples: $name ($expression)" >&2
  return 1
}

# Node CPU/memory/disk, pod CPU/memory, and Kubernetes object state.
query_metric node_cpu 'count(node_cpu_seconds_total) > 0'
query_metric node_memory 'count(node_memory_MemAvailable_bytes) > 0'
query_metric node_disk 'count(node_filesystem_avail_bytes) > 0'
query_metric pod_cpu 'count(container_cpu_usage_seconds_total) > 0'
query_metric pod_memory 'count(container_memory_working_set_bytes) > 0'
query_metric kubernetes_nodes 'count(kube_node_info) > 0'
query_metric kubernetes_pods 'count(kube_pod_info) > 0'
# CNPG and Higress expose different metric names between minor releases; use
# their stable metric-family prefixes while retaining the raw API evidence.
query_metric postgres 'count({__name__=~"cnpg_.+"}) > 0'
query_metric higress 'count({__name__=~"istio_.+|envoy_.+"}) > 0'

"$KUBECTL" get servicemonitor,podmonitor -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/scrape-monitors.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" -o wide >"$ARTIFACT_DIR/pods.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'Monitoring verification passed: node/pod/Kubernetes/PostgreSQL/Higress metrics available; Prometheus retention=%s; Grafana=ready\n' \
  "$retention"
