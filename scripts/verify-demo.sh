#!/usr/bin/env bash
# Verify the demo Deployment, Service endpoints, and Pod-name response.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/demo-verify}"
KUBECTL="${KUBECTL:-kubectl}"
CURL="${CURL:-curl}"
NAMESPACE="${APP_NAMESPACE:-open-card-demo}"
DEPLOYMENT="${APP_DEPLOYMENT:-open-card-demo}"
SERVICE="${APP_SERVICE:-open-card-demo}"
SELECTOR="${APP_SELECTOR:-app.kubernetes.io/name=open-card-demo}"
LOCAL_PORT="${DEMO_LOCAL_PORT:-18080}"

mkdir -p "$ARTIFACT_DIR"
port_forward_pid=""

cleanup() {
  if [[ -n $port_forward_pid ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
    port_forward_pid=""
  fi
}
capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml \
    >"$ARTIFACT_DIR/deployment-on-failure.yaml" 2>&1
  "$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide \
    >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get service,endpoints -n "$NAMESPACE" -o yaml \
    >"$ARTIFACT_DIR/services-on-failure.yaml" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
    >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  cleanup
  exit "$exit_code"
}
trap capture_failure ERR
trap cleanup EXIT

for command_name in "$KUBECTL" "$CURL"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command_name" >&2
    exit 1
  }
done

"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"
"$KUBECTL" wait --for=condition=Available deployment/"$DEPLOYMENT" \
  -n "$NAMESPACE" --timeout="${DEMO_READY_TIMEOUT:-180s}" \
  >"$ARTIFACT_DIR/deployment-ready.txt"
"$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/deployment.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide \
  >"$ARTIFACT_DIR/pods.txt"
"$KUBECTL" get service,endpoints -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/services.yaml"

desired="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.replicas}')"
ready="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.status.readyReplicas}')"
available="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.status.availableReplicas}')"
updated="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.status.updatedReplicas}')"
[[ $desired == 3 && $ready == 3 && $available == 3 && $updated == 3 ]] || {
  printf 'demo readiness mismatch: desired=%s ready=%s available=%s updated=%s\n' \
    "$desired" "$ready" "$available" "$updated" >&2
  exit 1
}

request_cpu="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.spec.containers[0].resources.requests.cpu}')"
request_memory="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.spec.containers[0].resources.requests.memory}')"
limit_cpu="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.spec.containers[0].resources.limits.cpu}')"
limit_memory="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}')"
for resource_value in "$request_cpu" "$request_memory" "$limit_cpu" "$limit_memory"; do
  [[ -n $resource_value ]] || { printf 'demo container resource is missing\n' >&2; exit 1; }
done

service_type="$("$KUBECTL" get service "$SERVICE" -n "$NAMESPACE" \
  -o jsonpath='{.spec.type}')"
service_port="$("$KUBECTL" get service "$SERVICE" -n "$NAMESPACE" \
  -o jsonpath='{.spec.ports[0].port}')"
[[ $service_type == ClusterIP && $service_port == 80 ]] || {
  printf 'demo Service mismatch: type=%s port=%s\n' "$service_type" "$service_port" >&2
  exit 1
}

pod_names="$("$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
pod_count="$(printf '%s\n' "$pod_names" | awk 'NF {count++} END {print count + 0}')"
[[ $pod_count == 3 ]] || {
  printf 'demo Pod count mismatch: %s (expected 3)\n' "$pod_count" >&2
  exit 1
}
printf '%s\n' "$pod_names" >"$ARTIFACT_DIR/pod-names.txt"

endpoint_ips="$("$KUBECTL" get endpoints "$SERVICE" -n "$NAMESPACE" \
  -o jsonpath='{.subsets[*].addresses[*].ip}')"
endpoint_count="$(printf '%s\n' "$endpoint_ips" | awk '{for (i = 1; i <= NF; i++) count++} END {print count + 0}')"
[[ $endpoint_count == 3 ]] || {
  printf 'demo endpoint count mismatch: %s (expected 3)\n' "$endpoint_count" >&2
  exit 1
}
printf '%s\n' "$endpoint_ips" >"$ARTIFACT_DIR/endpoint-ips.txt"

"$KUBECTL" port-forward -n "$NAMESPACE" "svc/$SERVICE" "$LOCAL_PORT:80" \
  >"$ARTIFACT_DIR/port-forward.log" 2>&1 &
port_forward_pid=$!

port_forward_ready=0
for _ in $(seq 1 "${DEMO_PORT_FORWARD_ATTEMPTS:-30}"); do
  if "$CURL" --fail --silent --show-error --max-time 3 \
    "http://127.0.0.1:$LOCAL_PORT/" >"$ARTIFACT_DIR/http-root-body.txt" 2>/dev/null; then
    port_forward_ready=1
    break
  fi
  if ! kill -0 "$port_forward_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
[[ $port_forward_ready == 1 ]] || {
  printf 'demo Service port-forward did not become ready\n' >&2
  exit 1
}

for path in / /api; do
  label=root
  [[ $path == /api ]] && label=api
  status="$("$CURL" --silent --show-error --connect-timeout 5 --max-time 15 \
    -o "$ARTIFACT_DIR/http-${label}-body.txt" \
    -w '%{http_code}' "http://127.0.0.1:$LOCAL_PORT$path")"
  printf '%s\n' "$status" >"$ARTIFACT_DIR/http-${label}-status.txt"
  [[ $status == 200 ]] || {
    printf 'demo Service %s returned HTTP %s\n' "$path" "$status" >&2
    exit 1
  }
  grep -Eq 'pod=' "$ARTIFACT_DIR/http-${label}-body.txt" || {
    printf 'demo Service %s response does not contain a Pod name\n' "$path" >&2
    exit 1
  }
done

if [[ -n "${APP_HEALTH_URL:-}" ]]; then
  "$CURL" --fail --silent --show-error --max-time 15 "$APP_HEALTH_URL" \
    >"$ARTIFACT_DIR/external-health-body.txt"
fi

"$KUBECTL" get deployment,pods,svc,endpoints -n "$NAMESPACE" -o wide \
  >"$ARTIFACT_DIR/workloads.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'Demo verification passed: 3/3 Pods ready; requests=%s CPU/%s memory; limits=%s CPU/%s memory; response includes pod name\n' \
  "$request_cpu" "$request_memory" "$limit_cpu" "$limit_memory" \
  | tee "$ARTIFACT_DIR/summary.txt"
