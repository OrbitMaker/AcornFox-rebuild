#!/usr/bin/env bash
# Verify Higress readiness, NodePorts, Ingress Host/path routing, and TLS.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/higress-verify}"
KUBECTL="${KUBECTL:-kubectl}"
CURL="${CURL:-curl}"
NAMESPACE="${HIGRESS_NAMESPACE:-higress-system}"
DEMO_NAMESPACE="${APP_NAMESPACE:-open-card-demo}"
GATEWAY_SERVICE="${HIGRESS_GATEWAY_SERVICE:-higress-gateway}"
HOSTNAME="${HIGRESS_HOST:-open-card.local}"
HTTP_NODEPORT="${HIGRESS_HTTP_NODEPORT:-30080}"
HTTPS_NODEPORT="${HIGRESS_HTTPS_NODEPORT:-30443}"
BACKEND_MODE="${HIGRESS_BACKEND_MODE:-auto}"
GATEWAY_ADDRESS="${HIGRESS_GATEWAY_ADDRESS:-${HIGRESS_GATEWAY_IP:-}}"

mkdir -p "$ARTIFACT_DIR"

capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get deployment,pods,svc -n "$NAMESPACE" -o wide \
    >"$ARTIFACT_DIR/workloads-on-failure.txt" 2>&1
  "$KUBECTL" get ingress -n "$DEMO_NAMESPACE" -o yaml \
    >"$ARTIFACT_DIR/ingress-on-failure.yaml" 2>&1
  "$KUBECTL" get endpoints -n "$DEMO_NAMESPACE" \
    >"$ARTIFACT_DIR/endpoints-on-failure.txt" 2>&1
  "$KUBECTL" get events -A --sort-by=.lastTimestamp \
    >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_failure ERR

for command_name in "$KUBECTL" "$CURL"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command_name" >&2
    exit 1
  }
done
case "$BACKEND_MODE" in
  auto|require|skip) ;;
  *) printf 'HIGRESS_BACKEND_MODE must be auto, require, or skip\n' >&2; exit 1 ;;
esac

"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"
"$KUBECTL" get deployment higress-controller -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/controller.yaml"
"$KUBECTL" get deployment higress-gateway -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/gateway.yaml"
"$KUBECTL" get service "$GATEWAY_SERVICE" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/gateway-service.yaml"
"$KUBECTL" get ingressclass higress -o yaml >"$ARTIFACT_DIR/ingressclass.yaml"
"$KUBECTL" get ingress open-card-demo -n "$DEMO_NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/ingress.yaml"
"$KUBECTL" wait --for=condition=Available deployment/higress-controller \
  -n "$NAMESPACE" --timeout="${HIGRESS_ROLLOUT_TIMEOUT:-300s}" \
  >"$ARTIFACT_DIR/controller-ready.txt"
"$KUBECTL" wait --for=condition=Available deployment/higress-gateway \
  -n "$NAMESPACE" --timeout="${HIGRESS_ROLLOUT_TIMEOUT:-300s}" \
  >"$ARTIFACT_DIR/gateway-ready.txt"

controller_available="$("$KUBECTL" get deployment higress-controller -n "$NAMESPACE" \
  -o jsonpath='{.status.availableReplicas}')"
gateway_replicas="$("$KUBECTL" get deployment higress-gateway -n "$NAMESPACE" \
  -o jsonpath='{.spec.replicas}')"
gateway_available="$("$KUBECTL" get deployment higress-gateway -n "$NAMESPACE" \
  -o jsonpath='{.status.availableReplicas}')"
[[ $controller_available == 1 ]] || {
  printf 'Higress controller is not available: %s\n' "$controller_available" >&2
  exit 1
}
[[ $gateway_replicas == 1 && $gateway_available == 1 ]] || {
  printf 'Higress gateway replica/readiness mismatch: replicas=%s available=%s\n' \
    "$gateway_replicas" "$gateway_available" >&2
  exit 1
}

service_type="$("$KUBECTL" get service "$GATEWAY_SERVICE" -n "$NAMESPACE" \
  -o jsonpath='{.spec.type}')"
service_http_nodeport="$("$KUBECTL" get service "$GATEWAY_SERVICE" -n "$NAMESPACE" \
  -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')"
service_https_nodeport="$("$KUBECTL" get service "$GATEWAY_SERVICE" -n "$NAMESPACE" \
  -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')"
[[ $service_type == NodePort ]] || {
  printf 'gateway Service is not NodePort: %s\n' "$service_type" >&2
  exit 1
}
[[ $service_http_nodeport == "$HTTP_NODEPORT" ]] || {
  printf 'HTTP NodePort mismatch: %s (expected %s)\n' "$service_http_nodeport" "$HTTP_NODEPORT" >&2
  exit 1
}
[[ $service_https_nodeport == "$HTTPS_NODEPORT" ]] || {
  printf 'HTTPS NodePort mismatch: %s (expected %s)\n' "$service_https_nodeport" "$HTTPS_NODEPORT" >&2
  exit 1
}

ingress_class="$("$KUBECTL" get ingress open-card-demo -n "$DEMO_NAMESPACE" \
  -o jsonpath='{.spec.ingressClassName}')"
ingress_host="$("$KUBECTL" get ingress open-card-demo -n "$DEMO_NAMESPACE" \
  -o jsonpath='{.spec.rules[0].host}')"
tls_secret="$("$KUBECTL" get ingress open-card-demo -n "$DEMO_NAMESPACE" \
  -o jsonpath='{.spec.tls[0].secretName}')"
[[ $ingress_class == higress ]] || {
  printf 'Ingress class mismatch: %s\n' "$ingress_class" >&2
  exit 1
}
[[ $ingress_host == "$HOSTNAME" ]] || {
  printf 'Ingress Host mismatch: %s\n' "$ingress_host" >&2
  exit 1
}
[[ $tls_secret == open-card-demo-tls ]] || {
  printf 'Ingress TLS Secret mismatch: %s\n' "$tls_secret" >&2
  exit 1
}

endpoint_ips="$("$KUBECTL" get endpoints open-card-demo -n "$DEMO_NAMESPACE" \
  -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
endpoint_count="$(printf '%s\n' "$endpoint_ips" | awk '{for (i = 1; i <= NF; i++) count++} END {print count + 0}')"
printf '%s\n' "$endpoint_ips" >"$ARTIFACT_DIR/backend-endpoints.txt"
route_state=pending

if [[ $BACKEND_MODE == require && $endpoint_count -lt 1 ]]; then
  printf 'Higress backend is required but open-card-demo has no ready endpoints\n' >&2
  exit 1
fi

if [[ $BACKEND_MODE != skip && $endpoint_count -gt 0 ]]; then
  if [[ -z $GATEWAY_ADDRESS ]]; then
    GATEWAY_ADDRESS="$("$KUBECTL" get nodes \
      -o jsonpath='{range .items[*].status.addresses[?(@.type=="InternalIP")]}{.address}{"\n"}{end}' \
      | awk 'NF {print; exit}')"
  fi
  [[ -n $GATEWAY_ADDRESS ]] || {
    printf 'set HIGRESS_GATEWAY_ADDRESS to test NodePorts from this host\n' >&2
    exit 1
  }

  if [[ $GATEWAY_ADDRESS == *:* ]]; then
    URL_HOST="[$GATEWAY_ADDRESS]"
  else
    URL_HOST="$GATEWAY_ADDRESS"
  fi

  request() {
    local protocol=$1
    local path=$2
    local port=$3
    local label=$4
    local body="$ARTIFACT_DIR/${label}-body.txt"
    local headers="$ARTIFACT_DIR/${label}-headers.txt"
    local url status

    if [[ $protocol == https ]]; then
      url="https://${HOSTNAME}:${port}${path}"
    else
      url="http://${URL_HOST}:${port}${path}"
    fi

    for _ in $(seq 1 "${HIGRESS_REQUEST_ATTEMPTS:-15}"); do
      if [[ $protocol == https ]]; then
        status="$("$CURL" --silent --show-error --connect-timeout "${HIGRESS_CONNECT_TIMEOUT:-5}" \
          --max-time "${HIGRESS_REQUEST_TIMEOUT:-15}" --insecure \
          --resolve "$HOSTNAME:$port:$GATEWAY_ADDRESS" -H "Host: $HOSTNAME" \
          -D "$headers" -o "$body" -w '%{http_code}' "$url" 2>/dev/null || true)"
      else
        status="$("$CURL" --silent --show-error --connect-timeout "${HIGRESS_CONNECT_TIMEOUT:-5}" \
          --max-time "${HIGRESS_REQUEST_TIMEOUT:-15}" -H "Host: $HOSTNAME" \
          -D "$headers" -o "$body" -w '%{http_code}' "$url" 2>/dev/null || true)"
      fi
      printf '%s\n' "$status" >"$ARTIFACT_DIR/${label}-status.txt"
      if [[ $status == 200 ]] && grep -Eq 'pod=' "$body"; then
        return 0
      fi
      sleep 2
    done
    printf '%s %s returned HTTP %s or no Pod response\n' "$protocol" "$path" "$status" >&2
    return 1
  }

  request http / "$HTTP_NODEPORT" http-root
  request http /api "$HTTP_NODEPORT" http-api
  request https / "$HTTPS_NODEPORT" https-root
  request https /api "$HTTPS_NODEPORT" https-api

  : >"$ARTIFACT_DIR/load-balancing-pods.txt"
  for _ in $(seq 1 30); do
    "$CURL" --silent --show-error --connect-timeout 5 --max-time 15 \
      -H "Host: $HOSTNAME" "http://${URL_HOST}:${HTTP_NODEPORT}/" \
      | sed -n 's/.*pod=\([^<]*\).*/\1/p' >>"$ARTIFACT_DIR/load-balancing-pods.txt"
  done
  sort -u "$ARTIFACT_DIR/load-balancing-pods.txt" \
    >"$ARTIFACT_DIR/load-balancing-unique-pods.txt"
  unique_pods="$(awk 'NF {count++} END {print count + 0}' "$ARTIFACT_DIR/load-balancing-unique-pods.txt")"
  [[ $unique_pods -eq 3 ]] || {
    printf 'Higress load-balancing reached %s unique Pods, expected 3\n' "$unique_pods" >&2
    return 1
  }
  printf 'ready\n' >"$ARTIFACT_DIR/backend-route-state.txt"
  route_state=ready
else
  printf 'pending\n' >"$ARTIFACT_DIR/backend-route-state.txt"
fi

"$KUBECTL" get deployment,pods,svc -n "$NAMESPACE" -o wide \
  >"$ARTIFACT_DIR/workloads.txt"
"$KUBECTL" get ingress,service,endpoints -n "$DEMO_NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/routing-resources.yaml"
"$KUBECTL" get events -A --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events.txt"

if [[ $route_state == ready ]]; then
  printf 'Higress verification passed: gateway/controller ready; HTTP+HTTPS Host/path routes returned 200; endpoints=%s\n' \
    "$endpoint_count" | tee "$ARTIFACT_DIR/summary.txt"
elif [[ $BACKEND_MODE == skip ]]; then
  printf 'Higress verification passed: gateway/controller ready; backend HTTP/HTTPS route checks skipped; endpoints=%s\n' \
    "$endpoint_count" | tee "$ARTIFACT_DIR/summary.txt"
else
  printf 'Higress verification passed: gateway/controller ready; backend route deferred until demo endpoints exist\n' \
    | tee "$ARTIFACT_DIR/summary.txt"
fi
