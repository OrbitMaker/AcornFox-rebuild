#!/usr/bin/env bash
# Delete one demo Pod while continuously probing Higress, then prove exact
# replica/endpoint recovery with no failed requests.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/drills/web-pod-recovery}"
NAMESPACE="${APP_NAMESPACE:-open-card-demo}"
DEPLOYMENT="${APP_DEPLOYMENT:-open-card-demo}"
SERVICE="${APP_SERVICE:-open-card-demo}"
SELECTOR="${APP_SELECTOR:-app.kubernetes.io/name=open-card-demo}"
KUBECTL="${KUBECTL:-kubectl}"
CURL="${CURL:-curl}"
HIGRESS_HOST="${HIGRESS_HOST:-open-card.local}"
HIGRESS_HTTP_NODEPORT="${HIGRESS_HTTP_NODEPORT:-30080}"
traffic_pid=""

mkdir -p "$ARTIFACT_DIR"

capture_failure() {
  local exit_code=$?
  set +e
  if [[ -n $traffic_pid ]]; then kill "$traffic_pid" 2>/dev/null || true; fi
  "$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/deployment-on-failure.yaml" 2>&1
  "$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_failure ERR

command -v "$KUBECTL" >/dev/null
command -v "$CURL" >/dev/null
"$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/deployment-before.yaml"
desired="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')"
[[ $desired =~ ^[1-9][0-9]*$ && $desired -le 3 ]] || { echo "invalid PoC replica count: $desired" >&2; exit 1; }

victim="$("$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o jsonpath='{.items[0].metadata.name}')"
[[ -n $victim ]] || { echo "no demo Pod matched $SELECTOR" >&2; exit 1; }
printf '%s\n' "$victim" >"$ARTIFACT_DIR/victim.txt"
"$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide >"$ARTIFACT_DIR/pods-before.txt"

gateway_address="${HIGRESS_GATEWAY_ADDRESS:-$("$KUBECTL" get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')}"
health_url="${APP_HEALTH_URL:-http://${gateway_address}:${HIGRESS_HTTP_NODEPORT}/}"
start_epoch="$(date +%s)"
: >"$ARTIFACT_DIR/traffic-status.tsv"
(
  for _ in $(seq 1 "${DEMO_DRILL_REQUESTS:-80}"); do
    code="$("$CURL" --silent --show-error --connect-timeout 2 --max-time 5 \
      -H "Host: $HIGRESS_HOST" -o /dev/null -w '%{http_code}' "$health_url" 2>/dev/null || true)"
    printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$code" >>"$ARTIFACT_DIR/traffic-status.tsv"
    sleep "${DEMO_DRILL_REQUEST_INTERVAL:-0.25}"
  done
) &
traffic_pid=$!

"$KUBECTL" delete pod "$victim" -n "$NAMESPACE" --wait=false >"$ARTIFACT_DIR/delete.txt"
deadline=$(( $(date +%s) + ${APP_RECOVERY_TIMEOUT_SECONDS:-180} ))
ready_now=0
pod_total=0
while (( $(date +%s) < deadline )); do
  ready_now="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  pod_total="$("$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" --no-headers 2>/dev/null | awk 'NF {count++} END {print count + 0}')"
  if [[ $ready_now == "$desired" && $pod_total == "$desired" ]] \
    && ! "$KUBECTL" get pod "$victim" -n "$NAMESPACE" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
[[ $ready_now == "$desired" && $pod_total == "$desired" ]] || {
  echo "deployment did not recover exactly $desired ready Pods" >&2
  exit 1
}
end_epoch="$(date +%s)"
printf '%s\n' "$((end_epoch - start_epoch))" >"$ARTIFACT_DIR/recovery-seconds.txt"

wait "$traffic_pid"
traffic_pid=""
bad_requests="$(awk '$2 != "200" {count++} END {print count + 0}' "$ARTIFACT_DIR/traffic-status.tsv")"
[[ $bad_requests -eq 0 ]] || { echo "gateway returned $bad_requests non-200 responses" >&2; exit 1; }

new_pods="$("$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
printf '%s\n' "$new_pods" >"$ARTIFACT_DIR/pods-after.txt"
new_count="$(awk 'NF {count++} END {print count + 0}' "$ARTIFACT_DIR/pods-after.txt")"
[[ $new_count -eq "$desired" ]] || { echo "recovered Pod count is $new_count/$desired" >&2; exit 1; }
if printf '%s\n' "$new_pods" | grep -Fxq "$victim"; then
  echo "deleted Pod still exists after recovery: $victim" >&2
  exit 1
fi
endpoint_count="$("$KUBECTL" get endpoints "$SERVICE" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' | awk '{print NF}')"
[[ $endpoint_count -eq "$desired" ]] || { echo "endpoint count is $endpoint_count/$desired" >&2; exit 1; }

"$CURL" --fail --silent --show-error --max-time 10 -H "Host: $HIGRESS_HOST" "$health_url" >"$ARTIFACT_DIR/health-response.txt"
"$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/deployment-after.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide >"$ARTIFACT_DIR/pods-after-wide.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events.txt"

printf 'Web Pod recovery passed: deleted %s; recovered %s replicas in %ss; non-200=%s\n' \
  "$victim" "$new_count" "$((end_epoch - start_epoch))" "$bad_requests"
