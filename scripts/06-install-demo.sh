#!/usr/bin/env bash
# Deploy the three-replica, low-resource demo used by gateway and recovery tests.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/demo}"
KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE="${APP_NAMESPACE:-open-card-demo}"
DEPLOYMENT="${APP_DEPLOYMENT:-open-card-demo}"
SERVICE="${APP_SERVICE:-open-card-demo}"
MANIFEST="$REPO_ROOT/components/demo/demo-web.yaml"
INGRESS_FILE="$REPO_ROOT/components/higress/ingress.yaml"
HIGRESS_HOST="${HIGRESS_HOST:-open-card.local}"

mkdir -p "$ARTIFACT_DIR"
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT

capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml \
    >"$ARTIFACT_DIR/deployment-on-failure.yaml" 2>&1
  "$KUBECTL" get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$DEPLOYMENT" -o wide \
    >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get service,endpoints -n "$NAMESPACE" -o yaml \
    >"$ARTIFACT_DIR/services-on-failure.yaml" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
    >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_failure ERR

for command_name in "$KUBECTL" sed mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command_name" >&2
    exit 1
  }
done

"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"
"$KUBECTL" apply -f "$MANIFEST" >"$ARTIFACT_DIR/demo-apply.txt"
rendered_ingress="$tmpdir/ingress.yaml"
sed "s|open-card.local|$HIGRESS_HOST|g" "$INGRESS_FILE" >"$rendered_ingress"
"$KUBECTL" apply -f "$rendered_ingress" >"$ARTIFACT_DIR/ingress-apply.txt"
"$KUBECTL" rollout status deployment/"$DEPLOYMENT" -n "$NAMESPACE" \
  --timeout="${APP_ROLLOUT_TIMEOUT:-300s}" >"$ARTIFACT_DIR/rollout.txt"
"$KUBECTL" wait --for=condition=Available deployment/"$DEPLOYMENT" \
  -n "$NAMESPACE" --timeout="${APP_READY_TIMEOUT:-180s}" \
  >"$ARTIFACT_DIR/ready.txt"

"$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/deployment.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" \
  -l "app.kubernetes.io/name=$DEPLOYMENT" -o wide >"$ARTIFACT_DIR/pods.txt"
"$KUBECTL" get service,endpoints -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/services.yaml"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

replicas="$("$KUBECTL" get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.replicas}')"
[[ $replicas == 3 ]] || {
  printf 'demo replica count mismatch: %s (expected 3)\n' "$replicas" >&2
  exit 1
}

printf 'Demo web ready: deployment=%s replicas=3; response includes POD_NAME; ingress reapplied\n' \
  "$DEPLOYMENT"
