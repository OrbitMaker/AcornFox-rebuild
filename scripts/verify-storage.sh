#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE="open-card-system"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/components/storage/artifacts}"
mkdir -p "$ARTIFACT_DIR"

command -v "$KUBECTL" >/dev/null || { echo "kubectl is required" >&2; exit 1; }

if ! "$KUBECTL" -n "$NAMESPACE" get pvc open-local-smoke >/dev/null 2>&1; then
  "$KUBECTL" apply -f "$ROOT_DIR/components/storage/smoke-pvc.yaml" >/dev/null
else
  "$KUBECTL" -n "$NAMESPACE" get deployment open-local-smoke >/dev/null
fi
"$KUBECTL" -n "$NAMESPACE" rollout status deployment/open-local-smoke --timeout=5m
"$KUBECTL" -n "$NAMESPACE" wait --for=jsonpath='{.status.phase}'=Bound pvc/open-local-smoke --timeout=5m
"$KUBECTL" -n "$NAMESPACE" wait --for=condition=Ready pod -l app.kubernetes.io/name=open-local-smoke --timeout=5m

pod="$("$KUBECTL" -n "$NAMESPACE" get pod -l app.kubernetes.io/name=open-local-smoke -o jsonpath='{.items[0].metadata.name}')"
marker="$("$KUBECTL" -n "$NAMESPACE" exec "$pod" -- cat /data/open-card-marker)"
[[ "$marker" == open-local-persistent ]] || { echo "initial PVC marker is invalid" >&2; exit 1; }
"$KUBECTL" -n "$NAMESPACE" get pvc,pod -o wide > "$ARTIFACT_DIR/before-restart.txt"

"$KUBECTL" -n "$NAMESPACE" delete pod "$pod" --wait=true >/dev/null
"$KUBECTL" -n "$NAMESPACE" rollout status deployment/open-local-smoke --timeout=5m
"$KUBECTL" -n "$NAMESPACE" wait --for=condition=Ready pod -l app.kubernetes.io/name=open-local-smoke --timeout=5m
pod="$("$KUBECTL" -n "$NAMESPACE" get pod -l app.kubernetes.io/name=open-local-smoke -o jsonpath='{.items[0].metadata.name}')"
marker="$("$KUBECTL" -n "$NAMESPACE" exec "$pod" -- cat /data/open-card-marker)"
[[ "$marker" == open-local-persistent ]] || { echo "PVC marker was lost after Pod restart" >&2; exit 1; }

requested="$($KUBECTL -n "$NAMESPACE" get pvc open-local-smoke -o jsonpath='{.spec.resources.requests.storage}')"
if [[ "$requested" == 1Gi ]]; then
  "$KUBECTL" -n "$NAMESPACE" patch pvc open-local-smoke --type merge \
    -p '{"spec":{"resources":{"requests":{"storage":"2Gi"}}}}' >/dev/null
fi
capacity=""
deadline=$((SECONDS + 300))
while (( SECONDS < deadline )); do
  capacity="$("$KUBECTL" -n "$NAMESPACE" get pvc open-local-smoke \
    -o jsonpath='{.status.capacity.storage}' 2>/dev/null || true)"
  [[ "$capacity" == 2Gi || "$capacity" == 2048Mi ]] && break
  sleep 3
done
[[ "$capacity" == 2Gi || "$capacity" == 2048Mi ]] || { echo "PVC expansion did not reach 2Gi" >&2; exit 1; }

"$KUBECTL" get nodelocalstorage -o wide > "$ARTIFACT_DIR/nodelocalstorage.txt"
"$KUBECTL" -n "$NAMESPACE" get pvc,pod -o wide > "$ARTIFACT_DIR/after-restart-and-expand.txt"
printf 'storage=PASS\nmarker=%s\nexpanded_capacity=%s\n' "$marker" "$capacity" | tee "$ARTIFACT_DIR/result.txt"
