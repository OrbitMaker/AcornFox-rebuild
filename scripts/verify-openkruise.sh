#!/usr/bin/env bash
# Prove that OpenKruise can perform an in-place CloneSet image update.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/openkruise-verify}"
KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE="${OPENKRUISE_SMOKE_NAMESPACE:-open-card-kruise}"
CLONESET="${OPENKRUISE_SMOKE_NAME:-kruise-smoke}"
SELECTOR="${OPENKRUISE_SMOKE_SELECTOR:-app.kubernetes.io/name=kruise-smoke}"
CONTAINER_NAME="${OPENKRUISE_SMOKE_CONTAINER:-nginx}"
INITIAL_IMAGE="${OPENKRUISE_SMOKE_INITIAL_IMAGE:-nginx:1.27-alpine}"
TARGET_IMAGE="${OPENKRUISE_SMOKE_TARGET_IMAGE:-nginx:1.27.1-alpine}"
MANIFEST="$REPO_ROOT/components/openkruise/cloneset-smoke.yaml"

mkdir -p "$ARTIFACT_DIR"

capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" -o yaml \
    >"$ARTIFACT_DIR/cloneset-on-failure.yaml" 2>&1
  "$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide \
    >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
    >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_failure ERR

command -v "$KUBECTL" >/dev/null 2>&1 || {
  printf '%s is required\n' "$KUBECTL" >&2
  exit 1
}

"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"
"$KUBECTL" wait --for=condition=Established \
  crd/clonesets.apps.kruise.io --timeout="${OPENKRUISE_CRD_TIMEOUT:-180s}" \
  >"$ARTIFACT_DIR/crd-ready.txt"
"$KUBECTL" apply -f "$MANIFEST" >"$ARTIFACT_DIR/smoke-apply.txt"

wait_for_clone() {
  local expected_image="${1:-}"
  local desired ready updated updated_ready pod current_image
  for _ in $(seq 1 "${OPENKRUISE_SMOKE_WAIT_ATTEMPTS:-120}"); do
    desired="$("$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" \
      -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
    ready="$("$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" \
      -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
    updated="$("$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" \
      -o jsonpath='{.status.updatedReplicas}' 2>/dev/null || true)"
    updated_ready="$("$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" \
      -o jsonpath='{.status.updatedReadyReplicas}' 2>/dev/null || true)"
    pod="$("$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    current_image=""
    if [[ -n $pod ]]; then
      current_image="$(pod_image "$pod" 2>/dev/null || true)"
    fi
    if [[ $desired == 1 && $ready == 1 && $updated == 1 && $updated_ready == 1 && -n $pod \
      && ( -z $expected_image || $current_image == "$expected_image" ) ]]; then
      printf '%s\n' "$pod"
      return 0
    fi
    sleep 2
  done
  printf 'CloneSet did not become ready: desired=%s ready=%s updated=%s updatedReady=%s\n' \
    "$desired" "$ready" "$updated" "$updated_ready" >&2
  return 1
}

pod_ready() {
  local pod=$1
  "$KUBECTL" wait --for=condition=Ready "pod/$pod" -n "$NAMESPACE" \
    --timeout="${OPENKRUISE_POD_TIMEOUT:-180s}" \
    >>"$ARTIFACT_DIR/pod-ready.txt"
}

patch_image() {
  local image=$1
  # CloneSet is a CRD, so use a JSON patch (strategic merge is unsupported for
  # CRDs). Replacing only the image preserves probes and resource limits.
  "$KUBECTL" patch cloneset "$CLONESET" -n "$NAMESPACE" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/image\",\"value\":\"$image\"}]" \
    >>"$ARTIFACT_DIR/image-patches.txt"
}

pod_image() {
  "$KUBECTL" get pod "$1" -n "$NAMESPACE" \
    -o jsonpath="{.spec.containers[?(@.name=='$CONTAINER_NAME')].image}"
}

pod_uid() {
  "$KUBECTL" get pod "$1" -n "$NAMESPACE" -o jsonpath='{.metadata.uid}'
}

pod_before="$(wait_for_clone "$INITIAL_IMAGE")"
pod_ready "$pod_before"
before_uid="$(pod_uid "$pod_before")"
before_image="$(pod_image "$pod_before")"
[[ $before_image == "$INITIAL_IMAGE" ]] || {
  printf 'unexpected initial image: %s (expected %s)\n' "$before_image" "$INITIAL_IMAGE" >&2
  exit 1
}

printf '%s\n' "$pod_before" >"$ARTIFACT_DIR/pod-before.txt"
printf '%s\n' "$before_uid" >"$ARTIFACT_DIR/pod-uid-before.txt"
printf '%s\n' "$before_image" >"$ARTIFACT_DIR/image-before.txt"
"$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/cloneset-before.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide \
  >"$ARTIFACT_DIR/pods-before.txt"

patch_image "$TARGET_IMAGE"
pod_after="$(wait_for_clone "$TARGET_IMAGE")"
pod_ready "$pod_after"
after_uid="$(pod_uid "$pod_after")"
after_image="$(pod_image "$pod_after")"

[[ $pod_after == "$pod_before" ]] || {
  printf 'CloneSet update replaced the Pod name: %s -> %s\n' "$pod_before" "$pod_after" >&2
  exit 1
}
[[ $after_uid == "$before_uid" ]] || {
  printf 'CloneSet update replaced the Pod UID: %s -> %s\n' "$before_uid" "$after_uid" >&2
  exit 1
}
[[ $after_image == "$TARGET_IMAGE" ]] || {
  printf 'CloneSet target image was not applied: %s (expected %s)\n' \
    "$after_image" "$TARGET_IMAGE" >&2
  exit 1
}

printf '%s\n' "$pod_after" >"$ARTIFACT_DIR/pod-after.txt"
printf '%s\n' "$after_uid" >"$ARTIFACT_DIR/pod-uid-after.txt"
printf '%s\n' "$after_image" >"$ARTIFACT_DIR/image-after.txt"
"$KUBECTL" get cloneset "$CLONESET" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/cloneset-after.yaml"
"$KUBECTL" get pods -n "$NAMESPACE" -l "$SELECTOR" -o wide \
  >"$ARTIFACT_DIR/pods-after.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'OpenKruise verification passed: CloneSet %s updated %s -> %s in place; Pod=%s UID=%s\n' \
  "$CLONESET" "$INITIAL_IMAGE" "$TARGET_IMAGE" "$pod_after" "$after_uid" \
  | tee "$ARTIFACT_DIR/summary.txt"
