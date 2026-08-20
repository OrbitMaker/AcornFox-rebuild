#!/usr/bin/env bash
# Install the pinned OpenKruise chart with the k3s containerd socket mounted.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/openkruise}"
NAMESPACE="${OPENKRUISE_NAMESPACE:-kruise-system}"
KUBECTL="${KUBECTL:-kubectl}"
HELM="${HELM:-helm}"
REPO_NAME="${OPENKRUISE_HELM_REPO_NAME:-openkruise}"
REPO_URL="${OPENKRUISE_HELM_REPO_URL:-https://openkruise.github.io/charts/}"
VERSION="${OPENKRUISE_VERSION:-1.9.1}"
SOCKET_LOCATION="${KRUISE_SOCKET_LOCATION:-/run/k3s}"
VALUES_FILE="$REPO_ROOT/components/openkruise/values.yaml"

mkdir -p "$ARTIFACT_DIR"

capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get crd/clonesets.apps.kruise.io -o yaml \
    >"$ARTIFACT_DIR/cloneset-crd-on-failure.yaml" 2>&1
  "$KUBECTL" get deployment,daemonset,pods -n "$NAMESPACE" -o wide \
    >"$ARTIFACT_DIR/workloads-on-failure.txt" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
    >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_failure ERR

for command_name in "$KUBECTL" "$HELM"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command_name" >&2
    exit 1
  }
done

"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"
"$HELM" repo add "$REPO_NAME" "$REPO_URL" --force-update \
  >"$ARTIFACT_DIR/helm-repo-add.txt"
"$HELM" repo update "$REPO_NAME" >"$ARTIFACT_DIR/helm-repo-update.txt"
printf 'chart=kruise\nversion=%s\nrepo=%s\nsocketLocation=%s\n' \
  "$VERSION" "$REPO_URL" "$SOCKET_LOCATION" >"$ARTIFACT_DIR/version.txt"

"$HELM" upgrade --install kruise "$REPO_NAME/kruise" \
  --version "$VERSION" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --reset-values \
  --values "$VALUES_FILE" \
  --set-string "installation.namespace=$NAMESPACE" \
  --set-string "daemon.socketLocation=$SOCKET_LOCATION" \
  --wait --timeout="${OPENKRUISE_HELM_TIMEOUT:-600s}" \
  >"$ARTIFACT_DIR/helm-upgrade.txt"

"$KUBECTL" rollout status deployment/kruise-controller-manager \
  -n "$NAMESPACE" --timeout="${OPENKRUISE_ROLLOUT_TIMEOUT:-300s}" \
  >"$ARTIFACT_DIR/controller-rollout.txt"
"$KUBECTL" rollout status daemonset/kruise-daemon \
  -n "$NAMESPACE" --timeout="${OPENKRUISE_ROLLOUT_TIMEOUT:-300s}" \
  >"$ARTIFACT_DIR/daemon-rollout.txt"
"$KUBECTL" wait --for=condition=Established \
  crd/clonesets.apps.kruise.io --timeout="${OPENKRUISE_CRD_TIMEOUT:-180s}" \
  >"$ARTIFACT_DIR/cloneset-crd-ready.txt"

"$KUBECTL" get deployment,daemonset,pods -n "$NAMESPACE" -o wide \
  >"$ARTIFACT_DIR/workloads.txt"
"$KUBECTL" get crd/clonesets.apps.kruise.io -o yaml \
  >"$ARTIFACT_DIR/cloneset-crd.yaml"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'OpenKruise %s ready; controller=1; daemon socket=%s\n' \
  "$VERSION" "$SOCKET_LOCATION"
