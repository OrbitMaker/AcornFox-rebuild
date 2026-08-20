#!/usr/bin/env bash
# Install CloudNativePG and the three-instance PostgreSQL PoC.
#
# This script intentionally keeps the operator manifest remote and versioned;
# the generated copy is saved under artifacts/postgres for auditability.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/postgres}"
NAMESPACE="${POSTGRES_NAMESPACE:-poc-data}"
CLUSTER_NAME="${POSTGRES_CLUSTER_NAME:-poc-postgres}"
OPERATOR_NAMESPACE="${CNPG_NAMESPACE:-cnpg-system}"
CNPG_VERSION="${CNPG_VERSION:-1.30.0}"
CNPG_MANIFEST_URL="${CNPG_MANIFEST_URL:-https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/v${CNPG_VERSION}/releases/cnpg-${CNPG_VERSION}.yaml}"
KUBECTL="${KUBECTL:-kubectl}"
CURL="${CURL:-curl}"

mkdir -p "$ARTIFACT_DIR"

capture_state() {
  local exit_code=$?
  set +e
  "$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/cluster-on-failure.yaml" 2>&1
  "$KUBECTL" get pods,pvc -n "$NAMESPACE" -l "cnpg.io/cluster=$CLUSTER_NAME" -o wide >"$ARTIFACT_DIR/workloads-on-failure.txt" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_state ERR

command -v "$KUBECTL" >/dev/null
command -v "$CURL" >/dev/null
"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"

operator_manifest="$ARTIFACT_DIR/cnpg-${CNPG_VERSION}.yaml"
if [[ ! -s "$operator_manifest" ]]; then
  "$CURL" --fail --location --retry 3 --retry-delay 2 --silent --show-error \
    "$CNPG_MANIFEST_URL" -o "$operator_manifest"
fi

# server-side apply is idempotent and handles a pre-existing namespace created
# by a previous run.  A version marker makes the installed operator auditable.
"$KUBECTL" apply --server-side --force-conflicts -f "$operator_manifest" \
  >"$ARTIFACT_DIR/operator-apply.txt"
printf 'cloudnative-pg=%s\nmanifest=%s\n' "$CNPG_VERSION" "$CNPG_MANIFEST_URL" \
  >"$ARTIFACT_DIR/version.txt"

"$KUBECTL" rollout status deployment/cnpg-controller-manager \
  -n "$OPERATOR_NAMESPACE" --timeout="${CNPG_OPERATOR_TIMEOUT:-180s}" \
  >"$ARTIFACT_DIR/operator-rollout.txt"

# Apply the cluster only after the CRD and controller are ready.  The storage
# stage owns the open-local StorageClass; fail fast if it is missing rather
# than silently falling back to a different provisioner.
"$KUBECTL" get storageclass "${POSTGRES_STORAGE_CLASS:-open-local-lvm}" \
  >"$ARTIFACT_DIR/storage-class.txt"
"$KUBECTL" apply -k "$REPO_ROOT/components/postgres" \
  >"$ARTIFACT_DIR/cluster-apply.txt"

"$KUBECTL" wait --for=condition=Ready "cluster/$CLUSTER_NAME" -n "$NAMESPACE" \
  --timeout="${POSTGRES_READY_TIMEOUT:-600s}" \
  >"$ARTIFACT_DIR/cluster-ready.txt"

"$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/cluster.yaml"
"$KUBECTL" get pods,pvc -n "$NAMESPACE" \
  -l "cnpg.io/cluster=$CLUSTER_NAME" -o wide >"$ARTIFACT_DIR/workloads.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'PostgreSQL PoC ready: %s/%s (CloudNativePG %s)\n' \
  "$NAMESPACE" "$CLUSTER_NAME" "$CNPG_VERSION"
