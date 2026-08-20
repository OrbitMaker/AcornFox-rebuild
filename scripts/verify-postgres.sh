#!/usr/bin/env bash
# Evidence-producing checks for the CloudNativePG PostgreSQL PoC.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/postgres-verify}"
NAMESPACE="${POSTGRES_NAMESPACE:-poc-data}"
CLUSTER_NAME="${POSTGRES_CLUSTER_NAME:-poc-postgres}"
STORAGE_CLASS="${POSTGRES_STORAGE_CLASS:-open-local-lvm}"
KUBECTL="${KUBECTL:-kubectl}"

mkdir -p "$ARTIFACT_DIR"

capture_state() {
  local exit_code=$?
  set +e
  "$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/cluster-on-failure.yaml" 2>&1
  "$KUBECTL" get pods,pvc -n "$NAMESPACE" -o wide >"$ARTIFACT_DIR/workloads-on-failure.txt" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  exit "$exit_code"
}
trap capture_state ERR

command -v "$KUBECTL" >/dev/null
"$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/cluster.yaml"
"$KUBECTL" wait --for=condition=Ready "cluster/$CLUSTER_NAME" -n "$NAMESPACE" \
  --timeout="${POSTGRES_READY_TIMEOUT:-120s}" >"$ARTIFACT_DIR/cluster-ready.txt"

instances="$("$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" \
  -o jsonpath='{.spec.instances}')"
[[ "$instances" == "3" ]] || { echo "expected 3 PostgreSQL instances, got $instances" >&2; exit 1; }

pod_rows="$("$KUBECTL" get pods -n "$NAMESPACE" -l "cnpg.io/cluster=$CLUSTER_NAME" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{range .status.containerStatuses[*]}{.ready}{" "}{end}{"\n"}{end}')"
printf '%s\n' "$pod_rows" >"$ARTIFACT_DIR/pods.tsv"
pod_count="$(awk 'NF {n++} END {print n+0}' "$ARTIFACT_DIR/pods.tsv")"
ready_count="$(awk '$2 == "Running" && $3 ~ /true/ {n++} END {print n+0}' "$ARTIFACT_DIR/pods.tsv")"
[[ "$pod_count" == "3" ]] || { echo "expected 3 PostgreSQL pods, got $pod_count" >&2; exit 1; }
[[ "$ready_count" == "3" ]] || { echo "expected 3 ready PostgreSQL pods, got $ready_count" >&2; exit 1; }

pvc_rows="$("$KUBECTL" get pvc -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.storageClassName}{"\t"}{.status.phase}{"\n"}{end}')"
printf '%s\n' "$pvc_rows" >"$ARTIFACT_DIR/pvcs.tsv"
pvc_count="$(awk 'NF {n++} END {print n+0}' "$ARTIFACT_DIR/pvcs.tsv")"
[[ "$pvc_count" -ge 3 ]] || { echo "expected at least 3 PostgreSQL PVCs, got $pvc_count" >&2; exit 1; }
if awk -v expected="$STORAGE_CLASS" 'NF && ($2 != expected || $3 != "Bound") {bad=1} END {exit bad+0}' "$ARTIFACT_DIR/pvcs.tsv"; then
  :
else
  echo "PostgreSQL PVCs are not all Bound on storage class $STORAGE_CLASS" >&2
  exit 1
fi

primary="$("$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" \
  -o jsonpath='{.status.currentPrimary}')"
[[ -n "$primary" ]] || { echo "CloudNativePG has not selected a primary" >&2; exit 1; }
printf '%s\n' "$primary" >"$ARTIFACT_DIR/current-primary.txt"

psql() {
  "$KUBECTL" exec -n "$NAMESPACE" "$primary" -- \
    psql -d appdb -v ON_ERROR_STOP=1 "$@"
}

probe_id="verify-$(date -u +%Y%m%dT%H%M%SZ)"
psql -Atqc "CREATE TABLE IF NOT EXISTS poc_failover_probe (id text PRIMARY KEY, observed_at timestamptz NOT NULL DEFAULT now()); INSERT INTO poc_failover_probe (id) VALUES ('$probe_id') ON CONFLICT (id) DO NOTHING; SELECT id FROM poc_failover_probe WHERE id = '$probe_id';" \
  >"$ARTIFACT_DIR/data-write.txt"
grep -Fqx "$probe_id" "$ARTIFACT_DIR/data-write.txt"
psql -Atqc "SELECT count(*) FROM pg_stat_replication WHERE state = 'streaming';" >"$ARTIFACT_DIR/replica-count.txt"
replica_count="$(tr -d '[:space:]' <"$ARTIFACT_DIR/replica-count.txt")"
[[ "$replica_count" == 2 ]] || {
  echo "expected two streaming replicas, got $replica_count" >&2
  exit 1
}
psql -Atqc "SHOW synchronous_standby_names;" >"$ARTIFACT_DIR/synchronous-standby-names.txt"
grep -Eq '^ANY 1 ' "$ARTIFACT_DIR/synchronous-standby-names.txt" || {
  echo "synchronous replication ANY 1 is not active" >&2
  exit 1
}
psql -Atqc "SELECT count(*) FROM pg_stat_replication WHERE sync_state IN ('sync', 'quorum');" \
  >"$ARTIFACT_DIR/synchronous-replica-count.txt"
synchronous_count="$(tr -d '[:space:]' <"$ARTIFACT_DIR/synchronous-replica-count.txt")"
[[ "$synchronous_count" =~ ^[0-9]+$ && "$synchronous_count" -ge 1 ]] || {
  echo "no synchronous replica is acknowledged by the primary" >&2
  exit 1
}

"$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/cluster-final.yaml"
"$KUBECTL" get pods,pvc -n "$NAMESPACE" -o wide \
  >"$ARTIFACT_DIR/workloads-final.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'PostgreSQL verification passed: 3 ready instances, %s PVCs on %s, primary %s, marker %s\n' \
  "$pvc_count" "$STORAGE_CLASS" "$primary" "$probe_id"
