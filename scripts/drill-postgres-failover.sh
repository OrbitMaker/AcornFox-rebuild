#!/usr/bin/env bash
# Delete the current CNPG primary and prove automatic failover, data
# persistence, and a reconnecting client through the rw Service.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/drills/postgres-failover}"
NAMESPACE="${POSTGRES_NAMESPACE:-poc-data}"
CLUSTER_NAME="${POSTGRES_CLUSTER_NAME:-poc-postgres}"
PROBE_NAME="${POSTGRES_RECONNECT_PROBE_NAME:-poc-pg-reconnect-probe}"
KUBECTL="${KUBECTL:-kubectl}"

mkdir -p "$ARTIFACT_DIR"

cleanup() {
  set +e
  "$KUBECTL" logs -n "$NAMESPACE" "$PROBE_NAME" --all-containers=true \
    >"$ARTIFACT_DIR/reconnect-probe.log" 2>&1
  "$KUBECTL" delete pod "$PROBE_NAME" -n "$NAMESPACE" --ignore-not-found --wait=false \
    >"$ARTIFACT_DIR/reconnect-probe-cleanup.txt" 2>&1
}
capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml >"$ARTIFACT_DIR/cluster-on-failure.yaml" 2>&1
  "$KUBECTL" get pods -n "$NAMESPACE" -o wide >"$ARTIFACT_DIR/pods-on-failure.txt" 2>&1
  "$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  cleanup
  exit "$exit_code"
}
trap capture_failure ERR
trap cleanup EXIT

command -v "$KUBECTL" >/dev/null
"$KUBECTL" wait --for=condition=Ready "cluster/$CLUSTER_NAME" -n "$NAMESPACE" \
  --timeout="${POSTGRES_READY_TIMEOUT:-120s}" >"$ARTIFACT_DIR/before-ready.txt"

old_primary="$("$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" \
  -o jsonpath='{.status.currentPrimary}')"
[[ -n "$old_primary" ]] || { echo "CNPG has no current primary" >&2; exit 1; }

psql_on() {
  local pod="$1"
  shift
  "$KUBECTL" exec -n "$NAMESPACE" "$pod" -- \
    psql -d appdb -v ON_ERROR_STOP=1 "$@"
}

probe_id="failover-$(date -u +%Y%m%dT%H%M%SZ)"
psql_on "$old_primary" -Atqc "CREATE TABLE IF NOT EXISTS poc_failover_probe (id text PRIMARY KEY, observed_at timestamptz NOT NULL DEFAULT now()); INSERT INTO poc_failover_probe (id) VALUES ('$probe_id') ON CONFLICT (id) DO NOTHING; SELECT id FROM poc_failover_probe WHERE id = '$probe_id';" \
  >"$ARTIFACT_DIR/pre-failover-write.txt"
grep -Fqx "$probe_id" "$ARTIFACT_DIR/pre-failover-write.txt"

cat >"$ARTIFACT_DIR/reconnect-probe.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $PROBE_NAME
  namespace: $NAMESPACE
  labels:
    app.kubernetes.io/name: postgres-reconnect-probe
    app.kubernetes.io/part-of: local-cloud-poc
spec:
  restartPolicy: Never
  containers:
    - name: psql-client
      image: postgres:17-alpine
      imagePullPolicy: IfNotPresent
      env:
        - name: PGHOST
          value: ${CLUSTER_NAME}-rw.${NAMESPACE}.svc.cluster.local
        - name: PGPORT
          value: "5432"
        - name: PGDATABASE
          value: appdb
        - name: PGUSER
          valueFrom:
            secretKeyRef:
              name: ${CLUSTER_NAME}-app
              key: username
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: ${CLUSTER_NAME}-app
              key: password
        - name: PGCONNECT_TIMEOUT
          value: "3"
      resources:
        requests:
          cpu: 10m
          memory: 32Mi
        limits:
          cpu: 50m
          memory: 64Mi
      command: ["/bin/sh", "-ceu"]
      args:
        - |
          deadline=\$(( \$(date +%s) + ${RECONNECT_PROBE_SECONDS:-120} ))
          while [ "\$(date +%s)" -lt "\$deadline" ]; do
            if psql -Atqc 'SELECT 1' >/dev/null 2>&1; then
              printf 'ok %s\\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            else
              printf 'retry %s\\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            fi
            sleep 2
          done
EOF

"$KUBECTL" delete pod "$PROBE_NAME" -n "$NAMESPACE" --ignore-not-found --wait=true \
  >"$ARTIFACT_DIR/reconnect-probe-preclean.txt"
"$KUBECTL" apply -f "$ARTIFACT_DIR/reconnect-probe.yaml" \
  >"$ARTIFACT_DIR/reconnect-probe-apply.txt"
"$KUBECTL" wait --for=condition=Ready "pod/$PROBE_NAME" -n "$NAMESPACE" \
  --timeout="${RECONNECT_PROBE_START_TIMEOUT:-90s}" \
  >"$ARTIFACT_DIR/reconnect-probe-start.txt"
sleep 3
pre_ok_count="$("$KUBECTL" logs -n "$NAMESPACE" "$PROBE_NAME" 2>/dev/null | grep -c '^ok ' || true)"
printf '%s\n' "$pre_ok_count" >"$ARTIFACT_DIR/reconnect-successes-before-delete.txt"

printf '%s\n' "$old_primary" >"$ARTIFACT_DIR/old-primary.txt"
failover_start_epoch="$(date +%s)"
"$KUBECTL" delete pod "$old_primary" -n "$NAMESPACE" --wait=false \
  >"$ARTIFACT_DIR/primary-delete.txt"

new_primary=""
for _ in $(seq 1 "${FAILOVER_TIMEOUT_SECONDS:-300}"); do
  candidate="$("$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.currentPrimary}' 2>/dev/null || true)"
  if [[ -n "$candidate" && "$candidate" != "$old_primary" ]]; then
    new_primary="$candidate"
    break
  fi
  sleep 1
done
[[ -n "$new_primary" ]] || { echo "CNPG did not elect a new primary" >&2; exit 1; }
printf '%s\n' "$new_primary" >"$ARTIFACT_DIR/new-primary.txt"
failover_end_epoch="$(date +%s)"
printf '%s\n' "$((failover_end_epoch - failover_start_epoch))" >"$ARTIFACT_DIR/failover-seconds.txt"

"$KUBECTL" wait --for=condition=Ready "cluster/$CLUSTER_NAME" -n "$NAMESPACE" \
  --timeout="${POSTGRES_READY_TIMEOUT:-180s}" >"$ARTIFACT_DIR/after-ready.txt"
sleep "${RECONNECT_SETTLE_SECONDS:-10}"

psql_on "$new_primary" -Atqc "SELECT id FROM poc_failover_probe WHERE id = '$probe_id';" \
  >"$ARTIFACT_DIR/post-failover-read.txt"
grep -Fqx "$probe_id" "$ARTIFACT_DIR/post-failover-read.txt"

"$KUBECTL" logs -n "$NAMESPACE" "$PROBE_NAME" --all-containers=true \
  >"$ARTIFACT_DIR/reconnect-probe.log"
ok_count="$(grep -c '^ok ' "$ARTIFACT_DIR/reconnect-probe.log" || true)"
[[ "$ok_count" -gt "$pre_ok_count" ]] || {
  echo "reconnect probe recorded no successful connection after primary deletion ($pre_ok_count -> $ok_count)" >&2
  exit 1
}
retry_count="$(grep -c '^retry ' "$ARTIFACT_DIR/reconnect-probe.log" || true)"

"$KUBECTL" get cluster "$CLUSTER_NAME" -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/cluster-final.yaml"
"$KUBECTL" get pods,pvc -n "$NAMESPACE" -o wide \
  >"$ARTIFACT_DIR/workloads-final.txt"
"$KUBECTL" get events -n "$NAMESPACE" --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'PostgreSQL failover passed: %s -> %s in %ss; marker %s persisted; reconnect successes=%s retries=%s\n' \
  "$old_primary" "$new_primary" "$((failover_end_epoch - failover_start_epoch))" "$probe_id" "$ok_count" "$retry_count"
