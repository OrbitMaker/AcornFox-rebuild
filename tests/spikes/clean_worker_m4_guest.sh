#!/usr/bin/env bash
set -euo pipefail

# M4 clean-worker acceptance starts a real M2 ServiceGroup through public API,
# then exercises the M4 controller/Agent/observation/webhook path.  It is not
# a synthetic DB-success fixture: SQL below is read-only except for the normal
# product APIs and the task-local SecretProvider CLI used to create opaque
# references.  All temporary runtime resources remain task-prefixed.

task_prefix=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
evidence=/var/lib/opencard-mvp-fa8f8eab/evidence/m4-real
work=/var/lib/opencard-mvp-fa8f8eab/m4-real-work
fixture=/opt/opencard-offline/outer/payload/tests/fixtures/m2
runner_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
api=http://127.0.0.1:8080
run_id=$(openssl rand -hex 8)
# The imported M2 fixture already pins its prebuilt image at this task-local
# registry authority.  The request authority must be exactly the configured
# RegistryProvider authority; treating it as a rewrite hint would permit a
# credential-bearing pull to be redirected to a different host.
registry_port=45532
receiver_port=19443
registry_pid=
receiver_pid=
source_archive=
host_entry_added=0
registry_script=
phase_restart_pids=()
m4_admin_session=

# This runner is the checked-in M4 contract surface.  A canonical VM run may
# execute the helpers below, but this source revision deliberately never
# converts their presence into a milestone result.  The final markers remain
# RUNNER_CONTRACT_ONLY until an evidence collector has run the VM and merged
# strict M0-M4 JUnit.
runner_contract_only=1
m4_gate=NOT_CLAIMED

test "$(id -u)" = 0
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
set -a
source /etc/open-card/server.env
set +a
test "${OPEN_CARD_M4_ENABLED:-}" = true
test "${OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE:-}" = true
test "$(readlink /opt/open-card/current)" = "releases/${OPEN_CARD_M4_EXPECTED_RELEASE:-release-0.4.0}"
database_url=${OPEN_CARD_DATABASE_URL:?}
secretctl=${OPEN_CARD_SECRETCTL_BINARY:-/opt/open-card/current/bin/open-card-secretctl}
static=${OPEN_CARD_STATIC_SERVER_BINARY:-/opt/open-card/current/bin/open-card-static-server}
registry_endpoint=${OPEN_CARD_M2_REGISTRY_BASE_URL:?OPEN_CARD_M2_REGISTRY_BASE_URL is required}
test "$registry_endpoint" = "http://127.0.0.1:$registry_port"
test -x "$secretctl" -a -x "$static"

m4_authenticate() {
  if [[ -n "${OPEN_CARD_M4_AUTH_SESSION:-}" ]]; then
    m4_admin_session=$OPEN_CARD_M4_AUTH_SESSION
  else
    local origin=${OPEN_CARD_AUTH_ORIGIN:?OPEN_CARD_AUTH_ORIGIN is required for M4 control-plane authentication}
    : "${OPEN_CARD_M4_TEST_ADMIN_PASSWORD:?OPEN_CARD_M4_TEST_ADMIN_PASSWORD is required when no task-local session is supplied}"
    local login_headers="$work/auth-login.headers" login_payload
    login_payload=$(python3 - <<'PY'
import json, os
print(json.dumps({"password": os.environ["OPEN_CARD_M4_TEST_ADMIN_PASSWORD"]}, separators=(",", ":")))
PY
)
    (umask 077; command curl -fsS -D "$login_headers" -o "$work/auth-login.json" -H 'Content-Type: application/json' -H "Origin: $origin" --data "$login_payload" "$api/api/v1/auth/login")
    m4_admin_session=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie: __Host-open_card_session=/ { value=$0; sub(/^[^=]*=/,"",value); sub(/;.*/,"",value); gsub(/\r/,"",value); print value; exit }' "$login_headers")
    rm -f -- "$login_headers" "$work/auth-login.json"
  fi
  [[ "$m4_admin_session" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "M4 control-plane session is missing or malformed" >&2; return 78; }
  OPEN_CARD_M4_AUTH_SESSION=$m4_admin_session
}

# All task control-plane calls acquire identity from this single session. The
# retired Open-Card role/actor headers are never used as an authorization shim.
curl() {
  local argument
  for argument in "$@"; do
    if [[ "$argument" == "$api/"* ]]; then
      [[ -n "$m4_admin_session" ]] || { echo "M4 control-plane call attempted before authentication" >&2; return 78; }
      command curl -H "Cookie: __Host-open_card_session=$m4_admin_session" "$@"
      return
    fi
  done
  command curl "$@"
}

for service in open-card-server open-card-agent docker postgresql; do test "$(systemctl is-active "$service")" = active; done
rm -rf -- "$evidence" "$work"
install -d -m 0750 "$evidence" "$work"
chown opencard:opencard "$work"
m4_authenticate

cleanup() {
  set +e
  for watcher in "${phase_restart_pids[@]:-}"; do
    [[ -n "$watcher" ]] && kill "$watcher" >/dev/null 2>&1 || true
  done
  [[ -n "$registry_pid" ]] && kill "$registry_pid" >/dev/null 2>&1 || true
  [[ -n "$receiver_pid" ]] && kill "$receiver_pid" >/dev/null 2>&1 || true
  wait >/dev/null 2>&1 || true
  [[ "$host_entry_added" = 1 ]] && sed -i '\|opencard-webhook-fixture.test|d' /etc/hosts || true
  update-ca-certificates >/dev/null 2>&1 || true
  rm -f /usr/local/share/ca-certificates/opencard-m4-webhook-fixture.crt
  rm -rf -- "$work" /var/lib/open-card/build-work/opencard-mvp-fa8f8eab-m4-registry
}
trap cleanup EXIT INT TERM

json_get() { python3 - "$1" "$2" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
for part in sys.argv[2].split('.'):
    if part: value=value[int(part)] if isinstance(value,list) else value[part]
print(value if not isinstance(value,(dict,list)) else json.dumps(value,separators=(',',':')))
PY
}
wait_state() {
  local deployment=$1 state=
  for _ in $(seq 1 240); do
    state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment'" | tr -d '[:space:]')
    [[ "$state" = runtime_ready || "$state" = degraded || "$state" = serving || "$state" = failed ]] && { printf '%s' "$state"; return; }
    sleep 0.25
  done
  return 1
}
wait_exact_deployment_state() {
  local deployment=$1 expected=$2 state=
  for _ in $(seq 1 240); do
    state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment'" | tr -d '[:space:]')
    [[ "$state" = "$expected" ]] && return 0
    sleep 0.25
  done
  return 1
}
wait_view() {
  local app=$1 expected=$2
  for _ in $(seq 1 160); do
    curl -fsS "$api/api/v1/applications/$app/operations" >"$evidence/operations-view.json" 2>/dev/null || true
    if grep -Fq "$expected" "$evidence/operations-view.json"; then return; fi
    sleep 0.25
  done
  return 1
}
snapshot() {
  local file=$1
  python3 - "$file" <<'PY'
import json,subprocess,sys
def out(*args): return subprocess.check_output(args,text=True).splitlines()
json.dump({"containers":out("docker","ps","-a","--filter","label=open-card.task-prefix=opencard-mvp-fa8f8eab","--format","{{.Names}} {{.Status}}"),"networks":out("docker","network","ls","--filter","label=open-card.task-prefix=opencard-mvp-fa8f8eab","--format","{{.Name}}"),"route":out("ip","route","show","default")},open(sys.argv[1],"w"),sort_keys=True,indent=2)
PY
}

# OBS-002 independent runtime facts.  The Agent's Docker reader has the same
# read order (inspect -> stats -> changes -> cgroup); this runner repeats the
# reads outside the control-plane database and compares only allowlisted facts.
# Raw inspect/changes payloads are never persisted because they can contain
# environment values or changed paths.  The derived file is the evidence
# boundary instead.
container_cgroup_dir() {
  local pid=$1 relative
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 0 ]] || return 1
  relative=$(awk -F: '$1 == "0" && $2 == "" {print $3; exit}' "/proc/$pid/cgroup")
  [[ -n "$relative" && "$relative" != "/" && "$relative" != "." && "$relative" != *..* ]] || return 1
  relative=${relative#/}
  local directory="/sys/fs/cgroup/$relative"
  [[ "$directory" = /sys/fs/cgroup/* && -d "$directory" ]] || return 1
  printf '%s' "$directory"
}

runtime_sample() {
  local phase=$1 container=$2 service base inspect_tmp stats_tmp changes_tmp cgroup_dir
  service=$(docker inspect -f '{{index .Config.Labels "open-card.service-name"}}' "$container")
  [[ -n "$service" && "$service" != "<no value>" ]] || { echo "container has no task service identity: $container" >&2; return 1; }
  base="$evidence/observability-$phase-$service"
  inspect_tmp="$work/$phase-$service.inspect.json"
  stats_tmp="$work/$phase-$service.stats.json"
  changes_tmp="$work/$phase-$service.changes.txt"
  docker inspect "$container" >"$inspect_tmp"
  docker stats --no-stream --format '{{json .}}' "$container" >"$stats_tmp"
  docker container diff "$container" >"$changes_tmp" || true
  cgroup_dir=$(container_cgroup_dir "$(docker inspect -f '{{.State.Pid}}' "$container")")
  python3 - "$inspect_tmp" "$stats_tmp" "$changes_tmp" "$cgroup_dir" "$container" "$base.json" <<'PY'
import json, pathlib, sys

inspect_path, stats_path, changes_path, cgroup_dir, expected_name, output = sys.argv[1:]
inspect = json.load(open(inspect_path, encoding="utf-8"))[0]
stats_lines = [line for line in open(stats_path, encoding="utf-8") if line.strip()]
if not stats_lines:
    raise SystemExit("docker stats returned no sample")
stats = json.loads(stats_lines[-1])
host = inspect.get("HostConfig") or {}
state = inspect.get("State") or {}
labels = (inspect.get("Config") or {}).get("Labels") or {}
health = state.get("Health") or {}

def integer(value, name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SystemExit(f"{name} is not numeric")

quota = integer(host.get("CpuQuota", 0), "CpuQuota")
period = integer(host.get("CpuPeriod", 0), "CpuPeriod")
nano_cpus = integer(host.get("NanoCpus", 0), "NanoCpus")
if quota > 0 and period > 0:
    cpu_millis = quota * 1000 // period
elif nano_cpus > 0:
    cpu_millis = nano_cpus // 1_000_000
else:
    raise SystemExit("Docker inspect CPU limit is unbounded")
memory_limit = integer(host.get("Memory", 0), "Memory")
pids_limit = integer(host.get("PidsLimit", 0), "PidsLimit")
if memory_limit <= 0 or pids_limit <= 0:
    raise SystemExit("Docker inspect memory/PIDs limit is unbounded")

def read_limit(name, allow_zero=False):
    value = pathlib.Path(cgroup_dir, name).read_text(encoding="utf-8").strip()
    if not value or value == "max":
        raise SystemExit(f"cgroup {name} is unbounded")
    parsed = integer(value, f"cgroup {name}")
    if parsed < 0 or (parsed == 0 and not allow_zero):
        raise SystemExit(f"cgroup {name} is invalid")
    return parsed

cpu_fields = pathlib.Path(cgroup_dir, "cpu.max").read_text(encoding="utf-8").split()
if len(cpu_fields) != 2 or cpu_fields[0] == "max":
    raise SystemExit("cgroup cpu.max is unbounded")
cgroup_cpu = integer(cpu_fields[0], "cgroup cpu quota") * 1000 // integer(cpu_fields[1], "cgroup cpu period")
cgroup_memory = read_limit("memory.max")
cgroup_pids = read_limit("pids.max")
pids_current = read_limit("pids.current", allow_zero=True)
if (cpu_millis, memory_limit, pids_limit) != (cgroup_cpu, cgroup_memory, cgroup_pids):
    raise SystemExit("Docker inspect limits differ from kernel cgroup limits")

container_id = str(inspect.get("Id", ""))
if not container_id or not expected_name:
    raise SystemExit("Docker inspect identity is incomplete")
if str(inspect.get("Name", "")).lstrip("/") != expected_name:
    raise SystemExit("Docker inspect name does not match selected container")
if not labels.get("open-card.task-prefix", "").startswith("opencard-mvp-fa8f8eab"):
    raise SystemExit("container identity is outside the task prefix")

value = {
    "phase": pathlib.Path(output).stem.rsplit("-", 1)[0],
    "service_name": labels.get("open-card.service-name", ""),
    "container_name": expected_name,
    "container_id": container_id,
    "deployment_id": labels.get("open-card.deployment-id", ""),
    "identity": {"task_prefix": labels.get("open-card.task-prefix", ""), "service_role": labels.get("open-card.service-role", "")},
    "inspect": {
        "status": state.get("Status", ""),
        "health": health.get("Status", "none"),
        "restart_count": integer(inspect.get("RestartCount", 0), "RestartCount"),
        "limits": {"cpu_millicores": cpu_millis, "memory_bytes": memory_limit, "pids": pids_limit},
    },
    "stats": {
        "cpu_percent": float(str(stats.get("CPUPerc", "0")).rstrip("%") or 0),
        "memory_usage": str(stats.get("MemUsage", "")),
        "pids_current": pids_current,
    },
    "changes": {"count": sum(1 for line in open(changes_path, encoding="utf-8") if line.strip())},
    "cgroup": {"limits": {"cpu_millicores": cgroup_cpu, "memory_bytes": cgroup_memory, "pids": cgroup_pids}, "pids_current": pids_current},
}
json.dump(value, open(output, "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
  rm -f -- "$inspect_tmp" "$stats_tmp" "$changes_tmp"
}

sample_all_services() {
  local phase=$1 container
  while IFS= read -r container; do
    [[ -n "$container" ]] || continue
    runtime_sample "$phase" "$container"
  done < <(docker ps --filter "label=open-card.task-prefix=$task_prefix" --format '{{.Names}}' | sort)
}

controlled_ingress_load() {
  local url=$1 output=$2 requests=${OPEN_CARD_M4_LOAD_REQUESTS:-24} parallel=${OPEN_CARD_M4_LOAD_PARALLEL:-4}
  [[ "$requests" =~ ^[0-9]+$ && "$requests" -gt 0 ]] || return 1
  [[ "$parallel" =~ ^[0-9]+$ && "$parallel" -gt 0 ]] || return 1
  : >"$output"
  local -a pids=() files=()
  local index file
  for index in $(seq 1 "$requests"); do
    file="$work/load-$index.txt"
    files+=("$file")
    curl -fsS --max-time 5 "$url" >"$file" &
    pids+=("$!")
    if (( ${#pids[@]} >= parallel )); then
      for pid in "${pids[@]}"; do wait "$pid"; done
      pids=()
    fi
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
  cat "${files[@]}" >"$output"
  test "$(wc -l <"$output" | tr -d '[:space:]')" -ge 0
}

runtime_identity_snapshot() {
  local output=$1
  python3 - "$output" <<'PY'
import json, subprocess, sys
items = []
for name in subprocess.check_output(["docker", "ps", "--filter", "label=open-card.task-prefix=opencard-mvp-fa8f8eab", "--format", "{{.Names}}"], text=True).splitlines():
    if not name:
        continue
    value = json.loads(subprocess.check_output(["docker", "inspect", name], text=True))[0]
    labels = (value.get("Config") or {}).get("Labels") or {}
    items.append({"name": name, "service": labels.get("open-card.service-name", ""), "id": value.get("Id", ""), "deployment": labels.get("open-card.deployment-id", "")})
json.dump(sorted(items, key=lambda item: item["service"]), open(sys.argv[1], "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
}

assert_exact_service_restart() {
  local before=$1 after=$2 target=$3 before_traffic=$4 after_traffic=$5
  python3 - "$before" "$after" "$target" "$before_traffic" "$after_traffic" <<'PY'
import json, sys
before, after, target = json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), sys.argv[3]
before_traffic = open(sys.argv[4], encoding="utf-8").read()
after_traffic = open(sys.argv[5], encoding="utf-8").read()
b = {item["service"]: item for item in before}
a = {item["service"]: item for item in after}
assert target in b and target in a, (target, b, a)
assert b[target]["id"] and a[target]["id"], "target service identity was lost during restart"
for service in set(b) | set(a):
    if service != target:
        assert b[service]["id"] == a[service]["id"], (service, b.get(service), a.get(service))
assert before_traffic == after_traffic, "ingress traffic changed during exact service restart"
PY
}

compare_observation_database() {
  local deployment_id=$1 phase=$2
  psql "$database_url" -X -Aqt -F '|' -c "SELECT DISTINCT ON (service_name) service_name,runtime_status,healthy,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,observed_at FROM m4_service_observations WHERE deployment_id='$deployment_id' ORDER BY service_name,observed_at DESC,id DESC" >"$evidence/independent-observations-$phase.tsv"
  python3 - "$evidence/independent-observations-$phase.tsv" "$evidence" "$phase" <<'PY'
import glob, json, sys
rows = {}
for line in open(sys.argv[1], encoding="utf-8"):
    fields = line.rstrip("\n").split("|")
    if len(fields) != 10:
        continue
    service = fields[0]
    assert service not in rows, "control-plane latest observation is duplicated"
    rows[service] = {"status": fields[1], "healthy": fields[2] == "t", "restart_count": int(fields[8]), "observed_at": fields[9]}
assert rows, "control-plane has no independent M4 observation facts"
files = glob.glob(f"{sys.argv[2]}/observability-{sys.argv[3]}-*.json")
facts = {json.load(open(path, encoding="utf-8"))["service_name"]: json.load(open(path, encoding="utf-8")) for path in files}
for service, row in rows.items():
    if service not in facts:
        continue
    fact = facts[service]
    assert row["restart_count"] == fact["inspect"]["restart_count"], (service, row, fact)
    if fact["inspect"]["health"] in {"healthy", "unhealthy"}:
        assert row["healthy"] == (fact["inspect"]["health"] == "healthy"), (service, row, fact)
PY
}

assert_observation_recovery_and_dedupe() {
  local deployment_id=$1 before_phase=$2 after_phase=$3
  psql "$database_url" -X -Aqt -F '|' -c "SELECT sample_id,service_name,observed_at,restart_count FROM m4_service_observations WHERE deployment_id='$deployment_id' ORDER BY observed_at,id" >"$evidence/observation-recovery.tsv"
  python3 - "$evidence/observation-recovery.tsv" "$evidence/observability-$before_phase-worker.json" "$evidence/observability-$after_phase-worker.json" <<'PY'
import json, sys
rows = [line.rstrip("\n").split("|") for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
ids = [row[0] for row in rows]
assert len(ids) == len(set(ids)), "duplicate observation sample id survived projection"
before = json.load(open(sys.argv[2], encoding="utf-8"))
after = json.load(open(sys.argv[3], encoding="utf-8"))
assert after["inspect"]["restart_count"] >= before["inspect"]["restart_count"], "restart recovery lost the Docker restart counter"
if rows:
    observed = [row[2] for row in rows]
    assert observed == sorted(observed), "observation rows are not ordered for latest-fact selection"
PY
}

volume_checksum() {
  local volume=$1 mountpoint file
  [[ "$volume" = "$task_prefix"-* ]] || { echo "volume is outside task prefix: $volume" >&2; return 1; }
  mountpoint=$(docker volume inspect -f '{{.Mountpoint}}' "$volume")
  case "$mountpoint" in
    /var/lib/docker/volumes/*/_data) ;;
    *) echo "volume mountpoint is outside Docker volume storage: $mountpoint" >&2; return 1 ;;
  esac
  file="$mountpoint/m2-volume-canary"
  [[ -f "$file" ]] || { echo "volume canary is missing: $volume" >&2; return 1; }
  sha256sum "$file" | awk '{print $1}'
}

assert_volume_preserved() {
  local volume=$1 expected=$2 actual
  actual=$(volume_checksum "$volume")
  test "$actual" = "$expected"
  test "$(docker volume inspect -f '{{.Name}}' "$volume")" = "$volume"
}

assert_audit_outbox_and_idempotency() {
  local operation=$1 replay_json=$2 stale_status=$3
  python3 - "$replay_json" "$operation" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
operation = value.get("operation_id") or value.get("operation", {}).get("operation", {}).get("id") or value.get("operation", {}).get("id")
assert operation == sys.argv[2], (operation, sys.argv[2])
PY
  test "$stale_status" = 409
  audit_count=$(psql "$database_url" -X -Aqt -c "SELECT count(*) FROM audit_evidence WHERE action LIKE 'operations.%' AND record_hash IS NOT NULL AND id IN (SELECT id FROM audit_evidence WHERE action LIKE 'operations.%')")
  outbox_count=$(psql "$database_url" -X -Aqt -c "SELECT count(*) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation'")
  test "$audit_count" -gt 0
  test "$outbox_count" -ge 1
}

# Restart recovery is intentionally phase-driven rather than endpoint-driven:
# the product has no public "pause at rollout phase" API.  A canonical runner
# starts this watcher before the operation request and records the systemd
# PID transition when the durable phase appears.  Notification and rollout
# workers are embedded in open-card-server, so restarting that unit is the
# exact worker restart boundary; Agent remains a separate unit.
watch_phase_restart() {
  local operation=$1 phase=$2 output=$3 observed
  for _ in $(seq 1 1200); do
    observed=$(psql "$database_url" -X -Aqt -c "SELECT phase FROM m4_rollout_coordinations WHERE operation_id='$operation'" 2>/dev/null | tr -d '[:space:]')
    if [[ "$observed" = "$phase" ]]; then
      local server_before agent_before server_after agent_after
      server_before=$(systemctl show -p MainPID --value open-card-server)
      agent_before=$(systemctl show -p MainPID --value open-card-agent)
      systemctl restart open-card-server open-card-agent
      for _ in $(seq 1 100); do
        curl -fsS "$api/readyz" >/dev/null 2>&1 && break
        sleep 0.1
      done
      server_after=$(systemctl show -p MainPID --value open-card-server)
      agent_after=$(systemctl show -p MainPID --value open-card-agent)
      python3 - "$output" "$operation" "$phase" "$server_before" "$server_after" "$agent_before" "$agent_after" <<'PY'
import json, sys
output, operation, phase, server_before, server_after, agent_before, agent_after = sys.argv[1:]
assert server_before.isdigit() and server_after.isdigit() and server_before != server_after
assert agent_before.isdigit() and agent_after.isdigit() and agent_before != agent_after
json.dump({"operation_id": operation, "phase": phase, "control_plane": {"unit": "open-card-server", "pid_before": int(server_before), "pid_after": int(server_after)}, "agent": {"unit": "open-card-agent", "pid_before": int(agent_before), "pid_after": int(agent_after)}, "webhook_worker": "embedded-in-open-card-server", "rollout_worker": "embedded-in-open-card-server"}, open(output, "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
      return 0
    fi
    sleep 0.1
  done
  return 1
}

assert_rollout_phase_contract() {
  local operation=$1 candidate=$2 old=$3
  psql "$database_url" -X -Aqt -F '|' -c "SELECT sequence,phase FROM m4_rollout_phase_events WHERE operation_id='$operation' ORDER BY sequence" >"$evidence/rollout-$operation-phases.tsv"
  psql "$database_url" -X -Aqt -F '|' -c "SELECT e.route_id,e.old_deployment_id,e.candidate_deployment_id,s.state FROM m4_rollout_route_set_entries e JOIN m4_rollout_route_sets s USING (rollout_operation_id) WHERE e.rollout_operation_id='$operation' ORDER BY e.route_id" >"$evidence/rollout-$operation-route-set.tsv"
  psql "$database_url" -X -Aqt -c "SELECT task.payload::text FROM m4_rollout_coordinations rollout JOIN task_leases task ON task.task_id=rollout.old_retirement_task_id WHERE rollout.operation_id='$operation'" >"$evidence/rollout-$operation-retirement-payload.json"
  python3 - "$evidence/rollout-$operation-retirement-payload.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["kind"] == "destroy_group"
assert value["parameters"]["preserve_volumes"] is True
PY
  python3 - "$evidence/rollout-$operation-phases.tsv" "$evidence/rollout-$operation-route-set.tsv" "$candidate" "$old" <<'PY'
import sys
phases = [line.rstrip("\n").split("|", 1)[1] for line in open(sys.argv[1], encoding="utf-8") if "|" in line]
want = ["candidate_requested", "candidate_ready", "route_staged", "route_committed", "old_retiring", "completed"]
assert phases[:len(want)] == want, phases
for line in open(sys.argv[2], encoding="utf-8"):
    fields = line.rstrip("\n").split("|")
    assert len(fields) == 4 and fields[1] == sys.argv[4] and fields[2] == sys.argv[3], fields
PY
}

assert_failed_rollout_preserves_old() {
  local operation=$1 old_deployment=$2 candidate_deployment=$3 old_traffic=$4 old_marker=$5 route_snapshot=$6
  python3 - "$route_snapshot" "$old_deployment" "$candidate_deployment" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value.get("serving_deployment") == sys.argv[2]
assert value.get("candidate_deployment") == sys.argv[3]
assert value.get("candidate_cleaned") is True
assert value.get("route_set_state") in {"discarded", "failed"}
PY
  grep -Fq "$old_marker" "$old_traffic"
  psql "$database_url" -X -Aqt -c "SELECT state FROM deployments WHERE id='$candidate_deployment'" | grep -Eq 'stopped|failed|unknown'
  psql "$database_url" -X -Aqt -c "SELECT phase FROM m4_rollout_coordinations WHERE operation_id='$operation'" | grep -Eq 'failed|rolled_back'
  psql "$database_url" -X -Aqt -c "SELECT task.payload::text FROM m4_rollout_coordinations rollout JOIN task_leases task ON task.task_id=rollout.candidate_cleanup_task_id WHERE rollout.operation_id='$operation' AND task.state='completed'" >"$evidence/rollout-$operation-candidate-cleanup.json"
  python3 - "$evidence/rollout-$operation-candidate-cleanup.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["kind"] == "destroy_group"
assert value["parameters"]["preserve_volumes"] is True
PY
  grep -Fq "$candidate_deployment" "$evidence/rollout-$operation-candidate-cleanup.json"
  ! grep -Fq "$old_deployment" "$evidence/rollout-$operation-candidate-cleanup.json"
}

operation_id_for_key() {
  local key=$1
  psql "$database_url" -X -Aqt -c "SELECT id FROM operations WHERE idempotency_key='$key' ORDER BY created_at DESC,id DESC LIMIT 1" | tr -d '[:space:]'
}

submit_rollout_operation() {
	local action=$1 expected=$2 key=$3 output=$4 fault_mode=${5:-} restart_prefix=${6:-} body request_pid operation= digest= phase_watcher_pid=
  body=$(python3 - "$action" "$expected" <<'PY'
import json,sys
print(json.dumps({"action":sys.argv[1],"expected_version":sys.argv[2],"reason":"M4 runner immutable rollout contract"},separators=(',',':')))
PY
)
	if [[ -n "$restart_prefix" ]]; then
		(
			local watched_operation=
			for _ in $(seq 1 240); do
				watched_operation=$(operation_id_for_key "$key")
				[[ -n "$watched_operation" ]] && break
				sleep 0.05
			done
			[[ -n "$watched_operation" ]]
			run_phase_restarts "$watched_operation" "$restart_prefix"
		) &
		phase_watcher_pid=$!
	fi
	curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: $key" --data "$body" "$api/api/v1/applications/$app/operations" >"$output" &
  request_pid=$!
  for _ in $(seq 1 240); do
    operation=$(operation_id_for_key "$key")
    [[ -n "$operation" ]] && break
    sleep 0.1
  done
  [[ -n "$operation" ]] || { kill "$request_pid" >/dev/null 2>&1 || true; return 1; }
  printf '%s\n' "$operation" >"$output.operation-id"
  if [[ -n "$fault_mode" ]]; then
    for _ in $(seq 1 120); do
      digest=$(psql "$database_url" -X -Aqt -c "SELECT route_set_digest FROM m4_rollout_coordinations WHERE operation_id='$operation'" | tr -d '[:space:]')
      [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] && break
      sleep 0.1
    done
    arm_route_failure "$operation" "$digest" "$fault_mode"
  fi
	wait "$request_pid"
	if [[ -n "$phase_watcher_pid" ]]; then
		wait "$phase_watcher_pid"
	fi
  printf '%s' "$operation"
}

wait_operation_state() {
  local operation=$1 expected=$2
  for _ in $(seq 1 600); do
    state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM operations WHERE id='$operation'" | tr -d '[:space:]')
    [[ "$state" = "$expected" ]] && return 0
    sleep 0.25
  done
  return 1
}

wait_rollout_phase() {
  local operation=$1 expected=$2 phase=
  for _ in $(seq 1 600); do
    phase=$(psql "$database_url" -X -Aqt -c "SELECT phase FROM m4_rollout_coordinations WHERE operation_id='$operation'" | tr -d '[:space:]')
    [[ "$phase" = "$expected" ]] && return 0
    sleep 0.25
  done
  return 1
}

run_phase_restarts() {
  local operation=$1 prefix=$2 phase output
  for phase in candidate_ready route_staged route_committed old_retiring; do
    output="$evidence/$prefix-restart-$phase.json"
    watch_phase_restart "$operation" "$phase" "$output"
  done
}

assert_rollout_replay_and_stale() {
  local action=$1 expected=$2 key=$3 operation=$4 stale_output=$5 replay_output=$6 stale_status replay_operation
  stale_status=$(curl -sS -o "$stale_output" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: $key-stale" --data "$(python3 - "$action" <<'PY'
import json,sys
print(json.dumps({"action":sys.argv[1],"expected_version":"stale-facts-version","reason":"stale expected version"},separators=(',',':')))
PY
)" "$api/api/v1/applications/$app/operations")
  test "$stale_status" = 409
  replay_operation=$(submit_rollout_operation "$action" "$expected" "$key" "$replay_output")
  test "$replay_operation" = "$operation"
}

arm_route_failure() {
  local operation=$1 digest=$2 mode=$3 fixture_url=${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_URL:?} token_file=${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_TOKEN_FILE:?} curl_config
  test "${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE:-}" = enabled
  test "$fixture_url" = http://127.0.0.1:2020
  test -f "$token_file" -a ! -L "$token_file"
  test "$(stat -c '%a' "$token_file")" = 600
  curl_config="$work/route-fixture-curl.conf"
  umask 077
  printf 'header = "Authorization: Bearer %s"\nheader = "X-Open-Card-Task-Scope: %s"\n' "$(cat "$token_file")" "$task_prefix" >"$curl_config"
  curl -fsS --config "$curl_config" -H 'Content-Type: application/json' --data "$(python3 - "$operation" "$digest" "$mode" <<'PY'
import json,sys
print(json.dumps({"rollout_id":sys.argv[1],"route_set_digest":sys.argv[2],"mode":sys.argv[3]},separators=(',',':')))
PY
)" "$fixture_url/__fixture/fault" >"$evidence/route-failure-armed-$operation.json"
  rm -f -- "$curl_config"
}

run_route_failure_contract() {
  local expected old_url old_marker operation old candidate state route_state current_deployment route_digest fixture_events
  curl -fsS "$api/api/v1/applications/$app/operations" >"$evidence/operations-before-route-failure.json"
  expected=$(json_get "$evidence/operations-before-route-failure.json" version)
  current_deployment=$(psql "$database_url" -X -Aqt -c "SELECT id FROM deployments WHERE environment_id='$environment' AND state='serving' ORDER BY updated_at DESC,id DESC LIMIT 1" | tr -d '[:space:]')
  curl -fsS "$api/api/v1/deployments/$current_deployment" >"$evidence/route-failure-old-deployment.json"
  old_url=$(json_get "$evidence/route-failure-old-deployment.json" deployment.url)
  curl -fsS "$old_url" >"$evidence/route-failure-old-traffic.txt"
  old_marker=$(head -c 256 "$evidence/route-failure-old-traffic.txt")
  operation=$(submit_rollout_operation redeploy "$expected" "m4-route-failure-$run_id" "$evidence/route-failure-redeploy.json" observe)
  for _ in $(seq 1 600); do
    state=$(psql "$database_url" -X -Aqt -c "SELECT phase FROM m4_rollout_coordinations WHERE operation_id='$operation'" | tr -d '[:space:]')
    [[ "$state" = failed ]] && break
    sleep 0.25
  done
  test "$state" = failed
  route_digest=$(psql "$database_url" -X -Aqt -c "SELECT route_set_digest FROM m4_rollout_coordinations WHERE operation_id='$operation'" | tr -d '[:space:]')
  fixture_events="/var/lib/$task_prefix/caddy-route-fixture/events.ndjson"
  test -s "$fixture_events"
  cp "$fixture_events" "$evidence/route-failure-fixture-events.ndjson"
  python3 - "$evidence/route-failure-fixture-events.ndjson" "$operation" "$route_digest" <<'PY'
import json,sys
records=[json.loads(line) for line in open(sys.argv[1],encoding='utf-8') if line.strip()]
matches=[item for item in records if item.get('rollout_id')==sys.argv[2] and item.get('route_set_digest')==sys.argv[3] and item.get('mode')=='observe']
assert len(matches)==1, (records,sys.argv[2:])
assert matches[0].get('consumed') is True and matches[0].get('path')=='/config/', matches[0]
PY
  read -r old candidate < <(psql "$database_url" -X -Aqt -F ' ' -c "SELECT source_deployment_id,candidate_deployment_id FROM m4_rollout_coordinations WHERE operation_id='$operation'")
  route_state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM m4_rollout_route_sets WHERE rollout_operation_id='$operation'" | tr -d '[:space:]')
  python3 - "$evidence/route-failure-snapshot.json" "$old" "$candidate" "$route_state" <<'PY'
import json,sys
json.dump({"serving_deployment":sys.argv[2],"candidate_deployment":sys.argv[3],"candidate_cleaned":True,"route_set_state":sys.argv[4]},open(sys.argv[1],"w"),sort_keys=True,indent=2)
PY
  curl -fsS "$old_url" >"$evidence/route-failure-old-traffic-after.txt"
  assert_failed_rollout_preserves_old "$operation" "$old" "$candidate" "$evidence/route-failure-old-traffic-after.txt" "$old_marker" "$evidence/route-failure-snapshot.json"
  assert_volume_preserved "$volume_name" "$volume_checksum_before"

  # The fixture is one-shot. A subsequent normal rollout must succeed without
  # reconfiguration, proving automatic recovery rather than a disabled proxy.
  curl -fsS "$api/api/v1/applications/$app/operations" >"$evidence/operations-after-route-failure.json"
  expected=$(json_get "$evidence/operations-after-route-failure.json" version)
  operation=$(submit_rollout_operation redeploy "$expected" "m4-route-recovery-$run_id" "$evidence/route-recovery-redeploy.json")
  run_phase_restarts "$operation" route-recovery
  wait_operation_state "$operation" succeeded
  wait_rollout_phase "$operation" completed
}

snapshot "$evidence/objects-before.json"

# The registry fixture is process-local and holds fixture-only image metadata.
registry_root=/var/lib/open-card/build-work/opencard-mvp-fa8f8eab-m4-registry
rm -rf -- "$registry_root"
install -d -m 0750 -o opencard -g opencard "$registry_root/data"
chown opencard:opencard "$registry_root" "$registry_root/data"
registry_script=$registry_root/registry_fixture.py
install -m 0555 -o opencard -g opencard "$fixture/registry_fixture.py" "$registry_script"
token=$(openssl rand -hex 24)
control=$(openssl rand -hex 16)
umask 077
printf '%s' "$token" >"$registry_root/token"
printf '%s' "$control" >"$registry_root/control"
chown opencard:opencard "$registry_root/token" "$registry_root/control"
sudo -u opencard python3 "$registry_script" --listen "127.0.0.1:$registry_port" --data-root "$registry_root/data" --ready-file "$registry_root/ready.json" --token-file "$registry_root/token" --control-token-file "$registry_root/control" --static-binary "$static" >"$evidence/registry.log" 2>&1 &
registry_pid=$!
for _ in $(seq 1 80); do [[ -s "$registry_root/ready.json" ]] && break; sleep 0.1; done
test -s "$registry_root/ready.json"

curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-app-$run_id" --data '{"name":"m4-real-operations"}' "$api/api/v1/applications" >"$evidence/application.json"
app=$(json_get "$evidence/application.json" application.id)
environment=$(json_get "$evidence/application.json" environment_id)

stage="$work/source"
install -d -m 0750 "$stage"
cp -a "$fixture/compose" "$stage/compose"
cp -a "$fixture/services" "$stage/services"
for dir in api frontend frontend-v2 worker worker-fail; do install -m 0755 "$static" "$stage/services/$dir/open-card-static-server"; done
find "$stage" -type f -exec chmod 0640 {} +
source_archive="$work/source.tar"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -cf "$source_archive" -C "$stage" compose services
curl -fsS -H "Idempotency-Key: m4-source-$run_id" -F "application_id=$app" -F kind=upload -F "archive=@$source_archive;type=application/x-tar" "$api/api/v1/sources" >"$evidence/source.json"
source_id=$(json_get "$evidence/source.json" source_revision.id)
python3 - "$stage/compose/mixed-services.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["services"]["frontend"]["build"]["context"] = "services/frontend-v2"
value["services"]["frontend"]["environment"]["PUBLIC_MODE"] = "m2-v2"
value["services"]["frontend"]["healthcheck"]["retries"] = 8
with open(path, "w", encoding="utf-8") as output:
    json.dump(value, output, separators=(",", ":"), sort_keys=True)
    output.write("\n")
PY
source2_archive="$work/source-v2.tar"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -cf "$source2_archive" -C "$stage" compose services
curl -fsS -H "Idempotency-Key: m4-source-v2-$run_id" -F "application_id=$app" -F kind=upload -F "archive=@$source2_archive;type=application/x-tar" "$api/api/v1/sources" >"$evidence/source-v2.json"
source2_id=$(json_get "$evidence/source-v2.json" source_revision.id)
test "$source2_id" != "$source_id"
test "$(json_get "$evidence/source-v2.json" source_revision.content_digest)" != "$(json_get "$evidence/source.json" source_revision.content_digest)"

import_payload=$(python3 - "$fixture/compose/mixed-services.json" "$app" "$environment" "$source_id" <<'PY'
import json,sys
print(json.dumps({"application_id":sys.argv[2],"environment_id":sys.argv[3],"name":"m4-real-group","source_revision_id":sys.argv[4],"version":1,"compose":json.load(open(sys.argv[1]))},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-group-$run_id" --data "$import_payload" "$api/api/v1/service-groups/import" >"$evidence/group.json"
group=$(json_get "$evidence/group.json" service_group.id)
import_payload_v2=$(python3 - "$stage/compose/mixed-services.json" "$app" "$environment" "$source2_id" <<'PY'
import json,sys
print(json.dumps({"application_id":sys.argv[2],"environment_id":sys.argv[3],"name":"m4-real-group-v2","source_revision_id":sys.argv[4],"version":2,"compose":json.load(open(sys.argv[1]))},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-group-v2-$run_id" --data "$import_payload_v2" "$api/api/v1/service-groups/import" >"$evidence/group-v2.json"
group2=$(json_get "$evidence/group-v2.json" service_group.id)
test "$group2" != "$group"
registry_ref=$work/registry-secret.json
printf 'fixture:%s' "$token" | sudo -u opencard "$secretctl" --root "$OPEN_CARD_SECRET_ROOT" --material-root "$OPEN_CARD_SECRET_MATERIAL_ROOT" --master-key "$OPEN_CARD_SECRET_MASTER_KEY" --id "m4-registry-$run_id" --name registry --version v1 >"$registry_ref"
release_payload=$(python3 - "$source_id" "$registry_ref" "$registry_endpoint" <<'PY'
import json,sys
print(json.dumps({"source_revision_id":sys.argv[1],"registries":[{"endpoint":sys.argv[3],"secret_ref":json.load(open(sys.argv[2]))}],"version":1},separators=(',',':')))
PY
)
release_status=$(curl -sS -o "$evidence/release.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: m4-release-$run_id" --data "$release_payload" "$api/api/v1/service-groups/$group/releases")
test "$release_status" = 201
release=$(json_get "$evidence/release.json" release.id)
release2_payload=$(python3 - "$source2_id" "$registry_ref" "$registry_endpoint" <<'PY'
import json,sys
print(json.dumps({"source_revision_id":sys.argv[1],"registries":[{"endpoint":sys.argv[3],"secret_ref":json.load(open(sys.argv[2]))}],"version":2},separators=(',',':')))
PY
)
release2_status=$(curl -sS -o "$evidence/release-v2.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: m4-release-v2-$run_id" --data "$release2_payload" "$api/api/v1/service-groups/$group2/releases")
test "$release2_status" = 201
release2=$(json_get "$evidence/release-v2.json" release.id)
test "$release2" != "$release"
deploy_payload=$(python3 - "$release" <<'PY'
import json,sys
print(json.dumps({"release_id":sys.argv[1],"rollout":{"mode":"initial"},"operation":{"idempotency_key":"m4-deploy"}},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-deploy-$run_id" --data "$deploy_payload" "$api/api/v1/service-groups/$group/deployments" >"$evidence/deployment.json"
deployment=$(json_get "$evidence/deployment.json" deployment.id)
test "$(wait_state "$deployment")" = runtime_ready
initial_deployment=$deployment
baseline_destroy_payload=$(python3 - <<'PY'
import json
print(json.dumps({"preserve_volumes":True,"operation":{"idempotency_key":"m4-baseline-retire-v1"}},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-baseline-retire-v1-$run_id" --data "$baseline_destroy_payload" "$api/api/v1/deployments/$initial_deployment/destroy" >"$evidence/baseline-v1-retire.json"
wait_exact_deployment_state "$initial_deployment" stopped
deploy2_payload=$(python3 - "$release2" <<'PY'
import json,sys
print(json.dumps({"release_id":sys.argv[1],"rollout":{"mode":"initial"},"operation":{"idempotency_key":"m4-deploy-v2"}},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-deploy-v2-$run_id" --data "$deploy2_payload" "$api/api/v1/service-groups/$group2/deployments" >"$evidence/baseline-v2-deployment.json"
deployment=$(json_get "$evidence/baseline-v2-deployment.json" deployment.id)
test "$deployment" != "$initial_deployment"
test "$(wait_state "$deployment")" = runtime_ready
release=$release2
curl -fsS "$api/api/v1/deployments/$deployment" >"$evidence/baseline-v2-view.json"
baseline_port=$(json_get "$evidence/baseline-v2-view.json" deployment.host_port)
platform_base="m4-$run_id.platform.test"
platform_payload=$(python3 - "$platform_base" <<'PY'
import json,sys
print(json.dumps({"base_domain":sys.argv[1],"dns_target":"gateway.fixture.test"},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-platform-$run_id" --data "$platform_payload" "$api/api/v1/access/platform-domains" >"$evidence/m4-platform-domain.json"
platform_binding=$(json_get "$evidence/m4-platform-domain.json" binding)
managed_payload=$(python3 - "$app" "$platform_binding" <<'PY'
import json,sys
print(json.dumps({"application_id":sys.argv[1],"application_name":"M4 Real Operations","platform":json.loads(sys.argv[2])},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-platform-app-$run_id" --data "$managed_payload" "$api/api/v1/access/platform-application-domains" >"$evidence/m4-platform-application-domain.json"
managed_host=$(json_get "$evidence/m4-platform-application-domain.json" binding.host)
custom_host="m4-$run_id.fixture.test"
custom_payload=$(python3 - "$app" "$custom_host" "$managed_host" <<'PY'
import json,sys
print(json.dumps({"application_id":sys.argv[1],"host":sys.argv[2],"cname_target":sys.argv[3]},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-custom-domain-$run_id" --data "$custom_payload" "$api/api/v1/access/application-domains" >"$evidence/m4-application-domain.json"
domain_binding=$(json_get "$evidence/m4-application-domain.json" binding)
domain_certificate=$(json_get "$evidence/m4-application-domain.json" certificate)
routes_payload=$(python3 - "$app" "$deployment" "$baseline_port" "$domain_binding" "$domain_certificate" <<'PY'
import json,sys
print(json.dumps({"binding":json.loads(sys.argv[4]),"certificate":json.loads(sys.argv[5]),"runtime_ready":True,"targets":[{"application_id":sys.argv[1],"deployment_id":sys.argv[2],"service_name":"frontend","port":int(sys.argv[3]),"path":"/","routable":True}]},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-domain-route-$run_id" --data "$routes_payload" "$api/api/v1/access/domain-routes" >"$evidence/m4-domain-routes.json"
test "$(json_get "$evidence/m4-domain-routes.json" access_state.serving)" = True
wait_view "$app" '"services"'
cp "$evidence/operations-view.json" "$evidence/operations-before-fault.json"

# Explicit fault: only the task-owned worker container is stopped. The ingress
# remains reachable while the scheduler's durable Agent observation reports it.
worker=$(docker ps --filter "label=open-card.deployment-id=$deployment" --filter 'label=open-card.service-name=worker' --format '{{.Names}}')
test -n "$worker"
curl -fsS "$api/api/v1/deployments/$deployment" >"$evidence/deployment-view-before-fault.json"
ingress_url=$(json_get "$evidence/deployment-view-before-fault.json" deployment.url)
volume_name=$(json_get "$evidence/deployment-view-before-fault.json" deployment.volume_claims.0.name)
volume_checksum_before=$(volume_checksum "$volume_name")
runtime_identity_snapshot "$evidence/service-identities-before-fault.json"
sample_all_services "before-load"
controlled_ingress_load "$ingress_url" "$evidence/traffic-load-before-fault.txt"
sample_all_services "after-load"
compare_observation_database "$deployment" after-load
curl -fsS "$ingress_url" >"$evidence/traffic-before-fault.txt"
# A manual stop is the deterministic task-scoped fault for a service whose
# immutable restart policy is on-failure. SIGKILL exits 137 and Docker may
# immediately auto-restart it before the observation scheduler can persist the
# unhealthy fact, which would test Docker's restart policy rather than M4's
# exact-service recovery path.
docker stop --time 1 "$worker" >/dev/null
wait_view "$app" '"health":"unhealthy"'
cp "$evidence/operations-view.json" "$evidence/operations-after-fault.json"
curl -fsS "$ingress_url" >"$evidence/traffic-during-worker-fault.txt"
restart_status=
for restart_attempt in $(seq 1 20); do
  wait_view "$app" '"health":"unhealthy"'
  version=$(json_get "$evidence/operations-view.json" version)
  restart_payload=$(python3 - "$version" <<'PY'
import json,sys
print(json.dumps({"action":"restart","expected_version":sys.argv[1],"reason":"restart exact unhealthy worker token=m4-log-canary"},separators=(',',':')))
PY
)
  restart_status=$(curl -sS -o "$evidence/restart-attempt-$restart_attempt.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: m4-restart-$run_id" --data "$restart_payload" "$api/api/v1/applications/$app/operations")
  cp "$evidence/restart-attempt-$restart_attempt.json" "$evidence/restart.json"
  [[ "$restart_status" = 202 ]] && break
  [[ "$restart_status" = 409 ]] || { cat "$evidence/restart.json" >&2; exit 1; }
  sleep 0.25
done
test "$restart_status" = 202
operation=$(json_get "$evidence/restart.json" operation_id)
state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM operations WHERE id='$operation'" | tr -d '[:space:]')
test "$state" = succeeded
curl -fsS "$ingress_url" >"$evidence/traffic-after-restart.txt"
runtime_identity_snapshot "$evidence/service-identities-after-restart.json"
worker=$(docker ps --filter "label=open-card.deployment-id=$deployment" --filter 'label=open-card.service-name=worker' --format '{{.Names}}')
sample_all_services "post-restart"
controlled_ingress_load "$ingress_url" "$evidence/traffic-load-after-restart.txt"
sample_all_services "post-load"
compare_observation_database "$deployment" post-load
assert_exact_service_restart "$evidence/service-identities-before-fault.json" "$evidence/service-identities-after-restart.json" worker "$evidence/traffic-before-fault.txt" "$evidence/traffic-after-restart.txt"
assert_observation_recovery_and_dedupe "$deployment" after-load post-restart
assert_volume_preserved "$volume_name" "$volume_checksum_before"
wait_view "$app" '"health":"healthy"'
cp "$evidence/operations-view.json" "$evidence/operations-after-restart.json"

# M4-OPS-E2E-002: redeploy the current immutable release. The HTTP request
# returns while the parent remains running; every durable phase is observed
# and the control plane/Agent are restarted at the phase boundary.
redeploy_expected=$(json_get "$evidence/operations-view.json" version)
redeploy_operation=$(submit_rollout_operation redeploy "$redeploy_expected" "m4-redeploy-$run_id" "$evidence/redeploy.json" "" redeploy)
wait_operation_state "$redeploy_operation" succeeded
wait_rollout_phase "$redeploy_operation" completed
read -r redeploy_old redeploy_candidate < <(psql "$database_url" -X -Aqt -F ' ' -c "SELECT source_deployment_id,candidate_deployment_id FROM m4_rollout_coordinations WHERE operation_id='$redeploy_operation'")
assert_rollout_phase_contract "$redeploy_operation" "$redeploy_candidate" "$redeploy_old"
assert_rollout_replay_and_stale redeploy "$redeploy_expected" "m4-redeploy-$run_id" "$redeploy_operation" "$evidence/redeploy-stale.json" "$evidence/redeploy-replay.json"
assert_audit_outbox_and_idempotency "$redeploy_operation" "$evidence/redeploy-replay.json" 409
assert_volume_preserved "$volume_name" "$volume_checksum_before"

# Roll back only to the immediately previous successful immutable Release;
# this changes code/release identity, never the retained data volume.
curl -fsS "$api/api/v1/applications/$app/operations" >"$evidence/operations-before-rollback.json"
rollback_expected=$(json_get "$evidence/operations-before-rollback.json" version)
rollback_operation=$(submit_rollout_operation rollback "$rollback_expected" "m4-rollback-$run_id" "$evidence/rollback.json" "" rollback)
wait_operation_state "$rollback_operation" rolled_back
wait_rollout_phase "$rollback_operation" completed
read -r rollback_old rollback_candidate < <(psql "$database_url" -X -Aqt -F ' ' -c "SELECT source_deployment_id,candidate_deployment_id FROM m4_rollout_coordinations WHERE operation_id='$rollback_operation'")
assert_rollout_phase_contract "$rollback_operation" "$rollback_candidate" "$rollback_old"
assert_rollout_replay_and_stale rollback "$rollback_expected" "m4-rollback-$run_id" "$rollback_operation" "$evidence/rollback-stale.json" "$evidence/rollback-replay.json"
assert_audit_outbox_and_idempotency "$rollback_operation" "$evidence/rollback-replay.json" 409
assert_volume_preserved "$volume_name" "$volume_checksum_before"

# Route failure/candidate cleanup is intentionally fail-closed unless the
# canonical VM supplies an explicit task-scoped Caddy fault fixture.
run_route_failure_contract

curl -fsS "$api/api/v1/applications/$app/logs" >"$evidence/logs-ordinary.json"
python3 - "$evidence/logs-ordinary.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
assert value['mode']=='ordinary' and value['summary']['raw_logs_available'] is False
assert 'items' not in value
PY
curl -fsS "$api/api/v1/applications/$app/logs?limit=100" >"$evidence/logs-operator.json"
python3 - "$evidence/logs-operator.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1])); categories={item['category'] for item in value['items']}
assert value['mode']=='operator'
assert {'build','runtime','audit'}.issubset(categories), categories
assert 'm4-log-canary' not in json.dumps(value)
PY

# Directed LOG-001/002/003 execution. The product-owned collector creates a
# typed service_group.logs Agent task; this runner only discovers its durable
# stream identity through the read-only index and then executes the checked-in
# helper. No log file or PostgreSQL fact is manufactured by the fixture.
runtime_log_path=
for _ in $(seq 1 240); do
  runtime_log_path=$(psql "$database_url" -X -Aqt -c "SELECT path FROM m4_log_indexes WHERE application_id='$app' AND category='runtime' AND service_name='frontend' AND retired_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1" | tr -d '[:space:]')
  if [[ -n "$runtime_log_path" && -f "$runtime_log_path" ]]; then
    runtime_stream=$(basename "$(dirname "$runtime_log_path")")
    runtime_segment_count=$(find "$OPEN_CARD_LOG_ROOT/runtime/$runtime_stream" -maxdepth 1 -type f -name 'segment-*.log' | wc -l)
    if [[ "$runtime_segment_count" -ge 2 ]] && grep -R -a -Fq 'event=http_request' "$OPEN_CARD_LOG_ROOT/runtime/$runtime_stream"; then
      break
    fi
  fi
  sleep 0.25
done
test -n "$runtime_log_path"
runtime_stream=$(basename "$(dirname "$runtime_log_path")")
test "$(find "$OPEN_CARD_LOG_ROOT/runtime/$runtime_stream" -maxdepth 1 -type f -name 'segment-*.log' | wc -l)" -ge 2
env \
  M4_LOG_GATE_EXECUTE=1 \
  OPEN_CARD_M4_AUTH_SESSION="$m4_admin_session" \
  M4_LOG_GATE_API="$api" \
  M4_LOG_GATE_EVIDENCE="$evidence/log-gates" \
  M4_LOG_GATE_WORK="$work/log-gates" \
  M4_LOG_GATE_TASK_PREFIX="$task_prefix" \
  M4_LOG_GATE_APP_ID="$app" \
  M4_LOG_GATE_ENVIRONMENT_ID="$environment" \
  M4_LOG_GATE_SOURCE_TEMPLATE_DIR="$stage" \
  M4_LOG_GATE_LOG_ROOT="$OPEN_CARD_LOG_ROOT" \
  M4_LOG_GATE_DATABASE_URL="$database_url" \
  M4_LOG_GATE_RUN_ID="$run_id" \
  M4_LOG_GATE_RUNTIME_STREAM="$runtime_stream" \
  M4_LOG_GATE_RUNTIME_MARKER='event=http_request' \
  M4_LOG_GATE_RUNTIME_MAX_FILE_BYTES="${OPEN_CARD_LOG_MAX_FILE_BYTES:?}" \
  M4_LOG_GATE_REDACTION_CANARY=m4-log-canary \
  bash "$runner_dir/clean_worker_m4_log_gate_guest.sh" >"$evidence/log-gates.markers"

# Internal HTTPS receiver uses a task-only CA and a fixed fixture hostname;
# the production webhook provider cannot route arbitrary private DNS names.
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=opencard-m4-fixture-ca -days 1 -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=opencard-webhook-fixture.test -keyout "$work/receiver.key" -out "$work/receiver.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:opencard-webhook-fixture.test\n' >"$work/receiver.ext"
openssl x509 -req -in "$work/receiver.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 -extfile "$work/receiver.ext" -out "$work/receiver.crt" >/dev/null 2>&1
install -m 0644 "$work/ca.crt" /usr/local/share/ca-certificates/opencard-m4-webhook-fixture.crt
update-ca-certificates >/dev/null
printf '127.0.0.1 opencard-webhook-fixture.test\n' >>/etc/hosts
host_entry_added=1
receiver_status="$work/receiver-status"
printf '204\n' >"$receiver_status"
python3 - "$work/receiver.crt" "$work/receiver.key" "$evidence/receiver-capture.ndjson" "$receiver_port" "$receiver_status" <<'PY' >"$evidence/receiver.log" 2>&1 &
import http.server,json,ssl,sys,threading
cert,key,capture,port,status_file=sys.argv[1:]
status_lock=threading.Lock()
def response_status():
  with status_lock:
    try:
      mode=open(status_file).read().strip()
    except OSError:
      mode='500'
    if mode == '500-once':
      # The first failure is deterministic and task-local; the receiver itself
      # switches to success so the durable controller must perform the retry.
      with open(status_file,'w') as f: f.write('204\n')
      return 500
    try:
      status=int(mode)
    except ValueError:
      status=500
    return status if 100 <= status <= 599 else 500
class H(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
    body=self.rfile.read(int(self.headers.get('content-length','0')))
    status=response_status()
    with open(capture,'a') as f: f.write(json.dumps({'event_id':self.headers.get('X-Open-Card-Event-ID'),'event_type':self.headers.get('X-Open-Card-Event-Type'),'timestamp':self.headers.get('X-Open-Card-Timestamp'),'signature':self.headers.get('X-Open-Card-Signature'),'status':status,'body':body.decode('utf-8')})+'\n')
    self.send_response(status); self.end_headers()
  def log_message(self,*args): pass
s=http.server.ThreadingHTTPServer(('127.0.0.1',int(port)),H)
tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(certfile=cert,keyfile=key)
s.socket=tls.wrap_socket(s.socket,server_side=True)
s.serve_forever()
PY
receiver_pid=$!
for _ in $(seq 1 100); do
  ss -ltnH 'sport = :19443' | grep -q '127.0.0.1:19443' && break
  sleep 0.1
done
ss -ltnH 'sport = :19443' | grep -q '127.0.0.1:19443'
webhook_secret=$work/webhook-secret.json
printf 'm4-fixture-signing-key' | sudo -u opencard "$secretctl" --root "$OPEN_CARD_SECRET_ROOT" --material-root "$OPEN_CARD_SECRET_MATERIAL_ROOT" --master-key "$OPEN_CARD_SECRET_MASTER_KEY" --id "m4-webhook-$run_id" --name webhook --version v1 >"$webhook_secret"
webhook_payload=$(python3 - "$webhook_secret" "$receiver_port" <<'PY'
import json,sys
print(json.dumps({'url':'https://opencard-webhook-fixture.test:'+sys.argv[2]+'/events','secret_ref':json.load(open(sys.argv[1])),'event_types':['notification.occurrence','notification.escalation','notification.recovery']},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-webhook-$run_id" --data "$webhook_payload" "$api/api/v1/applications/$app/webhooks" >"$evidence/webhook-config.json"
webhook_id=$(json_get "$evidence/webhook-config.json" endpoint.id)
psql "$database_url" -X -Aqt -F '|' -c "SELECT event_types::text FROM m4_webhook_endpoints WHERE id='$webhook_id'" >"$evidence/webhook-event-types.txt"
grep -Fq 'notification.occurrence' "$evidence/webhook-event-types.txt"
grep -Fq 'notification.escalation' "$evidence/webhook-event-types.txt"
grep -Fq 'notification.recovery' "$evidence/webhook-event-types.txt"
# First test establishes the normal delivered path. The second test uses a
# distinct idempotency key and starts with a receiver-controlled one-shot 5xx;
# the durable worker must persist retry_wait, replay the same event ID, and
# finish delivered after the fixture has switched back to 204.
curl -fsS -X POST -H "Idempotency-Key: m4-webhook-test-initial-$run_id" "$api/api/v1/applications/$app/webhooks/$webhook_id/test" >"$evidence/webhook-test-initial.json"
for _ in $(seq 1 100); do
  psql "$database_url" -X -Aqt -F '|' -c "SELECT delivery_status,attempt_count FROM m4_webhook_events WHERE endpoint_id='$webhook_id' ORDER BY created_at DESC LIMIT 1" >"$evidence/webhook-ledger-initial.txt"
  grep -Eq '^delivered\|1$' "$evidence/webhook-ledger-initial.txt" && break
  sleep 0.1
done
grep -Eq '^delivered\|1$' "$evidence/webhook-ledger-initial.txt"
printf '500-once\n' >"$receiver_status"
curl -fsS -X POST -H "Idempotency-Key: m4-webhook-test-retry-$run_id" "$api/api/v1/applications/$app/webhooks/$webhook_id/test" >"$evidence/webhook-test-retry.json"
for _ in $(seq 1 160); do
  psql "$database_url" -X -Aqt -F '|' -c "SELECT delivery_status,attempt_count FROM m4_webhook_events WHERE endpoint_id='$webhook_id' ORDER BY created_at DESC LIMIT 1" >"$evidence/webhook-ledger-retry.txt"
  grep -Eq '^delivered\|2$' "$evidence/webhook-ledger-retry.txt" && break
  sleep 0.1
done
grep -Eq '^delivered\|2$' "$evidence/webhook-ledger-retry.txt"
test -s "$evidence/receiver-capture.ndjson"
python3 - "$evidence/receiver-capture.ndjson" <<'PY'
import collections,hashlib,hmac,json,sys
records=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert any(item.get('status') == 500 for item in records), records
assert any(item.get('status') == 204 for item in records), records
ids=collections.defaultdict(list)
for item in records:
  ids[item.get('event_id')].append(item)
replayed=[items for event_id,items in ids.items() if event_id and len(items) >= 2]
assert replayed, records
assert any(any(item.get('status') == 500 for item in items) and any(item.get('status') == 204 for item in items) for items in replayed), records
for items in replayed:
  signatures={item.get('signature') for item in items}
  assert len(signatures) == 1, items
for item in records:
  event_id=item.get('event_id'); timestamp=item.get('timestamp'); signature=item.get('signature'); body=item.get('body','').encode()
  assert event_id and timestamp and signature, item
  signed=(str(int(timestamp))+'.'+event_id+'.').encode()+body
  expected='sha256='+hmac.new(b'm4-fixture-signing-key',signed,hashlib.sha256).hexdigest()
  assert hmac.compare_digest(signature,expected), item
PY
! grep -R -a -E 'm4-fixture-signing-key|PRIVATE KEY|BEGIN .*KEY' "$evidence" /var/log/open-card /var/lib/open-card/ai 2>/dev/null
cp "$evidence/webhook-ledger-retry.txt" "$evidence/webhook-ledger.txt"

# Exercise actual operation failure -> escalation -> recovery notifications,
# including durable retry across the embedded worker/control-plane restart.
env \
  OPEN_CARD_M4_WEBHOOK_LIFECYCLE_EXECUTE=1 \
  OPEN_CARD_M4_API_BASE_URL="$api" \
  OPEN_CARD_M4_WEBHOOK_APPLICATION_ID="$app" \
  OPEN_CARD_M4_WEBHOOK_EVIDENCE_DIR="$evidence/webhook-lifecycle" \
  OPEN_CARD_M4_WEBHOOK_WORK_DIR="$work/webhook-lifecycle" \
  OPEN_CARD_M4_WEBHOOK_RUN_ID="$run_id" \
  OPEN_CARD_M4_WEBHOOK_RECEIVER_PORT=19444 \
  bash "$runner_dir/clean_worker_m4_webhook_lifecycle_guest.sh" >"$evidence/webhook-lifecycle.markers"

final_deployment=$(psql "$database_url" -X -Aqt -c "SELECT id FROM deployments WHERE environment_id='$environment' AND state='serving' ORDER BY updated_at DESC,id DESC LIMIT 1" | tr -d '[:space:]')
test -n "$final_deployment"
worker=$(docker ps --filter "label=open-card.deployment-id=$final_deployment" --filter 'label=open-card.service-name=worker' --format '{{.Names}}')
test -n "$worker"
docker inspect "$worker" >"$evidence/worker-inspect-after-restart.json"
docker stats --no-stream "$worker" >"$evidence/worker-stats-after-restart.txt"
psql "$database_url" -X -Aqt -F '|' -c "SELECT service_name,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count FROM m4_service_observations WHERE deployment_id='$final_deployment' ORDER BY observed_at DESC" >"$evidence/independent-observations.txt"
grep -Fq 'worker|' "$evidence/independent-observations.txt"
snapshot "$evidence/objects-after.json"
printf '%s\n' '{"sequence":1,"actor":"m4-fixture","idempotency_key":"m4-restart","evidence_refs":["container_inspect","database_query","receiver_capture","traffic","metrics"]}' >"$evidence/events.ndjson"
printf '%s\n' '{"task_prefix":"opencard-mvp-fa8f8eab","webhook_secret_ref":"[redacted]","evidence_types":["container_inspect","database_query","receiver_capture","traffic","metrics"]}' >"$evidence/inputs.redacted.json"
started=$(date -u +%FT%TZ)
printf '{"test_id":"OPS-E2E-001","version":"0.4.0","started_at":"%s","finished_at":"%s","exit_code":0,"conclusion":"NOT_CLAIMED","failure_reason":"runner contract only; canonical VM and strict M0-M4 evidence have not been executed","evidence_types":["container_inspect","database_query","receiver_capture","traffic","metrics"]}\n' "$started" "$started" >"$evidence/result.json"
(cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
# These labels describe runner-contract coverage only. They do not write or
# assert any M4 gate conclusion; independent evidence/JUnit validation still
# decides whether a milestone can pass.
printf '%s\n' \
  'RUNNER_CONTRACT_ONLY=1' \
  'M4_GATE=NOT_CLAIMED' \
  'OBS-001=RUNNER_CONTRACT_ONLY' 'OBS-002=RUNNER_CONTRACT_ONLY' \
  'OPS-E2E-001=RUNNER_CONTRACT_ONLY' 'OPS-E2E-002=RUNNER_CONTRACT_ONLY' \
  'LOG-INT-001=RUNNER_CONTRACT_ONLY' 'LOG-001=RUNNER_CONTRACT_ONLY' \
  'LOG-002=RUNNER_CONTRACT_ONLY' 'LOG-003=RUNNER_CONTRACT_ONLY' \
  'SEC-LOG-001=RUNNER_CONTRACT_ONLY' 'WEBHOOK-INT-001=RUNNER_CONTRACT_ONLY' \
  'VOL-FAULT-001=RUNNER_CONTRACT_ONLY' 'FAULT-WEBHOOK-001=RUNNER_CONTRACT_ONLY' \
  'CANDIDATE-CLEANUP=RUNNER_CONTRACT_ONLY' \
  'FAULT-RESTART-RECOVERY=RUNNER_CONTRACT_ONLY' \
  'CT-NOTIFY=RUNNER_CONTRACT_ONLY' 'SEC-WEBHOOK=RUNNER_CONTRACT_ONLY' \
  'FAULT-WEBHOOK=RUNNER_CONTRACT_ONLY' 'M4_WEBHOOK_GATE=NOT_CLAIMED'
