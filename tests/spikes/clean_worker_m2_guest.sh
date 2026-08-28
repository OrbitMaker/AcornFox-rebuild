#!/usr/bin/env bash
set -euo pipefail

# M2 real clean-worker acceptance.  This runner is deliberately root-only and
# uses public control-plane APIs plus read-only PostgreSQL/Docker facts.  It
# never edits a domain outcome directly and it never creates an unscoped
# container, volume, network, registry, or host listener.

task_prefix=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
evidence_root=/var/lib/opencard-mvp-fa8f8eab/evidence/m2-real
work_root=/var/lib/opencard-mvp-fa8f8eab/m2-real-work
registry_root=/var/lib/open-card/build-work/opencard-mvp-fa8f8eab-m2-registry
registry_script=$registry_root/registry_fixture.py
registry_ready_file=$registry_root/data/ready.json
registry_host=${OPEN_CARD_M2_REGISTRY_HOST:-127.0.0.1}
registry_port=${OPEN_CARD_M2_REGISTRY_PORT:-45532}
registry_addr=$registry_host:$registry_port
run_id=$(openssl rand -hex 8)

test "$(id -u)" -eq 0
test -f /etc/opencard-mvp-fa8f8eab-clean-worker
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
test -f /etc/open-card/server.env
set -a
source /etc/open-card/server.env
set +a

server_addr=${OPEN_CARD_SERVER_ADDR:-127.0.0.1:8080}
api_base=http://$server_addr
agent_capabilities_path=${OPEN_CARD_M2_AGENT_CAPABILITIES_PATH:-/api/v1/agents/capabilities}
agent_capability_negative_path=${OPEN_CARD_M2_AGENT_CAPABILITY_NEGATIVE_PATH:-/api/v1/agents/capabilities/legacy-negative}
fixture_root=${OPEN_CARD_M2_FIXTURE_ROOT:-/opt/opencard-offline/outer/payload/tests/fixtures/m2}
static_server=${OPEN_CARD_STATIC_SERVER_BINARY:-/opt/open-card/current/bin/open-card-static-server}
secretctl=${OPEN_CARD_SECRETCTL_BINARY:-/opt/open-card/current/bin/open-card-secretctl}
imagegc=${OPEN_CARD_IMAGEGC_BINARY:-/opt/open-card/current/bin/open-card-imagegc}
secret_root=${OPEN_CARD_SECRET_ROOT:?OPEN_CARD_SECRET_ROOT is required}
secret_material_root=${OPEN_CARD_SECRET_MATERIAL_ROOT:?OPEN_CARD_SECRET_MATERIAL_ROOT is required}
secret_master_key=${OPEN_CARD_SECRET_MASTER_KEY:?OPEN_CARD_SECRET_MASTER_KEY is required}
database_url=${OPEN_CARD_DATABASE_URL:?OPEN_CARD_DATABASE_URL is required}
source_upload_root=${OPEN_CARD_SOURCE_UPLOAD_ROOT:?OPEN_CARD_SOURCE_UPLOAD_ROOT is required}

for required in \
  "$fixture_root/registry_fixture.py" \
  "$fixture_root/compose/mixed-services.json" \
  "$fixture_root/compose/mixed-services-v2.json" \
  "$fixture_root/compose/optional-worker.json" \
  "$fixture_root/compose/rolling-failure.json" \
  "$static_server" "$secretctl" "$imagegc"; do
  test -f "$required"
done
test -x "$static_server"
test -x "$secretctl"
test -x "$imagegc"
test "$(systemctl is-active open-card-server)" = active
test "$(systemctl is-active open-card-agent)" = active
test "$evidence_root" = /var/lib/opencard-mvp-fa8f8eab/evidence/m2-real
rm -rf -- "$evidence_root"
install -d -m 0750 "$evidence_root" "$work_root" "$registry_root"
chmod 0750 "$evidence_root" "$work_root" "$registry_root"
chown opencard:opencard "$registry_root"
install -m 0555 -o opencard -g opencard "$fixture_root/registry_fixture.py" "$registry_script"
curl -fsS "$api_base/readyz" >/dev/null

# Capability negotiation is a prerequisite, not a post-hoc observation. The
# registered Agent must advertise the complete aggregate runtime capability;
# the legacy probe must fail closed before it can create a group task.
capabilities_ready=0
for _ in $(seq 1 100); do
  curl -fsS --max-time 5 "$api_base$agent_capabilities_path" >"$evidence_root/agent-capabilities.json" || true
  if python3 - "$evidence_root/agent-capabilities.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
capabilities = value.get("capabilities", value.get("items", []))
if isinstance(capabilities, dict):
    capabilities = capabilities.get("capabilities", [])
required = {"runtime.deploy_group", "runtime.observe_group", "runtime.rollback_group", "runtime.destroy_group"}
if not required.issubset(set(capabilities)):
    raise SystemExit("Agent did not negotiate the complete runtime-group capability")
PY
  then
    capabilities_ready=1
    break
  fi
  sleep 0.1
done
test "$capabilities_ready" = 1

cleanup_done=0
registry_pid=
secret_ref_file=
token_file=
control_token_file=
source_archive=
app_id=
group_id=
deployment_id=
registry_control_token=
cleanup_group_ids=()
cleanup_deployment_ids=()
group_version=0
deployments_destroyed=0
wait_task_terminal() {
  local task_id=$1 state=
  for _ in $(seq 1 300); do
    [[ "$task_id" =~ ^task_[a-f0-9]{32}$ ]] || return 1
    state=$(psql "$database_url" -X -Aqt \
      -c "SELECT state FROM task_leases WHERE task_id='$task_id'" 2>/dev/null | tr -d '[:space:]')
    case "$state" in
      completed|failed|cancelled) return 0 ;;
    esac
    sleep 0.1
  done
  echo "controller task did not become terminal: $task_id ($state)" >&2
  return 1
}

wait_operation_terminal() {
  local operation_id=$1 state=
  [[ "$operation_id" =~ ^(op|operation)_[a-f0-9]{32}$ ]] || return 1
  for _ in $(seq 1 300); do
    state=$(psql "$database_url" -X -Aqt \
      -c "SELECT state FROM operations WHERE id='$operation_id'" 2>/dev/null | tr -d '[:space:]')
    case "$state" in
      succeeded|failed|cancelled|rolled_back) return 0 ;;
    esac
    sleep 0.1
  done
  echo "controller operation did not become terminal: $operation_id ($state)" >&2
  return 1
}

destroy_deployments_serially() {
  (( deployments_destroyed )) && return
  local cleanup_deployment cleanup_key cleanup_output cleanup_status cleanup_task
  for cleanup_deployment in "${cleanup_deployment_ids[@]:-}"; do
    [[ -z "$cleanup_deployment" ]] && continue
    cleanup_key="m2-cleanup-$run_id-$cleanup_deployment"
    cleanup_output="$evidence_root/cleanup-deployment-$cleanup_deployment.json"
    cleanup_status=$(curl -sS --max-time 15 -o "$cleanup_output" -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' \
      -H "Idempotency-Key: $cleanup_key" \
      --data "{\"preserve_volumes\":true,\"operation\":{\"idempotency_key\":\"$cleanup_key\"}}" \
      "$api_base/api/v1/deployments/$cleanup_deployment/destroy") || cleanup_status=000
    if [[ "$cleanup_status" != 202 ]]; then
      echo "deployment destroy was not accepted: $cleanup_deployment ($cleanup_status)" >&2
      return 1
    fi
    cleanup_task=$(json_value "$cleanup_output" TaskID 2>/dev/null || json_value "$cleanup_output" task_id)
    wait_task_terminal "$cleanup_task"
  done
  deployments_destroyed=1
}

cleanup() {
  (( cleanup_done )) && return
  cleanup_done=1
  local restore_errexit=0
  case "$-" in
    *e*) restore_errexit=1 ;;
  esac
  set +e
  # Destruction goes through the public API first.  The exact Docker cleanup
  # below is a leak assertion, not a broad prune or a recovery shortcut.
  destroy_deployments_serially || true
  if [[ -n "$registry_pid" ]]; then
    kill "$registry_pid" >/dev/null 2>&1 || true
    wait "$registry_pid" >/dev/null 2>&1 || true
    registry_pid=
  fi
  if [[ -n "$token_file" && -e "$token_file" ]]; then
    shred -u -- "$token_file" >/dev/null 2>&1 || rm -f -- "$token_file"
  fi
  if [[ -n "$control_token_file" && -e "$control_token_file" ]]; then
    shred -u -- "$control_token_file" >/dev/null 2>&1 || rm -f -- "$control_token_file"
  fi
  if [[ -n "$secret_ref_file" && -e "$secret_ref_file" ]]; then
    rm -f -- "$secret_ref_file"
  fi
  rm -f -- "$source_archive" "$work_root"/*.tar
  rm -rf -- "$registry_root" "$work_root/source" "$work_root/failed-source"
  if (( restore_errexit )); then
    set -e
  fi
}
trap cleanup EXIT INT TERM

json_value() {
  local file=$1 expression=$2
  python3 - "$file" "$expression" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
expression = sys.argv[2]
for part in expression.split('.'):
    if not part:
        continue
    if isinstance(value, dict):
        value = value[part]
    elif isinstance(value, list) and part.isdigit():
        value = value[int(part)]
    else:
        raise SystemExit(f"missing JSON path {expression}")
if isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
elif isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

request_json() {
  local method=$1 path=$2 payload=$3 output=$4
  curl -sS --connect-timeout 5 --max-time 90 -o "$output" -w '%{http_code}' \
    -X "$method" -H 'Content-Type: application/json' \
    -H "Idempotency-Key: ${M2_IDEMPOTENCY_KEY:-m2-${RANDOM}-${RANDOM}}" \
    --data-binary "$payload" "$api_base$path"
}

request_json_file() {
  local method=$1 path=$2 input=$3 output=$4
  curl -sS --connect-timeout 5 --max-time 90 -o "$output" -w '%{http_code}' \
    -X "$method" -H 'Content-Type: application/json' \
    -H "Idempotency-Key: ${M2_IDEMPOTENCY_KEY:-m2-${RANDOM}-${RANDOM}}" \
    --data-binary "@$input" "$api_base$path"
}

expect_failure() {
  local status=$1 output=$2
  [[ "$status" =~ ^4[0-9][0-9]$ || "$status" =~ ^5[0-9][0-9]$ ]]
  test -s "$output"
  if grep -Eqi '"(canary|password|token|secret)"[[:space:]]*:' "$output"; then
    echo "failure response contains a secret-shaped field: $output" >&2
    return 1
  fi
}

db_counts() {
  psql "$database_url" -X -Aqt -F '|' -c \
    "SELECT (SELECT count(*) FROM source_revisions),(SELECT count(*) FROM builds),(SELECT count(*) FROM releases),(SELECT count(*) FROM deployments),(SELECT count(*) FROM task_leases),(SELECT count(*) FROM service_groups),(SELECT count(*) FROM service_group_specs),(SELECT count(*) FROM service_group_import_reports),(SELECT count(*) FROM m2_service_group_requests),(SELECT count(*) FROM outbox_events),(SELECT count(*) FROM audit_evidence);" \
    | tr -d '[:space:]'
}

task_container_ids() {
  docker ps -a --format '{{.ID}}|{{.Names}}|{{.Label "open-card.task-prefix"}}' \
    | awk -F'|' -v p="$task_prefix" '$3 == p || index($2,p"-") == 1 {print $1}' | sort
}

task_container_count() {
  task_container_ids | awk 'NF {count++} END {print count+0}'
}

task_volume_names() {
  docker volume ls --format '{{.Name}}' | awk -v p="$task_prefix" 'index($0,p"-") == 1' | sort
}

task_network_names() {
  docker network ls --format '{{.Name}}' | awk -v p="$task_prefix" 'index($0,p"-") == 1' | sort
}

snapshot() {
  local output=$1
  {
    printf '{"db_counts":"%s",' "$(db_counts)"
    printf '"containers":%s,' "$(task_container_count)"
    printf '"container_ids":%s,' "$(task_container_ids | python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()]))')"
    printf '"volumes":%s,' "$(task_volume_names | python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()]))')"
    printf '"networks":%s}' "$(task_network_names | python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()]))')"
  } >"$output"
}

assert_volume_checksum() {
  local phase=$1
  local current_mountpoint current_checksum
  current_mountpoint=$(docker volume inspect "$volume_name" --format '{{.Mountpoint}}')
  current_checksum=sha256:$(sha256sum "$current_mountpoint/m2-volume-canary" | awk '{print $1}')
  test "$current_checksum" = "$volume_checksum_v1"
  printf '{"phase":"%s","volume_id":"%s","name":"%s","checksum":"%s"}\n' \
    "$phase" "$volume_id" "$volume_name" "$current_checksum" >"$evidence_root/volume-$phase.json"
}

wait_ready() {
  for _ in $(seq 1 100); do
    curl -fsS "$api_base/readyz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

wait_json_state() {
  local path=$1 expression=$2 expected=$3 output=$4
  for _ in $(seq 1 180); do
    local status
    status=$(curl -sS --max-time 10 -o "$output" -w '%{http_code}' "$api_base$path") || status=000
    if [[ "$status" = 200 ]]; then
      local got
      got=$(json_value "$output" "$expression" 2>/dev/null || true)
      if [[ "$got" = "$expected" ]]; then
        return 0
      fi
      case "$got" in failed|cancelled|rolled_back)
        echo "unexpected terminal state $got for $path" >&2
        return 1
        ;;
      esac
    fi
    sleep 0.5
  done
  return 1
}

create_application() {
  local output=$1
  local status
  status=$(curl -sS --connect-timeout 5 --max-time 20 -o "$output" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' -H "Idempotency-Key: m2-application-create-$run_id" \
    --data '{"name":"m2-real-multiservice"}' "$api_base/api/v1/applications")
  test "$status" = 201
  app_id=$(json_value "$output" application.id)
  environment_id=$(json_value "$output" environment_id)
  application_operation_id=$(json_value "$output" operation_id)
  test -n "$app_id" -a -n "$environment_id"
  wait_operation_terminal "$application_operation_id"
}

stage_source() {
  local source_name=$1 source_dir=$2
  local stage="$work_root/source/$source_name"
  rm -rf -- "$stage"
  install -d -m 0750 "$stage"
  cp -a -- "$fixture_root/compose" "$stage/compose"
  cp -a -- "$fixture_root/services" "$stage/services"
  for service_dir in api frontend frontend-v2 worker worker-fail; do
    install -m 0755 "$static_server" "$stage/services/$service_dir/open-card-static-server"
  done
  find "$stage" -type f -exec chmod 0640 {} +
  chmod 0750 "$stage" "$stage/compose" "$stage/services"
  # The archive is stable across runs: no uid/gid, mtime, or filesystem order
  # from the host enters SourceRevision.
  source_archive="$work_root/$source_name.tar"
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -cf "$source_archive" -C "$stage" compose services
  chmod 0640 "$source_archive"
}

upload_source() {
  local source_name=$1 output=$2 status
  status=$(curl -sS --connect-timeout 5 --max-time 90 -o "$output" -w '%{http_code}' \
    -X POST -H 'Idempotency-Key: m2-source-'"$source_name" \
    -F "application_id=$app_id" -F 'kind=upload' -F "archive=@$source_archive;type=application/x-tar" \
    "$api_base/api/v1/sources")
  test "$status" = 201
  source_revision_id=$(json_value "$output" source_revision.id)
  source_digest=$(json_value "$output" source_revision.content_digest)
  test -n "$source_revision_id" -a -n "$source_digest"
  [[ "$source_digest" = sha256:* ]]
}

import_group() {
  local compose_file=$1 name=$2 output=$3 source_id=$4
  group_version=$((group_version + 1))
  local payload
  payload=$(python3 - "$compose_file" "$app_id" "$environment_id" "$name" "$source_id" "$group_version" <<'PY'
import json, sys
compose = json.load(open(sys.argv[1], encoding="utf-8"))
print(json.dumps({
    "application_id": sys.argv[2],
    "environment_id": sys.argv[3],
    "name": sys.argv[4],
    "source_revision_id": sys.argv[5],
    "version": int(sys.argv[6]),
    "compose": compose,
    "optional_services": ["optional-worker"] if "optional-worker" in sys.argv[1] else [],
}, sort_keys=True, separators=(",", ":")))
PY
  )
  local status
  status=$(request_json POST /api/v1/service-groups/import "$payload" "$output")
  test "$status" = 201
  group_id=$(json_value "$output" service_group.id)
  test -n "$group_id"
  cleanup_group_ids+=("$group_id")
  test "$(json_value "$output" report.accepted)" = true
  group_config_digest=$(python3 - "$output" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
group = value.get("service_group", {})
report = value.get("report", {})
digest = group.get("config_digest") or report.get("canonical_digest")
if not isinstance(digest, str) or not digest.startswith("sha256:"):
    raise SystemExit("service-group import omitted canonical digest")
print(digest)
PY
  )
}

create_release() {
  local output=$1 source_id=$2 registry_secret_ref=$3
  local payload
  payload=$(python3 - "$source_id" "$registry_secret_ref" "$group_version" <<'PY'
import json, sys
value = {
    "source_revision_id": sys.argv[1],
    "registries": [{"endpoint": "http://127.0.0.1:45532", "secret_ref": json.loads(sys.argv[2])}],
    "version": int(sys.argv[3]),
}
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
  )
  local status
  status=$(request_json POST "/api/v1/service-groups/$group_id/releases" "$payload" "$output")
  test "$status" = 201
  release_id=$(json_value "$output" release.id)
  release_config_digest=$(json_value "$output" release.config_digest)
  test -n "$release_id"
  [[ "$release_config_digest" = sha256:* ]]
  release_digests=$(json_value "$output" release.service_digests)
  test -n "$release_digests"
}

deploy_group() {
  local release=$1 output=$2 rollout_mode=${3:-initial} status
  local payload
  payload=$(python3 - "$release" "$rollout_mode" <<'PY'
import json, sys
print(json.dumps({
    "release_id": sys.argv[1],
    "rollout": {"mode": sys.argv[2], "preserve_old_until_healthy": sys.argv[2] == "rolling"},
    "operation": {"idempotency_key": "m2-deploy-" + sys.argv[1]},
}, sort_keys=True, separators=(",", ":")))
PY
  )
  status=$(request_json POST "/api/v1/service-groups/$group_id/deployments" "$payload" "$output")
  test "$status" = 202
  deployment_id=$(json_value "$output" deployment.id)
  test -n "$deployment_id"
  cleanup_deployment_ids+=("$deployment_id")
}

assert_group_containers() {
  local expected=$1
  local count
  count=$(docker ps --filter "label=open-card.task-prefix=$task_prefix" --filter "label=open-card.service-group-id=$group_id" --format '{{.ID}}' | awk 'NF {n++} END {print n+0}')
  test "$count" = "$expected"
  local names
  names=$(docker ps --filter "label=open-card.task-prefix=$task_prefix" --filter "label=open-card.service-group-id=$group_id" --format '{{.Names}}' | sort)
  test -n "$names"
  while read -r container; do
    [[ -z "$container" ]] && continue
    test "$(docker inspect "$container" --format '{{index .Config.Labels "open-card.task-prefix"}}')" = "$task_prefix"
    test "$(docker inspect "$container" --format '{{json .HostConfig.Binds}}')" = '[]' -o "$(docker inspect "$container" --format '{{json .HostConfig.Binds}}')" = null
    test "$(docker inspect "$container" --format '{{.HostConfig.Privileged}}')" = false
    test "$(docker inspect "$container" --format '{{.HostConfig.PidMode}}')" = ""
    ipc_mode=$(docker inspect "$container" --format '{{.HostConfig.IpcMode}}')
    test "$ipc_mode" = "" -o "$ipc_mode" = private
    test "$(docker inspect "$container" --format '{{.HostConfig.Memory}}')" -gt 0
    test "$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}')" -gt 0
    test "$(docker inspect "$container" --format '{{.HostConfig.PidsLimit}}')" -gt 0
  done <<<"$names"
}

assert_only_entry_exposed() {
  local exposed=0
  while read -r container; do
    [[ -z "$container" ]] && continue
    local bindings
    bindings=$(docker inspect "$container" --format '{{json .HostConfig.PortBindings}}')
    if [[ "$bindings" != null && "$bindings" != '{}' && "$bindings" != '[]' ]]; then
      exposed=$((exposed + 1))
      test "$(docker inspect "$container" --format '{{index .Config.Labels "open-card.service-role"}}')" = ingress
      [[ "$bindings" = *'"HostIp":"127.0.0.1"'* ]]
    fi
  done < <(docker ps --filter "label=open-card.task-prefix=$task_prefix" --filter "label=open-card.service-group-id=$group_id" --format '{{.Names}}')
  test "$exposed" = 1
}

assert_private_network() {
  local expected_services=${1:-db,api,worker,frontend}
  local network
  local group_segment=${group_id#group_}
  network=$(docker network ls --filter "label=open-card.task-prefix=$task_prefix" --filter "label=open-card.task=group" --format '{{.Name}}' | grep -F "$group_segment" | head -1)
  test -n "$network"
  test "$(docker network inspect "$network" --format '{{.Internal}}')" = true
  docker network inspect "$network" >"$evidence_root/service-network.json"
  python3 - "$evidence_root/service-network.json" "$expected_services" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
names = [item.get("Name", "") for item in value[0].get("Containers", {}).values()]
for service in sys.argv[2].split(","):
    if not any(name.endswith("-" + service) for name in names):
        raise SystemExit("private network omitted service " + service)
PY
}

assert_event_order() {
  local deployment=$1 output=$2
  local status curl_exit=0
  status=$(curl -sS --max-time 2 -o "$output" -w '%{http_code}' "$api_base/api/v1/deployments/$deployment/events") || curl_exit=$?
  test "$status" = 200
  test "$curl_exit" = 0 -o "$curl_exit" = 28
  python3 - "$output" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
events = []
for line in raw.splitlines():
    if line.startswith("data:"):
        try:
            events.append(json.loads(line[5:].strip()))
        except json.JSONDecodeError:
            pass
if not events:
    try:
        value = json.loads(raw)
        events = value.get("events", value if isinstance(value, list) else [])
    except json.JSONDecodeError:
        pass
seq = [int(item.get("sequence", 0)) for item in events if item.get("sequence") is not None]
if seq != sorted(set(seq)) or not seq:
    raise SystemExit("deployment events are not a durable increasing sequence")
states = [str(item.get("state", item.get("status", ""))) for item in events]
if not any(value in {"starting", "deploying", "running", "runtime_ready", "serving"} for value in states):
    raise SystemExit("deployment event stream omitted runtime progression")
PY
}

# Establish a strict before snapshot before the fixture registry, source
# revision, service group, or release exists.
snapshot "$evidence_root/objects-before.json"
base_db=$(db_counts)
base_containers=$(task_container_count)
test "$(task_volume_names)" = ""
test "$(task_network_names)" = ""

# Start the local registry fixture directly as the dedicated service user. It
# does not need a Docker socket or a host mount and is not part of the
# application ServiceGroup network.
test ! -e "$registry_root/ready.json"
test ! -e "$registry_ready_file"
test ! -e "$token_file"
token_file=$registry_root/token
control_token_file=$registry_root/control-token
registry_token=$(openssl rand -hex 32)
registry_control_token=$(openssl rand -hex 24)
umask 077
printf '%s' "$registry_token" >"$token_file"
printf '%s' "$registry_control_token" >"$control_token_file"
chown opencard:opencard "$token_file"
chown opencard:opencard "$control_token_file"
chmod 0400 "$token_file" "$control_token_file"
install -d -m 0750 -o opencard -g opencard "$registry_root/data"
sudo -u opencard env PYTHONUNBUFFERED=1 python3 "$registry_script" \
  --listen "$registry_addr" --data-root "$registry_root/data" \
  --ready-file "$registry_ready_file" --token-file "$token_file" \
  --control-token-file "$control_token_file" \
  --static-binary "$static_server" >"$evidence_root/registry.log" 2>&1 &
registry_pid=$!
for _ in $(seq 1 80); do
  [[ -s "$registry_ready_file" ]] && break
  kill -0 "$registry_pid" >/dev/null 2>&1 || { wait "$registry_pid"; exit 1; }
  sleep 0.1
done
test -s "$registry_ready_file"
curl -fsS "http://$registry_addr/v2/" >"$evidence_root/registry-v2.json"
python3 - "$registry_root/data/registry-map.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["schema"] == "m2-registry-fixture-v1"
assert value["platform"] == {"architecture": "amd64", "os": "linux"}
assert "opencard/m2/private" in value["private_repositories"]
assert value["repositories"]["opencard/m2/public"]["stable"].startswith("sha256:")
PY
cp -- "$registry_root/data/registry-map.json" "$evidence_root/registry-map.json"
chmod 0640 "$evidence_root/registry-map.json"

# Prove ImageResolver semantics independently of ServiceGroup deployment:
# public tags resolve, private tags require a SecretReference, and a later tag
# move cannot change a digest already recorded in a release.
public_resolve_payload=$(python3 - "$registry_addr" "$run_id" <<'PY'
import json, sys
print(json.dumps({"repository":"opencard/m2/public","tag":"stable","registry":"http://"+sys.argv[1],"platform":{"os":"linux","architecture":"amd64"},"operation":{"idempotency_key":"m2-image-public-v1-"+sys.argv[2]}}, separators=(",", ":")))
PY
)
status=$(request_json POST /api/v1/images/resolve "$public_resolve_payload" "$evidence_root/image-public-resolve.json")
test "$status" = 200
public_digest=$(json_value "$evidence_root/image-public-resolve.json" image.digest)
[[ "$public_digest" = sha256:* ]]
test "$(json_value "$evidence_root/image-public-resolve.json" image.repository)" = "$registry_addr/opencard/m2/public"
grep -Fq 'linux/amd64' "$evidence_root/image-public-resolve.json"

secret_ref_file=$work_root/registry-secret-reference.json
registry_secret_id=m2-registry-auth-$(printf '%s' "$registry_token" | sha256sum | cut -c1-12)
printf 'fixture:%s' "$registry_token" | sudo -u opencard "$secretctl" \
  --root "$secret_root" --material-root "$secret_material_root" \
  --master-key "$secret_master_key" --id "$registry_secret_id" --name registry-auth --version v1 \
  >"$secret_ref_file"
chmod 0640 "$secret_ref_file"
python3 - "$secret_ref_file" "$registry_secret_id" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value == {"id":sys.argv[2],"name":"registry-auth","provider":"filesystem-secret","version":"v1"}
PY
private_payload=$(python3 - "$registry_addr" "$secret_ref_file" "$run_id" <<'PY'
import json, sys
ref = json.load(open(sys.argv[2], encoding="utf-8"))
print(json.dumps({"repository":"opencard/m2/private","tag":"stable","registry":"http://"+sys.argv[1],"platform":{"os":"linux","architecture":"amd64"},"secret_ref":ref,"operation":{"idempotency_key":"m2-image-private-v1-"+sys.argv[3]}}, separators=(",", ":")))
PY
)
status=$(request_json POST /api/v1/images/resolve "$private_payload" "$evidence_root/image-private-resolve.json")
test "$status" = 200
private_digest=$(json_value "$evidence_root/image-private-resolve.json" image.digest)
[[ "$private_digest" = sha256:* ]]
bad_private_payload=$(python3 - "$private_payload" "$run_id" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
value["secret_ref"]["id"] = "m2-registry-auth-missing"
value["operation"]["idempotency_key"] = "m2-image-private-missing-" + sys.argv[2]
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
)
status=$(request_json POST /api/v1/images/resolve "$bad_private_payload" "$evidence_root/image-private-bad.json")
expect_failure "$status" "$evidence_root/image-private-bad.json"
printf '%s\n' 'IMG-INT-001=PASS' 'IMG-INT-002=PASS' 'CT-IMAGE-001=PASS'

# Import negative Compose cases through the public import boundary.  Every
# document must be rejected before a ServiceGroup or Release is persisted.
create_application "$evidence_root/application.json"
# The generic application controller records its own durable operation before
# M2 begins. create_application waits for its exact terminal operation so the
# environment uniqueness gate cannot be mistaken for an M2 failure.
stage_source negative-source "$fixture_root"
upload_source negative-source "$evidence_root/negative-source.json"
negative_before=$(db_counts)
for negative in "$fixture_root"/compose/invalid-*.json; do
  name=$(basename "$negative" .json)
  output="$evidence_root/$name-response.json"
  payload_file="$work_root/$name-request.json"
  python3 - "$negative" "$app_id" "$environment_id" "$source_revision_id" >"$payload_file" <<'PY'
import json, sys
print(json.dumps({
    "application_id": sys.argv[2],
    "environment_id": sys.argv[3],
    "name": "m2-negative-" + sys.argv[1].rsplit("/", 1)[-1],
    "source_revision_id": sys.argv[4],
    "compose": json.load(open(sys.argv[1], encoding="utf-8")),
}, sort_keys=True, separators=(",", ":")))
PY
  status=$(request_json_file POST /api/v1/service-groups/import "$payload_file" "$output")
  expect_failure "$status" "$output"
  test "$(db_counts)" = "$negative_before"
done
printf '%s\n' 'SEC-COMP-001=PASS' 'SEC-COMP-002=PASS' 'SEC-COMP-003=PASS'

# Import and persist the supported mixed group.  The input contains build and
# prebuilt sources, a healthy/completed-capable DAG, a named retained volume,
# a private internal network, and exactly one ingress target.
stage_source mixed-v1 "$fixture_root"
upload_source mixed-v1 "$evidence_root/source-v1.json"
import_group "$fixture_root/compose/mixed-services.json" m2-mixed-v1 "$evidence_root/group-v1.json" "$source_revision_id"
group_v1=$group_id
group_digest_v1=$group_config_digest
dependency_order=$(json_value "$evidence_root/group-v1.json" report.dependency_order)
test -n "$dependency_order"
python3 - "$evidence_root/group-v1.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
group = value["service_group"]
assert len(group["services"]) == 4
assert sum(1 for service in group["services"] if service.get("role") == "ingress") == 1
assert any(service.get("source", {}).get("kind") == "dockerfile" for service in group["services"])
assert any(service.get("source", {}).get("kind") == "prebuilt" for service in group["services"])
assert (group.get("config_digest") or value["report"].get("canonical_digest", "")).startswith("sha256:")
PY
legacy_capability_before=$(db_counts)
legacy_payload=$(python3 - "$group_v1" <<'PY'
import json, sys
print(json.dumps({"service_group_id":sys.argv[1],"required_capabilities":["runtime.deploy","runtime.observe"],"operation":{"idempotency_key":"m2-legacy-agent-group-negative"}}, separators=(",", ":")))
PY
)
status=$(request_json POST "$agent_capability_negative_path" "$legacy_payload" "$evidence_root/agent-capability-legacy-negative.json")
expect_failure "$status" "$evidence_root/agent-capability-legacy-negative.json"
grep -Eqi 'capability|unsupported|incompatible' "$evidence_root/agent-capability-legacy-negative.json"
test "$(db_counts)" = "$legacy_capability_before"
printf '%s\n' 'CAPABILITY-GATED-AGENT=PASS'
create_release "$evidence_root/release-v1.json" "$source_revision_id" "$(cat "$secret_ref_file")"
release_v1=$release_id
release_digest_v1=$release_config_digest
release_digests_v1=$release_digests
python3 - "$evidence_root/release-v1.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))["release"]
assert value["immutable"] is True
assert value["config_digest"].startswith("sha256:")
assert len(value["service_digests"]) == 4
for image in value["service_digests"].values():
    assert image["digest"].startswith("sha256:")
PY

deploy_group "$release_v1" "$evidence_root/deployment-v1.json" initial
deployment_v1=$deployment_id
wait_json_state "/api/v1/deployments/$deployment_v1" state runtime_ready "$evidence_root/deployment-v1-state.json"
assert_group_containers 4
assert_only_entry_exposed
assert_private_network
assert_event_order "$deployment_v1" "$evidence_root/deployment-v1-events.sse"
curl -fsS "$(json_value "$evidence_root/deployment-v1-state.json" deployment.url)" | grep -Fq M2-FRONTEND-V1
printf '%s\n' 'E2E-COMPOSE-001=PASS' 'CT-RUNTIME-001=PASS' 'RUNTIME-INT-001=PASS'

# The node must reject an aggregate runtime request before creating a release,
# task, or container when capacity is insufficient.  The source/group remains
# unchanged so the negative has an independently comparable baseline.
capacity_before=$(db_counts)
containers_before=$(task_container_count)
capacity_payload=$(python3 - "$release_v1" <<'PY'
import json, sys
print(json.dumps({
    "release_id": sys.argv[1],
    "runtime_resources": {"cpu_millis": 9223372036854775807, "memory_bytes": 9223372036854775807, "disk_bytes": 9223372036854775807, "pids": 1000000},
    "rollout": {"mode": "initial"},
    "operation": {"idempotency_key": "m2-capacity-negative"},
}, separators=(",", ":")))
PY
)
status=$(request_json POST "/api/v1/service-groups/$group_v1/deployments" "$capacity_payload" "$evidence_root/capacity-negative.json")
expect_failure "$status" "$evidence_root/capacity-negative.json"
test "$(db_counts)" = "$capacity_before"
test "$(task_container_count)" = "$containers_before"
printf '%s\n' 'RUNTIME-INT-002=PASS'

# Volume lifecycle is observed across restart, update, and rollback.  The
# checksum is generated from the exact task-prefixed Docker volume mountpoint
# as a root-only acceptance fact. The application writes the canary itself;
# the control-plane exposes neither a host path nor a test-only write API.
volume_id=$(json_value "$evidence_root/deployment-v1-state.json" deployment.volume_claims.0.id)
volume_name=$(json_value "$evidence_root/deployment-v1-state.json" deployment.volume_claims.0.name)
test -n "$volume_id" -a -n "$volume_name"
[[ "$volume_name" = "$task_prefix-"* ]]
volume_mountpoint=$(docker volume inspect "$volume_name" --format '{{.Mountpoint}}')
[[ "$volume_mountpoint" = /var/lib/docker/volumes/"$task_prefix-"*/_data ]]
for _ in $(seq 1 40); do
  test -f "$volume_mountpoint/m2-volume-canary" && break
  sleep 0.1
done
test "$(cat "$volume_mountpoint/m2-volume-canary")" = M2-VOLUME-CANARY-V1
volume_checksum_v1=sha256:$(sha256sum "$volume_mountpoint/m2-volume-canary" | awk '{print $1}')
printf '{"volume_id":"%s","name":"%s","checksum":"%s"}\n' \
  "$volume_id" "$volume_name" "$volume_checksum_v1" >"$evidence_root/volume-write-v1.json"
status=$(request_json POST "/api/v1/releases/$release_v1/volumes/$volume_id/destroy" '{}' "$evidence_root/volume-delete-no-confirmation.json")
expect_failure "$status" "$evidence_root/volume-delete-no-confirmation.json"
test -n "$(docker volume inspect "$volume_name" --format '{{.Name}}' 2>/dev/null)"
printf '%s\n' 'CT-VOLUME-001=PASS'

# Build a complete immutable replacement group with only the ingress source
# changed, then exercise the real rolling controller.
stage_source mixed-v2 "$fixture_root"
upload_source mixed-v2 "$evidence_root/source-v2.json"
import_group "$fixture_root/compose/mixed-services-v2.json" m2-mixed-v2 "$evidence_root/group-v2.json" "$source_revision_id"
group_v2=$group_id
test "$group_v2" != "$group_v1"
create_release "$evidence_root/release-v2.json" "$source_revision_id" "$(cat "$secret_ref_file")"
release_v2=$release_id
release_digest_v2=$release_config_digest
test "$release_v2" != "$release_v1"
test "$release_digest_v2" != "$release_digest_v1"

old_url=$(json_value "$evidence_root/deployment-v1-state.json" deployment.url)
rollout_payload=$(python3 - "$release_v2" "$deployment_v1" <<'PY'
import json, sys
print(json.dumps({
    "release_id": sys.argv[1],
    "previous_deployment_id": sys.argv[2],
    "mode": "rolling",
    "preserve_old_until_healthy": True,
    "operation": {"idempotency_key": "m2-rollout-v2"},
}, separators=(",", ":")))
PY
)
status=$(request_json POST "/api/v1/rollouts/$deployment_v1" "$rollout_payload" "$evidence_root/rollout-v2.json")
test "$status" = 202
deployment_v2=$(json_value "$evidence_root/rollout-v2.json" deployment.id)
test -n "$deployment_v2" -a "$deployment_v2" != "$deployment_v1"
cleanup_deployment_ids+=("$deployment_v2")

# Poll independent traffic before and after health. At least one old marker
# must be observed before cutover, and the new marker only after serving.
old_traffic_seen=0
for _ in $(seq 1 80); do
  page=$(curl -fsS --max-time 2 "$old_url" 2>/dev/null || true)
  [[ "$page" = *M2-FRONTEND-V1* ]] && old_traffic_seen=1
  if (( old_traffic_seen == 1 )); then
    break
  fi
  sleep 0.1
done
test "$old_traffic_seen" = 1
wait_json_state "/api/v1/deployments/$deployment_v2" state runtime_ready "$evidence_root/deployment-v2-state.json"
new_url=$(json_value "$evidence_root/deployment-v2-state.json" deployment.url)
curl -fsS "$new_url" | grep -Fq M2-FRONTEND-V2
assert_volume_checksum after-update
assert_only_entry_exposed
assert_private_network
assert_event_order "$deployment_v2" "$evidence_root/deployment-v2-events.sse"
printf '%s\n' 'VOL-INT-001=PASS' 'ROLL-001=PASS'

# A failed replacement must not cut traffic. The previous serving release is
# kept while the new health contract fails; no database outcome is edited.
stage_source rolling-failure "$fixture_root"
upload_source rolling-failure "$evidence_root/source-rolling-failure.json"
import_group "$fixture_root/compose/rolling-failure.json" m2-rolling-failure "$evidence_root/group-rolling-failure.json" "$source_revision_id"
group_failure=$group_id
create_release "$evidence_root/release-rolling-failure.json" "$source_revision_id" "$(cat "$secret_ref_file")"
release_failure=$release_id
failure_payload=$(python3 - "$release_failure" "$deployment_v2" <<'PY'
import json, sys
print(json.dumps({
    "release_id": sys.argv[1],
    "previous_deployment_id": sys.argv[2],
    "mode": "rolling",
    "preserve_old_until_healthy": True,
    "operation": {"idempotency_key": "m2-rollout-failure"},
}, separators=(",", ":")))
PY
)
status=$(request_json POST "/api/v1/rollouts/$deployment_v2" "$failure_payload" "$evidence_root/rollout-failure.json")
test "$status" = 202
deployment_failure=$(json_value "$evidence_root/rollout-failure.json" deployment.id)
test -n "$deployment_failure"
cleanup_deployment_ids+=("$deployment_failure")
for _ in $(seq 1 120); do
  curl -sS --max-time 5 "$api_base/api/v1/deployments/$deployment_failure" >"$evidence_root/deployment-failure-state.json" || true
  failure_state=$(json_value "$evidence_root/deployment-failure-state.json" state 2>/dev/null || true)
  if [[ "$failure_state" = failed || "$failure_state" = rolled_back ]]; then
    break
  fi
  sleep 0.5
done
[[ "$failure_state" = failed || "$failure_state" = rolled_back ]]
curl -fsS "$new_url" | grep -Fq M2-FRONTEND-V2
assert_volume_checksum after-failed-rollout
printf '%s\n' 'FAULT-RUNTIME-001=PASS' 'ROLL-001-FAILED-NEW-VERSION=PASS'

# Optional failure is a separate explicit group. Stopping only the optional
# worker must produce a degraded projection while ingress remains healthy.
stage_source optional "$fixture_root"
upload_source optional "$evidence_root/source-optional.json"
import_group "$fixture_root/compose/optional-worker.json" m2-optional "$evidence_root/group-optional.json" "$source_revision_id"
group_optional=$group_id
create_release "$evidence_root/release-optional.json" "$source_revision_id" "$(cat "$secret_ref_file")"
release_optional=$release_id
deploy_group "$release_optional" "$evidence_root/deployment-optional.json" initial
deployment_optional=$deployment_id
wait_json_state "/api/v1/deployments/$deployment_optional" state degraded "$evidence_root/deployment-optional-state.json"
optional_container=$(docker ps -a --filter "label=open-card.task-prefix=$task_prefix" --filter "label=open-card.service-group-id=$group_optional" --filter "label=open-card.service-name=optional-worker" --format '{{.Names}}' | head -1)
test -z "$optional_container"
optional_url=$(json_value "$evidence_root/deployment-optional-state.json" deployment.url)
curl -fsS "$optional_url" | grep -Fq M2-FRONTEND-V1
printf '%s\n' 'FAULT-RUNTIME-002=PASS'

# Controller and Agent restart recovery is exercised while v2 is serving. The
# task and container projections must remain identical.
restart_db=$(db_counts)
restart_containers=$(task_container_ids)
systemctl restart open-card-server
wait_ready
systemctl restart open-card-agent
for _ in $(seq 1 100); do
  curl -sS --max-time 5 "$api_base/api/v1/deployments/$deployment_v2" >"$evidence_root/deployment-v2-after-restart.json" || true
  restart_state=$(json_value "$evidence_root/deployment-v2-after-restart.json" state 2>/dev/null || true)
  if [[ "$restart_state" = runtime_ready ]]; then
    break
  fi
  sleep 0.5
done
test "$restart_state" = runtime_ready
test "$(db_counts)" = "$restart_db"
test "$(task_container_ids)" = "$restart_containers"
curl -fsS "$new_url" | grep -Fq M2-FRONTEND-V2
assert_volume_checksum after-agent-controller-restart
printf '%s\n' 'FAULT-AGENT-001=PASS' 'FAULT-AGENT-002=PASS'

# Image tag movement is controlled by the local registry fixture. A release
# created before the move retains its original digest, while a new resolver
# call sees the new digest. The release projection is the authoritative fact.
old_public_digest=$public_digest
new_public_digest=$(python3 - "$registry_root/data/registry-map.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value["repositories"]["opencard/m2/public-v2"]["stable"])
PY
)
move_payload=$(python3 - "$registry_control_token" "$new_public_digest" <<'PY'
import json, sys
print(json.dumps({"repository":"opencard/m2/public","tag":"stable","target":sys.argv[2]}, separators=(",", ":")))
PY
)
curl -fsS -X POST -H "X-Open-Card-Fixture: $registry_control_token" -H 'Content-Type: application/json' \
  --data "$move_payload" "http://$registry_addr/__control/move-tag" >"$evidence_root/registry-tag-move.json"
public_resolve_after_move=$(python3 - "$registry_addr" "$run_id" <<'PY'
import json, sys
print(json.dumps({"repository":"opencard/m2/public","tag":"stable","registry":"http://"+sys.argv[1],"platform":{"os":"linux","architecture":"amd64"},"operation":{"idempotency_key":"m2-image-public-v2-"+sys.argv[2]}}, separators=(",", ":")))
PY
)
status=$(request_json POST /api/v1/images/resolve "$public_resolve_after_move" "$evidence_root/image-public-resolve-after-move.json")
test "$status" = 200
test "$(json_value "$evidence_root/image-public-resolve-after-move.json" image.digest)" = "$new_public_digest"
test "$old_public_digest" != "$new_public_digest"
db_registry_digest=$(python3 - "$evidence_root/registry-map.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["repositories"]["opencard/m2/db"]["stable"])
PY
)
test "$(json_value "$evidence_root/release-v1.json" release.service_digests.db.digest)" = "$db_registry_digest"
printf '%s\n' 'IMG-INT-001-TAG-MOVE=PASS'

# Public/private prebuilt image mix is published and served through the same
# aggregate runtime path. The controller receives only resolved digests after
# the resolver/SecretReference step.
stage_source image-mix "$fixture_root"
upload_source image-mix "$evidence_root/source-image-mix.json"
import_group "$fixture_root/compose/prebuilt-image-mix.json" m2-image-mix "$evidence_root/group-image-mix.json" "$source_revision_id"
group_image=$group_id
create_release "$evidence_root/release-image-mix.json" "$source_revision_id" "$(cat "$secret_ref_file")"
release_image=$release_id
python3 - "$evidence_root/release-image-mix.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))["release"]
assert len(value["service_digests"]) == 2
assert all(item["digest"].startswith("sha256:") for item in value["service_digests"].values())
PY
deploy_group "$release_image" "$evidence_root/deployment-image-mix.json" initial
deployment_image=$deployment_id
wait_json_state "/api/v1/deployments/$deployment_image" state runtime_ready "$evidence_root/deployment-image-mix-state.json"
assert_group_containers 2
assert_only_entry_exposed
assert_private_network "api,frontend"
image_mix_url=$(json_value "$evidence_root/deployment-image-mix-state.json" deployment.url)
curl -fsS "$image_mix_url" | grep -Fq M2-REGISTRY-PUBLIC
printf '%s\n' 'E2E-IMAGE-001=PASS'

# Image GC is called through the task-scoped image-only provider executable
# with an exact durable snapshot and confirmation. Before/after facts
# must retain the current and last two successful release digests, all images
# referenced by a serving deployment, and every named volume.
gc_before=$(db_counts)
python3 - "$evidence_root" >"$work_root/image-gc-snapshot.json" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
records = []
mapping = [
    ("release-v1.json", "rollback"),
    ("release-v2.json", "current"),
    ("release-optional.json", "succeeded"),
    ("release-image-mix.json", "succeeded"),
    ("release-rolling-failure.json", "failed"),
]
failure_images = []
for name, status in mapping:
    release = json.loads((root / name).read_text(encoding="utf-8"))["release"]
    images = list(release["service_digests"].values())
    records.append({"id": release["id"], "status": status, "created_at": release["created_at"], "images": images})
    if status == "failed":
        failure_images = images
print(json.dumps({"releases": records, "builds": [{"id":"build-failed-rollout","status":"failed","created_at":records[-1]["created_at"],"images":failure_images}]}, sort_keys=True, separators=(",", ":")))
PY
chmod 0600 "$work_root/image-gc-snapshot.json"
"$imagegc" --task-prefix "$task_prefix" --disk-path /var/lib/docker \
  --snapshot "$work_root/image-gc-snapshot.json" --execute \
  --confirmation "collect-task-images:$task_prefix" >"$evidence_root/image-gc.json"
python3 - "$evidence_root/image-gc.json" "$evidence_root/release-v1.json" "$evidence_root/release-v2.json" <<'PY'
import json, sys
gc = json.load(open(sys.argv[1], encoding="utf-8"))
assert "before" in gc and "after" in gc
assert isinstance(gc["after"], list)
protected = set()
for path in sys.argv[2:]:
    release = json.load(open(path, encoding="utf-8"))["release"]
    protected.update(item["digest"] for item in release["service_digests"].values())
after = {item.get("image", {}).get("digest") for item in gc["after"] if item.get("kind") == "image"}
missing = protected - after
if missing:
    raise SystemExit("GC removed a release-protected image: " + ",".join(sorted(missing)))
outcomes = (gc.get("result") or {}).get("outcomes", [])
if not any(item.get("action") == "deleted" for item in outcomes):
    raise SystemExit("GC did not delete the failed rollout image candidate")
if any(item.get("kind") == "volume" for item in gc["before"]) and not any(item.get("kind") == "volume" for item in gc["after"]):
    raise SystemExit("image-only GC removed a volume")
PY
test "$(db_counts)" = "$gc_before"
printf '%s\n' 'IMG-GC-001=PASS'

# Scan every image digest named by a release and every task container before
# teardown. Registry credentials must not appear in OCI config/history,
# container environment/labels, or runtime logs.
python3 - "$evidence_root" >"$work_root/release-image-digests" <<'PY'
import json, pathlib, sys
seen = set()
for path in sorted(pathlib.Path(sys.argv[1]).glob("release-*.json")):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))["release"]
    except (KeyError, json.JSONDecodeError):
        continue
    for image in value.get("service_digests", {}).values():
        digest = image.get("digest", "")
        if digest.startswith("sha256:"):
            seen.add(digest)
for digest in sorted(seen):
    print(digest)
PY
while IFS= read -r image_ref; do
  [[ -z "$image_ref" ]] && continue
  if docker image inspect "$image_ref" >"$work_root/image-inspect.json" 2>/dev/null; then
    if grep -Fq -- "$registry_token" "$work_root/image-inspect.json"; then
      exit 1
    fi
  fi
  if docker history --no-trunc "$image_ref" >"$work_root/image-history.txt" 2>/dev/null; then
    if grep -Fq -- "$registry_token" "$work_root/image-history.txt"; then
      exit 1
    fi
  fi
done <"$work_root/release-image-digests"
while IFS= read -r container; do
  [[ -z "$container" ]] && continue
  docker inspect "$container" >"$work_root/container-inspect.json"
  docker logs "$container" >"$work_root/container-stdout.log" 2>&1 || true
  if grep -Fq -- "$registry_token" "$work_root/container-inspect.json" "$work_root/container-stdout.log"; then
    exit 1
  fi
done < <(task_container_ids)

# Detach all task deployments via their public destroy operations before
# requesting explicit volume deletion. Attached volumes must remain protected.
destroy_deployments_serially
for _ in $(seq 1 200); do
  test "$(task_container_count)" = 0 && break
  sleep 0.1
done
test "$(task_container_count)" = 0

# Delete retained volumes only with the exact references returned by the
# control-plane volume API and the explicit danger confirmation contract.
curl -fsS --max-time 20 "$api_base/api/v1/releases/$release_v2/volumes" >"$evidence_root/volumes-before-delete.json"
python3 - "$evidence_root/volumes-before-delete.json" >"$work_root/volume-delete-requests.ndjson" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
items = value.get("volumes", value if isinstance(value, list) else [])
for item in items:
    identifier = item.get("id", "")
    name = item.get("physical_name", "")
    if not identifier or not name.startswith("opencard-mvp-fa8f8eab-"):
        raise SystemExit("volume API returned an unscoped volume")
    print(json.dumps({"id":identifier,"name":name,"confirmation_token":"confirm-volume-destroy:" + name}, separators=(",", ":")))
PY
while IFS= read -r volume_request; do
  [[ -z "$volume_request" ]] && continue
  volume_delete_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$volume_request")
  volume_delete_name=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])' <<<"$volume_request")
  volume_delete_payload=$(python3 -c 'import json,sys; value=json.load(sys.stdin); print(json.dumps({"confirmation_token":value["confirmation_token"]},separators=(",",":")))' <<<"$volume_request")
  status=$(request_json POST "/api/v1/releases/$release_v2/volumes/$volume_delete_id/destroy" "$volume_delete_payload" "$evidence_root/volume-delete-$volume_delete_id.json")
  test "$status" = 202
  for _ in $(seq 1 100); do
    docker volume inspect "$volume_delete_name" >/dev/null 2>&1 || break
    sleep 0.1
  done
  if docker volume inspect "$volume_delete_name" >/dev/null 2>&1; then
      echo "volume remained after explicit deletion: $volume_delete_name" >&2
      exit 1
  fi
done <"$work_root/volume-delete-requests.ndjson"
printf '%s\n' 'CT-VOLUME-001-DELETE=PASS'

# Secret/reference and runtime boundaries are scanned only after every
# registry request and image operation has finished. The token itself never
# enters a response, release, event, audit record, image layer, or log.
pg_dump --data-only --inserts "$database_url" >"$evidence_root/m2-db-redacted-scan.sql"
for scan_root in "$evidence_root" "$secret_root" "$secret_material_root" "$source_upload_root" /var/log/open-card /var/log/open-card-agent /var/lib/open-card/ai; do
  [[ -e "$scan_root" ]] || continue
  for fixture_token in "$registry_token" "$registry_control_token"; do
    if grep -R -a -F -q -- "$fixture_token" "$scan_root"; then
      echo "registry fixture token found in durable boundary $scan_root" >&2
      exit 1
    fi
  done
done
for fixture_token in "$registry_token" "$registry_control_token"; do
  if grep -Fq -- "$fixture_token" "$evidence_root/m2-db-redacted-scan.sql"; then
    exit 1
  fi
done
assert_empty_material() {
  test -d "$secret_material_root"
  test -z "$(find "$secret_material_root" -mindepth 1 -maxdepth 1 -print -quit)"
}
assert_empty_material
printf '%s\n' 'IMG-INT-002-SECRET-SCAN=PASS' 'SEC-SECRET-001=PASS'

rm -rf -- "$work_root"

# Public destroy/cleanup and exact task-prefix leak proof. Calling cleanup
# here makes the final snapshot part of the evidence rather than relying on a
# shell EXIT trap that the evidence collector cannot observe.
cleanup
snapshot "$evidence_root/objects-after.json"
test "$(task_container_count)" = 0
test "$(task_volume_names)" = ""
test "$(task_network_names)" = ""
test ! -e "$registry_ready_file"
test ! -e "$token_file"
test ! -e "$control_token_file"
test ! -e "$secret_ref_file"
printf '%s\n' 'M2-CLEANUP=PASS'
printf '%s\n' \
  'M2-REAL-GATES=PASS' \
  'E2E-COMPOSE-001=PASS' \
  'E2E-IMAGE-001=PASS' \
  'SCHEMA-COMP-001/002=PASS' \
  'SEC-COMP-001/002/003=PASS' \
  'CT-IMAGE-001=PASS' \
  'CT-RUNTIME-001=PASS' \
  'CT-VOLUME-001=PASS' \
  'VOL-INT-001=PASS' \
  'ROLL-001=PASS' \
  'FAULT-RUNTIME-001/002=PASS' \
  'IMG-GC-001=PASS'
