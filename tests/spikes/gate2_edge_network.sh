#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly CONFIRMATION="GATE2-NETWORK-READONLY"
readonly CONTRACT_SCHEMA_VERSION=1
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
readonly CONTRACT_FILE="$SCRIPT_DIR/../fixtures/gate2/port-contract.json"

usage() {
  cat >&2 <<'USAGE'
usage: gate2_edge_network.sh --observation-point local|external \
       --target HOST --task-id TASK_ID --evidence-dir DIRECTORY \
       --confirm GATE2-NETWORK-READONLY [--probe-origin ID]

local: inspect target listeners, processes, systemd units and local Docker/BuildKit
       Unix-socket boundaries. The independent external probe is UNKNOWN because
       it is not executed from this observation point.
external: run an independent TCP probe against the explicit non-loopback target.
          --probe-origin identifies the independent probe source.

Exit codes: 0=all executed checks pass, 1=fail, 2=unknown, 64=usage error.
This script never changes firewall, routing, proxy, service or server state.
USAGE
}

usage_error() {
  echo "gate2 edge network: $*" >&2
  usage
  exit 64
}

require_python() {
  command -v python3 >/dev/null 2>&1 || usage_error "python3 is required to load the checked-in contract"
}

load_contract() {
  [[ -f "$CONTRACT_FILE" && ! -L "$CONTRACT_FILE" ]] || usage_error "contract file is missing or unsafe"
  local values
  if ! values=$(python3 - "$CONTRACT_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
if value.get("schema_version") != 1 or value.get("contract_id") != "gate2-edge-network-v1":
    raise SystemExit("unsupported Gate 2 network contract")
approved = value.get("approved_tcp_ports")
forbidden = value.get("forbidden_tcp_ports")
sockets = value.get("forbidden_unix_sockets")
if approved != [80, 443] or forbidden != [8080, 18481, 2019, 2020, 5432, 8092]:
    raise SystemExit("Gate 2 port contract does not match the approved boundary")
if not isinstance(sockets, list) or not sockets or not all(isinstance(item, str) and item.startswith("/") for item in sockets):
    raise SystemExit("Gate 2 Unix-socket contract is invalid")
print("approved=" + ",".join(str(item) for item in approved))
print("forbidden=" + ",".join(str(item) for item in forbidden))
print("sockets=" + "|".join(sockets))
PY
  ); then
    usage_error "unable to load the Gate 2 network contract"
  fi

  APPROVED_PORTS=()
  FORBIDDEN_PORTS=()
  FORBIDDEN_SOCKETS=()
  local key value
  while IFS='=' read -r key value; do
    case "$key" in
      approved) IFS=',' read -r -a APPROVED_PORTS <<< "$value" ;;
      forbidden) IFS=',' read -r -a FORBIDDEN_PORTS <<< "$value" ;;
      sockets) IFS='|' read -r -a FORBIDDEN_SOCKETS <<< "$value" ;;
      *) usage_error "contract returned an unknown field" ;;
    esac
  done <<< "$values"
}

json_line() {
  local record_type=$1 check_id=$2 status=$3 detail=$4 port="${5-}"
  if [[ -n "$port" ]]; then
    printf '{"schema_version":%d,"record_type":"%s","task_id":"%s","observation_point":"%s","target":"%s","probe_origin":"%s","check_id":"%s","port":%s,"status":"%s","detail":"%s"}' \
      "$CONTRACT_SCHEMA_VERSION" "$record_type" "$task_id" "$observation_point" "$target" "$probe_origin" "$check_id" "$port" "$status" "$detail"
  else
    printf '{"schema_version":%d,"record_type":"%s","task_id":"%s","observation_point":"%s","target":"%s","probe_origin":"%s","check_id":"%s","status":"%s","detail":"%s"}' \
      "$CONTRACT_SCHEMA_VERSION" "$record_type" "$task_id" "$observation_point" "$target" "$probe_origin" "$check_id" "$status" "$detail"
  fi
}

append_line() {
  local line=$1
  printf '%s\n' "$line" >> "$summary_file"
  printf '%s\n' "$line"
}

record_check() {
  local check_id=$1 status=$2 detail=$3 port="${4-}"
  case "$status" in
    pass) pass_count=$((pass_count + 1)) ;;
    fail) fail_count=$((fail_count + 1)) ;;
    unknown) unknown_count=$((unknown_count + 1)) ;;
    *) usage_error "internal invalid status $status" ;;
  esac
  append_line "$(json_line check "$check_id" "$status" "$detail" "$port")"
}

record_summary() {
  local status=$1
  append_line "$(printf '{"schema_version":%d,"record_type":"summary","task_id":"%s","observation_point":"%s","target":"%s","probe_origin":"%s","status":"%s","pass_count":%d,"fail_count":%d,"unknown_count":%d}' \
    "$CONTRACT_SCHEMA_VERSION" "$task_id" "$observation_point" "$target" "$probe_origin" "$status" "$pass_count" "$fail_count" "$unknown_count")"
}

is_rejected_target() {
  case "$1" in
    localhost|localhost.*|*.localhost|127.*|0.0.0.0|::|[::]|::1|[::1]) return 0 ;;
    *) return 1 ;;
  esac
}

parse_local_listeners() {
  local listener_file=$1
  python3 - "$listener_file" <<'PY'
import ipaddress
import sys

ports = [80, 443, 8080, 18481, 2019, 2020, 5432, 8092]
observed = {port: {"public": False, "loopback": False} for port in ports}

def endpoint(value):
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        host, port = value.rsplit(":", 1)
    else:
        return None, None
    try:
        return host, int(port)
    except ValueError:
        return host, None

def is_loopback(host):
    if host in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

with open(sys.argv[1], encoding="utf-8", errors="replace") as stream:
    for line in stream:
        fields = line.split()
        if len(fields) < 4:
            continue
        host, port = endpoint(fields[3])
        if port not in observed:
            continue
        if host in ("*", "0.0.0.0", "::", ":::", "") or not is_loopback(host):
            observed[port]["public"] = True
        else:
            observed[port]["loopback"] = True

for port in ports:
    item = observed[port]
    if port in (80, 443):
        if item["public"]:
            status, detail = "pass", "non-loopback listener detected"
        elif item["loopback"]:
            status, detail = "fail", "approved port is loopback-only"
        else:
            status, detail = "unknown", "approved port has no local listener; external probe is authoritative"
    elif item["public"]:
        status, detail = "fail", "forbidden port has a non-loopback listener"
    else:
        status = "pass"
        detail = "forbidden port is absent or loopback-only"
    print(f"tcp.listener.{port}\t{port}\t{status}\t{detail}")
PY
}

local_observation() {
  local listeners_file="$evidence_dir/local-listeners.txt"
  local listeners_error="$evidence_dir/local-listeners.error.txt"
  if command -v ss >/dev/null 2>&1; then
    if ss -lntH > "$listeners_file" 2> "$listeners_error"; then
      local parsed check_id port status detail
      if parsed=$(parse_local_listeners "$listeners_file"); then
        while IFS=$'\t' read -r check_id port status detail; do
          [[ -n "$check_id" ]] || continue
          record_check "$check_id" "$status" "$detail" "$port"
        done <<< "$parsed"
      else
        record_check "tcp.listener.parser" unknown "listener output could not be parsed"
      fi
    else
      record_check "tcp.listener.tool" unknown "ss failed; local listener state is unknown"
    fi
  else
    : > "$listeners_file"
    record_check "tcp.listener.tool" unknown "ss is unavailable"
  fi

  local processes_file="$evidence_dir/local-processes.txt"
  if command -v ps >/dev/null 2>&1; then
    ps -eo pid=,user=,args= > "$processes_file" 2> "$evidence_dir/local-processes.error.txt" || true
  else
    : > "$processes_file"
  fi
  local pattern
  for pattern in caddy open-card-server; do
    if command -v pgrep >/dev/null 2>&1; then
      if pgrep -af "/opt/open-card/current/bin/$pattern" > "$evidence_dir/process-$pattern.txt" 2> /dev/null; then
        record_check "process.$pattern" pass "expected process path is running"
      else
        record_check "process.$pattern" fail "expected process path is not running"
      fi
    else
      record_check "process.$pattern" unknown "pgrep is unavailable"
    fi
  done

  local systemd_file="$evidence_dir/local-systemd.txt"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl show --no-pager \
      open-card-edge.service open-card-caddy.service open-card-server.service \
      -p Id -p ActiveState -p SubState -p User -p FragmentPath \
      > "$systemd_file" 2> "$evidence_dir/local-systemd.error.txt" || true
    local unit
    for unit in open-card-edge.service open-card-caddy.service; do
      if systemctl is-active --quiet "$unit"; then
        record_check "systemd.$unit" pass "unit is active"
      else
        record_check "systemd.$unit" fail "unit is not active"
      fi
    done
  else
    : > "$systemd_file"
    record_check "systemd.tool" unknown "systemctl is unavailable"
  fi

  local unix_file="$evidence_dir/local-unix-sockets.txt"
  if command -v ss >/dev/null 2>&1 && ss -lxH > "$unix_file" 2> "$evidence_dir/local-unix-sockets.error.txt"; then
    local socket socket_id
    for socket in "${FORBIDDEN_SOCKETS[@]}"; do
      socket_id=$(printf '%s' "$socket" | tr '/' '.')
      if grep -Fq -- "$socket" "$unix_file"; then
        record_check "unix.socket$socket_id" pass "socket is present only in the local Unix listener table"
      else
        record_check "unix.socket$socket_id" pass "socket is not present in the local Unix listener table"
      fi
    done
  else
    : > "$unix_file"
    record_check "unix.socket.tool" unknown "ss Unix-socket inspection is unavailable"
  fi

  record_check "external.probe.not_executed" unknown "external probe was not executed from the local observation point"
}

probe_tcp_port() {
  local port=$1 output_file=$2
  if [[ "$probe_tool" = nc ]]; then
    nc -z -w 3 "$target" "$port" > "$output_file" 2>&1
  else
    ncat -z -w 3 "$target" "$port" > "$output_file" 2>&1
  fi
}

external_observation() {
  local tool_file="$evidence_dir/external-probe-tool.txt"
  local port output_file probe_status
  if command -v nc >/dev/null 2>&1; then
    probe_tool=nc
  elif command -v ncat >/dev/null 2>&1; then
    probe_tool=ncat
  else
    probe_tool=
  fi
  if [[ -z "$probe_tool" ]]; then
    : > "$tool_file"
    record_check "external.probe.tool" unknown "nc/ncat is unavailable; no external probe was executed"
    for port in "${APPROVED_PORTS[@]}" "${FORBIDDEN_PORTS[@]}"; do
      record_check "external.tcp.$port" unknown "external probe tool is unavailable" "$port"
    done
    return
  fi
  printf '%s\n' "$probe_tool" > "$tool_file"
  record_check "external.probe.tool" pass "$probe_tool is available for the independent TCP probe"
  for port in "${APPROVED_PORTS[@]}" "${FORBIDDEN_PORTS[@]}"; do
    output_file="$evidence_dir/external-probe-$port.txt"
    set +e
    probe_tcp_port "$port" "$output_file"
    probe_status=$?
    set -e
    case "$probe_status" in
      0)
        if [[ "$port" = 80 || "$port" = 443 ]]; then
          record_check "external.tcp.$port" pass "approved TCP port accepted an independent probe" "$port"
        else
          record_check "external.tcp.$port" fail "forbidden TCP port accepted an independent probe" "$port"
        fi
        ;;
      1)
        if [[ "$port" = 80 || "$port" = 443 ]]; then
          record_check "external.tcp.$port" fail "approved TCP port did not accept an independent probe" "$port"
        else
          record_check "external.tcp.$port" pass "forbidden TCP port refused or timed out" "$port"
        fi
        ;;
      *)
        record_check "external.tcp.$port" unknown "probe command failed with an indeterminate tool error" "$port"
        ;;
    esac
  done
}

observation_point=
target=
task_id=
evidence_dir=
confirm=
probe_origin=
probe_tool=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --observation-point) [[ $# -gt 1 ]] || usage_error "$1 requires a value"; observation_point=$2; shift 2 ;;
    --target) [[ $# -gt 1 ]] || usage_error "$1 requires a value"; target=$2; shift 2 ;;
    --task-id) [[ $# -gt 1 ]] || usage_error "$1 requires a value"; task_id=$2; shift 2 ;;
    --evidence-dir) [[ $# -gt 1 ]] || usage_error "$1 requires a value"; evidence_dir=$2; shift 2 ;;
    --confirm) [[ $# -gt 1 ]] || usage_error "$1 requires a value"; confirm=$2; shift 2 ;;
    --probe-origin) [[ $# -gt 1 ]] || usage_error "$1 requires a value"; probe_origin=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown option $1" ;;
  esac
done

[[ "$observation_point" = local || "$observation_point" = external ]] || usage_error "--observation-point must be local or external"
[[ -n "$target" ]] || usage_error "--target is required"
[[ -n "$task_id" ]] || usage_error "--task-id is required"
[[ -n "$evidence_dir" ]] || usage_error "--evidence-dir is required"
[[ "$confirm" = "$CONFIRMATION" ]] || usage_error "exact confirmation marker is required"
[[ "$task_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || usage_error "task ID contains unsafe characters"
[[ "$target" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || usage_error "target must be a hostname or literal IP without shell/path characters"
is_rejected_target "$target" && usage_error "loopback/default localhost target is forbidden"
[[ "$evidence_dir" = /* && "$evidence_dir" != / && "$evidence_dir" != *$'\n'* && "$evidence_dir" != *$'\r'* ]] || usage_error "evidence directory must be an absolute non-root path"
if [[ "$observation_point" = external ]]; then
  [[ "$probe_origin" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$ ]] || usage_error "external observation requires a safe --probe-origin"
  case "$probe_origin" in local|localhost|self) usage_error "probe origin must identify an independent external probe" ;; esac
else
  [[ -z "$probe_origin" ]] || usage_error "--probe-origin is only valid for external observation"
fi

require_python
load_contract
if [[ -L "$evidence_dir" ]]; then usage_error "evidence directory must not be a symlink"; fi
mkdir -p -- "$evidence_dir"
[[ -d "$evidence_dir" ]] || usage_error "evidence directory could not be created"
summary_file="$evidence_dir/summary.ndjson"
[[ ! -L "$summary_file" ]] || usage_error "summary path must not be a symlink"

pass_count=0
fail_count=0
unknown_count=0
append_line "$(printf '{"schema_version":%d,"record_type":"run","task_id":"%s","observation_point":"%s","target":"%s","probe_origin":"%s","contract":"%s"}' \
  "$CONTRACT_SCHEMA_VERSION" "$task_id" "$observation_point" "$target" "$probe_origin" "gate2-edge-network-v1")"

if [[ "$observation_point" = local ]]; then
  local_observation
else
  external_observation
fi

if (( fail_count > 0 )); then
  overall_status=fail
  exit_status=1
elif (( unknown_count > 0 )); then
  overall_status=unknown
  exit_status=2
else
  overall_status=pass
  exit_status=0
fi
record_summary "$overall_status"
exit "$exit_status"
