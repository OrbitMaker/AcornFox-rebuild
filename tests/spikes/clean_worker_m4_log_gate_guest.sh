#!/usr/bin/env bash
# shellcheck shell=bash
#
# Directed M4 log-gate helper.  It is intentionally sourceable from the
# canonical guest runner after that runner has created a task-scoped M2 source
# fixture and completed at least one audited operation.  This file does not
# create a VM, alter a bundle, write SQL, or turn a source-level check into an
# M4 result.

set -euo pipefail

m4_log_gate_die() { echo "m4 log gate: $*" >&2; return 78; }

m4_log_gate_require() {
  local name=$1 value=${!1:-}
  [[ -n "$value" ]] || m4_log_gate_die "required environment variable is empty: $name"
}

m4_log_gate_task_path() {
  local value=$1 prefix=$2
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *".."* ]] || m4_log_gate_die "unsafe task path"
  case "$value" in
    "/var/lib/${prefix}"/*|"/var/lib/open-card/${prefix}"/*) ;;
    *) m4_log_gate_die "path is outside task prefix: $value" ;;
  esac
}

m4_log_gate_safe_component() {
  local value=$1
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || m4_log_gate_die "unsafe logical stream: $value"
}

m4_log_gate_product_log_root() {
  local value=$1
  # The canonical clean VM keeps the server-owned LogStore below this root.
  # It is a shared product path only inside the already task-isolated VM, so
  # never accept a caller-selected host path as a substitute.
  [[ "$value" = /var/lib/open-card/build-work/m4-logs ]] || m4_log_gate_die "unexpected server LogStore root"
  [[ ! -L "$value" ]] || m4_log_gate_die "LogStore root must not be a symlink"
}

m4_log_gate_json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    if part:
        value = value[int(part)] if isinstance(value, list) else value[part]
print(value if not isinstance(value, (dict, list)) else json.dumps(value, separators=(",", ":")))
PY
}

m4_log_gate_wait_ready() {
  local api=$1
  for _ in $(seq 1 100); do
    m4_log_gate_control_curl --fail --silent --show-error --connect-timeout 2 --max-time 3 "$api/readyz" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  m4_log_gate_die "control plane did not recover after the permitted restart"
}

m4_log_gate_assert_loopback_url() {
  local url=$1
  [[ "$url" =~ ^http://127\.0\.0\.1:[0-9]{1,5}(/|$) ]] || m4_log_gate_die "only loopback API URLs are allowed"
}

m4_log_gate_control_curl() {
  local session=${OPEN_CARD_M4_AUTH_SESSION:?OPEN_CARD_M4_AUTH_SESSION is required for M4 log-gate control-plane calls}
  [[ "$session" =~ ^[A-Za-z0-9_-]{43}$ ]] || m4_log_gate_die "M4 log-gate session is malformed"
  command curl -H "Cookie: __Host-open_card_session=$session" "$@"
}

m4_log_gate_assert_no_ai() {
  [[ "${OPEN_CARD_AI_ENABLED:-false}" != "true" ]] || m4_log_gate_die "AI must be disabled for deterministic M4 log gates"
  [[ "${OPEN_CARD_RUNTIME_TASK_PREFIX:-}" = "$M4_LOG_GATE_TASK_PREFIX" ]] || m4_log_gate_die "runtime task prefix does not match log gate"
}

m4_log_gate_require_context() {
  : "${M4_LOG_GATE_EXECUTE:=}"
  [[ "$M4_LOG_GATE_EXECUTE" = "1" ]] || m4_log_gate_die "set M4_LOG_GATE_EXECUTE=1 only in the approved task VM"
  for name in M4_LOG_GATE_API M4_LOG_GATE_EVIDENCE M4_LOG_GATE_WORK M4_LOG_GATE_TASK_PREFIX M4_LOG_GATE_APP_ID M4_LOG_GATE_ENVIRONMENT_ID M4_LOG_GATE_SOURCE_TEMPLATE_DIR M4_LOG_GATE_LOG_ROOT M4_LOG_GATE_DATABASE_URL; do
    m4_log_gate_require "$name"
  done
  [[ "$M4_LOG_GATE_TASK_PREFIX" = opencard-mvp-fa8f8eab ]] || m4_log_gate_die "unexpected task prefix"
  m4_log_gate_assert_loopback_url "$M4_LOG_GATE_API"
  m4_log_gate_task_path "$M4_LOG_GATE_EVIDENCE" "$M4_LOG_GATE_TASK_PREFIX"
  m4_log_gate_task_path "$M4_LOG_GATE_WORK" "$M4_LOG_GATE_TASK_PREFIX"
  m4_log_gate_task_path "$M4_LOG_GATE_SOURCE_TEMPLATE_DIR" "$M4_LOG_GATE_TASK_PREFIX"
  m4_log_gate_product_log_root "$M4_LOG_GATE_LOG_ROOT"
  [[ -d "$M4_LOG_GATE_SOURCE_TEMPLATE_DIR/services/frontend-v2" ]] || m4_log_gate_die "single Dockerfile source template is unavailable"
  [[ -f "$M4_LOG_GATE_SOURCE_TEMPLATE_DIR/services/frontend-v2/Dockerfile" ]] || m4_log_gate_die "source template has no Dockerfile service"
  [[ -d "$M4_LOG_GATE_LOG_ROOT/build" && -d "$M4_LOG_GATE_LOG_ROOT/runtime" && -d "$M4_LOG_GATE_LOG_ROOT/audit" ]] || m4_log_gate_die "configured LogStore root is incomplete"
  m4_log_gate_assert_no_ai
  m4_log_gate_safe_component "${M4_LOG_GATE_RUN_ID:-log-gate}"
  mkdir -p -m 0750 "$M4_LOG_GATE_EVIDENCE" "$M4_LOG_GATE_WORK"
}

# LOG-002 is deliberately a public-API execution, not an INSERT fixture.  One
# source revision and one single-Dockerfile ServiceGroup are created for each
# build so the immutable build/artifact contract is exercised 21 times.
m4_log_gate_capture_audit_before() {
  local before
  before=$(psql "$M4_LOG_GATE_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM audit_evidence WHERE action LIKE 'operations.%'")
  [[ "$before" =~ ^[1-9][0-9]*$ ]] || m4_log_gate_die "no audited operation exists before ordinary log GC"
  printf '%s\n' "$before" >"$M4_LOG_GATE_EVIDENCE/log-003-audit-before.txt"
}

m4_log_gate_reject_sensitive_runtime_literal() {
  local tree="$M4_LOG_GATE_WORK/sec-log-sensitive" compose="$M4_LOG_GATE_WORK/sec-log-sensitive.json"
  local archive="$M4_LOG_GATE_WORK/sec-log-sensitive.tar" response="$M4_LOG_GATE_EVIDENCE/sec-log-sensitive-response.json"
  install -d -m 0750 "$tree/services"
  cp -a -- "$M4_LOG_GATE_SOURCE_TEMPLATE_DIR/services/api" "$tree/services/api"
  python3 - "$M4_LOG_GATE_SOURCE_TEMPLATE_DIR/compose/mixed-services.json" "$compose" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding='utf-8'))
api=value['services']['api']
api.pop('depends_on',None); api.pop('networks',None)
api.setdefault('environment',{})['DATABASE_PASSWORD']='bare-runtime-canary'
json.dump({'version':value.get('version','3.9'),'services':{'api':api}},open(sys.argv[2],'w',encoding='utf-8'),separators=(',',':'),sort_keys=True)
PY
  cp "$compose" "$tree/compose.json"
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -cf "$archive" -C "$tree" compose.json services
  m4_log_gate_control_curl --fail --silent --show-error -H "Idempotency-Key: ${M4_LOG_GATE_RUN_ID:-log-gate}-sec-log-source" -F "application_id=$M4_LOG_GATE_APP_ID" -F kind=upload -F "archive=@$archive;type=application/x-tar" "$M4_LOG_GATE_API/api/v1/sources" >"$M4_LOG_GATE_EVIDENCE/sec-log-sensitive-source.json"
  local source_id status
  source_id=$(m4_log_gate_json_get "$M4_LOG_GATE_EVIDENCE/sec-log-sensitive-source.json" source_revision.id)
  python3 - "$M4_LOG_GATE_APP_ID" "$M4_LOG_GATE_ENVIRONMENT_ID" "$source_id" "$compose" >"$M4_LOG_GATE_WORK/sec-log-sensitive-import.json" <<'PY'
import json,sys
print(json.dumps({'application_id':sys.argv[1],'environment_id':sys.argv[2],'source_revision_id':sys.argv[3],'name':'m4-sec-log-sensitive','version':1,'compose':json.load(open(sys.argv[4],encoding='utf-8'))},separators=(',',':')))
PY
  status=$(m4_log_gate_control_curl --silent --show-error -o "$response" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: ${M4_LOG_GATE_RUN_ID:-log-gate}-sec-log-group" --data @"$M4_LOG_GATE_WORK/sec-log-sensitive-import.json" "$M4_LOG_GATE_API/api/v1/service-groups/import")
  [[ "$status" = 400 ]] || m4_log_gate_die "sensitive runtime literal was not rejected before ServiceGroup persistence"
  ! grep -a -Fq 'bare-runtime-canary' "$response"
  [[ $(psql "$M4_LOG_GATE_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM service_groups WHERE application_id='$M4_LOG_GATE_APP_ID' AND name='m4-sec-log-sensitive'") = 0 ]]
  ! grep -R -a -Fq 'bare-runtime-canary' "$M4_LOG_GATE_LOG_ROOT"
  pg_dump --data-only --no-owner --no-privileges "$M4_LOG_GATE_DATABASE_URL" >"$M4_LOG_GATE_WORK/sec-log-db.dump"
  ! grep -a -Fq 'bare-runtime-canary' "$M4_LOG_GATE_WORK/sec-log-db.dump"
  rm -f -- "$M4_LOG_GATE_WORK/sec-log-db.dump"
  ! grep -R -a -Fq 'bare-runtime-canary' /var/lib/open-card/ai 2>/dev/null
}

m4_log_gate_build_twenty_one() {
  local api=$M4_LOG_GATE_API app=$M4_LOG_GATE_APP_ID template=$M4_LOG_GATE_SOURCE_TEMPLATE_DIR
  local work=$M4_LOG_GATE_WORK evidence=$M4_LOG_GATE_EVIDENCE run_id=${M4_LOG_GATE_RUN_ID:-log-gate}
  local rows="$evidence/log-002-builds.tsv" release_payload source_archive source_id group status
  : >"$rows"
  for number in $(seq -w 1 21); do
    local tree compose
    tree="$work/log-002-$number"
    compose="$tree/compose.json"
    install -d -m 0750 "$tree/services"
    cp -a -- "$template/services/frontend-v2" "$tree/services/frontend-v2"
    # `index.html` is copied by the fixture Dockerfile, so this changes the
    # immutable OCI output for every build without adding a network step.
    printf '\n<!-- log-gate-build=%s -->\n' "$number" >>"$tree/services/frontend-v2/index.html"
    python3 - "$template/compose/mixed-services.json" "$compose" <<'PY'
import json, sys
source, target = sys.argv[1:]
value = json.load(open(source, encoding="utf-8"))
frontend = value["services"]["frontend"]
frontend.pop("depends_on", None)
frontend.pop("networks", None)
value = {"version": value.get("version", "3.9"), "services": {"frontend": frontend}}
json.dump(value, open(target, "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
PY
    source_archive="$work/log-002-$number.tar"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -cf "$source_archive" -C "$tree" compose.json services
    m4_log_gate_control_curl --fail --silent --show-error -H "Idempotency-Key: ${run_id}-log-002-source-${number}" -F "application_id=$app" -F kind=upload -F "archive=@$source_archive;type=application/x-tar" "$api/api/v1/sources" >"$evidence/log-002-source-$number.json"
    source_id=$(m4_log_gate_json_get "$evidence/log-002-source-$number.json" source_revision.id)
    [[ -n "$source_id" ]] || m4_log_gate_die "source upload did not return an immutable revision"
    local import_payload
    import_payload=$(python3 - "$app" "$M4_LOG_GATE_ENVIRONMENT_ID" "$source_id" "$number" <<'PY'
import json, sys
app, environment, source, number = sys.argv[1:]
compose = json.load(open("/dev/stdin")) if False else None
# The checked-in source tree supplies compose.json as a separate argument to
# curl below; this payload only contains immutable identity fields here.
print(json.dumps({"application_id": app, "environment_id": environment, "name": "m4-log-gate-" + number, "source_revision_id": source, "version": int(number) + 2}, separators=(",", ":")))
PY
)
    python3 - "$import_payload" "$compose" >"$work/log-002-import-$number.json" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
value["compose"] = json.load(open(sys.argv[2], encoding="utf-8"))
json.dump(value, sys.stdout, separators=(",", ":"))
PY
    m4_log_gate_control_curl --fail --silent --show-error -H 'Content-Type: application/json' -H "Idempotency-Key: ${run_id}-log-002-group-${number}" --data @"$work/log-002-import-$number.json" "$api/api/v1/service-groups/import" >"$evidence/log-002-group-$number.json"
    group=$(m4_log_gate_json_get "$evidence/log-002-group-$number.json" service_group.id)
    release_payload=$(python3 - "$source_id" "$number" <<'PY'
import json, sys
print(json.dumps({"source_revision_id": sys.argv[1], "version": int(sys.argv[2]) + 2}, separators=(",", ":")))
PY
)
    status=$(m4_log_gate_control_curl --silent --show-error -o "$evidence/log-002-release-$number.json" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: ${run_id}-log-002-release-${number}" --data "$release_payload" "$api/api/v1/service-groups/$group/releases")
    [[ "$status" = 201 ]] || m4_log_gate_die "BuildKit release $number returned HTTP $status"
    printf '%s|%s|%s\n' "$number" "$source_id" "$group" >>"$rows"
  done

  # Read-only database correlation is necessary because a release response is
  # intentionally not a log index API.  It proves each public release caused
  # exactly one immutable Dockerfile Build rather than only accepting HTTP.
  psql "$M4_LOG_GATE_DATABASE_URL" -X -Aqt -F '|' -c "SELECT split_part(plan.idempotency_key,':',1),build.id FROM builds build JOIN build_plans plan ON plan.id=build.plan_id WHERE plan.idempotency_key LIKE '${M4_LOG_GATE_RUN_ID:-log-gate}-log-002-release-%:build-plan:frontend' AND build.state='succeeded' ORDER BY build.created_at,build.id" >"$evidence/log-002-build-identities.tsv"
  python3 - "$rows" "$evidence/log-002-build-identities.tsv" "$M4_LOG_GATE_LOG_ROOT" <<'PY'
import os, sys
requests = [line.rstrip("\n").split("|") for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
builds = [line.rstrip("\n").split("|", 1) for line in open(sys.argv[2], encoding="utf-8") if line.strip()]
assert len(requests) == 21 and len({row[0] for row in requests}) == 21, requests
assert len(builds) == 21 and len({row[1] for row in builds}) == 21, builds
root = os.path.realpath(sys.argv[3])
assert root == "/var/lib/open-card/build-work/m4-logs", root
paths = [os.path.join(root, "build", "build-" + build_id) for _, build_id in builds]
assert not os.path.exists(paths[0]), "oldest of 21 BuildKit executions survived retention"
for path in paths[1:]:
    assert os.path.isdir(path) and not os.path.islink(path), path
    assert any(name.startswith("segment-") and name.endswith(".log") for name in os.listdir(path)), path
PY
}

m4_log_gate_restart_and_verify_build_recovery() {
  local api=$M4_LOG_GATE_API evidence=$M4_LOG_GATE_EVIDENCE
  systemctl restart open-card-server
  m4_log_gate_wait_ready "$api"
  m4_log_gate_control_curl --fail --silent --show-error "$api/api/v1/applications/$M4_LOG_GATE_APP_ID/logs?category=build&limit=100" >"$evidence/log-002-build-operator-after-restart.json"
  python3 - "$evidence/log-002-build-operator-after-restart.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["mode"] == "operator"
assert any(item.get("category") == "build" for item in value.get("items", [])), value
PY
}

# LOG-001 intentionally requires a product-owned capture operation.  The
# browser/operator read endpoint is read-only; it cannot be repurposed into an
# arbitrary Agent task submission.  A caller must provide the stream produced
# by that typed operation.  This protects the test from manufacturing rotated
# files outside the product path just to make a green result.
m4_log_gate_assert_runtime_rotation() {
  m4_log_gate_require M4_LOG_GATE_RUNTIME_STREAM
  m4_log_gate_require M4_LOG_GATE_RUNTIME_MARKER
  local stream=$M4_LOG_GATE_RUNTIME_STREAM marker=$M4_LOG_GATE_RUNTIME_MARKER
  local threshold=${M4_LOG_GATE_RUNTIME_MAX_FILE_BYTES:-10485760} root=$M4_LOG_GATE_LOG_ROOT evidence=$M4_LOG_GATE_EVIDENCE
  m4_log_gate_safe_component "$stream"
  [[ "$threshold" =~ ^[1-9][0-9]*$ ]] || m4_log_gate_die "runtime file threshold is invalid"
  python3 - "$root" "$stream" "$marker" "$threshold" <<'PY'
import os, sys
root, stream, marker, threshold = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
directory = os.path.join(root, "runtime", stream)
assert os.path.isdir(directory) and not os.path.islink(directory), directory
files = sorted(name for name in os.listdir(directory) if name.startswith("segment-") and name.endswith(".log"))
assert len(files) >= 2, "runtime capture did not rotate one logical stream"
content = b""
for name in files:
    path = os.path.join(directory, name)
    assert not os.path.islink(path) and os.path.getsize(path) <= threshold, path
    content += open(path, "rb").read()
assert marker.encode() in content, "cross-segment runtime content is incomplete"
PY
  m4_log_gate_control_curl --fail --silent --show-error "$M4_LOG_GATE_API/api/v1/applications/$M4_LOG_GATE_APP_ID/logs?category=runtime&limit=100" >"$evidence/log-001-runtime-operator.json"
  python3 - "$evidence/log-001-runtime-operator.json" "$marker" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["mode"] == "operator"
items = [item for item in value.get("items", []) if item.get("category") == "runtime"]
assert items and any(sys.argv[2] in item.get("content", "") for item in items), value
PY
}

m4_log_gate_assert_audit_survives_ordinary_gc() {
  local evidence=$M4_LOG_GATE_EVIDENCE before after
  before=$(tr -d '[:space:]' <"$evidence/log-003-audit-before.txt")
  [[ "$before" =~ ^[1-9][0-9]*$ ]] || m4_log_gate_die "audit baseline is absent or invalid"
  # The 21st public BuildKit release has already exercised LogStore's ordinary
  # retention GC.  AuditEvidence resides in its append-only table, not in the
  # ordinary local file quota; only read it here.
  after=$(psql "$M4_LOG_GATE_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM audit_evidence WHERE action LIKE 'operations.%'")
  printf '%s\n' "$after" >"$evidence/log-003-audit-after.txt"
  [[ "$after" =~ ^[0-9]+$ && "$after" -ge "$before" ]] || m4_log_gate_die "ordinary log GC changed audit evidence"
}

m4_log_gate_assert_redaction() {
  local canary=${M4_LOG_GATE_REDACTION_CANARY:-m4-log-canary} evidence=$M4_LOG_GATE_EVIDENCE
  m4_log_gate_control_curl --fail --silent --show-error "$M4_LOG_GATE_API/api/v1/applications/$M4_LOG_GATE_APP_ID/logs?limit=100" >"$evidence/log-gates-operator-redaction.json"
  python3 - "$evidence/log-gates-operator-redaction.json" "$canary" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
value = json.loads(text)
assert value["mode"] == "operator"
assert sys.argv[2] not in text, "known log canary leaked through operator API"
assert "[REDACTED]" in text, "operator API did not expose redaction evidence"
PY
}

run_m4_log_gate_guest() {
  m4_log_gate_require_context
  m4_log_gate_capture_audit_before
  m4_log_gate_reject_sensitive_runtime_literal
  m4_log_gate_build_twenty_one
  m4_log_gate_restart_and_verify_build_recovery
  m4_log_gate_assert_audit_survives_ordinary_gc
  m4_log_gate_assert_runtime_rotation
  m4_log_gate_assert_redaction
  printf '%s\n' \
    'RUNNER_CONTRACT_ONLY=1' \
    'LOG-001=EXECUTED_VERIFIED' \
    'LOG-002=EXECUTED_VERIFIED' \
    'LOG-003=EXECUTED_VERIFIED' \
    'M4_GATE=NOT_CLAIMED'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  run_m4_log_gate_guest "$@"
fi
