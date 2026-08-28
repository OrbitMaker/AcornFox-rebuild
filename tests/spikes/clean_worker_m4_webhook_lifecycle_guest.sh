#!/usr/bin/env bash
set -euo pipefail

# M4 webhook lifecycle guest contract.  This helper is intentionally narrow:
# it consumes an already-installed task VM, configures one task-local HTTPS
# receiver, drives an existing operator redeploy API through the task-local
# Caddy fault fixture, and reads durable facts for independent assertions.
# It never mutates PostgreSQL directly and never converts a runner result into
# a milestone PASS.

task_prefix=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
api=${OPEN_CARD_M4_API_BASE_URL:-http://127.0.0.1:8080}
app=${OPEN_CARD_M4_WEBHOOK_APPLICATION_ID:?OPEN_CARD_M4_WEBHOOK_APPLICATION_ID is required}
database_url=${OPEN_CARD_DATABASE_URL:?OPEN_CARD_DATABASE_URL is required}
fault_fixture=${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_URL:?OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_URL is required}
fault_token_file=${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_TOKEN_FILE:?OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_TOKEN_FILE is required}
evidence=${OPEN_CARD_M4_WEBHOOK_EVIDENCE_DIR:-/var/lib/opencard-mvp-fa8f8eab/evidence/m4-webhook-lifecycle}
work=${OPEN_CARD_M4_WEBHOOK_WORK_DIR:-/var/lib/opencard-mvp-fa8f8eab/m4-webhook-lifecycle-work}
receiver_port=${OPEN_CARD_M4_WEBHOOK_RECEIVER_PORT:-19444}
receiver_host=opencard-webhook-fixture.test
run_id=${OPEN_CARD_M4_WEBHOOK_RUN_ID:-$(openssl rand -hex 8)}
secretctl=${OPEN_CARD_SECRETCTL_BINARY:-/opt/open-card/current/bin/open-card-secretctl}

# These are contract labels only.  A canonical VM runner and strict evidence
# merger must decide the milestone state.
runner_contract_only=1
m4_gate=NOT_CLAIMED
receiver_pid=
host_entry_added=0
request_pid=
m4_admin_session=

case "$api" in
  http://127.0.0.1:*|https://127.0.0.1:*) ;;
  *) echo "M4 webhook lifecycle helper requires a loopback control-plane API" >&2; exit 1 ;;
esac
test "${OPEN_CARD_M4_WEBHOOK_LIFECYCLE_EXECUTE:-}" = 1
test -f /etc/opencard-mvp-fa8f8eab-clean-worker
test ! -L /etc/opencard-mvp-fa8f8eab-clean-worker
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
[[ "$evidence" = "/var/lib/$task_prefix/evidence/"* ]]
[[ "$work" = "/var/lib/$task_prefix/m4-"* ]]
for task_path in "$evidence" "$work"; do
  [[ "$task_path" != *..* && "$task_path" != *$'\n'* && "$task_path" != *$'\r'* ]]
  [[ ! -e "$task_path" || ! -L "$task_path" ]]
  task_parent=$(dirname "$task_path")
  [[ -d "$task_parent" && ! -L "$task_parent" ]]
  resolved_task_path=$(realpath -m "$task_path")
  [[ "$resolved_task_path" = "/var/lib/$task_prefix/"* && "$resolved_task_path" != "/var/lib/$task_prefix" ]]
done
test "${OPEN_CARD_M4_ENABLED:-}" = true
test "${OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE:-}" = true
test "${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE:-}" = enabled
test "$fault_fixture" = http://127.0.0.1:2020
test -r "$fault_token_file"
test "$(stat -c '%a' "$fault_token_file")" = 600
[[ "$receiver_port" =~ ^[0-9]+$ && "$receiver_port" -ge 1024 && "$receiver_port" -le 65535 ]]
test -x "$secretctl"

rm -rf -- "$work" "$evidence"
install -d -m 0750 "$work" "$evidence"

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

m4_authenticate

cleanup() {
  set +e
  [[ -n "$request_pid" ]] && kill "$request_pid" >/dev/null 2>&1 || true
  [[ -n "$receiver_pid" ]] && kill "$receiver_pid" >/dev/null 2>&1 || true
  wait >/dev/null 2>&1 || true
  [[ "$host_entry_added" = 1 ]] && sed -i '\|^127\.0\.0\.1 opencard-webhook-fixture\.test # opencard-mvp-fa8f8eab-m4-webhook-lifecycle$|d' /etc/hosts || true
  update-ca-certificates >/dev/null 2>&1 || true
  rm -f /usr/local/share/ca-certificates/opencard-m4-webhook-lifecycle.crt
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

json_get() {
  python3 - "$1" "$2" <<'PY'
import json,sys
value=json.load(open(sys.argv[1], encoding='utf-8'))
for part in sys.argv[2].split('.'):
    if part:
        value=value[int(part)] if isinstance(value,list) else value[part]
print(value if not isinstance(value,(dict,list)) else json.dumps(value,separators=(',',':')))
PY
}

query_operation_id() {
  local key=$1
  psql "$database_url" -X -Aqt -c "SELECT id FROM operations WHERE idempotency_key='$key' ORDER BY created_at DESC,id DESC LIMIT 1" | tr -d '[:space:]'
}

wait_ready() {
  for _ in $(seq 1 120); do
    curl -fsS "$api/readyz" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

wait_operations_serving() {
  local output=$1 status=
  for _ in $(seq 1 600); do
    status=$(curl -sS -o "$output" -w '%{http_code}' "$api/api/v1/applications/$app/operations" || true)
    if [[ "$status" = 200 ]] && python3 - "$output" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding='utf-8'))
raise SystemExit(0 if value.get('serving') is True else 1)
PY
    then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_phase() {
  local operation=$1 expected=$2 phase=
  for _ in $(seq 1 2400); do
    phase=$(psql "$database_url" -X -Aqt -c "SELECT phase FROM m4_rollout_coordinations WHERE operation_id='$operation'" | tr -d '[:space:]')
    [[ "$phase" = "$expected" ]] && return 0
    sleep 0.1
  done
  return 1
}

wait_operation() {
  local operation=$1 expected=$2 state=
  for _ in $(seq 1 2400); do
    state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM operations WHERE id='$operation'" | tr -d '[:space:]')
    [[ "$state" = "$expected" ]] && return 0
    sleep 0.1
  done
  return 1
}

wait_webhook_row() {
  local endpoint=$1 expected_status=$2 expected_attempts=$3 output=$4
  for _ in $(seq 1 600); do
    psql "$database_url" -X -Aqt -F '|' -c "SELECT delivery_status,attempt_count FROM m4_webhook_events WHERE endpoint_id='$endpoint' AND delivery_status='$expected_status' AND attempt_count>=$expected_attempts ORDER BY occurred_at,event_id LIMIT 1" >"$output"
    if [[ -s "$output" ]]; then return 0; fi
    sleep 0.1
  done
  return 1
}

wait_webhook_retry() {
  local endpoint=$1 output=$2
  for _ in $(seq 1 600); do
    psql "$database_url" -X -Aqt -F '|' -c "SELECT event_id,event_type,delivery_status,attempt_count,received_count,occurred_at FROM m4_webhook_events WHERE endpoint_id='$endpoint' AND delivery_status='retry_wait' AND attempt_count>=1 ORDER BY occurred_at,event_id LIMIT 1" >"$output"
    if [[ -s "$output" ]]; then return 0; fi
    sleep 0.1
  done
  return 1
}

# The receiver is HTTPS-only, bound to loopback, and controlled by a file in
# the task work directory.  It starts in 500 mode so the first lifecycle
# notification is durably parked in retry_wait.  The helper changes it to 204
# only after checking that retry state and restarting the embedded workers.
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=opencard-m4-webhook-lifecycle-ca -days 1 -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=$receiver_host" -keyout "$work/receiver.key" -out "$work/receiver.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\n' "$receiver_host" >"$work/receiver.ext"
openssl x509 -req -in "$work/receiver.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 -extfile "$work/receiver.ext" -out "$work/receiver.crt" >/dev/null 2>&1
install -m 0644 "$work/ca.crt" /usr/local/share/ca-certificates/opencard-m4-webhook-lifecycle.crt
update-ca-certificates >/dev/null
printf '127.0.0.1 %s # opencard-mvp-fa8f8eab-m4-webhook-lifecycle\n' "$receiver_host" >>/etc/hosts
host_entry_added=1
receiver_status="$work/receiver-status"
printf '500\n' >"$receiver_status"
receiver_capture="$evidence/receiver-capture.ndjson"
python3 - "$work/receiver.crt" "$work/receiver.key" "$receiver_capture" "$receiver_port" "$receiver_status" <<'PY' >"$evidence/receiver.log" 2>&1 &
import http.server,json,ssl,sys,threading
cert,key,capture,port,status_file=sys.argv[1:]
status_lock=threading.Lock()
def response_status():
  with status_lock:
    try:
      return int(open(status_file, encoding='utf-8').read().strip())
    except (OSError,ValueError):
      return 500
class H(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
    body=self.rfile.read(int(self.headers.get('content-length','0')))
    status=response_status()
    with open(capture,'a',encoding='utf-8') as output:
      output.write(json.dumps({'event_id':self.headers.get('X-Open-Card-Event-ID'),'event_type':self.headers.get('X-Open-Card-Event-Type'),'timestamp':self.headers.get('X-Open-Card-Timestamp'),'signature':self.headers.get('X-Open-Card-Signature'),'status':status,'body':body.decode('utf-8')})+'\n')
    self.send_response(status); self.end_headers()
  def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',int(port)),H)
tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(certfile=cert,keyfile=key)
server.socket=tls.wrap_socket(server.socket,server_side=True)
server.serve_forever()
PY
receiver_pid=$!
for _ in $(seq 1 100); do ss -ltnH "sport = :$receiver_port" | grep -q "127.0.0.1:$receiver_port" && break; sleep 0.1; done
ss -ltnH "sport = :$receiver_port" | grep -q "127.0.0.1:$receiver_port"

# Store only an opaque reference.  The canary is fed on stdin and never enters
# the API request, PostgreSQL assertions, receiver capture, or evidence files.
webhook_secret_ref="$work/webhook-secret.json"
printf 'm4-fixture-signing-key' | sudo -u opencard "$secretctl" --root "$OPEN_CARD_SECRET_ROOT" --material-root "$OPEN_CARD_SECRET_MATERIAL_ROOT" --master-key "$OPEN_CARD_SECRET_MASTER_KEY" --id "m4-webhook-lifecycle-$run_id" --name webhook --version v1 >"$webhook_secret_ref"
webhook_payload=$(python3 - "$webhook_secret_ref" "$receiver_port" <<'PY'
import json,sys
print(json.dumps({'url':'https://opencard-webhook-fixture.test:'+sys.argv[2]+'/events','secret_ref':json.load(open(sys.argv[1])),'event_types':['notification.occurrence','notification.escalation','notification.recovery']},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: m4-webhook-lifecycle-config-$run_id" --data "$webhook_payload" "$api/api/v1/applications/$app/webhooks" >"$evidence/webhook-config.json"
webhook_id=$(json_get "$evidence/webhook-config.json" endpoint.id)
test -n "$webhook_id"
psql "$database_url" -X -Aqt -c "SELECT event_types::text FROM m4_webhook_endpoints WHERE id='$webhook_id'" >"$evidence/webhook-event-types.txt"
for event_type in notification.occurrence notification.escalation notification.recovery; do grep -Fq "$event_type" "$evidence/webhook-event-types.txt"; done

# The fault fixture is the only supported task-local way to produce a real
# failed route observation without mutating DB state.  The operation request
# itself remains the normal public API and the embedded outbox/notification
# workers must observe its lifecycle.
failure_key="m4-webhook-lifecycle-failure-$run_id"
failure_operation=
failure_response=
failure_status_file=
for failure_attempt in $(seq 1 20); do
  wait_operations_serving "$evidence/operations-before-failure.json"
  expected_version=$(json_get "$evidence/operations-before-failure.json" version)
  failure_body=$(python3 - "$expected_version" <<'PY'
import json,sys
print(json.dumps({'action':'redeploy','expected_version':sys.argv[1],'reason':'M4 webhook lifecycle failure fixture'},separators=(',',':')))
PY
)
  failure_response="$evidence/failure-operation-attempt-$failure_attempt.json"
  failure_status_file="$work/failure-operation-attempt-$failure_attempt.status"
  curl -sS -o "$failure_response" -w '%{http_code}' -H 'Content-Type: application/json' -H "Idempotency-Key: $failure_key" --data "$failure_body" "$api/api/v1/applications/$app/operations" >"$failure_status_file" &
  request_pid=$!
  for _ in $(seq 1 40); do
    failure_operation=$(query_operation_id "$failure_key")
    [[ -n "$failure_operation" ]] && break
    sleep 0.1
  done
  [[ -n "$failure_operation" ]] && break
  wait "$request_pid"
  request_pid=
  failure_status=$(cat "$failure_status_file")
  [[ "$failure_status" = 409 ]] || { cat "$failure_response" >&2; exit 1; }
  sleep 0.25
done
test -n "$failure_operation"
route_digest=
for _ in $(seq 1 240); do
  route_digest=$(psql "$database_url" -X -Aqt -c "SELECT route_set_digest FROM m4_rollout_coordinations WHERE operation_id='$failure_operation'" | tr -d '[:space:]')
  [[ "$route_digest" =~ ^sha256:[0-9a-f]{64}$ ]] && break
  sleep 0.1
done
test "$route_digest" != ""
fault_curl_config="$work/fault-curl.conf"
umask 077
printf 'header = "Authorization: Bearer %s"\nheader = "X-Open-Card-Task-Scope: %s"\n' "$(cat "$fault_token_file")" "$task_prefix" >"$fault_curl_config"
curl -fsS --config "$fault_curl_config" -H 'Content-Type: application/json' --data "$(python3 - "$failure_operation" "$route_digest" <<'PY'
import json,sys
print(json.dumps({'rollout_id':sys.argv[1],'route_set_digest':sys.argv[2],'mode':'observe'},separators=(',',':')))
PY
)" "$fault_fixture/__fixture/fault" >"$evidence/failure-fixture.json"
rm -f -- "$fault_curl_config"
wait "$request_pid"
request_pid=
failure_status=$(cat "$failure_status_file")
cp "$failure_response" "$evidence/failure-operation.json"
test "$failure_status" = 202
wait_phase "$failure_operation" failed
wait_operation "$failure_operation" failed

# Capture and prove the first durable retry before allowing the receiver to
# recover.  This is a read-only DB assertion; the only write is the task-local
# receiver status file and the normal recovery operation API below.
wait_webhook_retry "$webhook_id" "$evidence/webhook-before-restart.tsv"
retry_event_id=$(cut -d '|' -f 1 "$evidence/webhook-before-restart.tsv")
test -n "$retry_event_id"
systemctl restart open-card-server
wait_ready
for _ in $(seq 1 800); do
  psql "$database_url" -X -Aqt -F '|' -c "SELECT delivery_status,attempt_count,extract(epoch FROM (next_attempt_at-last_attempt_at))::int FROM m4_webhook_events WHERE endpoint_id='$webhook_id' AND event_id='$retry_event_id'" >"$evidence/webhook-three-retries.tsv"
  grep -Eq '^retry_wait\|3\|3[0-1]$' "$evidence/webhook-three-retries.tsv" && break
  sleep 0.1
done
grep -Eq '^retry_wait\|3\|3[0-1]$' "$evidence/webhook-three-retries.tsv"
psql "$database_url" -X -Aqt -F '|' -c "SELECT attempt_number,extract(epoch FROM (created_at-lag(created_at) OVER (ORDER BY attempt_number))) FROM m4_webhook_attempts WHERE endpoint_id='$webhook_id' AND event_id='$retry_event_id' ORDER BY attempt_number" >"$evidence/webhook-retry-delays.tsv"
python3 - "$evidence/webhook-retry-delays.tsv" <<'PY'
import sys
rows=[line.rstrip('\n').split('|') for line in open(sys.argv[1],encoding='utf-8') if line.strip()]
assert [int(row[0]) for row in rows[:3]] == [1,2,3], rows
assert float(rows[1][1]) >= 0.8, rows
assert float(rows[2][1]) >= 4.5, rows
PY
printf '204\n' >"$receiver_status"
wait_webhook_row "$webhook_id" delivered 4 "$evidence/webhook-recovered-row.txt"

# Recovery is a second normal operation request.  It must be observed after
# failure/escalation facts and must not be synthesized by SQL.
curl -fsS "$api/api/v1/applications/$app/operations" >"$evidence/operations-before-recovery.json"
recovery_version=$(json_get "$evidence/operations-before-recovery.json" version)
recovery_key="m4-webhook-lifecycle-recovery-$run_id"
recovery_body=$(python3 - "$recovery_version" <<'PY'
import json,sys
print(json.dumps({'action':'redeploy','expected_version':sys.argv[1],'reason':'M4 webhook lifecycle recovery'},separators=(',',':')))
PY
)
curl -fsS -H 'Content-Type: application/json' -H "Idempotency-Key: $recovery_key" --data "$recovery_body" "$api/api/v1/applications/$app/operations" >"$evidence/recovery-operation.json"
recovery_operation=$(query_operation_id "$recovery_key")
test -n "$recovery_operation"
wait_operation "$recovery_operation" succeeded
wait_phase "$recovery_operation" completed

for _ in $(seq 1 800); do
  psql "$database_url" -X -Aqt -F '|' -c "SELECT event_id,event_type,delivery_status,attempt_count,received_count,occurred_at FROM m4_webhook_events WHERE endpoint_id='$webhook_id' ORDER BY occurred_at,event_id" >"$evidence/webhook-events.tsv"
  delivered_kinds=$(awk -F '|' '$3=="delivered" {seen[$2]=1} END {print length(seen)}' "$evidence/webhook-events.tsv")
  [[ "$delivered_kinds" = 3 ]] && break
  sleep 0.1
done
python3 - "$evidence/webhook-events.tsv" "$receiver_capture" <<'PY'
import collections,hashlib,hmac,json,sys
rows=[]
for line in open(sys.argv[1],encoding='utf-8'):
  fields=line.rstrip('\n').split('|')
  if len(fields)==6: rows.append(fields)
records=[json.loads(line) for line in open(sys.argv[2],encoding='utf-8') if line.strip()]
assert rows, 'no durable webhook lifecycle rows'
assert all(row[2]=='delivered' for row in rows), rows
kind_order={'notification.occurrence':0,'notification.escalation':1,'notification.recovery':2}
kinds=[row[1] for row in rows]
assert {'notification.occurrence','notification.escalation','notification.recovery'}.issubset(kinds), rows
by_id=collections.defaultdict(list)
for record in records:
  by_id[record.get('event_id')].append(record)
assert any(any(item.get('status')==500 for item in values) and any(item.get('status')==204 for item in values) for values in by_id.values()), records
for record in records:
  event_id=record.get('event_id'); timestamp=record.get('timestamp'); signature=record.get('signature'); body=record.get('body','').encode()
  assert event_id and timestamp and signature, record
  expected='sha256='+hmac.new(b'm4-fixture-signing-key',(str(int(timestamp))+'.'+event_id+'.').encode()+body,hashlib.sha256).hexdigest()
  assert hmac.compare_digest(signature,expected), record
  lower=body.decode('utf-8').lower()
  for forbidden in ('m4-fixture-signing-key','authorization','cookie','password','secret'):
    assert forbidden not in lower, (forbidden,record)
captured_types=[record.get('event_type') for record in records if record.get('event_type') in kind_order]
first={kind:captured_types.index(kind) for kind in kind_order if kind in captured_types}
assert set(first)==set(kind_order), captured_types
assert first['notification.occurrence'] < first['notification.escalation'] < first['notification.recovery'], captured_types
PY
! grep -R -a -E 'm4-fixture-signing-key|BEGIN .*PRIVATE KEY|authorization: bearer|cookie=' "$evidence" /var/log/open-card /var/lib/open-card/ai 2>/dev/null

printf '%s\n' \
  'CT-NOTIFY=RUNNER_CONTRACT_ONLY' \
  'SEC-WEBHOOK=RUNNER_CONTRACT_ONLY' \
  'FAULT-WEBHOOK=RUNNER_CONTRACT_ONLY' \
  'M4_WEBHOOK_LIFECYCLE_GATE=NOT_CLAIMED'
