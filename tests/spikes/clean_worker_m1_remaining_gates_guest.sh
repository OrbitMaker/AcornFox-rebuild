#!/usr/bin/env bash
set -euo pipefail

# This is a real clean-worker acceptance script.  It deliberately uses only
# the public M1 HTTP surface and read-only PostgreSQL/Docker inspection; it
# never changes a database outcome by hand.
task_prefix=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
evidence_root=/var/lib/opencard-mvp-fa8f8eab/evidence/m1-remaining-gates
probe_root=/var/lib/opencard-mvp-fa8f8eab/m1-remaining-build-probes
fixed_port=38123
gateway_port=8092

test "$(id -u)" -eq 0
test -f /etc/opencard-mvp-fa8f8eab-clean-worker
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
test -f /etc/open-card/server.env
set -a
source /etc/open-card/server.env
set +a

server_addr=${OPEN_CARD_SERVER_ADDR:-127.0.0.1:8080}
api_base=http://$server_addr
upload_root=${OPEN_CARD_SOURCE_UPLOAD_ROOT:-/var/lib/open-card/uploads}
test_upload_root=$upload_root/opencard-mvp-fa8f8eab-m1-remaining
buildctl=${OPEN_CARD_BUILDKIT_COMMAND:-/opt/open-card/current/bin/buildctl}
buildkit_address=${OPEN_CARD_BUILDKIT_ADDRESS:-unix:///run/open-card-buildkit/buildkitd.sock}
buildkit_home=/var/lib/open-card-buildkit
buildkit_runtime=/run/open-card-buildkit
static_server=${OPEN_CARD_STATIC_SERVER_BINARY:-/opt/open-card/current/bin/open-card-static-server}
static_digest=${OPEN_CARD_STATIC_RUNTIME_DIGEST:-}

for required in OPEN_CARD_DATABASE_URL OPEN_CARD_SOURCE_UPLOAD_ROOT OPEN_CARD_SOURCE_WORKSPACE_ROOT OPEN_CARD_BUILD_WORK_ROOT OPEN_CARD_OCI_STORE_ROOT OPEN_CARD_SECRET_ROOT OPEN_CARD_SECRET_MATERIAL_ROOT OPEN_CARD_SECRET_MASTER_KEY; do
  test -n "${!required:-}"
done
test "${OPEN_CARD_RUNTIME_TASK_PREFIX:-$task_prefix}" = "$task_prefix"
test "${OPEN_CARD_AGENT_GATEWAY_ADDR##*:}" = "$gateway_port"
test -x "$buildctl"
test -f "$static_server"
test "sha256:$(sha256sum "$static_server" | awk '{print $1}')" = "$static_digest"
test "$(systemctl is-active open-card-server)" = active
test "$(systemctl is-active open-card-agent)" = active
test "$(systemctl is-active open-card-buildkit)" = active
curl -fsS "$api_base/readyz" >/dev/null

install -d -m 0750 "$evidence_root" "$test_upload_root"
install -d -m 0750 -o opencard-buildkit -g opencard-buildkit "$probe_root"
chmod 0750 "$evidence_root" "$probe_root" "$test_upload_root"
security_probe=/opt/open-card/current/bin/open-card-security-probe
test -x "$security_probe"

cleanup_done=0
port_holder_pid=
fixed_dropin=
iptables_rule_active=0
agent_stopped_by_script=0
cleanup() {
  (( cleanup_done )) && return
  cleanup_done=1
  set +e
  if (( iptables_rule_active )); then
    iptables -D OUTPUT -p tcp --dport "$gateway_port" -j REJECT >/dev/null 2>&1 || true
    iptables_rule_active=0
  fi
  if [[ -n "$port_holder_pid" ]]; then
    kill "$port_holder_pid" >/dev/null 2>&1 || true
    wait "$port_holder_pid" >/dev/null 2>&1 || true
    port_holder_pid=
  fi
  if [[ -n "$fixed_dropin" && -e "$fixed_dropin" ]]; then
    rm -f -- "$fixed_dropin"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart open-card-server >/dev/null 2>&1 || true
    for _ in $(seq 1 50); do
      curl -fsS "$api_base/readyz" >/dev/null 2>&1 && break
      sleep 0.1
    done
  fi
  if (( agent_stopped_by_script )); then
    systemctl start open-card-agent >/dev/null 2>&1 || true
  fi
  rm -rf -- "$probe_root" "$test_upload_root"
}
trap cleanup EXIT INT TERM

db_counts() {
  psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -F '|' -c \
    "SELECT (SELECT count(*) FROM source_revisions),(SELECT count(*) FROM builds),(SELECT count(*) FROM releases),(SELECT count(*) FROM deployments),(SELECT count(*) FROM task_leases),(SELECT count(*) FROM m1_publish_requests),(SELECT count(*) FROM delivery_definitions),(SELECT count(*) FROM build_plans),(SELECT count(*) FROM artifacts),(SELECT count(*) FROM outbox_events),(SELECT count(*) FROM audit_evidence);" \
    | tr -d '[:space:]'
}

task_container_count() {
  docker ps -a --filter "label=open-card.task-prefix=$task_prefix" --format '{{.ID}}' \
    | awk 'NF {count++} END {print count+0}'
}

assert_counts_unchanged() {
  local expected_db=$1 expected_containers=$2
  test "$(db_counts)" = "$expected_db"
  test "$(task_container_count)" = "$expected_containers"
}

wait_ready() {
  for _ in $(seq 1 80); do
    if curl -fsS "$api_base/readyz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

create_application() {
  local name=$1 output=$2 status
  status=$(curl -sS --connect-timeout 5 --max-time 20 -o "$output" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' -H "Idempotency-Key: $name" \
    --data "{\"name\":\"$name\"}" "$api_base/api/v1/applications")
  test "$status" = 201
  mapfile -t application_facts < <(python3 - "$output" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
application = value.get("application", {})
for key in ("id",):
    if not application.get(key):
        raise SystemExit("application response omitted id")
for key in ("environment_id",):
    if not value.get(key):
        raise SystemExit("application response omitted environment_id")
if not value.get("operation_id"):
    raise SystemExit("application response omitted operation_id")
print(application["id"])
print(value["environment_id"])
print(value["operation_id"])
PY
  )
  test "${#application_facts[@]}" -eq 3
  app_id=${application_facts[0]}
  environment_id=${application_facts[1]}
  application_operation_id=${application_facts[2]}
  # Application creation owns a separate durable controller task in M0. Wait
  # for that transaction to reach a terminal state before taking a zero-side-
  # effect baseline for the independent M1 publish preflight.
  local task_state=
  for _ in $(seq 1 40); do
    task_state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c \
      "SELECT state FROM task_leases WHERE operation_id='$application_operation_id'")
    [[ "$task_state" = completed || "$task_state" = failed || "$task_state" = cancelled ]] && break
    sleep 0.1
  done
  [[ "$task_state" = completed || "$task_state" = failed || "$task_state" = cancelled ]]
}

write_publish_payload() {
  local output=$1 application_id=$2 env_id=$3 source_locator=$4 service_name=$5 target_repository=$6 storage_key=$7
  local build_cpu=$8 build_memory=$9 build_disk=${10} runtime_cpu=${11} runtime_memory=${12} runtime_disk=${13} runtime_pids=${14} secret_file=${15:-}
  python3 - "$output" "$application_id" "$env_id" "$source_locator" "$service_name" "$target_repository" "$storage_key" \
    "$build_cpu" "$build_memory" "$build_disk" "$runtime_cpu" "$runtime_memory" "$runtime_disk" "$runtime_pids" "$secret_file" <<'PY'
import json, sys

(
    output, application_id, environment_id, source_locator, service_name,
    target_repository, storage_key, build_cpu, build_memory, build_disk,
    runtime_cpu, runtime_memory, runtime_disk, runtime_pids, secret_file,
) = sys.argv[1:]
payload = {
    "application_id": application_id,
    "environment_id": environment_id,
    "service_group_id": "group_m1_remaining_gates",
    "service_name": service_name,
    "source": {"kind": "upload", "locator": source_locator},
    "build_kind": "dockerfile",
    "context_path": ".",
    "dockerfile_path": "Dockerfile",
    "target_repository": target_repository,
    "output_storage_key": storage_key,
    "build_resources": {
        "cpu_millis": int(build_cpu), "memory_bytes": int(build_memory),
        "disk_bytes": int(build_disk), "timeout_seconds": 300,
        "concurrency_slot": 1,
    },
    "build_network": {"mode": "none"},
    "runtime_resources": {
        "cpu_millis": int(runtime_cpu), "memory_bytes": int(runtime_memory),
        "disk_bytes": int(runtime_disk), "pids": int(runtime_pids),
    },
    "container_port": 8080,
    "version": 1,
    "actor": "m1-remaining-gates",
}
if secret_file:
    payload["build_secret_refs"] = [json.load(open(secret_file, encoding="utf-8"))]
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, separators=(",", ":"))
    handle.write("\n")
PY
  chmod 0640 "$output"
}

publish_status() {
  local key=$1 payload=$2 output=$3 status curl_error
  curl_error=$output.curl-error
  set +e
  status=$(curl -sS --connect-timeout 5 --max-time 360 -o "$output" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' -H "Idempotency-Key: $key" \
    --data-binary "@$payload" "$api_base/api/v1/publishes" 2>"$curl_error")
  local curl_status=$?
  set -e
  if (( curl_status != 0 )); then
    cat "$curl_error" >&2
    return 1
  fi
  printf '%s' "$status"
}

assert_capacity_rejection() {
  local status=$1 response=$2
  case "$status" in
    409) ;;
    *) echo "expected HTTP 409 capacity rejection, got $status" >&2; return 1 ;;
  esac
  grep -Fq '"code":"capacity_exceeded"' "$response"
}

assert_empty_children() {
  local directory=$1
  test -d "$directory"
  test -z "$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit)"
}

assert_no_canary_in_proc() {
  local path
  for path in /proc/[0-9]*/cmdline /proc/[0-9]*/environ; do
    [[ -r "$path" ]] || continue
    if tr '\0' '\n' <"$path" | grep -Fq -- "$canary"; then
      echo "secret canary found in process state" >&2
      return 1
    fi
  done
}

# A single application is enough to exercise both preflight branches; the
# baseline is taken after its deliberate application-creation side effect.
create_application m1-remaining-capacity "$evidence_root/capacity-application.json"
base_db=$(db_counts)
base_containers=$(task_container_count)

write_publish_payload "$evidence_root/capacity-build.json" "$app_id" "$environment_id" "$test_upload_root/base" web \
  open-card.local/apps/m1-capacity-build "$app_id/web" 500 $((512 * 1024 * 1024)) 9223372036854775807 250 $((64 * 1024 * 1024)) $((128 * 1024 * 1024)) 64
status=$(publish_status m1-capacity-build "$evidence_root/capacity-build.json" "$evidence_root/capacity-build-response.json")
assert_capacity_rejection "$status" "$evidence_root/capacity-build-response.json"
assert_counts_unchanged "$base_db" "$base_containers"

write_publish_payload "$evidence_root/capacity-runtime.json" "$app_id" "$environment_id" "$test_upload_root/base" web \
  open-card.local/apps/m1-capacity-runtime "$app_id/web" 500 $((512 * 1024 * 1024)) $((256 * 1024 * 1024)) 250 9223372036854775807 $((128 * 1024 * 1024)) 64
status=$(publish_status m1-capacity-runtime "$evidence_root/capacity-runtime.json" "$evidence_root/capacity-runtime-response.json")
assert_capacity_rejection "$status" "$evidence_root/capacity-runtime-response.json"
assert_counts_unchanged "$base_db" "$base_containers"

# Fixed-port capacity is exercised with the real server provider.  The
# drop-in, listener and daemon reload are all task-scoped and cleaned by trap.
fixed_dropin_dir=/etc/systemd/system/open-card-server.service.d
fixed_dropin=$fixed_dropin_dir/90-opencard-mvp-fa8f8eab-capacity.conf
test ! -e "$fixed_dropin"
install -d -m 0755 "$fixed_dropin_dir"
printf '%s\n' '[Service]' "Environment=OPEN_CARD_CAPACITY_FIXED_HOST_PORT=$fixed_port" >"$fixed_dropin"
systemctl daemon-reload
systemctl restart open-card-server
wait_ready
python3 - "$fixed_port" >"$evidence_root/fixed-port-holder.log" 2>&1 <<'PY' &
import socket, sys, time
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", port))
sock.listen(1)
while True:
    time.sleep(60)
PY
port_holder_pid=$!
for _ in $(seq 1 40); do
  ss -lntH "sport = :$fixed_port" | grep -q . && break
  sleep 0.1
done
ss -lntH "sport = :$fixed_port" | grep -q .
write_publish_payload "$evidence_root/capacity-port.json" "$app_id" "$environment_id" "$test_upload_root/base" web \
  open-card.local/apps/m1-capacity-port "$app_id/web" 500 $((512 * 1024 * 1024)) $((256 * 1024 * 1024)) 250 $((64 * 1024 * 1024)) $((128 * 1024 * 1024)) 64
status=$(publish_status m1-capacity-port "$evidence_root/capacity-port.json" "$evidence_root/capacity-port-response.json")
assert_capacity_rejection "$status" "$evidence_root/capacity-port-response.json"
assert_counts_unchanged "$base_db" "$base_containers"
kill "$port_holder_pid"
wait "$port_holder_pid" >/dev/null 2>&1 || true
port_holder_pid=
rm -f -- "$fixed_dropin"
systemctl daemon-reload
systemctl restart open-card-server
wait_ready
printf '%s\n' 'BUILD-INT-005=PASS'

# BuildKit negative tests run directly against the already-provisioned
# rootless worker.  No release controller or runtime container is involved.
sec_db=$(db_counts)
sec_containers=$(task_container_count)
install -d -m 0750 -o opencard-buildkit -g opencard-buildkit "$probe_root/isolation" "$probe_root/timeout"
install -m 0755 -o opencard-buildkit -g opencard-buildkit "$security_probe" "$probe_root/isolation/probe"
cat >"$probe_root/isolation/Dockerfile" <<'EOF'
FROM scratch
COPY probe /probe
RUN ["/probe","isolation"]
EOF
chown opencard-buildkit:opencard-buildkit "$probe_root/isolation/Dockerfile"
chmod 0640 "$probe_root/isolation/Dockerfile"

buildctl_as_builder() {
  sudo -u opencard-buildkit env HOME="$buildkit_home" XDG_RUNTIME_DIR="$buildkit_runtime" \
    "$buildctl" --addr "$buildkit_address" "$@"
}

buildctl_as_builder build --frontend dockerfile.v0 --local context="$probe_root/isolation" --local dockerfile="$probe_root/isolation" \
  --opt filename=Dockerfile --opt network=none --no-cache --progress plain \
  --output "type=oci,dest=$probe_root/isolation/result.oci" >"$evidence_root/sec-build-isolation.log" 2>&1
test -s "$probe_root/isolation/result.oci"
test "$(db_counts)" = "$sec_db"
test "$(task_container_count)" = "$sec_containers"

install -m 0755 -o opencard-buildkit -g opencard-buildkit "$security_probe" "$probe_root/timeout/probe"
cat >"$probe_root/timeout/Dockerfile" <<'EOF'
FROM scratch
COPY probe /probe
RUN ["/probe","sleep"]
EOF
chown opencard-buildkit:opencard-buildkit "$probe_root/timeout/Dockerfile"
chmod 0640 "$probe_root/timeout/Dockerfile"
set +e
timeout --signal=TERM --kill-after=5 8 sudo -u opencard-buildkit env HOME="$buildkit_home" XDG_RUNTIME_DIR="$buildkit_runtime" \
  "$buildctl" --addr "$buildkit_address" build --frontend dockerfile.v0 --local context="$probe_root/timeout" --local dockerfile="$probe_root/timeout" \
  --opt filename=Dockerfile --opt network=none --no-cache --progress plain \
  --output "type=oci,dest=$probe_root/timeout/result.oci" >"$evidence_root/sec-build-timeout.log" 2>&1
timeout_status=$?
set -e
test "$timeout_status" -ne 0
test ! -s "$probe_root/timeout/result.oci"
rm -f -- "$probe_root/timeout/result.oci"
test ! -e "$probe_root/timeout/result.oci"
sleep 1
test -z "$(pgrep -af '^buildkit-runc .*--bundle /var/lib/open-card-buildkit/' || true)"
buildctl_as_builder prune --all >"$evidence_root/sec-build-prune.log" 2>&1
test "$(db_counts)" = "$sec_db"
test "$(task_container_count)" = "$sec_containers"
rm -rf -- "$probe_root/isolation" "$probe_root/timeout"
assert_empty_children "$probe_root"
assert_empty_children "$OPEN_CARD_BUILD_WORK_ROOT"
printf '%s\n' 'SEC-BUILD-001=PASS' 'SEC-BUILD-002=PASS'

# Prepare source trees under the configured upload boundary.  The only
# runtime binary is the digest-checked canonical bundle binary already wired
# into server.env; no QGA/file injection or alternate source tree is used.
mkdir -p "$test_upload_root/base" "$test_upload_root/missing-secret" "$test_upload_root/secret-delay"
cp -- "$static_server" "$test_upload_root/base/open-card-static-server"
cp -- "$security_probe" "$test_upload_root/base/security-probe"
printf '%s\n' '<!doctype html><title>capacity fixture</title><h1>m1-capacity</h1>' >"$test_upload_root/base/index.html"
cat >"$test_upload_root/base/Dockerfile" <<'EOF'
FROM scratch
COPY --chmod=0555 open-card-static-server /open-card-static-server
COPY --chown=65532:65532 index.html /www/index.html
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/open-card-static-server","-root","/www","-listen",":8080"]
EOF
cp -a "$test_upload_root/base/." "$test_upload_root/missing-secret/"
cat >"$test_upload_root/missing-secret/Dockerfile" <<'EOF'
FROM scratch
COPY --chmod=0555 security-probe /probe
RUN --mount=type=secret,id=canary ["/probe","secret","canary","sha256:0000000000000000000000000000000000000000000000000000000000000000"]
EOF
cp -a "$test_upload_root/base/." "$test_upload_root/secret-delay/"
printf '%s\n' '<!doctype html><title>secret canary</title><h1>m1-secret</h1>' >"$test_upload_root/secret-delay/index.html"
find "$test_upload_root" -type f -exec chmod 0644 {} +
find "$test_upload_root" -type f \( -name open-card-static-server -o -name security-probe \) -exec chmod 0755 {} +
chmod 0755 "$test_upload_root" "$test_upload_root"/*

missing_ref_file=$evidence_root/missing-secret-reference.json
cat >"$missing_ref_file" <<'EOF'
{"id":"secret_m1_remaining_missing","name":"canary","provider":"filesystem-secret","version":"v1"}
EOF
create_application m1-remaining-secret "$evidence_root/secret-application.json"
missing_db=$(db_counts)
missing_containers=$(task_container_count)
write_publish_payload "$evidence_root/missing-secret.json" "$app_id" "$environment_id" "$test_upload_root/missing-secret" missing \
  open-card.local/apps/m1-missing-secret "$app_id/missing" 500 $((512 * 1024 * 1024)) $((256 * 1024 * 1024)) 250 $((64 * 1024 * 1024)) $((128 * 1024 * 1024)) 64 "$missing_ref_file"
status=$(publish_status m1-secret-missing "$evidence_root/missing-secret.json" "$evidence_root/missing-secret-response.json")
case "$status" in
  2??) echo "missing secret unexpectedly published with HTTP $status" >&2; exit 1 ;;
esac
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM releases')" = "$(cut -d'|' -f3 <<<"$missing_db")"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM deployments')" = "$(cut -d'|' -f4 <<<"$missing_db")"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM task_leases')" = "$(cut -d'|' -f5 <<<"$missing_db")"
test "$(task_container_count)" = "$missing_containers"
assert_empty_children "$OPEN_CARD_SECRET_MATERIAL_ROOT"

create_application m1-remaining-secret-success "$evidence_root/secret-success-application.json"

canary="opencard-m1-secret-canary-$(openssl rand -hex 16)"
canary_digest="sha256:$(printf '%s' "$canary" | sha256sum | awk '{print $1}')"
canary_ref_id="secret_m1_remaining_canary_$(openssl rand -hex 8)"
canary_ref_file=$evidence_root/secret-reference.json
printf '%s' "$canary" | sudo -u opencard /opt/open-card/current/bin/open-card-secretctl \
  --root "$OPEN_CARD_SECRET_ROOT" --material-root "$OPEN_CARD_SECRET_MATERIAL_ROOT" \
  --master-key "$OPEN_CARD_SECRET_MASTER_KEY" --id "$canary_ref_id" --name canary --version v1 \
  >"$canary_ref_file"
cat >"$test_upload_root/secret-delay/Dockerfile" <<EOF
FROM scratch
COPY --chmod=0555 security-probe /probe
COPY --chmod=0555 open-card-static-server /open-card-static-server
COPY --chown=65532:65532 index.html /www/index.html
RUN --mount=type=secret,id=canary ["/probe","secret","canary","$canary_digest"]
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/open-card-static-server","-root","/www","-listen",":8080","-startup-delay","8s"]
EOF
chmod 0644 "$test_upload_root/secret-delay/Dockerfile"
python3 - "$canary_ref_file" "$canary_ref_id" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["id"] == sys.argv[2]
assert value["name"] == "canary"
assert value["provider"] == "filesystem-secret"
assert value["version"] == "v1"
PY
secret_db_before=$(db_counts)
secret_containers_before=$(task_container_count)
write_publish_payload "$evidence_root/secret-delay.json" "$app_id" "$environment_id" "$test_upload_root/secret-delay" secret-web \
  open-card.local/apps/m1-secret-delay "$app_id/secret-web" 500 $((512 * 1024 * 1024)) $((256 * 1024 * 1024)) 250 $((64 * 1024 * 1024)) $((128 * 1024 * 1024)) 64 "$canary_ref_file"

# The delayed-health publish is intentionally performed while the real mTLS
# gateway is unavailable.  The server can finish source/build/release and
# queue the task, but the Agent cannot heartbeat, poll, or acknowledge it.
iptables -I OUTPUT 1 -p tcp --dport "$gateway_port" -j REJECT
iptables_rule_active=1
outage_start_ms=$(date +%s%3N)
status=$(publish_status m1-secret-delay "$evidence_root/secret-delay.json" "$evidence_root/secret-delay-response.json")
test "$status" = 202
mapfile -t publish_facts < <(python3 - "$evidence_root/secret-delay-response.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for section, key in (("source_revision", "id"), ("build", "id"), ("release", "id"), ("deployment", "id"), ("operation", "id")):
    if not value.get(section, {}).get(key):
        raise SystemExit(f"publish response omitted {section}.{key}")
    print(value[section][key])
print(value.get("task_id", ""))
print(value.get("artifact", {}).get("image", {}).get("repository", ""))
print(value.get("artifact", {}).get("image", {}).get("digest", ""))
PY
)
test "${#publish_facts[@]}" -eq 8
source_revision_id=${publish_facts[0]}
build_id=${publish_facts[1]}
release_id=${publish_facts[2]}
deployment_id=${publish_facts[3]}
operation_id=${publish_facts[4]}
task_id=${publish_facts[5]}
image_repository=${publish_facts[6]}
image_digest=${publish_facts[7]}
test -n "$task_id" -a -n "$image_repository" -a -n "$image_digest"
test "$(db_counts)" != "$secret_db_before"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM builds WHERE id='$build_id'")" = succeeded
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment_id'")" != serving
test "$(task_container_count)" = "$secret_containers_before"

# Poll during, rather than after, the 18-second firewall window.  The Agent
# service is stopped at the end of that window so the expired 30-second lease
# is taken over by the controller before the Agent is restarted.
unknown_seen=0
agent_stop_done=0
while :; do
  now_ms=$(date +%s%3N)
  elapsed_ms=$((now_ms - outage_start_ms))
  state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment_id'")
  [[ "$state" = unknown ]] && unknown_seen=1
  if (( agent_stop_done == 0 && elapsed_ms >= 17000 )); then
    systemctl stop open-card-agent
    agent_stopped_by_script=1
    agent_stop_done=1
  fi
  (( elapsed_ms >= 18000 )) && break
  sleep 0.2
done
outage_end_ms=$(date +%s%3N)
test "$((outage_end_ms - outage_start_ms))" -ge 18000
test "$((outage_end_ms - outage_start_ms))" -lt 20000
test "$unknown_seen" = 1
iptables -D OUTPUT -p tcp --dport "$gateway_port" -j REJECT
iptables_rule_active=0
printf '%s\n' 'iptables_dport_8092_outage_ms='"$((outage_end_ms - outage_start_ms))" >"$evidence_root/agent-outage-window.txt"

takeover_seen=0
for _ in $(seq 1 70); do
  task_row=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -F '|' -c "SELECT attempt,state,last_agent_sequence FROM task_leases WHERE task_id='$task_id'")
  task_attempt=${task_row%%|*}
  if [[ "$task_attempt" =~ ^[0-9]+$ ]] && (( task_attempt >= 2 )); then
    takeover_seen=1
    break
  fi
  sleep 1
done
test "$takeover_seen" = 1
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation_id' AND event_type='operation.lease_taken_over'")" -ge 1
systemctl start open-card-agent
agent_stopped_by_script=0

for _ in $(seq 1 100); do
  state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment_id'")
  task_state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM task_leases WHERE task_id='$task_id'")
  if [[ "$state" = serving && "$task_state" = completed ]]; then
    break
  fi
  [[ "$state" = failed || "$task_state" = failed ]] && exit 1
  sleep 0.5
done
test "$state" = serving
test "$task_state" = completed
host_port=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT host_port FROM deployments WHERE id='$deployment_id'")
test "$host_port" -ge 1 -a "$host_port" -le 65535
curl -fsS "http://127.0.0.1:$host_port/healthz" | grep -Fxq ok
curl -fsS "http://127.0.0.1:$host_port/" | grep -Fq m1-secret

container=$(docker ps --filter "label=open-card.task-prefix=$task_prefix" --filter "label=open-card.deployment-id=$deployment_id" --format '{{.Names}}')
test -n "$container"
test "$(docker inspect "$container" --format '{{.Image}}')" = "$image_digest"
test "$(docker inspect "$container" --format '{{.HostConfig.Memory}}')" = 67108864
test "$(docker inspect "$container" --format '{{.HostConfig.MemorySwap}}')" = 67108864
test "$(docker inspect "$container" --format '{{.HostConfig.CpuPeriod}}')" = 100000
test "$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}')" = 25000
test "$(docker inspect "$container" --format '{{.HostConfig.PidsLimit}}')" = 64
test "$(docker inspect "$container" --format '{{.HostConfig.Privileged}}')" = false
test "$(docker inspect "$container" --format '{{json .Mounts}}')" = '[]'
binds=$(docker inspect "$container" --format '{{json .HostConfig.Binds}}')
cap_add=$(docker inspect "$container" --format '{{json .HostConfig.CapAdd}}')
[[ "$binds" = null || "$binds" = '[]' ]]
[[ "$cap_add" = null || "$cap_add" = '[]' ]]
test "$(docker inspect "$container" --format '{{index .Config.Labels "open-card.task-prefix"}}')" = "$task_prefix"
test "$(docker inspect "$container" --format '{{index .Config.Labels "open-card.deployment-id"}}')" = "$deployment_id"
test "$(docker inspect "$container" --format '{{json .HostConfig.PortBindings}}')" = "{\"8080/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"$host_port\"}]}"
test "$(task_container_count)" = "$((secret_containers_before + 1))"

task_event_sequences=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT string_agg(sequence::text,',' ORDER BY sequence) FROM task_agent_events WHERE task_id='$task_id'")
test "$task_event_sequences" = '1,2,3,4'
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT last_agent_sequence FROM task_leases WHERE task_id='$task_id'")" = 4
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation_id' AND event_type='deployment.unknown'")" -ge 1
printf '%s\n' 'RUNTIME-INT-002=PASS' 'FAULT-AGENT-001=PASS' 'FAULT-AGENT-002=PASS'

# Secret material and every durable/observable boundary are scanned only
# after the successful canary build has completed and the materialization has
# been revoked by BuildProvider.  The canary itself is never written to an
# evidence file.
assert_empty_children "$OPEN_CARD_SECRET_MATERIAL_ROOT"
secret_dump=$evidence_root/secret-db-data.sql
pg_dump --data-only --inserts "$OPEN_CARD_DATABASE_URL" >"$secret_dump"
if grep -Fq -- "$canary" "$secret_dump"; then exit 1; fi
for scan_root in "$OPEN_CARD_SECRET_ROOT" "$OPEN_CARD_SECRET_MATERIAL_ROOT" "$OPEN_CARD_BUILD_WORK_ROOT" "$OPEN_CARD_OCI_STORE_ROOT" "$buildkit_home" /var/log/open-card /var/log/open-card-agent /var/lib/open-card/evidence /var/lib/open-card/ai; do
  [[ -e "$scan_root" ]] || continue
  if grep -R -a -F -q -- "$canary" "$scan_root"; then
    echo "secret canary found in durable filesystem boundary" >&2
    exit 1
  fi
done
assert_no_canary_in_proc
journalctl --since '-20 minutes' --no-pager -u open-card-server -u open-card-agent -u open-card-buildkit >"$evidence_root/secret-journal.log" 2>&1 || true
if grep -Fq -- "$canary" "$evidence_root/secret-journal.log"; then exit 1; fi

image_ref=$image_digest
docker image inspect "$image_ref" >"$evidence_root/secret-image-inspect.json"
docker image inspect "$image_ref" --format '{{json .Config}}' >"$evidence_root/secret-image-config.json"
docker history --no-trunc "$image_ref" >"$evidence_root/secret-image-history.txt"
docker inspect "$container" >"$evidence_root/secret-container-inspect.json"
for image_metadata in "$evidence_root/secret-image-inspect.json" "$evidence_root/secret-image-config.json" "$evidence_root/secret-image-history.txt" "$evidence_root/secret-container-inspect.json"; do
  if grep -Fq -- "$canary" "$image_metadata"; then exit 1; fi
done

timeout --signal=TERM --kill-after=3 5 curl -sS --max-time 4 -N \
  -H 'Last-Event-ID: evt-0' "$api_base/api/v1/operations/$operation_id/events" \
  >"$evidence_root/secret-sse.log" 2>&1 || true
if grep -Fq -- "$canary" "$evidence_root/secret-sse.log"; then exit 1; fi
psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash FROM audit_evidence WHERE created_at > now()-interval '30 minutes';" \
  >"$evidence_root/secret-audit.txt"
if grep -Fq -- "$canary" "$evidence_root/secret-audit.txt"; then exit 1; fi
assert_empty_children "$OPEN_CARD_BUILD_WORK_ROOT"
printf '%s\n' 'SEC-SECRET-001=PASS'

# Both restarts are deliberately after the real container is serving.  The
# container, endpoint, operation/task rows, and immutable source/release facts
# must remain identical while the mTLS gateway/session are reconstructed.
restart_db=$(db_counts)
restart_container_count=$(task_container_count)
systemctl restart open-card-server
wait_ready
systemctl restart open-card-agent
for _ in $(seq 1 80); do
  state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment_id'")
  task_state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM task_leases WHERE task_id='$task_id'")
  if [[ "$state" = serving && "$task_state" = completed ]]; then break; fi
  sleep 0.5
done
test "$state" = serving
test "$task_state" = completed
test "$(db_counts)" = "$restart_db"
test "$(task_container_count)" = "$restart_container_count"
curl -fsS "http://127.0.0.1:$host_port/healthz" | grep -Fxq ok
curl -fsS "http://127.0.0.1:$host_port/" | grep -Fq m1-secret
printf '%s\n' 'M1-REMAINING-GATES=PASS'
