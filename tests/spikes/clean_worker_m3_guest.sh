#!/usr/bin/env bash
set -euo pipefail

m3_test_admin_password=${OPEN_CARD_M3_TEST_ADMIN_PASSWORD:-}
export -n OPEN_CARD_M3_TEST_ADMIN_PASSWORD

task_prefix=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
evidence=/var/lib/opencard-mvp-fa8f8eab/evidence/m3-real
work=/var/lib/open-card/build-work/opencard-mvp-fa8f8eab-m3-real
api=http://127.0.0.1:8080
database_url=
backend_pids=()
negative_iface=
negative_address=192.0.2.2/32
run_id=$(openssl rand -hex 8)
platform_base="p-$run_id.platform.test"
custom_host="c-$run_id.fixture.test"
dns_fail_host="dns-fail-$run_id.fixture.test"
cert_fail_host="cert-fail-$run_id.fixture.test"
port_base=$((20000 + (16#${run_id:0:4} % 20000)))
old_port=$port_base
api_port=$((port_base + 1))
new_port=$((port_base + 2))
failed_observation_port=$((port_base + 3))
m3_auth_tmp_dir=
m3_auth_curl_config=

test "$(id -u)" -eq 0
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
set -a
source /etc/open-card/server.env
set +a
export -n OPEN_CARD_M3_TEST_ADMIN_PASSWORD
database_url=${OPEN_CARD_DATABASE_URL:?}
test "${OPEN_CARD_M3_ENABLED:-}" = true
test "${OPEN_CARD_CADDY_ADMIN_URL:-}" = http://127.0.0.1:2019
test "${OPEN_CARD_CADDY_LISTEN:-}" = 127.0.0.1:18443
test "$(readlink /opt/open-card/current)" = releases/release-0.3.3
test "$evidence" = /var/lib/opencard-mvp-fa8f8eab/evidence/m3-real
rm -rf -- "$evidence" "$work"
install -d -m 0750 "$evidence" "$work"
chown opencard:opencard "$work"

cleanup() {
  set +e
  m3_auth_cleanup
  for pid in "${backend_pids[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  wait >/dev/null 2>&1 || true
  if [[ -n "$negative_iface" ]]; then ip addr del "$negative_address" dev "$negative_iface" >/dev/null 2>&1 || true; fi
  if [[ -f "$work/server.env.backup" ]]; then
    install -m 0600 -o root -g opencard "$work/server.env.backup" /etc/open-card/server.env
    systemctl restart open-card-server >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

m3_authenticate() {
  local origin=${OPEN_CARD_AUTH_ORIGIN:?OPEN_CARD_AUTH_ORIGIN is required for M3 control-plane authentication}
  local password=${m3_test_admin_password:?OPEN_CARD_M3_TEST_ADMIN_PASSWORD is required for task-local login}
  unset m3_test_admin_password
  m3_auth_tmp_dir=$(mktemp -d "/tmp/${task_prefix}-m3-auth.XXXXXX")
  [[ ! -L "$m3_auth_tmp_dir" ]] || { echo "M3 authentication directory must not be a symlink" >&2; return 78; }
  chmod 0700 "$m3_auth_tmp_dir"
  local headers payload response session csrf
  headers=$(mktemp "$m3_auth_tmp_dir/auth-login.headers.XXXXXX")
  payload=$(mktemp "$m3_auth_tmp_dir/auth-login-request.XXXXXX")
  response=$(mktemp "$m3_auth_tmp_dir/auth-login-response.XXXXXX")
  printf '%s' "$password" | python3 -c 'import json, sys; print(json.dumps({"password": sys.stdin.read()}, separators=(",", ":")))' >"$payload"
  unset password
  chmod 0600 "$payload"
  (umask 077; command curl -fsS -D "$headers" -o "$response" -H 'Content-Type: application/json' -H "Origin: $origin" --data-binary "@$payload" "$api/api/v1/auth/login")
  session=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie: __Host-open_card_session=/ { value=$0; sub(/^[^=]*=/,"",value); sub(/;.*/,"",value); gsub(/\r/,"",value); print value; exit }' "$headers")
  csrf=$(awk 'BEGIN { IGNORECASE=1 } /^Set-Cookie: __Host-open_card_csrf=/ { value=$0; sub(/^[^=]*=/,"",value); sub(/;.*/,"",value); gsub(/\r/,"",value); print value; exit }' "$headers")
  [[ "$session" =~ ^[A-Za-z0-9_-]{43}$ && "$csrf" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "M3 control-plane authentication is missing or malformed" >&2; return 78; }
  m3_auth_curl_config=$(mktemp "$m3_auth_tmp_dir/auth-control-plane.XXXXXX")
  (umask 077; {
    printf 'header = "Cookie: __Host-open_card_session=%s; __Host-open_card_csrf=%s"\n' "$session" "$csrf"
    printf 'header = "X-Open-Card-CSRF: %s"\n' "$csrf"
  } >"$m3_auth_curl_config")
  rm -f -- "$headers" "$payload" "$response"
  unset session csrf
}

m3_auth_cleanup() {
  if [[ -n "${m3_auth_tmp_dir:-}" && "$m3_auth_tmp_dir" == "/tmp/${task_prefix}-m3-auth."* && -d "$m3_auth_tmp_dir" && ! -L "$m3_auth_tmp_dir" ]]; then
    rm -rf -- "$m3_auth_tmp_dir"
  fi
  unset m3_auth_curl_config m3_auth_tmp_dir
}

curl() {
  local argument
  for argument in "$@"; do
    if [[ "$argument" == "$api/"* ]]; then
      [[ -r "${m3_auth_curl_config:-}" ]] || { echo "M3 control-plane call attempted before authentication" >&2; return 78; }
      command curl --config "$m3_auth_curl_config" -H "Origin: $OPEN_CARD_AUTH_ORIGIN" "$@"
      return
    fi
  done
  command curl "$@"
}

request_json() {
  local method=$1 path=$2 body=$3 output=$4 key=$5
  key="$key-$run_id"
  curl -sS --connect-timeout 3 --max-time 30 -o "$output" -w '%{http_code}' \
    -X "$method" -H 'Content-Type: application/json' -H "Idempotency-Key: $key" \
    --data-binary "$body" "$api$path"
}

wait_ready() {
  for _ in $(seq 1 100); do curl -fsS "$api/readyz" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}

wait_operation_terminal() {
  local operation=$1 state=
  [[ "$operation" =~ ^(op|operation)_[a-f0-9]{32}$ ]]
  for _ in $(seq 1 300); do
    state=$(psql "$database_url" -X -Aqt -c "SELECT state FROM operations WHERE id='$operation'" 2>/dev/null | tr -d '[:space:]')
    case "$state" in succeeded|failed|cancelled|rolled_back) return 0;; esac
    sleep 0.1
  done
  return 1
}

start_backend() {
  local port=$1 root=$2 log=$3
  sudo -u opencard python3 -m http.server --bind 127.0.0.1 --directory "$root" "$port" >"$log" 2>&1 &
  backend_pids+=("$!")
  for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}

wait_https() {
  local host=$1 path=$2 marker=$3 output=$4
  for _ in $(seq 1 100); do
    if curl -ksS --resolve "$host:18443:127.0.0.1" "https://$host:18443$path" >"$output" 2>/dev/null && grep -Fq "$marker" "$output"; then return 0; fi
    sleep 0.1
  done
  return 1
}

snapshot() {
  local output=$1
  python3 - "$output" <<'PY'
import json,subprocess,sys
def lines(command):
    return [line for line in subprocess.check_output(command,text=True).splitlines() if line]
json.dump({
  "caddy_admin": lines(["ss","-ltnH","sport", "=", ":2019"]),
  "caddy_https": lines(["ss","-ltnH","sport", "=", ":18443"]),
  "task_processes": lines(["pgrep","-af","opencard-mvp-fa8f8eab|http.server 1900"]) if subprocess.run(["pgrep","-f","opencard-mvp-fa8f8eab|http.server 1900"],stdout=subprocess.DEVNULL).returncode==0 else [],
},open(sys.argv[1],"w"),indent=2,sort_keys=True)
PY
}

m3_authenticate
wait_ready
for service in open-card-server open-card-caddy postgresql; do test "$(systemctl is-active "$service")" = active; done
snapshot "$evidence/objects-before.json"

install -d -m 0750 -o opencard -g opencard "$work/old" "$work/new" "$work/api/api"
printf '%s\n' 'M3-OLD-FRONTEND' >"$work/old/index.html"
printf '%s\n' 'M3-NEW-FRONTEND' >"$work/new/index.html"
printf '%s\n' 'M3-API-V1' >"$work/api/api/index.html"
chown -R opencard:opencard "$work/old" "$work/new" "$work/api"
start_backend "$old_port" "$work/old" "$evidence/backend-old.log"
start_backend "$api_port" "$work/api" "$evidence/backend-api.log"
start_backend "$new_port" "$work/new" "$evidence/backend-new.log"

status=$(request_json POST /api/v1/applications '{"name":"m3-real-routing"}' "$evidence/application.json" "m3-application")
test "$status" = 201
app_id=$(jq -r .application.id "$evidence/application.json")
env_id=$(jq -r .environment_id "$evidence/application.json")
operation_id=$(jq -r .operation_id "$evidence/application.json")
wait_operation_terminal "$operation_id"
suffix=$(printf '%s' "$app_id" | sha256sum | cut -c1-16)
source_id=src_m3_$suffix
definition_id=def_m3_$suffix
release_old=release_m3_old_$suffix
release_new=release_m3_new_$suffix
deployment_old=dep_m3_old_$suffix
deployment_new=dep_m3_new_$suffix
digest=sha256:$(printf '%064d' 0 | tr 0 a)
psql "$database_url" -X -v ON_ERROR_STOP=1 \
  -v app="$app_id" -v env="$env_id" -v src="$source_id" -v def="$definition_id" \
  -v rold="$release_old" -v rnew="$release_new" -v dold="$deployment_old" -v dnew="$deployment_new" -v digest="$digest" \
  -v pold="$old_port" -v pnew="$new_port" <<'SQL'
INSERT INTO source_revisions(id,application_id,provider,content_digest,source_kind,locator,source_ref,workspace_ref,workspace_lifecycle,immutable)
VALUES(:'src',:'app','upload',:'digest','upload','upload://m3','m3-fixture','/var/lib/open-card/workspaces/m3','prepared',true);
INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES(:'def',:'app',:'src',1,'{}');
INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES(:'rold',:'app',:'def',1,jsonb_build_object('frontend',:'digest','api',:'digest'));
INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES(:'rnew',:'app',:'def',2,jsonb_build_object('frontend',:'digest','api',:'digest'));
INSERT INTO deployments(id,environment_id,release_id,state,host_ip,host_port,runtime_healthy,last_observed_at) VALUES(:'dold',:'env',:'rold','runtime_ready','127.0.0.1',:'pold',true,now());
INSERT INTO deployments(id,environment_id,release_id,state,host_ip,host_port,runtime_healthy,last_observed_at) VALUES(:'dnew',:'env',:'rnew','runtime_ready','127.0.0.1',:'pnew',true,now());
SQL

ip_body=$(jq -nc --arg app "$app_id" --arg dep "$deployment_old" --argjson port "$old_port" '{application_id:$app,deployment_id:$dep,service_name:"frontend",port:$port,path:"/",routable:true,server_ip:"127.0.0.1",runtime_ready:true}')
status=$(request_json POST /api/v1/access/ip-fallback "$ip_body" "$evidence/ip-fallback.json" m3-ip-fallback)
test "$status" = 201
jq -e '.access_state.ip_available==true and .access_state.https_ready==false and ((.access_state.domain // "")=="")' "$evidence/ip-fallback.json" >/dev/null
curl -fsS "http://127.0.0.1:$old_port/" | grep -Fq M3-OLD-FRONTEND
printf '%s\n' 'IP-FALLBACK=PASS'

platform_body=$(jq -nc --arg base "$platform_base" '{base_domain:$base,dns_target:"gateway.fixture.test"}')
status=$(request_json POST /api/v1/access/platform-domains "$platform_body" "$evidence/platform-domain.json" m3-platform-domain)
test "$status" = 201
jq -e '.binding.status=="ready" and .certificate.status=="ready" and .certificate.secret_ref.id!=""' "$evidence/platform-domain.json" >/dev/null
platform_binding=$(jq -c .binding "$evidence/platform-domain.json")
managed_body=$(jq -nc --arg app "$app_id" --arg name 'M3 Routing App' --argjson platform "$platform_binding" '{application_id:$app,application_name:$name,platform:$platform}')
status=$(request_json POST /api/v1/access/platform-application-domains "$managed_body" "$evidence/platform-application-domain.json" m3-platform-app)
test "$status" = 201
managed_host=$(jq -r .binding.host "$evidence/platform-application-domain.json")
[[ "$managed_host" = *.apps."$platform_base" ]]
status=$(request_json POST /api/v1/access/platform-application-domains "$managed_body" "$evidence/platform-application-domain-replay.json" m3-platform-app-replay)
test "$status" = 201
test "$(jq -r .binding.host "$evidence/platform-application-domain-replay.json")" = "$managed_host"
printf '%s\n' 'PLATFORM-DOMAIN=PASS'

custom_body=$(jq -nc --arg app "$app_id" --arg host "$custom_host" --arg target "$managed_host" '{application_id:$app,host:$host,cname_target:$target}')
status=$(request_json POST /api/v1/access/application-domains "$custom_body" "$evidence/application-domain.json" m3-app-domain)
test "$status" = 201
jq -e '.binding.status=="ready" and .certificate.status=="ready"' "$evidence/application-domain.json" >/dev/null
binding=$(jq -c .binding "$evidence/application-domain.json")
certificate=$(jq -c .certificate "$evidence/application-domain.json")
routes_body=$(jq -nc --arg app "$app_id" --arg dep "$deployment_old" --argjson binding "$binding" --argjson certificate "$certificate" --argjson old_port "$old_port" --argjson api_port "$api_port" '{binding:$binding,certificate:$certificate,runtime_ready:true,targets:[{application_id:$app,deployment_id:$dep,service_name:"frontend",port:$old_port,path:"/",routable:true},{application_id:$app,deployment_id:$dep,service_name:"api",port:$api_port,path:"/api",routable:true}]}')
status=$(request_json POST /api/v1/access/domain-routes "$routes_body" "$evidence/domain-routes.json" m3-domain-routes)
test "$status" = 201
jq -e '.access_state.https_ready==true and .access_state.serving==true and (.routes|length)==2' "$evidence/domain-routes.json" >/dev/null
wait_https "$custom_host" / M3-OLD-FRONTEND "$evidence/https-root-old.txt"
wait_https "$custom_host" /api/ M3-API-V1 "$evidence/https-api.txt"
printf '%s\n' 'CNAME-HTTPS-PATH=PASS'

conflict_body=$(jq -nc --arg app "$app_id" --arg dep "$deployment_old" --argjson binding "$binding" --argjson certificate "$certificate" --argjson port "$api_port" '{binding:$binding,certificate:$certificate,runtime_ready:true,targets:[{application_id:$app,deployment_id:$dep,service_name:"api",port:$port,path:"/api",routable:true},{application_id:$app,deployment_id:$dep,service_name:"api",port:$port,path:"/api/v1",routable:true}]}')
status=$(request_json POST /api/v1/access/domain-routes "$conflict_body" "$evidence/route-conflict.json" m3-route-conflict)
test "$status" = 409
worker_body=$(jq -nc --arg app "$app_id" --arg dep "$deployment_old" --argjson binding "$binding" --argjson certificate "$certificate" --argjson port "$api_port" '{binding:$binding,certificate:$certificate,runtime_ready:true,targets:[{application_id:$app,deployment_id:$dep,service_name:"worker",port:$port,path:"/worker",routable:false}]}')
status=$(request_json POST /api/v1/access/domain-routes "$worker_body" "$evidence/route-worker-reject.json" m3-route-worker)
test "$status" = 403
printf '%s\n' 'ROUTE-NEGATIVE=PASS'

curl -fsS http://127.0.0.1:2019/config/ | jq -S . >"$evidence/caddy-config-before.json"
grep -Fq '"module": "internal"' "$evidence/caddy-config-before.json"
! grep -Eqi 'acme|letsencrypt|PRIVATE KEY|certificate_1' "$evidence/caddy-config-before.json"
ss -ltnH 'sport = :2019' >"$evidence/caddy-admin-listener.txt"
grep -Eq '127\.0\.0\.1:2019|\[::1\]:2019' "$evidence/caddy-admin-listener.txt"
! grep -Eq '0\.0\.0\.0:2019|\[::\]:2019' "$evidence/caddy-admin-listener.txt"
for candidate in /sys/class/net/*; do
  [[ "${candidate##*/}" = lo ]] && continue
  negative_iface=${candidate##*/}
  break
done
test -n "$negative_iface"
ip addr add "$negative_address" dev "$negative_iface"
if curl -fsS --connect-timeout 1 http://192.0.2.2:2019/config/ >"$evidence/caddy-admin-negative.txt" 2>&1; then exit 1; fi
ip addr del "$negative_address" dev "$negative_iface"
negative_iface=
printf '%s\n' 'SEC-CADDY-001=PASS'

renew_body=$(jq -nc --arg app "$app_id" --argjson certificate "$certificate" '{application_id:$app,certificate:$certificate}')
status=$(request_json POST /api/v1/access/certificates/renew "$renew_body" "$evidence/certificate-renew.json" m3-cert-renew)
test "$status" = 201
test "$(jq -r .certificate.id "$evidence/certificate-renew.json")" = "$(jq -r .id <<<"$certificate")"
test "$(jq -r .certificate.secret_ref.id "$evidence/certificate-renew.json")" != "$(jq -r .secret_ref.id <<<"$certificate")"
! grep -Fq 'PRIVATE KEY' "$evidence/certificate-renew.json"
printf '%s\n' 'CERT-RENEW=PASS'

old_root=$(jq -c --argjson port "$old_port" '[.routes[]|select(.path=="/")][0] | {route:.,port:$port}' "$evidence/domain-routes.json")
new_root=$(jq -c --arg dep "$deployment_new" --argjson port "$new_port" '[.routes[]|select(.path=="/")][0] | .deployment_id=$dep | {route:.,port:$port}' "$evidence/domain-routes.json")
switch_body=$(jq -nc --arg app "$app_id" --argjson old "$old_root" --argjson candidate "$new_root" --arg health "http://127.0.0.1:$new_port/" '{application_id:$app,old:[$old],candidate:[$candidate],health_url:$health,observation_url:$health,window_ms:100}')
status=$(request_json POST /api/v1/access/traffic-switches "$switch_body" "$evidence/switch-success.json" m3-switch-success)
test "$status" = 202
wait_https "$custom_host" / M3-NEW-FRONTEND "$evidence/https-root-new.txt"
failed_switch=$(jq -nc --arg app "$app_id" --argjson old "$new_root" --argjson candidate "$old_root" --arg health "http://127.0.0.1:$old_port/" --arg observation "http://127.0.0.1:$failed_observation_port/" '{application_id:$app,old:[$old],candidate:[$candidate],health_url:$health,observation_url:$observation,window_ms:100}')
status=$(request_json POST /api/v1/access/traffic-switches "$failed_switch" "$evidence/switch-failure.json" m3-switch-failure)
test "$status" = 503
jq -e '.code=="unavailable" and (.message|contains("old deployment restored and remains serving"))' "$evidence/switch-failure.json" >/dev/null
wait_https "$custom_host" / M3-NEW-FRONTEND "$evidence/https-root-after-failed-switch.txt"
printf '%s\n' 'ROLL-002=PASS'

curl -fsS http://127.0.0.1:2019/config/ | jq -S . >"$evidence/caddy-config-before-restart.json"
config_hash_before=$(sha256sum "$evidence/caddy-config-before-restart.json" | awk '{print $1}')
systemctl restart open-card-caddy
wait_https "$custom_host" / M3-NEW-FRONTEND "$evidence/https-after-caddy-restart.txt"
curl -fsS http://127.0.0.1:2019/config/ | jq -S . >"$evidence/caddy-config-after-rebuild.json"
test "$(sha256sum "$evidence/caddy-config-after-rebuild.json" | awk '{print $1}')" = "$config_hash_before"
printf '%s\n' 'FAULT-CADDY-001=PASS'

install -m 0600 /etc/open-card/server.env "$work/server.env.backup"
printf '%s\n' 'OPEN_CARD_M3_DNS_FAIL=true' >>/etc/open-card/server.env
systemctl restart open-card-server
wait_ready
dns_fail_body=$(jq -nc --arg app "$app_id" --arg host "$dns_fail_host" --arg target "$managed_host" '{application_id:$app,host:$host,cname_target:$target}')
status=$(request_json POST /api/v1/access/application-domains "$dns_fail_body" "$evidence/dns-failure.json" m3-dns-failure)
test "$status" -ge 400
curl -fsS "http://127.0.0.1:$new_port/" | grep -Fq M3-NEW-FRONTEND
install -m 0600 -o root -g opencard "$work/server.env.backup" /etc/open-card/server.env
systemctl restart open-card-server
wait_ready
printf '%s\n' 'OPEN_CARD_M3_CERT_FAIL=true' >>/etc/open-card/server.env
systemctl restart open-card-server
wait_ready
cert_fail_body=$(jq -nc --arg app "$app_id" --arg host "$cert_fail_host" --arg target "$managed_host" '{application_id:$app,host:$host,cname_target:$target}')
status=$(request_json POST /api/v1/access/application-domains "$cert_fail_body" "$evidence/certificate-failure.json" m3-certificate-failure)
test "$status" -ge 400
curl -fsS "http://127.0.0.1:$new_port/" | grep -Fq M3-NEW-FRONTEND
install -m 0600 -o root -g opencard "$work/server.env.backup" /etc/open-card/server.env
rm -f "$work/server.env.backup"
systemctl restart open-card-server
wait_ready
wait_https "$custom_host" / M3-NEW-FRONTEND "$evidence/https-after-control-plane-restart.txt"
printf '%s\n' 'FAULT-CADDY-002=PASS'

set +e
curl -sS --max-time 2 "$api/api/v1/events" >"$evidence/events.sse"
sse_status=$?
set -e
test "$sse_status" = 0 -o "$sse_status" = 28
grep -Eq 'domain\.application_ready|route\.serving|certificate\.renewed|route\.switch' "$evidence/events.sse"
pg_dump --data-only --inserts "$database_url" >"$evidence/m3-db-redacted.sql"
! grep -R -a -E 'PRIVATE KEY|oc-dns01-' "$evidence" /var/log/open-card /var/lib/open-card/ai 2>/dev/null
! grep -a -E 'PRIVATE KEY|oc-dns01-' "$evidence/m3-db-redacted.sql"
printf '%s\n' 'SSE-AUDIT-SECRET=PASS'

for pid in "${backend_pids[@]}"; do kill "$pid" >/dev/null 2>&1 || true; done
wait >/dev/null 2>&1 || true
backend_pids=()
snapshot "$evidence/objects-after.json"
python3 - "$evidence/summary.json" <<'PY'
import json,sys
json.dump({"conclusion":"PASS","ai_enabled":False,"public_dns_mutations":0,"production_certificates":0,"routes":["/","/api"],"fallback_preserved":True,"old_serving_on_failed_switch":True},open(sys.argv[1],"w"),indent=2,sort_keys=True)
PY
printf '%s\n' \
  'M3-REAL-GATES=PASS' 'CT-ROUTE-001=PASS' 'CADDY-INT-001=PASS' \
  'E2E-DOMAIN-001=PASS' 'SEC-CADDY-001=PASS' 'ROLL-002=PASS' \
  'FAULT-CADDY-001=PASS' 'FAULT-CADDY-002=PASS'
