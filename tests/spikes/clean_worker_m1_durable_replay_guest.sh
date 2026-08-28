#!/usr/bin/env bash
set -euo pipefail
result=/var/lib/opencard-mvp-fa8f8eab/m1-durable-proof.json
readarray -t facts < <(python3 - "$result" <<'PY'
import json,sys
x=json.load(open(sys.argv[1],encoding='utf-8'))
for value in (x['deployment']['id'],x['operation']['id'],x['artifact']['image']['digest']): print(value)
PY
)
deployment=${facts[0]}
operation=${facts[1]}
digest=${facts[2]}
set -a; source /etc/open-card/server.env; set +a
for _ in $(seq 1 40); do
  state=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM deployments WHERE id='$deployment'")
  [[ "$state" == serving ]] && break
  [[ "$state" == failed ]] && exit 1
  sleep 0.5
done
test "$state" = serving
port=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT host_port FROM deployments WHERE id='$deployment'")
curl -fsS "http://127.0.0.1:$port/" | grep -Fq durable-idempotency-proof
before_builds=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM builds')
before_releases=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM releases')
before_deployments=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM deployments')
before_events=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation'")
before_containers=$(docker ps -a --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.ID}}' | wc -l)
systemctl restart open-card-server
for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS -H 'Content-Type: application/json' -H 'Idempotency-Key: m1-durable-publish' --data '{"application_id":"app_c1b1df7dec9b3857bf54cd79cdd7502c","environment_id":"env_fb26834bcf574ee2c91a5b14a7a2537a","service_group_id":"group_m1durable","service_name":"web","source":{"kind":"upload","locator":"/var/lib/open-card/uploads/m1-durable-proof"},"build_kind":"static","context_path":".","target_repository":"open-card.local/apps/m1-durable-proof","output_storage_key":"app-durable-proof/web","build_resources":{"cpu_millis":500,"memory_bytes":536870912,"timeout_seconds":300,"concurrency_slot":1},"build_network":{"mode":"none"},"runtime_resources":{"cpu_millis":275,"memory_bytes":67108864},"container_port":8080,"version":1,"actor":"m1-e2e"}' http://127.0.0.1:8080/api/v1/publishes >/var/lib/opencard-mvp-fa8f8eab/m1-durable-replay.json
cmp "$result" /var/lib/opencard-mvp-fa8f8eab/m1-durable-replay.json
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM builds')" = "$before_builds"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM releases')" = "$before_releases"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c 'SELECT count(*) FROM deployments')" = "$before_deployments"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation'")" = "$before_events"
test "$(docker ps -a --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.ID}}' | wc -l)" = "$before_containers"
test "$(docker inspect $(docker ps --filter "label=open-card.deployment-id=$deployment" --format '{{.Names}}') --format '{{.Image}}')" = "$digest"
curl -fsS "http://127.0.0.1:$port/" | grep -Fq durable-idempotency-proof
printf '%s\n' 'server_restart_replay=PASS' 'duplicate_builds=0' 'duplicate_releases=0' 'duplicate_deployments=0' 'duplicate_containers=0' 'duplicate_events=0' 'traffic_after_restart=PASS'
