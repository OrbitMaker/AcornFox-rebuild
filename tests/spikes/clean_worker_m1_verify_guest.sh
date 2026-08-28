#!/usr/bin/env bash
set -euo pipefail

result=/var/lib/opencard-mvp-fa8f8eab/m1-durable-proof.json
test -f "$result"
readarray -t facts < <(python3 - "$result" <<'PY'
import json,sys
x=json.load(open(sys.argv[1],encoding="utf-8"))
for value in (x["source_revision"]["id"],x["release"]["id"],x["deployment"]["id"],x["operation"]["id"],x["task_id"],x["artifact"]["image"]["digest"]): print(value)
PY
)
source_id=${facts[0]}
release_id=${facts[1]}
deployment_id=${facts[2]}
operation_id=${facts[3]}
task_id=${facts[4]}
digest=${facts[5]}
set -a
source /etc/open-card/server.env
set +a
row=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state||'|'||host(host_ip)||'|'||host_port FROM deployments WHERE id='$deployment_id'")
port=${row##*|}
test "$row" = "serving|127.0.0.1|$port"
curl -fsS "http://127.0.0.1:$port/" | grep -Fq durable-idempotency-proof
curl -fsS "http://127.0.0.1:$port/healthz" | grep -Fxq ok

container=$(docker ps --filter "label=open-card.deployment-id=$deployment_id" --format '{{.Names}}')
test -n "$container"
test "$(docker inspect "$container" --format '{{.Image}}')" = "$digest"
test "$(docker inspect "$container" --format '{{.HostConfig.Memory}}')" = 67108864
test "$(docker inspect "$container" --format '{{.HostConfig.MemorySwap}}')" = 67108864
test "$(docker inspect "$container" --format '{{.HostConfig.CpuPeriod}}')" = 100000
test "$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}')" = 27500
test "$(docker inspect "$container" --format '{{.HostConfig.Privileged}}')" = false
test "$(docker inspect "$container" --format '{{json .Mounts}}')" = '[]'
test "$(docker inspect "$container" --format '{{json .HostConfig.CapDrop}}')" = '["ALL"]'
test "$(docker inspect "$container" --format '{{index .Config.Labels "open-card.task-prefix"}}')" = opencard-mvp-fa8f8eab
test "$(docker network inspect opencard-mvp-fa8f8eab-runtime-network --format '{{.Internal}}')" = false
test -z "$(ip route show default)"

workspace=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT workspace_ref FROM source_revisions WHERE id='$source_id'")
test ! -e "$workspace"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state FROM source_workspace_events WHERE source_revision_id='$source_id' ORDER BY sequence DESC LIMIT 1")" = released
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM releases r JOIN release_artifacts ra ON ra.release_id=r.id JOIN artifacts a ON a.id=ra.artifact_id WHERE r.id='$release_id' AND a.image_digest='$digest'")" = 1
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state||'|'||last_agent_sequence FROM task_leases WHERE task_id='$task_id'")" = 'completed|4'

statuses=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT string_agg(payload->>'status',',' ORDER BY stream_sequence) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation_id'")
python3 - "$statuses" <<'PY'
import sys
values=sys.argv[1].split(',')
rank={'preparing':0,'building':1,'deploying':2,'succeeded':3,'failed':3}
assert values[0]=='preparing' and values[-1]=='succeeded'
assert {'preparing','building','deploying','succeeded'}.issubset(values)
assert all(rank[a] <= rank[b] for a,b in zip(values,values[1:])), values
PY
audit_count=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM audit_evidence WHERE actor_id='release-controller' AND created_at > now()-interval '30 minutes'")
test "$audit_count" -gt 0
ai_table=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT COALESCE(to_regclass('public.ai_invocations')::text,'absent')")
test "$ai_table" = absent

printf '%s\n' \
  'traffic=PASS' \
  'runtime_limits=PASS' \
  'digest_identity=PASS' \
  'workspace_released=PASS' \
  "publish_statuses=$statuses" \
  "audit_records=$audit_count" \
  'ai_invocations=absent'
