#!/usr/bin/env bash
set -euo pipefail

result=/var/lib/opencard-mvp-fa8f8eab/m1-git-proof.json
readarray -t facts < <(python3 - "$result" <<'PY'
import json,sys
x=json.load(open(sys.argv[1],encoding='utf-8'))
for value in (x['source_revision']['id'],x['source_revision']['commit'],x['release']['id'],x['deployment']['id'],x['operation']['id'],x['task_id'],x['artifact']['image']['digest']): print(value)
PY
)
source_id=${facts[0]}
commit=${facts[1]}
release_id=${facts[2]}
deployment_id=${facts[3]}
operation_id=${facts[4]}
task_id=${facts[5]}
digest=${facts[6]}
test "$commit" = 238e407fc77ddae6784bb3e70b5109d20adb4d2b
set -a
source /etc/open-card/server.env
set +a
row=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state||'|'||host(host_ip)||'|'||host_port FROM deployments WHERE id='$deployment_id'")
port=${row##*|}
test "$row" = "serving|127.0.0.1|$port"
curl -fsS "http://127.0.0.1:$port/" | grep -Fq git-dockerfile-proof
curl -fsS "http://127.0.0.1:$port/healthz" | grep -Fxq ok
container=$(docker ps --filter "label=open-card.deployment-id=$deployment_id" --format '{{.Names}}')
test "$(docker inspect "$container" --format '{{.Image}}')" = "$digest"
test "$(docker inspect "$container" --format '{{.HostConfig.CpuQuota}}')" = 30000
test "$(docker inspect "$container" --format '{{.HostConfig.Memory}}')" = 67108864
test "$(docker inspect "$container" --format '{{json .Mounts}}')" = '[]'
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT git_commit IS NOT NULL AND source_ref='main' AND locator='https://git.opencard.test/m1.git' FROM source_revisions WHERE id='$source_id'")" = t
workspace=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT workspace_ref FROM source_revisions WHERE id='$source_id'")
test ! -e "$workspace"
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT build_kind||'|'||dockerfile_path FROM build_plans WHERE source_revision_id='$source_id'")" = 'dockerfile|Dockerfile'
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT count(*) FROM release_artifacts ra JOIN artifacts a ON a.id=ra.artifact_id WHERE ra.release_id='$release_id' AND a.image_digest='$digest'")" = 1
test "$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT state||'|'||last_agent_sequence FROM task_leases WHERE task_id='$task_id'")" = 'completed|4'
statuses=$(psql "$OPEN_CARD_DATABASE_URL" -X -Aqt -c "SELECT string_agg(payload->>'status',',' ORDER BY stream_sequence) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id='$operation_id'")
python3 - "$statuses" <<'PY'
import sys
v=sys.argv[1].split(','); r={'preparing':0,'building':1,'deploying':2,'succeeded':3,'failed':3}
assert v[0]=='preparing' and v[-1]=='succeeded'
assert {'preparing','building','deploying','succeeded'}.issubset(v)
assert all(r[a] <= r[b] for a,b in zip(v,v[1:])),v
PY

printf '%s\n' \
  "git_commit=$commit" \
  'git_dockerfile_traffic=PASS' \
  'git_digest_identity=PASS' \
  'git_workspace_released=PASS' \
  "git_publish_statuses=$statuses"
