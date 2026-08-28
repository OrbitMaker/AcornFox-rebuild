#!/usr/bin/env bash
set -euo pipefail

domain=opencard-mvp-fa8f8eab-build-worker-01
timeout_seconds=${OPEN_CARD_GUEST_EXEC_TIMEOUT:-300}
if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: clean-worker-guest-exec.sh 'bounded command'" >&2
  exit 64
fi
sudo -n virsh dominfo "$domain" >/dev/null
test "$(sudo -n virsh domuuid "$domain")" = fce4e26d-93b0-5128-a090-969ef73835d4

request=$(python3 - "$1" <<'PY'
import json,sys
print(json.dumps({"execute":"guest-exec","arguments":{"path":"/bin/bash","arg":["-lc",sys.argv[1]],"capture-output":True}}))
PY
)
response=$(sudo -n virsh qemu-agent-command "$domain" "$request")
pid=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["return"]["pid"])' <<<"$response")
deadline=$((SECONDS + timeout_seconds))
while (( SECONDS < deadline )); do
  status=$(sudo -n virsh qemu-agent-command "$domain" "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":$pid}}")
  exited=$(python3 -c 'import json,sys; print(str(json.load(sys.stdin)["return"].get("exited",False)).lower())' <<<"$status")
  if [[ "$exited" = true ]]; then
    python3 - "$status" <<'PY'
import base64,json,sys
result=json.loads(sys.argv[1])["return"]
for field,stream in (("out-data",sys.stdout.buffer),("err-data",sys.stderr.buffer)):
    if result.get(field): stream.write(base64.b64decode(result[field]))
raise SystemExit(result.get("exitcode",1))
PY
    exit $?
  fi
  sleep 0.5
done
echo "guest command timed out after $timeout_seconds seconds" >&2
exit 124
