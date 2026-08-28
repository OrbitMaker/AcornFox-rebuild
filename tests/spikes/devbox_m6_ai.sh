#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence=${OPEN_CARD_M6_EVIDENCE_DIR:-$repo_root/artifacts/mvp/m6-raw-final/run1}
ssh_key=${OPEN_CARD_DEVBOX_SSH_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
ssh_target=${OPEN_CARD_DEVBOX_SSH_TARGET:-ubuntu@192.168.31.64}
mkdir -p "$evidence"

snapshot() {
  ssh -i "$ssh_key" -o BatchMode=yes "$ssh_target" 'set -eu
docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Labels}}" | grep -v "open-card.task=opencard-mvp-fa8f8eab" | sort | sha256sum
sudo virsh list --all --uuid --name 2>/dev/null | sort | sha256sum
sudo virsh net-list --all --uuid --name 2>/dev/null | sort | sha256sum
sudo virsh pool-list --all --uuid --name 2>/dev/null | sort | sha256sum
ip -4 route show default | sha256sum
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true
systemctl is-active docker containerd frpc libvirtd'
}

cd "$repo_root"
snapshot > "$evidence/host-before.txt"
go test -count=1 -v ./internal/foundation ./internal/domain ./internal/contracts ./internal/ai/provider ./internal/ai/context ./internal/ai/tools ./internal/ai/runner ./internal/ai/ledger ./internal/rules ./internal/ai/orchestrator ./cmd/open-card-server > "$evidence/local-m6-tests.log"
python3 tools/evidence/assert_m6_foundation.py --fixture-root tests/fixtures/m6 > "$evidence/fixture-validation.json"
python3 -m unittest -v tests/test_m6_controlled_ai_fixtures.py > "$evidence/python-tests.log" 2>&1
tests/integration/ai/run_devbox.sh > "$evidence/postgres-integration.log"
{
  for test_id in FAULT-BUILD-001 SEC-BUILD-001 SEC-BUILD-002 AI-DEG-001 E2E-GOLD-001; do
    test -f "artifacts/mvp/m1/$test_id/result.json"
    test -f "artifacts/mvp/m1/$test_id/manifest.sha256"
    printf '%s|' "$test_id"
    python3 - "$test_id" <<'PY'
import json,sys
from pathlib import Path
test_id=sys.argv[1]
value=json.loads(Path(f"artifacts/mvp/m1/{test_id}/result.json").read_text())
assert value["conclusion"]=="PASS" and value["exit_code"]==0
print(value["conclusion"])
PY
    shasum -a 256 "artifacts/mvp/m1/$test_id/manifest.sha256"
  done
} > "$evidence/inherited-buildkit-evidence.txt"
if rg -n 'net/http|os/exec|docker\.sock|ssh://' internal/ai/provider internal/ai/context internal/ai/tools internal/ai/runner > "$evidence/forbidden-import-scan.txt"; then
  if rg -n '^\s*"(net/http|os/exec)"' internal/ai/provider internal/ai/context internal/ai/tools internal/ai/runner; then
    exit 1
  fi
fi
snapshot > "$evidence/host-after.txt"
cmp "$evidence/host-before.txt" "$evidence/host-after.txt"
ssh -i "$ssh_key" -o BatchMode=yes "$ssh_target" 'set -eu
test ! -e /home/ubuntu/opencard-mvp-fa8f8eab/m6-integration-20260825
! docker exec opencard-mvp-fa8f8eab-postgres sh -lc '\''psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT datname FROM pg_database ORDER BY 1"'\'' | grep -q "^opencard_mvp_fa8f8eab_m6_"
test "$(docker inspect -f "{{.State.Status}}" opencard-mvp-fa8f8eab-postgres)" = running
test "$(docker inspect -f "{{.State.Status}}" opencard-mvp-fa8f8eab-caddy)" = running'
(
  cd "$evidence"
  find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 shasum -a 256 | sed 's#  \./#  #' > manifest.sha256
)
printf 'M6_CONTROLLED_AI_FINAL=PASS\n'
