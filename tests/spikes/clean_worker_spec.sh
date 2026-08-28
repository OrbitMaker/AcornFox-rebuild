#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/opencard-clean-worker.XXXXXX")"
cleanup() { /bin/rm -rf -- "$tmp"; }
trap cleanup EXIT INT TERM

image="$tmp/worker.img"
bundle="$tmp/offline.bundle"
spec="$tmp/spec.json"
dd if=/dev/zero of="$image" bs=1024 count=16 >/dev/null 2>&1
printf '%s' 'offline-buildkit-docker-fixture' >"$bundle"
image_sha="$(shasum -a 256 "$image" | awk '{print $1}')"
bundle_sha="$(shasum -a 256 "$bundle" | awk '{print $1}')"
python3 - "$repo_root/deploy/worker/clean-worker-spec.json" "$spec" "$image" "$image_sha" "$bundle" "$bundle_sha" <<'PY'
import json,sys
source,target,image,image_sha,bundle,bundle_sha=sys.argv[1:]
data=json.load(open(source,encoding='utf-8'))
data.update(image_path=image,image_sha256=image_sha,offline_bundle_path=bundle,offline_bundle_sha256=bundle_sha)
json.dump(data,open(target,'w',encoding='utf-8'),indent=2,sort_keys=True)
PY

python3 "$repo_root/tools/worker/validate_clean_worker_spec.py" "$spec" | grep -q 'READY_FOR_EXPLICIT_AUTHORIZATION'
printf 'tamper' >>"$image"
set +e
python3 "$repo_root/tools/worker/validate_clean_worker_spec.py" "$spec" >/dev/null
tamper_status=$?
set -e
test "$tamper_status" -eq 78
python3 "$repo_root/tools/worker/validate_clean_worker_spec.py" "$repo_root/deploy/worker/clean-worker-spec.json" --allow-placeholder | grep -q 'BLOCKED_PENDING_IMAGE_AND_AUTHORIZATION'
OPEN_CARD_TASK_ID=opencard-mvp-fa8f8eab "$repo_root/scripts/mvp/clean-worker-acceptance.sh" --dry-run | grep -q 'mutation\|checks'
OPEN_CARD_TASK_ID=opencard-mvp-fa8f8eab "$repo_root/scripts/mvp/clean-worker-reclaim.sh" --dry-run | grep -q 'mutation=none'
printf '%s\n' \
  'clean_worker_spec=valid' \
  'checksum_tamper=blocked' \
  'placeholder=blocked_pending_authorization' \
  'acceptance_dry_run=ok' \
  'reclaim_dry_run=ok'
