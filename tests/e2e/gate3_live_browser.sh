#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: gate3_live_browser.sh --origin https://127.0.0.1:HIGH_PORT --api-origin http://127.0.0.1:HIGH_PORT --evidence-dir PATH --task-prefix PREFIX [--keep-fixture]

The browser interactions remain explicit Playwright CLI steps recorded in the
Gate 3 evidence report. This script owns only fail-closed preflight checks and
the disposable upload fixture used by those steps. --keep-fixture retains that
fixture until the caller completes its explicit Playwright CLI upload step.
EOF
}

origin=
api_origin=
evidence_dir=
task_prefix=
keep_fixture=false
while (($# > 0)); do
  case "$1" in
    --origin) [[ $# -gt 1 ]] || { usage; exit 64; }; origin=$2; shift 2 ;;
    --api-origin) [[ $# -gt 1 ]] || { usage; exit 64; }; api_origin=$2; shift 2 ;;
    --evidence-dir) [[ $# -gt 1 ]] || { usage; exit 64; }; evidence_dir=$2; shift 2 ;;
    --task-prefix) [[ $# -gt 1 ]] || { usage; exit 64; }; task_prefix=$2; shift 2 ;;
    --keep-fixture) keep_fixture=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done

[[ -n "$origin" && -n "$api_origin" && -n "$evidence_dir" && -n "$task_prefix" ]] || { usage; exit 64; }
[[ "$origin" =~ ^https://127\.0\.0\.1:[0-9]{4,5}$ ]] || { echo 'origin must be an explicit HTTPS loopback high port' >&2; exit 64; }
[[ "$api_origin" =~ ^http://127\.0\.0\.1:[0-9]{4,5}$ ]] || { echo 'api-origin must be an explicit HTTP loopback high port' >&2; exit 64; }
[[ "$task_prefix" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo 'task-prefix contains unsafe characters' >&2; exit 64; }

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$evidence_dir"
summary="$evidence_dir/preflight.ndjson"
: > "$summary"
task_tmp=$(mktemp -d "/tmp/${task_prefix}.XXXXXX")
cleanup() {
  [[ "$keep_fixture" == true ]] && return
  if [[ "$task_tmp" == "/tmp/${task_prefix}."* && -d "$task_tmp" ]]; then
    rm -rf -- "$task_tmp"
  fi
}
trap cleanup EXIT

build_log="$task_tmp/live-build.log"
VITE_API_MODE=live VITE_API_BASE_URL=/api/v1 npm --prefix "$repo_root/web" run build >"$build_log" 2>&1
printf '{"check":"live_build","status":"PASS","contract":"VITE_API_MODE=live,VITE_API_BASE_URL=/api/v1"}\n' >> "$summary"

curl -kfsS "$origin/" >/dev/null
printf '{"check":"live_web_origin","status":"PASS","origin":"%s"}\n' "$origin" >> "$summary"
curl -fsS "$api_origin/healthz" >/dev/null
printf '{"check":"backend_health","status":"PASS","api_origin":"%s"}\n' "$api_origin" >> "$summary"

unauth_status=$(curl -ksS -o "$task_tmp/unauth-session.json" -w '%{http_code}' -H "Origin: $origin" "$api_origin/api/v1/auth/session")
if [[ "$unauth_status" == 401 ]]; then
  printf '{"check":"unauthenticated_session","status":"PASS","http_status":401}\n' >> "$summary"
else
  printf '{"check":"unauthenticated_session","status":"FAIL","http_status":%s}\n' "$unauth_status" >> "$summary"
  exit 1
fi

archive="$task_tmp/gate3-upload.zip"
command -v zip >/dev/null 2>&1 || { echo 'zip is required for the disposable browser fixture' >&2; exit 69; }
zip -q -j "$archive" "$repo_root/README.md"
archive_bytes=$(wc -c < "$archive" | tr -d ' ')
archive_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
printf '{"check":"browser_upload_fixture","status":"PASS","bytes":%s,"sha256":"%s","lifecycle":"temporary_task_directory"}\n' "$archive_bytes" "$archive_sha256" >> "$summary"
printf 'browser_upload_fixture=%s\n' "$archive"
printf 'evidence_summary=%s\n' "$summary"
