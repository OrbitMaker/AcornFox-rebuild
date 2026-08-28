#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
task_id="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"
case "$task_id" in
  opencard-mvp-fa8f8eab) ;;
  *) echo "unexpected task id: $task_id" >&2; exit 78 ;;
esac

work_parent="${OPEN_CARD_G7_WORK_ROOT:-${TMPDIR:-/tmp}/${task_id}-g7}"
case "$work_parent" in
  /tmp/${task_id}-g7|/var/tmp/${task_id}-g7) ;;
  *) echo "work root is outside the exact task prefix: $work_parent" >&2; exit 78 ;;
esac
root="$work_parent/root"
fixtures="$work_parent/fixtures"

cleanup() {
  [[ "${OPEN_CARD_G7_KEEP:-0}" = 1 ]] || rm -rf -- "$work_parent"
}
trap cleanup EXIT INT TERM
rm -rf -- "$work_parent"
mkdir -p -- "$fixtures"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | awk '{print $1}'
  else shasum -a 256 -- "$1" | awk '{print $1}'; fi
}

make_bundle() {
  local version=$1 release_id=$2 protocol=$3 body=$4 bundle
  bundle="$fixtures/$release_id"
  mkdir -p -- "$bundle/bin" "$bundle/systemd"
  printf '#!/usr/bin/env sh\nprintf "%%s\\n" "%s"\n' "$body" >"$bundle/bin/open-card-server"
  printf '#!/usr/bin/env sh\nprintf "%%s\\n" "agent-%s"\n' "$version" >"$bundle/bin/open-card-agent"
  chmod 0755 "$bundle/bin/open-card-server" "$bundle/bin/open-card-agent"
  cp -- "$repo_root/deploy/systemd/open-card-server.service" "$repo_root/deploy/systemd/open-card-agent.service" "$bundle/systemd/"
  local server_sha agent_sha server_unit_sha agent_unit_sha
  server_sha=$(sha256_file "$bundle/bin/open-card-server")
  agent_sha=$(sha256_file "$bundle/bin/open-card-agent")
  server_unit_sha=$(sha256_file "$bundle/systemd/open-card-server.service")
  agent_unit_sha=$(sha256_file "$bundle/systemd/open-card-agent.service")
  python3 - "$bundle/manifest.json" "$version" "$release_id" "$protocol" "$server_sha" "$agent_sha" "$server_unit_sha" "$agent_unit_sha" <<'PY'
import json, sys
path, version, release, protocol, server, agent, server_unit, agent_unit = sys.argv[1:]
value = {
    "schema_version": 1,
    "product": "open-card",
    "version": version,
    "release_id": release,
    "protocol": protocol,
    "config_dir": "/etc/open-card",
    "data_dir": "/var/lib/open-card",
    "compatibility": {
        "min_data_version": 1,
        "max_data_version": 7,
        "min_agent_protocol": "1.0",
        "max_agent_protocol": "1.1"
    },
    "files": [
        {"path": "bin/open-card-server", "sha256": server, "mode": 493},
        {"path": "bin/open-card-agent", "sha256": agent, "mode": 493},
        {"path": "systemd/open-card-server.service", "sha256": server_unit, "mode": 420},
        {"path": "systemd/open-card-agent.service", "sha256": agent_unit, "mode": 420}
    ]
}
with open(path, "w", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  printf '%s\n' "$bundle"
}

v1=$(make_bundle 1.0.0 release-1.0.0 1.0 server-v1)
v2=$(make_bundle 1.1.0 release-1.1.0 1.1 server-v2)
common=(--root "$root" --offline --test-safe-prefix "$work_parent")

"$repo_root/scripts/mvp/install.sh" "${common[@]}" --bundle "$v1"
repeat_output=$("$repo_root/scripts/mvp/install.sh" "${common[@]}" --bundle "$v1")
grep -q 'idempotent' <<<"$repeat_output"
test "$(readlink "$root/opt/open-card/current")" = releases/release-1.0.0
test -f "$root/etc/systemd/system/open-card-server.service"
test -f "$root/etc/systemd/system/open-card-agent.service"

printf 'before\n' >"$root/var/lib/open-card/control-plane.fixture"
"$repo_root/scripts/mvp/backup-control-plane.sh" --root "$root" --reason fixture --test-safe-prefix "$work_parent" >/dev/null
metadata=$(find "$root/var/lib/open-card/backups" -maxdepth 1 -name '*.json' -print -quit)
printf 'after\n' >"$root/var/lib/open-card/control-plane.fixture"
"$repo_root/scripts/mvp/restore-control-plane.sh" --root "$root" --backup "$metadata" --test-safe-prefix "$work_parent" >/dev/null
grep -qx before "$root/var/lib/open-card/control-plane.fixture"

health_fail="$fixtures/health-fail"
printf '#!/usr/bin/env sh\nexit 42\n' >"$health_fail"
chmod 0755 "$health_fail"
set +e
failed_output=$("$repo_root/scripts/mvp/upgrade.sh" "${common[@]}" --bundle "$v2" --health-command "$health_fail" 2>&1)
failed_status=$?
set -e
test "$failed_status" -ne 0
grep -q 'rolling back' <<<"$failed_output"
test "$(readlink "$root/opt/open-card/current")" = releases/release-1.0.0

success_output=$("$repo_root/scripts/mvp/upgrade.sh" "${common[@]}" --bundle "$v2" --health-command /usr/bin/true)
grep -q 'installed Open Card 1.1.0' <<<"$success_output"
active_release=$(readlink "$root/opt/open-card/current")
if [[ "$active_release" != releases/release-1.1.0 ]]; then
  echo "successful upgrade left unexpected current pointer: $active_release" >&2
  exit 1
fi
test "$(readlink "$root/opt/open-card/previous")" = releases/release-1.0.0

set +e
insecure_output=$("$repo_root/scripts/mvp/install.sh" --root "$root" --url http://example.invalid/open-card.tar.gz --test-safe-prefix "$work_parent" 2>&1)
insecure_status=$?
set -e
test "$insecure_status" -ne 0
grep -q 'https://' <<<"$insecure_output"

"$repo_root/scripts/mvp/uninstall.sh" --root "$root" --test-safe-prefix "$work_parent" >/dev/null
test -f "$root/var/lib/open-card/control-plane.fixture"
test ! -e "$root/opt/open-card"

printf '%s\n' \
  'install_repeat=idempotent' \
  'systemd_units=staged_not_activated' \
  'backup_restore=checksum_verified_fixture' \
  'failed_upgrade=pointer_rolled_back' \
  'n_minus_one_upgrade=activated' \
  'insecure_url=rejected' \
  'uninstall=data_preserved' \
  'cleanup=task_scoped'
