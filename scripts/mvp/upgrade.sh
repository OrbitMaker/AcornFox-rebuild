#!/usr/bin/env bash
set -euo pipefail
usage() {
  cat >&2 <<'USAGE'
usage: upgrade.sh --root TASK_ROOT --bundle BUNDLE [--url URL] [--offline]
                  [--health-command EXECUTABLE] [--database-dump-command EXECUTABLE]
                  [--database-restore-command EXECUTABLE]
                  [--migration-command EXECUTABLE] [--migration-dir DIRECTORY]
                  [--allow-downgrade]
                  [--expected-manifest-sha256 HEX]
                  [--confirm-installation-id UPGRADE:ID]
                  [--test-safe-prefix PATH] [--activate] [--dry-run]

Task-root upgrades retain the legacy backup/migration flow. System-root
upgrades stage the immutable RC1 substrate, provision the fixed upgrade
control identity, enable the boot-safe target, then delegate only to
open-card-upgrade.
USAGE
}
die() { echo "open-card upgrade: $*" >&2; exit 1; }

# Resolve a fixed production executable through only root-owned symlinks and
# root-owned non-group/world-writable parent directories. The final file must
# be executable, regular, root-owned, and non-group/world-writable.
verified_production_program() {
  local candidate=$1 target parent canonical component current owner mode numeric IFS
  [[ "$candidate" = /* && -n "$candidate" ]] || return 1
  while [[ -L "$candidate" ]]; do
    owner=$(/usr/bin/stat -c '%u' -- "$candidate") || return 1
    [[ "$owner" = 0 ]] || return 1
    target=$(/usr/bin/readlink -- "$candidate") || return 1
    [[ -n "$target" ]] || return 1
    if [[ "$target" = /* ]]; then
      candidate=$target
    else
      parent=$(/usr/bin/dirname -- "$candidate") || return 1
      candidate="$parent/$target"
    fi
  done
  [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || return 1
  parent=$(/usr/bin/dirname -- "$candidate") || return 1
  canonical=$(cd -P -- "$parent" && pwd -P) || return 1
  candidate="$canonical/$(/usr/bin/basename -- "$candidate")"
  [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || return 1
  owner=$(/usr/bin/stat -c '%u' /) || return 1
  mode=$(/usr/bin/stat -c '%a' /) || return 1
  [[ "$owner" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  numeric=$((8#$mode))
  (( (numeric & 8#022) == 0 )) || return 1
  current=/
  IFS=/ read -r -a parts <<< "${candidate#/}"
  for component in "${parts[@]}"; do
    [[ -n "$component" ]] || continue
    current="${current%/}/$component"
    [[ ! -L "$current" ]] || return 1
    owner=$(/usr/bin/stat -c '%u' -- "$current") || return 1
    mode=$(/usr/bin/stat -c '%a' -- "$current") || return 1
    [[ "$owner" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    numeric=$((8#$mode))
    (( (numeric & 8#022) == 0 )) || return 1
  done
  printf '%s\n' "$candidate"
}
root= bundle= bundle_url= health= database_dump_command= database_restore_command= migration_command= migration_dir= expected_manifest_sha256= safe_prefix= confirmation=
offline=0 dry_run=0 activate=0 allow_downgrade=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) [[ $# -gt 1 ]] || die "--root requires a value"; root=$2; shift 2 ;;
    --bundle) [[ $# -gt 1 ]] || die "--bundle requires a value"; bundle=$2; shift 2 ;;
    --url) [[ $# -gt 1 ]] || die "--url requires a value"; bundle_url=$2; shift 2 ;;
    --health-command|--health-cmd) [[ $# -gt 1 ]] || die "$1 requires a value"; health=$2; shift 2 ;;
    --database-dump-command) [[ $# -gt 1 ]] || die "--database-dump-command requires a value"; database_dump_command=$2; shift 2 ;;
    --database-restore-command) [[ $# -gt 1 ]] || die "--database-restore-command requires a value"; database_restore_command=$2; shift 2 ;;
    --migration-command) [[ $# -gt 1 ]] || die "--migration-command requires a value"; migration_command=$2; shift 2 ;;
    --migration-dir) [[ $# -gt 1 ]] || die "--migration-dir requires a value"; migration_dir=$2; shift 2 ;;
    --allow-downgrade) allow_downgrade=1; shift ;;
    --expected-manifest-sha256) [[ $# -gt 1 ]] || die "--expected-manifest-sha256 requires a value"; expected_manifest_sha256=$2; shift 2 ;;
    --confirm-installation-id) [[ $# -gt 1 ]] || die "--confirm-installation-id requires a value"; confirmation=$2; shift 2 ;;
    --test-safe-prefix) [[ $# -gt 1 ]] || die "--test-safe-prefix requires a value"; safe_prefix=$2; shift 2 ;;
    --activate) activate=1; shift ;;
    --offline) offline=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option $1" ;;
  esac
done
[[ -n "$root" ]] || die "--root is required"
[[ -n "$bundle" || -n "$bundle_url" ]] || die "--bundle or --url is required"
[[ -z "$bundle" || -z "$bundle_url" ]] || die "use either --bundle or --url"
[[ $offline -eq 0 || -z "$bundle_url" ]] || die "--offline refuses online bundle URLs"
backup_confirmation= restore_confirmation=
if [[ "$root" = "/" ]]; then
  # Production never inherits command lookup from its caller. This occurs
  # before the installation-ID validation invokes stat or cat.
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  [[ "$EUID" -eq 0 ]] || die "--root / requires EUID 0"
  [[ "${OPEN_CARD_ALLOW_SYSTEM_ROOT:-}" = "1" ]] || die "--root / requires OPEN_CARD_ALLOW_SYSTEM_ROOT=1"
  installation_id=/var/lib/open-card/installation-id
  [[ -f "$installation_id" && ! -L "$installation_id" && "$(stat -c '%u:%a' "$installation_id")" = "0:600" ]] || die "--root / requires root-owned installation-id"
  installation_value=$(cat -- "$installation_id")
  [[ "$confirmation" = "UPGRADE:$installation_value" ]] || die "--root / requires --confirm-installation-id UPGRADE:<installation-id>"
fi
if [[ -n "$migration_command" ]]; then
  [[ "$migration_command" = /* && -x "$migration_command" ]] || die "migration command must be an executable absolute path"
fi
if [[ -n "$migration_dir" ]]; then
  [[ "$migration_dir" = /* && -d "$migration_dir" && ! -L "$migration_dir" ]] || die "migration directory must be an existing real absolute directory"
fi
if [[ -n "$database_restore_command" ]]; then
  [[ "$database_restore_command" = /* && -x "$database_restore_command" ]] || die "database restore command must be an executable absolute path"
fi
if [[ -n "$database_dump_command" && -z "$database_restore_command" ]]; then
  die "--database-dump-command requires --database-restore-command for RC rollback"
fi
if (( activate )) && [[ "$root" != "/" ]]; then
  die "--activate requires --root / and clean-worker authorization"
fi
if (( allow_downgrade )); then
  [[ "${OPEN_CARD_ALLOW_DOWNGRADE:-}" = "1" ]] || die "--allow-downgrade requires OPEN_CARD_ALLOW_DOWNGRADE=1"
fi
if [[ -n "$expected_manifest_sha256" ]]; then
  [[ "$expected_manifest_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || die "expected manifest sha256 must be 64 hexadecimal characters"
  expected_manifest_sha256=$(tr '[:upper:]' '[:lower:]' <<< "$expected_manifest_sha256")
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)

# The production path is intentionally a short delegation boundary. It must
# never reach the task-root backup/restore/migration state machine below: the
# Go engine owns the transaction marker, candidate database, pointer swap,
# rollback and recovery journal.
if [[ "$root" = "/" ]]; then
  (( activate )) || die "--root / requires --activate"
  [[ -n "$expected_manifest_sha256" ]] || die "--root / requires --expected-manifest-sha256"
  [[ -z "$health" && -z "$database_dump_command" && -z "$database_restore_command" && -z "$migration_command" && -z "$migration_dir" ]] || die "--root / refuses --health-command, --database-dump-command, --database-restore-command, --migration-command, and --migration-dir"
  (( ! allow_downgrade )) || die "--root / refuses --allow-downgrade"

  stage_args=(--root / --stage-upgrade-substrate --expected-manifest-sha256 "$expected_manifest_sha256")
  [[ -n "$bundle" ]] && stage_args+=(--bundle "$bundle")
  [[ -n "$bundle_url" ]] && stage_args+=(--url "$bundle_url")
  (( offline )) && stage_args+=(--offline)
  (( dry_run )) && stage_args+=(--dry-run)
  if ! /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL "$script_dir/install.sh" "${stage_args[@]}"; then
    die "candidate substrate staging failed"
  fi
  if (( dry_run )); then
    exit 0
  fi

  production_upgrade=/opt/open-card/upgrade-tools/open-card-upgrade
  [[ -f "$production_upgrade" && ! -L "$production_upgrade" ]] || die "production upgrade helper is missing"
  [[ "$(stat -c '%u:%a' "$production_upgrade")" = "0:755" ]] || die "production upgrade helper is not root-owned mode 0755"
  [[ -f /usr/bin/systemctl && ! -L /usr/bin/systemctl && "$(stat -c '%u:%a' /usr/bin/systemctl)" = "0:755" ]] || die "trusted systemctl is unavailable"

  run_upgrade_helper() {
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C "$production_upgrade" "$@"
  }
  run_upgrade_helper prepare-control

  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemctl enable --now open-card-upgrade-safe.target
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemctl is-enabled --quiet open-card-upgrade-safe.target || die "upgrade-safe target is not enabled"
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemctl is-active --quiet open-card-upgrade-safe.target || die "upgrade-safe target is not active"
  for unit in open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service; do
    required_link="/etc/systemd/system/$unit.requires/open-card-upgrade-safe.target"
    [[ -L "$required_link" ]] || die "upgrade-safe target RequiredBy link is missing for $unit"
    [[ "$(/usr/bin/stat -c '%u' -- "$required_link")" = 0 ]] || die "upgrade-safe target RequiredBy link owner is unsafe for $unit"
    required_target=$(/usr/bin/readlink -- "$required_link") || die "upgrade-safe target RequiredBy link is unreadable for $unit"
    [[ "$required_target" = "../open-card-upgrade-safe.target" || "$required_target" = "/etc/systemd/system/open-card-upgrade-safe.target" ]] || die "upgrade-safe target RequiredBy link is unsafe for $unit"
    requirements=$(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemctl show "$unit" --property=Requires --value --no-pager) || die "upgrade-safe dependency is unreadable for $unit"
    [[ " $requirements " = *" open-card-upgrade-safe.target "* ]] || die "upgrade-safe target is not required by $unit"
  done

  production_python=$(verified_production_program /usr/bin/python3) || die "trusted production python is unavailable"
  candidate_release_id=$(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C "$production_python" - /opt/open-card/releases "$expected_manifest_sha256" <<'PY'
import hashlib, json, os, re, stat, sys

root = sys.argv[1]
expected = sys.argv[2]
try:
    root_stat = os.lstat(root)
except OSError as exc:
    raise SystemExit("candidate release root is unavailable") from exc
if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or root_stat.st_uid != 0 or root_stat.st_gid != 0 or root_stat.st_mode & 0o022:
    raise SystemExit("candidate release root is unsafe")
matches = []
for entry in os.scandir(root):
    if not entry.is_dir(follow_symlinks=False) or entry.is_symlink():
        continue
    manifest_path = os.path.join(root, entry.name, "manifest.json")
    try:
        info = os.lstat(manifest_path)
    except OSError:
        continue
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644:
        continue
    with open(manifest_path, "rb") as stream:
        raw = stream.read()
    if hashlib.sha256(raw).hexdigest() != expected:
        continue
    try:
        manifest = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise SystemExit("candidate manifest is invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("version") != "0.8.0-rc.1" or manifest.get("migration_version") != "0024" or manifest.get("release_id") != entry.name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", entry.name):
        raise SystemExit("candidate manifest is not the RC1/0024 release")
    matches.append(entry.name)
if len(matches) != 1:
    raise SystemExit("candidate manifest identity is ambiguous")
print(matches[0])
PY
  ) || die "candidate release identity is unavailable"
  [[ -r /proc/sys/kernel/random/uuid ]] || die "kernel transaction UUID source is unavailable"
  IFS= read -r kernel_uuid < /proc/sys/kernel/random/uuid
  [[ "$kernel_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || die "kernel transaction UUID is invalid"
  transaction_id="upgrade-${kernel_uuid//-/}"

  run_upgrade_helper preflight --transaction-id "$transaction_id" --release-id "$candidate_release_id" --manifest-sha256 "$expected_manifest_sha256" --expect-layout rc0-legacy
  run_upgrade_helper run --transaction-id "$transaction_id" --release-id "$candidate_release_id" --manifest-sha256 "$expected_manifest_sha256" --expect-layout rc0-legacy
  exit 0
fi

# First ask the installer to validate/download the candidate without changing
# the root. This also enforces the root safety boundary.
preflight_args=(--root "$root" --dry-run)
[[ -n "$bundle" ]] && preflight_args+=(--bundle "$bundle")
[[ -n "$bundle_url" ]] && preflight_args+=(--url "$bundle_url")
(( offline )) && preflight_args+=(--offline)
[[ -n "$safe_prefix" ]] && preflight_args+=(--test-safe-prefix "$safe_prefix")
[[ -n "$migration_dir" ]] && preflight_args+=(--migration-dir "$migration_dir")
(( allow_downgrade )) && preflight_args+=(--allow-downgrade)
[[ -n "$expected_manifest_sha256" ]] && preflight_args+=(--expected-manifest-sha256 "$expected_manifest_sha256")
if ! preflight_output=$("$script_dir/install.sh" "${preflight_args[@]}" 2>&1); then
  die "candidate bundle preflight failed: $preflight_output"
fi

prefix="$root/opt/open-card"
current="$prefix/current"
[[ -L "$current" ]] || die "upgrade requires an existing current release"
target=$(readlink -- "$current")
[[ "$target" = releases/* ]] || die "current pointer escapes releases"
old_release=${target#releases/}
[[ -f "$current/manifest.json" ]] || die "current release manifest is missing"
current_migration_version=
if [[ -f "$root/var/lib/open-card/migration.version" && ! -L "$root/var/lib/open-card/migration.version" ]]; then
  current_migration_version=$(tr -d '[:space:]' < "$root/var/lib/open-card/migration.version")
  [[ "$current_migration_version" =~ ^[0-9]{4}$ ]] || die "control-plane migration.version is invalid"
elif [[ -f "$root/var/lib/open-card/schema.version" && ! -L "$root/var/lib/open-card/schema.version" ]]; then
  persisted_schema_version=$(tr -d '[:space:]' < "$root/var/lib/open-card/schema.version")
  if [[ "$persisted_schema_version" =~ ^[0-9]+$ && "$persisted_schema_version" -ge 10 ]]; then
    printf -v current_migration_version '%04d' "$persisted_schema_version"
  fi
fi
current_release_version=$(python3 - "$current/manifest.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
)
edge_was_active=0
if [[ "$root" = "/" ]] && systemctl is-active --quiet open-card-edge.service; then
  edge_was_active=1
fi

# A backup is the durable rollback point for control-plane data. The backup
# script repeats root/path validation and is a no-op under --dry-run.
backup_args=(--root "$root" --reason "pre-upgrade-$old_release")
backup_args+=(--release-version "$current_release_version")
(( dry_run )) && backup_args+=(--dry-run)
[[ -n "$database_dump_command" ]] && backup_args+=(--database-dump-command "$database_dump_command")
[[ -n "$safe_prefix" ]] && backup_args+=(--test-safe-prefix "$safe_prefix")
[[ -n "$backup_confirmation" ]] && backup_args+=(--confirm-installation-id "$backup_confirmation")
backup_output=$(OPEN_CARD_CURRENT_MIGRATION_VERSION="$current_migration_version" "$script_dir/backup-control-plane.sh" "${backup_args[@]}" 2>&1) || die "control-plane backup failed: $backup_output"
backup_metadata=
if (( ! dry_run )); then
  backup_metadata=$(find "$root/var/lib/open-card/backups" -maxdepth 1 -type f -name 'backup-*.json' -print 2>/dev/null | sort | tail -n 1)
  [[ -n "$backup_metadata" && -f "$backup_metadata" ]] || die "control-plane backup metadata was not created"
fi

mark_recovery_required() {
  local original_status=$1 restore_status=$2 restore_output=$3
  local stop_status=0 current_pointer recovery_dir marker evidence
  if [[ "$root" = "/" ]]; then
    systemctl stop open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service >/dev/null 2>&1 || stop_status=$?
  fi
  current_pointer=$(readlink -- "$current" 2>/dev/null || printf '%s' "unknown")
  recovery_dir="$root/var/lib/open-card/evidence"
  marker="$root/var/lib/open-card/recovery-required.json"
  evidence="$recovery_dir/upgrade-recovery-required-$$.json"
  if ! mkdir -p -- "$recovery_dir"; then
    echo "open-card upgrade: unable to create recovery evidence directory; services remain stopped" >&2
    trap - EXIT
    exit 79
  fi
  if ! python3 - "$marker" "$evidence" "$original_status" "$restore_status" "$stop_status" "$backup_metadata" "$current_pointer" "$restore_output" <<'PY'
import json, os, sys, tempfile
marker, evidence, original, restored, stopped, backup, pointer, detail = sys.argv[1:]
value = {
    "state": "recovery_required",
    "phase": "control_plane_restore_failed",
    "original_failure_status": int(original),
    "restore_status": int(restored),
    "service_stop_status": int(stopped),
    "backup_metadata": backup,
    "current_pointer": pointer,
    "restore_error": detail[-4096:],
}
for path in (marker, evidence):
    parent = os.path.dirname(path); os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".recovery-", dir=parent, text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True); stream.write("\n")
    os.chmod(temporary, 0o600); os.replace(temporary, path)
PY
  then
    echo "open-card upgrade: unable to write recovery marker; services remain stopped" >&2
    trap - EXIT
    exit 79
  fi
  if ! chmod 0600 "$marker" "$evidence"; then
    echo "open-card upgrade: unable to protect recovery marker; services remain stopped" >&2
    trap - EXIT
    exit 79
  fi
  echo "open-card upgrade: recovery required; services stopped; marker=$marker" >&2
}

rollback_upgrade() {
  local status=$?
  if (( status != 0 && dry_run == 0 )) && [[ -n "${backup_metadata:-}" && -f "${backup_metadata:-}" ]]; then
    restore_args=(--root "$root" --backup "$backup_metadata")
    [[ -z "$database_restore_command" ]] || restore_args+=(--database-restore-command "$database_restore_command")
    [[ -z "$safe_prefix" ]] || restore_args+=(--test-safe-prefix "$safe_prefix")
    [[ -z "$restore_confirmation" ]] || restore_args+=(--confirm-installation-id "$restore_confirmation")
    set +e
    restore_output=$("$script_dir/restore-control-plane.sh" "${restore_args[@]}" 2>&1)
    restore_status=$?
    set -e
    if (( restore_status != 0 )); then
      mark_recovery_required "$status" "$restore_status" "$restore_output"
      trap - EXIT
      exit 78
    fi
  fi
  return "$status"
}
trap rollback_upgrade EXIT

install_args=(--root "$root")
[[ -n "$bundle" ]] && install_args+=(--bundle "$bundle")
[[ -n "$bundle_url" ]] && install_args+=(--url "$bundle_url")
(( offline )) && install_args+=(--offline)
(( dry_run )) && install_args+=(--dry-run)
(( allow_downgrade )) && install_args+=(--allow-downgrade)
[[ -n "$health" ]] && install_args+=(--health-command "$health")
[[ -n "$migration_command" ]] && install_args+=(--migration-command "$migration_command")
[[ -n "$migration_dir" ]] && install_args+=(--migration-dir "$migration_dir")
[[ -n "$expected_manifest_sha256" ]] && install_args+=(--expected-manifest-sha256 "$expected_manifest_sha256")
[[ -n "$safe_prefix" ]] && install_args+=(--test-safe-prefix "$safe_prefix")
(( activate )) && install_args+=(--activate)
"$script_dir/install.sh" "${install_args[@]}"
if [[ "$root" = "/" ]] && (( edge_was_active )); then
  /opt/open-card/current/bin/caddy validate --config /etc/open-card/open-card-edge.Caddyfile --adapter caddyfile
  /opt/open-card/current/bin/caddy adapt --config /etc/open-card/open-card-edge.Caddyfile --adapter caddyfile --validate >/dev/null
  systemctl enable --now open-card-edge.service
fi
