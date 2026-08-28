#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: restore-control-plane.sh --root TASK_ROOT --backup ARCHIVE_OR_METADATA
                                [--database-restore-command EXECUTABLE]
                                [--confirm-installation-id RESTORE:ID]
                                [--test-safe-prefix PATH] [--dry-run]
USAGE
}
die() { echo "open-card restore: $*" >&2; exit 1; }
root= backup= database_restore_command= safe_prefix= confirmation=
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) [[ $# -gt 1 ]] || die "--root requires a value"; root=$2; shift 2 ;;
    --backup) [[ $# -gt 1 ]] || die "--backup requires a value"; backup=$2; shift 2 ;;
    --database-restore-command) [[ $# -gt 1 ]] || die "--database-restore-command requires a value"; database_restore_command=$2; shift 2 ;;
    --confirm-installation-id) [[ $# -gt 1 ]] || die "--confirm-installation-id requires a value"; confirmation=$2; shift 2 ;;
    --test-safe-prefix) [[ $# -gt 1 ]] || die "--test-safe-prefix requires a value"; safe_prefix=$2; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option $1" ;;
  esac
done
[[ -n "$root" && "$root" = /* ]] || die "--root must be an absolute path"
[[ "$root" != *$'\n'* && "$root" != *$'\r'* ]] || die "root contains a newline"
[[ -n "$backup" ]] || die "--backup is required"
if [[ -n "$database_restore_command" ]]; then
  [[ "$database_restore_command" = /* && -x "$database_restore_command" ]] || die "database restore command must be an executable absolute path"
fi
system_root=0
if [[ "$root" = "/" ]]; then
  system_root=1
  [[ "$EUID" -eq 0 ]] || die "--root / requires EUID 0"
  [[ "${OPEN_CARD_ALLOW_SYSTEM_ROOT:-}" = "1" ]] || die "--root / requires OPEN_CARD_ALLOW_SYSTEM_ROOT=1"
  installation_id=/var/lib/open-card/installation-id
  [[ -f "$installation_id" && ! -L "$installation_id" && "$(stat -c '%u:%a' "$installation_id")" = "0:600" ]] || die "--root / requires root-owned installation-id"
  [[ "$confirmation" = "RESTORE:$(cat -- "$installation_id")" ]] || die "--root / requires --confirm-installation-id RESTORE:<installation-id>"
  [[ -z "$safe_prefix" ]] || die "--test-safe-prefix is not valid with --root /"
else
  [[ "$root" != "$HOME" && "$root" != "$HOME"/* ]] || die "refusing HOME or a path below HOME"
fi
if [[ -n "$safe_prefix" ]]; then
  [[ "$safe_prefix" = /* && "$safe_prefix" != "/" ]] || die "safe prefix must be absolute and non-root"
fi
parent=$(dirname -- "$root")
if [[ ! -d "$parent" && $dry_run -eq 0 ]]; then mkdir -p -- "$parent"; fi
parent=$(cd -- "$parent" 2>/dev/null && pwd -P) || die "cannot resolve root parent"
base=$(basename -- "$root")
if [[ -e "$root" || -L "$root" ]]; then
  [[ ! -L "$root" ]] || die "refusing symlink staging root"
  root_real=$(cd -- "$root" && pwd -P) || die "cannot resolve root"
else
  root_real="$parent/$base"
fi
if (( ! system_root )); then
  [[ "$root_real" != "/" && "$root_real" != "$HOME" && "$root_real" != "$HOME"/* ]] || die "unsafe root resolves to / or HOME"
fi
if (( system_root )); then
  [[ "$root_real" = "/" ]] || die "--root / resolves unexpectedly"
elif [[ -n "$safe_prefix" ]]; then
  safe_parent=$(cd -- "$(dirname -- "$safe_prefix")" && pwd -P) || die "cannot resolve safe prefix"
  safe_real="$safe_parent/$(basename -- "$safe_prefix")"
  case "$root_real" in "$safe_real"|"$safe_real"/*) ;; *) die "root is outside explicit test-safe prefix" ;; esac
else
  case "$root_real" in
    /tmp/open-card-g7*|/private/tmp/open-card-g7*|/var/tmp/open-card-g7*|/private/var/tmp/open-card-g7*|/tmp/opencard-g7*|/private/tmp/opencard-g7*|/var/tmp/opencard-g7*|/private/var/tmp/opencard-g7*) ;;
    *) die "root must use task-safe prefix open-card-g7* or --test-safe-prefix" ;;
  esac
fi
if (( ! system_root )) && [[ -e "$root" || -L "$root" ]]; then
  [[ "$root_real" = "$root" || ( "$root_real" = /private/* && "/${root_real#/private/}" = "$root" ) ]] || die "root resolves through an unexpected symlink"
fi

if [[ "$backup" = *.json ]]; then
  metadata="$backup"
else
  metadata="${backup%.tar.gz}.json"
fi
[[ -f "$metadata" ]] || die "backup metadata is missing: $metadata"
[[ ! -L "$metadata" ]] || die "backup metadata must not be a symlink"
command -v python3 >/dev/null 2>&1 || die "python3 standard library is required for metadata validation"
metadata_info=$(python3 - "$metadata" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
required = {"schema_version","backup_id","created_at","source_data_dir","archive","archive_sha256","reason","consistency"}
optional = {"source_config_dir", "release_version", "database_dump", "database_dump_sha256", "migration_version", "archive_size", "file_count", "source_mode", "config_mode", "source_digest", "config_digest", "config_file_count", "archive_layout"}
if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
    raise SystemExit("backup metadata fields are invalid")
if value["schema_version"] != 1 or not re.fullmatch(r"backup-[A-Za-z0-9._-]+", value["backup_id"]):
    raise SystemExit("backup metadata identity is invalid")
if value["source_data_dir"] != "/var/lib/open-card":
    raise SystemExit("backup source directory contract mismatch")
if value.get("source_config_dir", "/etc/open-card") != "/etc/open-card":
    raise SystemExit("backup source config directory contract mismatch")
if not isinstance(value["archive"], str) or "/" in value["archive"] or value["archive"] in ("", ".", ".."):
    raise SystemExit("backup archive name is unsafe")
if not isinstance(value["archive_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["archive_sha256"]):
    raise SystemExit("backup checksum is invalid")
if value["consistency"] not in ("filesystem-fixture", "pg-dump"):
    raise SystemExit("backup consistency is invalid")
if value["consistency"] == "pg-dump":
    if not isinstance(value.get("database_dump"), str) or "/" in value["database_dump"] or not re.fullmatch(r"[0-9a-f]{64}", value.get("database_dump_sha256", "")):
        raise SystemExit("database dump metadata is invalid")
if value.get("migration_version") and not re.fullmatch(r"[0-9]{4}", value["migration_version"]):
    raise SystemExit("backup migration version is invalid")
if not all(isinstance(value.get(key, 0), int) and value.get(key, 0) >= 0 for key in ("archive_size", "file_count", "source_mode", "config_mode")) or value.get("source_mode", 0) > 777 or value.get("config_mode", 0) > 777:
    raise SystemExit("backup size/count/permission metadata is invalid")
if value.get("source_digest") and not re.fullmatch(r"[0-9a-f]{64}", value["source_digest"]):
    raise SystemExit("backup source digest is invalid")
if value.get("config_digest") and not re.fullmatch(r"[0-9a-f]{64}", value["config_digest"]):
    raise SystemExit("backup config digest is invalid")
if value.get("config_file_count", 0) < 0 or value.get("archive_layout", "") not in ("", "m7-v2"):
    raise SystemExit("backup config/archive metadata is invalid")
print(value["archive"]); print(value["archive_sha256"]); print(value["backup_id"])
print(value["consistency"]); print(value.get("database_dump", "")); print(value.get("database_dump_sha256", ""))
print(value.get("archive_size", 0)); print(value.get("file_count", 0)); print(value.get("source_mode", 0)); print(value.get("config_mode", 0)); print(value.get("migration_version", "")); print(value.get("source_digest", "")); print(value.get("config_digest", "")); print(value.get("config_file_count", 0)); print(value.get("archive_layout", ""))
PY
) || die "backup metadata validation failed"
archive_name=$(sed -n '1p' <<< "$metadata_info")
expected_digest=$(sed -n '2p' <<< "$metadata_info")
backup_id=$(sed -n '3p' <<< "$metadata_info")
consistency=$(sed -n '4p' <<< "$metadata_info")
database_dump_name=$(sed -n '5p' <<< "$metadata_info")
database_dump_digest=$(sed -n '6p' <<< "$metadata_info")
archive_size=$(sed -n '7p' <<< "$metadata_info")
file_count=$(sed -n '8p' <<< "$metadata_info")
source_mode=$(sed -n '9p' <<< "$metadata_info")
config_mode=$(sed -n '10p' <<< "$metadata_info")
migration_version=$(sed -n '11p' <<< "$metadata_info")
source_digest=$(sed -n '12p' <<< "$metadata_info")
config_digest=$(sed -n '13p' <<< "$metadata_info")
config_file_count=$(sed -n '14p' <<< "$metadata_info")
archive_layout=$(sed -n '15p' <<< "$metadata_info")
database_url=${OPEN_CARD_DATABASE_URL:-${DATABASE_URL:-}}
if [[ "$consistency" = pg-dump ]]; then
  [[ -n "$database_restore_command" ]] || die "pg-dump backup restore requires --database-restore-command"
  [[ -n "$database_url" ]] || die "database restore requires OPEN_CARD_DATABASE_URL or DATABASE_URL"
  if (( system_root )); then
    die "production PostgreSQL restore is blocked: restore into a temporary database and atomic database swap are not implemented"
  fi
elif [[ -n "$database_restore_command" ]]; then
  die "--database-restore-command requires a pg-dump backup"
fi
if [[ "$backup" = *.json ]]; then
  archive="$(dirname -- "$metadata")/$archive_name"
else
  [[ "$(basename -- "$backup")" = "$archive_name" ]] || die "backup archive does not match metadata"
  archive="$backup"
fi
[[ -f "$archive" ]] || die "backup archive is missing: $archive"
[[ ! -L "$archive" ]] || die "backup archive must not be a symlink"
if command -v sha256sum >/dev/null 2>&1; then actual_digest=$(sha256sum -- "$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then actual_digest=$(shasum -a 256 -- "$archive" | awk '{print $1}')
else die "sha256sum or shasum is required"; fi
[[ "$actual_digest" = "$expected_digest" ]] || die "backup checksum mismatch"
if [[ "$archive_size" != 0 ]]; then
  if stat -c '%s' "$archive" >/dev/null 2>&1; then actual_size=$(stat -c '%s' "$archive"); else actual_size=$(stat -f '%z' "$archive"); fi
  [[ "$actual_size" = "$archive_size" ]] || die "backup archive size mismatch"
fi
python3 - "$archive" <<'PY' || die "backup archive contains unsafe entries"
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = archive.getmembers()
    if len(members) > 100_000 or sum(member.size for member in members) > 10_737_418_240:
        raise SystemExit("backup archive exceeds file-count or size limit")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isreg()) or member.mode & 0o022:
            raise SystemExit(f"unsafe backup archive entry: {member.name}")
PY
data_dir="$root_real/var/lib/open-card"
data_parent="$root_real/var/lib"
config_dir="$root_real/etc/open-card"
config_parent="$root_real/etc"
assert_no_symlink_components() {
  local value=$1 current_path=/ component
  IFS=/ read -ra components <<< "${value#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current_path="$current_path$component"
    [[ ! -L "$current_path" ]] || die "symlink path component is not allowed: $current_path"
    current_path="$current_path/"
  done
}
assert_no_symlink_components "$data_parent"
assert_no_symlink_components "$data_dir"
assert_no_symlink_components "$config_parent"
assert_no_symlink_components "$config_dir"
if (( dry_run )); then
  echo "open-card restore: would restore $archive into $data_dir"
  exit 0
fi
mkdir -p -- "$data_parent" "$config_parent"
stage="$data_parent/.open-card-restore-$backup_id.$$"
old="$data_parent/.open-card-previous-$backup_id.$$"
old_config="$config_parent/.open-card-previous-config-$backup_id.$$"
rm -rf -- "$stage" "$old"
mkdir -p -- "$stage"
chmod 0700 "$stage"
rollback() {
  if [[ -e "$data_dir" || -L "$data_dir" ]]; then rm -rf -- "$data_dir"; fi
  if [[ -d "$old" && ! -e "$data_dir" ]]; then mv -- "$old" "$data_dir"; fi
  if [[ -e "$config_dir" || -L "$config_dir" ]]; then rm -rf -- "$config_dir"; fi
  if [[ -d "$old_config" && ! -e "$config_dir" ]]; then mv -- "$old_config" "$config_dir"; fi
  rm -rf -- "$stage"
}
trap rollback EXIT
python3 - "$archive" "$stage" <<'PY' || die "backup archive extraction failed"
import sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as archive:
    archive.extractall(sys.argv[2], numeric_owner=False, filter="fully_trusted")
PY
data_stage="$stage"
config_stage=
if [[ "$archive_layout" = "m7-v2" ]]; then
  [[ -d "$stage/data" && -d "$stage/config" ]] || die "M7 backup archive must contain data/ and config/ subtrees"
  data_stage="$stage/data"
  config_stage="$stage/config"
fi
if [[ "$file_count" != 0 ]]; then
  actual_data_files=$(find "$data_stage" -type f -print | wc -l | tr -d '[:space:]')
  [[ "$actual_data_files" = "$file_count" ]] || die "restored data file count does not match metadata"
fi
if [[ -n "$config_stage" && "$config_file_count" != 0 ]]; then
  actual_config_files=$(find "$config_stage" -type f -print | wc -l | tr -d '[:space:]')
  [[ "$actual_config_files" = "$config_file_count" ]] || die "restored config file count does not match metadata"
fi
if [[ "$consistency" = pg-dump ]]; then
  dump_stage="$stage/$database_dump_name"
  [[ -f "$dump_stage" ]] || die "database dump is missing from backup archive"
  if command -v sha256sum >/dev/null 2>&1; then restored_dump_digest=$(sha256sum -- "$dump_stage" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then restored_dump_digest=$(shasum -a 256 -- "$dump_stage" | awk '{print $1}')
  else die "sha256sum or shasum is required"; fi
  [[ "$restored_dump_digest" = "$database_dump_digest" ]] || die "database dump checksum mismatch"
fi
if [[ -n "$(find "$data_stage" -type l -print -quit)" || -n "$(find "$data_stage" \( -type b -o -type c -o -type p -o -type s \) -print -quit)" ]]; then die "restored data contains unsafe filesystem entries"; fi
if [[ -n "$config_stage" && ( -n "$(find "$config_stage" -type l -print -quit)" || -n "$(find "$config_stage" \( -type b -o -type c -o -type p -o -type s \) -print -quit)" ) ]]; then die "restored config contains unsafe filesystem entries"; fi
if [[ -d "$data_dir" ]]; then mv -- "$data_dir" "$old"; fi
mv -- "$data_stage" "$data_dir"
if [[ -n "$config_stage" ]]; then
  if [[ -d "$config_dir" ]]; then mv -- "$config_dir" "$old_config"; fi
  mv -- "$config_stage" "$config_dir"
fi
mkdir -p -- "$data_dir/backups"
if [[ -d "$old/backups" ]]; then COPYFILE_DISABLE=1 cp -a -- "$old/backups"/. "$data_dir/backups"/; fi
if [[ "$source_mode" = 0 ]]; then source_mode=750; fi
chmod "$source_mode" "$data_dir" 2>/dev/null || chmod 0750 "$data_dir"
chmod 0700 "$data_dir/backups"
if [[ -n "$config_stage" ]]; then
  if [[ "$config_mode" = 0 ]]; then config_mode=750; fi
  chmod "$config_mode" "$config_dir" 2>/dev/null || chmod 0750 "$config_dir"
fi
if [[ -n "$database_restore_command" ]]; then
  restored_dump="$data_dir/$database_dump_name"
  [[ -f "$restored_dump" ]] || restored_dump="$stage/$database_dump_name"
	OPEN_CARD_RESTORED_BACKUP_ID="$backup_id" OPEN_CARD_RESTORED_DUMP="$restored_dump" "$database_restore_command" "$database_url" "$restored_dump" || die "database restore command failed"
fi
rm -rf -- "$old" "$old_config"
trap - EXIT
if [[ "$consistency" = pg-dump && -n "$database_restore_command" ]]; then
  echo "open-card restore: restored $(basename -- "$archive") and imported verified database dump"
elif [[ "$consistency" = pg-dump ]]; then
  echo "open-card restore: restored $(basename -- "$archive") and verified database dump"
else
  echo "open-card restore: restored $(basename -- "$archive")"
fi
