#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: backup-control-plane.sh --root TASK_ROOT [--reason LABEL]
                               [--release-version VERSION]
                               [--migration-version 0022]
                               [--database-dump-command EXECUTABLE]
                               [--confirm-installation-id BACKUP:ID]
                               [--test-safe-prefix PATH] [--dry-run]

When OPEN_CARD_DATABASE_URL or DATABASE_URL is set, a direct pg_dump-compatible
command is required. Without a database URL, the archive is explicitly marked
filesystem-fixture and is not a PostgreSQL snapshot.
USAGE
}
die() { echo "open-card backup: $*" >&2; exit 1; }
root= reason= release_version= migration_version= database_dump_command= safe_prefix= confirmation=
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) [[ $# -gt 1 ]] || die "--root requires a value"; root=$2; shift 2 ;;
    --reason) [[ $# -gt 1 ]] || die "--reason requires a value"; reason=$2; shift 2 ;;
    --release-version) [[ $# -gt 1 ]] || die "--release-version requires a value"; release_version=$2; shift 2 ;;
    --migration-version) [[ $# -gt 1 ]] || die "--migration-version requires a value"; migration_version=$2; shift 2 ;;
    --database-dump-command) [[ $# -gt 1 ]] || die "--database-dump-command requires a value"; database_dump_command=$2; shift 2 ;;
    --confirm-installation-id) [[ $# -gt 1 ]] || die "--confirm-installation-id requires a value"; confirmation=$2; shift 2 ;;
    --test-safe-prefix) [[ $# -gt 1 ]] || die "--test-safe-prefix requires a value"; safe_prefix=$2; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option $1" ;;
  esac
done
[[ -n "$root" && "$root" = /* ]] || die "--root must be an absolute path"
[[ "$root" != *$'\n'* && "$root" != *$'\r'* ]] || die "root contains a newline"
system_root=0
if [[ "$root" = "/" ]]; then
  system_root=1
  [[ "$EUID" -eq 0 ]] || die "--root / requires EUID 0"
  [[ "${OPEN_CARD_ALLOW_SYSTEM_ROOT:-}" = "1" ]] || die "--root / requires OPEN_CARD_ALLOW_SYSTEM_ROOT=1"
  installation_id=/var/lib/open-card/installation-id
  [[ -f "$installation_id" && ! -L "$installation_id" && "$(stat -c '%u:%a' "$installation_id")" = "0:600" ]] || die "--root / requires root-owned installation-id"
  [[ "$confirmation" = "BACKUP:$(cat -- "$installation_id")" ]] || die "--root / requires --confirm-installation-id BACKUP:<installation-id>"
  [[ -z "$safe_prefix" ]] || die "--test-safe-prefix is not valid with --root /"
else
  [[ "$root" != "$HOME" && "$root" != "$HOME"/* ]] || die "refusing HOME or a path below HOME"
fi
if [[ -n "$safe_prefix" ]]; then
  [[ "$safe_prefix" = /* && "$safe_prefix" != "/" ]] || die "safe prefix must be absolute and non-root"
fi
if [[ -n "$reason" ]]; then
  [[ "$reason" =~ ^[A-Za-z0-9._:-]+$ ]] || die "reason contains unsafe characters"
else
  reason=manual
fi
if [[ -n "$release_version" ]]; then
  [[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][A-Za-z0-9.-]+)?$ ]] || die "release version is invalid"
fi
if [[ -n "$migration_version" ]]; then
  [[ "$migration_version" =~ ^[0-9]{4}$ ]] || die "migration version is invalid"
fi
database_url=${OPEN_CARD_DATABASE_URL:-${DATABASE_URL:-}}
if [[ -n "$database_dump_command" ]]; then
  [[ "$database_dump_command" = /* && -x "$database_dump_command" ]] || die "database dump command must be an executable absolute path"
  [[ -n "$database_url" ]] || die "--database-dump-command requires OPEN_CARD_DATABASE_URL or DATABASE_URL"
fi
if [[ -n "$database_url" && -z "$database_dump_command" ]]; then
  die "database URL is configured; --database-dump-command is required for a consistent backup"
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

data_dir="$root_real/var/lib/open-card"
config_dir="$root_real/etc/open-card"
backup_dir="$data_dir/backups"
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
assert_no_symlink_components "$data_dir"
assert_no_symlink_components "$backup_dir"
assert_no_symlink_components "$config_dir"
if (( dry_run )); then
  if [[ -n "$database_url" ]]; then
    echo "open-card backup: would run database dump and archive $data_dir into $backup_dir (reason=$reason)"
  else
    echo "open-card backup: would archive filesystem fixture $data_dir into $backup_dir (reason=$reason)"
  fi
  exit 0
fi
mkdir -p -- "$data_dir" "$backup_dir" "$config_dir"
chmod 0700 "$backup_dir"
if [[ -n "$(find "$data_dir" -path "$backup_dir" -prune -o -type l -print -quit)" ]]; then
  die "control-plane data contains a symlink and cannot be safely archived"
fi
if find "$data_dir" -path "$backup_dir" -prune -o \( -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
  die "control-plane data contains a special file and cannot be safely archived"
fi
if [[ -n "$(find "$config_dir" -type l -print -quit)" ]]; then
  die "control-plane config contains a symlink and cannot be safely archived"
fi
if find "$config_dir" \( -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
  die "control-plane config contains a special file and cannot be safely archived"
fi
if find "$data_dir" -path "$backup_dir" -prune -o -type f \( -perm -002 -o -perm -020 \) -print -quit | grep -q .; then
  die "control-plane data contains a group/world-writable file"
fi
if find "$config_dir" -type f \( -perm -002 -o -perm -020 \) -print -quit | grep -q .; then
  die "control-plane config contains a group/world-writable file"
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_id="backup-${timestamp}-$$"
archive="$backup_dir/$backup_id.tar.gz"
metadata="$backup_dir/$backup_id.json"
staging="$root_real/var/lib/.$backup_id.tmp"
rm -rf -- "$staging"
mkdir -p -- "$staging"
chmod 0700 "$staging"
archive_tree="$staging/archive-tree"
mkdir -p -- "$archive_tree/data" "$archive_tree/config"
chmod 0700 "$archive_tree" "$archive_tree/data" "$archive_tree/config"
trap 'rm -rf -- "$staging"' EXIT
consistency=filesystem-fixture
database_dump_name=
database_dump_digest=
if [[ -n "$database_dump_command" ]]; then
  consistency=pg-dump
  database_dump_name=control-plane.sql
  "$database_dump_command" "$database_url" > "$staging/$database_dump_name" || die "database dump command failed"
  if command -v sha256sum >/dev/null 2>&1; then
    database_dump_digest=$(sha256sum -- "$staging/$database_dump_name" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    database_dump_digest=$(shasum -a 256 -- "$staging/$database_dump_name" | awk '{print $1}')
  else
    die "sha256sum or shasum is required"
  fi
fi
COPYFILE_DISABLE=1 cp -a -- "$data_dir"/. "$archive_tree/data"/
rm -rf -- "$archive_tree/data/backups"
COPYFILE_DISABLE=1 cp -a -- "$config_dir"/. "$archive_tree/config"/
if [[ "$consistency" = pg-dump ]]; then COPYFILE_DISABLE=1 cp -a -- "$staging/$database_dump_name" "$archive_tree/$database_dump_name"; fi
COPYFILE_DISABLE=1 tar -czf "$staging/archive.tar.gz" -C "$archive_tree" .
mv -- "$staging/archive.tar.gz" "$archive"
chmod 0600 "$archive"
if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum -- "$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  digest=$(shasum -a 256 -- "$archive" | awk '{print $1}')
else
  die "sha256sum or shasum is required"
fi
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if stat -c '%s' "$archive" >/dev/null 2>&1; then archive_size=$(stat -c '%s' "$archive"); source_mode=$(stat -c '%a' "$data_dir"); config_mode=$(stat -c '%a' "$config_dir"); else archive_size=$(stat -f '%z' "$archive"); source_mode=$(stat -f '%Lp' "$data_dir"); config_mode=$(stat -f '%Lp' "$config_dir"); fi
file_count=$(find "$data_dir" -path "$backup_dir" -prune -o -type f -print | wc -l | tr -d '[:space:]')
source_digest=$(python3 - "$data_dir" "$backup_dir" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1]); excluded = pathlib.Path(sys.argv[2])
digest = hashlib.sha256()
for path in sorted(root.rglob("*")):
    if path == excluded or excluded in path.parents or not path.is_file():
        continue
    relative = path.relative_to(root).as_posix().encode()
    digest.update(relative + b"\0" + path.read_bytes())
print(digest.hexdigest())
PY
)
config_digest=$(python3 - "$config_dir" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1]); digest = hashlib.sha256()
for path in sorted(root.rglob("*")):
    if not path.is_file(): continue
    digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
print(digest.hexdigest())
PY
)
config_file_count=$(find "$config_dir" -type f -print | wc -l | tr -d '[:space:]')
if [[ -z "$migration_version" ]]; then migration_version=${OPEN_CARD_CURRENT_MIGRATION_VERSION:-}; fi
if [[ -n "$migration_version" ]]; then
  [[ "$migration_version" =~ ^[0-9]{4}$ ]] || die "migration version is invalid"
fi
if [[ -n "$release_version" ]]; then
  cat > "$staging/metadata.json" <<EOF
{
  "schema_version": 1,
  "backup_id": "$backup_id",
  "created_at": "$created_at",
  "source_data_dir": "/var/lib/open-card",
  "source_config_dir": "/etc/open-card",
  "archive": "$(basename -- "$archive")",
  "archive_sha256": "$digest",
  "archive_size": $archive_size,
  "file_count": $file_count,
  "source_mode": $source_mode,
  "config_mode": $config_mode,
  "source_digest": "$source_digest",
  "config_digest": "$config_digest",
  "config_file_count": $config_file_count,
  "archive_layout": "m7-v2",
  "consistency": "$consistency",
  "database_dump": "$database_dump_name",
  "database_dump_sha256": "$database_dump_digest",
  "reason": "$reason",
  "release_version": "$release_version"
}
EOF
else
  cat > "$staging/metadata.json" <<EOF
{
  "schema_version": 1,
  "backup_id": "$backup_id",
  "created_at": "$created_at",
  "source_data_dir": "/var/lib/open-card",
  "source_config_dir": "/etc/open-card",
  "archive": "$(basename -- "$archive")",
  "archive_sha256": "$digest",
  "archive_size": $archive_size,
  "file_count": $file_count,
  "source_mode": $source_mode,
  "config_mode": $config_mode,
  "source_digest": "$source_digest",
  "config_digest": "$config_digest",
  "config_file_count": $config_file_count,
  "archive_layout": "m7-v2",
  "consistency": "$consistency",
  "database_dump": "$database_dump_name",
  "database_dump_sha256": "$database_dump_digest",
  "reason": "$reason"
}
EOF
fi
if [[ -n "$migration_version" ]]; then
  python3 - "$staging/metadata.json" "$migration_version" <<'PY'
import json, sys
path, migration = sys.argv[1:]
value = json.load(open(path, encoding="utf-8")); value["migration_version"] = migration
with open(path, "w", encoding="utf-8") as stream: json.dump(value, stream, indent=2); stream.write("\n")
PY
fi
mv -- "$staging/metadata.json" "$metadata"
chmod 0600 "$metadata"
echo "open-card backup: created $(basename -- "$archive")"
