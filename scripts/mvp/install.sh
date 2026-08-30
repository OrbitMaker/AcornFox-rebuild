#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: install.sh --root TASK_ROOT --bundle BUNDLE [--url URL] [--offline]
                  [--health-command EXECUTABLE] [--migration-command EXECUTABLE]
                  [--migration-dir DIRECTORY] [--allow-downgrade]
                  [--expected-manifest-sha256 HEX]
                  [--test-safe-prefix PATH] [--activate] [--stage-upgrade-substrate]
                  [--validate-activation-intent] [--dry-run]

`--root /` requires root plus either the legacy clean-worker gate or
OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL. System-root and URL installs
also require an externally supplied manifest SHA-256. Installation stages files
by default; --activate is required before service activation.
USAGE
}
die() { echo "open-card install: $*" >&2; exit 1; }
say() { echo "open-card install: $*"; }

root= bundle= bundle_url= health_command= migration_command= migration_dir= expected_manifest_sha256= safe_prefix= required_version=
offline=0 dry_run=0 activate=0 stage_upgrade_substrate=0 validate_activation_intent=0 allow_downgrade=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) [[ $# -gt 1 ]] || die "--root requires a value"; root=$2; shift 2 ;;
    --bundle) [[ $# -gt 1 ]] || die "--bundle requires a value"; bundle=$2; shift 2 ;;
    --url) [[ $# -gt 1 ]] || die "--url requires a value"; bundle_url=$2; shift 2 ;;
    --health-command|--health-cmd) [[ $# -gt 1 ]] || die "$1 requires a value"; health_command=$2; shift 2 ;;
    --migration-command) [[ $# -gt 1 ]] || die "--migration-command requires a value"; migration_command=$2; shift 2 ;;
    --migration-dir) [[ $# -gt 1 ]] || die "--migration-dir requires a value"; migration_dir=$2; shift 2 ;;
    --allow-downgrade) allow_downgrade=1; shift ;;
    --expected-manifest-sha256) [[ $# -gt 1 ]] || die "--expected-manifest-sha256 requires a value"; expected_manifest_sha256=$2; shift 2 ;;
    --require-version) [[ $# -gt 1 ]] || die "--require-version requires a value"; required_version=$2; shift 2 ;;
    --test-safe-prefix) [[ $# -gt 1 ]] || die "--test-safe-prefix requires a value"; safe_prefix=$2; shift 2 ;;
    --activate) activate=1; shift ;;
    --stage-upgrade-substrate) stage_upgrade_substrate=1; shift ;;
    --validate-activation-intent) validate_activation_intent=1; shift ;;
    --offline) offline=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option $1" ;;
  esac
done

[[ -n "$root" ]] || die "--root is required; refusing an empty root"
[[ "$root" = /* ]] || die "--root must be an absolute path"
[[ "$root" != *$'\n'* && "$root" != *$'\r'* ]] || die "root contains a newline"
[[ -z "$bundle_url" || -z "$bundle" ]] || die "use either --bundle or --url"
[[ -n "$bundle_url" || -n "$bundle" ]] || die "--bundle or --url is required"
[[ $offline -eq 0 || -z "$bundle_url" ]] || die "--offline refuses online bundle URLs"
[[ -z "$bundle_url" || "$bundle_url" == https://* ]] || die "online bundle URL must use https://"
if [[ -n "$expected_manifest_sha256" ]]; then
  [[ "$expected_manifest_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || die "expected manifest sha256 must be 64 hexadecimal characters"
  expected_manifest_sha256=$(tr '[:upper:]' '[:lower:]' <<< "$expected_manifest_sha256")
fi
if [[ -n "$required_version" && "$required_version" != "0.8.0-rc.2" ]]; then die "--require-version only accepts the current production candidate"; fi
system_root=0
if [[ "$root" = "/" ]]; then
  system_root=1
  [[ "$EUID" -eq 0 ]] || die "--root / requires EUID 0"
  [[ "${OPEN_CARD_ALLOW_SYSTEM_ROOT:-}" = "1" ]] || die "--root / requires OPEN_CARD_ALLOW_SYSTEM_ROOT=1"
  clean_worker_root=0
  production_root=0
  marker=/etc/opencard-mvp-fa8f8eab-clean-worker
  if [[ "${OPEN_CARD_SYSTEM_ROOT_CONFIRMATION:-}" = "opencard-mvp-fa8f8eab-build-worker-01" && -f "$marker" && ! -L "$marker" && "$(cat -- "$marker")" = "opencard-mvp-fa8f8eab-build-worker-01" ]]; then
    clean_worker_root=1
  elif [[ "${OPEN_CARD_INSTALL_CONFIRMATION:-}" = "OPEN-CARD-INSTALL" ]]; then
    production_root=1
  else
    die "--root / requires clean-worker authorization or OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL"
  fi
  if (( production_root && ! activate && ! dry_run && ! stage_upgrade_substrate )); then
    die "production system-root install requires --activate"
  fi
  if (( production_root )) && [[ "${OPEN_CARD_M6_ENABLED:-false}" = "true" || "${OPEN_CARD_AI_ENABLED:-false}" = "true" ]]; then
    die "production install refuses AI-enabled environment; keep AI disabled by default"
  fi
  [[ -z "$safe_prefix" ]] || die "--test-safe-prefix is not valid with --root /"
  (( clean_worker_root == 0 || ! activate || ! dry_run )) || die "clean-worker --activate cannot be combined with --dry-run"
else
  clean_worker_root=0
  production_root=0
  [[ "$root" != "$HOME" && "$root" != "$HOME"/* ]] || die "refusing HOME or a path below HOME"
  (( ! activate )) || die "--activate requires --root / and clean-worker authorization"
fi
if (( stage_upgrade_substrate )); then
  (( ! activate )) || die "--stage-upgrade-substrate cannot be combined with --activate"
  [[ -z "$health_command" && -z "$migration_command" && -z "$migration_dir" ]] || die "--stage-upgrade-substrate refuses health and migration commands"
  (( ! allow_downgrade )) || die "--stage-upgrade-substrate refuses --allow-downgrade"
fi
if (( validate_activation_intent )); then
  (( dry_run )) || die "--validate-activation-intent requires --dry-run"
  (( ! stage_upgrade_substrate && ! activate )) || die "--validate-activation-intent is a preflight-only flag"
fi
if [[ -n "$safe_prefix" ]]; then
  [[ "$safe_prefix" = /* && "$safe_prefix" != "/" ]] || die "--test-safe-prefix must be absolute and non-root"
fi
if [[ -n "$health_command" ]]; then
  [[ "$health_command" = /* && -x "$health_command" ]] || die "health command must be an executable absolute path"
fi
if [[ -n "$migration_command" ]]; then
  [[ "$migration_command" = /* && -x "$migration_command" ]] || die "migration command must be an executable absolute path"
fi
if [[ -n "$migration_dir" ]]; then
  [[ "$migration_dir" = /* && -d "$migration_dir" && ! -L "$migration_dir" ]] || die "migration directory must be an existing real absolute directory"
fi
if (( system_root )) || [[ -n "$bundle_url" ]]; then
  [[ -n "$expected_manifest_sha256" ]] || die "system-root and URL installs require --expected-manifest-sha256"
fi
if (( allow_downgrade )); then
  [[ "${OPEN_CARD_ALLOW_DOWNGRADE:-}" = "1" ]] || die "--allow-downgrade requires OPEN_CARD_ALLOW_DOWNGRADE=1"
fi
command -v python3 >/dev/null 2>&1 || die "python3 standard library is required for manifest validation"

tmpdir=${TMPDIR:-/tmp}
root_parent=$(dirname -- "$root")
if [[ ! -d "$root_parent" && $dry_run -eq 0 ]]; then mkdir -p -- "$root_parent"; fi
root_parent=$(cd -- "$root_parent" 2>/dev/null && pwd -P) || die "cannot resolve root parent"
root_base=$(basename -- "$root")
if [[ -e "$root" || -L "$root" ]]; then
  [[ ! -L "$root" ]] || die "refusing symlink staging root: $root"
  root_real=$(cd -- "$root" && pwd -P) || die "cannot resolve root"
else
  root_real="$root_parent/$root_base"
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
if [[ -n "$bundle_url" && -n "$bundle" ]]; then die "use either --bundle or --url"; fi
if (( ! dry_run )); then mkdir -p -- "$root"; fi

prefix="$root_real/opt/open-card"
config_dir="$root_real/etc/open-card"
data_dir="$root_real/var/lib/open-card"
releases="$prefix/releases"
current="$prefix/current"
previous="$prefix/previous"
backups="$data_dir/backups"
evidence="$data_dir/evidence"
systemd_dir="$root_real/etc/systemd/system"
upgrade_tools="$prefix/upgrade-tools"
upgrade_lock_dir="$root_real/run/lock"
upgrade_lock="$upgrade_lock_dir/open-card-upgrade.lock"

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
for path in "$prefix" "$config_dir" "$data_dir" "$systemd_dir"; do
  assert_no_symlink_components "$path"
done
if [[ -f "$data_dir/recovery-required.json" && ! -L "$data_dir/recovery-required.json" ]]; then
  die "previous upgrade left recovery-required state; resolve it before installing another release"
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- "$1" | awk '{print $1}'
  else die "sha256sum or shasum is required"; fi
}
safe_rel() {
  local value=$1 part
  [[ -n "$value" && "$value" != /* && "$value" != *'\'* && "$value" != */./* && "$value" != */../* && "$value" != ../* && "$value" != */.. && "$value" != "." && "$value" != ".." ]] || return 1
  IFS=/ read -ra parts <<< "$value"
  for part in "${parts[@]}"; do [[ -n "$part" && "$part" != "." && "$part" != ".." ]] || return 1; done
}
atomic_replace() {
  python3 - "$1" "$2" <<'PY'
import os, sys
os.replace(sys.argv[1], sys.argv[2])
PY
}
durable_sync_file_and_parent() {
  local path=$1
  if (( ! system_root )) && [[ "${OPEN_CARD_INSTALL_TEST_FAIL_DURABLE_SYNC:-}" = "1" ]]; then
    return 1
  fi
  python3 - "$path" <<'PY'
import os, stat, sys
path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise OSError("durable target is not regular")
    os.fsync(fd)
finally:
    os.close(fd)
parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
parent = os.open(os.path.dirname(path), parent_flags)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}
durable_sync_directory_and_parent() {
  local path=$1
  if (( ! system_root )) && [[ "${OPEN_CARD_INSTALL_TEST_FAIL_DURABLE_SYNC:-}" = "1" ]]; then
    return 1
  fi
  python3 - "$path" <<'PY'
import os, stat, sys
path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        raise OSError("durable target is not a directory")
    os.fsync(fd)
finally:
    os.close(fd)
parent = os.open(os.path.dirname(path), flags)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}
file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then stat -c '%a' "$1"; else stat -f '%Lp' "$1"; fi
}
file_owner() {
  if stat -c '%u' "$1" >/dev/null 2>&1; then stat -c '%u' "$1"; else stat -f '%u' "$1"; fi
}
require_stable_directory() {
  local path=$1 expected_owner=$2 expected_mode=$3 actual_mode actual_owner
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    mkdir -p -- "$path"
    chmod "$expected_mode" "$path" || die "could not set stable path mode: $path"
  fi
  [[ -d "$path" && ! -L "$path" ]] || die "stable path is not a real directory: $path"
  actual_mode=$(file_mode "$path")
  actual_owner=$(file_owner "$path")
  [[ "$actual_owner" = "$expected_owner" ]] || die "stable path owner mismatch: $path"
  [[ "$actual_mode" = "$expected_mode" ]] || die "stable path mode mismatch: $path"
  (( (8#$actual_mode & 8#022) == 0 )) || die "stable path is writable by group or others: $path"
}
require_stable_file() {
  local path=$1 expected_owner=$2 expected_mode=$3 actual_mode actual_owner
  [[ -f "$path" && ! -L "$path" ]] || die "stable file is missing or unsafe: $path"
  actual_mode=$(file_mode "$path")
  actual_owner=$(file_owner "$path")
  [[ "$actual_owner" = "$expected_owner" ]] || die "stable file owner mismatch: $path"
  [[ "$actual_mode" = "$expected_mode" ]] || die "stable file mode mismatch: $path"
}
install_stable_file() {
  local source=$1 destination=$2 expected_owner=$3 expected_mode=$4 label=$5 parent base temporary source_digest destination_digest
  parent=$(dirname -- "$destination")
  base=$(basename -- "$destination")
  [[ -f "$source" && ! -L "$source" ]] || die "$label source is missing or unsafe"
  require_stable_file "$source" "$expected_owner" "$expected_mode"
  require_stable_directory "$parent" "$expected_owner" 755
  source_digest=$(sha256_file "$source")
  if [[ -e "$destination" || -L "$destination" ]]; then
    require_stable_file "$destination" "$expected_owner" "$expected_mode"
    destination_digest=$(sha256_file "$destination")
    [[ "$destination_digest" = "$source_digest" ]] || die "$label conflicts with an existing stable file"
    durable_sync_file_and_parent "$destination" || die "$label durability outcome is unknown"
    return
  fi
  temporary=$(mktemp "$parent/.${base}.next.XXXXXX")
  if ! cp -- "$source" "$temporary"; then rm -f -- "$temporary"; die "could not stage $label"; fi
  chmod "$expected_mode" "$temporary" || { rm -f -- "$temporary"; die "could not set $label mode"; }
  require_stable_file "$temporary" "$expected_owner" "$expected_mode"
  if ! ln -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    require_stable_file "$destination" "$expected_owner" "$expected_mode"
    destination_digest=$(sha256_file "$destination")
    [[ "$destination_digest" = "$source_digest" ]] || die "$label conflicts with an existing stable file"
    durable_sync_file_and_parent "$destination" || die "$label durability outcome is unknown"
    return
  fi
  rm -f -- "$temporary"
  require_stable_file "$destination" "$expected_owner" "$expected_mode"
  destination_digest=$(sha256_file "$destination")
  [[ "$destination_digest" = "$source_digest" ]] || die "$label verification failed"
  durable_sync_file_and_parent "$destination" || die "$label durability outcome is unknown"
}
prepare_upgrade_lock() {
  local expected_owner=$1 temporary run_dir actual_owner actual_mode
  assert_no_symlink_components "$upgrade_lock_dir"
  run_dir=$(dirname -- "$upgrade_lock_dir")
  require_stable_directory "$run_dir" "$expected_owner" 755
  if (( system_root )); then
    [[ -d "$upgrade_lock_dir" && ! -L "$upgrade_lock_dir" ]] || die "system lock path is not a real directory"
    actual_owner=$(file_owner "$upgrade_lock_dir")
    actual_mode=$(file_mode "$upgrade_lock_dir")
    [[ "$actual_owner" = "$expected_owner" && "$actual_mode" = "1777" ]] || die "system lock path must be root-owned mode 1777"
  else
    require_stable_directory "$upgrade_lock_dir" "$expected_owner" 755
  fi
  if [[ -e "$upgrade_lock" || -L "$upgrade_lock" ]]; then
    require_stable_file "$upgrade_lock" "$expected_owner" 600
    durable_sync_file_and_parent "$upgrade_lock" || die "upgrade lock durability outcome is unknown"
    return
  fi
  temporary=$(mktemp "$upgrade_lock_dir/.open-card-upgrade.lock.next.XXXXXX")
  chmod 600 "$temporary" || { rm -f -- "$temporary"; die "could not set upgrade lock mode"; }
  require_stable_file "$temporary" "$expected_owner" 600
  if ! ln -- "$temporary" "$upgrade_lock"; then
    rm -f -- "$temporary"
    require_stable_file "$upgrade_lock" "$expected_owner" 600
    durable_sync_file_and_parent "$upgrade_lock" || die "upgrade lock durability outcome is unknown"
    return
  fi
  rm -f -- "$temporary"
  require_stable_file "$upgrade_lock" "$expected_owner" 600
  durable_sync_file_and_parent "$upgrade_lock" || die "upgrade lock durability outcome is unknown"
}
prepare_upgrade_layout_directory() {
  local path=$1 expected_owner=$2 expected_mode=$3 actual_owner actual_mode
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    mkdir -p -- "$path"
  fi
  [[ -d "$path" && ! -L "$path" ]] || die "upgrade layout path is not a real directory: $path"
  actual_owner=$(file_owner "$path")
  actual_mode=$(file_mode "$path")
  (( (8#$actual_mode & 8#022) == 0 )) || die "upgrade layout path is writable by group or others: $path"
  if [[ "$actual_owner" != "$expected_owner" ]]; then
    if (( system_root && EUID == 0 && expected_owner == 0 )); then
      chown 0:0 "$path" || die "could not normalize upgrade layout owner: $path"
    else
      die "upgrade layout owner mismatch: $path"
    fi
  fi
  chmod "$expected_mode" "$path" || die "could not normalize upgrade layout mode: $path"
  require_stable_directory "$path" "$expected_owner" "$expected_mode"
  durable_sync_directory_and_parent "$path" || die "upgrade layout durability outcome is unknown"
}
data_root_fault() {
  local phase=$1
  (( ! system_root )) && [[ -n "$safe_prefix" && "${OPEN_CARD_INSTALL_TEST_DATA_ROOT_FAULT:-}" = "$phase" ]]
}
data_root_force_transition() {
  (( ! system_root )) && [[ -n "$safe_prefix" && "${OPEN_CARD_INSTALL_TEST_DATA_ROOT_FORCE_TRANSITION:-}" = "1" ]]
}
prepare_upgrade_data_root() {
  local expected_owner=$1 actual_owner actual_mode
  if [[ ! -e "$data_dir" && ! -L "$data_dir" ]]; then
    mkdir -p -- "$data_dir"
  fi
  [[ -d "$data_dir" && ! -L "$data_dir" ]] || die "upgrade data root is not a real directory"
  actual_owner=$(file_owner "$data_dir")
  actual_mode=$(file_mode "$data_dir")
  (( (8#$actual_mode & 8#022) == 0 )) || die "upgrade data root is writable by group or others"
  data_root_fault before-chmod && die "upgrade data root fault before chmod"
  chmod 711 "$data_dir" || die "could not normalize upgrade data root mode"
  [[ "$(file_mode "$data_dir")" = "711" && "$(file_owner "$data_dir")" = "$actual_owner" ]] || die "upgrade data root mode verification failed"
  durable_sync_directory_and_parent "$data_dir" || die "upgrade data root durability outcome is unknown"
  data_root_fault after-chmod-before-chown && die "upgrade data root fault after chmod before chown"
  data_root_fault chown && die "upgrade data root fault before chown"
  if [[ "$actual_owner" != "$expected_owner" ]] || data_root_force_transition; then
    if (( system_root && EUID == 0 && expected_owner == 0 )); then
      chown 0:0 "$data_dir" || die "could not normalize upgrade data root owner"
    elif data_root_force_transition; then
      chown "$expected_owner" "$data_dir" || die "could not verify upgrade data root owner transition"
    else
      die "upgrade data root owner mismatch"
    fi
  fi
  [[ "$(file_mode "$data_dir")" = "711" && "$(file_owner "$data_dir")" = "$expected_owner" ]] || die "upgrade data root ownership verification failed"
  data_root_fault post-chown-sync && die "upgrade data root fault before post-chown sync"
  durable_sync_directory_and_parent "$data_dir" || die "upgrade data root post-chown durability outcome is unknown"
}
prepare_upgrade_substrate() {
  local expected_owner=$1
  prepare_upgrade_data_root "$expected_owner"
  prepare_upgrade_layout_directory "$prefix/activations" "$expected_owner" 711
  prepare_upgrade_layout_directory "$data_dir/backups" "$expected_owner" 700
  prepare_upgrade_layout_directory "$data_dir/upgrade-transactions" "$expected_owner" 700
  prepare_upgrade_layout_directory "$data_dir/upgrade-artifacts" "$expected_owner" 711
  install_stable_file "$release_dir/bin/open-card-upgrade" "$upgrade_tools/open-card-upgrade" "$expected_owner" 755 "upgrade recovery binary"
  require_stable_directory "$systemd_dir" "$expected_owner" 755
  install_stable_file "$release_dir/systemd/open-card-upgrade-recover.service" "$systemd_dir/open-card-upgrade-recover.service" "$expected_owner" 644 "upgrade recovery unit"
  install_stable_file "$release_dir/systemd/open-card-upgrade-safe.target" "$systemd_dir/open-card-upgrade-safe.target" "$expected_owner" 644 "upgrade safe target"
  install_stable_file "$release_dir/systemd/open-card-upgrade-finalize.service" "$systemd_dir/open-card-upgrade-finalize.service" "$expected_owner" 644 "upgrade finalizer unit"
  install_stable_file "$release_dir/systemd/open-card-edge.service.d/10-upgrade-marker.conf" "$systemd_dir/open-card-edge.service.d/10-upgrade-marker.conf" "$expected_owner" 644 "upgrade Edge marker drop-in"
  prepare_upgrade_lock "$expected_owner"
}

bundle_tmp=
cleanup() { [[ -z "$bundle_tmp" || ! -d "$bundle_tmp" ]] || rm -rf -- "$bundle_tmp"; }
trap cleanup EXIT
if [[ -n "$bundle_url" ]]; then
  command -v curl >/dev/null 2>&1 || die "curl is required for online bundle retrieval"
  bundle_tmp=$(mktemp -d "$tmpdir/open-card-g7-bundle.XXXXXX")
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$bundle_tmp/bundle.tar.gz" -- "$bundle_url" || die "bundle download failed"
  bundle="$bundle_tmp/bundle.tar.gz"
fi
if [[ -d "$bundle" ]]; then
  bundle_dir=$(cd -- "$bundle" && pwd -P) || die "cannot resolve bundle directory"
else
  [[ -f "$bundle" ]] || die "bundle not found: $bundle"
  bundle_tmp=${bundle_tmp:-$(mktemp -d "$tmpdir/open-card-g7-bundle.XXXXXX")}
  python3 - "$bundle" "$bundle_tmp" <<'PY' || die "bundle archive validation or extraction failed"
import pathlib, sys, tarfile
archive_path, target = sys.argv[1:]
with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    if len(members) > 10_000 or sum(member.size for member in members) > 1_073_741_824:
        raise SystemExit("bundle archive exceeds file-count or size limit")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isreg()):
            raise SystemExit(f"unsafe bundle archive entry: {member.name}")
    archive.extractall(target, filter="fully_trusted")
PY
  if [[ -f "$bundle_tmp/manifest.json" ]]; then bundle_dir="$bundle_tmp"
  else
    bundle_dir=$(dirname -- "$(find "$bundle_tmp" -mindepth 2 -maxdepth 2 -name manifest.json -print -quit)")
    [[ -f "$bundle_dir/manifest.json" ]] || die "archive must contain manifest.json at its root"
  fi
fi

manifest="$bundle_dir/manifest.json"
[[ -f "$manifest" ]] || die "bundle manifest.json is missing"
if [[ -n "$expected_manifest_sha256" ]]; then
  actual_manifest_sha256=$(sha256_file "$manifest")
  [[ "$actual_manifest_sha256" = "$expected_manifest_sha256" ]] || die "expected manifest sha256 mismatch; payload was not trusted"
fi
host_arch=$(uname -m 2>/dev/null || true)
case "$host_arch" in
  x86_64|amd64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
  *) die "unsupported runtime architecture: ${host_arch:-unknown}" ;;
esac
manifest_info=$(python3 - "$manifest" "$bundle_dir" "$host_arch" "$required_version" <<'PY'
import json, os, re, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
required = {"schema_version","product","version","release_id","protocol","config_dir","data_dir","compatibility","files"}
optional = {"architecture", "migration_version", "source_commit", "n_minus_one"}
if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
    raise SystemExit("manifest fields are invalid")
if value["schema_version"] != 1 or value["product"] != "open-card":
    raise SystemExit("unsupported manifest schema or product")
if not isinstance(value["version"], str) or not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value["version"]):
    raise SystemExit("manifest version is invalid")
if sys.argv[4] and value["version"] != sys.argv[4]:
    raise SystemExit("manifest version is not the required production candidate")
def normalize_protocol(raw):
    raw = raw.strip().lower()
    if raw == "v1":
        return "1.0"
    if not re.fullmatch(r"1\.(?:0|1)", raw):
        raise SystemExit("manifest Agent protocol must be 1.0 or 1.1")
    return raw
if not isinstance(value["release_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value["release_id"]):
    raise SystemExit("manifest release_id is unsafe")
architecture = value.get("architecture", "")
if architecture:
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(str(architecture).strip().lower(), "")
    if not architecture:
        raise SystemExit("manifest architecture is unsupported")
    runtime_arch = sys.argv[3]
    if architecture != runtime_arch:
        raise SystemExit(f"release architecture {architecture} is incompatible with runtime {runtime_arch}")
migration_version = value.get("migration_version", "")
if migration_version and (not isinstance(migration_version, str) or not re.fullmatch(r"[0-9]{4}", migration_version)):
    raise SystemExit("manifest migration version is invalid")
if value["config_dir"] != "/etc/open-card" or value["data_dir"] != "/var/lib/open-card":
    raise SystemExit("manifest directory contract mismatch")
compat = value["compatibility"]
compat_required = {"min_data_version","max_data_version","min_agent_protocol","max_agent_protocol"}
if not isinstance(compat, dict) or not compat_required <= set(compat) or set(compat) - compat_required - {"requires_data_backup"}:
    raise SystemExit("manifest compatibility is invalid")
if not isinstance(compat["min_data_version"], int) or not isinstance(compat["max_data_version"], int) or compat["min_data_version"] > compat["max_data_version"]:
    raise SystemExit("manifest data compatibility range is invalid")
protocol = normalize_protocol(value["protocol"])
minimum_protocol = normalize_protocol(compat["min_agent_protocol"])
maximum_protocol = normalize_protocol(compat["max_agent_protocol"])
if tuple(map(int, minimum_protocol.split("."))) > tuple(map(int, maximum_protocol.split("."))):
    raise SystemExit("manifest Agent protocol compatibility range is invalid")
files = value["files"]
if not isinstance(files, list) or not files:
    raise SystemExit("manifest files are empty")
if value["version"] in {"0.8.0-rc.1", "0.8.0-rc.2"}:
    candidate_version = value["version"]
    if migration_version != "0024" or not isinstance(value.get("source_commit"), str) or not re.fullmatch(r"[a-f0-9]{40}", value["source_commit"]):
        raise SystemExit(candidate_version + " production candidate must declare source and migration 0024")
    if candidate_version == "0.8.0-rc.1":
        lineage_by_architecture = {
            "amd64": ("3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253", "abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc", "960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392"),
            "arm64": ("e4f56105b3d184313d51365c7fff40b9f68111815def83c5e5985bc182177a57", "9560df1d4a739c729d857cd93b989b99976da0e86983ffa026d13202339d57b9", "fdfd6b6108870118714b70c9007937585fc0429d14fa9d64010a80016edc2a15"),
        }
        predecessor = ("0.8.0-rc.0", "0023", "35a2b198ac52949af3477475d89d4813b46a9490")
    else:
        lineage_by_architecture = {
            "amd64": ("1cf02e4a111e38a4061c692de418b67755a2e55f97a04cbc92cee8cb9f82a7be", "9056cb46537537f6cab21482d900160486098d857955d23b0ca8f131a9cc4233", "d0e8c111dcaa334c89bb815fc2ddc9b122887cddbbf7c59b6eb51436b931706f"),
            "arm64": ("6bf1e590c3054d373d9319f03581d7a623ee3093b53ddba7b343cf8af7f85fed", "56a697aed3a8f77261cfeb3074a7d7ab0cfb6389ab5d75225ad9931b665bfa86", "5fda1e9d0f80deadf6b87cb281d80793c9d1e910386624bc5975cdd0464a2650"),
        }
        predecessor = ("0.8.0-rc.1", "0024", "0d5c96bf7b7bd1c641b108cbbd54511d814f2aa0")
    if architecture not in lineage_by_architecture:
        raise SystemExit(candidate_version + " production candidate requires a supported architecture")
    manifest_sha256, archive_sha256, bundle_manifest_sha256 = lineage_by_architecture[architecture]
    expected_n_minus_one = {"version":predecessor[0],"migration_version":predecessor[1],"source_commit":predecessor[2],"release_manifest_sha256":manifest_sha256,"archive_sha256":archive_sha256,"bundle_manifest_sha256":bundle_manifest_sha256}
    if value.get("n_minus_one") != expected_n_minus_one:
        raise SystemExit(candidate_version + " production candidate has invalid N-1 lineage")
    production_required = {
        "bin/open-card-admin", "bin/open-card-upgrade",
        "systemd/open-card-edge.service", "systemd/open-card-upgrade-recover.service",
        "systemd/open-card-upgrade-safe.target", "systemd/open-card-upgrade-finalize.service",
        "systemd/open-card-edge.service.d/10-upgrade-marker.conf",
        "caddy/open-card-edge.Caddyfile.example",
        "migrations/control-plane/0024_dns_change_ledger.sql", "web/dist/index.html",
        "docs/licenses/licenses-manifest.json", "sbom.spdx.json", "source-manifest.sha256",
    }
    if candidate_version == "0.8.0-rc.2":
        production_required |= {"scripts/mvp/g6-staging-evidence.sh", "scripts/mvp/host-preflight.sh", "scripts/mvp/buildkit-production-capacity.sh", "tools/evidence/g6_validate.py", "tools/evidence/g6_target_receipt.py"}
    candidate_paths = {item.get("path") for item in files if isinstance(item, dict)}
    missing = sorted(production_required - candidate_paths)
    if missing:
        raise SystemExit(candidate_version + " production manifest is missing " + ", ".join(missing))
    forbidden = sorted(path for path in candidate_paths if isinstance(path, str) and ("fixture" in path.lower() or "/tests/" in "/" + path or path.endswith(".test") or "open-card-caddy-fixture" in path))
    if forbidden:
        raise SystemExit(candidate_version + " production manifest contains test-only payload")
elif value["version"] == "0.8.0-rc.0":
    if migration_version != "0023" or value.get("source_commit") != "35a2b198ac52949af3477475d89d4813b46a9490" or "n_minus_one" in value:
        raise SystemExit("0.8.0-rc.0 bootstrap lineage is invalid")
elif "source_commit" in value or "n_minus_one" in value:
    raise SystemExit("historical manifest must not carry production lineage")
seen = set()
print(value["version"]); print(value["release_id"]); print(protocol)
print(compat["min_data_version"]); print(compat["max_data_version"])
print(minimum_protocol); print(maximum_protocol)
for item in files:
    if not isinstance(item, dict) or not {"path", "sha256", "mode"} <= set(item) or set(item) - {"path", "sha256", "mode"}:
        raise SystemExit("manifest file entry is invalid")
    item_path, digest = item["path"], item["sha256"]
    if not isinstance(item_path, str) or not item_path or item_path.startswith("/") or "\\" in item_path or any(part in ("", ".", "..") for part in item_path.split("/")):
        raise SystemExit("manifest file path is unsafe")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("manifest file checksum is invalid")
    mode = item["mode"]
    if not isinstance(mode, int) or mode <= 0 or mode > 0o777 or mode & 0o022:
        raise SystemExit("manifest file mode is unsafe")
    if item_path in seen: raise SystemExit("manifest contains duplicate file")
    seen.add(item_path); print("F\t" + item_path + "\t" + digest + "\t" + format(mode, "o"))
actual = set()
for directory, directories, names in os.walk(sys.argv[2], followlinks=False):
    for name in names:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, sys.argv[2]).replace(os.sep, "/")
        if relative != "manifest.json":
            actual.add(relative)
if actual != seen:
    missing = sorted(seen - actual)
    extra = sorted(actual - seen)
    raise SystemExit(f"manifest file set mismatch missing={missing} extra={extra}")
PY
) || die "manifest validation failed"
version=$(sed -n '1p' <<< "$manifest_info")
release_id=$(sed -n '2p' <<< "$manifest_info")
release_name="$release_id"
release_dir="$releases/$release_name"
installation_id="$data_dir/installation-id"
if (( stage_upgrade_substrate )) && [[ "$version" != "0.8.0-rc.1" && "$version" != "0.8.0-rc.2" ]]; then
  die "--stage-upgrade-substrate requires an RC1 or RC2 production candidate"
fi
if (( validate_activation_intent )) && [[ "$version" = "0.8.0-rc.1" || "$version" = "0.8.0-rc.2" ]]; then
  die "$version system-root activation requires native bootstrap activation support"
fi
if (( system_root && ! stage_upgrade_substrate )); then
  if [[ -e "$current" || -L "$current" || -e "$installation_id" || -L "$installation_id" ]]; then
    die "existing production installation requires upgrade.sh or --stage-upgrade-substrate"
  fi
  if [[ ( "$version" = "0.8.0-rc.1" || "$version" = "0.8.0-rc.2" ) && $activate -eq 1 ]]; then
    die "$version system-root activation requires native bootstrap activation support"
  fi
fi
manifest_migration_version=$(python3 - "$manifest" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value.get("migration_version", ""))
PY
)
current_migration_version=
if [[ -f "$data_dir/migration.version" && ! -L "$data_dir/migration.version" ]]; then
  current_migration_version=$(tr -d '[:space:]' < "$data_dir/migration.version")
  [[ -z "$current_migration_version" || "$current_migration_version" =~ ^[0-9]{4}$ ]] || die "control-plane migration.version is invalid"
elif [[ -f "$data_dir/schema.version" && ! -L "$data_dir/schema.version" ]]; then
  persisted_schema_version=$(tr -d '[:space:]' < "$data_dir/schema.version")
  if [[ "$persisted_schema_version" =~ ^[0-9]+$ && "$persisted_schema_version" -ge 10 ]]; then
    printf -v current_migration_version '%04d' "$persisted_schema_version"
  fi
fi
if [[ -n "$migration_dir" ]]; then
  latest_migration=$(python3 - "$migration_dir" <<'PY'
import pathlib, re, sys
directory = pathlib.Path(sys.argv[1])
versions = []
for path in directory.iterdir():
    if path.is_dir() or path.suffix != ".sql":
        continue
    match = re.fullmatch(r"([0-9]{4})_[a-z0-9_]+\.sql", path.name)
    if not match:
        raise SystemExit(f"invalid migration filename: {path.name}")
    versions.append(match.group(1))
if not versions:
    raise SystemExit("migration directory contains no SQL migrations")
print(max(versions))
PY
) || die "migration directory validation failed"
  expected_migration=${manifest_migration_version:-0024}
  [[ "$latest_migration" = "$expected_migration" ]] || die "migration directory does not match candidate migration $expected_migration (got $latest_migration)"
fi

verify_release() {
  local target=$1 marker path digest mode actual actual_mode target_file
  python3 - "$target" "$manifest" <<'PY' || die "release file set does not match manifest"
import json, os, sys
target, manifest_path = sys.argv[1:]
manifest = json.load(open(manifest_path, encoding="utf-8"))
expected = {item["path"] for item in manifest["files"]}
actual = set()
for directory, directories, names in os.walk(target, followlinks=False):
    for name in names:
        relative = os.path.relpath(os.path.join(directory, name), target).replace(os.sep, "/")
        if relative != "manifest.json":
            actual.add(relative)
if actual != expected:
    raise SystemExit(1)
PY
  while IFS=$'\t' read -r marker path digest mode; do
    [[ "$marker" = F ]] || continue
    safe_rel "$path" || die "unsafe release path $path"
    target_file="$target/$path"
    [[ ! -L "$target_file" && -f "$target_file" ]] || die "release file missing or symlink: $path"
    actual=$(sha256_file "$target_file")
    [[ "$actual" = "$digest" ]] || die "checksum mismatch for $path (got $actual, want $digest)"
    if [[ -n "$mode" ]]; then
      if stat -c '%a' "$target_file" >/dev/null 2>&1; then actual_mode=$(stat -c '%a' "$target_file")
      else actual_mode=$(stat -f '%Lp' "$target_file"); fi
      [[ "$actual_mode" = "$mode" ]] || die "mode mismatch for $path (got $actual_mode, want $mode)"
    fi
  done < <(sed -n '8,$p' <<< "$manifest_info")
}

if [[ -d "$release_dir" ]]; then
  [[ ! -L "$release_dir" && -f "$release_dir/manifest.json" ]] || die "existing release is unsafe"
  verify_release "$release_dir"
else
  [[ ! -e "$release_dir" ]] || die "release path is not a directory"
  if (( dry_run )); then
    [[ -z "$(find "$bundle_dir" -type l -print -quit)" ]] || die "bundle contains symlinks"
    verify_release "$bundle_dir"
    say "would create release $release_name"
  else
    if (( stage_upgrade_substrate )); then
      mkdir -p -- "$releases" "$data_dir"
    else
      mkdir -p -- "$releases" "$config_dir" "$data_dir" "$backups" "$evidence"
    fi
    assert_no_symlink_components "$releases"
    stage_dir=$(mktemp -d "$releases/.staging-$release_name.XXXXXX")
    chmod 0755 "$stage_dir"
    cp -a -- "$bundle_dir"/. "$stage_dir"/
    [[ -z "$(find "$stage_dir" -type l -print -quit)" ]] || die "bundle contains symlinks"
    verify_release "$stage_dir"
    mv -- "$stage_dir" "$release_dir"
  fi
fi
if (( ! dry_run )); then
  if (( system_root )); then
    chown root:root "$prefix" "$releases" "$release_dir"
  fi
  chmod 0755 "$prefix" "$releases" "$release_dir"
fi

if (( stage_upgrade_substrate )); then
  if (( dry_run )); then
    say "would stage verified upgrade recovery substrate for $release_name"
    exit 0
  fi
  expected_owner=$(id -u)
  prepare_upgrade_substrate "$expected_owner"
  if (( system_root )); then
    command -v systemctl >/dev/null 2>&1 || die "systemctl is required for system-root upgrade substrate staging"
    systemctl daemon-reload
  fi
  # The recovery unit stays disabled until the E/F boot-safe activation gate
  # owns CLI enablement and crash/reboot evidence. Staging must not start it.
  say "staged verified upgrade recovery substrate for $release_name"
  exit 0
fi

if (( ! dry_run )); then
  mkdir -p -- "$config_dir" "$backups" "$evidence"
  if (( system_root )); then
    chown root:root "$backups" "$evidence"
    chmod 0700 "$backups" "$evidence"
    chown root:root "$config_dir"
    chmod 0711 "$config_dir"
  else
    chmod 0750 "$backups" "$evidence"
    chmod 0750 "$config_dir"
  fi
  if [[ "$version" = "0.8.0-rc.1" || "$version" = "0.8.0-rc.2" ]]; then
    expected_owner=$(id -u)
    prepare_upgrade_substrate "$expected_owner"
  else
    mkdir -p -- "$data_dir"
    chmod 0750 "$data_dir"
    mkdir -p -- "$systemd_dir"
  fi
  units=(open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service)
  if [[ -f "$bundle_dir/systemd/open-card-edge.service" && ! -L "$bundle_dir/systemd/open-card-edge.service" ]]; then
    units+=(open-card-edge.service)
  elif [[ "$version" = "0.8.0-rc.1" || "$version" = "0.8.0-rc.2" ]]; then
    die "$version production candidate is missing open-card-edge.service"
  fi
  for unit in "${units[@]}"; do
    [[ -f "$bundle_dir/systemd/$unit" && ! -L "$bundle_dir/systemd/$unit" ]] || die "bundle is missing $unit"
    cp -f -- "$bundle_dir/systemd/$unit" "$systemd_dir/$unit"
    chmod 0644 "$systemd_dir/$unit"
  done
fi

old_release=
if [[ -L "$current" ]]; then
  target=$(readlink -- "$current")
  [[ "$target" = releases/* ]] || die "current pointer escapes releases: $target"
  old_release=${target#releases/}
  safe_rel "$old_release" || die "current pointer target is unsafe"
elif [[ -e "$current" ]]; then
  die "current pointer is not a symlink"
fi
if [[ -n "$old_release" ]]; then
  data_version=1
  if [[ -f "$data_dir/schema.version" ]]; then
    data_version=$(tr -d '[:space:]' < "$data_dir/schema.version")
  fi
  [[ "$data_version" =~ ^[0-9]+$ ]] || die "control-plane schema.version is invalid"
  python3 - "$current/manifest.json" "$manifest" "$data_version" "$allow_downgrade" "$current_migration_version" <<'PY' || die "candidate release is not semantically compatible"
import json, re, sys
current_path, candidate_path, data_version, allow_downgrade = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
current = json.load(open(current_path, encoding="utf-8"))
candidate = json.load(open(candidate_path, encoding="utf-8"))
def semver_major(value):
    match = re.fullmatch(r"(\d+)\.\d+\.\d+(?:[-+].*)?", value)
    if not match:
        raise SystemExit("invalid semantic version")
    return int(match.group(1))
def semver(value):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", value)
    if not match:
        raise SystemExit("invalid semantic version")
    return tuple(map(int, match.groups()))
if current.get("product") != candidate.get("product"):
    raise SystemExit("product changed")
if semver_major(current["version"]) != semver_major(candidate["version"]):
    raise SystemExit("major version transition is not compatible")
if semver(candidate["version"]) < semver(current["version"]) and not allow_downgrade:
    raise SystemExit("release downgrade requires explicit authorization")
compat = candidate["compatibility"]
if not compat["min_data_version"] <= data_version <= compat["max_data_version"]:
    raise SystemExit("control-plane data version is outside candidate range")
def protocol_number(value):
    value = value.strip().lower()
    if value == "v1": value = "1.0"
    match = re.fullmatch(r"1\.(0|1)", value)
    if not match: raise SystemExit("invalid agent protocol")
    return int(value.split(".")[1])
current_protocol = protocol_number(current.get("protocol", ""))
minimum = protocol_number(compat["min_agent_protocol"])
maximum = protocol_number(compat["max_agent_protocol"])
if not minimum <= current_protocol <= maximum:
    raise SystemExit("agent protocol is outside candidate range")
current_migration = sys.argv[5] if len(sys.argv) > 5 else ""
candidate_migration = candidate.get("migration_version", "")
if current_migration and candidate_migration and int(candidate_migration) < int(current_migration) and not allow_downgrade:
    raise SystemExit("migration downgrade requires explicit authorization")
PY
fi
if [[ "$old_release" = "$release_name" ]]; then
  say "release $version is already active; install is idempotent"
  exit 0
fi
if (( dry_run )); then
  say "would atomically switch current from ${old_release:-none} to $release_name"
  [[ -z "$health_command" ]] || say "would run health command $health_command"
  [[ -z "$migration_command" ]] || say "would run migration command $migration_command (required current migration 0024)"
  exit 0
fi

if [[ -n "$migration_command" ]]; then
  required_migration_version=${manifest_migration_version:-0024}
  if [[ -n "$migration_dir" ]]; then
    migration_output=$(OPEN_CARD_RELEASE_DIR="$release_dir" OPEN_CARD_CONFIG_DIR="$config_dir" OPEN_CARD_DATA_DIR="$data_dir" OPEN_CARD_REQUIRED_MIGRATION_VERSION="$required_migration_version" "$migration_command" "$migration_dir" 2>&1) || die "migration failed; current pointer was not changed: $migration_output"
  else
    migration_output=$(OPEN_CARD_RELEASE_DIR="$release_dir" OPEN_CARD_CONFIG_DIR="$config_dir" OPEN_CARD_DATA_DIR="$data_dir" OPEN_CARD_REQUIRED_MIGRATION_VERSION="$required_migration_version" "$migration_command" 2>&1) || die "migration failed; current pointer was not changed: $migration_output"
  fi
  latest_migration=$(sed -nE 's/^([0-9]{4})_.*/\1/p' <<< "$migration_output" | tail -n 1)
  if [[ -z "$latest_migration" ]]; then
    latest_migration=$(sed -nE 's/.*latest_migration=([0-9]{4}).*/\1/p' <<< "$migration_output" | tail -n 1)
  fi
  [[ -z "$latest_migration" || "$latest_migration" = "$required_migration_version" ]] || die "migration command did not reach candidate migration $required_migration_version"
fi

pointer_switched=0
rollback_install() {
  local status=$?
  if (( status != 0 && pointer_switched == 1 )); then
    set +e
    say "installation verification failed; rolling back release pointer"
    [[ -z "${migration_state_tmp:-}" ]] || rm -f -- "$migration_state_tmp"
    [[ -z "${schema_state_tmp:-}" ]] || rm -f -- "$schema_state_tmp"
    rollback="$prefix/.rollback.next.$$"
    rm -f -- "$rollback"
    if [[ -n "$old_release" ]]; then
      ln -s -- "releases/$old_release" "$rollback"
      atomic_replace "$rollback" "$current"
    else
      rm -f -- "$current"
    fi
    if (( system_root && activate )); then
      if [[ -n "$old_release" ]]; then
        systemctl reset-failed open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service >/dev/null 2>&1 || true
        systemctl restart open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service >/dev/null 2>&1 || true
        systemctl try-restart open-card-edge.service >/dev/null 2>&1 || true
      else
        systemctl stop open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service >/dev/null 2>&1 || true
      fi
    fi
    pointer_switched=0
  fi
  return "$status"
}

mkdir -p -- "$prefix"
assert_no_symlink_components "$prefix"
[[ ! -e "$current" || -L "$current" ]] || die "refusing to replace non-symlink current pointer"
next="$prefix/.current.next.$$"
rm -f -- "$next"
ln -s -- "releases/$release_name" "$next"
atomic_replace "$next" "$current"
pointer_switched=1
trap rollback_install EXIT
if [[ -n "$old_release" ]]; then
  old_next="$prefix/.previous.next.$$"
  rm -f -- "$old_next"
  ln -s -- "releases/$old_release" "$old_next"
  atomic_replace "$old_next" "$previous"
fi
if (( system_root && activate )); then
  command -v getent >/dev/null 2>&1 || die "getent is required for system-root activation"
  command -v useradd >/dev/null 2>&1 || die "useradd is required for system-root activation"
  command -v install >/dev/null 2>&1 || die "install is required for system-root activation"
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required for system-root activation"
  for account in opencard opencard-agent opencard-buildkit opencard-caddy opencard-edge; do
    if ! getent passwd "$account" >/dev/null; then
      useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home "$account"
    fi
  done
  getent group docker >/dev/null || die "clean worker is missing the required docker group for opencard-agent"
  usermod -a -G docker opencard-agent
  install -d -m 0711 -o root -g root /var/lib/open-card
  install -d -m 0750 -o opencard -g opencard /var/log/open-card /var/lib/open-card/uploads /var/lib/open-card/workspaces /var/lib/open-card/build-work /var/lib/open-card/oci /var/lib/open-card/secrets /var/lib/open-card/secret-materials
  install -d -m 0750 -o opencard-agent -g opencard-agent /var/lib/open-card-agent /var/log/open-card-agent
  install -d -m 0700 -o opencard-buildkit -g opencard-buildkit /var/lib/open-card-buildkit /run/open-card-buildkit
  install -d -m 0750 -o opencard-caddy -g opencard-caddy /var/lib/open-card-caddy /var/log/open-card-caddy
  install -d -m 0750 -o opencard-edge -g opencard-edge /var/lib/open-card-edge /var/log/open-card-edge
  install -d -m 0700 -o opencard-edge -g opencard-edge /var/lib/open-card-edge/home /var/lib/open-card-edge/data /var/lib/open-card-edge/config
  systemctl daemon-reload
  systemctl enable open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service
  systemctl reset-failed open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service >/dev/null 2>&1 || true
  systemctl restart open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service
  # Edge stays disabled until install-host has rendered a domain-bound config
  # from explicit HTTPS origin and password-file activation inputs.
  systemctl disable --now open-card-edge.service >/dev/null 2>&1 || true
fi
if [[ -n "$health_command" ]] && ! OPEN_CARD_RELEASE_DIR="$release_dir" OPEN_CARD_CONFIG_DIR="$config_dir" OPEN_CARD_DATA_DIR="$data_dir" "$health_command"; then
  die "health command failed"
fi
if [[ -n "$migration_command" && -n "$manifest_migration_version" ]]; then
  migration_state="$data_dir/migration.version"
  migration_state_tmp="$data_dir/.migration.version.$$"
  printf '%s\n' "$manifest_migration_version" > "$migration_state_tmp"
  chmod 0640 "$migration_state_tmp"
  atomic_replace "$migration_state_tmp" "$migration_state"
  schema_state="$data_dir/schema.version"
  schema_state_tmp="$data_dir/.schema.version.$$"
  printf '%d\n' "$((10#$manifest_migration_version))" > "$schema_state_tmp"
  chmod 0640 "$schema_state_tmp"
  atomic_replace "$schema_state_tmp" "$schema_state"
fi
trap - EXIT
say "installed Open Card $version ($release_id)"
