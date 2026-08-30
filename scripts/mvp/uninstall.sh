#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: uninstall.sh --root TASK_ROOT [--purge --confirm OPEN-CARD-PURGE:ID]
                    [--test-safe-prefix PATH] [--dry-run]

Default uninstall removes binaries, release pointers, configuration and
systemd unit files while preserving /var/lib/open-card and its evidence.
USAGE
}
die() { echo "open-card uninstall: $*" >&2; exit 1; }
root= safe_prefix= confirm=
dry_run=0 purge=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) [[ $# -gt 1 ]] || die "--root requires a value"; root=$2; shift 2 ;;
    --purge) purge=1; shift ;;
    --confirm|--purge-token) [[ $# -gt 1 ]] || die "$1 requires a value"; confirm=$2; shift 2 ;;
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
  [[ -z "$safe_prefix" ]] || die "--test-safe-prefix is not valid with --root /"
else
  [[ "$root" != "$HOME" && "$root" != "$HOME"/* ]] || die "refusing HOME or a path below HOME"
fi
if (( purge )) && (( system_root )) && [[ "$confirm" != "OPEN-CARD-PURGE:$(cat -- "$installation_id")" ]]; then
  die "--purge requires --confirm OPEN-CARD-PURGE:<installation-id>"
elif (( purge )) && (( ! system_root )) && [[ "$confirm" != "OPEN-CARD-PURGE" ]]; then
  die "test purge requires --confirm OPEN-CARD-PURGE"
fi
if (( ! purge )) && [[ -n "$confirm" ]]; then
  die "--confirm is only valid with --purge"
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

prefix="$root_real/opt/open-card"
config_dir="$root_real/etc/open-card"
data_dir="$root_real/var/lib/open-card"
systemd_dir="$root_real/etc/systemd/system"
agent_state="$root_real/var/lib/open-card-agent"
agent_logs="$root_real/var/log/open-card-agent"
caddy_state="$root_real/var/lib/open-card-caddy"
caddy_logs="$root_real/var/log/open-card-caddy"
edge_state="$root_real/var/lib/open-card-edge"
edge_logs="$root_real/var/log/open-card-edge"
server_logs="$root_real/var/log/open-card"
buildkit_state="$root_real/var/lib/open-card-buildkit"
buildkit_image="$root_real/var/lib/open-card-buildkit-state.img"
buildkit_runtime="$root_real/run/open-card-buildkit"
buildkit_config="$root_real/etc/buildkit/buildkitd.toml"
apparmor_profile="$root_real/etc/apparmor.d/opencard-rootlesskit"
fstab_path="$root_real/etc/fstab"
fixture_unit="$systemd_dir/open-card-caddy-fixture.service"
buildkit_capacity_dir="$systemd_dir/open-card-buildkit.service.d"
buildkit_capacity_dropin="$buildkit_capacity_dir/20-production-capacity.conf"
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
  if [[ -e "$path" && ! -d "$path" ]]; then
    die "managed path is not a directory: $path"
  fi
done
for path in "$agent_state" "$agent_logs" "$caddy_state" "$caddy_logs" "$edge_state" "$edge_logs" "$server_logs" "$buildkit_state" "$buildkit_image" "$buildkit_runtime" "$buildkit_config" "$apparmor_profile" "$fixture_unit" "$buildkit_capacity_dir" "$buildkit_capacity_dropin"; do
  assert_no_symlink_components "$path"
done
if (( dry_run )); then
  if (( purge )); then
    echo "open-card uninstall: would purge binaries, config, runtime residue, data and evidence"
  else
    echo "open-card uninstall: would remove binaries, config and runtime residue; preserve $data_dir and evidence"
  fi
  exit 0
fi
if (( system_root )); then
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required for system-root uninstall"
  systemctl disable --now open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service open-card-caddy-fixture.service >/dev/null 2>&1 || true
  for service in open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service open-card-caddy-fixture.service; do
    systemctl kill --kill-who=all "$service" >/dev/null 2>&1 || true
  done
  managed_process_pattern='/opt/open-card/(current|releases/[^/]+)/bin/(open-card-server|open-card-agent|open-card-static-server|open-card-caddy-fixture|buildkitd|buildctl|rootlesskit|caddy)( |$)'
  managed_processes=
  for _ in $(seq 1 100); do
    managed_processes=$(pgrep -fa "$managed_process_pattern" 2>/dev/null || true)
    [[ -z "$managed_processes" ]] && break
    sleep 0.1
  done
  [[ -z "$managed_processes" ]] || die "managed processes did not stop: $managed_processes"
  if [[ -f "$apparmor_profile" ]] && command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -R -- "$apparmor_profile" >/dev/null 2>&1 || true
  fi
fi
if (( system_root )); then
  "$(dirname -- "$0")/buildkit-production-capacity.sh" remove
fi

rm -rf -- "$prefix" "$config_dir"
rm -f -- "$systemd_dir/open-card-server.service" "$systemd_dir/open-card-agent.service" "$systemd_dir/open-card-buildkit.service" "$systemd_dir/open-card-caddy.service" "$systemd_dir/open-card-edge.service" "$fixture_unit"
if (( system_root )) && command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$buildkit_state"; then
  command -v umount >/dev/null 2>&1 || die "umount is required to remove the BuildKit state mount"
  command -v findmnt >/dev/null 2>&1 || die "findmnt is required to verify the BuildKit state mount"
  command -v losetup >/dev/null 2>&1 || die "losetup is required to verify the BuildKit state image"
  mounted_source=$(findmnt -n -o SOURCE --target "$buildkit_state")
  expected_source=$(losetup -j "$buildkit_image" | awk -F: 'NR == 1 { print $1 }')
  [[ -n "$expected_source" && "$mounted_source" = "$expected_source" ]] ||
    die "refusing to unmount unexpected BuildKit state source $mounted_source"
  unmounted=0
  for _ in $(seq 1 50); do
    if umount --recursive "$buildkit_state" >/dev/null 2>&1; then unmounted=1; break; fi
    sleep 0.1
  done
  if [[ "$unmounted" != 1 ]]; then
    findmnt --recursive "$buildkit_state" >&2 || true
    die "failed to unmount BuildKit state"
  fi
fi
rm -rf -- "$agent_state" "$agent_logs" "$caddy_state" "$caddy_logs" "$server_logs" "$buildkit_state" "$buildkit_image" "$buildkit_runtime"
rm -f -- "$buildkit_config" "$apparmor_profile"
rmdir -- "$root_real/etc/buildkit/cdi" "$root_real/etc/buildkit" 2>/dev/null || true
if [[ -f "$fstab_path" && ! -L "$fstab_path" ]]; then
  fstab_line='/var/lib/open-card-buildkit-state.img /var/lib/open-card-buildkit ext4 loop,nodev,nosuid 0 2'
  fstab_tmp="$fstab_path.open-card-uninstall.$$"
  awk -v target="$fstab_line" '$0 != target { print }' "$fstab_path" > "$fstab_tmp"
  if ! cmp -s "$fstab_path" "$fstab_tmp"; then
    chmod --reference="$fstab_path" "$fstab_tmp" 2>/dev/null || chmod 0644 "$fstab_tmp"
    mv -- "$fstab_tmp" "$fstab_path"
  else
    rm -f -- "$fstab_tmp"
  fi
fi
if (( system_root )); then
  systemctl daemon-reload
  systemctl reset-failed open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service open-card-caddy-fixture.service >/dev/null 2>&1 || true
fi
if (( purge )); then
  rm -rf -- "$data_dir" "$edge_state" "$edge_logs"
  echo "open-card uninstall: purged installation data and evidence"
else
  echo "open-card uninstall: removed binaries/config and Edge unit; preserved $data_dir, evidence, backups, installation-id, and $edge_state"
fi
