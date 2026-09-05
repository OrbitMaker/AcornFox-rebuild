#!/usr/bin/env bash
# AcornFox's first-host setup is intentionally linear: once an effect fails it
# stops, leaves evidence intact, and never tries to delete or roll anything
# back. The detached Go helpers remain the sole release-state writers.
set -euo pipefail

readonly CLEAN_ENV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C)
readonly SCRIPT_DIR=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly PREFLIGHT="$SCRIPT_DIR/host-preflight.sh"
readonly INSTALL="$SCRIPT_DIR/install.sh"
readonly MIGRATE="$SCRIPT_DIR/control-plane-migrate.sh"
readonly STATE_ROOT=/var/lib/acornfox/install
readonly SUBID_START=231072
readonly SUBID_COUNT=65536

usage() {
  printf '%s\n' 'usage: install-host.sh --candidate-dir ABS --binding-sha256 HEX --bootstrap-helper ABS --bootstrap-helper-sha256 HEX'
}

bad_args() {
  printf '%s\n' 'acornfox install-host: invalid arguments' >&2
  exit 2
}

fail() {
  printf '%s\n' 'acornfox install-host: host setup failed' >&2
  exit 23
}

effect() {
  "${CLEAN_ENV[@]}" "$@" >&2
}

clean_output() {
  "${CLEAN_ENV[@]}" "$@"
}

require_account() {
  local account=$1 record name _ uid gid home shell group_record group_name group_gid group_members
  if record=$(clean_output /usr/bin/getent passwd "$account" 2>/dev/null); then
    IFS=: read -r name _ uid gid _ home shell <<<"$record"
    [[ $name == "$account" && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $home == /nonexistent && $shell == /usr/sbin/nologin ]] || fail
    group_record=$(clean_output /usr/bin/getent group "$account" 2>/dev/null) || fail
    IFS=: read -r group_name _ group_gid group_members <<<"$group_record"
    [[ $group_name == "$account" && $group_gid == "$gid" && -z $group_members ]] || fail
    return
  fi
  effect /usr/sbin/groupadd --system "$account"
  effect /usr/sbin/useradd --system --gid "$account" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$account"
  require_account "$account"
}

require_subid() {
  if clean_output /usr/bin/grep -qx 'acornfox-buildkit:231072:65536' /etc/subuid && clean_output /usr/bin/grep -qx 'acornfox-buildkit:231072:65536' /etc/subgid; then
    return
  fi
  if clean_output /usr/bin/grep -q '^acornfox-buildkit:' /etc/subuid || clean_output /usr/bin/grep -q '^acornfox-buildkit:' /etc/subgid; then
    fail
  fi
  effect /usr/sbin/usermod --add-subuids 231072-296607 --add-subgids 231072-296607 acornfox-buildkit
  clean_output /usr/bin/grep -qx 'acornfox-buildkit:231072:65536' /etc/subuid || fail
  clean_output /usr/bin/grep -qx 'acornfox-buildkit:231072:65536' /etc/subgid || fail
}

is_sha256() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

safe_candidate_dir() {
  local detail mode
  [[ $1 == /* && $1 != / && ! -L $1 && -d $1 ]] || return 1
  detail=$(clean_output /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$1") || return 1
  [[ $detail =~ ^0:0:[0-7]{3}:directory:2$ ]] || return 1
  mode=${detail#0:0:}
  mode=${mode%%:*}
  (( (8#$mode & 0022) == 0 ))
}

safe_helper() {
  local path=$1 expected=$2 detail actual
  [[ $path == /* && ! -L $path && -f $path ]] || return 1
  detail=$(clean_output /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$path") || return 1
  [[ $detail == '0:0:755:regular file:1' ]] || return 1
  actual=$(clean_output /usr/bin/sha256sum -- "$path") || return 1
  actual=${actual%% *}
  [[ $actual == "$expected" ]]
}

require_distinct_accounts() {
  local account record _ uid gid seen=" "
  for account in acornfox acornfox-agent acornfox-buildkit acornfox-caddy acornfox-edge; do
    record=$(clean_output /usr/bin/getent passwd "$account") || fail
    IFS=: read -r _ _ uid gid _ <<<"$record"
    [[ $seen != *" $uid:$gid "* ]] || fail
    seen+="$uid:$gid "
  done
}

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -ne 8 || $1 != --candidate-dir || $3 != --binding-sha256 || $5 != --bootstrap-helper || $7 != --bootstrap-helper-sha256 ]]; then
  bad_args
fi
[[ $(/usr/bin/id -u) -eq 0 ]] || fail
[[ ${ACORNFOX_INSTALL_CONFIRMATION:-} == ACORNFOX-INSTALL ]] || fail
[[ ${ACORNFOX_DEDICATED_HOST_CONFIRMATION:-} == ACORNFOX-DEDICATED-HOST ]] || fail
candidate_dir=$2
binding_sha256=$4
bootstrap_helper=$6
bootstrap_helper_sha256=$8
is_sha256 "$binding_sha256" && is_sha256 "$bootstrap_helper_sha256" || fail
safe_candidate_dir "$candidate_dir" || fail
safe_helper "$bootstrap_helper" "$bootstrap_helper_sha256" || fail

# stdout is reserved for machine-readable helper receipts. The preflight is
# read-only, so its canonical receipt is deliberately passed through.
"${CLEAN_ENV[@]}" "$PREFLIGHT" --phase pre
effect /usr/bin/apt-get update
effect /usr/bin/apt-get install -y --no-install-recommends ca-certificates docker.io postgresql postgresql-client uidmap util-linux apparmor apparmor-utils nftables iptables iproute2

for account in acornfox acornfox-agent acornfox-buildkit acornfox-caddy acornfox-edge; do
  require_account "$account"
done
require_distinct_accounts
require_subid
effect /usr/bin/install -d -o root -g root -m 0755 /var/lib/acornfox
effect /usr/bin/install -d -o root -g root -m 0700 "$STATE_ROOT"
effect /usr/bin/systemctl enable --now docker.service
effect /usr/bin/systemctl enable --now postgresql.service
"${CLEAN_ENV[@]}" "$PREFLIGHT" --phase post

"${CLEAN_ENV[@]}" "$INSTALL" --candidate-dir "$candidate_dir" --binding-sha256 "$binding_sha256" --bootstrap-helper "$bootstrap_helper" --bootstrap-helper-sha256 "$bootstrap_helper_sha256"
"${CLEAN_ENV[@]}" "$MIGRATE" --pending
effect /usr/bin/systemctl daemon-reload
effect /usr/bin/systemctl enable acornfox-upgrade-safe.target
effect /usr/bin/systemctl enable acornfox-build-network.service
effect /usr/bin/systemctl enable acornfox-buildkit.service
effect /usr/bin/systemctl enable acornfox-caddy.service
effect /usr/bin/systemctl enable acornfox-server.service
effect /usr/bin/systemctl enable acornfox-agent.service
effect /usr/bin/systemctl enable acornfox-edge.service
effect /usr/bin/systemctl enable acornfox-healthcheck.timer
effect /usr/bin/systemctl start acornfox-upgrade-safe.target
effect /usr/bin/systemctl start acornfox-build-network.service
effect /usr/bin/systemctl start acornfox-buildkit.service
effect /usr/bin/systemctl start acornfox-caddy.service
effect /usr/bin/systemctl start acornfox-server.service
effect /usr/bin/systemctl start acornfox-agent.service
effect /usr/bin/systemctl start acornfox-edge.service
effect /usr/bin/systemctl start acornfox-healthcheck.timer
effect /usr/bin/systemctl start acornfox-healthcheck.service
for unit in acornfox-upgrade-safe.target acornfox-build-network.service acornfox-buildkit.service acornfox-caddy.service acornfox-server.service acornfox-agent.service acornfox-edge.service acornfox-healthcheck.timer; do
  clean_output /usr/bin/systemctl is-enabled --quiet "$unit" || fail
  clean_output /usr/bin/systemctl is-active --quiet "$unit" || fail
done

printf '{"code":"installed","ok":true,"schema_version":1}\n'
