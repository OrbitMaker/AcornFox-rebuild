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
readonly APT_ROOT=/etc/apt
readonly APT_KEYRING_DIR="$APT_ROOT/keyrings"
readonly APT_SOURCE_DIR="$APT_ROOT/sources.list.d"
readonly PGDG_KEY_FILE="$APT_KEYRING_DIR/acornfox-postgresql.asc"
readonly PGDG_SOURCE_FILE="$APT_SOURCE_DIR/acornfox-postgresql.sources"
readonly PGDG_KEY_SHA256=0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76
PGDG_TMP_DIR_ID=
PGDG_TMP_CHILD_PATHS=()
PGDG_TMP_CHILD_IDENTITIES=()
PGDG_TMP_CHILD_TYPES=()

usage() {
  printf '%s\n' 'usage: install-host.sh --candidate-dir ABS --binding-sha256 HEX --bootstrap-helper ABS --bootstrap-helper-sha256 HEX'
  printf '%s\n' '       install-host.sh --candidate-dir ABS --binding-sha256 HEX --bootstrap-helper ABS --bootstrap-helper-sha256 HEX --host-bundle ABS --envelope ABS --public-key HEX --channel STRING --allowed-hosts HOSTS'
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

apt_effect() {
  "${CLEAN_ENV[@]}" DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l /usr/bin/apt-get "$@" >&2
}

safe_root_directory() {
  local detail mode
  [[ ! -L $1 && -d $1 ]] || return 1
  detail=$(clean_output /usr/bin/stat -c '%u:%g:%a:%F' -- "$1") || return 1
  [[ $detail =~ ^0:0:[0-7]{3}:directory$ ]] || return 1
  mode=${detail#0:0:}
  mode=${mode%%:*}
  (( (8#$mode & 0022) == 0 ))
}

safe_root_private_directory() {
  local mode
  safe_root_directory "$1" || return 1
  mode=$(clean_output /usr/bin/stat -c '%a' -- "$1") || return 1
  [[ $mode == 700 ]]
}

safe_root_file_matches() {
  local path=$1 material=$2 detail mode
  [[ ! -L $path && -f $path ]] || return 1
  detail=$(clean_output /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$path") || return 1
  [[ $detail =~ ^0:0:[0-7]{3}:regular\ file:1$ ]] || return 1
  mode=${detail#0:0:}
  mode=${mode%%:*}
  (( (8#$mode & 0022) == 0 )) || return 1
  clean_output /usr/bin/cmp -s -- "$material" "$path"
}

safe_public_apt_file_matches() {
  local detail
  safe_root_file_matches "$1" "$2" || return 1
  detail=$(clean_output /usr/bin/stat -c '%a' -- "$1") || return 1
  [[ $detail == 644 ]]
}

validate_managed_apt_file() {
  local path=$1 material=$2
  if [[ -e $path || -L $path ]]; then
    safe_root_file_matches "$path" "$material" || fail
  fi
}

ensure_root_directory() {
  local path=$1 parent=$2
  if [[ -e $path || -L $path ]]; then
    safe_root_directory "$path" || fail
    return
  fi
  safe_root_directory "$parent" || fail
  effect /usr/bin/install -d -o root -g root -m 0755 "$path"
  safe_root_directory "$path" || fail
}

create_managed_apt_file() {
  local path=$1 material=$2 parent tmp tmp_identity
  if [[ -e $path || -L $path ]]; then
    safe_root_file_matches "$path" "$material" || fail
    effect /usr/bin/chmod 0644 "$path"
    safe_public_apt_file_matches "$path" "$material" || fail
    return
  fi
  parent=${path%/*}
  safe_root_directory "$parent" || fail
  tmp=$(clean_output /usr/bin/mktemp "$parent/.${path##*/}.acornfox.XXXXXXXX") || fail
  tmp_identity=$(clean_output /usr/bin/stat -c '%d:%i' -- "$tmp") || fail
  if ! safe_own_temp_file "$tmp" "$tmp_identity"; then
    cleanup_own_temp_file "$tmp" "$tmp_identity"
    fail
  fi
  if ! clean_output /usr/bin/tee "$tmp" < "$material" >/dev/null; then
    cleanup_own_temp_file "$tmp" "$tmp_identity"
    fail
  fi
  if ! effect /usr/bin/chmod 0644 "$tmp"; then
    cleanup_own_temp_file "$tmp" "$tmp_identity"
    fail
  fi
  if ! safe_public_apt_file_matches "$tmp" "$material"; then
    cleanup_own_temp_file "$tmp" "$tmp_identity"
    fail
  fi
  if ! effect /usr/bin/sync -f -- "$tmp"; then
    cleanup_own_temp_file "$tmp" "$tmp_identity"
    fail
  fi
  # GNU mv exits successfully when -n leaves a competing target in place, so
  # success requires the exact temporary inode to have disappeared as well.
  if ! effect /usr/bin/mv -n -T -- "$tmp" "$path" || [[ -e $tmp || -L $tmp ]]; then
    cleanup_own_temp_file "$tmp" "$tmp_identity"
    fail
  fi
  safe_public_apt_file_matches "$path" "$material" || fail
  effect /usr/bin/sync -f -- "$parent"
}

safe_own_temp_file() {
  local path=$1 expected_identity=$2 detail mode
  [[ -n $expected_identity && ! -L $path && -f $path ]] || return 1
  detail=$(clean_output /usr/bin/stat -c '%d:%i:%u:%g:%a:%F:%h' -- "$path") || return 1
  [[ $detail == "$expected_identity":0:0:* ]] || return 1
  # GNU stat describes the just-created, inode-bound mktemp file as a
  # "regular empty file". It is permitted only before material is written.
  [[ $detail =~ :0:0:[0-7]{3}:regular(\ empty)?\ file:1$ ]] || return 1
  mode=${detail#"$expected_identity":0:0:}
  mode=${mode%%:*}
  (( (8#$mode & 0022) == 0 ))
}

cleanup_own_temp_file() {
  local path=$1 expected_identity=$2
  safe_own_temp_file "$path" "$expected_identity" || return 0
  effect /usr/bin/rm -- "$path" || fail
}

pgdg_path_identity() {
  clean_output /usr/bin/stat -c '%d:%i' -- "$1"
}

safe_recorded_pgdg_object() {
  local path=$1 expected_identity=$2 expected_type=$3 detail mode
  [[ -n $expected_identity && ! -L $path ]] || return 1
  case $expected_type in
    file) [[ -f $path ]] || return 1 ;;
    directory) [[ -d $path ]] || return 1 ;;
    *) return 1 ;;
  esac
  detail=$(clean_output /usr/bin/stat -c '%d:%i:%u:%g:%a:%F:%h' -- "$path") || return 1
  [[ $detail == "$expected_identity":0:0:* ]] || return 1
  case $expected_type in
    file) [[ $detail =~ :0:0:[0-7]{3}:regular\ file:1$ ]] || return 1 ;;
    directory) [[ $detail =~ :0:0:[0-7]{3}:directory:[2-9][0-9]*$ ]] || return 1 ;;
  esac
  mode=${detail#"$expected_identity":0:0:}
  mode=${mode%%:*}
  (( (8#$mode & 0022) == 0 ))
}

record_pgdg_tmp_child() {
  local path=$1 type=$2 identity
  identity=$(pgdg_path_identity "$path") || fail
  safe_recorded_pgdg_object "$path" "$identity" "$type" || fail
  PGDG_TMP_CHILD_PATHS+=("$path")
  PGDG_TMP_CHILD_IDENTITIES+=("$identity")
  PGDG_TMP_CHILD_TYPES+=("$type")
}

recorded_pgdg_tmp_child_index() {
  local path=$1 index
  for ((index = 0; index < ${#PGDG_TMP_CHILD_PATHS[@]}; index++)); do
    [[ ${PGDG_TMP_CHILD_PATHS[index]} == "$path" ]] && {
      printf '%s\n' "$index"
      return 0
    }
  done
  return 1
}

pgdg_tmp_children_are_closed() {
  local directory=$1 child index found=1
  shopt -s nullglob dotglob
  for child in "$directory"/*; do
    if ! index=$(recorded_pgdg_tmp_child_index "$child"); then
      found=0
      break
    fi
    safe_recorded_pgdg_object "$child" "${PGDG_TMP_CHILD_IDENTITIES[index]}" "${PGDG_TMP_CHILD_TYPES[index]}" || {
      found=0
      break
    }
  done
  if (( found )); then
    for ((index = 0; index < ${#PGDG_TMP_CHILD_PATHS[@]}; index++)); do
      [[ ${PGDG_TMP_CHILD_PATHS[index]%/*} == "$directory" ]] || continue
      safe_recorded_pgdg_object "${PGDG_TMP_CHILD_PATHS[index]}" "${PGDG_TMP_CHILD_IDENTITIES[index]}" "${PGDG_TMP_CHILD_TYPES[index]}" || {
        found=0
        break
      }
    done
  fi
  shopt -u dotglob nullglob
  (( found ))
}

cleanup_pgdg_tmp() {
  local index path system_sourceparts_index
  [[ -n ${pgdg_tmp_dir:-} && -n $PGDG_TMP_DIR_ID ]] || return 0
  safe_recorded_pgdg_object "$pgdg_tmp_dir" "$PGDG_TMP_DIR_ID" directory || return 0
  pgdg_tmp_children_are_closed "$pgdg_tmp_dir" || return 0
  if [[ -n ${PGDG_SYSTEM_SOURCEPARTS:-} ]]; then
    system_sourceparts_index=$(recorded_pgdg_tmp_child_index "$PGDG_SYSTEM_SOURCEPARTS") || return 0
    pgdg_tmp_children_are_closed "$PGDG_SYSTEM_SOURCEPARTS" || return 0
    for ((index = 0; index < ${#PGDG_TMP_CHILD_PATHS[@]}; index++)); do
      path=${PGDG_TMP_CHILD_PATHS[index]}
      [[ ${path%/*} == "$PGDG_SYSTEM_SOURCEPARTS" ]] || continue
      [[ ${PGDG_TMP_CHILD_TYPES[index]} == file ]] || return 0
      safe_recorded_pgdg_object "$path" "${PGDG_TMP_CHILD_IDENTITIES[index]}" file || return 0
      effect /usr/bin/rm -- "$path" || return 0
    done
    safe_recorded_pgdg_object "$PGDG_SYSTEM_SOURCEPARTS" "${PGDG_TMP_CHILD_IDENTITIES[system_sourceparts_index]}" directory || return 0
    effect /usr/bin/rmdir -- "$PGDG_SYSTEM_SOURCEPARTS" || return 0
  fi
  for ((index = 0; index < ${#PGDG_TMP_CHILD_PATHS[@]}; index++)); do
    path=${PGDG_TMP_CHILD_PATHS[index]}
    [[ ${path%/*} == "$pgdg_tmp_dir" ]] || continue
    [[ $path != "${PGDG_SYSTEM_SOURCEPARTS:-}" ]] || continue
    [[ ${PGDG_TMP_CHILD_TYPES[index]} == file ]] || return 0
    safe_recorded_pgdg_object "$path" "${PGDG_TMP_CHILD_IDENTITIES[index]}" file || return 0
    effect /usr/bin/rm -- "$path" || return 0
  done
  safe_recorded_pgdg_object "$pgdg_tmp_dir" "$PGDG_TMP_DIR_ID" directory || return 0
  effect /usr/bin/rmdir -- "$pgdg_tmp_dir" || return 0
}

prepare_pgdg_materials() {
  local key_sha
  pgdg_tmp_dir=$(clean_output /usr/bin/mktemp -d /run/acornfox-pgdg.XXXXXXXX) || fail
  safe_root_private_directory "$pgdg_tmp_dir" || fail
  PGDG_TMP_DIR_ID=$(pgdg_path_identity "$pgdg_tmp_dir") || fail
  trap 'cleanup_pgdg_tmp || true' EXIT
  readonly PGDG_KEY_MATERIAL="$pgdg_tmp_dir/acornfox-postgresql.asc"
  readonly PGDG_SOURCE_MATERIAL="$pgdg_tmp_dir/acornfox-postgresql.sources"
  clean_output /usr/bin/tee "$PGDG_KEY_MATERIAL" >/dev/null <<'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=DA1T
-----END PGP PUBLIC KEY BLOCK-----
EOF
  clean_output /usr/bin/tee "$PGDG_SOURCE_MATERIAL" >/dev/null <<'EOF'
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: trixie-pgdg
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/acornfox-postgresql.asc
EOF
  key_sha=$(clean_output /usr/bin/sha256sum -- "$PGDG_KEY_MATERIAL") || fail
  [[ ${key_sha%% *} == "$PGDG_KEY_SHA256" ]] || fail
  record_pgdg_tmp_child "$PGDG_KEY_MATERIAL" file
  record_pgdg_tmp_child "$PGDG_SOURCE_MATERIAL" file
}

require_debian_pgdg() {
  prepare_pgdg_materials
  safe_root_directory "$APT_ROOT" || fail
  if [[ -e $APT_KEYRING_DIR || -L $APT_KEYRING_DIR ]]; then
    safe_root_directory "$APT_KEYRING_DIR" || fail
  fi
  safe_root_directory "$APT_SOURCE_DIR" || fail
  validate_managed_apt_file "$PGDG_KEY_FILE" "$PGDG_KEY_MATERIAL"
  validate_managed_apt_file "$PGDG_SOURCE_FILE" "$PGDG_SOURCE_MATERIAL"
}

prepare_debian_system_sources() {
  local source source_name
  readonly PGDG_SYSTEM_SOURCEPARTS="$pgdg_tmp_dir/system-sourceparts"
  effect /usr/bin/install -d -o root -g root -m 0700 "$PGDG_SYSTEM_SOURCEPARTS"
  safe_root_private_directory "$PGDG_SYSTEM_SOURCEPARTS" || fail
  record_pgdg_tmp_child "$PGDG_SYSTEM_SOURCEPARTS" directory
  shopt -s nullglob
  for source in "$APT_SOURCE_DIR"/*.list "$APT_SOURCE_DIR"/*.sources; do
    [[ $source != "$PGDG_SOURCE_FILE" ]] || continue
    source_name=${source##*/}
    effect /usr/bin/cp -p -- "$source" "$PGDG_SYSTEM_SOURCEPARTS/$source_name"
    record_pgdg_tmp_child "$PGDG_SYSTEM_SOURCEPARTS/$source_name" file
  done
  shopt -u nullglob
}

debian_system_apt() {
  apt_effect -o "Dir::Etc::sourcelist=$APT_ROOT/sources.list" -o "Dir::Etc::sourceparts=$PGDG_SYSTEM_SOURCEPARTS" "$@"
}

publish_debian_pgdg() {
  ensure_root_directory "$APT_KEYRING_DIR" "$APT_ROOT"
  create_managed_apt_file "$PGDG_KEY_FILE" "$PGDG_KEY_MATERIAL"
  create_managed_apt_file "$PGDG_SOURCE_FILE" "$PGDG_SOURCE_MATERIAL"
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
  local account record _ uid gid seen=" " service_uids=" "
  for account in acornfox acornfox-agent acornfox-buildkit acornfox-caddy acornfox-edge acornfox-pi; do
    record=$(clean_output /usr/bin/getent passwd "$account") || fail
    IFS=: read -r _ _ uid gid _ <<<"$record"
    [[ $seen != *" $uid:$gid "* ]] || fail
    seen+="$uid:$gid "
    if [[ $account == acornfox-pi ]]; then
      [[ $service_uids != *" $uid "* ]] || fail
    else
      service_uids+="$uid "
    fi
  done
}

has_native_overlay=0
candidate_dir=""
binding_sha256=""
bootstrap_helper=""
bootstrap_helper_sha256=""
host_bundle=""
envelope=""
public_key=""
channel=""
allowed_hosts=""

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -eq 8 ]]; then
  if [[ $1 != --candidate-dir || $3 != --binding-sha256 || $5 != --bootstrap-helper || $7 != --bootstrap-helper-sha256 ]]; then
    bad_args
  fi
  candidate_dir=$2
  binding_sha256=$4
  bootstrap_helper=$6
  bootstrap_helper_sha256=$8
elif [[ $# -eq 18 ]]; then
  seen_flags=" "
  flag_count=0
  while [[ $# -gt 0 ]]; do
    flag=$1
    val=$2
    shift 2

    [[ $seen_flags != *" $flag "* ]] || bad_args
    seen_flags+="$flag "
    (( flag_count += 1 ))

    case $flag in
      --candidate-dir) candidate_dir=$val ;;
      --binding-sha256) binding_sha256=$val ;;
      --bootstrap-helper) bootstrap_helper=$val ;;
      --bootstrap-helper-sha256) bootstrap_helper_sha256=$val ;;
      --host-bundle) host_bundle=$val ;;
      --envelope) envelope=$val ;;
      --public-key) public_key=$val ;;
      --channel) channel=$val ;;
      --allowed-hosts) allowed_hosts=$val ;;
      *) bad_args ;;
    esac
  done
  if (( flag_count != 9 )) || [[ -z $candidate_dir || -z $binding_sha256 || -z $bootstrap_helper || -z $bootstrap_helper_sha256 || -z $host_bundle || -z $envelope || -z $public_key || -z $channel || -z $allowed_hosts ]]; then
    bad_args
  fi
  has_native_overlay=1
else
  bad_args
fi

[[ $(/usr/bin/id -u) -eq 0 ]] || fail
[[ ${ACORNFOX_INSTALL_CONFIRMATION:-} == ACORNFOX-INSTALL ]] || fail
[[ ${ACORNFOX_DEDICATED_HOST_CONFIRMATION:-} == ACORNFOX-DEDICATED-HOST ]] || fail
is_sha256 "$binding_sha256" && is_sha256 "$bootstrap_helper_sha256" || fail
safe_candidate_dir "$candidate_dir" || fail
safe_helper "$bootstrap_helper" "$bootstrap_helper_sha256" || fail

if (( has_native_overlay )); then
  is_sha256 "$public_key" || fail
  [[ $channel == stable || $channel == beta ]] || fail
  [[ -n $allowed_hosts ]] || fail
  [[ $host_bundle == /* && -f $host_bundle && ! -L $host_bundle ]] || fail
  [[ $envelope == /* && -f $envelope && ! -L $envelope ]] || fail
fi

console_access=${ACORNFOX_CONSOLE_ACCESS:-public_https}
public_origin=${ACORNFOX_PUBLIC_ORIGIN:-}
git_resolvers=${ACORNFOX_GIT_RESOLVERS:-}

if [[ $console_access == public_https ]]; then
  [[ -n $public_origin && -n $git_resolvers ]] || fail
  # Validate operator choices before package or host changes.
  "${CLEAN_ENV[@]}" "$bootstrap_helper" validate-runtime-inputs --public-origin "$public_origin" --git-resolvers "$git_resolvers"
elif [[ $console_access == local_loopback ]]; then
  [[ -z $public_origin ]] || fail
  # For local_loopback, validate choices with validate-local-runtime-inputs before changes.
  if [[ -n $git_resolvers ]]; then
    "${CLEAN_ENV[@]}" "$bootstrap_helper" validate-local-runtime-inputs --git-resolvers "$git_resolvers"
  else
    "${CLEAN_ENV[@]}" "$bootstrap_helper" validate-local-runtime-inputs
  fi
else
  fail
fi

if (( has_native_overlay )); then
  "${CLEAN_ENV[@]}" "$bootstrap_helper" initial-host-overlay-preflight \
    --host-bundle "$host_bundle" \
    --envelope "$envelope" \
    --public-key "$public_key" \
    --channel "$channel" \
    --allowed-hosts "$allowed_hosts" \
    --binding-sha256 "$binding_sha256" >/dev/null || fail
fi

# stdout is reserved for machine-readable helper receipts. The preflight is
# read-only, so its canonical receipt is deliberately passed through.
"${CLEAN_ENV[@]}" "$PREFLIGHT" --phase pre
if clean_output /usr/bin/grep -qx 'ID=ubuntu' /etc/os-release; then
  # Ubuntu 24.04 provides PostgreSQL 16 through its existing dependency path.
  apt_effect update
  apt_effect install -y --no-install-recommends ca-certificates docker.io postgresql postgresql-client git uidmap util-linux apparmor apparmor-utils nftables iptables iproute2
elif clean_output /usr/bin/grep -qx 'ID=debian' /etc/os-release; then
  # Debian 13's postgresql meta package currently selects 17.  Validate any
  # pre-existing AcornFox PGDG material before apt or account side effects.
  # The initial APT pass deliberately excludes even an exact pre-existing
  # PGDG source so a minimal host can obtain CA roots from its system sources.
  require_debian_pgdg
  prepare_debian_system_sources
  debian_system_apt update
  debian_system_apt install -y --no-install-recommends ca-certificates
  publish_debian_pgdg
  apt_effect update
  apt_effect install -y --no-install-recommends docker.io docker-cli postgresql-16 postgresql-client-16 git uidmap util-linux apparmor apparmor-utils nftables iptables iproute2
else
  fail
fi

for account in acornfox acornfox-agent acornfox-buildkit acornfox-caddy acornfox-edge acornfox-pi; do
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
if [[ $console_access == public_https ]]; then
  "${CLEAN_ENV[@]}" /opt/acornfox/upgrade-tools/acornfox-upgrade configure-runtime --public-origin "$public_origin" --git-resolvers "$git_resolvers"
else
  if [[ -n $git_resolvers ]]; then
    "${CLEAN_ENV[@]}" /opt/acornfox/upgrade-tools/acornfox-upgrade configure-local-runtime --git-resolvers "$git_resolvers"
  else
    "${CLEAN_ENV[@]}" /opt/acornfox/upgrade-tools/acornfox-upgrade configure-local-runtime
  fi
fi
effect /usr/bin/systemctl daemon-reload
effect /usr/bin/systemctl enable acornfox-upgrade-safe.target
effect /usr/bin/systemctl enable acornfox-build-network.service
effect /usr/bin/systemctl enable acornfox-buildkit.service
effect /usr/bin/systemctl enable acornfox-runtime-network.service
effect /usr/bin/systemctl enable acornfox-caddy.service
effect /usr/bin/systemctl enable acornfox-server.service
effect /usr/bin/systemctl enable acornfox-agent.service

if [[ $console_access == public_https ]]; then
  effect /usr/bin/systemctl enable acornfox-edge.service
  effect /usr/bin/systemctl enable acornfox-healthcheck.timer
  effect /usr/bin/systemctl start acornfox-upgrade-safe.target
  effect /usr/bin/systemctl start acornfox-build-network.service
  effect /usr/bin/systemctl start acornfox-buildkit.service
  effect /usr/bin/systemctl start acornfox-runtime-network.service
  effect /usr/bin/systemctl start acornfox-caddy.service
  effect /usr/bin/systemctl start acornfox-server.service
  effect /usr/bin/systemctl start acornfox-agent.service
  effect /usr/bin/systemctl start acornfox-edge.service
  effect /usr/bin/systemctl start acornfox-healthcheck.timer
  effect /usr/bin/systemctl start acornfox-healthcheck.service
  for unit in acornfox-upgrade-safe.target acornfox-build-network.service acornfox-buildkit.service acornfox-runtime-network.service acornfox-caddy.service acornfox-server.service acornfox-agent.service acornfox-edge.service acornfox-healthcheck.timer; do
    clean_output /usr/bin/systemctl is-enabled --quiet "$unit" || fail
    clean_output /usr/bin/systemctl is-active --quiet "$unit" || fail
  done
else
  # local_loopback: acornfox-edge and healthcheck timer (which checks port 18482) are disabled and inactive.
  effect /usr/bin/systemctl disable --now acornfox-edge.service
  effect /usr/bin/systemctl disable --now acornfox-healthcheck.timer
  effect /usr/bin/systemctl start acornfox-upgrade-safe.target
  effect /usr/bin/systemctl start acornfox-build-network.service
  effect /usr/bin/systemctl start acornfox-buildkit.service
  effect /usr/bin/systemctl start acornfox-runtime-network.service
  effect /usr/bin/systemctl start acornfox-caddy.service
  effect /usr/bin/systemctl start acornfox-server.service
  effect /usr/bin/systemctl start acornfox-agent.service
  for unit in acornfox-upgrade-safe.target acornfox-build-network.service acornfox-buildkit.service acornfox-runtime-network.service acornfox-caddy.service acornfox-server.service acornfox-agent.service; do
    clean_output /usr/bin/systemctl is-enabled --quiet "$unit" || fail
    clean_output /usr/bin/systemctl is-active --quiet "$unit" || fail
  done
  if clean_output /usr/bin/systemctl is-enabled --quiet acornfox-edge.service || clean_output /usr/bin/systemctl is-active --quiet acornfox-edge.service; then
    fail
  fi
  if clean_output /usr/bin/systemctl is-enabled --quiet acornfox-healthcheck.timer || clean_output /usr/bin/systemctl is-active --quiet acornfox-healthcheck.timer; then
    fail
  fi
  # Verify local endpoints on 18481 (healthz, readyz) and 8080 (setup page) with wait-local-ready helper
  "${CLEAN_ENV[@]}" /opt/acornfox/upgrade-tools/acornfox-upgrade wait-local-ready
fi
[[ ! -e /run/acornfox-pi/worker.sock && ! -L /run/acornfox-pi/worker.sock ]] || fail

if (( has_native_overlay )); then
  # Provisioning accepts only root-protected source ancestors; /tmp is shared.
  "${CLEAN_ENV[@]}" TMPDIR=/run "$bootstrap_helper" initial-host-overlay-apply \
    --host-bundle "$host_bundle" \
    --envelope "$envelope" \
    --public-key "$public_key" \
    --channel "$channel" \
    --allowed-hosts "$allowed_hosts" \
    --binding-sha256 "$binding_sha256" >/dev/null || fail
  effect /usr/bin/systemctl daemon-reload
  effect /usr/bin/systemctl enable --now acornfox-host-bootstrap.service
  clean_output /usr/bin/systemctl is-enabled --quiet acornfox-host-bootstrap.service || fail
  clean_output /usr/bin/systemctl is-active --quiet acornfox-host-bootstrap.service || fail
fi

printf '{"code":"installed","ok":true,"schema_version":1}\n'
