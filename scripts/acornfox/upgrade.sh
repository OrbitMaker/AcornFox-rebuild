#!/usr/bin/env bash
# Upgrade authority belongs to the next detached helper, not the currently
# installed binary.  12B-SUCCESSOR supplies repository-upgrade itself.
set -euo pipefail

readonly CLEAN_ENV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C)

usage() {
  printf '%s\n' 'usage: upgrade.sh --candidate-dir ABS --next-binding-sha256 HEX --current-binding-sha256 HEX --successor-helper ABS --successor-helper-sha256 HEX'
}

bad_args() {
  printf '%s\n' 'acornfox upgrade: invalid arguments' >&2
  exit 2
}

fail() {
  printf '%s\n' 'acornfox upgrade: input guard failed' >&2
  exit 23
}

clean() {
  "${CLEAN_ENV[@]}" "$@"
}

is_sha256() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

safe_candidate_dir() {
  local detail mode
  [[ $1 == /* && $1 != / && ! -L $1 && -d $1 ]] || return 1
  detail=$(clean /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$1") || return 1
  [[ $detail =~ ^0:0:[0-7]{3}:directory:2$ ]] || return 1
  mode=${detail#0:0:}
  mode=${mode%%:*}
  (( (8#$mode & 0022) == 0 ))
}

safe_helper() {
  local path=$1 expected=$2 detail actual
  [[ $path == /* && ! -L $path && -f $path ]] || return 1
  detail=$(clean /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$path") || return 1
  [[ $detail == '0:0:755:regular file:1' ]] || return 1
  actual=$(clean /usr/bin/sha256sum -- "$path") || return 1
  actual=${actual%% *}
  [[ $actual == "$expected" ]]
}

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -ne 10 || $1 != --candidate-dir || $3 != --next-binding-sha256 || $5 != --current-binding-sha256 || $7 != --successor-helper || $9 != --successor-helper-sha256 ]]; then
  bad_args
fi
candidate_dir=$2
next_binding_sha256=$4
current_binding_sha256=$6
successor_helper=$8
successor_helper_sha256=${10}
[[ $(/usr/bin/id -u) -eq 0 ]] || fail
is_sha256 "$next_binding_sha256" && is_sha256 "$current_binding_sha256" && is_sha256 "$successor_helper_sha256" || fail
[[ $next_binding_sha256 != "$current_binding_sha256" ]] || fail
safe_candidate_dir "$candidate_dir" || fail
safe_helper "$successor_helper" "$successor_helper_sha256" || fail

exec "${CLEAN_ENV[@]}" "$successor_helper" repository-upgrade --candidate-dir "$candidate_dir" --binding-sha256 "$next_binding_sha256" --current-binding-sha256 "$current_binding_sha256" --self-sha256 "$successor_helper_sha256"
