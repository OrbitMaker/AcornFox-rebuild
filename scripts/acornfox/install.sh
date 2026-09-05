#!/usr/bin/env bash
# This script is an input guard and a detached-helper handoff only. Candidate
# verification, journals and host materialization stay in acornfox-upgrade.
set -euo pipefail

readonly CLEAN_ENV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C)

usage() {
  printf '%s\n' 'usage: install.sh --candidate-dir ABS --binding-sha256 HEX --bootstrap-helper ABS --bootstrap-helper-sha256 HEX'
}

bad_args() {
  printf '%s\n' 'acornfox install: invalid arguments' >&2
  exit 2
}

fail() {
  printf '%s\n' 'acornfox install: input guard failed' >&2
  exit 23
}

clean() {
  "${CLEAN_ENV[@]}" "$@"
}

is_sha256() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

safe_candidate_dir() {
  local detail
  [[ $1 == /* && $1 != / && ! -L $1 && -d $1 ]] || return 1
  detail=$(clean /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$1") || return 1
  [[ $detail =~ ^0:0:[0-7]{3}:directory:2$ ]] || return 1
  local mode=${detail#0:0:}
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
if [[ $# -ne 8 || $1 != --candidate-dir || $3 != --binding-sha256 || $5 != --bootstrap-helper || $7 != --bootstrap-helper-sha256 ]]; then
  bad_args
fi
candidate_dir=$2
binding_sha256=$4
bootstrap_helper=$6
bootstrap_helper_sha256=$8
[[ $(/usr/bin/id -u) -eq 0 ]] || fail
is_sha256 "$binding_sha256" && is_sha256 "$bootstrap_helper_sha256" || fail
safe_candidate_dir "$candidate_dir" || fail
safe_helper "$bootstrap_helper" "$bootstrap_helper_sha256" || fail

exec "${CLEAN_ENV[@]}" "$bootstrap_helper" repository-bootstrap --candidate-dir "$candidate_dir" --binding-sha256 "$binding_sha256" --self-sha256 "$bootstrap_helper_sha256"
