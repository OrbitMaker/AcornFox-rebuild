#!/usr/bin/env bash
# The migration algorithm belongs to the installed AcornFox helper. This
# wrapper intentionally has no SQL, archive, or recovery implementation.
set -euo pipefail

readonly CLEAN_ENV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C)
readonly HELPER=/opt/acornfox/upgrade-tools/acornfox-upgrade

usage() {
  printf '%s\n' 'usage: control-plane-migrate.sh --pending'
}

bad_args() {
  printf '%s\n' 'acornfox control-plane-migrate: invalid arguments' >&2
  exit 2
}

fail() {
  printf '%s\n' 'acornfox control-plane-migrate: helper guard failed' >&2
  exit 23
}

safe_helper() {
  local detail
  [[ ! -L $HELPER && -f $HELPER ]] || return 1
  detail=$("${CLEAN_ENV[@]}" /usr/bin/stat -c '%u:%g:%a:%F:%h' -- "$HELPER") || return 1
  [[ $detail == '0:0:755:regular file:1' ]]
}

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -ne 1 || $1 != --pending ]]; then
  bad_args
fi
[[ $(/usr/bin/id -u) -eq 0 ]] || fail
safe_helper || fail

exec "${CLEAN_ENV[@]}" "$HELPER" migrate-control-plane --pending
