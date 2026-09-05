#!/usr/bin/env bash
# AcornFox host preflight is deliberately read-only. It validates only the
# fixed first-release platform contract; it neither sizes nor mutates a host.
set -euo pipefail

readonly CLEAN_ENV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C)

usage() {
  printf '%s\n' 'usage: host-preflight.sh --phase pre|post'
}

bad_args() {
  printf '%s\n' 'acornfox host-preflight: invalid arguments' >&2
  exit 2
}

fail() {
  printf '{"architecture":"unknown","code":"eligibility_failed","ok":false,"os_id":"unknown","os_version":"unknown","phase":"%s","prerequisites":"unchecked","schema_version":1,"systemd":"unknown"}\n' "${phase:-unknown}"
  exit 23
}

clean() {
  "${CLEAN_ENV[@]}" "$@"
}

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -ne 2 || $1 != --phase || ( $2 != pre && $2 != post ) ]]; then
  bad_args
fi
phase=$2

[[ ${EUID:-1} -eq 0 ]] || fail
[[ -r /etc/os-release ]] || fail
if ! clean /usr/bin/grep -qx 'ID=ubuntu' /etc/os-release || ! clean /usr/bin/grep -Eq '^VERSION_ID="?24\.04"?$' /etc/os-release; then
  fail
fi
[[ $(clean /usr/bin/uname -m) == x86_64 ]] || fail
clean /usr/bin/systemctl --version >/dev/null || fail
[[ $(clean /usr/bin/systemctl is-system-running) == running ]] || fail

if [[ $phase == post ]]; then
  docker_version=$(clean /usr/bin/docker --version) || fail
  psql_version=$(clean /usr/bin/psql --version) || fail
  postgres_version=$(clean /usr/lib/postgresql/16/bin/postgres --version) || fail
  [[ $docker_version == Docker\ version\ * ]] || fail
  [[ $psql_version == psql\ \(PostgreSQL\)\ 16.* ]] || fail
  [[ $postgres_version == postgres\ \(PostgreSQL\)\ 16.* ]] || fail
  clean /usr/bin/systemctl is-enabled --quiet docker.service || fail
  clean /usr/bin/systemctl is-active --quiet docker.service || fail
  clean /usr/bin/systemctl is-enabled --quiet postgresql.service || fail
  clean /usr/bin/systemctl is-active --quiet postgresql.service || fail

  for account in acornfox acornfox-agent acornfox-buildkit acornfox-caddy acornfox-edge; do
    record=$(clean /usr/bin/getent passwd "$account") || fail
    IFS=: read -r name _ uid gid _ home shell <<<"$record"
    [[ $name == "$account" && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $home == /nonexistent && $shell == /usr/sbin/nologin ]] || fail
    group_record=$(clean /usr/bin/getent group "$account") || fail
    IFS=: read -r group_name _ group_gid group_members <<<"$group_record"
    [[ $group_name == "$account" && $group_gid == "$gid" && -z $group_members ]] || fail
  done
  [[ $(clean /usr/bin/stat -c '%u:%g:%a:%F' /var/lib/acornfox/install) == '0:0:700:directory' ]] || fail
  clean /usr/bin/grep -qx 'acornfox-buildkit:231072:65536' /etc/subuid || fail
  clean /usr/bin/grep -qx 'acornfox-buildkit:231072:65536' /etc/subgid || fail
fi

if [[ $phase == pre ]]; then
  prerequisites=unchecked
else
  prerequisites=ready
fi
printf '{"architecture":"amd64","code":"ok","ok":true,"os_id":"ubuntu","os_version":"24.04","phase":"%s","prerequisites":"%s","schema_version":1,"systemd":"running"}\n' "$phase" "$prerequisites"
