#!/usr/bin/env bash
set -euo pipefail
die() { printf 'open-card host-preflight: %s\n' "$*" >&2; exit 2; }
mode= task_root=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-prerequisites-pending) [[ -z "$mode" ]] || die "preflight modes conflict"; mode=early; shift ;;
    --post-prerequisites) [[ -z "$mode" ]] || die "preflight modes conflict"; mode=post; shift ;;
    --task-fixture-root) [[ $# -gt 1 ]] || die "--task-fixture-root requires a value"; task_root=$2; shift 2 ;;
    *) die "unsupported option $1" ;;
  esac
done
[[ -n "$mode" ]] || mode=early
if [[ -n "$task_root" ]]; then
  [[ "${OPEN_CARD_HOST_PREFLIGHT_TEST:-}" = 1 ]] || die "task fixture seam is disabled"
  [[ "$task_root" = /* && -d "$task_root" && ! -L "$task_root" ]] || die "task fixture root must be a real absolute directory"
fi
fact() { local n=$1 c=$2 p; if [[ -n "$task_root" ]]; then p="$task_root/$n"; [[ -f "$p" && ! -L "$p" ]] || die "task fixture is missing or unsafe: $n"; cat -- "$p"; else eval "$c"; fi; }
num() { [[ "$1" =~ ^[0-9]+$ ]]; }
zero() { num "$1" && printf '%s' "$1" || printf 0; }
os_release=$(fact os-release 'cat /etc/os-release'); architecture=$(fact architecture 'uname -m'); vcpus=$(fact vcpus 'nproc'); meminfo=$(fact meminfo 'cat /proc/meminfo')
root_df=$(fact root.df 'df -Pk / | tail -n 1'); inode_df=$(fact root.inodes 'df -Pi / | tail -n 1'); time_state=$(fact time 'timedatectl show --property=NTPSynchronized --value 2>/dev/null || true')
docker_state=$(fact docker 'if command -v docker >/dev/null 2>&1; then printf "available:%s:%s" "$(docker info --format "{{.DockerRootDir}}" 2>/dev/null || true)" "$(docker ps -aq 2>/dev/null | wc -l)"; else printf missing; fi')
listeners=$(fact listeners 'if command -v ss >/dev/null 2>&1; then ss -H -ltn 2>/dev/null || true; else printf unavailable; fi')
services=$(fact services 'for u in docker postgresql nginx apache2 caddy k3s kubelet open-card-server open-card-agent open-card-buildkit open-card-caddy open-card-edge; do if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$u.service"; then printf "%s\n" "$u"; fi; done')
reasons=(); fail() { reasons+=("$1"); }
[[ "$architecture" = x86_64 ]] || fail architecture
grep -qx 'ID=ubuntu' <<<"$os_release" && grep -qx 'VERSION_ID="24.04"' <<<"$os_release" || fail os
num "$vcpus" || fail vcpus_format; num "$vcpus" && (( vcpus >= 4 )) || fail vcpus
mem_total=$(awk '/^MemTotal:/ {print $2}' <<<"$meminfo"); mem_available=$(awk '/^MemAvailable:/ {print $2}' <<<"$meminfo")
num "$mem_total" && num "$mem_available" || fail memory_format; num "$mem_total" && num "$mem_available" && (( mem_total >= 8388608 && mem_available * 100 >= mem_total * 30 )) || fail memory
read -r _ root_total _ root_free _ _ <<<"$root_df"; read -r _ inode_total _ inode_free _ _ <<<"$inode_df"
num "$root_total" && num "$root_free" || fail disk_format; num "$inode_total" && num "$inode_free" || fail inode_format
num "$root_total" && num "$root_free" && (( root_total >= 104857600 && root_free >= 73400320 && root_free * 100 >= root_total * 30 )) || fail disk
num "$inode_total" && num "$inode_free" && (( inode_total > 0 && inode_free * 100 >= inode_total * 30 )) || fail inodes
[[ "$time_state" = yes ]] || fail time_sync
docker_kind=missing docker_containers=0
if [[ "$docker_state" != missing ]]; then IFS=: read -r docker_kind docker_root docker_containers <<<"$docker_state"; [[ "$docker_kind" = available && "$docker_root" = /* && "$docker_containers" =~ ^[0-9]+$ ]] || fail docker_format; num "$docker_containers" && (( docker_containers == 0 )) || fail existing_containers; elif [[ "$mode" = post ]]; then fail docker_prerequisite; fi
listener_conflicts=0 listener_format=0
if [[ "$listeners" = unavailable ]]; then fail listeners_unavailable; else while IFS= read -r line; do [[ -z "$line" ]] && continue; local_address=$(awk '{print $4}' <<<"$line"); [[ -n "$local_address" ]] || { listener_format=1; continue; }; port=${local_address##*:}; [[ "$port" =~ ^[0-9]+$ ]] || { listener_format=1; continue; }; allowed=0; [[ "$port" = 22 ]] && allowed=1; [[ "$mode" = post && "$port" = 5432 && ( "$local_address" = 127.0.0.1:5432 || "$local_address" = '[::1]:5432' ) ]] && allowed=1; (( allowed )) || listener_conflicts=$((listener_conflicts + 1)); done <<<"$listeners"; fi
(( listener_format == 0 )) || fail listeners_format; (( listener_conflicts == 0 )) || fail listeners
service_conflicts=0; while IFS= read -r service; do
  [[ -z "$service" ]] && continue
  allowed=0
  [[ "$service" = docker ]] && allowed=1
  [[ "$mode" = post && "$service" = postgresql ]] && allowed=1
  (( allowed )) || service_conflicts=$((service_conflicts + 1))
done <<<"$services"; (( service_conflicts == 0 )) || fail existing_services
status=pass; (( ${#reasons[@]} == 0 )) || status=fail
reason_lines=
if (( ${#reasons[@]} > 0 )); then reason_lines=$(printf '%s\n' "${reasons[@]}"); fi
python3 - "$status" "$mode" "$architecture" "$(zero "$vcpus")" "$(zero "$mem_total")" "$(zero "$mem_available")" "$(zero "$root_total")" "$(zero "$root_free")" "$(zero "$inode_total")" "$(zero "$inode_free")" "$docker_kind" "$(zero "$docker_containers")" "$listener_conflicts" "$service_conflicts" "$([[ "$time_state" = yes ]] && echo true || echo false)" "$reason_lines" <<'PY'
import json, sys
s,m,a,c,mt,ma,dt,df,it,inf,d,dc,lc,sc,ntp,r=sys.argv[1:]
print(json.dumps({"schema_version":1,"status":s,"mode":m,"architecture":a,"vcpus":int(c),"memory_total_kib":int(mt),"memory_available_kib":int(ma),"root_total_kib":int(dt),"root_free_kib":int(df),"inode_total":int(it),"inode_free":int(inf),"time_synchronized":ntp=="true","docker":d,"docker_containers":int(dc),"listener_conflicts":int(lc),"service_conflicts":int(sc),"reasons":[x for x in r.splitlines() if x]}, separators=(",",":")))
PY
[[ "$status" = pass ]] || exit 1
