#!/usr/bin/env bash
set -euo pipefail
umask 077

die() { printf '%s\n' invalid_gate6_evidence >&2; exit 2; }

phase= identity= app_host= cookie= confirmation= task_root= sse_last_event_id=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase) [[ $# -gt 1 ]] || die; phase=$2; shift 2 ;;
    --identity) [[ $# -gt 1 ]] || die; identity=$2; shift 2 ;;
    --app-host) [[ $# -gt 1 ]] || die; app_host=$2; shift 2 ;;
    --session-cookie-file) [[ $# -gt 1 ]] || die; cookie=$2; shift 2 ;;
    --sse-last-event-id) [[ $# -gt 1 ]] || die; sse_last_event_id=$2; shift 2 ;;
    --confirm) [[ $# -gt 1 ]] || die; confirmation=$2; shift 2 ;;
    --task-root) [[ $# -gt 1 ]] || die; task_root=$2; shift 2 ;;
    *) die ;;
  esac
done
[[ "$phase" =~ ^(snapshot-preinstall|install-verify|restart-drill|reboot-handoff|reboot-verify)$ ]] || die
[[ "$identity" = /* && -f "$identity" && ! -L "$identity" ]] || die

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
release_root=$(cd -- "$script_dir/../.." && pwd -P)
builder="$release_root/tools/evidence/g6_target_receipt.py"
[[ -f "$builder" && ! -L "$builder" ]] || die

task=0 expected_uid=0
if [[ -n "$task_root" ]]; then
  [[ "${OPEN_CARD_G6_STAGING_TEST:-}" = 1 && "$task_root" = /* && "$task_root" != / && -d "$task_root" && ! -L "$task_root" ]] || die
  [[ "$(cd -- "$task_root" && pwd -P)" = "$task_root" ]] || die
  task=1; expected_uid=$EUID
else
  [[ "$EUID" -eq 0 ]] || die
fi

identity_values=$(/usr/bin/python3 - "$identity" "$expected_uid" "$(dirname "$builder")" <<'PY'
import json, os, re, stat, sys
from pathlib import Path
path, uid, module_root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sys.path.insert(0,module_root)
import g6_target_receipt as builder
try:
    value=builder.strict(Path(path),uid)
    validated=builder.identity(value,uid)
    run=validated["run_id"]; source=validated["source"]
    installation=value.get("installation_id_file","")
    print(run); print(installation); print(source["tag"]); print(source["commit"]); print(source["bundle_manifest_sha256"]); print(validated.get("installation_id_sha256",""))
except Exception: raise SystemExit(2)
PY
) || die
run_id=$(sed -n '1p' <<<"$identity_values")
installation_file=$(sed -n '2p' <<<"$identity_values")
source_tag=$(sed -n '3p' <<<"$identity_values")
source_commit=$(sed -n '4p' <<<"$identity_values")
bundle_sha=$(sed -n '5p' <<<"$identity_values")
installation_sha=$(sed -n '6p' <<<"$identity_values")

if (( task )); then
  evidence_root="$task_root/var/lib/open-card/evidence/gate6/$run_id"
  fixture_root="$task_root/fixtures"
  host_receipt="$fixture_root/host-preflight.json"
else
  evidence_root="/var/lib/open-card/evidence/gate6/$run_id"
  fixture_root=
  host_receipt=/var/lib/open-card/evidence/host-preflight.json
fi
if [[ -e "$evidence_root" || -L "$evidence_root" ]]; then
  [[ -d "$evidence_root" && ! -L "$evidence_root" ]] || die
  /usr/bin/python3 - "$evidence_root" "$expected_uid" <<'PY' || exit 2
import os,stat,sys
s=os.lstat(sys.argv[1])
if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=int(sys.argv[2]) or stat.S_IMODE(s.st_mode)!=0o700: raise SystemExit(2)
PY
else
  /usr/bin/install -d -m 0700 "$evidence_root"
fi
scratch=$(/usr/bin/mktemp -d "$evidence_root/.collect-$phase.XXXXXX")
cleanup() { /bin/rm -rf -- "$scratch"; }
trap cleanup EXIT

phase_dir="$evidence_root/$phase"
receipt="$phase_dir/receipt.json"
previous=
case "$phase" in
  snapshot-preinstall) [[ "$confirmation" = G6-SNAPSHOT-READONLY && -z "$installation_file" && -z "$cookie" ]] || die ;;
  install-verify) previous="$evidence_root/snapshot-preinstall/receipt.json" ;;
  restart-drill) previous="$evidence_root/install-verify/receipt.json" ;;
  reboot-handoff) previous="$evidence_root/restart-drill/receipt.json" ;;
  reboot-verify) previous="$evidence_root/reboot-handoff/receipt.json" ;;
esac

validate_secure_file() {
  /usr/bin/python3 - "$1" "$expected_uid" "$2" <<'PY'
import os,stat,sys
path,uid,mode=sys.argv[1],int(sys.argv[2]),int(sys.argv[3],8)
try:
 s=os.lstat(path)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=mode: raise ValueError
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); opened=os.fstat(fd); os.close(fd)
 if (opened.st_dev,opened.st_ino)!=(s.st_dev,s.st_ino): raise ValueError
except Exception: raise SystemExit(2)
PY
}

validate_host_receipt() {
  /usr/bin/python3 - "$1" "$2" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8")); mode=sys.argv[2]
required={"schema_version","status","mode","architecture","vcpus","memory_total_kib","memory_available_kib","root_total_kib","root_free_kib","inode_total","inode_free","time_synchronized","docker","docker_containers","listener_conflicts","service_conflicts","reasons"}
if set(value)!=required or value["schema_version"]!=1 or value["status"]!="pass" or value["mode"]!=mode or value["architecture"]!="x86_64" or value["vcpus"]<4: raise SystemExit(2)
if value["memory_total_kib"]<8388608 or value["memory_available_kib"]*100<value["memory_total_kib"]*30: raise SystemExit(2)
if value["root_total_kib"]<104857600 or value["root_free_kib"]<73400320 or value["root_free_kib"]*100<value["root_total_kib"]*30: raise SystemExit(2)
if value["inode_total"]<=0 or value["inode_free"]*100<value["inode_total"]*30 or value["time_synchronized"] is not True: raise SystemExit(2)
if value["docker_containers"]!=0 or value["listener_conflicts"]!=0 or value["service_conflicts"]!=0 or value["reasons"]!=[]: raise SystemExit(2)
if mode=="post" and value["docker"]!="available": raise SystemExit(2)
if mode=="early" and value["docker"] not in {"available","missing"}: raise SystemExit(2)
PY
}

restart_marker="$evidence_root/.restart-drill.in-progress"
manage_restart_marker() {
  /usr/bin/python3 - "$1" "$restart_marker" "$evidence_root" "$expected_uid" "$run_id" "$confirmation_sha" <<'PY'
import json,os,stat,sys,tempfile
action,target,parent,uid,run,digest=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5],sys.argv[6]
raw=(json.dumps({"run_id":run,"confirmation_sha256":digest},sort_keys=True,separators=(",",":"))+"\n").encode()
def syncdir():
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)
if action=="create":
 if os.path.lexists(target): raise SystemExit(2)
 fd,tmp=tempfile.mkstemp(prefix=".restart-drill.",dir=parent)
 try:
  with os.fdopen(fd,"wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(),0o600); os.fchown(stream.fileno(),uid,os.getgid() if uid else 0); os.fsync(stream.fileno())
  os.link(tmp,target,follow_symlinks=False); os.unlink(tmp); syncdir()
 finally:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
else:
 s=os.lstat(target)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=0o600: raise SystemExit(2)
 fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
 try: existing=os.read(fd,4096)
 finally: os.close(fd)
 if existing!=raw: raise SystemExit(2)
 os.unlink(target); syncdir()
PY
}

installation_raw=
confirmation_sha=
if [[ "$phase" != snapshot-preinstall ]]; then
  [[ "$installation_file" = /* ]] || die
  validate_secure_file "$installation_file" 0600 || die
  installation_raw=$(/bin/cat -- "$installation_file")
  [[ -n "$installation_raw" && "$installation_raw" != *$'\n'* && "$installation_raw" != *$'\r'* ]] || die
  case "$phase" in
    install-verify) [[ "$confirmation" = G6-INSTALL-VERIFY-READONLY ]] || die ;;
    restart-drill) [[ "$confirmation" = "G6:restart-services:$installation_raw" ]] || die ;;
    reboot-handoff) [[ "$confirmation" = "G6:reboot:$installation_raw" ]] || die ;;
    reboot-verify) [[ "$confirmation" = G6-REBOOT-VERIFY-READONLY ]] || die ;;
  esac
  if [[ -x /usr/bin/sha256sum ]]; then
    confirmation_sha=$(printf '%s' "$confirmation" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
  else
    confirmation_sha=$(printf '%s' "$confirmation" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')
  fi
  [[ "$app_host" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || die
  [[ "$sse_last_event_id" =~ ^evt-[0-9]+$ ]] || die
  [[ "$cookie" = /* ]] || die
  validate_secure_file "$cookie" 0600 || die
  [[ -f "$previous" && ! -L "$previous" ]] || die
  /usr/bin/python3 - "$previous" "$expected_uid" "$(dirname "$builder")" "$run_id" "$source_tag" "$source_commit" "$bundle_sha" "$installation_sha" "$phase" <<'PY' || exit 2
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[3]); import g6_validate as g6
receipt=g6.receipt_from_path(Path(sys.argv[1]),owner=int(sys.argv[2]))
expected={"install-verify":"SNAPSHOT_PREINSTALL","restart-drill":"INSTALL_VERIFY","reboot-handoff":"RESTART_DRILL","reboot-verify":"REBOOT_HANDOFF"}[sys.argv[9]]
if receipt["phase"]!=expected or receipt["run_id"]!=sys.argv[4] or receipt["source"]!={"tag":sys.argv[5],"commit":sys.argv[6],"bundle_manifest_sha256":sys.argv[7]}: raise SystemExit(2)
if expected!="SNAPSHOT_PREINSTALL" and receipt.get("installation_id_sha256")!=sys.argv[8]: raise SystemExit(2)
phase_root=Path(sys.argv[1]).parent
if {entry.relative_to(phase_root).as_posix() for entry in phase_root.iterdir()}!={"receipt.json",*(item["path"] for item in receipt["artifacts"])}: raise SystemExit(2)
PY
fi

copy_fixture() {
  local name=$1 destination=$2
  [[ -n "$fixture_root" && -f "$fixture_root/$name" && ! -L "$fixture_root/$name" ]] || die
  /usr/bin/install -m 0600 "$fixture_root/$name" "$destination"
}

if [[ -f "$receipt" && ! -L "$receipt" ]]; then
  /usr/bin/python3 - "$receipt" "$scratch/facts.json" <<'PY' || exit 2
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
json.dump(value["facts"],open(sys.argv[2],"w",encoding="utf-8"),separators=(",",":"))
PY
  declarations=()
  if [[ "$phase" = snapshot-preinstall ]]; then names=(host-preflight.json); else names=(host-preflight.json listeners.txt processes.txt api.json sse.ndjson app-route.json); fi
  for name in "${names[@]}"; do declarations+=(--artifact "$name=$phase_dir/$name"); done
else
  if [[ "$phase" = snapshot-preinstall ]]; then
    if (( task )); then
      copy_fixture host-preflight-pending.json "$scratch/host-preflight.json"
    else
      "$script_dir/host-preflight.sh" --allow-prerequisites-pending >"$scratch/host-preflight.json"
    fi
    validate_host_receipt "$scratch/host-preflight.json" early || die
    if (( task )); then
      [[ ! -e "$fixture_root/existing-installation" && ! -L "$fixture_root/existing-installation" ]] || die
    else
      for existing in /opt/open-card/current /opt/open-card/active /var/lib/open-card/installation-id /etc/open-card/server.env; do [[ ! -e "$existing" && ! -L "$existing" ]] || die; done
    fi
    /usr/bin/python3 - "$scratch/host-preflight.json" "$scratch/facts.json" <<'PY' || die
import hashlib,json,sys
raw=open(sys.argv[1],"rb").read(); value=json.loads(raw)
if value.get("schema_version")!=1 or value.get("status")!="pass" or value.get("mode")!="early": raise SystemExit(2)
facts={"host_preflight_sha256":hashlib.sha256(raw).hexdigest(),"existing_installation":False,"colocated_workloads":False,"source_tag_verified":True,"bundle_manifest_verified":True}
json.dump(facts,open(sys.argv[2],"w",encoding="utf-8"),separators=(",",":"))
PY
    declarations=(--artifact "host-preflight.json=$scratch/host-preflight.json")
  else
    if [[ "$phase" = restart-drill ]]; then
      manage_restart_marker create || die
      if (( task )); then
        printf '%s\n' open-card-buildkit.service open-card-server.service open-card-agent.service open-card-caddy.service open-card-edge.service >>"$task_root/restart-actions.log"
      else
        for unit in open-card-buildkit.service open-card-server.service open-card-agent.service open-card-caddy.service; do /usr/bin/systemctl restart "$unit"; done
        /usr/bin/systemctl restart open-card-edge.service
      fi
    fi
    validate_secure_file "$host_receipt" 0600 || die
    /usr/bin/install -m 0600 "$host_receipt" "$scratch/host-preflight.json" || die
    validate_host_receipt "$scratch/host-preflight.json" post || die
    if (( task )); then
      for name in listeners.txt processes.txt api.json sse.ndjson app-route.json state.json; do copy_fixture "$name" "$scratch/$name"; done
      /usr/bin/python3 - "$scratch/api.json" "$scratch/sse.ndjson" "$scratch/app-route.json" "$sse_last_event_id" "$app_host" <<'PY' || die
import json,sys
api=json.load(open(sys.argv[1],encoding="utf-8")); sse=json.loads(open(sys.argv[2],encoding="utf-8").read()); app=json.load(open(sys.argv[3],encoding="utf-8"))
if api.get("authenticated") is not True: raise SystemExit(2)
if sse.get("http_status")!=200 or sse.get("content_type")!="text/event-stream" or sse.get("request_last_event_id")!=sys.argv[4] or not isinstance(sse.get("event_count"),int) or sse["event_count"]<1 or not sse.get("replayed"): raise SystemExit(2)
if app.get("http_status")!=200 or app.get("host")!=sys.argv[5]: raise SystemExit(2)
PY
    else
      /usr/bin/ss -lntup >"$scratch/listeners.txt"
      /usr/bin/ps -eo pid=,user=,comm= >"$scratch/processes.txt"
      /usr/bin/curl --fail --silent --show-error http://127.0.0.1:8080/readyz >"$scratch/ready.json"
      /usr/bin/curl --fail --silent --show-error --cookie "$cookie" http://127.0.0.1:8080/api/v1/auth/session >"$scratch/api.json"
      /usr/bin/python3 - "$scratch/api.json" <<'PY' || die
import json,sys
v=json.load(open(sys.argv[1],encoding="utf-8"))
if v.get("authenticated") is not True: raise SystemExit(2)
PY
      set +e
      sse_status=$(/usr/bin/curl --silent --show-error --no-buffer --max-time 3 --dump-header "$scratch/sse.headers" --output "$scratch/sse.body" --cookie "$cookie" --header "Last-Event-ID: $sse_last_event_id" --write-out '%{http_code}' http://127.0.0.1:8080/api/v1/events)
      sse_rc=$?
      set -e
      [[ "$sse_status" = 200 && ( "$sse_rc" -eq 0 || "$sse_rc" -eq 28 ) ]] || die
      /usr/bin/grep -Eiq '^content-type:[[:space:]]*text/event-stream' "$scratch/sse.headers" || die
      /usr/bin/python3 - "$scratch/sse.body" "$scratch/sse.ndjson" "$sse_last_event_id" <<'PY' || die
import hashlib,json,re,sys
raw=open(sys.argv[1],"rb").read(); text=raw.decode("utf-8"); requested=int(sys.argv[3].removeprefix("evt-")); events=[]
for frame in text.split("\n\n"):
 lines=frame.splitlines(); fields={line.split(":",1)[0]:line.split(":",1)[1].lstrip() for line in lines if ":" in line and not line.startswith(":")}
 if {"id","event","data"}<=set(fields) and fields["event"]=="message" and re.fullmatch(r"evt-[0-9]+",fields["id"]):
  json.loads(fields["data"]); events.append(fields["id"])
if not events or not any(int(item.removeprefix("evt-"))>requested for item in events): raise SystemExit(2)
summary={"http_status":200,"content_type":"text/event-stream","request_last_event_id":sys.argv[3],"first_event_id":events[0],"event_count":len(events),"replayed":True,"body_sha256":hashlib.sha256(raw).hexdigest()}
open(sys.argv[2],"w",encoding="utf-8").write(json.dumps(summary,separators=(",",":"))+"\n")
PY
      app_status=$(/usr/bin/curl --silent --show-error --output "$scratch/app.body" --write-out '%{http_code}' --header "Host: $app_host" http://127.0.0.1:18481/)
      [[ "$app_status" = 200 ]] || die
      /usr/bin/python3 - "$scratch/app.body" "$scratch/app-route.json" "$app_host" <<'PY'
import hashlib,json,sys
raw=open(sys.argv[1],"rb").read(); json.dump({"http_status":200,"host":sys.argv[3],"body_sha256":hashlib.sha256(raw).hexdigest()},open(sys.argv[2],"w",encoding="utf-8"),separators=(",",":"))
PY
      units=(open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service)
      unit_json=
      for unit in "${units[@]}"; do /usr/bin/systemctl is-active --quiet "$unit" && /usr/bin/systemctl is-enabled --quiet "$unit" || die; unit_json+="$unit"$'\n'; done
      /usr/bin/systemctl is-active --quiet open-card-upgrade-safe.target && /usr/bin/systemctl is-enabled --quiet open-card-upgrade-safe.target || die
      active_pointer=$(/usr/bin/readlink /opt/open-card/active); current_pointer=$(/usr/bin/readlink /opt/open-card/current); previous_pointer=
      [[ ! -L /opt/open-card/previous-active ]] || previous_pointer=$(/usr/bin/readlink /opt/open-card/previous-active)
      [[ ! -e /var/lib/open-card/upgrade-in-progress && ! -L /var/lib/open-card/upgrade-in-progress ]] || die
      boot_id=$(/bin/cat /proc/sys/kernel/random/boot_id)
      /usr/bin/python3 - "$scratch/state.json" "$unit_json" "$active_pointer" "$current_pointer" "$previous_pointer" "$boot_id" <<'PY'
import json,sys
path,units,active,current,previous,boot=sys.argv[1:]
names=[name for name in units.splitlines() if name]
json.dump({"units":{name:{"active":True,"enabled":True} for name in names},"upgrade_safe_target_active":True,"upgrade_safe_target_enabled":True,"active_pointer":active,"current_pointer":current,"previous_active_pointer":previous,"upgrade_marker_absent":True,"boot_id":boot},open(path,"w",encoding="utf-8"),separators=(",",":"))
PY
    fi
    /usr/bin/python3 - "$phase" "$scratch/state.json" "$scratch/facts.json" "$confirmation_sha" "$source_tag" "$source_commit" "$bundle_sha" "$scratch/host-preflight.json" "$scratch/listeners.txt" "$scratch/processes.txt" "$scratch/api.json" "$scratch/sse.ndjson" "$scratch/app-route.json" <<'PY' || die
import hashlib,json,sys
phase,state_path,out,confirmation,tag,commit,bundle,*paths=sys.argv[1:]
state=json.load(open(state_path,encoding="utf-8"))
names=("host_preflight_sha256","listeners_sha256","processes_sha256","api_sha256","sse_sha256","app_route_sha256")
facts={key:hashlib.sha256(open(path,"rb").read()).hexdigest() for key,path in zip(names,paths)}
facts.update({key:state[key] for key in ("units","upgrade_safe_target_active","upgrade_safe_target_enabled","active_pointer","current_pointer","previous_active_pointer","upgrade_marker_absent")})
if phase=="restart-drill": facts.update({"action":"restart_services","confirmation_sha256":confirmation})
if phase in {"reboot-handoff","reboot-verify"}: facts.update({"boot_id":state["boot_id"],"confirmation_sha256":confirmation,"source_tag":tag,"source_commit":commit,"bundle_manifest_sha256":bundle})
json.dump(facts,open(out,"w",encoding="utf-8"),separators=(",",":"))
PY
    declarations=()
    for name in host-preflight.json listeners.txt processes.txt api.json sse.ndjson app-route.json; do declarations+=(--artifact "$name=$scratch/$name"); done
  fi
fi

args=(publish --phase "$phase" --identity "$identity" --facts "$scratch/facts.json" --output-dir "$evidence_root")
args+=("${declarations[@]}")
if [[ "$phase" = reboot-verify ]]; then args+=(--handoff-receipt "$previous"); elif [[ -n "$previous" ]]; then args+=(--previous-receipt "$previous"); fi
result=$(/usr/bin/python3 "$builder" "${args[@]}") || die
if [[ "$phase" = restart-drill && ( -e "$restart_marker" || -L "$restart_marker" ) ]]; then manage_restart_marker remove || die; fi
printf '%s\n' "$result"
