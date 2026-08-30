#!/usr/bin/env bash
# Disposable Ubuntu guest only: real RC0 -> RC1 Gate5B production-wrapper
# success, V2 backup/restore, normal reboot, and ACTIVE_SWITCHED crash recovery.
# Public DNS/ACME and customer acceptance stay outside.
set -Eeuo pipefail
umask 077

mode=${1:-initial}
[[ "$mode" == initial || "$mode" == post-reboot ]]
scenario=${OPEN_CARD_G5B_PRODUCT_SCENARIO:-success}
[[ "$scenario" == success || "$scenario" == active-switch-crash ]]
prefix=${OPEN_CARD_G5B_PRODUCT_PREFIX:-opencard-g5b-20260830-a02}
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
source_root=${OPEN_CARD_G5B_PRODUCT_SOURCE_ROOT:-/home/ubuntu/g5b-product-source}
state="/var/lib/open-card/$prefix"
evidence="$state/evidence"
rc0="$source_root/candidates/rc0"
rc1="$source_root/candidates/rc1"
marker=/var/lib/open-card/upgrade-in-progress
tx="g5b-success-${prefix##*-}"
rc0_manifest_sha=3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253
rc0_archive_sha=abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc
rc0_bundle_sha=960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392
rc1_manifest_sha=fe0f3017eb4faa5ba329bc8f1fb1cb810eb334ab8cdc1fff5075d9069f93aaf1
rc1_archive_sha=9dfbed75ac4d5ec765f6518876b42abe0b80d6aa66d7fe5fb2b6900695473cc3
rc1_bundle_sha=cdc3c7f01d75371d9a186f810ca600f78ca190046a7c77956837f17cdd276936
rc1_source=cba392e00b64116b0ad87881a74e8f2e4d697e8c
edge_domain=console.g5b.invalid

[[ "$(id -u)" -eq 0 ]]
[[ -d "$source_root" && ! -L "$source_root" ]]
install -d -o root -g root -m 0700 "$state" "$evidence"
printf '%s\n' "$prefix" >"$state/.open-card-task-marker"
chmod 0600 "$state/.open-card-task-marker"

failure() {
  local code=$?
  trap - ERR
  printf 'guest_failure_phase=%s line=%s command=%q\n' "${phase:-unknown}" "${BASH_LINENO[0]:-unknown}" "${BASH_COMMAND:-unknown}" >&2
  systemctl --no-pager --full status postgresql docker open-card-upgrade-safe.target open-card-upgrade-recover.service open-card-upgrade-finalize.service open-card-server open-card-agent open-card-buildkit open-card-caddy open-card-edge >"$evidence/failure-systemctl.txt" 2>&1 || true
  journalctl -b --no-pager -u postgresql -u docker -u open-card-upgrade-safe.target -u open-card-upgrade-recover.service -u open-card-upgrade-finalize.service -u open-card-server -u open-card-agent -u open-card-buildkit -u open-card-caddy -u open-card-edge >"$evidence/failure-journal.txt" 2>&1 || true
  {
    for unit in open-card-upgrade-recover.service open-card-upgrade-safe.target open-card-upgrade-finalize.service open-card-edge.service open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service; do
      printf '[%s]\n' "$unit"
      systemctl show "$unit" --property=FragmentPath --property=DropInPaths --property=NeedDaemonReload --property=UnitFileState --property=ActiveState --property=Requires --property=Wants --property=Before --no-pager || true
    done
  } >"$evidence/failure-boot-properties.txt" 2>&1
  stat -c '%U:%G %a %F %n' /opt/open-card /var/lib/open-card /etc/open-card /etc/systemd/system /run /run/lock /run/lock/open-card-upgrade.lock >"$evidence/failure-upgrade-paths.txt" 2>&1 || true
  python3 - "$evidence/failure-upgrade-state.json" <<'PY' || true
import glob, hashlib, json, os, pathlib, re, sys
target = pathlib.Path(sys.argv[1])
value = {"journals": [], "links": {}, "files": {}}
for name in sorted(glob.glob("/var/lib/open-card/upgrade-transactions/*.json")):
    path = pathlib.Path(name)
    if path.is_symlink() or not path.is_file():
        continue
    journal = json.loads(path.read_text(encoding="utf-8"))
    value["journals"].append({key: journal.get(key) for key in (
        "transaction_id", "request_kind", "revision", "state", "failure",
        "old_activation_id", "candidate_activation_id", "candidate_database_name",
        "history",
    )})
for name in ("active", "previous-active", "current"):
    path = pathlib.Path("/opt/open-card") / name
    value["links"][name] = os.readlink(path) if path.is_symlink() else None
marker = pathlib.Path("/var/lib/open-card/upgrade-in-progress")
if marker.is_file() and not marker.is_symlink():
    raw = marker.read_text(encoding="ascii", errors="strict").strip()
    value["marker"] = raw if re.fullmatch(r"[A-Za-z0-9._-]+", raw) else "invalid"
for name in (
    "/etc/open-card/server.env",
    "/etc/systemd/system/open-card-server.service",
    "/etc/open-card/open-card-edge.Caddyfile",
):
    path = pathlib.Path(name)
    if path.is_file() and not path.is_symlink():
        value["files"][name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": oct(path.stat().st_mode & 0o777),
        }
value["activation_tree"] = []
activation_root = pathlib.Path("/opt/open-card/activations")
value["activation_collection"] = {"exists": activation_root.exists(), "symlink": activation_root.is_symlink()}
if activation_root.is_dir() and not activation_root.is_symlink():
    root_stat = activation_root.stat()
    value["activation_collection"].update({"mode": oct(root_stat.st_mode & 0o777), "uid": root_stat.st_uid, "gid": root_stat.st_gid})
    for path in sorted(activation_root.rglob("*")):
        entry = {"path": str(path.relative_to(activation_root))}
        if path.is_symlink():
            entry.update({"type": "symlink", "target": os.readlink(path)})
        elif path.is_dir():
            entry.update({"type": "directory", "mode": oct(path.stat().st_mode & 0o777)})
        elif path.is_file():
            entry.update({"type": "file", "mode": oct(path.stat().st_mode & 0o777), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        else:
            entry["type"] = "other"
        value["activation_tree"].append(entry)
target.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
  exit "$code"
}
trap failure ERR

sha256() { sha256sum -- "$1" | awk '{print $1}'; }
wait_active() {
  local unit=$1
  for _ in $(seq 1 240); do systemctl is-active --quiet "$unit" && return 0; sleep 0.25; done
  return 1
}
wait_http() {
  local url=$1
  for _ in $(seq 1 240); do curl --fail --silent --show-error "$url" >/dev/null 2>&1 && return 0; sleep 0.25; done
  return 1
}
http_code() { curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$1"; }
assert_edge_running() {
  wait_active open-card-edge.service
  [[ "$(systemctl is-enabled open-card-edge.service)" = enabled ]]
}
assert_edge_active() {
  assert_edge_running
  [[ "$(http_code http://127.0.0.1:18482/healthz)" = 200 ]]
  [[ "$(http_code http://127.0.0.1:18482/not-healthz)" = 404 ]]
}
assert_runtime_services() {
  local unit
  for unit in open-card-upgrade-safe.target open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service; do wait_active "$unit"; done
  test -S /run/open-card-buildkit/buildkitd.sock
  wait_http http://127.0.0.1:8080/readyz
  wait_http http://127.0.0.1:18481/readyz
  assert_edge_active
  [[ ! -e "$marker" && ! -L "$marker" ]]
}
run_active_switch_crash() {
  local wrapper_pid helper_pid watcher_pid tx candidate_id journal status journal_state i
  local -a helper_pids=()
  set +e
  env OPEN_CARD_ALLOW_SYSTEM_ROOT=1 bash "$rc1/release/scripts/mvp/upgrade.sh" --root / --offline --activate --expected-manifest-sha256 "$rc1_manifest_sha" --bundle "$rc1/release" --confirm-installation-id "UPGRADE:$(cat /var/lib/open-card/installation-id)" >"$evidence/production-upgrade.jsonl" 2>"$evidence/production-upgrade.stderr" &
  wrapper_pid=$!
  set -e
  for _ in $(seq 1 12000); do
    if grep -q '"command":"preflight"' "$evidence/production-upgrade.jsonl" 2>/dev/null; then
      read -r tx candidate_id < <(python3 - "$evidence/production-upgrade.jsonl" <<'PY'
import json,sys
values=[]
for line in open(sys.argv[1], encoding="utf-8"):
    try: values.append(json.loads(line))
    except ValueError: pass
values=[v for v in values if v.get("command") == "preflight" and v.get("ok") is True]
assert len(values) == 1
value=values[0]["eligibility"]
print(value["transaction_id"], value["candidate_activation_id"])
PY
)
      break
    fi
    kill -0 "$wrapper_pid" 2>/dev/null || break
    sleep 0.005
  done
  [[ "${tx:-}" =~ ^upgrade-[0-9a-f]{32}$ && "${candidate_id:-}" =~ ^act-[0-9a-f]{24}$ ]]
  journal="/var/lib/open-card/upgrade-transactions/$tx.json"
  for _ in $(seq 1 12000); do
    if grep -q '"state":"MIGRATED"' "$journal" 2>/dev/null; then
      mapfile -t helper_pids < <(pgrep -f "^/opt/open-card/upgrade-tools/open-card-upgrade run --transaction-id $tx ")
      [[ ${#helper_pids[@]} -eq 1 ]]
      helper_pid=${helper_pids[0]}
      kill -STOP "$helper_pid"
      break
    fi
    kill -0 "$wrapper_pid" 2>/dev/null || break
    sleep 0.005
  done
  [[ "${helper_pid:-}" =~ ^[0-9]+$ ]]
  (
    for ((i=0; i<200000; i++)); do
      if [[ "$(readlink /opt/open-card/active 2>/dev/null || true)" = "activations/$candidate_id" ]]; then
        kill -KILL "$helper_pid"
        exit 0
      fi
    done
    exit 1
  ) &
  watcher_pid=$!
  kill -CONT "$helper_pid"
  wait "$watcher_pid"
  set +e
  wait "$wrapper_pid"
  status=$?
  set -e
  [[ $status -ne 0 ]]
  journal_state=$(python3 - "$journal" <<'PY'
import json,sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["state"])
PY
)
  [[ "$journal_state" == VALIDATED || "$journal_state" == ACTIVE_SWITCHED ]]
  [[ "$(cat "$marker")" = "$tx" ]]
  printf '%s\n' "$tx" >"$state/crash-transaction-id"
  printf 'scenario=active-switch-crash\ntransaction_id=%s\njournal_state_before_reboot=%s\nmarker=retained\n' "$tx" "$journal_state" >"$evidence/crash-armed-summary.txt"
  printf 'G5B_PRODUCT_CRASH_ARMED=PASS\n'
}
post_reboot_crash() {
  local tx journal active previous old_activation candidate_activation old_database candidate_database db_password old_url
  phase=post_reboot_crash
  assert_runtime_services
  tx=$(cat "$state/crash-transaction-id")
  journal="/var/lib/open-card/upgrade-transactions/$tx.json"
  python3 - "$journal" <<'PY' >"$evidence/crash-recovery-journal.txt"
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["request_kind"] == "upgrade" and value["state"] == "ROLLED_BACK"
assert value["failure"]["code"] == "boot_recovered"
print("request_kind=upgrade")
print("state=ROLLED_BACK")
print("failure_code=boot_recovered")
PY
  active=$(readlink /opt/open-card/active)
  previous=$(readlink /opt/open-card/previous-active)
  [[ "$active" =~ ^activations/legacy-[0-9a-f]{24}$ && "$previous" =~ ^activations/act-[0-9a-f]{24}$ ]]
  old_activation=${active#activations/}
  candidate_activation=${previous#activations/}
  read -r old_database candidate_database < <(python3 - "/opt/open-card/activations/$old_activation/activation.json" "/opt/open-card/activations/$candidate_activation/activation.json" <<'PY'
import json,sys
old,candidate=[json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]
assert old["release"]["version"] == "0.8.0-rc.0" and old["database"]["migration"] == "0023"
assert candidate["release"]["version"] == "0.8.0-rc.1" and candidate["database"]["migration"] == "0024"
print(old["database"]["name"], candidate["database"]["name"])
PY
)
  db_password=$(cat /etc/open-card/postgres-password)
  old_url="postgresql://opencard:${db_password}@127.0.0.1:5432/${old_database}?sslmode=disable"
  [[ "$(psql "$old_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = rc0-before-upgrade ]]
  [[ "$(runuser -u postgres -- psql -d "$candidate_database" -X -Aqt -c 'SELECT count(*) FROM schema_migrations')" = 24 ]]
  [[ ! -e "$marker" && ! -L "$marker" ]]
  printf 'crash_recovery=PASS\njournal_state=ROLLED_BACK\nmarker=absent\nedge=active\ncandidate_retained=PASS\npublic_dns_acme_customer_acceptance=PENDING\n' >"$evidence/crash-recovery-summary.txt"
  ! grep -R -a -E 'postgres(ql)?://|OPEN_CARD_DATABASE_URL=|BEGIN [A-Z ]*PRIVATE KEY|password=' "$evidence"
  (cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >manifest.sha256)
  printf 'G5B_PRODUCT_CRASH_POST_REBOOT=PASS\n'
}
post_reboot() {
  if [[ "$scenario" == active-switch-crash ]]; then
    post_reboot_crash
    return
  fi
  local active restored_database db_password restored_url
  phase=post_reboot
  assert_runtime_services
  [[ "$(readlink /opt/open-card/current)" = active/release ]]
  active=$(readlink /opt/open-card/active)
  [[ "$active" =~ ^activations/(act|restore)-[0-9a-f]{24}$ ]]
  active=${active#activations/}
  restored_database=$(python3 - "/opt/open-card/activations/$active/activation.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["release"]["version"] == "0.8.0-rc.1" and value["database"]["migration"] == "0024"
print(value["database"]["name"])
PY
)
  db_password=$(cat /etc/open-card/postgres-password)
  restored_url="postgresql://opencard:${db_password}@127.0.0.1:5432/${restored_database}?sslmode=disable"
  [[ "$(psql "$restored_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = rc0-before-upgrade ]]
  systemctl --no-pager --full status open-card-upgrade-safe.target open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service open-card-edge.service >"$evidence/post-reboot-systemd.txt" 2>&1
  ss -ltnp >"$evidence/post-reboot-listeners.txt"
  grep -Eq ':(80|443|18482)[[:space:]]' "$evidence/post-reboot-listeners.txt"
  ! grep -R -a -E 'postgres(ql)?://|OPEN_CARD_DATABASE_URL=|BEGIN [A-Z ]*PRIVATE KEY|password=' "$evidence"
  printf 'post_reboot=PASS\nmarker=absent\nedge=active\n' >"$evidence/post-reboot-summary.txt"
  (cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >manifest.sha256)
  printf 'G5B_PRODUCT_POST_REBOOT=PASS\n'
}
verify_candidate() {
  local root=$1 version=$2 migration=$3 source=$4 manifest_sha=$5 archive_sha=$6 bundle_sha=$7
  [[ -d "$root/release" && ! -L "$root/release" ]]
  [[ -f "$root/release/manifest.json" && ! -L "$root/release/manifest.json" ]]
  [[ -f "$root/open-card-$version-production.tar.gz" && ! -L "$root/open-card-$version-production.tar.gz" ]]
  [[ -f "$root/bundle-manifest.sha256" && ! -L "$root/bundle-manifest.sha256" ]]
  [[ "$(sha256 "$root/release/manifest.json")" = "$manifest_sha" ]]
  [[ "$(sha256 "$root/open-card-$version-production.tar.gz")" = "$archive_sha" ]]
  [[ "$(sha256 "$root/bundle-manifest.sha256")" = "$bundle_sha" ]]
  python3 - "$root/release/manifest.json" "$version" "$migration" "$source" <<'PY'
import json, sys
path, version, migration, source = sys.argv[1:]
value = json.load(open(path, encoding="utf-8"))
assert value["release_id"] == "release-" + version
assert value["version"] == version and value["migration_version"] == migration
assert value["source_commit"] == source and value["architecture"] == "amd64"
PY
  tar -tzf "$root/open-card-$version-production.tar.gz" | LC_ALL=C sort >"$evidence/archive-$version-members.txt"
  ! grep -Eq '(^|/)\.DS_Store$' "$evidence/archive-$version-members.txt"
}

if [[ "$mode" = post-reboot ]]; then
  post_reboot
  exit 0
fi

phase=source_binding
test -f "$source_root/source-commit.txt" && ! test -L "$source_root/source-commit.txt"
test -f "$source_root/source-manifest.sha256" && ! test -L "$source_root/source-manifest.sha256"
test -f "$source_root/harness-commit.txt" && ! test -L "$source_root/harness-commit.txt"
(cd "$source_root" && sha256sum -c source-manifest.sha256) >"$evidence/source-manifest-check.txt" 2>&1
[[ "$(tr -d '\n' <"$source_root/source-commit.txt")" = "$rc1_source" ]]
[[ "$(tr -d '\n' <"$source_root/harness-commit.txt")" =~ ^[0-9a-f]{40}$ ]]
cp "$source_root/source-commit.txt" "$source_root/source-manifest.sha256" "$source_root/harness-commit.txt" "$evidence/"
chmod 0600 "$evidence/source-commit.txt" "$evidence/source-manifest.sha256" "$evidence/harness-commit.txt"

phase=candidate_verify
verify_candidate "$rc0" 0.8.0-rc.0 0023 35a2b198ac52949af3477475d89d4813b46a9490 "$rc0_manifest_sha" "$rc0_archive_sha" "$rc0_bundle_sha"
verify_candidate "$rc1" 0.8.0-rc.1 0024 "$rc1_source" "$rc1_manifest_sha" "$rc1_archive_sha" "$rc1_bundle_sha"
[[ -z "$(find "$rc0" "$rc1" -type l -print -quit)" ]]
# install.sh intentionally preserves bundle metadata.  The isolated transfer
# lands under ubuntu, so make the copied, already-hash-verified candidates
# root-controlled before staging; the privileged CLI later requires this.
chown -R root:root "$rc0" "$rc1"
python3 - "$rc1/release/manifest.json" <<'PY' >"$evidence/rc1-lineage.json"
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
want = {"version":"0.8.0-rc.0", "migration_version":"0023", "source_commit":"35a2b198ac52949af3477475d89d4813b46a9490", "release_manifest_sha256":"3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253", "archive_sha256":"abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc", "bundle_manifest_sha256":"960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392"}
assert value.get("n_minus_one") == want
print(json.dumps(want, sort_keys=True))
PY

phase=runtime_prerequisites
export DEBIAN_FRONTEND=noninteractive
apt-get update >"$evidence/apt-update.log" 2>&1
apt-get install -y --no-install-recommends apparmor apparmor-utils ca-certificates curl docker.io openssl postgresql postgresql-client uidmap >"$evidence/apt-install.log" 2>&1
systemctl enable --now postgresql docker
wait_active postgresql
wait_active docker

phase=accounts_and_config
for account in opencard opencard-agent opencard-buildkit opencard-caddy opencard-edge; do
  getent passwd "$account" >/dev/null || useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home "$account"
done
getent group docker >/dev/null
usermod -a -G docker opencard-agent
install -d -o root -g root -m 0750 /etc/open-card
install -d -o root -g root -m 0755 /etc/buildkit
install -d -o root -g root -m 0755 /etc/cdi /var/run/cdi
install -d -o root -g root -m 0711 /var/lib/open-card
install -d -o opencard -g opencard -m 0750 /var/log/open-card /var/lib/open-card/uploads /var/lib/open-card/workspaces /var/lib/open-card/build-work /var/lib/open-card/oci /var/lib/open-card/secrets /var/lib/open-card/secret-materials
install -d -o opencard-agent -g opencard-agent -m 0750 /var/lib/open-card-agent /var/log/open-card-agent
install -d -o opencard-buildkit -g opencard-buildkit -m 0700 /var/lib/open-card-buildkit /run/open-card-buildkit
install -d -o opencard-caddy -g opencard-caddy -m 0750 /var/lib/open-card-caddy /var/log/open-card-caddy
install -d -o opencard-caddy -g opencard-caddy -m 0700 /var/lib/open-card-caddy/home /var/lib/open-card-caddy/data /var/lib/open-card-caddy/config
install -d -o opencard-edge -g opencard-edge -m 0750 /var/lib/open-card-edge /var/log/open-card-edge
install -d -o opencard-edge -g opencard-edge -m 0700 /var/lib/open-card-edge/home /var/lib/open-card-edge/data /var/lib/open-card-edge/config
openssl rand -hex 24 >/var/lib/open-card/installation-id
chown root:root /var/lib/open-card/installation-id
chmod 0600 /var/lib/open-card/installation-id
cat >/etc/buildkit/buildkitd.toml <<'EOF'
debug = false
[worker.oci]
  enabled = true
  snapshotter = "native"
  max-parallelism = 1
[worker.containerd]
  enabled = false
EOF
chmod 0644 /etc/buildkit/buildkitd.toml
grep -q '^opencard-buildkit:' /etc/subuid || echo 'opencard-buildkit:100000:65536' >>/etc/subuid
grep -q '^opencard-buildkit:' /etc/subgid || echo 'opencard-buildkit:100000:65536' >>/etc/subgid
cat >/etc/apparmor.d/opencard-rootlesskit <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile opencard-rootlesskit /opt/open-card/releases/*/bin/rootlesskit flags=(unconfined) {
  userns,
}
EOF
apparmor_parser -r /etc/apparmor.d/opencard-rootlesskit

db_password=$(openssl rand -hex 24)
install -o root -g root -m 0600 /dev/null /etc/open-card/postgres-password
printf '%s\n' "$db_password" >/etc/open-card/postgres-password
runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<SQL
SELECT 'CREATE ROLE opencard LOGIN PASSWORD ''$db_password'' NOCREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'opencard')\gexec
SELECT 'CREATE DATABASE opencard OWNER opencard' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'opencard')\gexec
SQL
database_url="postgresql://opencard:${db_password}@127.0.0.1:5432/opencard?sslmode=disable"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj '/CN=Open Card Gate5B CA' -keyout /etc/open-card/agent-ca.key -out /etc/open-card/agent-ca.crt >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\nsubjectAltName=DNS:opencard-agent\n' >/etc/open-card/agent-cert.ext
openssl req -newkey rsa:2048 -sha256 -nodes -subj '/CN=opencard-agent' -keyout /etc/open-card/agent.key -out /etc/open-card/agent.csr >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 -in /etc/open-card/agent.csr -CA /etc/open-card/agent-ca.crt -CAkey /etc/open-card/agent-ca.key -CAcreateserial -extfile /etc/open-card/agent-cert.ext -out /etc/open-card/agent.crt >/dev/null 2>&1
printf 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:opencard-control-plane,IP:127.0.0.1\n' >/etc/open-card/server-cert.ext
openssl req -newkey rsa:2048 -sha256 -nodes -subj '/CN=opencard-control-plane' -keyout /etc/open-card/server.key -out /etc/open-card/server.csr >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 -in /etc/open-card/server.csr -CA /etc/open-card/agent-ca.crt -CAkey /etc/open-card/agent-ca.key -CAcreateserial -extfile /etc/open-card/server-cert.ext -out /etc/open-card/server.crt >/dev/null 2>&1
chmod 0600 /etc/open-card/agent-ca.key /etc/open-card/agent.key /etc/open-card/server.key
chmod 0644 /etc/open-card/agent-ca.crt /etc/open-card/agent.crt /etc/open-card/server.crt
chown opencard-agent:opencard-agent /etc/open-card/agent.key /etc/open-card/agent.crt /etc/open-card/agent-ca.crt
chown opencard:opencard /etc/open-card/server.key /etc/open-card/server.crt
agent_serial=$(openssl x509 -in /etc/open-card/agent.crt -noout -serial | cut -d= -f2)
agent_serial=$(python3 - "$agent_serial" <<'PY'
import sys
print(int(sys.argv[1], 16))
PY
)
openssl rand 32 >/etc/open-card/build-secret.key
chown opencard:opencard /etc/open-card/build-secret.key
chmod 0400 /etc/open-card/build-secret.key
cat >/etc/open-card/Caddyfile <<'EOF'
{
  admin 127.0.0.1:2019
  auto_https off
}
http://127.0.0.1:18481 {
  reverse_proxy 127.0.0.1:8080
}
EOF
chmod 0644 /etc/open-card/Caddyfile
cat >/etc/open-card/caddy.env <<'EOF'
HOME=/var/lib/open-card-caddy/home
XDG_DATA_HOME=/var/lib/open-card-caddy/data
XDG_CONFIG_HOME=/var/lib/open-card-caddy/config
OPEN_CARD_CADDY_LISTEN=127.0.0.1:18481
EOF
chown root:opencard-caddy /etc/open-card/caddy.env
chmod 0640 /etc/open-card/caddy.env
cat >/etc/open-card/agent.env <<EOF
OPEN_CARD_INSTANCE_ID=$prefix
OPEN_CARD_NODE_ID=$prefix-node
OPEN_CARD_AGENT_VERSION=1.1
OPEN_CARD_CONTROL_PLANE_URL=https://127.0.0.1:8092
OPEN_CARD_CONTROL_PLANE_SERVER_NAME=opencard-control-plane
OPEN_CARD_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_AGENT_TLS_CERT=/etc/open-card/agent.crt
OPEN_CARD_AGENT_TLS_KEY=/etc/open-card/agent.key
OPEN_CARD_RUNTIME_ENABLED=false
EOF
chmod 0600 /etc/open-card/agent.env
cat >/etc/open-card/server.env <<EOF
OPEN_CARD_SERVER_ADDR=127.0.0.1:8080
OPEN_CARD_DATABASE_URL=$database_url
OPEN_CARD_AGENT_GATEWAY_ADDR=127.0.0.1:8092
OPEN_CARD_AGENT_IDENTITIES_JSON=[{"certificate_id":"$agent_serial","instance_id":"$prefix","node_id":"$prefix-node"}]
OPEN_CARD_SERVER_AGENT_TLS_CA=/etc/open-card/agent-ca.crt
OPEN_CARD_SERVER_AGENT_TLS_CERT=/etc/open-card/server.crt
OPEN_CARD_SERVER_AGENT_TLS_KEY=/etc/open-card/server.key
OPEN_CARD_M1_ENABLED=false
OPEN_CARD_M2_ENABLED=false
OPEN_CARD_M3_ENABLED=false
OPEN_CARD_M4_ENABLED=false
OPEN_CARD_M4_ROLLOUT_ENABLED=false
OPEN_CARD_M5_ENABLED=false
OPEN_CARD_M6_ENABLED=false
OPEN_CARD_AI_ENABLED=false
OPEN_CARD_BUILDKIT_WORKER=host-rootless
OPEN_CARD_BUILDKIT_ADDRESS=unix:///run/open-card-buildkit/buildkitd.sock
OPEN_CARD_CADDY_ADMIN_URL=http://127.0.0.1:2019
OPEN_CARD_CADDY_LISTEN=127.0.0.1:18481
EOF
chmod 0600 /etc/open-card/server.env

phase=migrate_rc0
DATABASE_URL="$database_url" bash "$rc0/release/scripts/mvp/control-plane-migrate.sh" "$rc0/release/migrations/control-plane" >"$evidence/rc0-migrate.txt"
[[ "$(psql "$database_url" -X -Aqt -c 'SELECT count(*) FROM schema_migrations')" = 23 ]]

phase=install_rc0
rc0_compat_marker=/etc/opencard-mvp-fa8f8eab-clean-worker
printf '%s\n' opencard-mvp-fa8f8eab-build-worker-01 >"$rc0_compat_marker"
chmod 0600 "$rc0_compat_marker"
env OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_SYSTEM_ROOT_CONFIRMATION=opencard-mvp-fa8f8eab-build-worker-01 OPEN_CARD_M6_ENABLED=false OPEN_CARD_AI_ENABLED=false bash "$rc0/release/scripts/mvp/install.sh" --root / --offline --expected-manifest-sha256 "$rc0_manifest_sha" --bundle "$rc0/release" >"$evidence/rc0-install.txt" 2>&1
rm -f -- "$rc0_compat_marker"
[[ "$(readlink /opt/open-card/current)" = releases/release-0.8.0-rc.0 ]]
chown root:root /opt/open-card /opt/open-card/releases /opt/open-card/releases/release-0.8.0-rc.0 /etc/open-card /etc/buildkit
chmod 0755 /opt/open-card /opt/open-card/releases /opt/open-card/releases/release-0.8.0-rc.0 /etc/buildkit
chmod 0711 /etc/open-card
systemctl daemon-reload
systemctl enable open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service
systemctl reset-failed open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service >/dev/null 2>&1 || true
systemctl restart open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service
printf 'rc0_stage=verified_nonactivating\nruntime_traversal=explicit_compatibility_bridge\n' >"$evidence/rc0-compat-layout.txt"
for unit in open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service; do wait_active "$unit"; done
test -S /run/open-card-buildkit/buildkitd.sock
wait_http http://127.0.0.1:8080/healthz
wait_http http://127.0.0.1:18481/healthz
[[ "$(systemctl is-active open-card-edge.service || true)" != active && ! -e "$marker" ]]
psql "$database_url" -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE gate5b_success_sentinel(id integer PRIMARY KEY, value text NOT NULL);
INSERT INTO gate5b_success_sentinel(id,value) VALUES (1,'rc0-before-upgrade');
SQL

phase=activate_rc0_edge
! grep -q '^OPEN_CARD_AUTH_ORIGIN=' /etc/open-card/server.env
printf 'OPEN_CARD_AUTH_ORIGIN=https://%s\n' "$edge_domain" >>/etc/open-card/server.env
edge_template=/opt/open-card/current/caddy/open-card-edge.Caddyfile.example
edge_next=/etc/open-card/.open-card-edge.Caddyfile.next
python3 - "$edge_template" "$edge_next" "$edge_domain" <<'PY'
import pathlib, sys
source, target, domain = map(pathlib.Path, sys.argv[1:])
text = source.read_text(encoding="utf-8")
if text.count("console.example.invalid") != 1:
    raise SystemExit("Edge template console hostname is not unique")
target.write_text(text.replace("console.example.invalid", str(domain)), encoding="utf-8")
PY
install -m 0640 -o root -g opencard-edge "$edge_next" /etc/open-card/open-card-edge.Caddyfile
rm -f -- "$edge_next"
install -m 0640 -o root -g opencard-edge /opt/open-card/current/caddy/open-card-edge.env.example /etc/open-card/open-card-edge.env
/opt/open-card/current/bin/caddy validate --config /etc/open-card/open-card-edge.Caddyfile --adapter caddyfile >"$evidence/edge-validate.txt"
/opt/open-card/current/bin/caddy adapt --config /etc/open-card/open-card-edge.Caddyfile --adapter caddyfile --validate >"$evidence/edge-adapt.json"
systemctl restart open-card-server.service
admin_password="$state/admin-password"
openssl rand -base64 32 >"$admin_password"
chmod 0600 "$admin_password"
systemctl enable --now open-card-edge.service
/opt/open-card/current/bin/open-card-admin bootstrap --password-file "$admin_password" >"$evidence/admin-bootstrap.txt"
rm -f -- "$admin_password"
assert_edge_running

phase=production_upgrade_wrapper
if [[ "$scenario" == active-switch-crash ]]; then
  run_active_switch_crash
  exit 0
fi
env OPEN_CARD_ALLOW_SYSTEM_ROOT=1 bash "$rc1/release/scripts/mvp/upgrade.sh" --root / --offline --activate --expected-manifest-sha256 "$rc1_manifest_sha" --bundle "$rc1/release" --confirm-installation-id "UPGRADE:$(cat /var/lib/open-card/installation-id)" >"$evidence/production-upgrade.jsonl" 2>"$evidence/production-upgrade.stderr"
tx=$(python3 - "$evidence/production-upgrade.jsonl" <<'PY'
import json, sys
transactions=[]
for line in open(sys.argv[1], encoding="utf-8"):
    try: value=json.loads(line)
    except ValueError: continue
    if value.get("ok") is True and value.get("state") == "COMMITTED" and "transaction_id" in value:
        transactions.append(value["transaction_id"])
assert len(transactions) == 1
print(transactions[0])
PY
)
[[ "$tx" =~ ^upgrade-[0-9a-f]{32}$ ]]

phase=assertions
[[ ! -e "$marker" && ! -L "$marker" && "$(readlink /opt/open-card/current)" = active/release ]]
candidate_activation=$(readlink /opt/open-card/active)
previous_activation=$(readlink /opt/open-card/previous-active)
[[ "$candidate_activation" =~ ^activations/act-[0-9a-f]{24}$ && "$previous_activation" =~ ^activations/legacy-[0-9a-f]{24}$ ]]
candidate_activation=${candidate_activation#activations/}
previous_activation=${previous_activation#activations/}
[[ "$(readlink "/opt/open-card/activations/$candidate_activation/release")" = ../../releases/release-0.8.0-rc.1 ]]
[[ "$(readlink "/opt/open-card/activations/$previous_activation/release")" = ../../releases/release-0.8.0-rc.0 ]]
python3 - "/opt/open-card/activations/$candidate_activation/activation.json" "/opt/open-card/activations/$previous_activation/activation.json" <<'PY' >"$evidence/activations.json"
import json,sys
c,p=[json.load(open(x)) for x in sys.argv[1:]]
assert c["origin"] == "native" and c["release"]["version"] == "0.8.0-rc.1" and c["database"]["migration"] == "0024" and c.get("legacy_projection") is None
assert p["origin"] == "rc0_compat_projection" and p["release"]["version"] == "0.8.0-rc.0" and p["database"]["migration"] == "0023" and p.get("legacy_projection")
print(json.dumps({"candidate":{"activation_id":c["activation_id"],"release":c["release"],"database":c["database"]},"previous":{"activation_id":p["activation_id"],"release":p["release"],"database":p["database"]}},sort_keys=True))
PY
candidate_database=$(python3 - "/opt/open-card/activations/$candidate_activation/activation.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["database"]["name"])
PY
)
candidate_url="postgresql://opencard:${db_password}@127.0.0.1:5432/${candidate_database}?sslmode=disable"
[[ "$(psql "$database_url" -X -Aqt -c 'SELECT count(*) FROM schema_migrations')" = 23 ]]
[[ "$(psql "$candidate_url" -X -Aqt -c 'SELECT count(*) FROM schema_migrations')" = 24 ]]
[[ "$(psql "$database_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = rc0-before-upgrade ]]
[[ "$(psql "$candidate_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = rc0-before-upgrade ]]
assert_runtime_services
! grep -q '^OPEN_CARD_DATABASE_URL=' /etc/open-card/server.env
control_role_flags=$(runuser -u postgres -- psql -X -Aqt -F, -v ON_ERROR_STOP=1 -c "SELECT rolname || ',' || rolcreatedb || ',' || rolsuper || ',' || rolcreaterole FROM pg_roles WHERE rolname = 'open_card_upgrade_control'")
runtime_role_flags=$(runuser -u postgres -- psql -X -Aqt -F, -v ON_ERROR_STOP=1 -c "SELECT rolname || ',' || rolcreatedb || ',' || rolsuper || ',' || rolcreaterole FROM pg_roles WHERE rolname = 'opencard'")
printf '%s\n%s\n' "$control_role_flags" "$runtime_role_flags" >"$evidence/postgres-role-flags.txt"
[[ "$control_role_flags" = 'open_card_upgrade_control,true,false,false' && "$runtime_role_flags" = 'opencard,false,false,false' ]]
runuser -u postgres -- psql -X -Aqt -v ON_ERROR_STOP=1 -c "SELECT pg_has_role('open_card_upgrade_control','opencard','member')" | grep -Fxq t

phase=production_backup
env OPEN_CARD_ALLOW_SYSTEM_ROOT=1 bash /opt/open-card/current/scripts/mvp/backup-control-plane.sh --root / --reason gate5b_product --confirm-installation-id "BACKUP:$(cat /var/lib/open-card/installation-id)" >"$evidence/production-backup.json" 2>"$evidence/production-backup.stderr"
backup_id=$(python3 - "$evidence/production-backup.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["ok"] is True and value["command"] == "backup-create"
backup=value["backup"]
assert backup["schema_version"] == 2 and backup["backup_id"].startswith("backup-")
print(backup["backup_id"])
PY
)
[[ "$backup_id" =~ ^backup-[A-Za-z0-9._-]+$ ]]
[[ -f "/var/lib/open-card/backups/$backup_id/backup.json" && -f "/var/lib/open-card/backups/$backup_id/control-plane.dump" ]]
psql "$candidate_url" -X -v ON_ERROR_STOP=1 -c "UPDATE gate5b_success_sentinel SET value='mutated-after-backup' WHERE id=1"
[[ "$(psql "$candidate_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = mutated-after-backup ]]

phase=production_restore
env OPEN_CARD_ALLOW_SYSTEM_ROOT=1 bash /opt/open-card/current/scripts/mvp/restore-control-plane.sh --root / --backup "$backup_id" --confirm-installation-id "RESTORE:$(cat /var/lib/open-card/installation-id)" >"$evidence/production-restore.json" 2>"$evidence/production-restore.stderr"
restore_tx=$(python3 - "$evidence/production-restore.json" <<'PY'
import json,sys
values=[json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
runs=[value for value in values if value.get("ok") is True and value.get("command") == "restore-run" and value.get("request_kind") == "restore" and value.get("state") == "COMMITTED"]
assert len(runs) == 1
print(runs[0]["transaction_id"])
PY
)
[[ "$restore_tx" =~ ^restore-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]]
assert_runtime_services
restored_link=$(readlink /opt/open-card/active)
pre_restore_link=$(readlink /opt/open-card/previous-active)
[[ "$restored_link" =~ ^activations/restore-[0-9a-f]{24}$ && "$pre_restore_link" = "activations/$candidate_activation" ]]
restored_activation=${restored_link#activations/}
restored_database=$(python3 - "/opt/open-card/activations/$restored_activation/activation.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["release"]["version"] == "0.8.0-rc.1" and value["database"]["migration"] == "0024"
print(value["database"]["name"])
PY
)
restored_url="postgresql://opencard:${db_password}@127.0.0.1:5432/${restored_database}?sslmode=disable"
[[ "$restored_database" != "$candidate_database" ]]
[[ "$(psql "$restored_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = rc0-before-upgrade ]]
[[ "$(psql "$candidate_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = mutated-after-backup ]]
[[ "$(psql "$database_url" -X -Aqt -c 'SELECT value FROM gate5b_success_sentinel WHERE id=1')" = rc0-before-upgrade ]]
[[ -d "/var/lib/open-card/upgrade-artifacts/$tx" && -d "/var/lib/open-card/upgrade-artifacts/$restore_tx" ]]
python3 - "/var/lib/open-card/upgrade-transactions/$restore_tx.json" <<'PY' >"$evidence/restore-journal-request-kind.txt"
import json, sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["transaction_id"] in sys.argv[1]
assert value["request_kind"] == "restore" and value["state"] == "COMMITTED"
print(json.dumps({"transaction_id":value["transaction_id"],"request_kind":value["request_kind"],"state":value["state"]}, sort_keys=True))
PY

systemctl --no-pager --full status postgresql docker open-card-upgrade-safe open-card-server open-card-agent open-card-buildkit open-card-caddy open-card-edge >"$evidence/systemd-status.txt" 2>&1 || true
{
  printf 'rc0_schema_rows=23\n'
  printf 'candidate_schema_rows=24\n'
  printf 'marker=absent\n'
  printf 'edge=active\n'
  printf 'backup_restore=PASS\n'
  printf 'upgrade_transaction=%s\n' "$tx"
  printf 'restore_transaction=%s\n' "$restore_tx"
  printf 'backup_id=%s\n' "$backup_id"
  printf 'crash_failure_matrix=PENDING\n'
  printf 'public_dns_acme_customer_acceptance=PENDING\n'
} >"$evidence/summary.txt"
! grep -R -a -E 'postgres(ql)?://|OPEN_CARD_DATABASE_URL=|BEGIN [A-Z ]*PRIVATE KEY|password=' "$evidence"
(cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >manifest.sha256)
printf 'G5B_PRODUCT_INITIAL=PASS\n'
