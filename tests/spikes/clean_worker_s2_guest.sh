#!/usr/bin/env bash
set -euo pipefail

task_id=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
marker=/etc/opencard-mvp-fa8f8eab-clean-worker
workspace=/var/lib/opencard-mvp-fa8f8eab/workspace
evidence=/var/lib/opencard-mvp-fa8f8eab/evidence/s2
builder=opencard-mvp-fa8f8eab-rootless
buildx=/opt/open-card/current/bin/docker-buildx
buildkit_socket=unix:///run/open-card-buildkit/buildkitd.sock

test "$(id -u)" -eq 0
test -f "$marker" && test "$(cat "$marker")" = "$domain"
test "$(systemctl is-active open-card-buildkit)" = active
test ! -e /host
test ! -S /var/run/host-docker.sock
buildkit_source=$(findmnt -n -o SOURCE /var/lib/open-card-buildkit)
[[ "$buildkit_source" =~ ^/dev/loop[0-9]+$ ]]
buildkit_size=$(findmnt -b -n -o SIZE /var/lib/open-card-buildkit)
test "$buildkit_size" -le 4294967296
service_cgroup=/sys/fs/cgroup/system.slice/open-card-buildkit.service
test "$(cat "$service_cgroup/memory.max")" = 536870912
test "$(cat "$service_cgroup/cpu.max")" = "50000 100000"
install -d -m 0750 -o opencard-buildkit -g opencard-buildkit "$workspace" "$evidence"

run_as_builder() {
  sudo -u opencard-buildkit env HOME=/var/lib/open-card-buildkit XDG_RUNTIME_DIR=/run/open-card-buildkit "$@"
}

run_as_builder "$buildx" rm "$builder" >/dev/null 2>&1 || true
run_as_builder "$buildx" create --name "$builder" --driver remote "$buildkit_socket" --use >/dev/null
run_as_builder "$buildx" inspect --builder "$builder" --bootstrap >"$evidence/builder-inspect.txt"
grep -Fq 'BuildKit version: v0.32.2' "$evidence/builder-inspect.txt"

positive="$workspace/positive"
install -d -m 0750 -o opencard-buildkit -g opencard-buildkit "$positive"
install -m 0755 -o opencard-buildkit -g opencard-buildkit /bin/busybox "$positive/busybox"
cat >"$positive/Dockerfile" <<'EOF'
FROM scratch
COPY busybox /bin/busybox
COPY busybox /bin/sh
RUN ["/bin/busybox","sh","-c","test ! -e /var/run/docker.sock; test ! -e /host; if /bin/busybox wget -T 2 -O /dev/null http://169.254.169.254/latest/meta-data/; then exit 71; fi"]
RUN --mount=type=secret,id=canary /bin/busybox sh -c 'test -s /run/secrets/canary && test "$(stat -c %a /run/secrets/canary)" = 400'
EOF
chown opencard-buildkit:opencard-buildkit "$positive/Dockerfile"
chmod 0640 "$positive/Dockerfile"
canary="opencard-s2-canary-$(openssl rand -hex 16)"
canary_file="$workspace/.ephemeral-canary"
printf '%s' "$canary" >"$canary_file"
chown opencard-buildkit:opencard-buildkit "$canary_file"
chmod 0400 "$canary_file"

BUILDX_EXPERIMENTAL=1 run_as_builder "$buildx" build \
  --builder "$builder" \
  --progress plain \
  --network none \
  --resource memory=512m \
  --resource memory-swap=512m \
  --resource cpu-period=100000 \
  --resource cpu-quota=50000 \
  --secret "id=canary,src=$canary_file" \
  --metadata-file "$evidence/positive-metadata.json" \
  --output "type=oci,dest=$evidence/positive.oci" \
  "$positive" >"$evidence/positive.log" 2>&1
test -s "$evidence/positive.oci"
if grep -aR -Fq "$canary" "$evidence"; then
  echo "secret canary leaked into evidence or image" >&2
  exit 72
fi
python3 - "$evidence/positive-metadata.json" <<'PY'
import json, re, sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
digest=value.get("containerimage.digest","")
assert re.fullmatch(r"sha256:[0-9a-f]{64}",digest), value
print("image_digest="+digest)
PY
sha256sum "$evidence/positive.oci" >"$evidence/positive.oci.sha256"
python3 - "$evidence/positive.oci" <<'PY'
import tarfile,sys
with tarfile.open(sys.argv[1],"r:") as archive:
    names=archive.getnames()
    assert "oci-layout" in names and "index.json" in names
PY
python3 - "$canary_file" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1])
p.unlink()
PY
test ! -e "$canary_file"

timeout_context="$workspace/timeout"
install -d -m 0750 -o opencard-buildkit -g opencard-buildkit "$timeout_context"
install -m 0755 -o opencard-buildkit -g opencard-buildkit /bin/busybox "$timeout_context/busybox"
cat >"$timeout_context/Dockerfile" <<'EOF'
FROM scratch
COPY busybox /bin/busybox
RUN ["/bin/busybox","sh","-c","while :; do sleep 1; done"]
EOF
chown opencard-buildkit:opencard-buildkit "$timeout_context/Dockerfile"
set +e
timeout --signal=TERM --kill-after=5 5 \
  sudo -u opencard-buildkit env HOME=/var/lib/open-card-buildkit XDG_RUNTIME_DIR=/run/open-card-buildkit BUILDX_EXPERIMENTAL=1 \
  "$buildx" build --builder "$builder" --progress plain --network none \
  --resource memory=512m --resource cpu-period=100000 --resource cpu-quota=50000 \
  --output "type=oci,dest=$evidence/timeout.oci" "$timeout_context" >"$evidence/timeout.log" 2>&1 &
timeout_wrapper=$!
set -e
runc_pid=
for _ in $(seq 1 50); do
  runc_pid=$(pgrep -f '^buildkit-runc .* run .*--bundle /var/lib/open-card-buildkit/' | head -1 || true)
  [[ -n "$runc_pid" ]] && break
  sleep 0.2
done
test -n "$runc_pid"
build_pid=$(pgrep -P "$runc_pid" | head -1)
test -n "$build_pid"
build_cgroup=$(sed -n 's/^0:://p' "/proc/$build_pid/cgroup")
test "$build_cgroup" = /system.slice/open-card-buildkit.service
{
  echo "build_pid=$build_pid"
  echo "build_cgroup=$build_cgroup"
  echo "memory.max=$(cat "/sys/fs/cgroup$build_cgroup/memory.max")"
  echo "cpu.max=$(cat "/sys/fs/cgroup$build_cgroup/cpu.max")"
} >"$evidence/build-step-cgroup.txt"
grep -Fxq 'memory.max=536870912' "$evidence/build-step-cgroup.txt"
grep -Fxq 'cpu.max=50000 100000' "$evidence/build-step-cgroup.txt"
set +e
wait "$timeout_wrapper"
timeout_status=$?
set -e
test "$timeout_status" -ne 0
test ! -e "$evidence/timeout.oci"
sleep 2
test -z "$(pgrep -f '^buildkit-runc .* run .*--bundle /var/lib/open-card-buildkit/' || true)"

run_as_builder /opt/open-card/current/bin/buildctl --addr "$buildkit_socket" prune --all >"$evidence/prune.log"
python3 - "$workspace" <<'PY'
from pathlib import Path
import shutil,sys
p=Path(sys.argv[1])
assert str(p)=="/var/lib/opencard-mvp-fa8f8eab/workspace"
shutil.rmtree(p)
PY
test ! -e "$workspace"
df -B1 /var/lib/open-card-buildkit >"$evidence/buildkit-filesystem.txt"
systemctl show open-card-buildkit -p User -p Delegate -p MemoryMax -p CPUQuotaPerSecUSec -p NoNewPrivileges >"$evidence/buildkit-service.txt"
test "$(systemctl show open-card-buildkit -p User --value)" = opencard-buildkit

printf '%s\n' \
  's2_guest=PASS' \
  'rootless_buildkit=v0.32.2' \
  'build_memory_max=536870912' \
  'build_cpu_max=50000 100000' \
  "buildkit_filesystem_max_bytes=$buildkit_size" \
  'metadata_network=denied' \
  'docker_socket=absent_from_build' \
  'host_mount=absent' \
  'ephemeral_secret=mounted_then_removed_no_leak' \
  'timeout_cleanup=pass' \
  'workspace_cleanup=pass'
