#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ssh_key=${OPEN_CARD_DEVBOX_SSH_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
ssh_target=${OPEN_CARD_DEVBOX_SSH_TARGET:-ubuntu@192.168.31.64}
evidence_dir=${OPEN_CARD_M5_EVIDENCE_DIR:-}
task=opencard-mvp-fa8f8eab
network=$task-m5-net
server=$task-m5-server
load=$task-m5-load
remote_root=/home/ubuntu/$task/m5-docker-20260825
local_tmp=$(mktemp -d)
ssh_args=(-i "$ssh_key" -o BatchMode=yes "$ssh_target")

snapshot() {
  ssh "${ssh_args[@]}" 'set -eu
docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Labels}}" | grep -v "open-card.task=opencard-mvp-fa8f8eab" | sort | sha256sum
sudo virsh list --all --uuid --name 2>/dev/null | sort | sha256sum
sudo virsh net-list --all --uuid --name 2>/dev/null | sort | sha256sum
sudo virsh pool-list --all --uuid --name 2>/dev/null | sort | sha256sum
ip -4 route show default | sha256sum
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true
systemctl is-active docker containerd frpc libvirtd'
}

cleanup_remote() {
  ssh "${ssh_args[@]}" bash -s -- "$task" "$server" "$load" "$network" "$remote_root" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
task=$1; server=$2; load=$3; network=$4; remote_root=$5
for name in "$load" "$server"; do
  if docker inspect "$name" >/dev/null 2>&1; then
    test "$(docker inspect -f '{{index .Config.Labels "open-card.task"}}' "$name")" = "$task"
    docker rm -f "$name" >/dev/null
  fi
done
if docker network inspect "$network" >/dev/null 2>&1; then
  test "$(docker network inspect -f '{{index .Labels "open-card.task"}}' "$network")" = "$task"
  docker network rm "$network" >/dev/null
fi
test -f "/home/ubuntu/$task/.open-card-task-marker"
rm -f "$remote_root/inspect-before.json" "$remote_root/inspect-after.json" "$remote_root/stats-before.json" "$remote_root/stats-after.json" "$remote_root/time-before.txt" "$remote_root/time-after.txt"
rmdir "$remote_root" 2>/dev/null || true
REMOTE
}

cleanup() {
  cleanup_remote
  rm -rf "$local_tmp"
}
trap cleanup EXIT

cd "$repo_root"
snapshot > "$local_tmp/host-before.txt"
ssh "${ssh_args[@]}" bash -s -- "$task" "$server" "$load" "$network" "$remote_root" <<'REMOTE'
set -euo pipefail
task=$1; server=$2; load=$3; network=$4; remote_root=$5
test -f "/home/ubuntu/$task/.open-card-task-marker"
for resource in "$server" "$load"; do ! docker inspect "$resource" >/dev/null 2>&1; done
! docker network inspect "$network" >/dev/null 2>&1
mkdir -p "$remote_root"
docker network create --internal --label "open-card.task=$task" "$network" >/dev/null
docker run -d --name "$server" --label "open-card.task=$task" --network "$network" --network-alias m5-server --cpus .25 --memory 32m --pids-limit 32 --restart no nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10 >/dev/null
docker run -d --name "$load" --label "open-card.task=$task" --network "$network" --cpus .5 --memory 64m --pids-limit 64 --restart no --health-cmd 'test ! -f /tmp/m5-unhealthy' --health-interval 1s --health-timeout 1s --health-retries 1 alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc sh -c 'dd if=/dev/zero of=/tmp/m5.bin bs=1M count=8 >/dev/null 2>&1; while :; do wget -qO- http://m5-server/ >/dev/null 2>&1 || true; done & while :; do :; done' >/dev/null
for _ in $(seq 1 20); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$load")" = healthy ]] && break
  sleep 1
done
test "$(docker inspect -f '{{.State.Health.Status}}' "$load")" = healthy
sleep 3
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$remote_root/time-before.txt"
docker inspect --size "$load" > "$remote_root/inspect-before.json"
docker stats --no-stream --format '{{json .}}' "$load" > "$remote_root/stats-before.json"
docker exec "$load" touch /tmp/m5-unhealthy
for _ in $(seq 1 20); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$load")" = unhealthy ]] && break
  sleep 1
done
test "$(docker inspect -f '{{.State.Health.Status}}' "$load")" = unhealthy
sleep 3
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$remote_root/time-after.txt"
docker inspect --size "$load" > "$remote_root/inspect-after.json"
docker stats --no-stream --format '{{json .}}' "$load" > "$remote_root/stats-after.json"
REMOTE

for name in inspect-before.json inspect-after.json stats-before.json stats-after.json time-before.txt time-after.txt; do
  scp -q -i "$ssh_key" "$ssh_target:$remote_root/$name" "$local_tmp/$name"
done
python3 tests/spikes/m5_capture_docker_facts.py \
  --inspect-before "$local_tmp/inspect-before.json" --stats-before "$local_tmp/stats-before.json" --time-before "$(<"$local_tmp/time-before.txt")" \
  --inspect-after "$local_tmp/inspect-after.json" --stats-after "$local_tmp/stats-after.json" --time-after "$(<"$local_tmp/time-after.txt")" \
  --output "$local_tmp/docker-facts.json"

OPEN_CARD_M5_DOCKER_FACTS_LOCAL="$local_tmp/docker-facts.json" tests/integration/usage/run_devbox.sh | tee "$local_tmp/integration.log"
cleanup_remote
ssh "${ssh_args[@]}" "! docker inspect '$server' >/dev/null 2>&1 && ! docker inspect '$load' >/dev/null 2>&1 && ! docker network inspect '$network' >/dev/null 2>&1 && test ! -e '$remote_root'"
snapshot > "$local_tmp/host-after.txt" 2>/dev/null || true

if ! cmp -s "$local_tmp/host-before.txt" "$local_tmp/host-after.txt"; then
  diff -u "$local_tmp/host-before.txt" "$local_tmp/host-after.txt"
  exit 1
fi
if [[ -n "$evidence_dir" ]]; then
	mkdir -p "$evidence_dir"
	cp "$local_tmp/docker-facts.json" "$local_tmp/inspect-before.json" "$local_tmp/inspect-after.json" "$local_tmp/stats-before.json" "$local_tmp/stats-after.json" "$local_tmp/integration.log" "$local_tmp/host-before.txt" "$local_tmp/host-after.txt" "$evidence_dir/"
	(
		cd "$evidence_dir"
		find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 shasum -a 256 | sed 's#  \./#  #' > manifest.sha256
	)
fi
rm -rf "$local_tmp"
trap - EXIT
printf 'M5_REAL_DOCKER_DB=PASS\n'
