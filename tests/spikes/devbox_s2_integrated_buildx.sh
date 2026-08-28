#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEVBOX_SSH_KEY:-}" ]]; then
  echo "DEVBOX_SSH_KEY is required" >&2
  exit 64
fi

DEVBOX_HOST="${DEVBOX_HOST:-ubuntu@192.168.31.64}"
TASK_ID="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"

ssh -i "$DEVBOX_SSH_KEY" -o BatchMode=yes "$DEVBOX_HOST" "
set -u
base=/home/ubuntu/$TASK_ID
fixture=\"\$base/fixtures/s2-integrated\"
plugin=\"\$base/cli-plugins/docker-buildx\"
export DOCKER_CONFIG=\"\$base/docker-config\"
image=$TASK_ID-s2-integrated:probe
metadata=\"\$base/s2-integrated-metadata.json\"

test -f \"\$base/.open-card-task-marker\"
printf '%s  %s\\n' 48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778 \"\$plugin\" | sha256sum -c -

apparmor_before=\$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
non_task_before=\$(docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum | awk '{print \$1}')
vm_before=\$(sudo -n virsh list --all --name | sort | sha256sum | awk '{print \$1}')

docker buildx version
docker buildx inspect default --bootstrap

docker buildx build \\
  --builder default \\
  --progress=plain \\
  --network=none \\
  --no-cache \\
  --resource memory=64m \\
  --resource memory-swap=64m \\
  --resource cpu-period=100000 \\
  --resource cpu-quota=50000 \\
  --metadata-file \"\$metadata\" \\
  --label open-card.task=$TASK_ID \\
  --tag \"\$image\" \\
  --load \\
  -f \"\$fixture/Dockerfile\" \\
  --build-arg TASK_ID=$TASK_ID \\
  \"\$fixture\"

test \"\$(docker image inspect \"\$image\" --format '{{index .Config.Labels \"open-card.task\"}}')\" = $TASK_ID
runtime_output=\$(docker run --rm --label open-card.task=$TASK_ID --network none --memory 64m --cpus 0.5 \"\$image\")
test \"\$runtime_output\" = 4194304

if docker buildx build --builder default --progress=plain --network=none --no-cache \\
  --resource memory=64m --resource cpu-quota=50000 \\
  -f \"\$fixture/Dockerfile.network-deny\" \"\$fixture\"; then
  echo network_negative_unexpected_success >&2
  exit 21
fi
echo network_negative_blocked=yes

set +e
docker buildx build --builder default --progress=plain --network=none --no-cache \\
  --resource memory=64m --resource memory-swap=64m \\
  --resource cpu-period=100000 --resource cpu-quota=50000 \\
  -f \"\$fixture/Dockerfile.cgroup\" \"\$fixture\"
resource_status=\$?

timeout --signal=TERM 5s docker buildx build --builder default --progress=plain \\
  --network=none --no-cache --resource memory=64m --resource cpu-quota=50000 \\
  -f \"\$fixture/Dockerfile.timeout\" \"\$fixture\"
timeout_status=\$?
set -e

sleep 2
apparmor_after=\$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
non_task_after=\$(docker ps --format '{{.ID}} {{.Labels}}' | awk '\$0 !~ /open-card.task=/' | sort | sha256sum | awk '{print \$1}')
vm_after=\$(sudo -n virsh list --all --name | sort | sha256sum | awk '{print \$1}')

test \"\$apparmor_before\" = \"\$apparmor_after\"
test \"\$non_task_before\" = \"\$non_task_after\"
test \"\$vm_before\" = \"\$vm_after\"
test \"\$timeout_status\" -eq 124
test -n \"\$(ip route show default)\"
for service in docker.service containerd.service frpc.service libvirtd.service; do
  test \"\$(systemctl is-active \"\$service\")\" = active
done

if docker ps -a --filter label=open-card.task=$TASK_ID --format '{{.Mounts}}' | grep -q docker.sock; then
  echo docker_socket_mount_detected >&2
  exit 23
fi

builder_driver=\$(docker buildx inspect default | awk '/^Driver:/ {print \$2}')
worker_network=\$(docker buildx inspect default | awk -F: '/worker.network/ {gsub(/^ +/,\"\",\$2); print \$2}')
buildkit_version=\$(docker buildx inspect default | awk '/BuildKit version:/ {print \$3}')

echo apparmor_unchanged=\$apparmor_after
echo non_task_containers_unchanged=yes
echo vm_inventory_unchanged=yes
echo docker_socket_in_user_build=absent
echo network_negative=blocked
echo timeout_status=\$timeout_status
echo builder_driver=\$builder_driver
echo builder_worker_network=\$worker_network
echo buildkit_version=\$buildkit_version
echo metadata_sha256=\$(sha256sum \"\$metadata\" | awk '{print \$1}')
echo resource_cgroup_probe_status=\$resource_status

if [[ \"\$resource_status\" -ne 0 ]]; then
  echo gate=FAIL
  echo blocker=integrated_buildkit_resource_limits_not_applied
  echo observed_memory_max=max
  echo observed_cpu_max='max 100000'
  exit 78
fi

echo gate=PASS
"
