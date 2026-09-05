#!/usr/bin/env bash
# Acceptance fixture only. Never run this on an installation or shared host.
set -euo pipefail
[[ $(hostname) = acornfox-afb-build-03b-product-p2-20260905 && $EUID = 0 ]] || exit 23
[[ $(cat /sys/class/dmi/id/product_uuid) = 7c3a1917-178a-4628-a62b-52dc95a4908d ]] || exit 23
echo '2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af  /tmp/buildkit.tar.gz' | sha256sum -c -
echo 'b1302b7395918266d561b9e3053771253f20761807e042ae80a1868d6e86b71c  /tmp/rootlesskit.tar.gz' | sha256sum -c -
command -v newuidmap
! id afb-buildkit >/dev/null 2>&1
useradd -m -d /var/lib/acornfox-build-proof -s /usr/sbin/nologin afb-buildkit
grep -q '^afb-buildkit:' /etc/subuid
grep -q '^afb-buildkit:' /etc/subgid
install -d -m0755 /opt/acornfox-build-proof/bin
tar -xzf /tmp/buildkit.tar.gz -C /opt/acornfox-build-proof
tar -xzf /tmp/rootlesskit.tar.gz -C /opt/acornfox-build-proof/bin
truncate -s 4G /var/lib/acornfox-build-proof-state.img
mkfs.ext4 -q -F /var/lib/acornfox-build-proof-state.img
mount -o loop /var/lib/acornfox-build-proof-state.img /var/lib/acornfox-build-proof
chown afb-buildkit:afb-buildkit /var/lib/acornfox-build-proof
cat >/etc/apparmor.d/acornfox-task-rootlesskit <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>
profile acornfox-task-rootlesskit /opt/acornfox-build-proof/bin/rootlesskit flags=(unconfined) {
  userns,
}
PROFILE
apparmor_parser -r /etc/apparmor.d/acornfox-task-rootlesskit
cat >/opt/acornfox-build-proof/buildkit.toml <<'CONFIG'
[worker.oci]
  max-parallelism = 1
CONFIG
cat >/etc/systemd/system/acornfox-buildkit-proof.service <<'UNIT'
[Unit]
Description=Disposable AcornFox BuildKit proof
[Service]
User=afb-buildkit
Group=afb-buildkit
Environment=HOME=/var/lib/acornfox-build-proof
Environment=XDG_RUNTIME_DIR=/run/open-card-buildkit
Environment=PATH=/opt/acornfox-build-proof/bin:/usr/bin:/bin
RuntimeDirectory=open-card-buildkit
RuntimeDirectoryMode=0750
Delegate=yes
MemoryMax=512M
CPUQuota=50%
TasksMax=128
KillMode=mixed
TimeoutStopSec=15
ExecStart=/opt/acornfox-build-proof/bin/rootlesskit --net=host --copy-up=/etc --copy-up=/run --propagation=rslave --state-dir=/run/open-card-buildkit/rootlesskit /opt/acornfox-build-proof/bin/buildkitd --config /opt/acornfox-build-proof/buildkit.toml --rootless --addr unix:///run/open-card-buildkit/buildkitd.sock --root /var/lib/acornfox-build-proof/state --oci-worker-snapshotter=native --oci-worker-net=host --containerd-worker=false
UNIT
systemctl daemon-reload
systemctl start acornfox-buildkit-proof.service

for attempt in {1..30}; do
  if /opt/acornfox-build-proof/bin/buildctl --addr unix:///run/open-card-buildkit/buildkitd.sock debug workers >/dev/null 2>&1; then
    exit 0
  fi
  systemctl is-active --quiet acornfox-buildkit-proof.service || exit 23
  sleep 0.2
done
exit 23
