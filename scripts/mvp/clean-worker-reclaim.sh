#!/usr/bin/env bash
set -euo pipefail

mode="${1:---dry-run}"
task_id=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
domain_uuid=fce4e26d-93b0-5128-a090-969ef73835d4
volume=opencard-mvp-fa8f8eab-build-worker-01.qcow2
pool=opencard-mvp-fa8f8eab-build-workers
pool_uuid=72a914c5-b6c7-5f22-a3bd-88f9b43f1619
network=opencard-mvp-fa8f8eab-build-isolated
network_uuid=03f91824-e5c9-5655-ac06-fec291e81c93
pool_path=/var/lib/libvirt/images/opencard-mvp-fa8f8eab
task_root=/home/ubuntu/opencard-mvp-fa8f8eab

printf '%s\n' "domain=$domain" "pool=$pool" "volume=$volume" "network=$network"
if [[ "$mode" == "--dry-run" ]]; then
  printf '%s\n' 'mode=dry-run' 'mutation=none' 'authorization=required'
  exit 0
fi
if [[ "$mode" != "--execute" || "${OPEN_CARD_ALLOW_VM_LIFECYCLE:-}" != 1 || "${OPEN_CARD_RECLAIM_CONFIRMATION:-}" != "reclaim-$domain" ]]; then
  echo "VM reclaim requires explicit lifecycle authorization and exact confirmation" >&2
  exit 77
fi

sudo test -f "$pool_path/.open-card-task-marker"
sudo grep -Fxq "task_id=$task_id" "$pool_path/.open-card-task-marker"
test -f "$task_root/.open-card-task-marker"
if sudo virsh dominfo "$domain" >/dev/null 2>&1; then
  test "$(sudo virsh domuuid "$domain")" = "$domain_uuid"
fi
if sudo virsh pool-info "$pool" >/dev/null 2>&1; then
  test "$(sudo virsh pool-uuid "$pool")" = "$pool_uuid"
  test "$(sudo virsh pool-dumpxml "$pool" | sed -n 's:.*<path>\(.*\)</path>.*:\1:p')" = "$pool_path"
fi
if sudo virsh net-info "$network" >/dev/null 2>&1; then
  test "$(sudo virsh net-uuid "$network")" = "$network_uuid"
  test -z "$(sudo virsh net-dumpxml "$network" | grep -E '<forward|<ip ' || true)"
fi

sudo virsh shutdown "$domain" --mode agent >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  state=$(sudo virsh domstate "$domain" 2>/dev/null || true)
  [[ "$state" == "shut off" || -z "$state" ]] && break
  sleep 1
done
test "$(sudo virsh domstate "$domain" 2>/dev/null || true)" != running
if sudo virsh dominfo "$domain" >/dev/null 2>&1; then sudo virsh undefine "$domain" >/dev/null; fi
if sudo virsh vol-info "$volume" --pool "$pool" >/dev/null 2>&1; then sudo virsh vol-delete "$volume" --pool "$pool" >/dev/null; fi
if sudo virsh net-info "$network" >/dev/null 2>&1; then
  sudo virsh net-destroy "$network" >/dev/null 2>&1 || true
  sudo virsh net-undefine "$network" >/dev/null
fi
if sudo virsh pool-info "$pool" >/dev/null 2>&1; then
  sudo virsh pool-destroy "$pool" >/dev/null 2>&1 || true
  sudo virsh pool-undefine "$pool" >/dev/null
fi

sudo python3 - "$pool_path" <<'PY'
from pathlib import Path
import shutil,sys
path=Path(sys.argv[1])
assert str(path)=="/var/lib/libvirt/images/opencard-mvp-fa8f8eab"
marker=path/".open-card-task-marker"
assert marker.is_file() and "task_id=opencard-mvp-fa8f8eab" in marker.read_text()
shutil.rmtree(path)
PY
python3 - "$task_root" <<'PY'
from pathlib import Path
import shutil,sys
root=Path(sys.argv[1])
assert str(root)=="/home/ubuntu/opencard-mvp-fa8f8eab"
assert (root/".open-card-task-marker").is_file()
for name in (
    "clean-worker-offline-source", "clean-worker-m4-repo", "clean-worker-offline-assets",
    "clean-worker-offline-debs", "m4-assembled-payload", "clean-worker-offline-iso-root",
    "clean-worker-provision", "clean-worker-m7-repo", "clean-worker-m7-canonical-source",
    "clean-worker-m7-assets", "clean-worker-m7-debs", "m7-assembled-payload",
    "clean-worker-m7-iso-root", "m7-snapshots", "m7-temp", "m7-cache",
):
    path=root/name
    if path.exists():
        for child in sorted(path.rglob("*"), reverse=True):
            try: child.chmod(0o700 if child.is_dir() else 0o600)
            except OSError: pass
        path.chmod(0o700)
        shutil.rmtree(path)
for name in (
    "opencard-mvp-fa8f8eab-clean-worker-offline-bundle.tar", "clean-worker-runtime-spec.json",
    "assemble-result.json", "bundle-result.json", "guest-evidence-export.tar.gz",
    "provision-clean-worker.sh", "clean-worker-guest-exec.sh", "clean-worker-guest-file-copy.py",
    "opencard-mvp-fa8f8eab-m4-offline-bundle.tar", "m4-clean-worker-runtime-spec.json",
    "m4-assemble-result.json", "m4-bundle-result.json", "m4-bundle-validation.json",
    "m4-canonical-source.stdout", "m4-canonical-source.stderr", "m4-canonical-source.pid",
    "m4-runtime-spec-validation.json", "m4-host-before.json", "m4-host-after.json",
    "m4-guest-run.stdout", "m4-guest-run.stderr", "m4-guest-evidence.tar",
    "opencard-mvp-fa8f8eab-m7-offline-bundle.tar", "m7-clean-worker-runtime-spec.json",
    "m7-assemble-result.json", "m7-bundle-result.json", "m7-bundle-validation.json",
    "m7-canonical-source.stdout", "m7-canonical-source.stderr", "m7-canonical-source.pid",
    "m7-runtime-spec-validation.json", "m7-host-before.json", "m7-host-after.json",
    "m7-host-before-create.json", "m7-host-after-reclaim.json", "m7-guest-run.stdout",
    "m7-guest-run.stderr", "m7-guest-evidence.tar", "m7-rc-snapshot.qcow2",
    "opencard-mvp-fa8f8eab-build-worker-01-seed.iso",
    "opencard-mvp-fa8f8eab-build-worker-01-offline.iso",
):
    path=root/name
    if path.exists() and path.is_file(): path.unlink()
for path in root.iterdir():
    if not path.is_file(): continue
    name=path.name
    if (
        (name.startswith("m7-round-") and name.endswith(".tar.gz"))
        or name in {
            "m7-final-evidence.tar.gz", "m7-supply-evidence.tar.gz",
            "m7-failure-evidence.tar.gz", "m7-ubuntu-gpg.log",
        }
    ):
        path.unlink()
PY

! sudo virsh dominfo "$domain" >/dev/null 2>&1
! sudo virsh pool-info "$pool" >/dev/null 2>&1
! sudo virsh net-info "$network" >/dev/null 2>&1
test ! -e /sys/class/net/virbr-opencard
sudo test ! -e "$pool_path"
printf '%s\n' 'domain=absent' 'volume=absent' 'pool=absent' 'network=absent' 'bundle=absent' 'reclaim=complete'
