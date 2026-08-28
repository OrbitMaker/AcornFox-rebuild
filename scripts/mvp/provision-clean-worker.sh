#!/usr/bin/env bash
set -euo pipefail

task_id=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
domain_uuid=fce4e26d-93b0-5128-a090-969ef73835d4
pool=opencard-mvp-fa8f8eab-build-workers
pool_uuid=72a914c5-b6c7-5f22-a3bd-88f9b43f1619
volume=opencard-mvp-fa8f8eab-build-worker-01.qcow2
network=opencard-mvp-fa8f8eab-build-isolated
network_uuid=03f91824-e5c9-5655-ac06-fec291e81c93
bridge=virbr-opencard
pool_path=/var/lib/libvirt/images/opencard-mvp-fa8f8eab
work_path=/home/ubuntu/opencard-mvp-fa8f8eab/clean-worker-provision
marker="$pool_path/.open-card-task-marker"
base_image="$pool_path/ubuntu-24.04-server-cloudimg-amd64.img"
volume_path="$pool_path/$volume"
seed_iso="$pool_path/opencard-mvp-fa8f8eab-build-worker-01-seed.iso"
bundle_iso="$pool_path/opencard-mvp-fa8f8eab-build-worker-01-offline.iso"

if [[ "${OPEN_CARD_ALLOW_VM_LIFECYCLE:-}" != 1 || "${OPEN_CARD_PROVISION_CONFIRMATION:-}" != "provision-$domain" ]]; then
  echo "clean-worker provisioning requires the exact lifecycle authorization" >&2
  exit 77
fi
test "$(id -u)" -ne 0
sudo -n true
for command in virsh virt-install qemu-img python3; do command -v "$command" >/dev/null; done

sudo test -f "$marker" && sudo test ! -L "$marker"
test -f /home/ubuntu/opencard-mvp-fa8f8eab/.open-card-task-marker
sudo grep -Fxq "task_id=$task_id" "$marker"
sudo grep -Fxq "domain=$domain" "$marker"
sudo grep -Fxq "domain_uuid=$domain_uuid" "$marker"
sudo grep -Fxq "network=$network" "$marker"
sudo grep -Fxq "network_uuid=$network_uuid" "$marker"
sudo test -f "$base_image" && sudo test ! -L "$base_image"
sudo test -f "$seed_iso" && sudo test ! -L "$seed_iso"
sudo test -f "$bundle_iso" && sudo test ! -L "$bundle_iso"

if sudo virsh dominfo "$domain" >/dev/null 2>&1 || sudo virsh pool-info "$pool" >/dev/null 2>&1 || sudo virsh net-info "$network" >/dev/null 2>&1; then
  echo "an exact clean-worker libvirt resource already exists" >&2
  exit 78
fi
sudo test ! -e "$volume_path"
if ip link show "$bridge" >/dev/null 2>&1; then
  echo "isolated bridge name is already occupied" >&2
  exit 78
fi

install -d -m 0750 "$work_path"
pool_xml_staging="$work_path/$pool.xml"
network_xml_staging="$work_path/$network.xml"
domain_xml_staging="$work_path/$domain.xml"
pool_xml="$pool_path/$pool.xml"
network_xml="$pool_path/$network.xml"
domain_xml="$pool_path/$domain.xml"
cat >"$pool_xml_staging.part" <<EOF
<pool type='dir'>
  <name>$pool</name>
  <uuid>$pool_uuid</uuid>
  <target><path>$pool_path</path><permissions><mode>0750</mode></permissions></target>
</pool>
EOF
mv "$pool_xml_staging.part" "$pool_xml_staging"
cat >"$network_xml_staging.part" <<EOF
<network ipv6='no'>
  <name>$network</name>
  <uuid>$network_uuid</uuid>
  <bridge name='$bridge' stp='off' delay='0'/>
</network>
EOF
mv "$network_xml_staging.part" "$network_xml_staging"
chmod 0640 "$pool_xml_staging" "$network_xml_staging"
sudo install -m 0640 -o root -g libvirt-qemu "$pool_xml_staging" "$pool_xml"
sudo install -m 0640 -o root -g libvirt-qemu "$network_xml_staging" "$network_xml"

sudo virsh pool-define "$pool_xml_staging" >/dev/null
sudo virsh pool-start "$pool" >/dev/null
test "$(sudo virsh pool-info "$pool" | awk '/Autostart:/{print $2}')" = no
sudo qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$volume_path" 40G
sudo chown libvirt-qemu:libvirt-qemu "$volume_path"
sudo chmod 0640 "$volume_path"
sudo virsh pool-refresh "$pool" >/dev/null
test "$(sudo virsh vol-path --pool "$pool" "$volume")" = "$volume_path"

sudo virsh net-define "$network_xml_staging" >/dev/null
sudo virsh net-start "$network" >/dev/null
test "$(sudo virsh net-info "$network" | awk '/Autostart:/{print $2}')" = no
test -z "$(sudo virsh net-dumpxml "$network" | grep -E '<forward|<ip ' || true)"

sudo virt-install --connect qemu:///system \
  --name "$domain" \
  --uuid "$domain_uuid" \
  --memory 4096 \
  --vcpus 2 \
  --cpu host-passthrough \
  --os-variant ubuntu24.04 \
  --import \
  --disk "path=$volume_path,format=qcow2,bus=virtio,cache=none,discard=unmap" \
  --disk "path=$seed_iso,device=cdrom,readonly=on" \
  --disk "path=$bundle_iso,device=cdrom,readonly=on" \
  --network "network=$network,model=virtio" \
  --channel unix,target_type=virtio,name=org.qemu.guest_agent.0 \
  --graphics none \
  --console pty,target_type=serial \
  --noautoconsole \
  --print-xml >"$domain_xml_staging.part"
mv "$domain_xml_staging.part" "$domain_xml_staging"
chmod 0640 "$domain_xml_staging"

python3 - "$domain_xml_staging" "$pool_path" "$domain" "$domain_uuid" "$network" <<'PY'
import pathlib, sys, xml.etree.ElementTree as ET
path, pool_path, domain, domain_uuid, network = sys.argv[1:]
root = ET.parse(path).getroot()
assert root.findtext("name") == domain
assert root.findtext("uuid") == domain_uuid
assert int(root.findtext("memory")) == 4194304
assert int(root.findtext("vcpu")) == 2
assert not root.findall("./devices/filesystem")
assert not root.findall("./devices/hostdev")
interfaces = root.findall("./devices/interface")
assert len(interfaces) == 1 and interfaces[0].find("source").get("network") == network
disks = root.findall("./devices/disk")
assert len(disks) == 3
for disk in disks:
    source = disk.find("source")
    source_path = source.get("file") if source is not None else None
    assert source_path and pathlib.Path(source_path).is_relative_to(pool_path)
for disk in disks[1:]:
    assert disk.find("readonly") is not None
channels = root.findall("./devices/channel")
assert len(channels) == 1 and channels[0].find("target").get("name") == "org.qemu.guest_agent.0"
PY
sudo install -m 0640 -o root -g libvirt-qemu "$domain_xml_staging" "$domain_xml"

sudo virsh define "$domain_xml_staging" >/dev/null
test "$(sudo virsh domuuid "$domain")" = "$domain_uuid"
test "$(sudo virsh dominfo "$domain" | awk '/Autostart:/{print $2}')" = disable
sudo virsh start "$domain" >/dev/null
printf '%s\n' \
  "domain=$domain" \
  "domain_uuid=$domain_uuid" \
  "pool=$pool" \
  "pool_uuid=$pool_uuid" \
  "volume=$volume_path" \
  "network=$network" \
  "network_uuid=$network_uuid" \
  'autostart=disabled' \
  'forwarding=none' \
  'host_filesystems=none' \
  'host_devices=none' \
  'provision=complete'
