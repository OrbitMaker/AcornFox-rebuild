#!/usr/bin/env python3
"""
AcornFox Desktop VM Preparation Planner (AFD-01)
Strictly task-scoped generator for Ubuntu 24.04 and Debian 13 VM setups.

Mandates (Review V3):
- Strictly limited to acornfox-desktop-{ubuntu,debian}-20260912
- Strictly 2 vCPU, 4096 MiB RAM, 40 GiB independent qcow2 disk
- Digest MUST be provided and must be a valid 64-char hex (SHA256) or 128-char hex (SHA512).
  Rejects None/empty/invalid length/non-hex.
- Image and pubkey MUST be regular files (lstat, not symlinks).
- Pubkey MUST be a single line, valid base64 encoding with inner SSH key type matching declaration
  (supports ssh-ed25519 with 32-byte key, ssh-rsa >= 2048-bit).
- Target pool MUST be strictly /var/lib/libvirt/images/acornfox-desktop-20260912.
- Stage dir must be a newly created directory; existing dir or symlink rejected.
- virsh fixed to connect qemu:///system; runs `virsh --connect qemu:///system list --all --name`.
  Any virsh error, non-zero return code, or timeout REJECTS the plan. No silent pass.
- XML constructed cleanly with xml.etree.ElementTree. No duplicate virt-install representations.
  No invalid graphics tag.
- Strictly plan-only; --apply is blocked.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET


ALLOWED_DISTROS = {"ubuntu", "debian"}
TASK_TAG = "20260912"
VM_CPUS = 2
VM_RAM_MIB = 4096
VM_RAM_KIB = VM_RAM_MIB * 1024
VM_DISK_GB = 40

STRICT_POOL_DIR = f"/var/lib/libvirt/images/acornfox-desktop-{TASK_TAG}"


def validate_digest(digest_str):
    if not digest_str or not isinstance(digest_str, str):
        raise ValueError("Image digest must be provided and cannot be empty")
    digest_clean = digest_str.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", digest_clean):
        raise ValueError("Image digest must contain only hexadecimal characters")
    if len(digest_clean) == 64:
        return "sha256", digest_clean
    elif len(digest_clean) == 128:
        return "sha512", digest_clean
    else:
        raise ValueError(f"Image digest length {len(digest_clean)} is invalid (must be 64 for SHA-256 or 128 for SHA-512)")


def compute_file_digest(file_path, algorithm):
    hasher = hashlib.sha256() if algorithm == "sha256" else hashlib.sha512()
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_regular_file(path_str, desc):
    if not path_str or not isinstance(path_str, str):
        raise ValueError(f"{desc} path is required")
    p = pathlib.Path(path_str)
    try:
        st = p.lstat()
    except OSError as e:
        raise FileNotFoundError(f"{desc} file not found: {path_str} ({e})") from e

    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{desc} cannot be a symbolic link: {path_str}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{desc} must be a regular file: {path_str}")
    return p.resolve()


def validate_ssh_pubkey(pubkey_path):
    with open(pubkey_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if len(lines) != 1:
        raise ValueError(f"SSH public key file must contain exactly one non-empty line, found {len(lines)}")

    line = lines[0]
    parts = line.split()
    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format: missing key type or base64 blob")

    key_type, b64_blob = parts[0], parts[1]

    # Validate base64 decoding
    try:
        key_bytes = base64.b64decode(b64_blob, validate=True)
    except Exception as e:
        raise ValueError(f"SSH public key base64 decoding failed: {e}") from e

    # Parse SSH wire format: string key_type followed by fields
    if len(key_bytes) < 4:
        raise ValueError("SSH public key payload is truncated")

    type_len = struct.unpack(">I", key_bytes[:4])[0]
    if len(key_bytes) < 4 + type_len:
        raise ValueError("SSH public key truncated wire format")

    inner_type = key_bytes[4:4+type_len].decode("ascii", errors="replace")
    if inner_type != key_type:
        raise ValueError(f"SSH key declaration '{key_type}' does not match inner key type '{inner_type}'")

    if key_type == "ssh-ed25519":
        # Wire: string "ssh-ed25519" (11 bytes) + string key (32 bytes)
        # Total: 4 + 11 + 4 + 32 = 51 bytes
        offset = 4 + type_len
        if len(key_bytes) < offset + 4:
            raise ValueError("ssh-ed25519 key missing key payload length")
        key_len = struct.unpack(">I", key_bytes[offset:offset+4])[0]
        if key_len != 32 or len(key_bytes) != offset + 4 + 32:
            raise ValueError(f"ssh-ed25519 key must contain exactly 32-byte public key, got length {key_len}")
    elif key_type == "ssh-rsa":
        offset = 4 + type_len
        # Wire: string "ssh-rsa" + mpint e + mpint n
        if len(key_bytes) < offset + 4:
            raise ValueError("ssh-rsa key missing exponent length")
        e_len = struct.unpack(">I", key_bytes[offset:offset+4])[0]
        offset += 4 + e_len
        if len(key_bytes) < offset + 4:
            raise ValueError("ssh-rsa key missing modulus length")
        n_len = struct.unpack(">I", key_bytes[offset:offset+4])[0]
        if n_len < 256:  # Less than 2048-bit RSA
            raise ValueError(f"ssh-rsa key length ({n_len*8} bits) is under the 2048-bit security requirement")
    else:
        raise ValueError(f"Unsupported SSH key type '{key_type}', only ssh-ed25519 and ssh-rsa are permitted")

    return line


def check_virsh_domain_conflict(domain_name):
    """
    Fixed to qemu:///system. list --all --name must succeed.
    Any failure or timeout raises an exception.
    """
    virsh_bin = shutil.which("virsh")
    if not virsh_bin:
        raise RuntimeError("virsh command not found; cannot verify libvirt domain conflict status")

    try:
        proc = subprocess.run(
            [virsh_bin, "--connect", "qemu:///system", "list", "--all", "--name"],
            capture_output=True,
            text=True,
            timeout=5
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"virsh query timed out after 5 seconds: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to execute virsh: {e}") from e

    if proc.returncode != 0:
        raise RuntimeError(f"virsh returned exit code {proc.returncode}: {proc.stderr.strip()}")

    existing_domains = {d.strip() for d in proc.stdout.splitlines() if d.strip()}
    if domain_name in existing_domains:
        raise RuntimeError(f"Conflict detected: domain '{domain_name}' already exists in libvirt")


def build_domain_xml_tree(domain_name, pool_dir, bridge_net="default"):
    volume_path = os.path.join(pool_dir, f"{domain_name}.qcow2")
    seed_iso_path = os.path.join(pool_dir, f"{domain_name}-seed.iso")

    domain = ET.Element("domain", type="kvm")

    name_el = ET.SubElement(domain, "name")
    name_el.text = domain_name

    mem_el = ET.SubElement(domain, "memory", unit="KiB")
    mem_el.text = str(VM_RAM_KIB)
    cur_mem = ET.SubElement(domain, "currentMemory", unit="KiB")
    cur_mem.text = str(VM_RAM_KIB)

    vcpu_el = ET.SubElement(domain, "vcpu", placement="static")
    vcpu_el.text = str(VM_CPUS)

    os_el = ET.SubElement(domain, "os")
    type_el = ET.SubElement(os_el, "type", arch="x86_64", machine="q35")
    type_el.text = "hvm"
    ET.SubElement(os_el, "boot", dev="hd")

    features_el = ET.SubElement(domain, "features")
    ET.SubElement(features_el, "acpi")
    ET.SubElement(features_el, "apic")

    ET.SubElement(domain, "cpu", mode="host-passthrough", check="none")
    ET.SubElement(domain, "clock", offset="utc")
    ET.SubElement(domain, "on_poweroff").text = "destroy"
    ET.SubElement(domain, "on_reboot").text = "restart"
    ET.SubElement(domain, "on_crash").text = "destroy"

    devices_el = ET.SubElement(domain, "devices")
    ET.SubElement(devices_el, "emulator").text = "/usr/bin/qemu-system-x86_64"

    # Disk vda
    disk_vda = ET.SubElement(devices_el, "disk", type="file", device="disk")
    ET.SubElement(disk_vda, "driver", name="qemu", type="qcow2", cache="none", discard="unmap")
    ET.SubElement(disk_vda, "source", file=volume_path)
    ET.SubElement(disk_vda, "target", dev="vda", bus="virtio")

    # CDROM seed.iso
    disk_cd = ET.SubElement(devices_el, "disk", type="file", device="cdrom")
    ET.SubElement(disk_cd, "driver", name="qemu", type="raw")
    ET.SubElement(disk_cd, "source", file=seed_iso_path)
    ET.SubElement(disk_cd, "target", dev="sda", bus="sata")
    ET.SubElement(disk_cd, "readonly")

    # Network
    net_el = ET.SubElement(devices_el, "interface", type="network")
    ET.SubElement(net_el, "source", network=bridge_net)
    ET.SubElement(net_el, "model", type="virtio")

    # Serial and console
    ser_el = ET.SubElement(devices_el, "serial", type="pty")
    ET.SubElement(ser_el, "target", type="isa-serial", port="0")
    con_el = ET.SubElement(devices_el, "console", type="pty")
    ET.SubElement(con_el, "target", type="serial", port="0")

    # QEMU Guest Agent channel
    chan_el = ET.SubElement(devices_el, "channel", type="unix")
    ET.SubElement(chan_el, "target", type="virtio", name="org.qemu.guest_agent.0")

    # Standard VGA video device (prevents GRUB boot loop in cloud images like Debian 13 without graphics/VNC)
    video_el = ET.SubElement(devices_el, "video")
    ET.SubElement(video_el, "model", type="vga", vram="16384", heads="1")

    return domain


def build_cloud_init_safe_yaml(hostname, pubkey_line):
    # Construct safe JSON-serializable user data dictionary
    # Cloud-init supports standard YAML syntax
    return (
        "#cloud-config\n"
        f"hostname: {json.dumps(hostname)}\n"
        f"fqdn: {json.dumps(hostname + '.local')}\n"
        "manage_etc_hosts: true\n"
        "users:\n"
        "  - name: acornfox\n"
        "    gecos: AcornFox Test User\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
        "    shell: /bin/bash\n"
        "    ssh_authorized_keys:\n"
        f"      - {json.dumps(pubkey_line)}\n"
        "ssh_pwauth: false\n"
        "disable_root: true\n"
        "package_update: false\n"
    )


def create_vm_plan(distro, image_path, expected_digest, pubkey_path, stage_dir, pool_dir=None, check_virsh=True):
    if distro not in ALLOWED_DISTROS:
        raise ValueError(f"Distro '{distro}' is not allowed. Must be one of: {sorted(ALLOWED_DISTROS)}")

    # Pool path enforcement
    effective_pool = pool_dir if pool_dir else STRICT_POOL_DIR
    if os.path.normpath(effective_pool) != os.path.normpath(STRICT_POOL_DIR):
        raise ValueError(f"Pool directory must strictly be {STRICT_POOL_DIR}, got {effective_pool}")

    domain_name = f"acornfox-desktop-{distro}-{TASK_TAG}"

    # 1. Image verification
    hash_algo, clean_expected_hash = validate_digest(expected_digest)
    image_file = validate_regular_file(image_path, "Base image")
    actual_hash = compute_file_digest(image_file, hash_algo)
    if actual_hash != clean_expected_hash:
        raise ValueError(f"Base image digest mismatch for {image_file}! Expected {clean_expected_hash}, computed {actual_hash}")

    # 2. Public key verification
    pubkey_file = validate_regular_file(pubkey_path, "SSH public key")
    sanitized_pubkey = validate_ssh_pubkey(pubkey_file)

    # 3. Libvirt domain conflict check
    if check_virsh:
        check_virsh_domain_conflict(domain_name)

    # 4. Stage dir verification: MUST be a new directory created in this run
    stage_path = pathlib.Path(stage_dir)
    if stage_path.is_symlink():
        raise ValueError(f"Stage directory cannot be a symbolic link: {stage_dir}")
    if stage_path.exists():
        if not stage_path.is_dir() or any(stage_path.iterdir()):
            raise ValueError(f"Stage directory must be a newly created empty directory: {stage_dir}")
    else:
        stage_path.mkdir(parents=True, exist_ok=False)

    # 5. Write staged artifacts only after all validations succeed
    cloud_init_content = build_cloud_init_safe_yaml(domain_name, sanitized_pubkey)
    cloud_init_file = stage_path / f"{domain_name}-user-data"
    with open(cloud_init_file, "w", encoding="utf-8") as f:
        f.write(cloud_init_content)

    domain_tree = build_domain_xml_tree(domain_name, effective_pool)
    xml_file = stage_path / f"{domain_name}.xml"
    ET.indent(domain_tree, space="  ")
    domain_tree_str = ET.tostring(domain_tree, encoding="utf-8", xml_declaration=False).decode("utf-8")
    with open(xml_file, "w", encoding="utf-8") as f:
        f.write(domain_tree_str + "\n")

    return {
        "domain_name": domain_name,
        "distro": distro,
        "vcpu": VM_CPUS,
        "ram_mib": VM_RAM_MIB,
        "disk_gb": VM_DISK_GB,
        "base_image": str(image_file),
        "base_image_digest": actual_hash,
        "digest_type": hash_algo,
        "domain_xml_staged": str(xml_file),
        "cloud_init_staged": str(cloud_init_file),
        "target_pool_dir": effective_pool,
        "target_volume": f"{effective_pool}/{domain_name}.qcow2",
        "seed_iso_target": f"{effective_pool}/{domain_name}-seed.iso",
        "status": "plan_generated_requires_independent_disk_and_seed_creation"
    }


def main():
    parser = argparse.ArgumentParser(description="AcornFox Desktop VM Preparation Planner")
    parser.add_argument("--distro", choices=["ubuntu", "debian"], required=True, help="Target distro (ubuntu or debian)")
    parser.add_argument("--image", required=True, help="Path to base cloud image regular file")
    parser.add_argument("--digest", required=True, help="Expected image digest (SHA-256 or SHA-512)")
    parser.add_argument("--pubkey", required=True, help="Path to authorized SSH public key regular file")
    parser.add_argument("--stage-dir", required=True, help="New empty staging directory for XML/cloud-init")
    parser.add_argument("--pool-dir", default=STRICT_POOL_DIR, help=f"Libvirt pool directory (Must be {STRICT_POOL_DIR})")
    parser.add_argument("--apply", action="store_true", help="Execute changes (Blocked in AFD-01)")

    args = parser.parse_args()

    if args.apply:
        print("ERROR: --apply is strictly blocked in AFD-01. Plan must be reviewed by the main agent.", file=sys.stderr)
        sys.exit(77)

    try:
        plan = create_vm_plan(
            distro=args.distro,
            image_path=args.image,
            expected_digest=args.digest,
            pubkey_path=args.pubkey,
            stage_dir=args.stage_dir,
            pool_dir=args.pool_dir
        )
        print(json.dumps(plan, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
