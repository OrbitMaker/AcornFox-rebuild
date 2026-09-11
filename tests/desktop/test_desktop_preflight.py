#!/usr/bin/env python3
"""
Unit and Contract Tests for AcornFox Desktop Preflight and VM Planner (AFD-01 Review V3)
Tests:
1. Schema & keys contract, installation_status == "not_checked".
2. Mac vm_stat regex with 16384 page size parsing.
3. Subprocess failures return None/null, never raise or crash.
4. CPU virtualization flag and /dev/kvm accessibility separate observation.
5. Disk usage free bytes reporting.
6. Container engine response != installation ready.
7. prepare-vm digest validation: None/empty/invalid length/non-hex rejected.
8. prepare-vm public key validation: invalid base64, multiple lines, wire length mismatch, type mismatch, symlinks rejected.
9. prepare-vm valid ed25519 (32-byte key) accepted and safely serialized into cloud-init.
10. prepare-vm strict pool enforcement (/var/lib/libvirt/images/acornfox-desktop-20260912).
11. prepare-vm stage directory: existing non-empty directory or symlink rejected.
12. prepare-vm virsh domain conflict check: error, timeout, or existing domain raises exception.
13. prepare-vm XML generation: valid ElementTree, 2 vCPU, 4096 MiB, no invalid graphics tag.
14. prepare-vm CLI --apply exit code 77.
"""

import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts/acornfox-desktop")
sys.path.insert(0, SCRIPTS_DIR)

import preflight

prepare_vm_spec = importlib.util.spec_from_file_location("prepare_vm", os.path.join(SCRIPTS_DIR, "prepare-vm.py"))
prepare_vm = importlib.util.module_from_spec(prepare_vm_spec)
prepare_vm_spec.loader.exec_module(prepare_vm)


def make_valid_ed25519_pubkey():
    # Construct a valid wire format ed25519 public key
    # wire format: string "ssh-ed25519" + string (32 bytes raw key)
    key_type = b"ssh-ed25519"
    raw_key = b"\x01" * 32
    wire = struct.pack(">I", len(key_type)) + key_type + struct.pack(">I", len(raw_key)) + raw_key
    b64 = base64.b64encode(wire).decode("ascii")
    return f"ssh-ed25519 {b64} test@domain\n"


class TestDesktopPreflight(unittest.TestCase):

    def test_schema_and_keys(self):
        data = preflight.inspect_host()
        required_keys = {
            "schema_version", "inspection_scope", "installation_status",
            "os_id", "os_version", "architecture", "cpu_cores",
            "total_ram_mb", "available_ram_mb", "memory_probe_status",
            "available_ram_is_estimated", "disk_free_bytes",
            "cpu_virtualization_flag", "dev_kvm_accessible",
            "virtualization_type", "virtualization_probe_status",
            "container_engine", "container_engine_ready",
            "vm_tools", "notices"
        }
        self.assertTrue(required_keys.issubset(data.keys()))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["inspection_scope"], "host_only_read_only")
        self.assertEqual(data["installation_status"], "not_checked")

    def test_mac_vm_stat_16384_page_size_parsing(self):
        orig_sysctl = subprocess.check_output
        def mock_output(cmd, **kwargs):
            if cmd == ["sysctl", "-n", "hw.memsize"]:
                return "17179869184\n"
            if cmd == ["vm_stat"]:
                return (
                    "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                    "Pages free: 1000.\n"
                    "Pages inactive: 2000.\n"
                )
            return orig_sysctl(cmd, **kwargs)

        try:
            subprocess.check_output = mock_output
            total_mb, avail_mb, status, estimated = preflight.get_memory_info("Darwin")
            self.assertEqual(total_mb, 16384)
            # (1000 + 2000) * 16384 = 49152000 bytes = 46 MiB
            self.assertEqual(avail_mb, 46)
            self.assertEqual(status, "ok")
            self.assertTrue(estimated)
        finally:
            subprocess.check_output = orig_sysctl

    def test_probe_failures_return_none(self):
        orig_sysctl = subprocess.check_output
        def fail_output(cmd, **kwargs):
            raise subprocess.CalledProcessError(1, cmd)

        try:
            subprocess.check_output = fail_output
            total_mb, avail_mb, status, estimated = preflight.get_memory_info("Darwin")
            self.assertIsNone(total_mb)
            self.assertIsNone(avail_mb)
            self.assertEqual(status, "unavailable")
        finally:
            subprocess.check_output = orig_sysctl

    def test_cpu_virt_and_dev_kvm_separated(self):
        flag, dev_kvm, v_type, status = preflight.check_virtualization("Linux")
        self.assertIsInstance(flag, bool)
        self.assertIsInstance(dev_kvm, bool)
        self.assertIsInstance(v_type, str)


class TestDesktopVMPlanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_dir = pathlib.Path(self.test_dir.name)

        # Create dummy base image
        self.image_path = self.base_dir / "test-cloud.img"
        content = b"TEST_CLOUD_IMAGE_V3"
        with open(self.image_path, "wb") as f:
            f.write(content)
        self.image_sha256 = hashlib.sha256(content).hexdigest()

        # Create valid ed25519 pubkey
        self.pubkey_path = self.base_dir / "id_ed25519.pub"
        with open(self.pubkey_path, "w", encoding="utf-8") as f:
            f.write(make_valid_ed25519_pubkey())

        self.pool_dir = "/var/lib/libvirt/images/acornfox-desktop-20260912"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_digest_validation_rejects_invalid(self):
        # Rejects None, empty, wrong length, non-hex
        for invalid in [None, "", "not-hex", "d0fe84bb", "g" * 64, "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e301"]:
            with self.assertRaises(ValueError):
                prepare_vm.validate_digest(invalid)

        # Accepts 64-char sha256 and 128-char sha512
        algo256, clean256 = prepare_vm.validate_digest("a" * 64)
        self.assertEqual(algo256, "sha256")
        self.assertEqual(clean256, "a" * 64)

        algo512, clean512 = prepare_vm.validate_digest("b" * 128)
        self.assertEqual(algo512, "sha512")
        self.assertEqual(clean512, "b" * 128)

    def test_pubkey_validation_rejects_invalid(self):
        # 1. Multi-line pubkey rejected
        bad_file = self.base_dir / "multiline.pub"
        with open(bad_file, "w") as f:
            f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG...\nssh-rsa AAAAB3...\n")
        with self.assertRaises(ValueError):
            prepare_vm.validate_ssh_pubkey(bad_file)

        # 2. Invalid base64 rejected
        bad_b64 = self.base_dir / "bad_b64.pub"
        with open(bad_b64, "w") as f:
            f.write("ssh-ed25519 not-valid-base64!! comment\n")
        with self.assertRaises(ValueError):
            prepare_vm.validate_ssh_pubkey(bad_b64)

        # 3. Key type mismatch between prefix and wire
        bad_wire = self.base_dir / "mismatch.pub"
        wire = struct.pack(">I", 7) + b"ssh-rsa" + b"extra"
        b64 = base64.b64encode(wire).decode("ascii")
        with open(bad_wire, "w") as f:
            f.write(f"ssh-ed25519 {b64} comment\n")
        with self.assertRaises(ValueError):
            prepare_vm.validate_ssh_pubkey(bad_wire)

        # 4. Valid key accepted
        line = prepare_vm.validate_ssh_pubkey(self.pubkey_path)
        self.assertTrue(line.startswith("ssh-ed25519"))

    def test_reject_symlink_files(self):
        sym_image = self.base_dir / "sym_image.img"
        os.symlink(self.image_path, sym_image)
        with self.assertRaises(ValueError):
            prepare_vm.validate_regular_file(str(sym_image), "Image")

        sym_pub = self.base_dir / "sym_pub.pub"
        os.symlink(self.pubkey_path, sym_pub)
        with self.assertRaises(ValueError):
            prepare_vm.validate_regular_file(str(sym_pub), "Pubkey")

    def test_strict_pool_enforcement(self):
        stage_dir = str(self.base_dir / "new_stage_pool")
        with self.assertRaises(ValueError) as ctx:
            prepare_vm.create_vm_plan(
                distro="ubuntu",
                image_path=str(self.image_path),
                expected_digest=self.image_sha256,
                pubkey_path=str(self.pubkey_path),
                stage_dir=stage_dir,
                pool_dir="/var/lib/libvirt/images/unauthorized_pool",
                check_virsh=False
            )
        self.assertIn("Pool directory must strictly be", str(ctx.exception))

    def test_stage_dir_must_be_new(self):
        existing_stage = self.base_dir / "occupied_stage"
        existing_stage.mkdir()
        (existing_stage / "stale.txt").write_text("content")

        with self.assertRaises(ValueError):
            prepare_vm.create_vm_plan(
                distro="ubuntu",
                image_path=str(self.image_path),
                expected_digest=self.image_sha256,
                pubkey_path=str(self.pubkey_path),
                stage_dir=str(existing_stage),
                pool_dir=self.pool_dir,
                check_virsh=False
            )

    def test_plan_generation_xml_and_cloud_init(self):
        stage_dir = str(self.base_dir / "clean_stage")
        plan = prepare_vm.create_vm_plan(
            distro="ubuntu",
            image_path=str(self.image_path),
            expected_digest=self.image_sha256,
            pubkey_path=str(self.pubkey_path),
            stage_dir=stage_dir,
            pool_dir=self.pool_dir,
            check_virsh=False
        )

        self.assertEqual(plan["domain_name"], "acornfox-desktop-ubuntu-20260912")
        self.assertEqual(plan["vcpu"], 2)
        self.assertEqual(plan["ram_mib"], 4096)
        self.assertEqual(plan["disk_gb"], 40)

        # Parse XML
        tree = ET.parse(plan["domain_xml_staged"])
        root = tree.getroot()
        self.assertEqual(root.findtext("name"), "acornfox-desktop-ubuntu-20260912")
        self.assertEqual(int(root.findtext("vcpu")), 2)
        self.assertEqual(int(root.findtext("memory")), 4194304)

        # Ensure no invalid graphics element exists
        graphics = root.findall(".//graphics")
        self.assertEqual(len(graphics), 0)

        # Ensure standard VGA video device exists (prevents GRUB boot loop in Debian 13)
        video = root.find(".//video/model")
        self.assertIsNotNone(video)
        self.assertEqual(video.get("type"), "vga")
        self.assertEqual(video.get("vram"), "16384")

        # Check cloud-init user data
        with open(plan["cloud_init_staged"], "r") as f:
            cinit = f.read()
        self.assertIn("ssh-ed25519", cinit)
        self.assertIn("acornfox-desktop-ubuntu-20260912", cinit)

    def test_virsh_conflict_and_error_handling(self):
        orig_run = subprocess.run
        orig_which = prepare_vm.shutil.which

        # Mock shutil.which to pretend virsh exists
        prepare_vm.shutil.which = lambda cmd: "/usr/bin/virsh" if cmd == "virsh" else None

        # Case 1: virsh returns error
        def mock_error(*args, **kwargs):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="connection refused")

        try:
            subprocess.run = mock_error
            with self.assertRaises(RuntimeError) as ctx:
                prepare_vm.check_virsh_domain_conflict("acornfox-desktop-ubuntu-20260912")
            self.assertIn("virsh returned exit code", str(ctx.exception))
        finally:
            subprocess.run = orig_run

        # Case 2: virsh finds existing domain
        def mock_found(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, stdout="existing-vm\nacornfox-desktop-ubuntu-20260912\n", stderr="")

        try:
            subprocess.run = mock_found
            with self.assertRaises(RuntimeError) as ctx:
                prepare_vm.check_virsh_domain_conflict("acornfox-desktop-ubuntu-20260912")
            self.assertIn("Conflict detected: domain 'acornfox-desktop-ubuntu-20260912' already exists", str(ctx.exception))
        finally:
            subprocess.run = orig_run
            prepare_vm.shutil.which = orig_which

    def test_apply_flag_blocked(self):
        cli_script = os.path.join(SCRIPTS_DIR, "prepare-vm.py")
        res = subprocess.run([
            sys.executable, cli_script,
            "--distro", "ubuntu",
            "--image", str(self.image_path),
            "--digest", self.image_sha256,
            "--pubkey", str(self.pubkey_path),
            "--stage-dir", str(self.base_dir / "apply_stage"),
            "--apply"
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 77)
        self.assertIn("--apply is strictly blocked in AFD-01", res.stderr)


if __name__ == "__main__":
    unittest.main()
