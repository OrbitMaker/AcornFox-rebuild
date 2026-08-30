#!/usr/bin/env python3
import json
import os
import stat
import subprocess
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "mvp" / "host-preflight.sh"
CAPACITY = ROOT / "scripts" / "mvp" / "buildkit-production-capacity.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "g6_host_preflight"


class HostPreflightTests(unittest.TestCase):
    def run_fixture(self, name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(SCRIPT), "--task-fixture-root", str(FIXTURES / name)],
            env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"},
            text=True,
            capture_output=True,
            check=False,
        )

    def run_capacity(self, verb: str, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CAPACITY), verb, "--task-root", str(root)],
            env={"PATH": os.environ["PATH"], "OPEN_CARD_BUILDKIT_CAPACITY_TEST": "1"},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_fixed_capacity_boundary_and_machine_receipt(self) -> None:
        result = self.run_fixture("pass")
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["vcpus"], 4)
        self.assertEqual(receipt["memory_total_kib"], 8388608)
        self.assertEqual(receipt["root_total_kib"], 104857600)
        self.assertEqual(receipt["root_free_kib"], 83886080)
        self.assertEqual(receipt["reasons"], [])
        self.assertNotIn("OPEN_CARD", result.stdout)

    def test_low_disk_is_rejected_without_mutation(self) -> None:
        before = {path.relative_to(FIXTURES): path.stat().st_mtime_ns for path in (FIXTURES / "low-disk").iterdir()}
        result = self.run_fixture("low-disk")
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "fail")
        self.assertIn("disk", receipt["reasons"])
        after = {path.relative_to(FIXTURES): path.stat().st_mtime_ns for path in (FIXTURES / "low-disk").iterdir()}
        self.assertEqual(before, after)

    def test_task_seam_is_explicit_and_production_paths_are_fixed(self) -> None:
        result = subprocess.run([str(SCRIPT), "--task-fixture-root", str(FIXTURES / "pass")], text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("task fixture seam is disabled", result.stderr)
        text = SCRIPT.read_text(encoding="utf-8")
        host = (ROOT / "scripts/mvp/install-host.sh").read_text(encoding="utf-8")
        capacity = CAPACITY.read_text(encoding="utf-8")
        self.assertIn("OPEN_CARD_DEDICATED_HOST_CONFIRMATION", host)
        self.assertIn("OPEN-CARD-DEDICATED-HOST", text + host)
        self.assertIn("MemoryMax=2G", capacity)
        self.assertIn("CPUQuota=200%", capacity)
        self.assertEqual(stat.S_IMODE(SCRIPT.stat().st_mode), 0o755)
        for options in (
            ["--allow-prerequisites-pending", "--post-prerequisites"],
            ["--post-prerequisites", "--allow-prerequisites-pending"],
        ):
            result = subprocess.run(
                [str(SCRIPT), *options, "--task-fixture-root", str(FIXTURES / "pass")],
                env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("preflight modes conflict", result.stderr)

    def test_multiple_and_malformed_facts_always_emit_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "fixture"
            shutil.copytree(FIXTURES / "pass", root)
            (root / "vcpus").write_text("four\n", encoding="utf-8")
            (root / "root.df").write_text("malformed\n", encoding="utf-8")
            (root / "listeners").write_text("LISTEN 0 1 0.0.0.0:443 0.0.0.0:*\n", encoding="utf-8")
            (root / "services").write_text("nginx\n", encoding="utf-8")
            result = subprocess.run([str(SCRIPT), "--task-fixture-root", str(root)], env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"}, text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "fail")
        self.assertEqual(receipt["vcpus"], 0)
        self.assertEqual(receipt["root_total_kib"], 0)
        self.assertIn("vcpus_format", receipt["reasons"])
        self.assertIn("disk_format", receipt["reasons"])
        self.assertIn("listeners", receipt["reasons"])
        self.assertIn("existing_services", receipt["reasons"])

    def test_listener_and_post_prerequisite_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "fixture"
            shutil.copytree(FIXTURES / "pass", root)
            (root / "listeners").write_text("LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 1 127.0.0.1:5432 0.0.0.0:*\n", encoding="utf-8")
            (root / "services").write_text("docker\npostgresql\n", encoding="utf-8")
            command = [str(SCRIPT), "--post-prerequisites", "--task-fixture-root", str(root)]
            result = subprocess.run(command, env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"}, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout)
            (root / "listeners").write_text("LISTEN 0 1 [::]:443 [::]:*\n", encoding="utf-8")
            result = subprocess.run(command, env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"}, text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("listeners", json.loads(result.stdout)["reasons"])

    def test_all_frozen_capacity_and_isolation_boundaries_fail_closed(self) -> None:
        cases = {
            "architecture": {"architecture": "aarch64\n"},
            "os": {"os-release": 'ID=debian\nVERSION_ID="24.04"\n'},
            "vcpus": {"vcpus": "3\n"},
            "memory-total": {"meminfo": "MemTotal: 8388607 kB\nMemAvailable: 4194304 kB\n"},
            "memory-reserve": {"meminfo": "MemTotal: 8388608 kB\nMemAvailable: 2516582 kB\n"},
            "disk-total": {"root.df": "/dev/vda1 104857599 1000 90000000 14% /\n"},
            "disk-free": {"root.df": "/dev/vda1 104857600 31457280 73400319 30% /\n"},
            "disk-reserve": {"root.df": "/dev/vda1 300000000 210000000 80000000 74% /\n"},
            "inode-reserve": {"root.inodes": "/dev/vda1 1000000 700001 299999 71% /\n"},
            "time": {"time": "no\n"},
            "containers": {"docker": "available:/var/lib/docker:1\n"},
            "service": {"services": "nginx\n"},
            "listener": {"listeners": "LISTEN 0 1 0.0.0.0:443 0.0.0.0:*\n"},
        }
        for expected_reason, replacements in cases.items():
            with self.subTest(expected_reason=expected_reason), tempfile.TemporaryDirectory() as raw:
                fixture = Path(raw).resolve() / "fixture"
                shutil.copytree(FIXTURES / "pass", fixture)
                for name, value in replacements.items():
                    (fixture / name).write_text(value, encoding="utf-8")
                result = subprocess.run(
                    [str(SCRIPT), "--task-fixture-root", str(fixture)],
                    env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1", "SECRET_CANARY": "must-not-leak"},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], "fail")
                self.assertNotIn("must-not-leak", result.stdout + result.stderr)
        with tempfile.TemporaryDirectory() as raw:
            fixture = Path(raw).resolve() / "fixture"
            shutil.copytree(FIXTURES / "pass", fixture)
            (fixture / "services").write_text("docker\n", encoding="utf-8")
            result = subprocess.run(
                [str(SCRIPT), "--task-fixture-root", str(fixture)],
                env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
        with tempfile.TemporaryDirectory() as raw:
            real = Path(raw).resolve() / "real"
            real.mkdir()
            link = Path(raw).resolve() / "link"
            link.symlink_to(real, target_is_directory=True)
            result = subprocess.run(
                [str(SCRIPT), "--task-fixture-root", str(link)],
                env={"PATH": os.environ["PATH"], "OPEN_CARD_HOST_PREFLIGHT_TEST": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_capacity_helper_create_verify_replay_remove_and_absent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            empty_root = Path(raw).resolve() / "empty"
            empty_root.mkdir(mode=0o700)
            initially_absent = self.run_capacity("remove", empty_root)
            self.assertEqual(initially_absent.returncode, 0, initially_absent.stdout + initially_absent.stderr)
            self.assertEqual(initially_absent.stdout.count("\n"), 1)
            self.assertEqual(json.loads(initially_absent.stdout), {"status": "absent"})
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "root"
            root.mkdir(mode=0o700)
            created = self.run_capacity("install", root)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            self.assertEqual(json.loads(created.stdout), {"status": "created"})
            target = root / "etc/systemd/system/open-card-buildkit.service.d/20-production-capacity.conf"
            self.assertEqual(target.read_bytes(), b"[Service]\nMemoryMax=2G\nCPUQuota=200%\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
            self.assertEqual(json.loads(self.run_capacity("verify", root).stdout), {"status": "existing"})
            replay = self.run_capacity("install", root)
            self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
            self.assertEqual(json.loads(replay.stdout), {"status": "existing"})
            removed = self.run_capacity("remove", root)
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertEqual(json.loads(removed.stdout), {"status": "removed"})
            self.assertFalse(target.exists())
            absent = self.run_capacity("remove", root)
            self.assertEqual(absent.returncode, 0, absent.stdout + absent.stderr)
            self.assertEqual(json.loads(absent.stdout), {"status": "absent"})

    def test_capacity_helper_rejects_foreign_mode_and_symlink_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "root"
            root.mkdir(mode=0o700)
            self.assertEqual(self.run_capacity("install", root).returncode, 0)
            target = root / "etc/systemd/system/open-card-buildkit.service.d/20-production-capacity.conf"
            target.write_text("[Service]\nMemoryMax=infinity\n", encoding="utf-8")
            foreign = self.run_capacity("install", root)
            self.assertNotEqual(foreign.returncode, 0)
            self.assertEqual(json.loads(foreign.stdout)["code"], "invalid_target")
            self.assertIn("infinity", target.read_text(encoding="utf-8"))
            target.write_bytes(b"[Service]\nMemoryMax=2G\nCPUQuota=200%\n")
            target.chmod(0o600)
            wrong_mode = self.run_capacity("verify", root)
            self.assertNotEqual(wrong_mode.returncode, 0)
            target.unlink()
            outside = root / "outside"
            outside.write_text("sentinel", encoding="utf-8")
            target.symlink_to(outside)
            symlink = self.run_capacity("remove", root)
            self.assertNotEqual(symlink.returncode, 0)
            self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "root"
            root.mkdir(mode=0o700)
            outside = Path(raw).resolve() / "outside"
            outside.mkdir()
            (root / "etc").symlink_to(outside, target_is_directory=True)
            parent_link = self.run_capacity("install", root)
            self.assertNotEqual(parent_link.returncode, 0)
            self.assertEqual(json.loads(parent_link.stdout)["code"], "unsafe_parent")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "root"
            root.mkdir(mode=0o700)
            disabled = subprocess.run(
                [str(CAPACITY), "install", "--task-root", str(root)],
                env={"PATH": os.environ["PATH"]},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(disabled.returncode, 0)

    def test_installer_arms_capacity_rollback_before_reload_and_activation(self) -> None:
        host = (ROOT / "scripts/mvp/install-host.sh").read_text(encoding="utf-8")
        helper = (ROOT / "scripts/mvp/buildkit-production-capacity.sh").read_text(encoding="utf-8")
        created = host.index('capacity_receipt=$("$script_dir/buildkit-production-capacity.sh" install)')
        armed = host.index("trap capacity_rollback EXIT", created)
        reload = host.index("/usr/bin/systemctl daemon-reload", armed)
        activation = host.index('"${installer[@]}"', reload)
        disarmed = host.index("trap - EXIT", activation)
        self.assertLess(created, armed)
        self.assertLess(armed, reload)
        self.assertLess(reload, activation)
        self.assertLess(activation, disarmed)
        self.assertIn('"$script_dir/buildkit-production-capacity.sh" remove', host[created:activation])
        self.assertIn("os.link(temporary, target", helper)


if __name__ == "__main__":
    unittest.main()
