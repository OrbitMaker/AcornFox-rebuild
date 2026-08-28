from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "deploy" / "worker" / "clean-worker-spec.json"
VALIDATOR_PATH = REPO_ROOT / "tools" / "worker" / "validate_clean_worker_spec.py"
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "clean-worker"
IMAGE_FIXTURE = FIXTURE_ROOT / "worker-image.fixture"
BUNDLE_FIXTURE = FIXTURE_ROOT / "offline-bundle.fixture"
TASK_ID = "opencard-mvp-fa8f8eab"


def load_spec() -> dict[str, object]:
    payload = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("clean worker spec must be an object")
    return payload


class CleanWorkerSpecTests(unittest.TestCase):
    def run_validator(self, spec_path: Path, *extra_args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR_PATH), str(spec_path), *extra_args],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def write_artifact_spec(self, directory: Path) -> Path:
        image_path = directory / "worker.img"
        bundle_path = directory / "offline.bundle"
        shutil.copyfile(IMAGE_FIXTURE, image_path)
        shutil.copyfile(BUNDLE_FIXTURE, bundle_path)

        spec = load_spec()
        spec["image_path"] = str(image_path)
        spec["image_sha256"] = hashlib.sha256(image_path.read_bytes()).hexdigest()
        spec["offline_bundle_path"] = str(bundle_path)
        spec["offline_bundle_sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        spec_path = directory / "clean-worker-spec.json"
        spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return spec_path

    def test_checked_in_spec_uses_exact_task_resource_names(self) -> None:
        spec = load_spec()

        self.assertEqual(spec["task_id"], TASK_ID)
        self.assertEqual(spec["domain_name"], f"{TASK_ID}-build-worker-01")
        self.assertEqual(spec["domain_uuid"], "fce4e26d-93b0-5128-a090-969ef73835d4")
        self.assertEqual(spec["pool_name"], f"{TASK_ID}-build-workers")
        self.assertEqual(spec["pool_uuid"], "72a914c5-b6c7-5f22-a3bd-88f9b43f1619")
        self.assertEqual(spec["pool_path"], f"/var/lib/libvirt/images/{TASK_ID}")
        self.assertEqual(spec["volume_name"], f"{TASK_ID}-build-worker-01.qcow2")
        self.assertEqual(spec["network_name"], f"{TASK_ID}-build-isolated")
        self.assertEqual(spec["network_uuid"], "03f91824-e5c9-5655-ac06-fec291e81c93")

    def test_only_exact_authorized_resources_are_accepted(self) -> None:
        authorized = {
            "vcpus": 2,
            "memory_mib": 4096,
            "disk_gib": 40,
            "build_memory_mib": 512,
            "build_cpu_quota": 50000,
            "build_cpu_period": 100000,
            "build_timeout_seconds": 300,
            "max_concurrent_builds": 1,
        }
        with tempfile.TemporaryDirectory() as raw_tmp:
            directory = Path(raw_tmp)
            spec_path = self.write_artifact_spec(directory)
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            spec["resources"].update(authorized)
            spec["acceptance"]["expected_memory_max_bytes"] = authorized["build_memory_mib"] * 1024 * 1024
            spec["acceptance"]["expected_cpu_max"] = f"{authorized['build_cpu_quota']} {authorized['build_cpu_period']}"
            spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            accepted = self.run_validator(spec_path)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            self.assertEqual(json.loads(accepted.stdout)["provisioning_status"], "READY_FOR_EXPLICIT_AUTHORIZATION")

            for field, value in authorized.items():
                unauthorized = json.loads(spec_path.read_text(encoding="utf-8"))
                unauthorized["resources"][field] = value + 1
                unauthorized["acceptance"]["expected_memory_max_bytes"] = unauthorized["resources"]["build_memory_mib"] * 1024 * 1024
                unauthorized["acceptance"]["expected_cpu_max"] = (
                    f"{unauthorized['resources']['build_cpu_quota']} {unauthorized['resources']['build_cpu_period']}"
                )
                unauthorized_path = directory / f"unauthorized-{field}.json"
                unauthorized_path.write_text(json.dumps(unauthorized, indent=2, sort_keys=True) + "\n", encoding="utf-8")

                rejected = self.run_validator(unauthorized_path)
                self.assertNotEqual(rejected.returncode, 0, field)
                self.assertIn("approved exact value", rejected.stdout, field)

    def test_isolation_forbids_forwarding_mounts_socket_privilege_and_autostart(self) -> None:
        mutations = {
            "network_mode": "isolated-forwarding",
            "network_forward": True,
            "host_mounts": ["/var/lib/opencard"],
            "host_devices": ["/dev/kvm"],
            "host_docker_socket": True,
            "privileged": True,
            "autostart": True,
        }
        with tempfile.TemporaryDirectory() as raw_tmp:
            directory = Path(raw_tmp)
            baseline_path = self.write_artifact_spec(directory)
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            self.assertFalse(baseline["isolation"].get("autostart", False))

            for field, value in mutations.items():
                mutated = json.loads(json.dumps(baseline))
                mutated["isolation"][field] = value
                mutated_path = directory / f"mutated-{field}.json"
                mutated_path.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n", encoding="utf-8")

                rejected = self.run_validator(mutated_path)
                self.assertNotEqual(rejected.returncode, 0, field)

    def test_placeholder_artifacts_are_blocked_until_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            spec_path = Path(raw_tmp) / "clean-worker-spec.json"
            spec_path.write_text(SPEC_PATH.read_text(encoding="utf-8"), encoding="utf-8")

            blocked = self.run_validator(spec_path)
            self.assertEqual(blocked.returncode, 78, blocked.stdout + blocked.stderr)
            blocked_payload = json.loads(blocked.stdout)
            self.assertFalse(blocked_payload["valid"])
            self.assertTrue(blocked_payload["blocked"])

            allowed = self.run_validator(spec_path, "--allow-placeholder")
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            allowed_payload = json.loads(allowed.stdout)
            self.assertTrue(allowed_payload["valid"])
            self.assertEqual(allowed_payload["provisioning_status"], "BLOCKED_PENDING_IMAGE_AND_AUTHORIZATION")

    def test_tampered_artifact_checksum_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            directory = Path(raw_tmp)
            spec_path = self.write_artifact_spec(directory)

            accepted = self.run_validator(spec_path)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

            with (directory / "worker.img").open("ab") as image:
                image.write(b"tampered")
            rejected = self.run_validator(spec_path)
            self.assertEqual(rejected.returncode, 78, rejected.stdout + rejected.stderr)
            payload = json.loads(rejected.stdout)
            self.assertFalse(payload["valid"])
            self.assertTrue(payload["blocked"])
            self.assertIn("image checksum mismatch", payload["error"])


if __name__ == "__main__":
    unittest.main()
