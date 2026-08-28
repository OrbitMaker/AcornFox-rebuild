from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "m7"
RUNBOOK_ROOT = ROOT / "docs" / "runbooks"
sys.path.insert(0, str(ROOT / "tools" / "evidence"))

import assert_m7_foundation as foundation  # noqa: E402


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain an object")
    return value


class M7FoundationTests(unittest.TestCase):
    def test_fixture_manifest_metadata_and_runbooks_are_valid(self) -> None:
        summary = foundation.validate_m7_foundation(FIXTURE_ROOT, runbook_root=RUNBOOK_ROOT)
        self.assertTrue(summary["passed"], summary)
        self.assertFalse(summary["writes_gate_evidence"])

    def test_frozen_matrix_contains_exact_sixteen_ids(self) -> None:
        metadata = read_json(FIXTURE_ROOT / "metadata.json")
        self.assertEqual(
            set(metadata["test_ids"]),
            {
                "INSTALL-001", "INSTALL-002", "INSTALL-003",
                "UPGRADE-001", "UPGRADE-002", "UPGRADE-003", "UPGRADE-004", "UPGRADE-005",
                "RC-SUPPLY-001", "BACKUP-RESTORE-001", "REBOOT-RECOVERY-001",
                "FAULT-RC-001", "SECURITY-RC-001", "E2E-RC-001",
                "REGRESSION-RC-001", "HOST-RECLAIM-001",
            },
        )
        self.assertEqual(metadata["support_matrix"], {
            "os": "Ubuntu 24.04 LTS",
            "architecture": "amd64",
            "network_modes": ["online-explicit", "offline-bundle"],
            "docker": "external-preflight",
            "systemd": True,
            "autostart": True,
        })

    def test_canonical_bundle_descriptors_match_payload_checksums_and_modes(self) -> None:
        manifest = read_json(FIXTURE_ROOT / "bundle" / "canonical-manifest.json")
        self.assertEqual(manifest["active_gate"], "NOT_RUN")
        self.assertTrue(manifest["fixture_only"])
        for descriptor in manifest["files"]:
            source = FIXTURE_ROOT / "bundle" / descriptor["source"]
            self.assertTrue(source.is_file(), descriptor)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), descriptor["sha256"], descriptor["source"])
            self.assertEqual(source.stat().st_mode & 0o777, descriptor["mode"], descriptor["source"])

    def test_manifest_tampering_is_detected_without_active_evidence_write(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            copied = Path(raw_tmp) / "m7"
            shutil.copytree(FIXTURE_ROOT, copied)
            payload = copied / "bundle" / "payload" / "open-card-server"
            payload.write_text(payload.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
            issues = foundation.validate_fixture_manifest(copied)
            self.assertIn("manifest_mismatch", {issue.code for issue in issues})
            self.assertIn("bundle_checksum", {issue.code for issue in issues})

    def test_runbooks_map_all_ids_to_existing_safe_entrypoints(self) -> None:
        issues = foundation.validate_runbooks(RUNBOOK_ROOT)
        self.assertEqual(issues, [], [issue.as_dict() for issue in issues])
        combined = "\n".join(path.read_text(encoding="utf-8") for path in RUNBOOK_ROOT.glob("m7-*.md"))
        for script in (
            "scripts/mvp/install.sh",
            "scripts/mvp/upgrade.sh",
            "scripts/mvp/backup-control-plane.sh",
            "scripts/mvp/restore-control-plane.sh",
            "scripts/mvp/uninstall.sh",
        ):
            self.assertIn(script, combined)

    def test_default_uninstall_and_reclaim_contracts_are_fail_closed(self) -> None:
        uninstall = read_json(FIXTURE_ROOT / "uninstall" / "preserve-default.json")
        self.assertEqual(uninstall["default_mode"], "preserve-data")
        self.assertFalse(uninstall["dangerous_mode"]["default_enabled"])
        self.assertEqual(uninstall["dangerous_mode"]["requires_exact_confirmation"], "OPEN-CARD-PURGE")
        reclaim = read_json(FIXTURE_ROOT / "host" / "reclaim-contract.json")
        self.assertEqual(reclaim["task_prefix"], "opencard-mvp-fa8f8eab")
        self.assertEqual(reclaim["domain"], "opencard-mvp-fa8f8eab-build-worker-01")
        self.assertFalse(reclaim["limits"]["forwarding"])
        self.assertFalse(reclaim["limits"]["host_mounts"])
        self.assertFalse(reclaim["limits"]["host_devices"])
        self.assertIn("host_diff_zero", reclaim["reclaim_sequence"])

    def test_e2e_fixture_is_contract_only_and_ai_disabled(self) -> None:
        scenario = read_json(FIXTURE_ROOT / "e2e" / "rc-scenario.json")
        self.assertEqual(scenario["status"], "RUNNER_CONTRACT_ONLY")
        self.assertFalse(scenario["ai_enabled"])
        self.assertEqual([step["step"] for step in scenario["steps"]], list(range(1, 9)))
        self.assertTrue(scenario["completion_rules"]["all_steps_need_independent_evidence"])
        self.assertTrue(scenario["completion_rules"]["failed_step_is_not_pass"])

    def test_validator_rejects_weak_only_real_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence = Path(raw_tmp) / "INSTALL-001"
            evidence.mkdir()
            values = {
                "result.json": {
                    "test_id": "INSTALL-001", "version": 1,
                    "started_at": "2026-08-26T00:00:00Z", "finished_at": "2026-08-26T00:00:01Z",
                    "exit_code": 0, "conclusion": "PASS", "failure_reason": None,
                    "evidence_types": ["http_200", "container_exists"],
                },
                "inputs.redacted.json": {"bundle_ref": "fixture"},
                "objects-before.json": {"evidence_type": "http_200"},
                "objects-after.json": {"evidence_type": "container_exists"},
            }
            for name, value in values.items():
                (evidence / name).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            (evidence / "events.ndjson").write_text(json.dumps({
                "sequence": 1, "actor": "m7-test", "idempotency_key": "INSTALL-001:1", "evidence_refs": ["objects-after.json"],
            }) + "\n", encoding="utf-8")
            manifest_lines = []
            for name in foundation.REQUIRED_EVIDENCE_FILES:
                if name != "manifest.sha256":
                    manifest_lines.append(f"{hashlib.sha256((evidence / name).read_bytes()).hexdigest()}  {name}")
            (evidence / "manifest.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
            issues = foundation.validate_evidence_dir(evidence, expected_test_id="INSTALL-001")
            self.assertIn("insufficient_evidence", {issue.code for issue in issues})


if __name__ == "__main__":
    unittest.main()
