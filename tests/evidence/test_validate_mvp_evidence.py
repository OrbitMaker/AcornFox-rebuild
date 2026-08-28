from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "tools" / "evidence" / "validate_mvp_evidence.py"
M0_RUNNER = REPO_ROOT / "tools" / "evidence" / "run_m0_evidence_tests.py"
REQUIRED_EVIDENCE_FILES = (
    "result.json",
    "inputs.redacted.json",
    "objects-before.json",
    "objects-after.json",
    "events.ndjson",
)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_manifest(evidence_dir: Path) -> None:
    lines = []
    for name in REQUIRED_EVIDENCE_FILES:
        digest = hashlib.sha256((evidence_dir / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (evidence_dir / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_valid_evidence(evidence_dir: Path, test_id: str = "UNIT-SAMPLE-001") -> None:
    evidence_dir.mkdir(parents=True)
    _write_json(
        evidence_dir / "result.json",
        {
            "test_id": test_id,
            "version": 1,
            "started_at": "2026-08-24T00:00:00Z",
            "finished_at": "2026-08-24T00:00:01Z",
            "exit_code": 0,
            "conclusion": "PASS",
            "failure_reason": None,
            "evidence_types": ["object_state", "event_sequence", "checksum"],
        },
    )
    _write_json(
        evidence_dir / "inputs.redacted.json",
        {
            "source_revision": "fixture-v1",
            "secret_ref": "db-password",
            "password": "[REDACTED]",
        },
    )
    _write_json(evidence_dir / "objects-before.json", {"release": None, "evidence_type": "object_state"})
    _write_json(evidence_dir / "objects-after.json", {"release": {"id": "rel_1"}, "evidence_type": "object_state"})
    (evidence_dir / "events.ndjson").write_text(
        json.dumps(
            {
                "sequence": 1,
                "actor": "test-runner",
                "idempotency_key": "UNIT-SAMPLE-001:1",
                "evidence_refs": ["objects-after.json"],
                "evidence_type": "event_sequence",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_manifest(evidence_dir)


class EvidenceValidatorTests(unittest.TestCase):
    def run_validator(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), *args],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_evidence_001_fails_when_required_evidence_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "artifacts" / "mvp" / "m0" / "EVIDENCE-001"
            _write_valid_evidence(evidence_dir, "EVIDENCE-001")
            (evidence_dir / "objects-after.json").unlink()

            completed = self.run_validator(str(evidence_dir))

            self.assertNotEqual(completed.returncode, 0)
            payload = json.loads(completed.stdout)
            issues = payload["results"][0]["issues"]
            self.assertIn("missing_file", {issue["code"] for issue in issues})
            self.assertTrue(any("objects-after.json" in issue["message"] for issue in issues))

    def test_evidence_002_fails_when_http_and_container_are_the_only_success_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "artifacts" / "mvp" / "m1" / "EVIDENCE-002"
            evidence_dir.mkdir(parents=True)
            _write_json(
                evidence_dir / "result.json",
                {
                    "test_id": "EVIDENCE-002",
                    "version": 1,
                    "started_at": "2026-08-24T00:00:00Z",
                    "finished_at": "2026-08-24T00:00:01Z",
                    "exit_code": 0,
                    "conclusion": "PASS",
                    "failure_reason": None,
                    "evidence_types": ["http_200", "container_exists"],
                },
            )
            _write_json(evidence_dir / "inputs.redacted.json", {"url": "http://127.0.0.1:18080"})
            _write_json(evidence_dir / "objects-before.json", {"evidence_type": "http_200"})
            _write_json(evidence_dir / "objects-after.json", {"evidence_type": "container_exists"})
            (evidence_dir / "events.ndjson").write_text(
                json.dumps(
                    {
                        "sequence": 1,
                        "actor": "test-runner",
                        "idempotency_key": "EVIDENCE-002:1",
                        "evidence_refs": ["result.json"],
                        "evidence_type": "http_200",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            _write_manifest(evidence_dir)

            completed = self.run_validator(str(evidence_dir))

            self.assertNotEqual(completed.returncode, 0)
            payload = json.loads(completed.stdout)
            issues = payload["results"][0]["issues"]
            self.assertIn("insufficient_evidence", {issue["code"] for issue in issues})

    def test_valid_evidence_writes_machine_readable_junit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "artifacts" / "mvp" / "m0" / "UNIT-SAMPLE-001"
            output_dir = Path(raw_tmp) / "validator-output"
            junit_path = output_dir / "junit.xml"
            _write_valid_evidence(evidence_dir)

            completed = self.run_validator(str(evidence_dir), "--output-dir", str(output_dir), "--junit", str(junit_path))

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue((output_dir / "validator-result.json").is_file())
            suite = ET.parse(junit_path).getroot()
            self.assertEqual(suite.attrib["tests"], "1")
            self.assertEqual(suite.attrib["failures"], "0")

    def test_milestone_gate_rejects_structurally_valid_failed_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "artifacts" / "mvp" / "m0" / "SPIKE-FAIL-001"
            _write_valid_evidence(evidence_dir, "SPIKE-FAIL-001")
            result_path = evidence_dir / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["exit_code"] = 78
            result["conclusion"] = "FAIL"
            result["failure_reason"] = "resource limit was not enforced"
            _write_json(result_path, result)
            _write_manifest(evidence_dir)

            structural = self.run_validator(str(evidence_dir))
            gate = self.run_validator(str(evidence_dir), "--require-pass-conclusion")

            self.assertEqual(structural.returncode, 0, structural.stdout + structural.stderr)
            self.assertNotEqual(gate.returncode, 0)
            payload = json.loads(gate.stdout)
            issues = payload["results"][0]["issues"]
            self.assertIn("test_not_passed", {issue["code"] for issue in issues})

    def test_m0_runner_writes_required_evidence_contract_for_evidence_gates(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            artifacts_root = Path(raw_tmp) / "artifacts"
            completed = subprocess.run(
                [sys.executable, str(M0_RUNNER), "--artifacts-root", str(artifacts_root)],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            for test_id in ("EVIDENCE-001", "EVIDENCE-002"):
                evidence_dir = artifacts_root / "mvp" / "m0" / test_id
                for name in (*REQUIRED_EVIDENCE_FILES, "manifest.sha256"):
                    self.assertTrue((evidence_dir / name).is_file(), f"{test_id} missing {name}")
                result = json.loads((evidence_dir / "result.json").read_text(encoding="utf-8"))
                self.assertEqual(result["conclusion"], "PASS")
            suite = ET.parse(artifacts_root / "mvp" / "m0" / "evidence-junit.xml").getroot()
            self.assertEqual(suite.attrib["tests"], "2")
            self.assertEqual(suite.attrib["failures"], "0")


if __name__ == "__main__":
    unittest.main()
