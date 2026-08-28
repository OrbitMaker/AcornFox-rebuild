from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "evidence"))

import assert_m4_foundation as foundation  # noqa: E402


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_evidence_manifest(evidence_dir: Path) -> None:
    lines = []
    for name in foundation.REQUIRED_EVIDENCE_FILES:
        if name == "manifest.sha256":
            continue
        digest = hashlib.sha256((evidence_dir / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (evidence_dir / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_evidence(evidence_dir: Path, *, weak_only: bool = False, secret: bool = False) -> None:
    evidence_dir.mkdir(parents=True)
    evidence_types = ["http_200", "container_exists"] if weak_only else ["object_state", "event_sequence", "audit"]
    _write_json(
        evidence_dir / "result.json",
        {
            "test_id": "LOG-INT-001",
            "version": 1,
            "started_at": "2026-08-25T00:00:00Z",
            "finished_at": "2026-08-25T00:00:01Z",
            "exit_code": 0,
            "conclusion": "PASS",
            "failure_reason": None,
            "evidence_types": evidence_types,
        },
    )
    _write_json(
        evidence_dir / "inputs.redacted.json",
        {"secret_ref": "secretprovider://m4/test", "password": "not-redacted" if secret else "[REDACTED]"},
    )
    _write_json(evidence_dir / "objects-before.json", {"evidence_type": evidence_types[0], "status": "before"})
    _write_json(evidence_dir / "objects-after.json", {"evidence_type": evidence_types[0], "status": "after"})
    (evidence_dir / "events.ndjson").write_text(
        json.dumps(
            {
                "sequence": 1,
                "actor": "m4-test-runner",
                "idempotency_key": "LOG-INT-001:1",
                "evidence_refs": ["objects-after.json"],
                "evidence_type": evidence_types[1],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_evidence_manifest(evidence_dir)


class M4FoundationTests(unittest.TestCase):
    def test_checked_in_fixture_manifest_is_exact_and_read_only(self) -> None:
        result = foundation.validate_m4_foundation(REPO_ROOT / "tests" / "fixtures" / "m4")
        self.assertTrue(result["passed"], result)
        self.assertFalse(result["writes_gate_evidence"])

    def test_fixture_manifest_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            fixture_root = Path(raw_tmp) / "m4"
            shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "m4", fixture_root)
            (fixture_root / "logs" / "redaction-inputs.json").write_text("{}\n", encoding="utf-8")

            issues = foundation.validate_fixture_manifest(fixture_root)

            self.assertIn("manifest_mismatch", {issue.code for issue in issues})

    def test_valid_m4_evidence_passes_without_writing_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "m4" / "LOG-INT-001"
            _write_evidence(evidence_dir)
            before = sorted(path.relative_to(evidence_dir).as_posix() for path in evidence_dir.rglob("*"))

            issues = foundation.validate_evidence_dir(evidence_dir, expected_test_id="LOG-INT-001")

            self.assertEqual(issues, [])
            after = sorted(path.relative_to(evidence_dir).as_posix() for path in evidence_dir.rglob("*"))
            self.assertEqual(before, after)

    def test_http_and_container_only_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "m4" / "LOG-INT-001"
            _write_evidence(evidence_dir, weak_only=True)

            issues = foundation.validate_evidence_dir(evidence_dir, expected_test_id="LOG-INT-001")

            self.assertIn("insufficient_evidence", {issue.code for issue in issues})

    def test_missing_required_file_and_unredacted_secret_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            evidence_dir = Path(raw_tmp) / "m4" / "SEC-LOG-001"
            _write_evidence(evidence_dir, secret=True)
            (evidence_dir / "events.ndjson").unlink()

            issues = foundation.validate_evidence_dir(evidence_dir, expected_test_id="SEC-LOG-001")
            codes = {issue.code for issue in issues}

            self.assertIn("missing_required_evidence", codes)
            self.assertIn("unredacted_secret", codes)


if __name__ == "__main__":
    unittest.main()
