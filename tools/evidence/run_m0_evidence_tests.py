#!/usr/bin/env python3
"""Run M0 evidence-contract gate tests and write MVP evidence artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from validate_mvp_evidence import ValidationResult, validate_evidence_dir


CONTRACT_FILES = (
    "result.json",
    "inputs.redacted.json",
    "objects-before.json",
    "objects-after.json",
    "events.ndjson",
)


@dataclass
class GateCase:
    test_id: str
    description: str
    passed: bool
    failure_reason: str | None
    validation: ValidationResult
    expected_issue: str


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_manifest(evidence_dir: Path) -> None:
    lines = []
    for name in CONTRACT_FILES:
        digest = hashlib.sha256((evidence_dir / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (evidence_dir / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_valid_fixture(evidence_dir: Path, test_id: str) -> None:
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
    _write_json(evidence_dir / "inputs.redacted.json", {"fixture": test_id, "secret_ref": "fixture-secret"})
    _write_json(evidence_dir / "objects-before.json", {"application": None, "evidence_type": "object_state"})
    _write_json(evidence_dir / "objects-after.json", {"application": {"id": "app_fixture"}, "evidence_type": "object_state"})
    (evidence_dir / "events.ndjson").write_text(
        json.dumps(
            {
                "sequence": 1,
                "actor": "fixture",
                "idempotency_key": f"{test_id}:fixture:1",
                "evidence_refs": ["objects-after.json"],
                "evidence_type": "event_sequence",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_manifest(evidence_dir)


def _write_case_evidence(case: GateCase, output_root: Path) -> None:
    evidence_dir = output_root / "mvp" / "m0" / case.test_id
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True)

    started = datetime.now(timezone.utc).isoformat()
    issues = [{"code": issue.code, "message": issue.message} for issue in case.validation.issues]
    result = {
        "test_id": case.test_id,
        "version": 1,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "exit_code": 0 if case.passed else 1,
        "conclusion": "PASS" if case.passed else "FAIL",
        "failure_reason": case.failure_reason,
        "expected_issue": case.expected_issue,
        "validator_passed_target": case.validation.passed,
    }
    inputs = {
        "description": case.description,
        "target_evidence_dir": str(case.validation.evidence_dir),
        "expected_issue": case.expected_issue,
        "inputs_are_redacted": True,
    }
    before = {
        "required_files": list(CONTRACT_FILES) + ["manifest.sha256"],
        "target_test_id": case.validation.test_id,
    }
    after = {
        "validator_result": {
            "passed": case.validation.passed,
            "issues": issues,
        }
    }
    event = {
        "sequence": 1,
        "actor": "m0-evidence-runner",
        "idempotency_key": f"{case.test_id}:m0-evidence-runner:1",
        "evidence_refs": ["result.json", "objects-after.json"],
        "evidence_type": "manifest_validator",
    }

    _write_json(evidence_dir / "result.json", result)
    _write_json(evidence_dir / "inputs.redacted.json", inputs)
    _write_json(evidence_dir / "objects-before.json", before)
    _write_json(evidence_dir / "objects-after.json", after)
    (evidence_dir / "events.ndjson").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    _write_manifest(evidence_dir)


def _write_junit(cases: list[GateCase], output_path: Path) -> None:
    suite = Element(
        "testsuite",
        {
            "name": "open-card-m0-evidence-gates",
            "tests": str(len(cases)),
            "failures": str(sum(1 for case in cases if not case.passed)),
        },
    )
    for case in cases:
        testcase = SubElement(suite, "testcase", {"classname": "m0.evidence", "name": case.test_id})
        if not case.passed:
            failure = SubElement(testcase, "failure", {"message": case.failure_reason or "failed"})
            failure.text = json.dumps([issue.__dict__ for issue in case.validation.issues], indent=2)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tostring(suite, encoding="utf-8", xml_declaration=True))


def run_cases(output_root: Path) -> list[GateCase]:
    cases: list[GateCase] = []
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)

        missing_fixture = tmp / "missing-required-file" / "EVIDENCE-001"
        _write_valid_fixture(missing_fixture, "EVIDENCE-001")
        (missing_fixture / "objects-after.json").unlink()
        missing_result = validate_evidence_dir(missing_fixture)
        missing_has_expected_issue = any(issue.code == "missing_file" and "objects-after.json" in issue.message for issue in missing_result.issues)
        cases.append(
            GateCase(
                test_id="EVIDENCE-001",
                description="Deleting any required evidence file makes the gate fail.",
                passed=(not missing_result.passed and missing_has_expected_issue),
                failure_reason=None if (not missing_result.passed and missing_has_expected_issue) else "validator did not reject missing required evidence",
                validation=missing_result,
                expected_issue="missing_file",
            )
        )

        weak_fixture = tmp / "weak-only" / "EVIDENCE-002"
        _write_valid_fixture(weak_fixture, "EVIDENCE-002")
        _write_json(
            weak_fixture / "result.json",
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
        _write_json(weak_fixture / "objects-before.json", {"evidence_type": "http_200"})
        _write_json(weak_fixture / "objects-after.json", {"evidence_type": "container_exists"})
        (weak_fixture / "events.ndjson").write_text(
            json.dumps(
                {
                    "sequence": 1,
                    "actor": "fixture",
                    "idempotency_key": "EVIDENCE-002:fixture:1",
                    "evidence_refs": ["result.json"],
                    "evidence_type": "http_200",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        _write_manifest(weak_fixture)
        weak_result = validate_evidence_dir(weak_fixture)
        weak_has_expected_issue = any(issue.code == "insufficient_evidence" for issue in weak_result.issues)
        cases.append(
            GateCase(
                test_id="EVIDENCE-002",
                description="HTTP 200 and container existence alone are insufficient success evidence.",
                passed=(not weak_result.passed and weak_has_expected_issue),
                failure_reason=None if (not weak_result.passed and weak_has_expected_issue) else "validator did not reject weak-only evidence",
                validation=weak_result,
                expected_issue="insufficient_evidence",
            )
        )

    for case in cases:
        _write_case_evidence(case, output_root)
    _write_junit(cases, output_root / "mvp" / "m0" / "evidence-junit.xml")
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Open Card M0 evidence gate tests.")
    parser.add_argument("--artifacts-root", type=Path, default=Path("artifacts"), help="Artifact root. Defaults to ./artifacts.")
    args = parser.parse_args(argv)

    cases = run_cases(args.artifacts_root)
    print(json.dumps(
        {
            "passed": all(case.passed for case in cases),
            "results": [
                {
                    "test_id": case.test_id,
                    "passed": case.passed,
                    "failure_reason": case.failure_reason,
                    "evidence_dir": str(args.artifacts_root / "mvp" / "m0" / case.test_id),
                }
                for case in cases
            ],
            "junit": str(args.artifacts_root / "mvp" / "m0" / "evidence-junit.xml"),
        },
        indent=2,
        sort_keys=True,
    ))
    return 0 if all(case.passed for case in cases) else 1


if __name__ == "__main__":
    sys.exit(main())
