#!/usr/bin/env python3
"""Validate Open Card MVP evidence directories.

The validator intentionally uses only the Python standard library so it can run
before the product stack, Docker, BuildKit, or the frontend toolchain exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring


REQUIRED_FILES = (
    "result.json",
    "inputs.redacted.json",
    "objects-before.json",
    "objects-after.json",
    "events.ndjson",
    "manifest.sha256",
)

RESULT_REQUIRED_FIELDS = (
    "test_id",
    "version",
    "started_at",
    "finished_at",
    "exit_code",
    "conclusion",
    "failure_reason",
)

EVENT_REQUIRED_FIELDS = ("sequence", "actor", "idempotency_key", "evidence_refs")

SECRET_FIELD_MARKERS = ("password", "token", "secret", "cookie", "credential", "private_key")
SECRET_REFERENCE_MARKERS = ("secret_ref", "secret_reference", "credential_ref", "credential_reference")
REDACTED_MARKERS = ("***", "redacted", "<redacted>", "[redacted]")
WEAK_EVIDENCE_TYPES = {"http_200", "http", "container_exists", "container"}


@dataclass
class ValidationIssue:
    code: str
    message: str


@dataclass
class ValidationResult:
    evidence_dir: Path
    test_id: str
    passed: bool
    issues: list[ValidationIssue] = field(default_factory=list)


def _read_json(path: Path) -> tuple[Any | None, list[ValidationIssue]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except FileNotFoundError:
        return None, [ValidationIssue("missing_file", f"missing required file: {path.name}")]
    except json.JSONDecodeError as exc:
        return None, [ValidationIssue("invalid_json", f"{path.name} is not valid JSON: {exc}")]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_manifest(path: Path) -> tuple[dict[str, str], list[ValidationIssue]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {}, [ValidationIssue("missing_file", "missing required file: manifest.sha256")]

    entries: dict[str, str] = {}
    issues: list[ValidationIssue] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 64:
            issues.append(ValidationIssue("invalid_manifest", f"manifest line {number} is invalid"))
            continue
        entries[parts[1]] = parts[0].lower()
    return entries, issues


def _walk_values(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_walk_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_walk_values(child))
    return values


def _collect_evidence_types(*documents: Any) -> set[str]:
    evidence_types: set[str] = set()
    for document in documents:
        for value in _walk_values(document):
            if isinstance(value, dict):
                for key in ("evidence_type", "type", "kind", "source"):
                    item = value.get(key)
                    if isinstance(item, str):
                        evidence_types.add(item.strip().lower())
                for key in ("evidence_types", "evidenceKinds", "evidence_kinds"):
                    item = value.get(key)
                    if isinstance(item, list):
                        evidence_types.update(str(entry).strip().lower() for entry in item)
            elif isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in WEAK_EVIDENCE_TYPES:
                    evidence_types.add(lowered)
    return {item for item in evidence_types if item}


def _has_unredacted_secret(value: Any, path: str = "$") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered_key = key.lower()
            child_path = f"{path}.{key}"
            is_reference = any(marker in lowered_key for marker in SECRET_REFERENCE_MARKERS) or lowered_key.endswith("_ref")
            if not is_reference and any(marker in lowered_key for marker in SECRET_FIELD_MARKERS):
                if isinstance(child, str) and not any(marker in child.lower() for marker in REDACTED_MARKERS):
                    return child_path
            found = _has_unredacted_secret(child, child_path)
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _has_unredacted_secret(child, f"{path}[{index}]")
            if found:
                return found
    return None


def _read_events(path: Path) -> tuple[list[dict[str, Any]], list[ValidationIssue]]:
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return [], [ValidationIssue("missing_file", "missing required file: events.ndjson")]

    events: list[dict[str, Any]] = []
    issues: list[ValidationIssue] = []
    for number, line in enumerate(raw_lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(ValidationIssue("invalid_ndjson", f"events.ndjson line {number} is invalid: {exc}"))
            continue
        if not isinstance(event, dict):
            issues.append(ValidationIssue("invalid_event", f"events.ndjson line {number} is not an object"))
            continue
        missing = [field for field in EVENT_REQUIRED_FIELDS if field not in event]
        if missing:
            issues.append(ValidationIssue("event_missing_field", f"events.ndjson line {number} missing: {', '.join(missing)}"))
        events.append(event)

    if not events:
        issues.append(ValidationIssue("empty_events", "events.ndjson must contain at least one event"))
    return events, issues


def validate_evidence_dir(evidence_dir: Path, *, require_pass_conclusion: bool = False) -> ValidationResult:
    evidence_dir = evidence_dir.resolve()
    result_json, issues = _read_json(evidence_dir / "result.json")
    test_id = "UNKNOWN"
    if isinstance(result_json, dict):
        test_id = str(result_json.get("test_id") or evidence_dir.name)
    else:
        result_json = {}

    for name in REQUIRED_FILES:
        if not (evidence_dir / name).is_file():
            issues.append(ValidationIssue("missing_file", f"missing required file: {name}"))

    missing_result_fields = [field for field in RESULT_REQUIRED_FIELDS if field not in result_json]
    if missing_result_fields:
        issues.append(ValidationIssue("result_missing_field", f"result.json missing: {', '.join(missing_result_fields)}"))

    inputs, input_issues = _read_json(evidence_dir / "inputs.redacted.json")
    issues.extend(input_issues)
    if inputs is not None:
        secret_path = _has_unredacted_secret(inputs)
        if secret_path:
            issues.append(ValidationIssue("unredacted_input", f"inputs.redacted.json contains an unredacted sensitive field at {secret_path}"))

    before, before_issues = _read_json(evidence_dir / "objects-before.json")
    after, after_issues = _read_json(evidence_dir / "objects-after.json")
    issues.extend(before_issues)
    issues.extend(after_issues)

    events, event_issues = _read_events(evidence_dir / "events.ndjson")
    issues.extend(event_issues)

    manifest, manifest_issues = _parse_manifest(evidence_dir / "manifest.sha256")
    issues.extend(manifest_issues)
    for name in REQUIRED_FILES:
        if name == "manifest.sha256":
            continue
        file_path = evidence_dir / name
        if not file_path.is_file():
            continue
        expected = manifest.get(name)
        if expected is None:
            issues.append(ValidationIssue("manifest_missing_entry", f"manifest.sha256 missing entry for {name}"))
            continue
        actual = _sha256(file_path)
        if actual != expected:
            issues.append(ValidationIssue("manifest_mismatch", f"manifest checksum mismatch for {name}"))

    conclusion = str(result_json.get("conclusion", "")).upper()
    if require_pass_conclusion and conclusion != "PASS":
        issues.append(
            ValidationIssue(
                "test_not_passed",
                f"result.json conclusion must be PASS for a milestone gate, got {conclusion or 'EMPTY'}",
            )
        )
    if conclusion == "PASS":
        evidence_types = _collect_evidence_types(result_json, inputs, before, after, events)
        strong_types = evidence_types - WEAK_EVIDENCE_TYPES
        if not strong_types:
            issues.append(
                ValidationIssue(
                    "insufficient_evidence",
                    "PASS cannot rely only on HTTP 200, container existence, or equivalent weak evidence",
                )
            )

    return ValidationResult(evidence_dir=evidence_dir, test_id=test_id, passed=not issues, issues=issues)


def write_result_json(validation: ValidationResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "test_id": validation.test_id,
        "version": 1,
        "started_at": now,
        "finished_at": now,
        "exit_code": 0 if validation.passed else 1,
        "conclusion": "PASS" if validation.passed else "FAIL",
        "failure_reason": None if validation.passed else "; ".join(issue.message for issue in validation.issues),
        "issues": [{"code": issue.code, "message": issue.message} for issue in validation.issues],
        "validated_path": str(validation.evidence_dir),
    }
    path = output_dir / "validator-result.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_junit(validations: list[ValidationResult], output_path: Path) -> Path:
    testsuite = Element(
        "testsuite",
        {
            "name": "open-card-mvp-evidence",
            "tests": str(len(validations)),
            "failures": str(sum(1 for item in validations if not item.passed)),
        },
    )
    for validation in validations:
        testcase = SubElement(
            testsuite,
            "testcase",
            {
                "classname": "evidence",
                "name": validation.test_id,
            },
        )
        if not validation.passed:
            failure = SubElement(testcase, "failure", {"message": validation.issues[0].message if validation.issues else "validation failed"})
            failure.text = "\n".join(f"{issue.code}: {issue.message}" for issue in validation.issues)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tostring(testsuite, encoding="utf-8", xml_declaration=True))
    return output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Open Card MVP evidence directories.")
    parser.add_argument("evidence_dirs", nargs="+", type=Path, help="Evidence directories to validate.")
    parser.add_argument("--output-dir", type=Path, help="Directory for validator-result.json for single-dir runs.")
    parser.add_argument("--junit", type=Path, help="Write JUnit XML result.")
    parser.add_argument(
        "--require-pass-conclusion",
        action="store_true",
        help="Fail validation when result.json does not conclude PASS; use for milestone gate summaries.",
    )
    args = parser.parse_args(argv)

    validations = [
        validate_evidence_dir(path, require_pass_conclusion=args.require_pass_conclusion)
        for path in args.evidence_dirs
    ]
    if args.output_dir:
        if len(validations) != 1:
            parser.error("--output-dir is only supported when validating one evidence directory")
        write_result_json(validations[0], args.output_dir)
    if args.junit:
        write_junit(validations, args.junit)

    print(json.dumps(
        {
            "passed": all(item.passed for item in validations),
            "results": [
                {
                    "test_id": item.test_id,
                    "path": str(item.evidence_dir),
                    "passed": item.passed,
                    "issues": [{"code": issue.code, "message": issue.message} for issue in item.issues],
                }
                for item in validations
            ],
        },
        indent=2,
        sort_keys=True,
    ))
    return 0 if all(item.passed for item in validations) else 1


if __name__ == "__main__":
    sys.exit(main())
