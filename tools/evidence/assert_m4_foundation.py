#!/usr/bin/env python3
"""Validate M4 fixture integrity and real-evidence foundation contracts.

This is deliberately a read-only foundation check.  It never creates an
``artifacts/mvp/m4`` directory, writes a result, or changes a gate conclusion.
It validates the checked-in fixture manifest and, when an evidence directory
is supplied, validates the evidence files required by the approved M4 spec.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REQUIRED_EVIDENCE_FILES = (
    "result.json",
    "inputs.redacted.json",
    "objects-before.json",
    "objects-after.json",
    "events.ndjson",
    "manifest.sha256",
)

M4_TEST_IDS = frozenset(
    {
        "UNIT-REDACT-001",
        "UNIT-WEBHOOK-001",
        "SCHEMA-OP-001",
        "CT-NOTIFY-001",
        "LOG-INT-001",
        "WEBHOOK-INT-001",
        "OBS-001",
        "OBS-002",
        "LOG-001",
        "LOG-002",
        "LOG-003",
        "OPS-E2E-001",
        "OPS-E2E-002",
        "SEC-SECRET-001",
        "SEC-LOG-001",
        "SEC-WEBHOOK-001",
        "SEC-WEBHOOK-002",
        "VOL-FAULT-001",
        "FAULT-WEBHOOK-001",
        "EVIDENCE-001",
        "EVIDENCE-002",
    }
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

WEAK_EVIDENCE_TYPES = {
    "http",
    "http_200",
    "http200",
    "container",
    "container_exists",
    "container-exists",
}
STRONG_EVIDENCE_TYPES = {
    "audit",
    "audit_hash",
    "checksum",
    "container_inspect",
    "database_query",
    "event_sequence",
    "files",
    "logs",
    "metrics",
    "object_state",
    "receiver_capture",
    "traffic",
}

REDACTED_MARKERS = ("[redacted]", "<redacted>", "***")
SECRET_REFERENCE_MARKERS = ("secretprovider://", "secret_ref", "secret_reference", "credential_ref")
SENSITIVE_KEYS = (
    "password",
    "token",
    "cookie",
    "credential",
    "private_key",
    "secret_value",
    "signing_key",
)
FORBIDDEN_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN\s+(?:RSA |EC |OPENSSH |)PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)
TEST_CANARY_PATTERN = re.compile(r"\bm4-[a-z0-9-]*canary\b", re.IGNORECASE)


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    path: str | None = None

    def as_dict(self) -> dict[str, str]:
        result = {"code": self.code, "message": self.message}
        if self.path is not None:
            result["path"] = self.path
        return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_evidence_type(value: str) -> str:
    lowered = value.strip().lower().replace(" ", "_")
    return lowered.replace("-", "_")


def _walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def _load_json(path: Path) -> tuple[Any | None, list[Issue]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except FileNotFoundError:
        return None, [Issue("missing_file", f"missing JSON file: {path.name}", str(path))]
    except json.JSONDecodeError as exc:
        return None, [Issue("invalid_json", f"invalid JSON: {exc}", str(path))]


def _parse_manifest(path: Path) -> tuple[dict[str, str], list[Issue]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {}, [Issue("missing_manifest", "fixture manifest.sha256 is missing", str(path))]

    entries: dict[str, str] = {}
    issues: list[Issue] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            issues.append(Issue("invalid_manifest", f"manifest line {number} is invalid", str(path)))
            continue
        name = parts[1]
        if name in entries:
            issues.append(Issue("duplicate_manifest_entry", f"manifest repeats {name}", str(path)))
        entries[name] = parts[0].lower()
    return entries, issues


def _fixture_manifest_name(name: str) -> str:
    """Accept the repository-root paths used by the checked-in fixture manifest."""

    cleaned = name.replace("\\", "/")
    for prefix in ("./", "tests/fixtures/m4/"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    return cleaned


def validate_fixture_manifest(fixture_root: Path) -> list[Issue]:
    """Validate every checked-in M4 fixture and require an exact manifest."""

    fixture_root = fixture_root.resolve()
    manifest_path = fixture_root / "manifest.sha256"
    entries, issues = _parse_manifest(manifest_path)
    actual_paths = {
        path.relative_to(fixture_root).as_posix()
        for path in fixture_root.rglob("*")
        if path.is_file() and path.name != "manifest.sha256"
    }
    normalised_entries: dict[str, str] = {}
    for name, digest in entries.items():
        normalised = _fixture_manifest_name(name)
        normalised_parts = Path(normalised).parts
        if Path(normalised).is_absolute() or ".." in normalised_parts:
            issues.append(Issue("invalid_manifest_path", f"manifest path escapes fixture root: {name}", str(manifest_path)))
            continue
        if normalised in normalised_entries:
            issues.append(Issue("duplicate_manifest_entry", f"manifest repeats {normalised}", str(manifest_path)))
        normalised_entries[normalised] = digest
    listed_paths = set(normalised_entries)

    for name in sorted(listed_paths - actual_paths):
        issues.append(Issue("manifest_extra_entry", f"manifest references missing fixture {name}", str(manifest_path)))
    for name in sorted(actual_paths - listed_paths):
        issues.append(Issue("manifest_missing_entry", f"fixture is not listed in manifest: {name}", str(manifest_path)))

    for name, expected in sorted(normalised_entries.items()):
        path = fixture_root / name
        if not path.is_file():
            continue
        if _sha256(path) != expected:
            issues.append(Issue("manifest_mismatch", f"fixture checksum mismatch: {name}", str(path)))

    for path in fixture_root.rglob("*"):
        if path.is_symlink():
            issues.append(Issue("fixture_symlink", "fixture tree must contain regular files only", str(path)))

    for path in sorted(fixture_root.rglob("*.json")):
        value, json_issues = _load_json(path)
        issues.extend(json_issues)
        if value is not None and not isinstance(value, dict):
            issues.append(Issue("fixture_shape", "fixture JSON must be an object", str(path)))
    issues.extend(_scan_sensitive_files(fixture_root, allow_test_canaries=True))
    return issues


def _sensitive_value_issue(value: str, path: str, *, allow_test_canaries: bool) -> Issue | None:
    lowered = value.lower()
    if any(marker in lowered for marker in SECRET_REFERENCE_MARKERS):
        return None
    if any(marker in lowered for marker in REDACTED_MARKERS):
        return None
    if allow_test_canaries and "canary" in lowered:
        return None
    return Issue("unredacted_secret", "sensitive field contains non-redacted material", path)


def _scan_json_secrets(value: Any, path: str, *, allow_test_canaries: bool) -> list[Issue]:
    issues: list[Issue] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lowered_key = key.lower()
            child_path = f"{path}.{key}"
            if isinstance(child, str) and any(marker in lowered_key for marker in SENSITIVE_KEYS):
                issue = _sensitive_value_issue(child, child_path, allow_test_canaries=allow_test_canaries)
                if issue:
                    issues.append(issue)
            issues.extend(_scan_json_secrets(child, child_path, allow_test_canaries=allow_test_canaries))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_scan_json_secrets(child, f"{path}[{index}]", allow_test_canaries=allow_test_canaries))
    return issues


def _scan_sensitive_files(root: Path, *, allow_test_canaries: bool) -> list[Issue]:
    issues: list[Issue] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern.search(text):
                issues.append(Issue("forbidden_secret_material", f"forbidden secret material found: {pattern.pattern}", str(path)))
        if not allow_test_canaries and TEST_CANARY_PATTERN.search(text):
            issues.append(Issue("test_canary_leak", "fixture test canary appears in real evidence", str(path)))
        if path.suffix.lower() == ".json":
            value, json_issues = _load_json(path)
            issues.extend(json_issues)
            if value is not None:
                issues.extend(_scan_json_secrets(value, "$", allow_test_canaries=allow_test_canaries))
    return issues


def _collect_evidence_types(documents: Iterable[Any], evidence_dir: Path) -> set[str]:
    types: set[str] = set()
    for document in documents:
        for _, value in _walk(document):
            if isinstance(value, dict):
                for key in ("evidence_type", "type", "kind", "source"):
                    item = value.get(key)
                    if isinstance(item, str):
                        types.add(_normalise_evidence_type(item))
                for key in ("evidence_types", "evidenceKinds", "evidence_kinds"):
                    item = value.get(key)
                    if isinstance(item, list):
                        types.update(_normalise_evidence_type(str(entry)) for entry in item)
            elif isinstance(value, str):
                normalised = _normalise_evidence_type(value)
                if normalised in WEAK_EVIDENCE_TYPES or normalised in STRONG_EVIDENCE_TYPES:
                    types.add(normalised)
    for path in evidence_dir.iterdir():
        if path.is_file():
            stem = _normalise_evidence_type(path.stem)
            if stem in WEAK_EVIDENCE_TYPES or stem in STRONG_EVIDENCE_TYPES:
                types.add(stem)
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for weak in WEAK_EVIDENCE_TYPES:
                if weak in _normalise_evidence_type(content):
                    types.add(weak)
    return types


def _read_events(path: Path) -> tuple[list[dict[str, Any]], list[Issue]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return [], [Issue("missing_file", "missing events.ndjson", str(path))]
    events: list[dict[str, Any]] = []
    issues: list[Issue] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(Issue("invalid_ndjson", f"invalid events.ndjson line: {exc}", str(path)))
            continue
        if not isinstance(value, dict):
            issues.append(Issue("invalid_event", f"events.ndjson line {number} is not an object", str(path)))
            continue
        missing = [field for field in EVENT_REQUIRED_FIELDS if field not in value]
        if missing:
            issues.append(Issue("event_missing_field", f"events.ndjson line {number} missing {', '.join(missing)}", str(path)))
        events.append(value)
    if not events:
        issues.append(Issue("empty_events", "events.ndjson must contain at least one event", str(path)))
    return events, issues


def _validate_evidence_manifest(evidence_dir: Path, issues: list[Issue]) -> None:
    manifest_path = evidence_dir / "manifest.sha256"
    entries, manifest_issues = _parse_manifest(manifest_path)
    issues.extend(manifest_issues)
    for name in REQUIRED_EVIDENCE_FILES:
        if name == "manifest.sha256":
            continue
        path = evidence_dir / name
        if not path.is_file():
            continue
        expected = entries.get(name)
        if expected is None:
            issues.append(Issue("manifest_missing_entry", f"evidence manifest misses {name}", str(manifest_path)))
        elif _sha256(path) != expected:
            issues.append(Issue("manifest_mismatch", f"evidence checksum mismatch: {name}", str(path)))


def validate_evidence_dir(evidence_dir: Path, *, expected_test_id: str | None = None) -> list[Issue]:
    """Validate one real M4 evidence directory without writing any output."""

    evidence_dir = evidence_dir.resolve()
    issues: list[Issue] = []
    if not evidence_dir.is_dir():
        return [Issue("missing_evidence_dir", "M4 evidence directory is missing", str(evidence_dir))]

    for name in REQUIRED_EVIDENCE_FILES:
        if not (evidence_dir / name).is_file():
            issues.append(Issue("missing_required_evidence", f"missing required evidence file: {name}", str(evidence_dir / name)))

    result, result_issues = _load_json(evidence_dir / "result.json")
    issues.extend(result_issues)
    if not isinstance(result, dict):
        result = {}
    missing_result_fields = [field for field in RESULT_REQUIRED_FIELDS if field not in result]
    if missing_result_fields:
        issues.append(Issue("result_missing_field", f"result.json missing: {', '.join(missing_result_fields)}", str(evidence_dir / "result.json")))
    test_id = str(result.get("test_id") or evidence_dir.name)
    if expected_test_id is not None and test_id != expected_test_id:
        issues.append(Issue("test_id_mismatch", f"result test_id {test_id!r} does not match {expected_test_id!r}", str(evidence_dir / "result.json")))
    if test_id not in M4_TEST_IDS:
        issues.append(Issue("unknown_m4_test_id", f"not an approved M4 test ID: {test_id}", str(evidence_dir / "result.json")))

    documents: list[Any] = [result]
    for name in ("inputs.redacted.json", "objects-before.json", "objects-after.json"):
        value, value_issues = _load_json(evidence_dir / name)
        issues.extend(value_issues)
        if value is not None:
            documents.append(value)
            issues.extend(_scan_json_secrets(value, f"$.{name}", allow_test_canaries=False))

    events, event_issues = _read_events(evidence_dir / "events.ndjson")
    issues.extend(event_issues)
    documents.append(events)

    _validate_evidence_manifest(evidence_dir, issues)
    issues.extend(_scan_sensitive_files(evidence_dir, allow_test_canaries=False))

    conclusion = str(result.get("conclusion", "")).upper()
    if conclusion == "PASS":
        evidence_types = _collect_evidence_types(documents, evidence_dir)
        if not evidence_types or not (evidence_types & STRONG_EVIDENCE_TYPES):
            issues.append(Issue("insufficient_evidence", "PASS requires strong evidence, not only HTTP 200 or container existence", str(evidence_dir)))
        elif evidence_types <= WEAK_EVIDENCE_TYPES:
            issues.append(Issue("insufficient_evidence", "PASS cannot rely only on HTTP 200 or container existence", str(evidence_dir)))

    return issues


def validate_m4_foundation(
    fixture_root: Path,
    evidence_root: Path | None = None,
    *,
    test_id: str | None = None,
) -> dict[str, Any]:
    """Return a machine-readable read-only validation summary."""

    issues = validate_fixture_manifest(fixture_root)
    evidence_results: list[dict[str, Any]] = []
    if evidence_root is not None:
        root = evidence_root.resolve()
        directories = [root / test_id] if test_id else sorted(path for path in root.iterdir() if path.is_dir()) if root.is_dir() else []
        if test_id and not (root / test_id).is_dir():
            evidence_results.append({"test_id": test_id, "passed": False, "issues": [issue.as_dict() for issue in validate_evidence_dir(root / test_id, expected_test_id=test_id)]})
        elif not directories:
            issues.append(Issue("missing_evidence_root", "M4 evidence root has no test directories", str(root)))
        else:
            for directory in directories:
                directory_issues = validate_evidence_dir(directory, expected_test_id=directory.name)
                evidence_results.append({"test_id": directory.name, "passed": not directory_issues, "issues": [issue.as_dict() for issue in directory_issues]})
    passed = not issues and all(item["passed"] for item in evidence_results)
    return {
        "milestone": "M4",
        "passed": passed,
        "fixture_root": str(Path(fixture_root).resolve()),
        "fixture_issues": [issue.as_dict() for issue in issues],
        "evidence": evidence_results,
        "writes_gate_evidence": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, default=Path("tests/fixtures/m4"))
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--test-id")
    args = parser.parse_args(argv)
    summary = validate_m4_foundation(args.fixture_root, args.evidence_root, test_id=args.test_id)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
