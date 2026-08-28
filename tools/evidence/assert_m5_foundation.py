#!/usr/bin/env python3
"""Validate the deterministic M5 usage fixture and evidence contracts.

The validator is intentionally read-only.  It checks fixture shape, exact
SHA-256 coverage, window/identity semantics, the no-commercial-field boundary,
and (when requested) independent M5 evidence directories.  It never creates
or updates an evidence result and therefore cannot promote the M5 gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


FIXTURE_FILES = frozenset(
    {
        "README.md",
        "metadata.json",
        "samples.json",
        "expected-aggregates.json",
        "retention.json",
    }
)
M5_TEST_IDS = frozenset(
    {
        "UNIT-USAGE-001",
        "CT-METER-001",
        "USAGE-INT-001",
        "E2E-USAGE-001",
        "USAGE-001",
        "USAGE-002",
        "USAGE-003",
    }
)
REQUIRED_EVIDENCE_FILES = (
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
WEAK_EVIDENCE_TYPES = frozenset({"http", "http_200", "http200", "container", "container_exists"})
STRONG_EVIDENCE_TYPES = frozenset(
    {
        "audit",
        "audit_hash",
        "checksum",
        "database_query",
        "event_sequence",
        "metrics",
        "object_state",
        "raw_observation",
        "usage_aggregate",
        "usage_raw",
    }
)
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "price",
        "prices",
        "amount",
        "currency",
        "invoice",
        "invoices",
        "payment",
        "payments",
        "balance",
        "balances",
        "billing",
        "charge",
        "charges",
        "subscription",
        "subscriptions",
    }
)
SENSITIVE_KEYS = frozenset({"password", "token", "cookie", "secret", "private_key", "credential"})
FORBIDDEN_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN\s+(?:RSA |EC |OPENSSH |)PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    path: str | None = None

    def as_dict(self) -> dict[str, str]:
        value = {"code": self.code, "message": self.message}
        if self.path is not None:
            value["path"] = self.path
        return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_evidence_type(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_")


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
        return {}, [Issue("missing_manifest", "manifest.sha256 is missing", str(path))]
    entries: dict[str, str] = {}
    issues: list[Issue] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            issues.append(Issue("invalid_manifest", f"manifest line {number} is invalid", str(path)))
            continue
        if parts[1] in entries:
            issues.append(Issue("duplicate_manifest_entry", f"manifest repeats {parts[1]}", str(path)))
        entries[parts[1]] = parts[0].lower()
    return entries, issues


def _parse_utc(value: Any, path: str, issues: list[Issue]) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        issues.append(Issue("timestamp_not_utc", "timestamp must be an RFC3339 UTC value ending in Z", path))
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        issues.append(Issue("invalid_timestamp", str(exc), path))
        return None
    if parsed.tzinfo != timezone.utc:
        issues.append(Issue("timestamp_not_utc", "timestamp must use UTC", path))
    return parsed


def _scan_forbidden_fields(value: Any, path: str = "$") -> list[Issue]:
    issues: list[Issue] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).strip().lower()
            if lowered in FORBIDDEN_FIELD_NAMES:
                issues.append(Issue("forbidden_usage_field", f"field is outside M5 usage scope: {key}", f"{path}.{key}"))
            issues.extend(_scan_forbidden_fields(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_scan_forbidden_fields(child, f"{path}[{index}]"))
    return issues


def _scan_sensitive_files(root: Path) -> list[Issue]:
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
                issues.append(Issue("forbidden_secret_material", "forbidden secret material found", str(path)))
        if path.suffix.lower() == ".json":
            value, json_issues = _load_json(path)
            issues.extend(json_issues)
            if value is not None:
                for location, item in _walk(value):
                    if not isinstance(item, dict):
                        continue
                    for key, child in item.items():
                        if str(key).lower() in SENSITIVE_KEYS and isinstance(child, str) and child not in {"[REDACTED]", "[redacted]", "<redacted>"}:
                            issues.append(Issue("unredacted_secret", "sensitive fixture value is not redacted", f"{location}.{key}"))
    return issues


def _validate_usage_documents(fixture_root: Path) -> list[Issue]:
    issues: list[Issue] = []
    metadata, metadata_issues = _load_json(fixture_root / "metadata.json")
    samples_doc, sample_issues = _load_json(fixture_root / "samples.json")
    expected, expected_issues = _load_json(fixture_root / "expected-aggregates.json")
    retention, retention_issues = _load_json(fixture_root / "retention.json")
    issues.extend(metadata_issues + sample_issues + expected_issues + retention_issues)
    for name, document in (("metadata.json", metadata), ("samples.json", samples_doc), ("expected-aggregates.json", expected), ("retention.json", retention)):
        if document is not None and not isinstance(document, dict):
            issues.append(Issue("fixture_shape", f"{name} must contain an object", str(fixture_root / name)))
    if not all(isinstance(document, dict) for document in (metadata, samples_doc, expected, retention)):
        return issues

    metadata_ids = set(metadata.get("test_ids", []))
    if metadata_ids != set(M5_TEST_IDS):
        issues.append(Issue("test_id_mapping", "metadata test_ids do not match the approved M5 set", str(fixture_root / "metadata.json")))
    window = samples_doc.get("bucket_width_seconds")
    if samples_doc.get("timezone") != "UTC" or window != 300:
        issues.append(Issue("window_contract", "samples must use UTC and a 300 second bucket", str(fixture_root / "samples.json")))
    if samples_doc.get("from") != "2026-08-25T00:00:00Z" or samples_doc.get("to") != "2026-08-25T00:10:00Z":
        issues.append(Issue("fixture_clock", "fixed sample window changed", str(fixture_root / "samples.json")))
    samples = samples_doc.get("samples")
    if not isinstance(samples, list) or not samples:
        issues.append(Issue("samples_missing", "samples must be a non-empty array", str(fixture_root / "samples.json")))
        return issues
    required = {
        "source_id", "application_id", "environment_id", "deployment_id", "release_id", "service_name",
        "observed_at", "cpu_millicores", "memory_bytes", "disk_bytes", "network_rx_bytes",
        "network_tx_bytes", "restart_count", "exception_count", "runtime_seconds",
        "limit_cpu_millicores", "limit_memory_bytes", "limit_disk_bytes", "limit_pids",
    }
    source_ids: list[str] = []
    applications: set[str] = set()
    for index, sample in enumerate(samples):
        path = f"{fixture_root / 'samples.json'}:samples[{index}]"
        if not isinstance(sample, dict):
            issues.append(Issue("sample_shape", "sample must be an object", path))
            continue
        missing = required - set(sample)
        if missing:
            issues.append(Issue("sample_field", f"sample missing: {', '.join(sorted(missing))}", path))
        source_id = sample.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            issues.append(Issue("sample_identity", "source_id is required", path))
        else:
            source_ids.append(source_id)
        application = sample.get("application_id")
        if isinstance(application, str):
            applications.add(application)
        _parse_utc(sample.get("observed_at"), f"{path}.observed_at", issues)
        for key in required - {"source_id", "application_id", "environment_id", "deployment_id", "release_id", "service_name", "observed_at"}:
            if key in sample and (not isinstance(sample[key], int) or sample[key] < 0):
                issues.append(Issue("sample_value", f"{key} must be a non-negative integer", f"{path}.{key}"))
    if set(applications) != {"app-alpha", "app-beta"}:
        issues.append(Issue("application_isolation", "fixture must contain exactly two application identities", str(fixture_root / "samples.json")))
    if not any(count > 1 for count in Counter(source_ids).values()):
        issues.append(Issue("dedupe_case_missing", "fixture must contain an identical duplicate sample", str(fixture_root / "samples.json")))
    delivery_order = samples_doc.get("delivery_order")
    if not isinstance(delivery_order, list) or Counter(delivery_order) != Counter(source_ids):
        issues.append(Issue("delivery_order", "delivery_order must preserve the sample multiset", str(fixture_root / "samples.json")))
    late_ids = samples_doc.get("late_sample_ids")
    if not isinstance(late_ids, list) or not set(late_ids).issubset(set(source_ids)):
        issues.append(Issue("late_sample_case", "late_sample_ids must reference fixture samples", str(fixture_root / "samples.json")))

    aggregates = expected.get("aggregates")
    if not isinstance(aggregates, list) or len(aggregates) != 3:
        issues.append(Issue("aggregate_shape", "expected fixture must contain alpha web, alpha worker and beta web", str(fixture_root / "expected-aggregates.json")))
    else:
        expected_keys = {(item.get("application_id"), item.get("service_name")) for item in aggregates if isinstance(item, dict)}
        if expected_keys != {("app-alpha", "web"), ("app-alpha", "worker"), ("app-beta", "web")}:
            issues.append(Issue("aggregate_identity", "expected aggregate identities are incomplete", str(fixture_root / "expected-aggregates.json")))
        for index, aggregate in enumerate(aggregates):
            if not isinstance(aggregate, dict):
                issues.append(Issue("aggregate_shape", "aggregate must be an object", f"expected-aggregates.json:aggregates[{index}]"))
                continue
            _parse_utc(aggregate.get("window_start"), f"expected-aggregates.json:aggregates[{index}].window_start", issues)
            _parse_utc(aggregate.get("window_end"), f"expected-aggregates.json:aggregates[{index}].window_end", issues)
            configured = aggregate.get("configured_limits")
            actual = aggregate.get("actual")
            if not isinstance(configured, dict) or not isinstance(actual, dict):
                issues.append(Issue("limit_actual_split", "configured_limits and actual must remain separate", f"expected-aggregates.json:aggregates[{index}]"))
    storage = retention.get("storage")
    if not isinstance(storage, dict) or storage.get("low_priority_raw_sampling_paused") is not True:
        issues.append(Issue("watermark_contract", "retention fixture must show low-priority sampling protection", str(fixture_root / "retention.json")))
    if not set(retention.get("must_retain", [])) >= {"latest_aggregate", "audit_evidence", "current_observation"}:
        issues.append(Issue("retention_protection", "latest aggregate, audit evidence and current observation must be retained", str(fixture_root / "retention.json")))
    return issues


def validate_fixture_manifest(fixture_root: Path) -> list[Issue]:
    """Validate exact checked-in M5 fixture files and semantic contracts."""

    fixture_root = fixture_root.resolve()
    entries, issues = _parse_manifest(fixture_root / "manifest.sha256")
    actual = {path.relative_to(fixture_root).as_posix() for path in fixture_root.rglob("*") if path.is_file() and path.name != "manifest.sha256"}
    listed = set(entries)
    for name in sorted(actual - listed):
        issues.append(Issue("manifest_missing_entry", f"fixture is not listed: {name}", str(fixture_root / name)))
    for name in sorted(listed - actual):
        issues.append(Issue("manifest_extra_entry", f"manifest references missing fixture: {name}", str(fixture_root / "manifest.sha256")))
    if actual != FIXTURE_FILES:
        issues.append(Issue("fixture_file_set", f"unexpected fixture file set: {sorted(actual)}", str(fixture_root)))
    for name, expected in entries.items():
        path = fixture_root / name
        if path.is_file() and _sha256(path) != expected:
            issues.append(Issue("manifest_mismatch", f"fixture checksum mismatch: {name}", str(path)))
    for path in fixture_root.rglob("*"):
        if path.is_symlink():
            issues.append(Issue("fixture_symlink", "fixture tree must contain regular files only", str(path)))
    issues.extend(_validate_usage_documents(fixture_root))
    for path in sorted(fixture_root.glob("*.json")):
        value, _ = _load_json(path)
        if value is not None:
            issues.extend(_scan_forbidden_fields(value, path.name))
    issues.extend(_scan_sensitive_files(fixture_root))
    return issues


def _read_events(path: Path) -> tuple[list[dict[str, Any]], list[Issue]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return [], [Issue("missing_file", "missing events.ndjson", str(path))]
    events: list[dict[str, Any]] = []
    issues: list[Issue] = []
    for number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(Issue("invalid_ndjson", str(exc), str(path)))
            continue
        if not isinstance(value, dict):
            issues.append(Issue("invalid_event", f"event {number} is not an object", str(path)))
            continue
        missing = [field for field in EVENT_REQUIRED_FIELDS if field not in value]
        if missing:
            issues.append(Issue("event_missing_field", f"event {number} missing {', '.join(missing)}", str(path)))
        events.append(value)
    if not events:
        issues.append(Issue("empty_events", "events.ndjson must contain at least one event", str(path)))
    return events, issues


def _collect_evidence_types(documents: Iterable[Any]) -> set[str]:
    types: set[str] = set()
    for document in documents:
        for _, value in _walk(document):
            if isinstance(value, dict):
                for key in ("evidence_type", "type", "kind", "source"):
                    item = value.get(key)
                    if isinstance(item, str):
                        types.add(_normalise_evidence_type(item))
                for key in ("evidence_types", "evidence_kinds"):
                    item = value.get(key)
                    if isinstance(item, list):
                        types.update(_normalise_evidence_type(str(entry)) for entry in item)
    return types


def _validate_evidence_manifest(evidence_dir: Path, issues: list[Issue]) -> None:
    entries, manifest_issues = _parse_manifest(evidence_dir / "manifest.sha256")
    issues.extend(manifest_issues)
    for name in REQUIRED_EVIDENCE_FILES:
        if name == "manifest.sha256":
            continue
        path = evidence_dir / name
        if path.is_file() and (name not in entries or _sha256(path) != entries[name]):
            issues.append(Issue("manifest_mismatch", f"evidence checksum mismatch or missing entry: {name}", str(path)))


def validate_evidence_dir(evidence_dir: Path, *, expected_test_id: str | None = None) -> list[Issue]:
    """Validate one M5 evidence directory without writing output."""

    evidence_dir = evidence_dir.resolve()
    issues: list[Issue] = []
    if not evidence_dir.is_dir():
        return [Issue("missing_evidence_dir", "M5 evidence directory is missing", str(evidence_dir))]
    for name in REQUIRED_EVIDENCE_FILES:
        if not (evidence_dir / name).is_file():
            issues.append(Issue("missing_required_evidence", f"missing required evidence file: {name}", str(evidence_dir / name)))
    result, result_issues = _load_json(evidence_dir / "result.json")
    issues.extend(result_issues)
    if not isinstance(result, dict):
        result = {}
    missing = [field for field in RESULT_REQUIRED_FIELDS if field not in result]
    if missing:
        issues.append(Issue("result_missing_field", f"result.json missing: {', '.join(missing)}", str(evidence_dir / "result.json")))
    test_id = str(result.get("test_id") or evidence_dir.name)
    if expected_test_id is not None and test_id != expected_test_id:
        issues.append(Issue("test_id_mismatch", f"result test_id {test_id!r} does not match {expected_test_id!r}", str(evidence_dir / "result.json")))
    if test_id not in M5_TEST_IDS:
        issues.append(Issue("unknown_m5_test_id", f"not an approved M5 test ID: {test_id}", str(evidence_dir / "result.json")))
    documents: list[Any] = [result]
    for name in ("inputs.redacted.json", "objects-before.json", "objects-after.json"):
        value, value_issues = _load_json(evidence_dir / name)
        issues.extend(value_issues)
        if value is not None:
            documents.append(value)
            issues.extend(_scan_forbidden_fields(value, name))
    events, event_issues = _read_events(evidence_dir / "events.ndjson")
    issues.extend(event_issues)
    documents.append(events)
    _validate_evidence_manifest(evidence_dir, issues)
    issues.extend(_scan_sensitive_files(evidence_dir))
    if str(result.get("conclusion", "")).upper() == "PASS":
        evidence_types = _collect_evidence_types(documents)
        if not evidence_types or not evidence_types.intersection(STRONG_EVIDENCE_TYPES) or evidence_types.issubset(WEAK_EVIDENCE_TYPES):
            issues.append(Issue("insufficient_evidence", "PASS requires independent usage/database evidence", str(evidence_dir)))
    return issues


def validate_m5_foundation(
    fixture_root: Path,
    evidence_root: Path | None = None,
    *,
    test_id: str | None = None,
) -> dict[str, Any]:
    """Return a machine-readable, read-only M5 foundation summary."""

    issues = validate_fixture_manifest(fixture_root)
    evidence_results: list[dict[str, Any]] = []
    if evidence_root is not None:
        root = evidence_root.resolve()
        directories = [root / test_id] if test_id else sorted(path for path in root.iterdir() if path.is_dir()) if root.is_dir() else []
        if test_id and not (root / test_id).is_dir():
            evidence_results.append({"test_id": test_id, "passed": False, "issues": [issue.as_dict() for issue in validate_evidence_dir(root / test_id, expected_test_id=test_id)]})
        elif not directories:
            issues.append(Issue("missing_evidence_root", "M5 evidence root has no test directories", str(root)))
        else:
            for directory in directories:
                directory_issues = validate_evidence_dir(directory, expected_test_id=directory.name)
                evidence_results.append({"test_id": directory.name, "passed": not directory_issues, "issues": [issue.as_dict() for issue in directory_issues]})
    return {
        "milestone": "M5",
        "passed": not issues and all(item["passed"] for item in evidence_results),
        "fixture_root": str(Path(fixture_root).resolve()),
        "fixture_issues": [issue.as_dict() for issue in issues],
        "evidence": evidence_results,
        "writes_gate_evidence": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, default=Path("tests/fixtures/m5"))
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--test-id")
    args = parser.parse_args(argv)
    summary = validate_m5_foundation(args.fixture_root, args.evidence_root, test_id=args.test_id)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
