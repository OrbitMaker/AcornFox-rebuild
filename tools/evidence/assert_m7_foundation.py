#!/usr/bin/env python3
"""Read-only validator for the Open Card M7 RC fixture and runbook contract.

This validator intentionally never writes active evidence or changes a gate
state.  It verifies the frozen install/upgrade matrix, canonical fixture
manifest/checksums, runbook coverage and the shape of optional real evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


INSTALL_UPGRADE_IDS = frozenset(
    {
        "INSTALL-001",
        "INSTALL-002",
        "INSTALL-003",
        "UPGRADE-001",
        "UPGRADE-002",
        "UPGRADE-003",
        "UPGRADE-004",
        "UPGRADE-005",
    }
)
RC_TEST_IDS = frozenset(
    {
        "RC-SUPPLY-001",
        "BACKUP-RESTORE-001",
        "REBOOT-RECOVERY-001",
        "FAULT-RC-001",
        "SECURITY-RC-001",
        "E2E-RC-001",
        "REGRESSION-RC-001",
        "HOST-RECLAIM-001",
    }
)
M7_TEST_IDS = INSTALL_UPGRADE_IDS | RC_TEST_IDS
REQUIRED_RUNBOOKS = (
    "m7-install.md",
    "m7-upgrade.md",
    "m7-backup-restore.md",
    "m7-recovery-uninstall.md",
    "m7-rc-acceptance.md",
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
        "database_checksum",
        "database_query",
        "filesystem_snapshot",
        "migration",
        "network_boundary",
        "object_state",
        "sbom",
        "systemd",
        "terminal",
        "version",
    }
)
FORBIDDEN_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN\s+(?:RSA |EC |OPENSSH |)PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
SENSITIVE_KEYS = frozenset({"password", "token", "cookie", "secret", "private_key", "credential"})
REDACTED_VALUES = frozenset({"[REDACTED]", "[redacted]", "<redacted>", "***"})


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


def _safe_relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _scan_secrets(value: Any, path: str = "$") -> list[Issue]:
    issues: list[Issue] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in SENSITIVE_KEYS and isinstance(child, str) and child not in REDACTED_VALUES:
                issues.append(Issue("unredacted_secret", "sensitive value is not redacted", child_path))
            issues.extend(_scan_secrets(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_scan_secrets(child, f"{path}[{index}]"))
    return issues


def _scan_files_for_secrets(root: Path) -> list[Issue]:
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
                issues.extend(_scan_secrets(value, path.name))
    return issues


def _validate_canonical_bundle(fixture_root: Path) -> list[Issue]:
    bundle_root = fixture_root / "bundle"
    manifest_path = bundle_root / "canonical-manifest.json"
    value, issues = _load_json(manifest_path)
    if not isinstance(value, dict):
        return issues
    required = {"schema_version", "product", "version", "release_id", "protocol", "config_dir", "data_dir", "compatibility", "files", "assets", "active_gate"}
    if set(value) - required - {"fixture_only"} or not required <= set(value):
        issues.append(Issue("bundle_manifest_fields", "canonical bundle manifest fields are not exact", str(manifest_path)))
        return issues
    if value["schema_version"] != 1 or value["product"] != "open-card" or value["protocol"] != "1.1":
        issues.append(Issue("bundle_identity", "canonical bundle identity is invalid", str(manifest_path)))
    if value.get("config_dir") != "/etc/open-card" or value.get("data_dir") != "/var/lib/open-card":
        issues.append(Issue("directory_contract", "canonical bundle directory contract is invalid", str(manifest_path)))
    if value.get("active_gate") != "NOT_RUN" or value.get("fixture_only") is not True:
        issues.append(Issue("gate_state", "fixture bundle must not claim active RC status", str(manifest_path)))
    compatibility = value.get("compatibility")
    if not isinstance(compatibility, dict) or not {"min_data_version", "max_data_version", "min_agent_protocol", "max_agent_protocol"} <= set(compatibility):
        issues.append(Issue("compatibility_matrix", "bundle compatibility window is incomplete", str(manifest_path)))
    descriptors = value.get("files")
    seen_targets: set[str] = set()
    if not isinstance(descriptors, list) or not descriptors:
        issues.append(Issue("bundle_files", "bundle files must be non-empty", str(manifest_path)))
    else:
        for index, descriptor in enumerate(descriptors):
            path = f"{manifest_path}:files[{index}]"
            if not isinstance(descriptor, dict) or set(descriptor) != {"path", "source", "sha256", "mode"}:
                issues.append(Issue("bundle_file_descriptor", "bundle file descriptor is invalid", path))
                continue
            target, source, digest, mode = descriptor["path"], descriptor["source"], descriptor["sha256"], descriptor["mode"]
            if not _safe_relative(target) or not _safe_relative(source) or target in seen_targets:
                issues.append(Issue("bundle_file_path", "bundle file path is unsafe or repeated", path))
                continue
            seen_targets.add(target)
            source_path = bundle_root / source
            if not source_path.is_file() or source_path.is_symlink():
                issues.append(Issue("bundle_source_missing", f"bundle source is missing: {source}", path))
                continue
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or _sha256(source_path) != digest:
                issues.append(Issue("bundle_checksum", f"bundle checksum mismatch: {source}", str(source_path)))
            if not isinstance(mode, int) or mode <= 0 or mode & 0o022 or stat.S_IMODE(source_path.stat().st_mode) != mode:
                issues.append(Issue("bundle_mode", f"bundle mode mismatch: {source}", str(source_path)))
    return issues


def validate_fixture_manifest(fixture_root: Path) -> list[Issue]:
    """Validate exact M7 fixture coverage and canonical bundle semantics."""

    fixture_root = fixture_root.resolve()
    entries, issues = _parse_manifest(fixture_root / "manifest.sha256")
    actual = {path.relative_to(fixture_root).as_posix() for path in fixture_root.rglob("*") if path.is_file() and path.name != "manifest.sha256"}
    listed = set(entries)
    for name in sorted(actual - listed):
        issues.append(Issue("manifest_missing_entry", f"fixture is not listed: {name}", str(fixture_root / name)))
    for name in sorted(listed - actual):
        issues.append(Issue("manifest_extra_entry", f"manifest references missing file: {name}", str(fixture_root / "manifest.sha256")))
    for name, expected in entries.items():
        path = fixture_root / name
        if path.is_file() and _sha256(path) != expected:
            issues.append(Issue("manifest_mismatch", f"fixture checksum mismatch: {name}", str(path)))
    for path in fixture_root.rglob("*"):
        if path.is_symlink():
            issues.append(Issue("fixture_symlink", "fixture tree must contain regular files only", str(path)))
        elif path.is_file() and path.suffix.lower() == ".json":
            value, json_issues = _load_json(path)
            issues.extend(json_issues)
            if value is not None:
                issues.extend(_scan_secrets(value, path.name))
    issues.extend(_validate_canonical_bundle(fixture_root))
    return issues


def validate_metadata(fixture_root: Path) -> list[Issue]:
    metadata, issues = _load_json(fixture_root / "metadata.json")
    if not isinstance(metadata, dict):
        return issues
    actual_ids = set(metadata.get("test_ids", []))
    if actual_ids != set(M7_TEST_IDS):
        issues.append(Issue("test_id_matrix", "metadata test_ids do not match frozen M7/RC IDs", str(fixture_root / "metadata.json")))
    matrix = metadata.get("support_matrix")
    if not isinstance(matrix, dict) or matrix.get("os") != "Ubuntu 24.04 LTS" or matrix.get("architecture") != "amd64":
        issues.append(Issue("support_matrix", "support matrix must be Ubuntu 24.04 LTS amd64", str(fixture_root / "metadata.json")))
    units = metadata.get("units")
    if units != [
        "open-card-server.service",
        "open-card-agent.service",
        "open-card-buildkit.service",
        "open-card-caddy.service",
    ]:
        issues.append(Issue("unit_matrix", "systemd unit matrix is not exact", str(fixture_root / "metadata.json")))
    if metadata.get("evidence_policy", {}).get("unrun_status") != "NOT_RUN":
        issues.append(Issue("unrun_status", "unrun status must be NOT_RUN", str(fixture_root / "metadata.json")))
    return issues


def validate_runbooks(runbook_root: Path) -> list[Issue]:
    runbook_root = runbook_root.resolve()
    issues: list[Issue] = []
    contents: list[str] = []
    for name in REQUIRED_RUNBOOKS:
        path = runbook_root / name
        if not path.is_file():
            issues.append(Issue("missing_runbook", f"required runbook is missing: {name}", str(path)))
            continue
        text = path.read_text(encoding="utf-8")
        contents.append(text)
        if "RUNBOOK_CONTRACT_ONLY" not in text or "NOT_RUN" not in text:
            issues.append(Issue("runbook_status", "runbook must declare contract-only and NOT_RUN semantics", str(path)))
        for pattern in (
            re.compile(r"^\s*(?:sudo\s+)?virsh\s+destroy\b", re.MULTILINE),
            re.compile(r"^\s*rm\s+-rf\s+/\s*$", re.MULTILINE),
            re.compile(r"^\s*(?:sudo\s+)?ip\s+route\s+(?:add|del)\b", re.MULTILINE),
            re.compile(r"^\s*(?:sudo\s+)?systemctl\s+(?:stop|disable)\s+docker(?:\.service)?\b", re.MULTILINE),
        ):
            if pattern.search(text):
                issues.append(Issue("unsafe_runbook_command", f"unsafe command pattern appears in {name}", str(path)))
    combined = "\n".join(contents)
    for test_id in sorted(M7_TEST_IDS):
        if test_id not in combined:
            issues.append(Issue("runbook_test_mapping", f"runbooks omit {test_id}", str(runbook_root)))
    if "scripts/mvp/install.sh" not in combined or "scripts/mvp/upgrade.sh" not in combined or "scripts/mvp/backup-control-plane.sh" not in combined or "scripts/mvp/restore-control-plane.sh" not in combined or "scripts/mvp/uninstall.sh" not in combined:
        issues.append(Issue("runbook_script_mapping", "runbooks must map to the existing M7 script entrypoints", str(runbook_root)))
    return issues


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
    """Validate a real M7 evidence directory without writing output."""

    evidence_dir = evidence_dir.resolve()
    issues: list[Issue] = []
    if not evidence_dir.is_dir():
        return [Issue("missing_evidence_dir", "M7 evidence directory is missing", str(evidence_dir))]
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
    if test_id not in M7_TEST_IDS:
        issues.append(Issue("unknown_m7_test_id", f"not an approved M7 test ID: {test_id}", str(evidence_dir / "result.json")))
    documents: list[Any] = [result]
    for name in ("inputs.redacted.json", "objects-before.json", "objects-after.json"):
        value, value_issues = _load_json(evidence_dir / name)
        issues.extend(value_issues)
        if value is not None:
            documents.append(value)
            issues.extend(_scan_secrets(value, name))
    events, event_issues = _read_events(evidence_dir / "events.ndjson")
    issues.extend(event_issues)
    documents.append(events)
    _validate_evidence_manifest(evidence_dir, issues)
    issues.extend(_scan_files_for_secrets(evidence_dir))
    if str(result.get("conclusion", "")).upper() == "PASS":
        evidence_types = _collect_evidence_types(documents)
        if not evidence_types or not evidence_types.intersection(STRONG_EVIDENCE_TYPES) or evidence_types.issubset(WEAK_EVIDENCE_TYPES):
            issues.append(Issue("insufficient_evidence", "PASS requires independent RC evidence, not only HTTP/container facts", str(evidence_dir)))
    return issues


def validate_m7_foundation(
    fixture_root: Path,
    evidence_root: Path | None = None,
    *,
    runbook_root: Path | None = None,
    test_id: str | None = None,
) -> dict[str, Any]:
    """Return a machine-readable, read-only M7 foundation summary."""

    issues = validate_fixture_manifest(fixture_root)
    issues.extend(validate_metadata(fixture_root))
    if runbook_root is not None:
        issues.extend(validate_runbooks(runbook_root))
    evidence_results: list[dict[str, Any]] = []
    if evidence_root is not None:
        root = evidence_root.resolve()
        directories = [root / test_id] if test_id else sorted(path for path in root.iterdir() if path.is_dir()) if root.is_dir() else []
        if test_id and not (root / test_id).is_dir():
            evidence_results.append({"test_id": test_id, "passed": False, "issues": [issue.as_dict() for issue in validate_evidence_dir(root / test_id, expected_test_id=test_id)]})
        elif not directories:
            issues.append(Issue("missing_evidence_root", "M7 evidence root has no test directories", str(root)))
        else:
            for directory in directories:
                directory_issues = validate_evidence_dir(directory, expected_test_id=directory.name)
                evidence_results.append({"test_id": directory.name, "passed": not directory_issues, "issues": [issue.as_dict() for issue in directory_issues]})
    return {
        "milestone": "M7",
        "passed": not issues and all(item["passed"] for item in evidence_results),
        "fixture_root": str(Path(fixture_root).resolve()),
        "runbook_root": str(Path(runbook_root).resolve()) if runbook_root is not None else None,
        "fixture_issues": [issue.as_dict() for issue in issues],
        "evidence": evidence_results,
        "writes_gate_evidence": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, default=Path("tests/fixtures/m7"))
    parser.add_argument("--runbook-root", type=Path, default=Path("docs/runbooks"))
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--test-id")
    args = parser.parse_args(argv)
    summary = validate_m7_foundation(args.fixture_root, args.evidence_root, runbook_root=args.runbook_root, test_id=args.test_id)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
