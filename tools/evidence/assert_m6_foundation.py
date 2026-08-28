#!/usr/bin/env python3
"""Read-only validator for deterministic M6 fixtures and active evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


M6_TEST_IDS = frozenset({"UNIT-AI-001", "SCHEMA-AI-001", "SCHEMA-AI-002", "CT-AI-001", "E2E-AI-001", "AI-SEC-001", "AI-SEC-002", "AI-SEC-003", "AI-SEC-004", "AI-SEC-005", "AI-DEG-001", "AI-DEG-002", "AI-DEG-003", "AI-CTX-001", "AI-PLAN-001", "AI-CATALOG-001", "AI-CATALOG-002", "AI-RUNNER-001", "AI-LEDGER-001", "AI-LEDGER-002", "AI-RULE-001", "AI-RULE-002", "AI-RULE-003", "AI-METRIC-001", "AI-PROFILE-001"})
FIXTURE_FILES = frozenset({"README.md", "metadata.json", "contexts.json", "plans.json", "catalog.json", "rules.json", "scenarios.json"})
REQUIRED_EVIDENCE = ("result.json", "inputs.redacted.json", "objects-before.json", "objects-after.json", "events.ndjson", "manifest.sha256")
STRONG = {"audit", "checksum", "database_query", "event_sequence", "object_state", "policy_decision", "sandbox", "security_negative", "structured_plan", "test", "tool_evidence"}
SENSITIVE_PATTERNS = (re.compile(r"-----BEGIN\s+(?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.I), re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,}\b"), re.compile(r"postgres://[^\s:@]+:[^\s@]+@", re.I))


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    path: str = ""
    def as_dict(self) -> dict[str, str]: return {key: value for key, value in {"code": self.code, "message": self.message, "path": self.path}.items() if value}


def sha256(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path: Path) -> Any: return json.loads(path.read_text(encoding="utf-8"))


def parse_manifest(path: Path) -> tuple[dict[str, str], list[Issue]]:
    if not path.is_file(): return {}, [Issue("missing_manifest", "manifest.sha256 is missing", str(path))]
    result: dict[str, str] = {}; issues: list[Issue] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]): issues.append(Issue("invalid_manifest", f"invalid line {number}", str(path))); continue
        if parts[1] in result: issues.append(Issue("duplicate_manifest", f"duplicate {parts[1]}", str(path)))
        result[parts[1]] = parts[0]
    return result, issues


def scan_text(root: Path) -> list[Issue]:
    issues: list[Issue] = []
    for path in root.rglob("*"):
        if not path.is_file(): continue
        try: text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError: continue
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(text): issues.append(Issue("sensitive_plaintext", "sensitive material found", str(path)))
    return issues


def validate_fixture(root: Path) -> list[Issue]:
    root = root.resolve(); manifest, issues = parse_manifest(root / "manifest.sha256")
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and path.name != "manifest.sha256"}
    if actual != FIXTURE_FILES: issues.append(Issue("fixture_file_set", f"unexpected files: {sorted(actual)}", str(root)))
    if set(manifest) != actual: issues.append(Issue("manifest_file_set", "fixture manifest does not cover exact files", str(root)))
    for name, digest in manifest.items():
        if (root / name).is_file() and sha256(root / name) != digest: issues.append(Issue("manifest_mismatch", name, str(root / name)))
    try:
        metadata, contexts, plans, catalog, rules, scenarios = (load(root / name) for name in ("metadata.json", "contexts.json", "plans.json", "catalog.json", "rules.json", "scenarios.json"))
        if set(metadata["test_ids"]) != M6_TEST_IDS: issues.append(Issue("test_id_mapping", "M6 IDs differ from approved spec"))
        if metadata["external_model_calls"] is not False or metadata["profiles"] != ["china", "global", "local", "disabled"]: issues.append(Issue("profile_boundary", "offline profile matrix is invalid"))
        safe = contexts["safe"]
        if not all(item["value"] == "[REDACTED]" for item in safe["secret_references"]): issues.append(Issue("secret_redaction", "secret reference exposes a value"))
        if any(item["treated_as_instruction"] for item in safe["untrusted_data"]): issues.append(Issue("prompt_injection", "repository text became instruction"))
        plan = plans["valid"]
        if plan["schema_version"] != "1.0" or not plan["budget"] or not plan["sources"] or not plan["requires_user_confirmation"]: issues.append(Issue("plan_contract", "strict plan fields are incomplete"))
        if set(catalog["denied"]) < {"shell.exec", "ssh.run", "docker.socket", "kubernetes.production", "production.restart", "core.hot_update", "secret.plaintext"}: issues.append(Issue("catalog_boundary", "denied catalog is incomplete"))
        if rules["states"] != ["proposed", "testing", "reviewed", "shadow", "approved", "promoted"]: issues.append(Issue("rule_lifecycle", "rule lifecycle is not review gated"))
        if scenarios["golden_path"]["ai_enabled"] is not False or scenarios["e2e"]["production_writes"] != 0: issues.append(Issue("golden_path", "AI-off or zero-production-write boundary changed"))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc: issues.append(Issue("fixture_shape", str(exc), str(root)))
    issues.extend(scan_text(root)); return issues


def walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values(): yield from walk(child)
    elif isinstance(value, list):
        for child in value: yield from walk(child)


def validate_evidence(path: Path) -> list[Issue]:
    issues: list[Issue] = []
    for name in REQUIRED_EVIDENCE:
        if not (path / name).is_file(): issues.append(Issue("missing_evidence", name, str(path)))
    if issues: return issues
    result = load(path / "result.json"); test_id = str(result.get("test_id", path.name))
    if test_id != path.name or test_id not in M6_TEST_IDS: issues.append(Issue("test_id", test_id, str(path)))
    if result.get("conclusion") != "PASS" or result.get("exit_code") != 0: issues.append(Issue("not_passed", test_id, str(path)))
    manifest, manifest_issues = parse_manifest(path / "manifest.sha256"); issues.extend(manifest_issues)
    for name in REQUIRED_EVIDENCE:
        if name != "manifest.sha256" and (name not in manifest or sha256(path / name) != manifest[name]): issues.append(Issue("manifest_mismatch", name, str(path)))
    documents = [result, load(path / "inputs.redacted.json"), load(path / "objects-before.json"), load(path / "objects-after.json")]
    documents.extend(json.loads(line) for line in (path / "events.ndjson").read_text(encoding="utf-8").splitlines() if line)
    types = {str(item).lower() for document in documents for value in walk(document) if isinstance(value, dict) for key in ("evidence_type", "type", "kind", "source") if (item := value.get(key)) is not None}
    for document in documents:
        for value in walk(document):
            if isinstance(value, dict) and isinstance(value.get("evidence_types"), list):
                types.update(str(item).lower() for item in value["evidence_types"])
    if not types.intersection(STRONG): issues.append(Issue("insufficient_evidence", "PASS lacks policy/sandbox/database evidence", str(path)))
    issues.extend(scan_text(path)); return issues


def validate(fixture_root: Path, evidence_root: Path | None) -> dict[str, Any]:
    fixture_issues = validate_fixture(fixture_root); evidence = []
    if evidence_root is not None:
        for test_id in sorted(M6_TEST_IDS):
            issues = validate_evidence(evidence_root / test_id)
            evidence.append({"test_id": test_id, "passed": not issues, "issues": [issue.as_dict() for issue in issues]})
    return {"milestone": "M6", "passed": not fixture_issues and all(item["passed"] for item in evidence), "fixture_issues": [issue.as_dict() for issue in fixture_issues], "evidence": evidence, "writes_gate_evidence": False}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--fixture-root", type=Path, default=Path("tests/fixtures/m6")); parser.add_argument("--evidence-root", type=Path); args = parser.parse_args()
    result = validate(args.fixture_root, args.evidence_root); print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)); return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
