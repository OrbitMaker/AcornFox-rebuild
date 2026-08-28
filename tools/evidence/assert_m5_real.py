#!/usr/bin/env python3
"""Independently assert one approved M5 gate from frozen real-load evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from assert_m5_foundation import M5_TEST_IDS, validate_fixture_manifest


SENSITIVE = (
    re.compile(rb"-----BEGIN\s+(?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.I),
    re.compile(rb"authorization:\s*bearer", re.I),
    re.compile(rb"cookie=", re.I),
    re.compile(rb"postgres://[^\s:@]+:[^\s@]+@", re.I),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(root: Path, name: str) -> Path:
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise AssertionError(f"missing regular M5 raw evidence file: {name}")
    return path


def load_json(root: Path, name: str):
    return json.loads(require(root, name).read_text(encoding="utf-8"))


def validate_manifest(root: Path) -> int:
    entries: dict[str, str] = {}
    for line in require(root, "manifest.sha256").read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, name = line.split(None, 1)
        name = name.strip().removeprefix("./")
        assert re.fullmatch(r"[0-9a-f]{64}", digest) and name not in entries
        entries[name] = digest
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and path.name != "manifest.sha256"}
    assert set(entries) == actual, (sorted(set(entries) - actual), sorted(actual - set(entries)))
    for name, digest in entries.items():
        assert sha256(root / name) == digest, name
    return len(entries)


def run_check(*args: str) -> None:
    completed = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"directed check failed: {' '.join(args)}\n{completed.stdout}")


def scan_sensitive(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for pattern in SENSITIVE:
            assert pattern.search(data) is None, path.name


def assert_docker_facts(root: Path) -> dict:
    facts = load_json(root, "docker-facts.json")
    assert facts["task_prefix"] == "opencard-mvp-fa8f8eab"
    assert facts["no_host_mounts"] is True and facts["no_docker_socket"] is True
    assert facts["network_mode"] == "opencard-mvp-fa8f8eab-m5-net"
    assert re.fullmatch(r"[0-9a-f]{64}", facts["container_id"])
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", facts["image_digest"])
    before, after = facts["samples"]
    assert before["healthy"] is True and after["healthy"] is False
    assert before["limit_cpu_millicores"] == after["limit_cpu_millicores"] == 500
    assert before["limit_memory_bytes"] == after["limit_memory_bytes"] == 64 << 20
    assert before["limit_pids"] == after["limit_pids"] == 64
    for sample in (before, after):
        assert sample["memory_bytes"] > 0 and sample["disk_bytes"] >= 8 << 20
        assert sample["network_rx_bytes"] > 0 and sample["network_tx_bytes"] > 0
    assert after["network_rx_bytes"] > before["network_rx_bytes"]
    assert after["network_tx_bytes"] > before["network_tx_bytes"]
    return facts


def assert_integration(root: Path) -> str:
    text = require(root, "integration.log").read_text(encoding="utf-8")
    retention = require(root, "retention-integration.log").read_text(encoding="utf-8")
    assert "TestM5ProjectsM4CompactsAndKeepsApplicationScope" in text
    assert "TestM5RealDockerFactsAggregateWithoutCrossApplicationLeak" in text
    assert text.count("--- PASS:") >= 2 and "latest_migration=0020" in text
    assert "m5_tables=4" in text and "usage_rows=4|3" in text
    assert "TestM5WatermarkRejectsRawWriteAndRetentionKeepsLatestAggregateAndAudit" in retention
    assert "--- PASS: TestM5WatermarkRejectsRawWriteAndRetentionKeepsLatestAggregateAndAudit" in retention
    assert "latest_migration=0020" in retention and "usage_rows=2|2" in retention
    return text + retention


def assert_gate(test_id: str, root: Path, fixture_root: Path) -> list[str]:
    assert test_id in M5_TEST_IDS
    assert not validate_fixture_manifest(fixture_root)
    count = validate_manifest(root)
    assert require(root, "host-before.txt").read_bytes() == require(root, "host-after.txt").read_bytes()
    scan_sensitive(root)
    facts = assert_docker_facts(root)
    assert_integration(root)
    checks = [f"raw manifest verifies {count} files", "protected host before/after snapshots match"]
    if test_id == "UNIT-USAGE-001":
        run_check("go", "test", "./internal/usage", "./internal/foundation", "-run", "Usage|AggregateFacts", "-count=1")
        checks += ["fixed UTC aggregate unit vectors pass", "actual units and limits remain separate"]
    elif test_id == "CT-METER-001":
        run_check("go", "test", "./internal/contracts", "./internal/providers/meter/local", "-run", "CT_METER|Meter", "-count=1")
        checks += ["fake and local MeterProvider contracts pass", "real PostgreSQL projection and query pass"]
    elif test_id == "USAGE-INT-001":
        checks += ["empty PostgreSQL migrated through 0020", "M4 observations projected into revisioned average peak and trend buckets", "hard watermark rejected raw writes while retained aggregate and audit remained queryable"]
    elif test_id == "E2E-USAGE-001":
        checks += ["task-scoped Docker CPU memory disk and network load was independently sampled", "healthy-to-unhealthy observation produced an aggregate anomaly"]
    elif test_id == "USAGE-001":
        run_check("go", "test", "./internal/usage", "./internal/contracts", "-run", "Late|Deduplicates", "-count=1")
        checks += ["duplicate identity is idempotent and conflicting reuse fails", "late and out-of-order facts land in the UTC bucket"]
    elif test_id == "USAGE-002":
        run_check("go", "test", "./cmd/open-card-server", "-run", "TestM5UsageHandlerFailsClosedForOperatorAndAIContext|TestM5UsageWindow", "-count=1")
        checks += ["operator detail and AI context fail closed", "second application query returned zero buckets"]
    elif test_id == "USAGE-003":
        run_check("go", "test", "./cmd/open-card-server", "-run", "TestProjectM5UsageSeparatesActualLimitsAndRawFromAI", "-count=1")
        assert facts["samples"][0]["cpu_millicores"] != facts["samples"][0]["limit_cpu_millicores"]
        checks += ["average peak trend and configured limits remain distinct", "API projection contains no commercial or AI raw-data fields"]
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, default=Path("tests/fixtures/m5"))
    args = parser.parse_args()
    checks = assert_gate(args.test_id, args.raw_root.resolve(), args.fixture_root.resolve())
    print(json.dumps({"test_id": args.test_id, "conclusion": "PASS", "checks": checks, "evidence_type": "usage_aggregate"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
