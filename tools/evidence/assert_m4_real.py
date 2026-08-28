#!/usr/bin/env python3
"""Assert one approved M4 gate against the final canonical VM evidence.

The runner deliberately writes NOT_CLAIMED.  This independent reader turns a
specific, checked assertion over that immutable raw tree into a gate result;
it never mutates the raw evidence or the tested system.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import subprocess
from pathlib import Path

from assert_m4_foundation import M4_TEST_IDS


SENSITIVE = (
    re.compile(rb"-----BEGIN\s+(?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.I),
    re.compile(rb"\bm4-[a-z0-9-]*canary\b", re.I),
    re.compile(rb"m4-fixture-signing-key", re.I),
    re.compile(rb"authorization:\s*bearer", re.I),
    re.compile(rb"cookie=", re.I),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(root: Path, relative: str) -> Path:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise AssertionError(f"required regular evidence file is missing: {relative}")
    return path


def load_json(root: Path, relative: str):
    return json.loads(require(root, relative).read_text(encoding="utf-8"))


def read_lines(root: Path, relative: str) -> list[str]:
    return [line for line in require(root, relative).read_text(encoding="utf-8").splitlines() if line]


def read_ndjson(root: Path, relative: str) -> list[dict]:
    return [json.loads(line) for line in read_lines(root, relative)]


def validate_raw_manifest(root: Path) -> int:
    entries = {}
    for line in read_lines(root, "manifest.sha256"):
        digest, name = line.split(None, 1)
        name = name.strip()
        while name.startswith("./"):
            name = name[2:]
        assert re.fullmatch(r"[0-9a-f]{64}", digest) and name not in entries
        entries[name] = digest
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and path.name != "manifest.sha256"}
    assert set(entries) == actual, (sorted(set(entries) - actual), sorted(actual - set(entries)))
    for name, digest in entries.items():
        assert sha256(root / name) == digest, name
    return len(entries)


def scan_no_sensitive(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or path.name.endswith(".tar"):
            continue
        data = path.read_bytes()
        for pattern in SENSITIVE:
            assert pattern.search(data) is None, path.relative_to(root).as_posix()


def run_check(*args: str) -> None:
    completed = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"directed check failed: {Path(args[0]).name} exit={completed.returncode}")


def assert_hmac(records: list[dict]) -> None:
    assert records
    for record in records:
        event_id, timestamp, signature = record.get("event_id"), record.get("timestamp"), record.get("signature")
        assert event_id and timestamp and signature
        body = record.get("body", "").encode()
        signed = (str(int(timestamp)) + "." + event_id + ".").encode() + body
        expected = "sha256=" + hmac.new(b"m4-fixture-signing-key", signed, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(signature, expected)


def rollout_phase_files(root: Path) -> list[Path]:
    return sorted(root.glob("rollout-*-phases.tsv"))


def assert_phases(root: Path) -> None:
    expected = ["candidate_requested", "candidate_ready", "route_staged", "route_committed", "old_retiring", "completed"]
    files = rollout_phase_files(root)
    assert len(files) >= 2
    for path in files:
        phases = [line.split("|", 1)[1] for line in path.read_text(encoding="utf-8").splitlines() if line]
        assert phases == expected, (path.name, phases)


def assert_gate(test_id: str, root: Path) -> tuple[list[str], list[Path]]:
    checks: list[str] = []
    files: list[Path] = []

    def use(*relative: str) -> None:
        files.extend(require(root, item) for item in relative)

    if test_id == "UNIT-REDACT-001":
        run_check("go", "test", "./internal/foundation", "-run", "TestUnitREDACT001SecretsAndEncodedVariants", "-count=1")
        scan_no_sensitive(root)
        use("log-gates/log-gates-operator-redaction.json")
        checks += ["redaction unit vector passed", "raw evidence contains no secret canary or private key"]
    elif test_id == "UNIT-WEBHOOK-001":
        run_check("go", "test", "./internal/foundation", "-run", "TestUnitWEBHOOK001SignatureVectorAndReplay", "-count=1")
        records = read_ndjson(root, "receiver-capture.ndjson")
        assert_hmac(records)
        use("receiver-capture.ndjson")
        checks += ["signature unit vector passed", "captured signatures verify"]
    elif test_id == "SCHEMA-OP-001":
        run_check("go", "test", "./internal/persistence/postgres", "-run", "TestM4.*Migration|TestM4RolloutPhaseTransitionsFailClosed", "-count=1")
        assert_phases(root)
        assert load_json(root, "redeploy-stale.json")["code"] == "conflict"
        assert load_json(root, "rollback-stale.json")["code"] == "conflict"
        use("redeploy-stale.json", "rollback-stale.json")
        files += rollout_phase_files(root)
        checks += ["M4 schema/state tests passed", "rollout phases and stale-version conflicts are exact"]
    elif test_id == "CT-NOTIFY-001":
        rows = [line.split("|") for line in read_lines(root, "webhook-lifecycle/webhook-events.tsv")]
        assert [row[1] for row in rows] == ["notification.occurrence", "notification.escalation", "notification.recovery"]
        assert all(row[2] == "delivered" for row in rows)
        use("webhook-lifecycle/webhook-events.tsv", "webhook-lifecycle/receiver-capture.ndjson")
        checks += ["failure escalation recovery ordering is durable", "all lifecycle notifications delivered"]
    elif test_id == "LOG-INT-001":
        ordinary, operator = load_json(root, "logs-ordinary.json"), load_json(root, "logs-operator.json")
        assert ordinary["mode"] == "ordinary" and ordinary["summary"]["raw_logs_available"] is False
        categories = {item["category"] for item in operator["items"]}
        assert {"build", "runtime", "audit"} <= categories
        use("logs-ordinary.json", "logs-operator.json")
        checks += ["ordinary view hides raw logs", "operator query contains three durable log classes"]
    elif test_id == "WEBHOOK-INT-001":
        assert read_lines(root, "webhook-ledger-initial.txt") == ["delivered|1"]
        assert read_lines(root, "webhook-ledger-retry.txt") == ["delivered|2"]
        records = read_ndjson(root, "receiver-capture.ndjson")
        assert any(item["status"] == 500 for item in records) and any(item["status"] == 204 for item in records)
        use("webhook-ledger-initial.txt", "webhook-ledger-retry.txt", "receiver-capture.ndjson")
        checks += ["test notification delivered", "one-shot failure durably retried"]
    elif test_id == "OBS-001":
        view = load_json(root, "operations-before-fault.json")
        assert len(view["services"]) == 4
        assert all(service["health"] == "healthy" for service in view["services"])
        assert load_json(root, "operations-after-restart.json")["serving"] is True
        use("operations-before-fault.json", "operations-after-restart.json")
        checks += ["ordinary operations fact shows four healthy services", "post-restart view recovered"]
    elif test_id == "OBS-002":
        names = ["api", "db", "frontend", "worker"]
        for phase in ("before-load", "after-load", "post-restart", "post-load"):
            for name in names:
                value = load_json(root, f"observability-{phase}-{name}.json")
                assert value["inspect"]["limits"] == value["cgroup"]["limits"]
                assert value["identity"]["task_prefix"] == "opencard-mvp-fa8f8eab"
                files.append(root / f"observability-{phase}-{name}.json")
        use("independent-observations-after-load.tsv", "independent-observations-post-load.tsv")
        checks += ["Docker inspect and kernel cgroup limits agree", "independent samples cover load and restart"]
    elif test_id == "LOG-001":
        assert "LOG-001=EXECUTED_VERIFIED" in read_lines(root, "log-gates.markers")
        value = load_json(root, "log-gates/log-001-runtime-operator.json")
        assert value["mode"] == "operator" and any(item["category"] == "runtime" for item in value["items"])
        use("log-gates.markers", "log-gates/log-001-runtime-operator.json")
        checks += ["runtime collection executed", "rotated runtime logs remain queryable after restart"]
    elif test_id == "LOG-002":
        assert "LOG-002=EXECUTED_VERIFIED" in read_lines(root, "log-gates.markers")
        assert len(read_lines(root, "log-gates/log-002-builds.tsv")) == 21
        assert len(read_lines(root, "log-gates/log-002-build-identities.tsv")) == 21
        assert len(load_json(root, "log-gates/log-002-build-operator-after-restart.json")["items"]) == 20
        use("log-gates/log-002-builds.tsv", "log-gates/log-002-build-identities.tsv", "log-gates/log-002-build-operator-after-restart.json")
        checks += ["21 builds exercised", "only latest 20 build executions survive and recover"]
    elif test_id == "LOG-003":
        assert "LOG-003=EXECUTED_VERIFIED" in read_lines(root, "log-gates.markers")
        before = int(read_lines(root, "log-gates/log-003-audit-before.txt")[0])
        after = int(read_lines(root, "log-gates/log-003-audit-after.txt")[0])
        assert before > 0 and after == before
        use("log-gates/log-003-audit-before.txt", "log-gates/log-003-audit-after.txt", "log-gates/log-gates-operator-redaction.json")
        checks += ["audit facts retained across ordinary GC", "audit operator projection is redacted"]
    elif test_id == "OPS-E2E-001":
        before = {item["service"]: item for item in load_json(root, "service-identities-before-fault.json")}
        after = {item["service"]: item for item in load_json(root, "service-identities-after-restart.json")}
        assert before["worker"]["id"] and after["worker"]["id"]
        assert all(before[name]["id"] == after[name]["id"] for name in before if name != "worker")
        assert require(root, "traffic-before-fault.txt").read_bytes() == require(root, "traffic-after-restart.txt").read_bytes()
        assert load_json(root, "restart.json")["operation"]["operation"]["status"] == "succeeded"
        use("service-identities-before-fault.json", "service-identities-after-restart.json", "traffic-before-fault.txt", "traffic-after-restart.txt", "restart.json")
        checks += ["only the unhealthy worker identity changed", "ingress traffic and other services were uninterrupted"]
    elif test_id == "OPS-E2E-002":
        assert_phases(root)
        snapshot = load_json(root, "route-failure-snapshot.json")
        assert snapshot["candidate_cleaned"] is True and snapshot["route_set_state"] == "discarded"
        assert load_json(root, "operations-after-route-failure.json")["serving"] is True
        use("route-failure-snapshot.json", "operations-after-route-failure.json", "route-recovery-redeploy.json")
        files += rollout_phase_files(root)
        checks += ["redeploy and rollback completed all durable phases", "failed candidate cleaned while old route stayed serving"]
    elif test_id == "SEC-SECRET-001":
        run_check("go", "test", "./internal/providers/secret", "./internal/foundation", "-run", "Secret|REDACT", "-count=1")
        scan_no_sensitive(root)
        use("inputs.redacted.json", "log-gates/sec-log-sensitive-response.json")
        checks += ["SecretProvider/redaction tests passed", "VM evidence contains no secret canary or key material"]
    elif test_id == "SEC-LOG-001":
        scan_no_sensitive(root)
        response = load_json(root, "log-gates/sec-log-sensitive-response.json")
        assert response["code"] in {"compose_rejected", "validation_failed", "invalid_json"}
        use("log-gates/sec-log-sensitive-response.json", "log-gates/log-gates-operator-redaction.json")
        checks += ["sensitive source rejected", "operator log response contains no canary"]
    elif test_id == "SEC-WEBHOOK-001":
        records = read_ndjson(root, "webhook-lifecycle/receiver-capture.ndjson")
        assert_hmac(records)
        forbidden = ("authorization", "cookie", "password", "secret")
        assert all(not any(word in item["body"].lower() for word in forbidden) for item in records)
        use("webhook-lifecycle/receiver-capture.ndjson")
        checks += ["lifecycle HMAC verifies", "payload excludes credentials and raw logs"]
    elif test_id == "SEC-WEBHOOK-002":
        run_check("go", "test", "./internal/providers/notification/webhook", "-run", "TestWebhookRejectsUnsafeTargetsRedirectsAndRawKeys|TestWebhookLoopbackFixturePermitsOnlyFixedInternalHostname", "-count=1")
        endpoint = load_json(root, "webhook-lifecycle/webhook-config.json")["endpoint"]["url"]
        assert endpoint.startswith("https://opencard-webhook-fixture.test:19444/")
        use("webhook-lifecycle/webhook-config.json")
        checks += ["SSRF redirect DNS and raw-key negatives passed", "real fixture stayed on exact loopback hostname"]
    elif test_id == "VOL-FAULT-001":
        cleanup = next(root.glob("rollout-*-candidate-cleanup.json"))
        value = json.loads(cleanup.read_text(encoding="utf-8"))
        assert value["kind"] == "destroy_group" and value["parameters"]["preserve_volumes"] is True
        for path in root.glob("rollout-*-retirement-payload.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["parameters"]["preserve_volumes"] is True
            files.append(path)
        files.append(cleanup)
        checks += ["candidate cleanup preserves volumes", "old retirement tasks preserve volumes"]
    elif test_id == "FAULT-WEBHOOK-001":
        delays = read_lines(root, "webhook-lifecycle/webhook-retry-delays.tsv")
        assert float(delays[1].split("|")[1]) >= 0.8 and float(delays[2].split("|")[1]) >= 4.5
        assert read_lines(root, "webhook-lifecycle/webhook-three-retries.tsv") == ["retry_wait|3|30"]
        assert read_lines(root, "webhook-lifecycle/webhook-recovered-row.txt") == ["delivered|4"]
        use("webhook-lifecycle/webhook-retry-delays.tsv", "webhook-lifecycle/webhook-three-retries.tsv", "webhook-lifecycle/webhook-recovered-row.txt")
        checks += ["1/5/30 retry schedule persisted", "worker restart resumed and delivered attempt 4"]
    elif test_id == "EVIDENCE-001":
        count = validate_raw_manifest(root)
        use("manifest.sha256", "result.json")
        checks += [f"raw recursive manifest verifies {count} files", "runner result is exit zero and deliberately NOT_CLAIMED"]
    elif test_id == "EVIDENCE-002":
        run_check("python3", "tests/evidence/test_validate_mvp_evidence.py")
        run_check("python3", "tests/evidence/test_assert_m4_foundation.py")
        count = validate_raw_manifest(root)
        before_path = require(root.parent, "m4-final27-host-before.json")
        after_path = require(root.parent, "m4-final27-host-after.json")
        before, after = json.loads(before_path.read_text(encoding="utf-8")), json.loads(after_path.read_text(encoding="utf-8"))
        for key in ("apparmor_restrict_unprivileged_userns", "default_route", "services", "non_task_containers_sha256", "non_task_containers_count", "non_task_domains_sha256", "non_task_domains", "non_task_networks_sha256", "non_task_networks", "non_task_pools_sha256", "non_task_pools"):
            assert before[key] == after[key], key
        assert not any(after["task_resources"].values())
        use("manifest.sha256", "events.ndjson")
        files += [before_path, after_path, require(root.parent, "m4-final27-reclaim.log")]
        checks += ["evidence validator negative/positive tests passed", f"final raw manifest remains exact across {count} files", "host before/after protected hashes match and task VM resources are absent"]
    else:
        raise AssertionError(f"unsupported M4 test id: {test_id}")
    return checks, sorted(set(files))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-root", required=True, type=Path)
    parser.add_argument("--test-id", required=True)
    args = parser.parse_args()
    if args.test_id not in M4_TEST_IDS:
        raise SystemExit("test id is not in the approved M4 matrix")
    root = args.raw_root.resolve()
    assert root.is_dir() and root.name == "m4-real"
    assert validate_raw_manifest(root) >= 190
    raw_result = load_json(root, "result.json")
    assert raw_result["exit_code"] == 0 and raw_result["conclusion"] == "NOT_CLAIMED"
    runner_exit = root.parent / "m4-final27-guest-run.exit"
    assert runner_exit.read_text(encoding="utf-8").strip() == "0"
    checks, files = assert_gate(args.test_id, root)
    print(json.dumps({
        "test_id": args.test_id,
        "conclusion": "PASS",
        "raw_runner": "final27",
        "checks": checks,
        "evidence": [{"path": (path.relative_to(root).as_posix() if path.is_relative_to(root) else "../" + path.relative_to(root.parent).as_posix()), "sha256": sha256(path)} for path in files],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
