#!/usr/bin/env python3
"""Assert one M2 gate against the exported clean-worker evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


MARKERS = {
    "BUILD-INT-005": "RUNTIME-INT-002=PASS",
    "CT-IMAGE-001": "CT-IMAGE-001=PASS",
    "CT-RUNTIME-001": "CT-RUNTIME-001=PASS",
    "CT-SECRET-001": "SEC-SECRET-001=PASS",
    "CT-VOLUME-001": "CT-VOLUME-001-DELETE=PASS",
    "E2E-COMPOSE-001": "E2E-COMPOSE-001=PASS",
    "E2E-IMAGE-001": "E2E-IMAGE-001=PASS",
    "FAULT-AGENT-001": "FAULT-AGENT-001=PASS",
    "FAULT-AGENT-002": "FAULT-AGENT-002=PASS",
    "FAULT-RUNTIME-001": "FAULT-RUNTIME-001=PASS",
    "FAULT-RUNTIME-002": "FAULT-RUNTIME-002=PASS",
    "IMG-GC-001": "IMG-GC-001=PASS",
    "IMG-INT-001": "IMG-INT-001-TAG-MOVE=PASS",
    "IMG-INT-002": "IMG-INT-002-SECRET-SCAN=PASS",
    "ROLL-001": "ROLL-001-FAILED-NEW-VERSION=PASS",
    "RUNTIME-INT-001": "RUNTIME-INT-001=PASS",
    "RUNTIME-INT-002": "RUNTIME-INT-002=PASS",
    "SCHEMA-RELEASE-001": "M2-REAL-GATES=PASS",
    "SCHEMA-SERVICE-001": "M2-REAL-GATES=PASS",
    "SEC-SECRET-001": "SEC-SECRET-001=PASS",
    "VOL-FAULT-001": "ROLL-001-FAILED-NEW-VERSION=PASS",
    "VOL-INT-001": "VOL-INT-001=PASS",
    "M2-REAL-GATES": "M2-REAL-GATES=PASS",
}


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--raw-root", required=True, type=Path)
    args = parser.parse_args()

    root = args.raw_root.resolve()
    evidence = root / "m2-real"
    stdout_files = sorted(root.glob("m2-guest-run-v*.stdout"))
    if len(stdout_files) != 1:
        raise AssertionError("raw evidence must contain exactly one guest stdout")
    stdout = stdout_files[0].read_text(encoding="utf-8")
    marker = MARKERS.get(args.test_id)
    if marker is not None and marker not in stdout:
        raise AssertionError(f"missing clean-worker marker {marker}")

    after = load_json(evidence / "objects-after.json")
    assert after.get("containers") == 0
    assert after.get("volumes") == []
    assert after.get("networks") == []

    if args.test_id == "M2-CANONICAL-BUNDLE":
        bundle_results = sorted(root.glob("m2-bundle-result-v*.json"))
        assert len(bundle_results) == 1
        bundle = load_json(bundle_results[0])
        assert bundle.get("valid") is True and bundle.get("entries") == 9
        assert str(bundle.get("sha256", "")) in (root / "m2-export-manifest-v49.sha256").read_text(encoding="utf-8")
    elif args.test_id in {"M2-VM-RECLAIM", "M2-HOST-ISOLATION"}:
        assert (root / "m2-host-before.json").read_bytes() == (root / "m2-host-after-reclaim-v49.json").read_bytes()
        cleanup = (root / "m2-final-cleanup-v49.log").read_text(encoding="utf-8")
        for required in ("domain=absent", "volume=absent", "pool=absent", "network=absent", "host_baseline=exact_match"):
            assert required in cleanup
    elif args.test_id == "BUILD-INT-005":
        assert load_json(evidence / "capacity-negative.json").get("code") == "capacity_exceeded"
    elif args.test_id in {"SCHEMA-SERVICE-001", "SCHEMA-RELEASE-001", "E2E-COMPOSE-001"}:
        group = load_json(evidence / "group-v1.json")["service_group"]
        release = load_json(evidence / "release-v1.json")["release"]
        assert isinstance(group, dict) and str(group.get("config_digest", "")).startswith("sha256:")
        assert isinstance(release, dict) and release.get("immutable") is True
        digests = release.get("service_digests", {})
        assert isinstance(digests, dict) and len(digests) == 4
        assert all(str(item.get("digest", "")).startswith("sha256:") for item in digests.values())
        assert load_json(evidence / "deployment-v1-state.json").get("state") == "runtime_ready"
    elif args.test_id in {"CT-IMAGE-001", "IMG-INT-001"}:
        before = load_json(evidence / "image-public-resolve.json")["image"]
        after_move = load_json(evidence / "image-public-resolve-after-move.json")["image"]
        assert isinstance(before, dict) and isinstance(after_move, dict)
        assert before.get("digest") != after_move.get("digest")
        release = load_json(evidence / "release-v1.json")["release"]
        assert release["service_digests"]["db"]["resolved_tag"] == "stable"
    elif args.test_id in {"IMG-INT-002", "CT-SECRET-001", "SEC-SECRET-001"}:
        assert (evidence / "m2-db-redacted-scan.sql").is_file()
        assert load_json(evidence / "image-private-bad.json").get("code") in {"unauthorized", "forbidden"}
    elif args.test_id in {"CT-RUNTIME-001", "RUNTIME-INT-001"}:
        networks = json.loads((evidence / "service-network.json").read_text(encoding="utf-8"))
        assert isinstance(networks, list) and len(networks) == 1
        assert networks[0].get("Internal") is True
        assert len(networks[0].get("Containers", {})) == 2
    elif args.test_id == "RUNTIME-INT-002":
        assert load_json(evidence / "capacity-negative.json").get("code") == "capacity_exceeded"
    elif args.test_id in {"CT-VOLUME-001", "VOL-INT-001", "VOL-FAULT-001"}:
        checksums = {
            load_json(evidence / name).get("checksum")
            for name in (
                "volume-write-v1.json",
                "volume-after-update.json",
                "volume-after-failed-rollout.json",
                "volume-after-agent-controller-restart.json",
            )
        }
        assert len(checksums) == 1 and next(iter(checksums), "")
        if args.test_id == "CT-VOLUME-001":
            assert any(evidence.glob("volume-delete-volume_*.json"))
    elif args.test_id in {"FAULT-AGENT-001", "FAULT-AGENT-002"}:
        restarted = load_json(evidence / "deployment-v2-after-restart.json")
        assert restarted.get("state") == "runtime_ready"
    elif args.test_id in {"FAULT-RUNTIME-001", "ROLL-001"}:
        assert load_json(evidence / "deployment-failure-state.json").get("state") in {"failed", "rolled_back"}
        assert load_json(evidence / "deployment-v2-state.json").get("state") == "runtime_ready"
    elif args.test_id == "FAULT-RUNTIME-002":
        assert load_json(evidence / "deployment-optional-state.json").get("state") == "degraded"
    elif args.test_id == "E2E-IMAGE-001":
        assert load_json(evidence / "deployment-image-mix-state.json").get("state") == "runtime_ready"
        assert len(load_json(evidence / "release-image-mix.json")["release"]["service_digests"]) == 2
    elif args.test_id == "IMG-GC-001":
        gc = load_json(evidence / "image-gc.json")
        outcomes = gc.get("result", {}).get("outcomes", [])
        assert any(item.get("action") == "deleted" for item in outcomes)
        assert any(item.get("kind") == "volume" for item in gc.get("after", []))

    if marker is None and args.test_id not in {"M2-CANONICAL-BUNDLE", "M2-VM-RECLAIM", "M2-HOST-ISOLATION"}:
        raise SystemExit(f"unsupported M2 test id: {args.test_id}")
    print(json.dumps({"test_id": args.test_id, "marker": marker, "objects_after": after}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
