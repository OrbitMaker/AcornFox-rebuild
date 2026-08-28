#!/usr/bin/env python3
"""Assert one M3 gate against the final clean-worker evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


MARKERS = {
    "SCHEMA-ROUTE-001": "ROUTE-NEGATIVE=PASS",
    "CT-ROUTE-001": "CT-ROUTE-001=PASS",
    "CADDY-INT-001": "CADDY-INT-001=PASS",
    "E2E-DOMAIN-001": "E2E-DOMAIN-001=PASS",
    "SEC-CADDY-001": "SEC-CADDY-001=PASS",
    "ROLL-002": "ROLL-002=PASS",
    "FAULT-CADDY-001": "FAULT-CADDY-001=PASS",
    "FAULT-CADDY-002": "FAULT-CADDY-002=PASS",
}


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--raw-root", required=True, type=Path)
    args = parser.parse_args()

    root = args.raw_root.resolve()
    evidence = root / "extracted" / "m3-real"
    stdout = (root / "m3-final2-guest-run.stdout").read_text(encoding="utf-8")
    marker = MARKERS.get(args.test_id)
    if marker is not None and marker not in stdout:
        raise AssertionError(f"missing clean-worker marker {marker}")

    summary = load_json(evidence / "summary.json")
    assert summary == {
        "ai_enabled": False,
        "conclusion": "PASS",
        "fallback_preserved": True,
        "old_serving_on_failed_switch": True,
        "production_certificates": 0,
        "public_dns_mutations": 0,
        "routes": ["/", "/api"],
    }
    before = load_json(evidence / "objects-before.json")
    after = load_json(evidence / "objects-after.json")
    assert before["caddy_admin"] == after["caddy_admin"]
    assert before["caddy_https"] == after["caddy_https"]

    if args.test_id == "SCHEMA-ROUTE-001":
        assert load_json(evidence / "route-conflict.json")["code"] == "conflict"
        assert load_json(evidence / "route-worker-reject.json")["code"] == "forbidden"
        routes = load_json(evidence / "domain-routes.json")["routes"]
        assert isinstance(routes, list) and {item["path"] for item in routes} == {"/", "/api"}
    elif args.test_id == "CT-ROUTE-001":
        routes = load_json(evidence / "domain-routes.json")["routes"]
        assert isinstance(routes, list) and all(item["verified"] and item["serving"] for item in routes)
        assert sha256(evidence / "caddy-config-before-restart.json") == sha256(evidence / "caddy-config-after-rebuild.json")
    elif args.test_id == "CADDY-INT-001":
        assert (evidence / "https-root-old.txt").read_text().strip() == "M3-OLD-FRONTEND"
        assert (evidence / "https-api.txt").read_text().strip() == "M3-API-V1"
        config = load_json(evidence / "caddy-config-before.json")
        assert config["admin"]["listen"] == "127.0.0.1:2019"
    elif args.test_id == "E2E-DOMAIN-001":
        fallback = load_json(evidence / "ip-fallback.json")["access_state"]
        assert fallback["ip_available"] is True and fallback["https_ready"] is False and "domain" not in fallback
        assert load_json(evidence / "platform-domain.json")["binding"]["status"] == "ready"
        application = load_json(evidence / "application-domain.json")
        assert application["binding"]["status"] == "ready" and application["certificate"]["status"] == "ready"
        route_state = load_json(evidence / "domain-routes.json")["access_state"]
        assert route_state["runtime_ready"] and route_state["https_ready"] and route_state["serving"]
    elif args.test_id == "SEC-CADDY-001":
        listener = (evidence / "caddy-admin-listener.txt").read_text()
        assert "127.0.0.1:2019" in listener and "0.0.0.0:2019" not in listener
        assert (evidence / "caddy-admin-negative.txt").read_text().strip()
        combined = b"".join(path.read_bytes() for path in evidence.iterdir() if path.is_file())
        assert b"PRIVATE KEY" not in combined and b"oc-dns01-" not in combined
    elif args.test_id == "ROLL-002":
        success = load_json(evidence / "switch-success.json")
        failure = load_json(evidence / "switch-failure.json")
        assert success["status"] == "stable"
        assert failure == {"code": "unavailable", "message": "observation failed; old deployment restored and remains serving"}
        assert (evidence / "https-root-after-failed-switch.txt").read_text().strip() == "M3-NEW-FRONTEND"
    elif args.test_id == "FAULT-CADDY-001":
        assert sha256(evidence / "caddy-config-before-restart.json") == sha256(evidence / "caddy-config-after-rebuild.json")
        assert (evidence / "https-after-caddy-restart.txt").read_text().strip() == "M3-NEW-FRONTEND"
    elif args.test_id == "FAULT-CADDY-002":
        assert load_json(evidence / "dns-failure.json")["code"] == "unavailable"
        assert load_json(evidence / "certificate-failure.json")["code"] == "unavailable"
        assert (evidence / "https-after-control-plane-restart.txt").read_text().strip() == "M3-NEW-FRONTEND"
    elif args.test_id == "M3-CANONICAL-BUNDLE":
        bundle = load_json(root / "m3-bundle-result-final2.json")
        assert bundle["valid"] is True and bundle["entries"] == 10
        assert bundle["sha256"] == "93fb6e4b11c03d71376876b58a72d088cff9bcf3d9a992332e04df9643fe1f09"
        assert bundle["sha256"] in (root / "staging.sha256").read_text(encoding="utf-8")
        assert load_json(evidence / "bundle-validation.json") == bundle
        assert (evidence / "current-release.txt").read_text().strip() == "releases/release-0.3.3"
    elif args.test_id in {"M3-HOST-ISOLATION", "M3-VM-RECLAIM"}:
        host_before = load_json(root / "m3-host-before-final2.json")
        host_after = load_json(root / "m3-host-after-final2-reclaim.json")
        assert host_before == host_after
        assert host_after["task_resources"] == {"domain": False, "network": False, "pool": False, "volume": False}
        cleanup = (root / "m3-final2-reclaim.log").read_text(encoding="utf-8")
        for required in ("domain=absent", "volume=absent", "pool=absent", "network=absent", "reclaim=complete"):
            assert required in cleanup
        if args.test_id == "M3-VM-RECLAIM":
            vm = ET.parse(root / "m3-final2-vm.xml").getroot()
            assert vm.findtext("uuid") == "fce4e26d-93b0-5128-a090-969ef73835d4"
            assert vm.findtext("vcpu") == "2" and vm.findtext("memory") == "4194304"
            assert not vm.findall("./devices/filesystem") and not vm.findall("./devices/hostdev")
            assert len(vm.findall("./devices/interface")) == 1 and len(vm.findall("./devices/disk")) == 3
    else:
        raise SystemExit(f"unsupported M3 test id: {args.test_id}")

    print(json.dumps({"test_id": args.test_id, "marker": marker, "summary": summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
