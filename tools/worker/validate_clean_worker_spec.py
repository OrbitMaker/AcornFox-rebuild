#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any


TASK_PREFIX = "opencard-mvp-fa8f8eab"
PLACEHOLDER = "REQUIRED_BEFORE_PROVISIONING"
EXPECTED_NAMES = {
    "domain_name": "opencard-mvp-fa8f8eab-build-worker-01",
    "pool_name": "opencard-mvp-fa8f8eab-build-workers",
    "volume_name": "opencard-mvp-fa8f8eab-build-worker-01.qcow2",
    "network_name": "opencard-mvp-fa8f8eab-build-isolated",
}
EXPECTED_UUIDS = {
    "domain_uuid": "fce4e26d-93b0-5128-a090-969ef73835d4",
    "pool_uuid": "72a914c5-b6c7-5f22-a3bd-88f9b43f1619",
    "network_uuid": "03f91824-e5c9-5655-ac06-fec291e81c93",
}
EXPECTED_POOL_PATH = "/var/lib/libvirt/images/opencard-mvp-fa8f8eab"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_task_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"opencard-mvp-fa8f8eab[a-z0-9_.-]*", value):
        raise ValueError(f"{field} must use the exact task prefix")
    return value


def validate_artifact(path_value: Any, digest_value: Any, field: str, allow_placeholder: bool) -> dict[str, Any]:
    if path_value == PLACEHOLDER or digest_value == PLACEHOLDER:
        if allow_placeholder:
            return {"field": field, "status": "BLOCKED_PENDING_ARTIFACT"}
        raise RuntimeError(f"{field} path and sha256 are required before provisioning")
    if not isinstance(path_value, str) or not os.path.isabs(path_value):
        raise ValueError(f"{field} path must be absolute")
    path = Path(path_value)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{field} must be a regular non-symlink file")
    if not isinstance(digest_value, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_value):
        raise ValueError(f"{field} sha256 is invalid")
    actual = sha256(path)
    if actual != digest_value:
        raise RuntimeError(f"{field} checksum mismatch")
    return {"field": field, "status": "VERIFIED", "size_bytes": info.st_size, "sha256": actual}


def validate(spec: dict[str, Any], allow_placeholder: bool) -> dict[str, Any]:
    if spec.get("schema_version") != 1:
        raise ValueError("unsupported clean worker spec version")
    if spec.get("task_id") != TASK_PREFIX:
        raise ValueError("task_id does not match the approved task")
    for field, expected in EXPECTED_NAMES.items():
        if require_task_name(spec.get(field), field) != expected:
            raise ValueError(f"{field} does not match the approved exact resource")
    for field, expected in EXPECTED_UUIDS.items():
        try:
            parsed = str(uuid.UUID(str(spec.get(field))))
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{field} is invalid") from exc
        if parsed != expected:
            raise ValueError(f"{field} does not match the approved exact UUID")
    if spec.get("pool_path") != EXPECTED_POOL_PATH:
        raise ValueError("pool_path does not match the approved exact path")
    resources = spec.get("resources")
    if not isinstance(resources, dict):
        raise ValueError("resources object is required")
    exact_resources = {
        "vcpus": 2,
        "memory_mib": 4096,
        "disk_gib": 40,
        "build_memory_mib": 512,
        "build_cpu_quota": 50000,
        "build_cpu_period": 100000,
        "build_timeout_seconds": 300,
        "max_concurrent_builds": 1,
    }
    for field, expected in exact_resources.items():
        value = resources.get(field)
        if not isinstance(value, int) or value != expected:
            raise ValueError(f"resource {field} does not match the approved exact value")
    isolation = spec.get("isolation")
    if not isinstance(isolation, dict):
        raise ValueError("isolation object is required")
    if isolation.get("network_mode") != "isolated-no-forward":
        raise ValueError("clean worker network must have no forwarding")
    if isolation.get("network_forward") is not False or isolation.get("autostart") is not False:
        raise ValueError("network forwarding and autostart are forbidden")
    if isolation.get("metadata_endpoint_denied") is not True:
        raise ValueError("metadata endpoint must be denied")
    if isolation.get("host_mounts") != [] or isolation.get("host_devices") != [] or isolation.get("host_docker_socket") is not False or isolation.get("privileged") is not False:
        raise ValueError("host mounts, devices, Docker socket, and privilege are forbidden")
    if isolation.get("user_namespace") != "guest-local-rootless":
        raise ValueError("BuildKit must be rootless inside the guest")
    acceptance = spec.get("acceptance")
    if not isinstance(acceptance, dict):
        raise ValueError("acceptance object is required")
    if acceptance.get("expected_memory_max_bytes") != resources["build_memory_mib"] * 1024 * 1024:
        raise ValueError("acceptance memory.max disagrees with resource limit")
    if acceptance.get("expected_cpu_max") != f"{resources['build_cpu_quota']} {resources['build_cpu_period']}":
        raise ValueError("acceptance cpu.max disagrees with resource limit")
    for field in ("require_timeout_cleanup", "require_workspace_cleanup", "require_socket_absence"):
        if acceptance.get(field) is not True:
            raise ValueError(f"acceptance {field} must remain required")
    artifacts = [
        validate_artifact(spec.get("image_path"), spec.get("image_sha256"), "image", allow_placeholder),
        validate_artifact(spec.get("offline_bundle_path"), spec.get("offline_bundle_sha256"), "offline_bundle", allow_placeholder),
    ]
    blocked = any(item["status"].startswith("BLOCKED") for item in artifacts)
    return {
        "valid": True,
        "provisioning_status": "BLOCKED_PENDING_IMAGE_AND_AUTHORIZATION" if blocked else "READY_FOR_EXPLICIT_AUTHORIZATION",
        "task_id": TASK_PREFIX,
        "artifacts": artifacts,
        "resources": resources,
        "isolation": isolation,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("--allow-placeholder", action="store_true")
    args = parser.parse_args()
    try:
        payload = json.loads(args.spec.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("spec must be a JSON object")
        result = validate(payload, args.allow_placeholder)
    except RuntimeError as exc:
        print(json.dumps({"valid": False, "blocked": True, "error": str(exc)}, sort_keys=True))
        return 78
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "blocked": False, "error": str(exc)}, sort_keys=True))
        return 64
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
