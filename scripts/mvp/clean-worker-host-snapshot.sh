#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import subprocess
from typing import Any

TASK = "opencard-mvp-fa8f8eab"
DOMAIN = f"{TASK}-build-worker-01"
POOL = f"{TASK}-build-workers"
NETWORK = f"{TASK}-build-isolated"
VOLUME = f"{TASK}-build-worker-01.qcow2"


def run(arguments: list[str], *, check: bool = True) -> str:
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and result.returncode != 0:
        raise SystemExit(f"command failed: {arguments!r}: {result.stderr.strip()}")
    return result.stdout.strip()


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def virsh(*arguments: str, check: bool = True) -> str:
    return run(["sudo", "-n", "virsh", *arguments], check=check)


def names(kind: str) -> list[str]:
    command = {"domain": ("list", "--all", "--name"), "network": ("net-list", "--all", "--name"), "pool": ("pool-list", "--all", "--name")}[kind]
    return sorted(item.strip() for item in virsh(*command).splitlines() if item.strip() and not item.strip().startswith(TASK))


domains: list[dict[str, str]] = []
for name in names("domain"):
    domains.append({
        "name": name,
        "uuid": virsh("domuuid", name),
        "state": virsh("domstate", name),
        "autostart": virsh("dominfo", name).split("Autostart:", 1)[1].splitlines()[0].strip(),
        "inactive_xml_sha256": hashlib.sha256(virsh("dumpxml", "--inactive", name).encode()).hexdigest(),
    })

networks: list[dict[str, str]] = []
for name in names("network"):
    info = virsh("net-info", name)
    networks.append({"name": name, "info_sha256": hashlib.sha256(info.encode()).hexdigest(), "xml_sha256": hashlib.sha256(virsh("net-dumpxml", name).encode()).hexdigest()})

pools: list[dict[str, str]] = []
for name in names("pool"):
    info = virsh("pool-info", name)
    pools.append({"name": name, "info_sha256": hashlib.sha256(info.encode()).hexdigest(), "xml_sha256": hashlib.sha256(virsh("pool-dumpxml", name).encode()).hexdigest()})

container_ids = [item for item in run(["docker", "ps", "-aq"]).splitlines() if item]
containers: list[dict[str, Any]] = []
if container_ids:
    for item in json.loads(run(["docker", "inspect", *container_ids])):
        name = item.get("Name", "").lstrip("/")
        labels = (item.get("Config") or {}).get("Labels") or {}
        if name.startswith(TASK) or labels.get("open-card.task") == TASK:
            continue
        host = item.get("HostConfig") or {}
        state = item.get("State") or {}
        containers.append({
            "id": item.get("Id"),
            "name": name,
            "image_id": item.get("Image"),
            "image_ref": (item.get("Config") or {}).get("Image"),
            "status": state.get("Status"),
            "restart_policy": (host.get("RestartPolicy") or {}).get("Name"),
            "network_mode": host.get("NetworkMode"),
            "mounts": sorted((mount.get("Type"), mount.get("Name"), mount.get("Source"), mount.get("Destination")) for mount in item.get("Mounts") or []),
        })
containers.sort(key=lambda item: (item["name"], item["id"] or ""))

services = {name: run(["systemctl", "is-active", name], check=False) for name in ("docker", "containerd", "frpc", "libvirtd")}
task_resources = {
    "domain": bool(virsh("dominfo", DOMAIN, check=False)),
    "pool": bool(virsh("pool-info", POOL, check=False)),
    "network": bool(virsh("net-info", NETWORK, check=False)),
    "volume": bool(virsh("vol-info", "--pool", POOL, VOLUME, check=False)),
}
snapshot = {
    "schema_version": 1,
    "task_id": TASK,
    "apparmor_restrict_unprivileged_userns": run(["cat", "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"]),
    "default_route": run(["ip", "route", "show", "default"]),
    "services": services,
    "non_task_containers_sha256": digest(containers),
    "non_task_containers_count": len(containers),
    "non_task_domains_sha256": digest(domains),
    "non_task_domains": [item["name"] for item in domains],
    "non_task_networks_sha256": digest(networks),
    "non_task_networks": [item["name"] for item in networks],
    "non_task_pools_sha256": digest(pools),
    "non_task_pools": [item["name"] for item in pools],
    "task_resources": task_resources,
}
print(json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True))
PY
