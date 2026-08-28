#!/usr/bin/env python3
"""Normalize task-scoped Docker inspect/stats into the M5 E2E fixture."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


UNITS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
}


def bytes_value(raw: str) -> int:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?i?b)\s*", raw, re.IGNORECASE)
    if not match:
        raise ValueError(f"unsupported Docker byte value: {raw}")
    return round(float(match.group(1)) * UNITS[match.group(2).lower()])


def pair(raw: str) -> tuple[int, int]:
    left, right = raw.split("/", 1)
    return bytes_value(left), bytes_value(right)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def parse_time(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def sample(identity: str, inspect: dict, stats: dict, observed_at: datetime) -> dict:
    memory, memory_limit = pair(stats["MemUsage"])
    network_rx, network_tx = pair(stats["NetIO"])
    cpu_percent = float(stats["CPUPerc"].rstrip("%"))
    health = inspect["State"].get("Health", {}).get("Status")
    host = inspect["HostConfig"]
    return {
        "id": identity,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "healthy": health == "healthy",
        "cpu_millicores": max(0, round(cpu_percent * 10)),
        "memory_bytes": memory,
        "disk_bytes": int(inspect["SizeRw"]),
        "network_rx_bytes": network_rx,
        "network_tx_bytes": network_tx,
        "restart_count": int(inspect["RestartCount"]),
        "limit_cpu_millicores": int(host["NanoCpus"]) // 1_000_000,
        "limit_memory_bytes": int(memory_limit),
        "limit_pids": int(host["PidsLimit"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inspect-before", type=Path, required=True)
    parser.add_argument("--stats-before", type=Path, required=True)
    parser.add_argument("--time-before", required=True)
    parser.add_argument("--inspect-after", type=Path, required=True)
    parser.add_argument("--stats-after", type=Path, required=True)
    parser.add_argument("--time-after", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before_inspect, after_inspect = load(args.inspect_before)[0], load(args.inspect_after)[0]
    before_stats, after_stats = load(args.stats_before), load(args.stats_after)
    container_id = before_inspect["Id"].removeprefix("sha256:")
    if container_id != after_inspect["Id"].removeprefix("sha256:"):
        raise SystemExit("container identity changed during M5 observation")
    mounts = before_inspect.get("Mounts", [])
    result = {
        "task_prefix": "opencard-mvp-fa8f8eab",
        "container_id": container_id,
        "image_digest": before_inspect["Image"],
        "no_host_mounts": not mounts,
        "no_docker_socket": all(item.get("Destination") != "/var/run/docker.sock" for item in mounts),
        "network_mode": before_inspect["HostConfig"]["NetworkMode"],
        "samples": [
            sample("m5-docker-before", before_inspect, before_stats, parse_time(args.time_before)),
            sample("m5-docker-unhealthy", after_inspect, after_stats, parse_time(args.time_after)),
        ],
    }
    if result["samples"][0]["healthy"] is not True or result["samples"][1]["healthy"] is not False:
        raise SystemExit("Docker health transition was not independently observed")
    if result["samples"][1]["network_rx_bytes"] <= result["samples"][0]["network_rx_bytes"]:
        raise SystemExit("Docker network receive counter did not increase")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
