#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import stat
import subprocess

DOMAIN = "opencard-mvp-fa8f8eab-build-worker-01"
UUID = "fce4e26d-93b0-5128-a090-969ef73835d4"
HOST_PREFIX = pathlib.Path("/home/ubuntu/opencard-mvp-fa8f8eab")
GUEST_PREFIX = pathlib.PurePosixPath("/var/lib/opencard-mvp-fa8f8eab/incoming")


def virsh(payload: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        ["sudo", "-n", "virsh", "qemu-agent-command", DOMAIN, json.dumps(payload, separators=(",", ":"))],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host_path", type=pathlib.Path)
    parser.add_argument("guest_path")
    args = parser.parse_args()
    source = args.host_path.resolve()
    info = source.lstat()
    if not source.is_relative_to(HOST_PREFIX) or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit("host source must be a regular task-scoped file")
    destination = pathlib.PurePosixPath(args.guest_path)
    if not destination.is_relative_to(GUEST_PREFIX) or destination == GUEST_PREFIX:
        raise SystemExit("guest destination escaped the task incoming directory")
    uuid = subprocess.run(["sudo", "-n", "virsh", "domuuid", DOMAIN], text=True, stdout=subprocess.PIPE, check=True).stdout.strip()
    if uuid != UUID:
        raise SystemExit("clean-worker domain UUID mismatch")
    opened = virsh({"execute": "guest-file-open", "arguments": {"path": str(destination), "mode": "w"}})
    handle = int(opened["return"])
    try:
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(32 * 1024), b""):
                virsh({"execute": "guest-file-write", "arguments": {"handle": handle, "buf-b64": base64.b64encode(chunk).decode("ascii")}})
        virsh({"execute": "guest-file-flush", "arguments": {"handle": handle}})
    finally:
        virsh({"execute": "guest-file-close", "arguments": {"handle": handle}})
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
