#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import subprocess

DOMAIN = "opencard-mvp-fa8f8eab-build-worker-01"
UUID = "fce4e26d-93b0-5128-a090-969ef73835d4"
HOST_PREFIX = pathlib.Path("/home/ubuntu/opencard-mvp-fa8f8eab")


def virsh(*arguments: str) -> dict[str, object]:
    completed = subprocess.run(["sudo", "-n", "virsh", *arguments], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("guest_path")
    parser.add_argument("host_path", type=pathlib.Path)
    args = parser.parse_args()
    destination = args.host_path.resolve()
    if not destination.is_relative_to(HOST_PREFIX):
        raise SystemExit("host destination escaped the exact task path")
    uuid = subprocess.run(["sudo", "-n", "virsh", "domuuid", DOMAIN], text=True, stdout=subprocess.PIPE, check=True).stdout.strip()
    if uuid != UUID:
        raise SystemExit("clean-worker domain UUID mismatch")
    opened = virsh("qemu-agent-command", DOMAIN, json.dumps({"execute": "guest-file-open", "arguments": {"path": args.guest_path, "mode": "r"}}))
    handle = int(opened["return"])
    temporary = destination.with_name(destination.name + ".part")
    try:
        with temporary.open("wb") as output:
            while True:
                result = virsh("qemu-agent-command", DOMAIN, json.dumps({"execute": "guest-file-read", "arguments": {"handle": handle, "count": 1024 * 1024}}))["return"]
                output.write(base64.b64decode(str(result.get("buf-b64", ""))))
                if result.get("eof"):
                    break
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
        virsh("qemu-agent-command", DOMAIN, json.dumps({"execute": "guest-file-close", "arguments": {"handle": handle}}))
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
