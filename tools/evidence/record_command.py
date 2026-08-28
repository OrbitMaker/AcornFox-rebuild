#!/usr/bin/env python3
"""Run one deterministic check and package its output as MVP evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--milestone", required=True)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--evidence-type", action="append", required=True)
    parser.add_argument("--artifacts-root", type=Path, default=Path("artifacts"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")

    evidence_dir = args.artifacts_root / "mvp" / args.milestone / args.test_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    finished = datetime.now(timezone.utc)

    (evidence_dir / "stdout.log").write_text(completed.stdout, encoding="utf-8")
    (evidence_dir / "stderr.log").write_text(completed.stderr, encoding="utf-8")
    write_json(
        evidence_dir / "result.json",
        {
            "test_id": args.test_id,
            "version": 1,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "exit_code": completed.returncode,
            "conclusion": "PASS" if completed.returncode == 0 else "FAIL",
            "failure_reason": None if completed.returncode == 0 else "recorded command returned non-zero",
            "evidence_types": args.evidence_type,
            "duration_seconds": (finished - started).total_seconds(),
        },
    )
    write_json(
        evidence_dir / "inputs.redacted.json",
        {
            "description": args.description,
            "command_name": Path(command[0]).name,
            "argument_count": len(command) - 1,
            "environment_recorded": False,
        },
    )
    write_json(evidence_dir / "objects-before.json", {"evidence_type": "test_precondition", "captured": True})
    write_json(
        evidence_dir / "objects-after.json",
        {
            "evidence_type": "process_exit",
            "exit_code": completed.returncode,
            "stdout_sha256": sha256(evidence_dir / "stdout.log"),
            "stderr_sha256": sha256(evidence_dir / "stderr.log"),
        },
    )
    event = {
        "sequence": 1,
        "actor": "mvp-command-recorder",
        "idempotency_key": f"{args.milestone}:{args.test_id}:1",
        "evidence_refs": ["stdout.log", "stderr.log", "objects-after.json"],
        "evidence_type": "process_exit",
    }
    (evidence_dir / "events.ndjson").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

    manifest_lines = []
    for path in sorted(evidence_dir.iterdir()):
        if path.name == "manifest.sha256" or not path.is_file():
            continue
        manifest_lines.append(f"{sha256(path)}  {path.name}")
    (evidence_dir / "manifest.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    print(str(evidence_dir))
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
