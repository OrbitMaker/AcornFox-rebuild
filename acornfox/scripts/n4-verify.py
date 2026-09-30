#!/usr/bin/env python3
"""Verify one frozen, local source snapshot. Never transfer or publish it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().parents[1]
REPO = MODULE.parent
PLATFORMS = [(os_, arch) for os_ in ("linux", "darwin", "windows")
             for arch in ("amd64", "arm64")]


def snapshot(out):
    files = []
    for source in sorted(MODULE.rglob("*")):
        if not source.is_file() or source.is_symlink():
            continue
        rel = source.relative_to(MODULE)
        if any(p in {".cache", "node_modules", "__pycache__", "prototype", "wheels"}
               for p in rel.parts):
            continue
        if not (source.suffix in {".go", ".mod", ".sum", ".html", ".css", ".js", ".cjs", ".py", ".sh"}
                or source.name in {"Dockerfile", "requirements.txt"}
                or rel.parts[0] in {"testdata", "tests"}):
            continue
        data = source.read_bytes()
        target = out / "source" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files.append({"path": str(rel), "sha256": hashlib.sha256(data).hexdigest()})
    encoded = json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    (out / "source-manifest.json").write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def run(command, cwd, env, log):
    with log.open("wb") as stream:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description="对本地源码快照进行六平台编译或真实当前平台测试")
    parser.add_argument("mode", choices=("compile", "tests", "all"))
    args = parser.parse_args()
    cache = REPO / ".cache"
    cache.mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="n4-" + args.mode + "-", dir=cache))
    manifest = snapshot(out)
    env = os.environ.copy()
    report = {"created_at": datetime.now(timezone.utc).isoformat(),
              "host_os": platform.system(), "host_arch": platform.machine(),
              "source_manifest_sha256": manifest, "results": []}
    version = subprocess.run(["go", "version"], capture_output=True, text=True, check=True)
    report["go_version"] = version.stdout.strip()
    success = True
    if args.mode in ("compile", "all"):
        binaries = out / "binaries"
        binaries.mkdir()
        for os_, arch in PLATFORMS:
            suffix = ".exe" if os_ == "windows" else ""
            binary = binaries / ("acornfox-" + os_ + "-" + arch + suffix)
            target_env = dict(env, GOOS=os_, GOARCH=arch, CGO_ENABLED="0")
            code = run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/acornfox"],
                       out / "source", target_env, out / (os_ + "-" + arch + ".log"))
            entry = {"os": os_, "arch": arch, "exit_code": code,
                     "cross_compile": "pass" if code == 0 else "fail",
                     "native_execution": "not_run"}
            if code == 0:
                entry["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
                entry["bytes"] = binary.stat().st_size
                entry["file_format"] = subprocess.run(["file", "-b", str(binary)],
                    capture_output=True, text=True, check=True).stdout.strip()
            report["results"].append(entry)
            success = success and code == 0
            print(os_ + "/" + arch + ": " + entry["cross_compile"], flush=True)
        report["boundary"] = "交叉编译不代表目标平台实际运行；Linux全量测试与Docker实测另行执行。"
    if args.mode in ("tests", "all"):
        for name, command in (
            ("build", ["go", "build", "./..."]),
            ("vet", ["go", "vet", "./..."]),
            ("race_tests", ["go", "test", "-json", "-race", "-count=1", "-p", "2", "./..."]),
        ):
            test_env = dict(env, TMPDIR="/tmp")
            log = out / (name + ".log")
            code = run(command, out / "source", test_env, log)
            entry = {"check": name, "exit_code": code, "status": "pass" if code == 0 else "fail"}
            if name == "race_tests":
                actions = []
                for line in log.read_text(errors="replace").splitlines():
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if event.get("Action") in ("skip", "fail"):
                        actions.append({k: event[k] for k in ("Action", "Package", "Test") if k in event})
                entry["skips_and_failures"] = actions
            report["results"].append(entry)
            success = success and code == 0
            print(name + ": " + entry["status"], flush=True)
        report["boundary"] = "结果仅对应当前平台；带skip的Docker测试不算实测通过，macOS的runner凭据测试不能冒充Linux验收。"
    report["overall"] = "pass" if success else "fail"
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print("本地证据目录：" + str(out), flush=True)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
