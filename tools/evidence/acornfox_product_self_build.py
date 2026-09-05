#!/usr/bin/env python3
"""Run the bounded two-root build proof on the existing disposable task VM.

This is an acceptance driver, not an installer or a public release builder.
Toolchains are provisioned and verified before the controlled download phase.
Both compilation phases run without a network namespace interface.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import tarfile
import time


TASK = "acornfox-afb-build-03b-product-p2-20260905"
ROOT = Path("/home/ubuntu/acornfox-product-build")
GO = ROOT / "tools/go/bin/go"
NODE_BIN = ROOT / "tools/node-v22.22.0-linux-x64/bin"
POLICY = Path("/etc/acornfox/acornfox-controlled-egress-policy-v1.json")
TARGETS = {
    "acornfox-server": "open-card-server", "acornfox-agent": "open-card-agent",
    "acornfox-static-server": "open-card-static-server", "acornfox-secretctl": "open-card-secretctl",
    "acornfox-security-probe": "open-card-security-probe", "acornfox-imagegc": "open-card-imagegc",
    "acornfox": "acornfox", "acornfox-admin": "open-card-admin",
    "acornfox-upgrade": "open-card-upgrade", "acornfox-healthcheck": "open-card-healthcheck",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_installed_toolchains(inputs):
    inventory = {}
    for name, filename in [("go", "go.tar.gz"), ("node", "node.tar.xz")]:
        archive_path = ROOT / "tools" / filename
        expected = next(t["sha256"] for t in inputs["toolchains"] if t["name"] == name)
        if digest(archive_path) != expected:
            raise ValueError("toolchain archive digest changed")
        with tarfile.open(archive_path) as archive:
            for member in archive:
                relative = Path(member.name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("invalid toolchain archive path")
                path = ROOT / "tools" / relative
                if member.isfile():
                    wanted = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                    if path.is_symlink() or digest(path) != wanted:
                        raise ValueError("installed toolchain bytes changed")
                    inventory[member.name] = wanted
                elif member.issym():
                    if not path.is_symlink() or os.readlink(path) != member.linkname:
                        raise ValueError("installed toolchain link changed")
    raw = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return {"files": len(inventory), "installed_inventory_sha256": hashlib.sha256(raw).hexdigest()}


def run(args, log, cwd=None, timeout=900):
    started = time.monotonic()
    timed_out = False
    with log.open("w") as output:
        process = subprocess.Popen(args, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    receipt = {"command": args, "exit_code": process.returncode, "timed_out": timed_out, "elapsed_seconds": round(time.monotonic() - started, 3)}
    log.with_suffix(log.suffix + ".json").write_text(json.dumps(receipt, indent=2) + "\n")
    if process.returncode:
        raise RuntimeError(f"{log.name}: exit {process.returncode}")


def main():
    if not __debug__:
        raise SystemExit("optimized Python cannot run an assertion-based acceptance proof")
    if os.geteuid() != 0 or socket.gethostname() != TASK:
        raise SystemExit("this proof is restricted to its disposable task VM")
    inputs = json.loads(Path("/tmp/acornfox-product-build-inputs-v1.json").read_text())
    assert inputs["controlled_egress_policy_sha256"] == "sha256:" + digest(POLICY)
    source = Path("/tmp/product-source.tar")
    assert digest(source) == inputs["transfer_archive_sha256"]
    for name, filename in [("go", "go.tar.gz"), ("node", "node.tar.xz")]:
        expected = next(t["sha256"] for t in inputs["toolchains"] if t["name"] == name)
        assert digest(ROOT / "tools" / filename) == expected
    assert subprocess.check_output([str(GO), "version"], text=True).strip() == "go version go1.25.13 linux/amd64"
    assert subprocess.check_output([str(NODE_BIN / "node"), "--version"], text=True).strip() == "v22.22.0"
    tools_before = verify_installed_toolchains(inputs)
    evidence = ROOT / "proof"
    evidence.mkdir(exist_ok=False)
    user = pwd.getpwnam("ubuntu")
    before_resolv = Path("/etc/resolv.conf").read_bytes()
    try:
        Path("/etc/resolv.conf").write_text("nameserver 1.1.1.1\nnameserver 1.0.0.1\noptions timeout:2 attempts:2\n")
        subprocess.run(["/usr/local/sbin/acornfox-p0-policy", "apply"], check=True)
        results = []
        for letter in ["a", "b"]:
            base = ROOT / ("independent-" + letter)
            base.mkdir(exist_ok=False)
            src = base / "source"
            src.mkdir()
            with tarfile.open(source) as archive:
                archive.extractall(src, filter="data")
            for file in inputs["lock_files"]:
                assert digest(src / file["path"]) == file["sha256"]
            for name in ["home", "go-cache", "go-modules", "npm-cache", "out", "tmp"]:
                (base / name).mkdir()
            for name in ["npm-user-config", "npm-global-config"]:
                (base / name).write_text("")
            subprocess.run(["/usr/bin/chown", "-R", f"{user.pw_uid}:{user.pw_gid}", str(base)], check=True)
            environment = [
                "PATH=" + str(NODE_BIN) + ":" + str(GO.parent) + ":/usr/bin:/bin",
                "HOME=" + str(base / "home"), "TMPDIR=" + str(base / "tmp"),
                "LANG=C", "LC_ALL=C", "TZ=UTC", "GOENV=off", "GOTOOLCHAIN=local",
                "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOMAXPROCS=2",
                "GOCACHE=" + str(base / "go-cache"), "GOMODCACHE=" + str(base / "go-modules"),
                "GOPROXY=https://goproxy.cn", "GOSUMDB=sum.golang.google.cn", "GOFLAGS=-mod=readonly",
                "npm_config_cache=" + str(base / "npm-cache"),
                "npm_config_userconfig=" + str(base / "npm-user-config"),
                "npm_config_globalconfig=" + str(base / "npm-global-config"),
                "npm_config_registry=https://registry.npmjs.org", "npm_config_audit=false",
                "VITE_API_MODE=live", "VITE_API_BASE_URL=/api/v1",
                "SOURCE_DATE_EPOCH=" + str(inputs["source_commit_epoch"]),
            ]
            user_command = ["/usr/sbin/runuser", "-u", "ubuntu", "--", "/usr/bin/env", "-i", *environment]
            run([*user_command, str(GO), "mod", "download", "-json", "all"], evidence / f"{letter}-go-download.log", src)
            run([*user_command, str(NODE_BIN / "npm"), "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=http"], evidence / f"{letter}-npm-download.log", src / "web")
            # Each executable build has a fresh empty network namespace. Neither
            # an ambient proxy nor the online worker can supply a missed input.
            offline = ["/usr/bin/unshare", "--net", *user_command]
            for binary, package in TARGETS.items():
                run([*offline, str(GO), "build", "-p=2", "-trimpath", "-buildvcs=false", "-tags=acornfox", "-ldflags=-s -w -buildid=", "-o", str(base / "out" / binary), "./cmd/" + package], evidence / f"{letter}-{binary}.log", src)
            run([*offline, str(NODE_BIN / "npm"), "run", "build"], evidence / f"{letter}-web-build.log", src / "web")
            run([*offline, str(GO), "mod", "verify"], evidence / f"{letter}-go-verify.log", src)
            for file in inputs["lock_files"]:
                assert digest(src / file["path"]) == file["sha256"]
            hashes = {p.name: digest(p) for p in sorted((base / "out").iterdir())}
            hashes.update({"web/" + str(p.relative_to(src / "web/dist")): digest(p) for p in sorted((src / "web/dist").rglob("*")) if p.is_file()})
            assert len(hashes) > len(TARGETS)
            results.append(hashes)
        assert results[0] == results[1], "independent product build bytes differ"
        tools_after = verify_installed_toolchains(inputs)
        if tools_after != tools_before:
            raise ValueError("toolchain changed during build")
        receipt = {"status": "PASS", "source_commit": inputs["source_commit"], "policy_digest": inputs["controlled_egress_policy_sha256"], "input_lock_sha256": digest(Path("/tmp/acornfox-product-build-inputs-v1.json")), "driver_sha256": digest(Path(__file__)), "tools": {"go": digest(GO), "node": digest(NODE_BIN / "node")}, "roots": 2, "go_binaries_per_root": len(TARGETS), "outputs": results[0], "build_network": "unshare --net (empty)", "release_candidate": False, "host_accepted": False}
        receipt["toolchain_inventory"] = tools_after
        (evidence / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    finally:
        with (evidence / "nft-final.json").open("w") as output:
            subprocess.run(["/usr/sbin/nft", "-j", "list", "table", "inet", "acornfox_p0"], stdout=output)
        subprocess.run(["/usr/sbin/nft", "delete", "table", "inet", "acornfox_p0"], check=False)
        Path("/etc/resolv.conf").write_bytes(before_resolv)


if __name__ == "__main__":
    main()
