#!/usr/bin/env python3
"""Create deterministic Gate5 source-and-artifact security scan evidence."""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


ARCHES = ("amd64", "arm64")
RELEASE_VERSIONS = {"0.8.0-rc.1", "0.8.0-rc.2", "0.8.0-rc.3"}
GOVULNCHECK_VERSION = "v1.7.0"
POLICY = {
    "content_patterns": ("pem_private_key", "tencent_akid", "aws_akia", "github_token", "openai_token"),
    "sensitive_filenames": (".env", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa"),
    "fixture_paths": ("test", "tests", "testdata", "fixtures"),
}
PATTERNS = {
    "pem_private_key": re.compile(rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    "tencent_akid": re.compile(rb"AKID[A-Za-z0-9]{16,}"),
    "aws_akia": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "openai_token": re.compile(rb"sk-[A-Za-z0-9]{32,}"),
}
HEX_40 = re.compile(r"^[a-f0-9]{40}$")


class SecurityScanError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path, label: str, executable: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise SecurityScanError(f"{label} is missing") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or (executable and not info.st_mode & 0o111):
        raise SecurityScanError(f"{label} must be a regular{' executable' if executable else ''} non-symlink file")


def directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise SecurityScanError(f"{label} is missing") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SecurityScanError(f"{label} must be a real directory")


def strict_json_bytes(raw: bytes, label: str) -> dict[str, object]:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise SecurityScanError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise SecurityScanError(f"{label} must be a JSON object")
    return value


def safe_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise SecurityScanError("unsafe scanned path")
    return path


def fixture_path(path: PurePosixPath) -> bool:
    return any(part.lower() in POLICY["fixture_paths"] for part in path.parts) or path.name.endswith("_test.go")


def sensitive_filename(path: PurePosixPath) -> bool:
    name = path.name.lower()
    return (
        (name == ".env" or (name.startswith(".env.") and not name.endswith(".example")))
        or name.endswith((".pem", ".key", ".p12", ".pfx"))
        or name == "id_rsa"
    )


def scan_bytes(data: bytes, path: PurePosixPath, *, allow_fixture: bool) -> tuple[int, int]:
    matches = sum(len(pattern.findall(data)) for pattern in PATTERNS.values())
    matches += int(sensitive_filename(path))
    if not matches:
        return 0, 0
    if allow_fixture and fixture_path(path):
        return 0, matches
    return matches, 0


def tree_digest(root: Path) -> str:
    directory(root, "scan root")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise SecurityScanError("scan root contains an unsafe entry")
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(sha256(path).encode())
    return digest.hexdigest()


def tracked_tree_digest(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(sha256(path).encode())
    return digest.hexdigest()


def verify_source(source: Path, commit: str) -> tuple[list[Path], str]:
    directory(source, "source worktree")
    try:
        head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        detached = subprocess.run(["git", "-C", str(source), "symbolic-ref", "-q", "HEAD"], text=True, capture_output=True).returncode == 1
        dirty = subprocess.run(["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"], check=True, text=True, capture_output=True).stdout
        names = subprocess.run(["git", "-C", str(source), "ls-files", "-z"], check=True, capture_output=True).stdout.decode("utf-8", "surrogateescape").split("\0")
    except subprocess.CalledProcessError as error:
        raise SecurityScanError("source Git verification failed") from error
    if head != commit or not detached or dirty:
        raise SecurityScanError("source worktree is not clean, detached, and fixed at requested commit")
    paths = []
    for name in names:
        if not name:
            continue
        relative = safe_name(name)
        path = source.joinpath(*relative.parts)
        regular(path, "tracked source file")
        paths.append(path)
    return paths, tracked_tree_digest(source, paths)


def parse_concatenated_json(raw: bytes) -> list[dict[str, object]]:
    decoder = json.JSONDecoder(object_pairs_hook=lambda pairs: _no_duplicates(pairs))
    text = raw.decode("utf-8")
    documents = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except (ValueError, json.JSONDecodeError) as error:
            raise SecurityScanError("govulncheck output is malformed JSON") from error
        if not isinstance(value, dict):
            raise SecurityScanError("govulncheck output document must be an object")
        documents.append(value)
    if not documents:
        raise SecurityScanError("govulncheck output is empty")
    return documents


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def parse_rfc3339(value: str, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SecurityScanError(f"{label} is not RFC3339") from error
    if parsed.tzinfo is None:
        raise SecurityScanError(f"{label} is not RFC3339")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_govuln_version_time(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S %z UTC")
    except ValueError as error:
        raise SecurityScanError("govulncheck DB updated is invalid") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SecurityScanError("govulncheck DB updated is not UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def go_metadata(binary: Path) -> tuple[dict[str, str], dict[str, str]]:
    regular(binary, "Go binary", executable=True)
    env = {"PATH": f"{binary.parent}:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "GOWORK": "off", "HOME": tempfile.gettempdir()}
    try:
        version = subprocess.run([str(binary), "version"], check=True, text=True, capture_output=True, env=env).stdout.strip()
        goroot = subprocess.run([str(binary), "env", "GOROOT"], check=True, text=True, capture_output=True, env=env).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise SecurityScanError("Go binary execution failed") from error
    match = re.fullmatch(r"go version (go[^ ]+) ([^/ ]+)/(amd64|arm64|[A-Za-z0-9_]+)", version)
    if not match or not goroot.startswith("/"):
        raise SecurityScanError("Go binary version metadata is invalid")
    metadata = {"binary_sha256": sha256(binary), "version": match.group(1), "platform": f"{match.group(2)}/{match.group(3)}"}
    return metadata, {**env, "GOROOT": goroot}


def govuln_metadata(binary: Path, go_binary: Path, source: Path) -> dict[str, object]:
    regular(binary, "govulncheck binary", executable=True)
    go, env = go_metadata(go_binary)
    try:
        version = subprocess.run([str(binary), "-version"], check=True, text=True, capture_output=True, env=env).stdout
        run = subprocess.run([str(binary), "-json", "./..."], cwd=source, text=False, capture_output=True, env=env)
    except subprocess.CalledProcessError as error:
        raise SecurityScanError("govulncheck version execution failed") from error
    lines = version.strip().splitlines()
    if len(lines) != 4:
        raise SecurityScanError("govulncheck version metadata is invalid")
    go_match = re.fullmatch(r"Go: (go[^ ]+)", lines[0])
    scanner_match = re.fullmatch(r"Scanner: (govulncheck@v[^ ]+)", lines[1])
    db_match = re.fullmatch(r"DB: (https://[^ ]+)", lines[2])
    updated_match = re.fullmatch(r"DB updated: (.+)", lines[3])
    if not go_match or not scanner_match or not db_match or not updated_match:
        raise SecurityScanError("govulncheck version metadata is invalid")
    scanner_version = scanner_match.group(1).removeprefix("govulncheck@")
    db_updated = parse_govuln_version_time(updated_match.group(1))
    if run.returncode != 0:
        raise SecurityScanError("govulncheck scan exited nonzero")
    docs = parse_concatenated_json(run.stdout)
    configs = [doc["config"] for doc in docs if set(doc) == {"config"} and isinstance(doc["config"], dict)]
    if len(configs) != 1:
        raise SecurityScanError("govulncheck output must contain exactly one config document")
    config = configs[0]
    expected_config_keys = {"protocol_version", "scanner_name", "scanner_version", "db", "db_last_modified", "go_version", "scan_mode", "scan_level"}
    if set(config) != expected_config_keys or any(not isinstance(config[key], str) or not config[key] for key in expected_config_keys):
        raise SecurityScanError("govulncheck config metadata is invalid")
    if (
        scanner_version != GOVULNCHECK_VERSION
        or
        config["protocol_version"] != "v1.0.0"
        or config["scanner_name"] != "govulncheck"
        or config["scan_mode"] != "source"
        or config["scan_level"] != "symbol"
        or config["scanner_version"] != scanner_version
        or config["go_version"] != go_match.group(1)
        or config["db"] != db_match.group(1)
        or parse_rfc3339(config["db_last_modified"], "govulncheck config DB updated") != db_updated
    ):
        raise SecurityScanError("govulncheck config does not match version metadata")
    findings = sum(1 for doc in docs if "finding" in doc)
    if findings:
        raise SecurityScanError("govulncheck reported findings")
    return {
        "binary_sha256": sha256(binary),
        "scanner_name": config["scanner_name"],
        "scanner_version": config["scanner_version"],
        "go_version": config["go_version"],
        "db": config["db"],
        "db_last_modified": db_updated,
        "scan_mode": config["scan_mode"],
        "scan_level": config["scan_level"],
        "raw_output_sha256": sha256_bytes(run.stdout),
        "document_count": len(docs),
        "finding_count": 0,
        "go_binary": go,
    }


def scan_directory(root: Path, *, allow_fixture: bool) -> tuple[int, int, str]:
    blocking = allowed = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise SecurityScanError("scan directory contains an unsafe entry")
        if path.is_file():
            found, canary = scan_bytes(path.read_bytes(), PurePosixPath(path.relative_to(root).as_posix()), allow_fixture=allow_fixture)
            blocking += found
            allowed += canary
    return blocking, allowed, tree_digest(root)


def scan_archives(candidate_set: Path) -> tuple[int, int]:
    blocking = allowed = 0
    for arch in ARCHES:
        archives = list((candidate_set / arch).glob("*.tar.gz"))
        if len(archives) != 1:
            raise SecurityScanError("candidate architecture must contain exactly one archive")
        try:
            with tarfile.open(archives[0], "r:gz") as archive:
                for member in archive.getmembers():
                    name = safe_name(member.name)
                    if not member.isfile():
                        raise SecurityScanError("candidate archive contains a non-regular member")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise SecurityScanError("candidate archive member cannot be read")
                    with stream:
                        found, canary = scan_bytes(stream.read(), name, allow_fixture=False)
                    blocking += found
                    allowed += canary
        except tarfile.TarError as error:
            raise SecurityScanError("candidate archive is invalid") from error
    return blocking, allowed


def verify_version_bindings(candidate_set: Path, certification: Path, version: str) -> None:
    index = strict_json_bytes((certification / "release-index.json").read_bytes(), "release index")
    certificate = strict_json_bytes((certification / "certification.json").read_bytes(), "certification")
    if index.get("version") != version or index.get("schema") != "open-card-release-index.v1":
        raise SecurityScanError("release index version is inconsistent")
    if version != "0.8.0-rc.1" and certificate.get("version") != version:
        raise SecurityScanError("certification version is inconsistent")
    for arch in ARCHES:
        root = candidate_set / arch
        for relative, label in (("build-record.json", "build record"), ("release/manifest.json", "release manifest"), ("production-bundle.json", "production bundle")):
            path = root / relative
            regular(path, label)
            value = strict_json_bytes(path.read_bytes(), label)
            if relative == "build-record.json":
                version_value = value.get("candidate", {}).get("version") if isinstance(value.get("candidate"), dict) else None
            else:
                version_value = value.get("version")
            if version_value != version:
                raise SecurityScanError("candidate version is inconsistent")


def publish_no_replace(candidate: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if candidate.parent.resolve() != output.parent.resolve():
        raise SecurityScanError("scan candidate and output must share a parent")
    if sys.platform == "darwin":
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise SecurityScanError("atomic no-replace publication is unavailable")
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(candidate), os.fsencode(output), 0x00000004)
    elif sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise SecurityScanError("atomic no-replace publication is unavailable")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(candidate), -100, os.fsencode(output), 0x00000001)
    else:
        raise SecurityScanError("atomic no-replace publication is unavailable")
    if result == 0:
        return
    if ctypes.get_errno() == errno.EEXIST:
        raise SecurityScanError("refusing to overwrite security scan output")
    raise SecurityScanError("atomic no-replace security scan publication failed")


def scan(source: Path, source_commit: str, candidate_set: Path, certification: Path, govulncheck: Path, go_binary: Path, output: Path, version: str = "0.8.0-rc.1") -> dict[str, object]:
    if not HEX_40.fullmatch(source_commit):
        raise SecurityScanError("source commit must be lowercase hexadecimal")
    if version not in RELEASE_VERSIONS:
        raise SecurityScanError("release version is unsupported")
    if output.exists():
        raise SecurityScanError("refusing to overwrite security scan output")
    directory(output.parent, "security scan output parent")
    source_files, source_digest = verify_source(source, source_commit)
    directory(candidate_set, "candidate set")
    if {entry.name for entry in candidate_set.iterdir()} != set(ARCHES):
        raise SecurityScanError("candidate set must contain exactly amd64 and arm64")
    directory(certification, "certification root")
    if {entry.name for entry in certification.iterdir()} != {"certification.json", "release-index.json"}:
        raise SecurityScanError("certification root does not contain exactly the required evidence")
    for path in certification.iterdir():
        regular(path, "certification evidence")
    verify_version_bindings(candidate_set, certification, version)
    source_blocking = source_allowed = 0
    for path in source_files:
        found, canary = scan_bytes(path.read_bytes(), PurePosixPath(path.relative_to(source).as_posix()), allow_fixture=True)
        source_blocking += found
        source_allowed += canary
    candidate_blocking, candidate_allowed, candidate_digest = scan_directory(candidate_set, allow_fixture=False)
    archive_blocking, archive_allowed = scan_archives(candidate_set)
    cert_blocking, cert_allowed, certification_digest = scan_directory(certification, allow_fixture=False)
    blocking = source_blocking + candidate_blocking + archive_blocking + cert_blocking
    allowed = source_allowed + candidate_allowed + archive_allowed + cert_allowed
    if blocking:
        raise SecurityScanError("secret scan reported blocking matches")
    govuln = govuln_metadata(govulncheck, go_binary, source)
    report = {
        "schema": "open-card-production-security-scan.v1",
        "scope": "gate5_source_and_artifacts",
        "production_accepted": False,
        "version": version,
        "source_commit": source_commit,
        "policy_sha256": sha256_bytes(canonical_json(POLICY)),
        "govulncheck": govuln,
        "scope_digests": {"source_tree": source_digest, "candidate_tree": candidate_digest, "certification_tree": certification_digest},
        "secret_scan": {"blocking_count": 0, "allowed_fixture_canary_count": allowed},
    }
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.scan-", dir=output.parent))
    try:
        (temporary / "security-scan.json").write_bytes(canonical_json(report))
        (temporary / "security-scan.json").chmod(0o644)
        temporary.chmod(0o750)
        publish_no_replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-worktree", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--candidate-set", required=True, type=Path)
    parser.add_argument("--certification-root", required=True, type=Path)
    parser.add_argument("--govulncheck", required=True, type=Path)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--version", default="0.8.0-rc.1", choices=sorted(RELEASE_VERSIONS))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = scan(args.source_worktree, args.source_commit, args.candidate_set, args.certification_root, args.govulncheck, args.go, args.output, args.version)
    except SecurityScanError as error:
        print(f"production security scan: {error}")
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
