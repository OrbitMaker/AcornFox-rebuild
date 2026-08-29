#!/usr/bin/env python3
"""Build the locally verified 0.8.0-rc.0 amd64 candidate from fixed inputs.

This driver deliberately has no download path. A caller supplies a clean,
detached source worktree and a local runtime-input directory; every runtime
asset is selected by the checked-in runtime-input manifest and matched by
filename plus SHA-256 before it is read. The only accepted RC0 source commit is
the frozen installable bootstrap baseline.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NamedTuple


VERSION = "0.8.0-rc.0"
MIGRATION_VERSION = "0023"
ARCHITECTURE = "amd64"
RC0_SOURCE_COMMIT = "35a2b198ac52949af3477475d89d4813b46a9490"
N_MINUS_ONE_RELEASE_MANIFEST_SHA256 = "3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253"
N_MINUS_ONE_ARCHIVE_SHA256 = "abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc"
N_MINUS_ONE_BUNDLE_MANIFEST_SHA256 = "960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392"
N_MINUS_ONE_DECLARED_FILE_COUNT = 62


@dataclass(frozen=True)
class NMinusOneEvidence:
    candidate_root: Path
    release_path: Path
    version: str
    migration: str
    source_commit: str
    release_manifest_sha256: str
    archive_sha256: str
    bundle_manifest_sha256: str


class ReleaseSpec(NamedTuple):
    version: str
    migration: str
    bootstrap: bool
RC0_SPEC = ReleaseSpec("0.8.0-rc.0", "0023", True)
RC1_SPEC = ReleaseSpec("0.8.0-rc.1", "0024", False)
def release_spec(version: str) -> ReleaseSpec:
    if version == RC0_SPEC.version: return RC0_SPEC
    if version == RC1_SPEC.version: return RC1_SPEC
    raise ProductionBuildError("unsupported release specification")
GATE3_STATUS = "pass_limited_external_linux_required"
LIVE_METADATA = {
    "mode": "live",
    "apiBaseUrl": "/api/v1",
    "schemaVersion": "open-card-build-attestation.v1",
}
GO_TARGETS = {
    "open-card-server": "./cmd/open-card-server",
    "open-card-agent": "./cmd/open-card-agent",
    "open-card-static-server": "./cmd/open-card-static-server",
    "open-card-secretctl": "./cmd/open-card-secretctl",
    "open-card-security-probe": "./cmd/open-card-security-probe",
    "open-card-imagegc": "./cmd/open-card-imagegc",
    "open-card-admin": "./cmd/open-card-admin",
}
RUNTIME_LAYOUT = {
    "buildkit": {
        "archive": True,
        "members": {
            "bin/buildkitd": "buildkitd",
            "bin/buildctl": "buildctl",
            "bin/buildkit-runc": "buildkit-runc",
        },
    },
    "rootlesskit": {
        "archive": True,
        "members": {"rootlesskit": "rootlesskit"},
    },
    "buildx": {
        "archive": False,
        "members": {"docker-buildx": "docker-buildx"},
    },
    "caddy": {
        "archive": True,
        "members": {"caddy": "caddy"},
    },
}
RUNTIME_VERSIONS = {
    "buildkit": "0.32.2",
    "rootlesskit": "3.1.0",
    "buildx": "0.36.1",
    "caddy": "2.11.4",
}
RUNTIME_ASSETS = {
    "buildkit": {
        "amd64": {
            "url": "https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-amd64.tar.gz",
            "filename": "buildkit.tar.gz",
        },
        "arm64": {
            "url": "https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-arm64.tar.gz",
            "filename": "buildkit.tar.gz",
        },
    },
    "rootlesskit": {
        "amd64": {
            "url": "https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-x86_64.tar.gz",
            "filename": "rootlesskit.tar.gz",
        },
        "arm64": {
            "url": "https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-aarch64.tar.gz",
            "filename": "rootlesskit.tar.gz",
        },
    },
    "buildx": {
        "amd64": {
            "url": "https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-amd64",
            "filename": "docker-buildx",
        },
        "arm64": {
            "url": "https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-arm64",
            "filename": "docker-buildx",
        },
    },
    "caddy": {
        "amd64": {
            "url": "https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz",
            "filename": "caddy.tar.gz",
        },
        "arm64": {
            "url": "https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_arm64.tar.gz",
            "filename": "caddy.tar.gz",
        },
    },
}
TEST_PATH_PARTS = frozenset({"test", "tests", "testdata", "fixtures", "__tests__"})


class ProductionBuildError(RuntimeError):
    pass


class RuntimeInput:
    __slots__ = ("path", "filename", "digest")

    def __init__(self, path: Path, filename: str, digest: str) -> None:
        self.path = path
        self.filename = filename
        self.digest = digest


def lowercase_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ProductionBuildError(f"{label} is missing: {path}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProductionBuildError(f"{label} must be a regular non-symlink file: {path}")


def directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ProductionBuildError(f"{label} is missing: {path}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProductionBuildError(f"{label} must be a real directory: {path}")


def safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts:
        raise ProductionBuildError(f"archive member path is unsafe: {name!r}")
    return path


def test_only_payload(relative: PurePosixPath) -> bool:
    normalized = relative.as_posix().lower()
    name = relative.name.lower()
    return (
        any(part.lower() in TEST_PATH_PARTS for part in relative.parts)
        or "fixture" in normalized
        or name.endswith(".test")
        or ".test." in name
        or name.endswith(".spec")
        or ".spec." in name
    )


def copy_regular(source: Path, target: Path, mode: int) -> None:
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProductionBuildError(f"input cannot be opened safely: {source}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ProductionBuildError(f"input is not a regular file: {source}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(descriptor, "rb", closefd=False) as input_stream, target.open(
            "xb"
        ) as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
    except FileExistsError as error:
        raise ProductionBuildError(f"refusing to overwrite staged file: {target}") from error
    finally:
        os.close(descriptor)
    target.chmod(mode)


def snapshot_pinned_file(
    path: Path,
    expected_sha256: str,
    target: Path,
    label: str,
    mode: int,
) -> str:
    if not lowercase_hex(expected_sha256, 64):
        raise ProductionBuildError(f"{label} SHA-256 must be lowercase hexadecimal")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProductionBuildError(f"{label} cannot be opened safely") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ProductionBuildError(f"{label} must be a regular non-symlink file")
        digest = hashlib.sha256()
        target.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(descriptor, "rb", closefd=False) as input_stream, target.open(
            "xb"
        ) as output_stream:
            for block in iter(lambda: input_stream.read(1 << 20), b""):
                digest.update(block)
                output_stream.write(block)
    except FileExistsError as error:
        raise ProductionBuildError(f"refusing to overwrite private {label} snapshot") from error
    finally:
        os.close(descriptor)
    target.chmod(mode)
    actual = digest.hexdigest()
    if actual != expected_sha256:
        target.unlink(missing_ok=True)
        raise ProductionBuildError(f"{label} does not match the pinned SHA-256")
    return actual


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_runtime_inputs(
    manifest_path: Path,
    runtime_dir: Path,
    arch: str,
) -> dict[str, RuntimeInput]:
    regular(manifest_path, "runtime-input manifest snapshot")
    directory(runtime_dir, "runtime-input directory")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBuildError("runtime-input manifest is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {"schema_version", "runtime_inputs"}:
        raise ProductionBuildError("runtime-input manifest schema is invalid")
    if document["schema_version"] != 1 or not isinstance(document["runtime_inputs"], dict):
        raise ProductionBuildError("runtime-input manifest version is invalid")
    records = document["runtime_inputs"]
    if set(records) != set(RUNTIME_LAYOUT) or set(records) != set(RUNTIME_VERSIONS):
        raise ProductionBuildError("runtime-input manifest must declare exactly the required tools")

    selected: dict[str, RuntimeInput] = {}
    seen_names: set[str] = set()
    for tool in sorted(RUNTIME_LAYOUT):
        record = records[tool]
        expected_contract = RUNTIME_ASSETS[tool]
        if (
            not isinstance(record, dict)
            or set(record) != {"version", "architectures"}
            or record["version"] != RUNTIME_VERSIONS[tool]
        ):
            raise ProductionBuildError(f"runtime-input record is invalid: {tool}")
        architectures = record["architectures"]
        if not isinstance(architectures, dict) or set(architectures) != set(expected_contract):
            raise ProductionBuildError(f"runtime-input architectures are invalid: {tool}")
        for contract_arch, expected_asset in expected_contract.items():
            candidate = architectures[contract_arch]
            if (
                not isinstance(candidate, dict)
                or set(candidate) != {"url", "filename", "sha256"}
                or candidate["url"] != expected_asset["url"]
                or candidate["filename"] != expected_asset["filename"]
                or not lowercase_hex(candidate["sha256"], 64)
            ):
                raise ProductionBuildError(f"runtime-input asset contract is invalid: {tool}/{contract_arch}")
        if arch not in architectures:
            raise ProductionBuildError(f"runtime-input architecture is unavailable: {tool}/{arch}")
        asset = architectures[arch]
        filename = asset["filename"]
        expected = asset["sha256"]
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or not lowercase_hex(expected, 64)
        ):
            raise ProductionBuildError(f"runtime-input asset name or digest is invalid: {tool}")
        if filename in seen_names:
            raise ProductionBuildError("runtime-input manifest reuses a filename")
        seen_names.add(filename)
        source = runtime_dir / filename
        regular(source, f"runtime input {tool}")
        if sha256(source) != expected:
            raise ProductionBuildError(f"runtime input digest mismatch: {tool}")
        selected[tool] = RuntimeInput(source, filename, expected)
    return selected


def extract_runtime_archive(archive: Path, target: Path, members: dict[str, str]) -> None:
    regular(archive, "runtime archive")
    extracted: set[str] = set()
    seen_paths: set[str] = set()
    try:
        with tarfile.open(archive, "r:gz") as source:
            entries = source.getmembers()
            if len(entries) > 10_000 or sum(max(entry.size, 0) for entry in entries) > 2 * 1024**3:
                raise ProductionBuildError("runtime archive exceeds safe entry or size limits")
            for entry in entries:
                relative = safe_relative(entry.name)
                normalized = relative.as_posix()
                if normalized in seen_paths:
                    raise ProductionBuildError("runtime archive contains duplicate paths")
                seen_paths.add(normalized)
                if not (entry.isdir() or entry.isreg()):
                    raise ProductionBuildError("runtime archive contains a non-regular entry")
                if not entry.isreg() or normalized not in members:
                    continue
                if normalized in extracted:
                    raise ProductionBuildError("runtime archive duplicates a required executable")
                stream = source.extractfile(entry)
                if stream is None:
                    raise ProductionBuildError("runtime archive cannot read a required executable")
                destination = target / members[normalized]
                destination.parent.mkdir(parents=True, exist_ok=True)
                with stream, destination.open("xb") as output_stream:
                    shutil.copyfileobj(stream, output_stream)
                destination.chmod(0o755)
                extracted.add(normalized)
    except tarfile.TarError as error:
        raise ProductionBuildError("runtime archive is invalid") from error
    if extracted != set(members):
        missing = sorted(set(members) - extracted)
        raise ProductionBuildError(f"runtime archive is missing required executables: {missing}")


def snapshot_runtime_inputs(
    selected: dict[str, RuntimeInput],
    target: Path,
) -> dict[str, RuntimeInput]:
    snapshots: dict[str, RuntimeInput] = {}
    for tool, asset in selected.items():
        destination = target / asset.filename
        snapshot_pinned_file(
            asset.path,
            asset.digest,
            destination,
            f"runtime input {tool}",
            0o600,
        )
        snapshots[tool] = RuntimeInput(destination, asset.filename, asset.digest)
    return snapshots


def stage_runtime_inputs(selected: dict[str, RuntimeInput], stage: Path) -> None:
    runtime = stage / "runtime" / ARCHITECTURE
    for tool, layout in RUNTIME_LAYOUT.items():
        if layout["archive"]:
            extract_runtime_archive(selected[tool].path, runtime, layout["members"])
        else:
            source_name, destination_name = next(iter(layout["members"].items()))
            if source_name != selected[tool].filename:
                raise ProductionBuildError("direct runtime input filename does not match its manifest")
            copy_regular(selected[tool].path, runtime / destination_name, 0o755)


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    records: list[list[str]],
) -> str:
    records.append(command)
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ProductionBuildError(f"command failed: {' '.join(command)}\n{detail[-4000:]}")
    return result.stdout


def isolated_build_environments(root: Path) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    home = root / "home"
    go_cache = root / "go-cache"
    go_mod_cache = root / "go-mod-cache"
    npm_cache = root / "npm-cache"
    npm_user_config = root / "npm-userrc"
    npm_global_config = root / "npm-globalrc"
    for directory_path in (home, go_cache, go_mod_cache, npm_cache):
        directory_path.mkdir(mode=0o700)
    for config in (npm_user_config, npm_global_config):
        config.write_text("audit=false\nfund=false\n", encoding="utf-8")
        config.chmod(0o600)
    base = {
        "HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PATH": os.environ.get("PATH", ""),
        "TMPDIR": str(root),
    }
    go_env = {
        **base,
        "CGO_ENABLED": "0",
        "GOARCH": ARCHITECTURE,
        "GOCACHE": str(go_cache),
        "GOENV": "off",
        "GOFLAGS": "",
        "GOMODCACHE": str(go_mod_cache),
        "GONOSUMDB": "",
        "GOPRIVATE": "",
        "GOPROXY": "https://proxy.golang.org,direct",
        "GOOS": "linux",
        "GOSUMDB": "sum.golang.org",
        "GOWORK": "off",
    }
    npm_env = {
        **base,
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_CACHE": str(npm_cache),
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_GLOBALCONFIG": str(npm_global_config),
        "NPM_CONFIG_USERCONFIG": str(npm_user_config),
        "VITE_API_BASE_URL": "/api/v1",
        "VITE_API_MODE": "live",
    }
    return base, go_env, npm_env


def verify_clean_detached_worktree(worktree: Path, source_commit: str, spec: ReleaseSpec = RC0_SPEC) -> None:
    directory(worktree, "source worktree")
    if spec.bootstrap and source_commit != RC0_SOURCE_COMMIT:
        raise ProductionBuildError("RC0 build must use the frozen installable bootstrap source commit")
    if not spec.bootstrap and not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        raise ProductionBuildError("RC1 build must use a lowercase source commit")
    try:
        head = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        detached_result = subprocess.run(
            ["git", "-C", str(worktree), "symbolic-ref", "-q", "HEAD"],
            text=True,
            capture_output=True,
        )
        dirty = subprocess.run(
            [
                "git",
                "-C",
                str(worktree),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ProductionBuildError("source worktree Git verification failed") from error
    if detached_result.returncode not in {0, 1}:
        raise ProductionBuildError("source worktree detached-head verification failed")
    if head != source_commit or detached_result.returncode != 1 or dirty:
        raise ProductionBuildError("source worktree must be clean, detached, and fixed at source commit")


def exact_regular(path: Path, label: str, mode: int) -> None:
    regular(path, label)
    if stat.S_IMODE(path.stat().st_mode) != mode:
        raise ProductionBuildError(f"{label} has an unsafe mode")


def load_strict_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProductionBuildError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise ProductionBuildError(f"{label} must be a JSON object")
    return value


def verify_n_minus_one_candidate_root(root: Path) -> NMinusOneEvidence:
    directory(root, "N-1 candidate root")
    archive_name = "open-card-0.8.0-rc.0-production.tar.gz"
    expected_root = {"release", "bundle-manifest.sha256", "production-bundle.json", "build-record.json", archive_name}
    actual_root = {path.name for path in root.iterdir()}
    if actual_root != expected_root:
        raise ProductionBuildError("N-1 candidate root does not contain exactly the required evidence")
    release = root / "release"
    directory(release, "N-1 release")
    bundle_manifest = root / "bundle-manifest.sha256"
    production_bundle = root / "production-bundle.json"
    build_record_path = root / "build-record.json"
    archive = root / archive_name
    exact_regular(bundle_manifest, "N-1 bundle manifest", 0o640)
    exact_regular(production_bundle, "N-1 production bundle metadata", 0o640)
    exact_regular(build_record_path, "N-1 build record", 0o640)
    exact_regular(archive, "N-1 archive", 0o644)
    manifest = root / "release" / "manifest.json"
    exact_regular(manifest, "N-1 release manifest", 0o644)
    manifest_digest = sha256(manifest)
    if manifest_digest != N_MINUS_ONE_RELEASE_MANIFEST_SHA256:
        raise ProductionBuildError("N-1 release manifest digest is not pinned")
    archive_digest = sha256(archive)
    if archive_digest != N_MINUS_ONE_ARCHIVE_SHA256:
        raise ProductionBuildError("N-1 archive digest is not pinned")
    bundle_digest = sha256(bundle_manifest)
    if bundle_digest != N_MINUS_ONE_BUNDLE_MANIFEST_SHA256:
        raise ProductionBuildError("N-1 bundle manifest digest is not pinned")
    expected_lines = (
        f"{N_MINUS_ONE_ARCHIVE_SHA256}  {archive_name}",
        f"{N_MINUS_ONE_RELEASE_MANIFEST_SHA256}  release/manifest.json",
    )
    if bundle_manifest.read_text(encoding="utf-8") != "\n".join(expected_lines) + "\n":
        raise ProductionBuildError("N-1 bundle manifest must contain exactly the pinned archive and release manifest")
    release_document = load_strict_json(manifest, "N-1 release manifest")
    build_record = load_strict_json(build_record_path, "N-1 build record")
    metadata = load_strict_json(production_bundle, "N-1 bundle metadata")
    if (release_document.get("version"), release_document.get("migration_version"), release_document.get("architecture"), release_document.get("source_commit")) != (RC0_SPEC.version, RC0_SPEC.migration, ARCHITECTURE, RC0_SOURCE_COMMIT):
        raise ProductionBuildError("N-1 release manifest metadata is invalid")
    files = release_document.get("files")
    if not isinstance(files, list) or len(files) != N_MINUS_ONE_DECLARED_FILE_COUNT:
        raise ProductionBuildError("N-1 release manifest must declare exactly the frozen file set")
    if validate_release(release, version=RC0_SPEC.version, migration_version=RC0_SPEC.migration, arch=ARCHITECTURE, source_commit=RC0_SOURCE_COMMIT) != manifest_digest:
        raise ProductionBuildError("N-1 release validation did not preserve its pinned manifest")
    bundle = build_record.get("bundle")
    candidate = build_record.get("candidate")
    if (
        build_record.get("production_accepted") is not False
        or not isinstance(candidate, dict)
        or not isinstance(bundle, dict)
        or (candidate.get("version"), candidate.get("migration_version"), candidate.get("architecture"), candidate.get("source_commit")) != (RC0_SPEC.version, RC0_SPEC.migration, ARCHITECTURE, RC0_SOURCE_COMMIT)
        or (bundle.get("archive"), bundle.get("archive_sha256"), bundle.get("manifest_sha256"), bundle.get("bundle_manifest_sha256")) != (archive_name, archive_digest, manifest_digest, bundle_digest)
    ):
        raise ProductionBuildError("N-1 build record is not bootstrap-only")
    n_minus_one = metadata.get("n_minus_one")
    if (
        metadata.get("candidate_status") != "bootstrap_baseline"
        or metadata.get("production_accepted") is not False
        or (metadata.get("source_commit"), metadata.get("version"), metadata.get("migration_version")) != (RC0_SOURCE_COMMIT, RC0_SPEC.version, RC0_SPEC.migration)
        or not isinstance(n_minus_one, dict)
        or n_minus_one != {"manifest_sha256": None, "release_embedded": False, "release_id": None, "status": "not_required_bootstrap", "version": None}
    ):
        raise ProductionBuildError("N-1 bundle metadata is invalid")
    return NMinusOneEvidence(
        candidate_root=root.resolve(),
        release_path=release.resolve(),
        version=RC0_SPEC.version,
        migration=RC0_SPEC.migration,
        source_commit=RC0_SOURCE_COMMIT,
        release_manifest_sha256=manifest_digest,
        archive_sha256=archive_digest,
        bundle_manifest_sha256=bundle_digest,
    )


def verify_clean_tracked_tool(
    tool_path: Path,
    expected_sha256: str,
    label: str,
) -> tuple[Path, dict[str, str]]:
    regular(tool_path, label)
    if not lowercase_hex(expected_sha256, 64):
        raise ProductionBuildError(f"{label} SHA-256 must be lowercase hexadecimal")
    try:
        repository = subprocess.run(
            ["git", "-C", str(tool_path.parent), "rev-parse", "--show-toplevel"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "-C", repository, "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        dirty = subprocess.run(
            [
                "git",
                "-C",
                repository,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        relative = tool_path.resolve().relative_to(Path(repository).resolve()).as_posix()
        tracked_blob = subprocess.run(
            ["git", "-C", repository, "rev-parse", f"{commit}:{relative}"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        committed_contents = subprocess.run(
            ["git", "-C", repository, "show", f"{commit}:{relative}"],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ProductionBuildError(f"{label} Git verification failed") from error
    except ValueError as error:
        raise ProductionBuildError(f"{label} must live inside its Git repository") from error
    if (
        not lowercase_hex(commit, 40)
        or dirty
        or hashlib.sha256(committed_contents).hexdigest() != expected_sha256
    ):
        raise ProductionBuildError(f"{label} repository must be clean and commit-pinned")
    return Path(repository), {
        "commit": commit,
        "relative_path": relative,
        "commit_blob": tracked_blob,
        "sha256": expected_sha256,
    }


def snapshot_source_tree(worktree: Path, source_commit: str, target: Path) -> None:
    try:
        archive = subprocess.run(
            ["git", "-C", str(worktree), "archive", "--format=tar", source_commit],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ProductionBuildError("source worktree archive snapshot failed") from error
    directory(target, "source snapshot target")
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            for entry in source.getmembers():
                relative = safe_relative(entry.name)
                normalized = relative.as_posix()
                if normalized in seen:
                    raise ProductionBuildError("source worktree archive contains duplicate paths")
                seen.add(normalized)
                if not (entry.isdir() or entry.isreg()):
                    raise ProductionBuildError("source worktree archive contains an unsafe entry")
                destination = target.joinpath(*relative.parts)
                if entry.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                stream = source.extractfile(entry)
                if stream is None:
                    raise ProductionBuildError("source worktree archive cannot read an entry")
                destination.parent.mkdir(parents=True, exist_ok=True)
                with stream, destination.open("xb") as output_stream:
                    shutil.copyfileobj(stream, output_stream)
                destination.chmod(entry.mode & 0o777)
    except tarfile.TarError as error:
        raise ProductionBuildError("source worktree archive is invalid") from error


def tree_digest(root: Path) -> str:
    directory(root, "tree")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ProductionBuildError("tree contains an unsafe entry")
        if path.is_file():
            if test_only_payload(PurePosixPath(relative.as_posix())):
                raise ProductionBuildError("tree contains a test-only payload")
            name = relative.as_posix().encode()
            digest.update(len(name).to_bytes(8, "big"))
            digest.update(name)
            digest.update(sha256(path).encode())
    return digest.hexdigest()


def stage_digests(stage: Path) -> list[dict[str, object]]:
    directory(stage, "stage")
    entries: list[dict[str, object]] = []
    for path in sorted(stage.rglob("*")):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ProductionBuildError("stage contains an unsafe entry")
        if path.is_file():
            entries.append(
                {
                    "path": path.relative_to(stage).as_posix(),
                    "sha256": sha256(path),
                    "mode": stat.S_IMODE(path.stat().st_mode),
                }
            )
    return entries


def validate_release(
    release: Path,
    *,
    version: str,
    migration_version: str,
    arch: str,
    source_commit: str,
) -> str:
    manifest_path = release / "manifest.json"
    regular(manifest_path, "release manifest")
    manifest_digest = sha256(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBuildError("release manifest is invalid JSON") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != version
        or manifest.get("migration_version") != migration_version
        or manifest.get("architecture") != arch
        or manifest.get("source_commit") != source_commit
    ):
        raise ProductionBuildError("release manifest does not match the candidate contract")
    expected_lineage = {
        "version": RC0_SPEC.version,
        "migration_version": RC0_SPEC.migration,
        "source_commit": RC0_SOURCE_COMMIT,
        "release_manifest_sha256": N_MINUS_ONE_RELEASE_MANIFEST_SHA256,
        "archive_sha256": N_MINUS_ONE_ARCHIVE_SHA256,
        "bundle_manifest_sha256": N_MINUS_ONE_BUNDLE_MANIFEST_SHA256,
    }
    if version == RC1_SPEC.version:
        if manifest.get("n_minus_one") != expected_lineage:
            raise ProductionBuildError("RC1 release manifest has invalid frozen N-1 lineage")
    elif "n_minus_one" in manifest:
        raise ProductionBuildError("RC0 release manifest must not carry N-1 lineage")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ProductionBuildError("release manifest has no files")
    declared: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "mode"}:
            raise ProductionBuildError("release manifest file entry is invalid")
        relative, digest, mode = entry["path"], entry["sha256"], entry["mode"]
        path = safe_relative(relative) if isinstance(relative, str) else None
        if (
            path is None
            or path.as_posix() in declared
            or not lowercase_hex(digest, 64)
            or not isinstance(mode, int)
            or isinstance(mode, bool)
        ):
            raise ProductionBuildError("release manifest entry is unsafe")
        if test_only_payload(path) or mode < 0 or mode > 0o777 or mode & 0o022:
            raise ProductionBuildError("release manifest includes an unsafe payload")
        target = release.joinpath(*path.parts)
        regular(target, "release payload")
        if sha256(target) != digest or stat.S_IMODE(target.stat().st_mode) != mode:
            raise ProductionBuildError("release payload does not match manifest")
        declared.add(path.as_posix())
    actual: set[str] = set()
    for path in release.rglob("*"):
        if path.is_symlink():
            raise ProductionBuildError("release contains a symlink")
        if path.is_dir():
            continue
        regular(path, "release payload")
        if path != manifest_path:
            actual.add(path.relative_to(release).as_posix())
    if actual != declared:
        raise ProductionBuildError("release files do not exactly match manifest")
    return manifest_digest


def ensure_non_aliases(output: Path, inputs: dict[str, Path]) -> None:
    output = output.resolve(strict=False)
    resolved: dict[str, Path] = {}
    for label, input_path in inputs.items():
        resolved[label] = input_path.resolve(strict=False)
    for label, input_path in resolved.items():
        if output == input_path or output.is_relative_to(input_path):
            raise ProductionBuildError(f"output must not alias {label}")
        if input_path.is_relative_to(output):
            raise ProductionBuildError(f"{label} must not alias output")
    values = list(resolved.items())
    for index, (left_label, left_path) in enumerate(values):
        for right_label, right_path in values[index + 1 :]:
            if left_path == right_path:
                raise ProductionBuildError(f"{left_label} and {right_label} must differ")


def require_ignored_output_if_in_repository(output: Path, repository: Path) -> None:
    try:
        relative = output.resolve(strict=False).relative_to(repository.resolve())
    except ValueError:
        return
    result = subprocess.run(
        ["git", "-C", str(repository), "check-ignore", "--quiet", "--no-index", "--", relative.as_posix()],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ProductionBuildError("candidate output inside the build-tool repository must be Git ignored")


def reserve_private_candidate_path(output: Path) -> Path:
    parent = output.parent
    for _ in range(32):
        candidate = parent / f".{output.name}.candidate-{secrets.token_hex(16)}"
        try:
            os.mkdir(candidate, 0o700)
        except FileExistsError:
            continue
        try:
            candidate.rmdir()
        except OSError as error:
            raise ProductionBuildError("cannot reserve a private candidate path") from error
        return candidate
    raise ProductionBuildError("cannot allocate a private candidate path")


def _darwin_rename_no_replace(candidate: Path, output: Path) -> None:
    try:
        renamex_np = ctypes.CDLL(None, use_errno=True).renamex_np
    except AttributeError as error:
        raise ProductionBuildError("atomic no-replace publication is unavailable") from error
    renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    renamex_np.restype = ctypes.c_int
    rename_exclusive = 0x00000004
    result = renamex_np(os.fsencode(candidate), os.fsencode(output), rename_exclusive)
    if result == 0:
        return
    failure = ctypes.get_errno()
    if failure == errno.EEXIST:
        raise ProductionBuildError("refusing to overwrite candidate output")
    raise ProductionBuildError(
        f"atomic no-replace candidate publication failed: errno {failure}"
    )


def _linux_rename_no_replace(candidate: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    rename_no_replace = 0x00000001
    at_fdcwd = -100
    try:
        renameat2 = libc.renameat2
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            at_fdcwd,
            os.fsencode(candidate),
            at_fdcwd,
            os.fsencode(output),
            rename_no_replace,
        )
    except AttributeError:
        syscall_numbers = {"x86_64": 316, "amd64": 316, "aarch64": 276, "arm64": 276}
        machine = os.uname().machine.lower()
        if machine not in syscall_numbers:
            raise ProductionBuildError("Linux renameat2 syscall is unsupported on this architecture")
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        result = syscall(
            syscall_numbers[machine],
            at_fdcwd,
            os.fsencode(candidate),
            at_fdcwd,
            os.fsencode(output),
            rename_no_replace,
        )
    if result == 0:
        return
    failure = ctypes.get_errno()
    if failure == errno.EEXIST:
        raise ProductionBuildError("refusing to overwrite candidate output")
    raise ProductionBuildError(
        f"atomic no-replace candidate publication failed: errno {failure}"
    )


def publish_no_replace(candidate: Path, output: Path) -> None:
    if candidate.parent.resolve() != output.parent.resolve():
        raise ProductionBuildError("candidate and output must share one parent directory")
    if sys.platform == "darwin":
        _darwin_rename_no_replace(candidate, output)
    elif sys.platform.startswith("linux"):
        _linux_rename_no_replace(candidate, output)
    else:
        raise ProductionBuildError("atomic no-replace publication is unavailable on this platform")


def verify_published_candidate(
    output: Path,
    *,
    version: str,
    migration_version: str,
    arch: str,
    source_commit: str,
    manifest_digest: str,
    archive_name: str,
    archive_digest: str,
    bundle_manifest_digest: str,
) -> None:
    if validate_release(
        output / "release",
        version=version,
        migration_version=migration_version,
        arch=arch,
        source_commit=source_commit,
    ) != manifest_digest:
        raise ProductionBuildError("published release changed after atomic publication")
    archive = output / archive_name
    regular(archive, "published candidate archive")
    if sha256(archive) != archive_digest:
        raise ProductionBuildError("published candidate archive changed after atomic publication")
    bundle_manifest = output / "bundle-manifest.sha256"
    regular(bundle_manifest, "published bundle manifest")
    if sha256(bundle_manifest) != bundle_manifest_digest:
        raise ProductionBuildError("published bundle manifest changed after atomic publication")


def build_candidate(
    *,
    source_worktree: Path,
    source_commit: str,
    runtime_inputs: Path,
    runtime_inputs_sha256: str,
    runtime_dir: Path,
    output: Path,
    bundle_tool: Path,
    bundle_tool_sha256: str,
    driver_sha256: str,
    version: str = RC0_SPEC.version,
    n_minus_one_candidate_root: Path | None = None,
) -> dict[str, object]:
    spec = release_spec(version)
    if not spec.bootstrap and n_minus_one_candidate_root is None:
        raise ProductionBuildError("RC1 build requires verified local N-1 evidence")
    if spec.bootstrap and n_minus_one_candidate_root is not None:
        raise ProductionBuildError("RC0 bootstrap must not accept N-1 evidence")
    n_minus_one_evidence = (
        verify_n_minus_one_candidate_root(n_minus_one_candidate_root)
        if n_minus_one_candidate_root is not None
        else None
    )
    if output.exists():
        raise ProductionBuildError("refusing to overwrite candidate output")
    directory(output.parent, "candidate output parent")
    verify_clean_detached_worktree(source_worktree, source_commit, spec)
    driver_path = Path(__file__).resolve()
    driver_repo, driver_metadata = verify_clean_tracked_tool(
        driver_path,
        driver_sha256,
        "production build driver",
    )
    bundle_repo, bundle_metadata = verify_clean_tracked_tool(
        bundle_tool,
        bundle_tool_sha256,
        "production bundle tool",
    )
    if driver_repo != bundle_repo or driver_metadata["commit"] != bundle_metadata["commit"]:
        raise ProductionBuildError("production driver and bundle tool must share one clean commit")
    ensure_non_aliases(
        output,
        {
            "source worktree": source_worktree,
            "runtime-input manifest": runtime_inputs,
            "runtime input directory": runtime_dir,
            "production build driver": driver_path,
            "production bundle tool": bundle_tool,
        },
    )
    require_ignored_output_if_in_repository(output, driver_repo)

    commands: list[list[str]] = []
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.build-", dir=output.parent) as raw:
        build_root = Path(raw)
        base_env, go_env, npm_env = isolated_build_environments(build_root)
        runtime_manifest_snapshot = build_root / "runtime-inputs.json"
        runtime_manifest_digest = snapshot_pinned_file(
            runtime_inputs,
            runtime_inputs_sha256,
            runtime_manifest_snapshot,
            "runtime-input manifest",
            0o600,
        )
        bundle_tool_snapshot = build_root / "production_bundle.py"
        bundle_tool_digest = snapshot_pinned_file(
            bundle_tool,
            bundle_tool_sha256,
            bundle_tool_snapshot,
            "production bundle tool",
            0o700,
        )
        driver_snapshot = build_root / "production_build.py"
        driver_digest = snapshot_pinned_file(
            driver_path,
            driver_sha256,
            driver_snapshot,
            "production build driver",
            0o700,
        )
        selected_inputs = load_runtime_inputs(
            runtime_manifest_snapshot,
            runtime_dir,
            ARCHITECTURE,
        )
        source_snapshot = build_root / "source"
        source_snapshot.mkdir(mode=0o700)
        snapshot_source_tree(source_worktree, source_commit, source_snapshot)
        runtime_snapshot = snapshot_runtime_inputs(
            selected_inputs,
            build_root / "runtime-inputs",
        )
        stage = build_root / "stage"
        (stage / "binaries" / ARCHITECTURE).mkdir(parents=True)
        for binary, package in GO_TARGETS.items():
            run_command(
                ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", str(stage / "binaries" / ARCHITECTURE / binary), package],
                cwd=source_snapshot,
                env=go_env,
                records=commands,
            )
        stage_runtime_inputs(runtime_snapshot, stage)
        go_environment = json.loads(
            run_command(
                ["go", "env", "-json", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED", "GOWORK"],
            cwd=source_snapshot,
            env=go_env,
            records=commands,
            )
        )

        web_root = source_snapshot / "web"
        run_command(["npm", "ci"], cwd=web_root, env=npm_env, records=commands)
        run_command(["npm", "run", "build"], cwd=web_root, env=npm_env, records=commands)
        metadata_path = web_root / "dist/build-metadata.json"
        regular(metadata_path, "Live web build metadata")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ProductionBuildError("Live web build metadata is invalid") from error
        if metadata != LIVE_METADATA:
            raise ProductionBuildError("web build did not produce the Live same-origin contract")
        web_dist = web_root / "dist"
        web_tree_digest = tree_digest(web_dist)
        attestation = {
            "schema_version": "open-card-live-attestation.v1",
            "source_commit": source_commit,
            "build_metadata_sha256": sha256(metadata_path),
            "dist_tree_sha256": web_tree_digest,
            "gate3_status": GATE3_STATUS,
        }
        attestation_path = build_root / "live-attestation.json"
        attestation_path.write_bytes(canonical_json(attestation))
        attestation_path.chmod(0o640)
        attestation_digest = sha256(attestation_path)

        candidate = reserve_private_candidate_path(output)
        run_command(
            [
                sys.executable,
                str(bundle_tool_snapshot),
                "assemble",
                "--stage-root",
                str(stage),
                "--repo-root",
                str(source_worktree),
                "--output-root",
                str(candidate),
                "--web-dist",
                str(web_dist),
                "--arch",
                ARCHITECTURE,
                "--version",
                spec.version,
                "--migration-version",
                spec.migration,
                "--source-commit",
                source_commit,
                *(
                    [
                        "--n-minus-one-release",
                        str(n_minus_one_evidence.release_path),
                        "--n-minus-one-manifest-sha256",
                        n_minus_one_evidence.release_manifest_sha256,
                        "--n-minus-one-archive-sha256",
                        n_minus_one_evidence.archive_sha256,
                        "--n-minus-one-bundle-manifest-sha256",
                        n_minus_one_evidence.bundle_manifest_sha256,
                    ]
                    if n_minus_one_evidence is not None
                    else []
                ),
                "--live-attestation",
                str(attestation_path),
                "--live-attestation-sha256",
                attestation_digest,
            ],
            cwd=source_worktree,
            env=base_env,
            records=commands,
        )
        manifest_digest = validate_release(
            candidate / "release",
            version=spec.version,
            migration_version=spec.migration,
            arch=ARCHITECTURE,
            source_commit=source_commit,
        )
        archive = candidate / f"open-card-{spec.version}-production.tar.gz"
        regular(archive, "candidate archive")
        archive_digest = sha256(archive)
        bundle_manifest = candidate / "bundle-manifest.sha256"
        regular(bundle_manifest, "candidate bundle manifest")
        bundle_manifest_digest = sha256(bundle_manifest)
        expected_bundle_lines = {
            f"{archive_digest}  {archive.name}",
            f"{manifest_digest}  release/manifest.json",
        }
        if set(bundle_manifest.read_text(encoding="utf-8").splitlines()) != expected_bundle_lines:
            raise ProductionBuildError("candidate bundle manifest does not match generated artifacts")
        record = {
            "schema_version": "open-card-production-build.v1",
            "production_accepted": False,
            "candidate": {
                "version": spec.version,
                "migration_version": spec.migration,
                "architecture": ARCHITECTURE,
                "source_commit": source_commit,
            },
            "build_tool": {
                "commit": driver_metadata["commit"],
                "driver": {**driver_metadata, "sha256": driver_digest},
                "bundle": {**bundle_metadata, "sha256": bundle_tool_digest},
            },
            "runtime_inputs": {
                "manifest_sha256": runtime_manifest_digest,
                "assets": {
                    tool: {"filename": asset.filename, "sha256": asset.digest}
                    for tool, asset in sorted(runtime_snapshot.items())
                },
            },
            "tools": {
                "go_environment": go_environment,
                "git_version": run_command(["git", "--version"], cwd=source_snapshot, env=base_env, records=commands).strip(),
                "node_version": run_command(["node", "--version"], cwd=source_snapshot, env=base_env, records=commands).strip(),
                "npm_version": run_command(["npm", "--version"], cwd=source_snapshot, env=base_env, records=commands).strip(),
                "python_version": run_command([sys.executable, "--version"], cwd=source_snapshot, env=base_env, records=commands).strip(),
            },
            "commands": commands,
            "stage_files": stage_digests(stage),
            "live_web": {
                "build_metadata_sha256": sha256(metadata_path),
                "dist_tree_sha256": web_tree_digest,
                "attestation_sha256": attestation_digest,
                "gate3_status": GATE3_STATUS,
            },
            "bundle": {
                "archive": archive.name,
                "archive_sha256": archive_digest,
                "manifest_sha256": manifest_digest,
                "bundle_manifest_sha256": bundle_manifest_digest,
            },
            "n_minus_one": (
                {
                    "version": n_minus_one_evidence.version,
                    "migration_version": n_minus_one_evidence.migration,
                    "source_commit": n_minus_one_evidence.source_commit,
                    "release_manifest_sha256": n_minus_one_evidence.release_manifest_sha256,
                    "archive_sha256": n_minus_one_evidence.archive_sha256,
                    "bundle_manifest_sha256": n_minus_one_evidence.bundle_manifest_sha256,
                    "status": "verified_local_candidate",
                    "release_embedded": False,
                }
                if n_minus_one_evidence is not None
                else None
            ),
        }
        (candidate / "build-record.json").write_bytes(canonical_json(record))
        (candidate / "build-record.json").chmod(0o640)
        candidate.chmod(0o750)
        publish_no_replace(candidate, output)
        verify_published_candidate(
            output,
            version=spec.version,
            migration_version=spec.migration,
            arch=ARCHITECTURE,
            source_commit=source_commit,
            manifest_digest=manifest_digest,
            archive_name=archive.name,
            archive_digest=archive_digest,
            bundle_manifest_digest=bundle_manifest_digest,
        )
        return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", nargs="?")
    parser.add_argument("--source-worktree", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--version", default=RC0_SPEC.version, choices=(RC0_SPEC.version, RC1_SPEC.version))
    parser.add_argument("--n-minus-one-candidate-root", type=Path)
    parser.add_argument("--runtime-inputs", required=True, type=Path)
    parser.add_argument("--runtime-inputs-sha256", required=True)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--bundle-tool",
        default=Path(__file__).with_name("production_bundle.py"),
        type=Path,
    )
    parser.add_argument("--bundle-tool-sha256", required=True)
    parser.add_argument("--driver-sha256", required=True)
    args = parser.parse_args()
    try:
        record = build_candidate(
            source_worktree=args.source_worktree.resolve(),
            source_commit=args.source_commit,
            runtime_inputs=args.runtime_inputs.resolve(),
            runtime_inputs_sha256=args.runtime_inputs_sha256,
            runtime_dir=args.runtime_dir.resolve(),
            output=args.output.resolve(strict=False),
            bundle_tool=args.bundle_tool.resolve(),
            bundle_tool_sha256=args.bundle_tool_sha256,
            driver_sha256=args.driver_sha256,
            version=args.version,
            n_minus_one_candidate_root=args.n_minus_one_candidate_root.resolve() if args.n_minus_one_candidate_root else None,
        )
    except ProductionBuildError as error:
        print(f"production build: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
