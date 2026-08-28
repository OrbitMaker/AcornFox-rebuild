#!/usr/bin/env python3
"""Assemble the credential-free Open Card 0.7.0-rc.1 source contract.

This tool is intentionally offline. The caller supplies cross-built binaries,
fixed per-architecture runtime assets, and a checksum-covered Debian input
directory. It creates deterministic tar files and manifests; it never
provisions a VM, starts a service, downloads a dependency, or follows a
symlink.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.7.0-rc.1"
N_MINUS_ONE = "0.6.0"
PROTOCOL = "1.1"
N_MINUS_ONE_PROTOCOL = "1.0"
ARCHES = ("amd64", "arm64")
BINARIES = (
    "open-card-server",
    "open-card-agent",
    "open-card-static-server",
    "open-card-secretctl",
    "open-card-security-probe",
    "open-card-imagegc",
)
ASSETS = ("buildkit.tar.gz", "rootlesskit.tar.gz", "docker-buildx", "caddy.tar.gz", "ubuntu-24.04-server-cloudimg.img")
UBUNTU_GPG_SIGNER = "UEC Image Automatic Signing Key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
PINNED_PROVENANCE = {
    "buildkit.tar.gz": {"version": "0.32.2", "url": "https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-{arch}.tar.gz"},
    "rootlesskit.tar.gz": {"version": "3.1.0", "url": "https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-{asset_arch}.tar.gz"},
    "docker-buildx": {"version": "0.36.1", "url": "https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-{arch}"},
    "caddy.tar.gz": {"version": "2.11.4", "url": "https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_{arch}.tar.gz"},
    "ubuntu-24.04-server-cloudimg.img": {"version": "24.04", "url": "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-{arch}.img"},
}
UNITS = (
    "open-card-server.service",
    "open-card-agent.service",
    "open-card-buildkit.service",
    "open-card-caddy.service",
)
G7_SCRIPTS = (
    "install-host.sh",
    "install.sh",
    "upgrade.sh",
    "uninstall.sh",
    "backup-control-plane.sh",
    "restore-control-plane.sh",
    "control-plane-migrate.sh",
)
DOC_FILES = (
    "README.md",
    "docs/architecture.md",
    "docs/adr/0007-installation-service-model.md",
    "docs/mvp-product-spec.md",
    "docs/mvp-implementation-status.md",
    "docs/known-issues.md",
)
SOURCE_ROOTS = ("api", "cmd", "internal")
FORBIDDEN_NAME_PARTS = frozenset(
    {
        ".env",
        "authorized_keys",
        "credential",
        "credentials",
        "kubeconfig",
        "password",
        "passwd",
        "secret",
        "secrets",
        "token",
    }
)
FORBIDDEN_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
)
PRIVATE_KEY_BLOCK = re.compile(
    rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{32,}-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+@=%~-]*$")
MIGRATION = re.compile(r"^(\d{4})_[A-Za-z0-9._-]+\.sql$")


class M7Error(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def regular(path: Path) -> Path:
    try:
        info = path.lstat()
    except OSError as exc:
        raise M7Error(f"cannot stat input: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise M7Error(f"input must be a regular non-symlink file: {path}")
    return path


def directory(path: Path, field: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise M7Error(f"{field} must be a regular directory")
    return path.resolve()


def safe_relative(value: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or "" in path.parts or "\\" in value or not SAFE_RELATIVE.fullmatch(value):
        raise M7Error(f"unsafe relative path: {value}")


def set_epoch(path: Path) -> None:
    os.utime(path, (0, 0), follow_symlinks=False)


def copy_file(source: Path, target: Path, mode: int | None = None) -> None:
    regular(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode if mode is not None else (source.stat().st_mode & 0o777 & ~0o022))
    set_epoch(target)


def forbidden_name(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered.endswith(FORBIDDEN_SUFFIXES):
        return True
    parts = [part for part in re.split(r"[._+-]+", lowered) if part]
    return lowered == ".env" or lowered.startswith(".env.") or any(part in FORBIDDEN_NAME_PARTS for part in parts)


def scan_credentials(path: Path, *, skip_binary: bool = False, allow_fixture_name: bool = False) -> None:
    verified_debian_binary = skip_binary and path.suffix == ".deb"
    if not allow_fixture_name and not verified_debian_binary and forbidden_name(path):
        raise M7Error(f"credential-like filename is forbidden: {path.name}")
    raw = path.read_bytes()
    if any(pattern.search(raw) for pattern in SECRET_PATTERNS):
        raise M7Error(f"credential material is forbidden: {path}")
    if skip_binary:
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return
    # Do not reject ordinary source identifiers such as SECRET_ROOT. Only
    # reject an assigned quoted/high-entropy value in release text.
    assignment = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|password)\s*[:=]\s*[\"']([A-Za-z0-9_+/=-]{24,})[\"']")
    if assignment.search(text):
        raise M7Error(f"credential-looking assignment is forbidden: {path}")


def scan_fixture_content(label: str, raw: bytes) -> None:
    """Reject credentials while allowing non-secret compiled test vectors.

    Compiled test binaries may contain the literal BEGIN marker from a
    negative assertion. That marker alone is not key material. A complete PEM
    block, a provider token, or a high-entropy credential assignment is always
    rejected; prose such as "fixture" or "canary" never bypasses validation.
    """
    binary_member = b"\x00" in raw[:8192] or label.endswith((".test", "open-card-caddy-fixture"))
    if PRIVATE_KEY_BLOCK.search(raw) or any(pattern.search(raw) for pattern in SECRET_PATTERNS[1:]):
        raise M7Error(f"credential material in test fixture: {label}")
    if not binary_member and SECRET_PATTERNS[0].search(raw):
        raise M7Error(f"private-key marker in text test fixture: {label}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return
    assignment = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|password)\s*[:=]\s*[\"']([A-Za-z0-9_+/=-]{24,})[\"']")
    if assignment.search(text):
        raise M7Error(f"credential-looking assignment in test fixture: {label}")


def scan_fixture_archive(path: Path) -> None:
    try:
        with tarfile.open(path, "r:") as archive:
            for member in archive.getmembers():
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts or not (member.isfile() or member.isdir()):
                    raise M7Error(f"unsafe test fixture archive member: {member.name}")
                if member.isfile():
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise M7Error(f"cannot read test fixture archive member: {member.name}")
                    scan_fixture_content(member.name, handle.read())
    except (OSError, tarfile.TarError) as exc:
        raise M7Error(f"invalid test fixture archive: {path}") from exc


def copy_tree(source: Path, target: Path, *, exclude_tests: bool = False) -> list[Path]:
    copied: list[Path] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part in {".git", ".omx", ".pytest_cache", "__pycache__", "node_modules", ".playwright-cli"} for part in relative.parts):
            continue
        if exclude_tests and ("tests" in relative.parts or "testdata" in relative.parts or "fixtures" in relative.parts or path.name.endswith("_test.go")):
            continue
        if path.is_symlink():
            raise M7Error(f"symlink is forbidden in source input: {path}")
        if not path.is_file():
            continue
        target_path = target / relative
        copy_file(path, target_path)
        scan_credentials(target_path)
        copied.append(target_path)
    return copied


def verify_manifest(root: Path, manifest: Path, expected_prefix: str, required: Iterable[str]) -> list[Path]:
    if manifest.is_symlink() or not manifest.is_file():
        raise M7Error(f"checksum manifest is missing: {manifest}")
    listed: dict[str, str] = {}
    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise M7Error(f"invalid checksum manifest entry: {raw_line}")
        relative = parts[1].strip()
        safe_relative(relative)
        if relative in listed:
            raise M7Error(f"duplicate checksum manifest entry: {relative}")
        if not relative.startswith(expected_prefix):
            raise M7Error(f"checksum entry escapes expected root: {relative}")
        listed[relative] = parts[0]
    actual = sorted(
        str(path.relative_to(root)).replace(os.sep, "/")
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name != manifest.name and not (expected_prefix == "debs/" and path.name == "packages.txt")
    )
    if sorted(listed) != actual:
        raise M7Error(f"checksum manifest coverage mismatch: missing={sorted(set(actual)-set(listed))} extra={sorted(set(listed)-set(actual))}")
    for relative, expected_digest in listed.items():
        path = root / relative
        regular(path)
        if sha256(path) != expected_digest:
            raise M7Error(f"checksum mismatch: {relative}")
    missing = [name for name in required if name not in listed]
    if missing:
        raise M7Error(f"required fixed inputs are missing: {missing}")
    return [root / relative for relative in sorted(listed)]


def read_checksum_entries(manifest: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        digest, relative = line.split(None, 1)
        entries[relative.strip()] = digest
    return entries


def copy_verified_inputs(root: Path, output: Path, kind: str, required: Iterable[str]) -> list[Path]:
    manifest = root / ("assets.sha256" if kind == "assets" else "debs.sha256")
    prefix = "" if kind == "assets" else "debs/"
    files = verify_manifest(root, manifest, prefix, required)
    if kind == "debs" and not files:
        raise M7Error("Debian input manifest contains no packages")
    destination = output / "inputs" / kind
    destination.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for path in files:
        relative = path.relative_to(root)
        target = destination / relative
        copy_file(path, target, 0o644)
        scan_credentials(target, skip_binary=target.suffix in {".deb", ".gz"})
        copied.append(target)
    if kind == "debs":
        packages = root / "packages.txt"
        regular(packages)
        copy_file(packages, destination / "packages.txt", 0o644)
        copied.append(destination / "packages.txt")
    copied_manifest = destination / manifest.name
    copy_file(manifest, copied_manifest, 0o644)
    copied.append(copied_manifest)
    return copied


def tar_info(name: str, size: int, mode: int, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def extract_fixed_assets(asset_root: Path, output: Path) -> dict[str, dict[str, Path]]:
    """Safely extract only runtime executables from fixed asset archives."""
    extracted: dict[str, dict[str, Path]] = {}
    archive_specs = {
        "buildkit.tar.gz": (("buildkitd", "buildctl", "buildkit-runc"), {"buildkit-cni-bridge", "buildkit-cni-firewall", "buildkit-cni-host-local", "buildkit-cni-loopback", "buildkit-qemu-aarch64", "buildkit-qemu-arm", "buildkit-qemu-i386", "buildkit-qemu-ppc64le", "buildkit-qemu-riscv64", "buildkit-qemu-s390x", "buildkit-qemu-x86_64"}),
        "rootlesskit.tar.gz": (("rootlesskit",), {"rootlessctl", "rootlesskit-docker-proxy"}),
        "caddy.tar.gz": (("caddy",), set()),
    }
    for arch in ARCHES:
        arch_root = output / "cross-build" / arch / "runtime"
        arch_root.mkdir(parents=True, exist_ok=True)
        extracted[arch] = {}
        for archive_name, (required_names, optional_names) in archive_specs.items():
            archive_path = asset_root / arch / archive_name
            regular(archive_path)
            found: dict[str, tarfile.TarInfo] = {}
            try:
                with tarfile.open(archive_path, "r:gz") as archive:
                    members = archive.getmembers()
                    if len(members) > 128:
                        raise M7Error(f"fixed asset archive has too many members: {archive_path}")
                    total_size = 0
                    for member in members:
                        member_path = Path(member.name)
                        if member_path.is_absolute() or ".." in member_path.parts or "" in member_path.parts:
                            raise M7Error(f"unsafe fixed asset archive path: {member.name}")
                        if member.issym() or member.islnk() or member.isdev() or not (member.isdir() or member.isfile()):
                            raise M7Error(f"unsupported fixed asset archive member: {member.name}")
                        if member.size < 0 or member.size > 4 * 1024 * 1024 * 1024:
                            raise M7Error(f"fixed asset archive member is too large: {member.name}")
                        total_size += member.size
                        if total_size > 4 * 1024 * 1024 * 1024:
                            raise M7Error(f"fixed asset archive is too large: {archive_path}")
                        if member.isdir():
                            continue
                        name = member_path.name
                        if name not in required_names and name not in optional_names and name not in {"LICENSE", "LICENSE.txt", "README", "README.md"}:
                            raise M7Error(f"unexpected fixed asset archive member: {member.name}")
                        if name in required_names:
                            if name in found:
                                raise M7Error(f"duplicate fixed asset binary: {name}")
                            found[name] = member
                    missing = [name for name in required_names if name not in found]
                    if missing:
                        raise M7Error(f"fixed asset archive omits binaries: {archive_path}: {missing}")
                    for name, member in found.items():
                        handle = archive.extractfile(member)
                        if handle is None:
                            raise M7Error(f"cannot read fixed asset binary: {member.name}")
                        target = arch_root / name
                        target.write_bytes(handle.read())
                        target.chmod(0o755)
                        set_epoch(target)
                        scan_credentials(target, skip_binary=True)
                        extracted[arch][name] = target
            except (OSError, tarfile.TarError) as exc:
                raise M7Error(f"invalid fixed asset archive: {archive_path}") from exc
        raw_buildx = asset_root / arch / "docker-buildx"
        regular(raw_buildx)
        target = arch_root / "docker-buildx"
        copy_file(raw_buildx, target, 0o755)
        scan_credentials(target, skip_binary=True)
        extracted[arch]["docker-buildx"] = target
    return extracted


def write_tar(output: Path, root: Path, members: Iterable[Path]) -> None:
    files = sorted({path for path in members if path.is_file()}, key=lambda path: path.relative_to(root).as_posix())
    directories: set[str] = set()
    for path in files:
        relative = path.relative_to(root)
        directories.update(parent.as_posix() for parent in relative.parents if parent.as_posix() != ".")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:") as archive:
        for name in sorted(directories):
            archive.addfile(tar_info(name + "/", 0, 0o755, True))
        for path in files:
            relative = path.relative_to(root).as_posix()
            mode = path.stat().st_mode & 0o777 & ~0o022
            with path.open("rb") as handle:
                info = tar_info(relative, path.stat().st_size, mode)
                archive.addfile(info, handle)
    output.chmod(0o640)
    set_epoch(output)


def migration_files(repo: Path) -> list[Path]:
    paths = sorted((repo / "migrations/control-plane").glob("*.sql"))
    numbers: list[int] = []
    for path in paths:
        match = MIGRATION.fullmatch(path.name)
        if not match:
            raise M7Error(f"invalid migration filename: {path.name}")
        numbers.append(int(match.group(1)))
    if not paths or numbers != list(range(1, max(numbers) + 1)):
        raise M7Error("migrations must be contiguous from 0001 through current")
    return paths


def make_configs(root: Path) -> list[Path]:
    configs = {
        "server.env.example": "OPEN_CARD_SERVER_ADDR=127.0.0.1:8080\nOPEN_CARD_DATABASE_URL=<configure-at-install>\nOPEN_CARD_AGENT_GATEWAY_ADDR=127.0.0.1:8092\nOPEN_CARD_M6_ENABLED=false\n",
        "agent.env.example": "OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID=<configure-at-install>\nOPEN_CARD_AGENT_DISPATCH_NODE_ID=<configure-at-install>\nOPEN_CARD_SERVER_AGENT_TLS_CA=/etc/open-card/agent-ca.crt\n",
        "caddy.env.example": "OPEN_CARD_CADDY_LISTEN=127.0.0.1:8080\nOPEN_CARD_CADDY_ADMIN_URL=http://127.0.0.1:2019\n",
        "Caddyfile.example": "http://127.0.0.1:8080 {\n    respond /readyz 200\n}\n",
    }
    written: list[Path] = []
    for name, content in configs.items():
        path = root / "config" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o640)
        set_epoch(path)
        scan_credentials(path)
        written.append(path)
    return written


def make_runbooks(root: Path) -> list[Path]:
    runbooks = {
        "INSTALL.md": """# RC install runbook\n\n1. Verify `manifest.json`, `bundle-manifest.sha256`, SBOM, and fixed input checksums.\n2. Install the N-1 `release-0.6.0` on a clean supported host.\n3. Run the M7 preflight and health evidence before activation.\n4. Keep credentials generated by the installer outside the bundle.\n\nThis runbook does not authorize VM provisioning or network downloads.\n""",
        "UPGRADE.md": """# RC upgrade runbook\n\nUpgrade from `release-0.6.0` to `release-0.7.0-rc.1` only after a verified control-plane backup. Apply `migrations/n-minus-one` for the N-1 baseline, then the full `migrations/current` set during the controlled upgrade. Keep the previous release pointer until independent health evidence passes.\n""",
        "RECOVERY.md": """# RC recovery runbook\n\nOn failed health or migration evidence, stop new tasks, retain the current serving release, restore the previous release pointer, and use the recorded database snapshot. Do not delete application data or audit evidence as part of a default rollback.\n""",
    }
    written: list[Path] = []
    for name, content in runbooks.items():
        path = root / "docs/runbooks" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o640)
        set_epoch(path)
        scan_credentials(path)
        written.append(path)
    return written


def copy_source(repo: Path, output: Path) -> list[Path]:
    source = output / "source"
    copied: list[Path] = []
    for root_name in SOURCE_ROOTS:
        copied.extend(copy_tree(repo / root_name, source / root_name, exclude_tests=True))
    for relative in ("go.mod", "go.sum", "Makefile"):
        path = repo / relative
        if path.is_file():
            target = source / relative
            copy_file(path, target)
            scan_credentials(target)
            copied.append(target)
    for relative in DOC_FILES:
        path = repo / relative
        if not path.is_file():
            raise M7Error(f"canonical documentation input is missing: {relative}")
        target = source / relative
        copy_file(path, target)
        scan_credentials(target)
        copied.append(target)
    for root_name in ("docs/licenses",):
        copied.extend(copy_tree(repo / root_name, source / root_name))
    copied.extend(copy_tree(repo / "web/dist", source / "web/dist"))
    copied.extend(copy_tree(repo / "migrations/control-plane", source / "migrations/control-plane"))
    return copied


def copy_systemd(repo: Path, root: Path) -> list[Path]:
    copied: list[Path] = []
    for name in UNITS:
        source = repo / "deploy/systemd" / name
        target = root / "systemd" / name
        copy_file(source, target, 0o644)
        scan_credentials(target)
        copied.append(target)
    return copied


def make_release(root: Path, stage: Path, runtime: dict[str, dict[str, Path]], arch: str, version: str, max_data_version: int) -> Path:
    release = root / "releases" / f"release-{version}"
    if release.exists():
        raise M7Error(f"release already exists: {release}")
    for binary in BINARIES:
        source = stage / "binaries" / arch / binary
        if not source.is_file():
            raise M7Error(f"missing {arch} binary: {binary}")
        copy_file(source, release / "bin" / binary, 0o755)
    for binary in ("buildkitd", "buildctl", "buildkit-runc", "rootlesskit", "docker-buildx", "caddy"):
        copy_file(runtime[arch][binary], release / "bin" / binary, 0o755)
    for unit in UNITS:
        copy_file(root / "systemd" / unit, release / "systemd" / unit, 0o644)
    for config in (root / "config").glob("*"):
        copy_file(config, release / "config" / config.name, 0o640)
    (release / "VERSION").parent.mkdir(parents=True, exist_ok=True)
    (release / "VERSION").write_text(version + "\n", encoding="utf-8")
    (release / "VERSION").chmod(0o644)
    set_epoch(release / "VERSION")
    files: list[dict[str, Any]] = []
    for path in sorted(item for item in release.rglob("*") if item.is_file()):
        relative = path.relative_to(release).as_posix()
        files.append({"path": relative, "sha256": sha256(path), "mode": path.stat().st_mode & 0o777})
    release_protocol = N_MINUS_ONE_PROTOCOL if version == N_MINUS_ONE else PROTOCOL
    manifest = {
        "schema_version": 1,
        "product": "open-card",
        "version": version,
        "release_id": f"release-{version}",
        "architecture": arch,
        "migration_version": f"{max_data_version:04d}",
        "protocol": release_protocol,
        "config_dir": "/etc/open-card",
        "data_dir": "/var/lib/open-card",
        "compatibility": {
            "min_data_version": 1,
            "max_data_version": max_data_version,
            "min_agent_protocol": "1.0",
            "max_agent_protocol": release_protocol,
            "requires_data_backup": True,
        },
        "files": files,
    }
    manifest_path = release / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    manifest_path.chmod(0o644)
    set_epoch(manifest_path)
    return release


def make_migrations(repo: Path, root: Path) -> list[Path]:
    paths = migration_files(repo)
    destination = root / "migrations"
    all_paths: list[Path] = []
    for path in paths:
        for name in ("all", "current"):
            target = destination / name / path.name
            copy_file(path, target, 0o644)
            all_paths.append(target)
    n_minus_one = paths[:-1]
    for path in n_minus_one:
        target = destination / "n-minus-one" / path.name
        copy_file(path, target, 0o644)
        all_paths.append(target)
    for path in paths[:6]:
        target = destination / "v1" / path.name
        copy_file(path, target, 0o644)
        all_paths.append(target)
    return all_paths


def make_arch_manifests(stage: Path, root: Path, runtime: dict[str, dict[str, Path]]) -> list[Path]:
    outputs: list[Path] = []
    for arch in ARCHES:
        entries: list[dict[str, Any]] = []
        for binary in BINARIES:
            path = stage / "binaries" / arch / binary
            regular(path)
            entries.append({"name": binary, "path": f"binaries/{arch}/{binary}", "sha256": sha256(path), "mode": 0o755})
        runtime_entries = []
        for name in ("buildkitd", "buildctl", "buildkit-runc", "rootlesskit", "docker-buildx", "caddy"):
            path = runtime[arch][name]
            runtime_entries.append({"name": name, "path": f"cross-build/{arch}/runtime/{name}", "sha256": sha256(path), "mode": 0o755})
        asset_entries = []
        for asset in ASSETS:
            path = root / "inputs/assets" / arch / asset
            asset_entries.append({"name": asset, "path": f"inputs/assets/{arch}/{asset}", "sha256": sha256(path)})
        manifest = {"schema_version": 1, "product": "open-card", "version": VERSION, "goos": "linux", "goarch": arch, "binaries": entries, "runtime_assets": runtime_entries, "fixed_assets": asset_entries}
        target = root / "cross-build" / arch / "manifest.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canonical_json(manifest))
        target.chmod(0o644)
        set_epoch(target)
        outputs.append(target)
    return outputs


def make_fixtures(repo: Path, stage: Path, root: Path) -> Path:
    fixture_root = root / "m7-fixtures-tree"
    fixture_root.mkdir(parents=True, exist_ok=True)
    for milestone in ("m2", "m3", "m4"):
        fixture_source = repo / "tests/fixtures" / milestone
        for path in sorted(fixture_source.rglob("*")):
            if path.is_symlink():
                raise M7Error(f"fixture symlink is forbidden: {path}")
            if path.is_file():
                copy_file(path, fixture_root / "tests/fixtures" / milestone / path.relative_to(fixture_source), 0o640)
    wire_fixture_roots = (
        (repo / "api/agent/v1/testdata/m2", fixture_root / "agent-wire-root/testdata/m2"),
        (repo / "tests/fixtures/compatibility", fixture_root / "agent-wire-root/github.com/open-card/open-card/tests/fixtures/compatibility"),
    )
    for source_root, target_root in wire_fixture_roots:
        for path in sorted(source_root.rglob("*")):
            if path.is_symlink():
                raise M7Error(f"Agent wire fixture symlink is forbidden: {path}")
            if path.is_file():
                copy_file(path, target_root / path.relative_to(source_root), 0o640)
    names = [
        "tests/spikes/clean_worker_m2_guest.sh",
        "tests/spikes/clean_worker_m3_guest.sh",
        "tests/spikes/clean_worker_m4_guest.sh",
        "tests/spikes/clean_worker_m4_log_gate_guest.sh",
        "tests/spikes/clean_worker_m4_webhook_lifecycle_guest.sh",
    ]
    names.extend(str(path.relative_to(repo)) for path in sorted((repo / "tests/spikes").glob("*m7*.sh")))
    for relative in names:
        source = repo / relative
        if source.is_file():
            target = fixture_root / relative
            copy_file(source, target, 0o750 if source.suffix == ".sh" else 0o640)
    test_root = stage / "test-only" / "amd64"
    for path in sorted(test_root.glob("*")) if test_root.is_dir() else []:
        if path.is_file() and not path.is_symlink():
            copy_file(path, fixture_root / "bin/amd64" / path.name, 0o755)
    marker = fixture_root / "README.md"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("Test-only M7 fixtures. These files are never included in a production release manifest.\n", encoding="utf-8")
    marker.chmod(0o640)
    set_epoch(marker)
    archive = root / "m7-fixtures.tar"
    write_tar(archive, fixture_root, [path for path in fixture_root.rglob("*") if path.is_file()])
    shutil.rmtree(fixture_root)
    return archive


def make_sbom(root: Path, files: list[Path]) -> Path:
    components = []
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        components.append({"SPDXID": "SPDXRef-" + hashlib.sha256(relative.encode()).hexdigest()[:20], "name": relative, "versionInfo": VERSION, "downloadLocation": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}]})
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "open-card-0.7.0-rc.1", "documentNamespace": "https://open-card.invalid/sbom/0.7.0-rc.1", "packages": components}
    target = root / "sbom.spdx.json"
    target.write_bytes(canonical_json(sbom))
    target.chmod(0o640)
    set_epoch(target)
    return target


def write_checksums(root: Path, relative_paths: Iterable[Path], filename: str) -> Path:
    entries = []
    for path in sorted(relative_paths, key=lambda item: item.relative_to(root).as_posix()):
        if path.name == filename or not path.is_file():
            continue
        entries.append(f"{sha256(path)}  {path.relative_to(root).as_posix()}")
    target = root / filename
    target.write_text("\n".join(entries) + "\n", encoding="utf-8")
    target.chmod(0o640)
    set_epoch(target)
    return target


def make_supply_chain(root: Path, assets_root: Path, debs_root: Path) -> Path:
    entries = read_checksum_entries(assets_root / "assets.sha256")
    fixed_assets = []
    for arch in ARCHES:
        for asset in ASSETS:
            relative = f"{arch}/{asset}"
            digest = entries.get(relative)
            if digest is None:
                raise M7Error(f"fixed asset provenance is missing: {relative}")
            provenance = PINNED_PROVENANCE[asset]
            asset_arch = "x86_64" if arch == "amd64" and asset == "rootlesskit.tar.gz" else "aarch64" if arch == "arm64" and asset == "rootlesskit.tar.gz" else arch
            fixed_assets.append({"name": asset, "architecture": arch, "version": provenance["version"], "url": provenance["url"].format(arch=arch, asset_arch=asset_arch), "sha256": digest, "sha256_source": "assets.sha256"})
    deb_manifest = read_checksum_entries(debs_root / "debs.sha256")
    supply = {
        "schema_version": 1,
        "product": "open-card",
        "version": VERSION,
        "n_minus_one": N_MINUS_ONE,
        "offline_only": True,
        "ubuntu_gpg_signer": UBUNTU_GPG_SIGNER,
        "build_toolchain": {"name": "go", "version": "1.25.13", "release_page": "https://go.dev/dl/", "url": "https://dl.google.com/go/go1.25.13.linux-amd64.tar.gz", "sha256": "39042a078ea9ceebe3ecda4a7188f0f5b96e14a071d27923ba7f40b456e85ae3"},
        "fixed_assets": fixed_assets,
        "debian_inputs": {"packages_manifest": "packages.txt", "checksum_manifest": "debs.sha256", "packages": [{"path": path, "sha256": digest} for path, digest in sorted(deb_manifest.items())]},
        "provenance_policy": "URLs and versions are fixed by this contract; bytes are accepted only when assets.sha256 matches exactly.",
    }
    target = root / "supply-chain.json"
    target.write_bytes(canonical_json(supply))
    target.chmod(0o640)
    set_epoch(target)
    return target


def assemble(stage: Path, repo: Path, output: Path, debs_root: Path, assets_root: Path) -> dict[str, Any]:
    stage = directory(stage, "stage root")
    repo = directory(repo, "repository root")
    debs_root = directory(debs_root, "Debian input root")
    assets_root = directory(assets_root, "fixed asset root")
    if output.exists():
        raise M7Error("refusing to overwrite canonical M7 output")
    output.mkdir(parents=True)
    (output / "systemd").mkdir()
    (output / "VERSION").write_text(VERSION + "\n", encoding="utf-8")
    (output / "VERSION").chmod(0o640)
    set_epoch(output / "VERSION")
    (output / "N-MINUS-ONE").write_text(N_MINUS_ONE + "\n", encoding="utf-8")
    (output / "N-MINUS-ONE").chmod(0o640)
    set_epoch(output / "N-MINUS-ONE")
    copy_source(repo, output)
    copy_tree(repo / "docs/licenses", output / "docs/licenses")
    copy_tree(repo / "web/dist", output / "web/dist")
    copy_systemd(repo, output)
    make_configs(output)
    make_runbooks(output)
    asset_required = [f"{arch}/{asset}" for arch in ARCHES for asset in ASSETS]
    copy_verified_inputs(assets_root, output, "assets", asset_required)
    runtime = extract_fixed_assets(assets_root, output)
    make_arch_manifests(stage, output, runtime)
    copy_verified_inputs(debs_root, output, "debs", [f"debs/{path.name}" for path in sorted((debs_root / "debs").glob("*.deb"))])
    supply_chain = make_supply_chain(output, assets_root, debs_root)
    make_migrations(repo, output)
    current_release = make_release(output, stage, runtime, "amd64", VERSION, len(migration_files(repo)))
    n_minus_one = make_release(output, stage, runtime, "amd64", N_MINUS_ONE, len(migration_files(repo)) - 1)
    # A release directory is the installer input; arm64 is selected from the
    # cross-build manifest by the platform-specific release pipeline.
    (output / "compatibility.json").write_bytes(canonical_json({"schema_version": 1, "current": VERSION, "n_minus_one": N_MINUS_ONE, "architectures": list(ARCHES), "production_binaries": list(BINARIES), "test_only_excluded": ["open-card-caddy-fixture", "integration-tests"]}))
    (output / "compatibility.json").chmod(0o640)
    set_epoch(output / "compatibility.json")
    releases_root = output / "releases"
    write_tar(output / "releases.tar", releases_root, [path for path in releases_root.rglob("*") if path.is_file()])
    migration_root = output / "migrations"
    write_tar(output / "migrations.tar", migration_root, [path for path in migration_root.rglob("*") if path.is_file()])
    g7_root = output / "source" / "scripts/mvp"
    g7_archive_root = output / "g7"
    for name in G7_SCRIPTS:
        copy_file(repo / "scripts/mvp" / name, g7_archive_root / name, 0o750)
    write_tar(output / "g7-scripts.tar", g7_archive_root, [path for path in g7_archive_root.rglob("*") if path.is_file()])
    fixture_archive = make_fixtures(repo, stage, output)
    deb_archive = output / "debs.tar"
    write_tar(deb_archive, output / "inputs/debs", [path for path in (output / "inputs/debs").rglob("*") if path.is_file()])
    asset_archive = output / "assets.tar"
    write_tar(asset_archive, output / "inputs/assets", [path for path in (output / "inputs/assets").rglob("*") if path.is_file()])
    summary = {"version": VERSION, "n_minus_one": N_MINUS_ONE, "release_dirs": [current_release.name, n_minus_one.name], "migrations": len(migration_files(repo)), "production_binaries": list(BINARIES), "fixture_archive": fixture_archive.name, "fixture_root": "tests/fixtures + tests/spikes + bin/amd64 (test-only archive)", "fixture_binary": "bin/amd64/open-card-caddy-fixture", "sbom": "sbom.spdx.json", "bundle_manifest": "bundle-manifest.sha256"}
    (output / "summary.json").write_bytes(canonical_json(summary))
    (output / "summary.json").chmod(0o640)
    set_epoch(output / "summary.json")
    source_files = [path for path in (output / "source").rglob("*") if path.is_file()]
    source_checksum = write_checksums(output, source_files, "source-manifest.sha256")
    licenses = [path for path in (output / "source/docs/licenses").rglob("*") if path.is_file()]
    write_checksums(output, licenses, "licenses-manifest.sha256")
    sbom_files = [path for path in output.rglob("*") if path.is_file() and path.name not in {"sbom.spdx.json", "bundle-manifest.sha256"}]
    sbom = make_sbom(output, sbom_files)
    files = []
    for path in sorted(path for path in output.rglob("*") if path.is_file() and path.name not in {"manifest.json", "bundle-manifest.sha256"}):
        files.append({"path": path.relative_to(output).as_posix(), "sha256": sha256(path), "mode": path.stat().st_mode & 0o777, "size_bytes": path.stat().st_size})
    manifest = {"schema_version": 1, "product": "open-card", "version": VERSION, "n_minus_one": N_MINUS_ONE, "protocol": PROTOCOL, "architectures": list(ARCHES), "production_binaries": list(BINARIES), "test_only_excluded": ["open-card-caddy-fixture", "integration-tests"], "test_only_payload": {"archive": fixture_archive.name, "caddy_fixture_binary": "bin/amd64/open-card-caddy-fixture"}, "migrations": {"first": "0001", "current_count": len(migration_files(repo)), "n_minus_one_count": len(migration_files(repo)) - 1}, "fixed_inputs": {"assets": "inputs/assets/assets.sha256", "debs": "inputs/debs/debs.sha256"}, "supply_chain": supply_chain.relative_to(output).as_posix(), "sbom": sbom.relative_to(output).as_posix(), "source_checksum": source_checksum.relative_to(output).as_posix(), "bundle_checksum": "bundle-manifest.sha256", "files": files}
    manifest_path = output / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    manifest_path.chmod(0o640)
    set_epoch(manifest_path)
    bundle_checksum = write_checksums(output, [path for path in output.rglob("*") if path.is_file()], "bundle-manifest.sha256")
    # A final scan covers every generated textual and executable input. Hash
    # files are excluded from credential-pattern scanning only because they are
    # hexadecimal by construction.
    for path in output.rglob("*"):
        if path.is_file() and path.name not in {"source-manifest.sha256", "licenses-manifest.sha256", "bundle-manifest.sha256"}:
            relative_parts = path.relative_to(output).parts
            if path.name == "m7-fixtures.tar":
                scan_fixture_archive(path)
            elif relative_parts[:1] == ("m7-fixtures-tree",):
                scan_fixture_content(path.as_posix(), path.read_bytes())
            else:
                scan_credentials(path, skip_binary=path.suffix in {".deb", ".gz", ".tar"})
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble",))
    parser.add_argument("--stage-root", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--debs-root", required=True, type=Path)
    parser.add_argument("--assets-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = assemble(args.stage_root.resolve(), args.repo_root.resolve(), args.output_root.resolve(), args.debs_root.resolve(), args.assets_root.resolve())
    except M7Error as exc:
        # assemble() only accepts a path that did not exist at entry. Remove a
        # partial output so a failed verification cannot be mistaken for a
        # usable canonical source tree or leave debris for the next attempt.
        if args.output_root.exists() and not args.output_root.is_symlink():
            shutil.rmtree(args.output_root)
        print(json.dumps({"ready": False, "error": str(exc)}, sort_keys=True))
        return 64
    print(json.dumps({"ready": True, **result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
