#!/usr/bin/env python3
"""Build and verify reproducible, credential-free clean-worker bundles.

The archive is deliberately a plain POSIX/GNU tar file.  It contains only a
canonical manifest and explicitly named payload files; it never expands
directories, follows symlinks, or touches a VM/network/service.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, BinaryIO


FORMAT_VERSION = 1
MANIFEST_PATH = "manifest.json"
MAX_INPUTS = 128
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
FILE_MODE = 0o644
ARCHIVE_PATH_PATTERN = re.compile(r"payload/[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
FORBIDDEN_NAME_PARTS = frozenset(
    {
        ".env",
        "authorized_keys",
        "credential",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
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


class BundleError(ValueError):
    """Raised when an offline bundle is structurally or policy invalid."""


def sha256_checked(handle: BinaryIO, label: str) -> str:
    digest = hashlib.sha256()
    overlap = b""
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
        scan = overlap + chunk
        if any(pattern.search(scan) for pattern in SECRET_PATTERNS):
            raise BundleError(f"credential material is forbidden: {label}")
        overlap = scan[-256:]
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def require_absolute_path(value: str, field: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise BundleError(f"{field} must be an absolute path")
    return path


def validate_archive_path(archive_path: str) -> None:
    if not ARCHIVE_PATH_PATTERN.fullmatch(archive_path):
        raise BundleError("input archive path must be payload/<safe-flat-filename>")
    lowered = archive_path.lower()
    name = archive_path.rsplit("/", 1)[1]
    stem_parts = re.split(r"[._+-]+", name.lower())
    if (
        name.lower() == ".env"
        or name.lower().startswith(".env.")
        or any(part in FORBIDDEN_NAME_PARTS for part in stem_parts)
        or lowered.endswith(FORBIDDEN_SUFFIXES)
    ):
        raise BundleError(f"input archive path is credential-like: {archive_path}")


def assert_regular_source(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BundleError(f"cannot stat input: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BundleError(f"input must be a regular non-symlink file: {path}")
    if info.st_size < 0 or info.st_size > MAX_TOTAL_BYTES:
        raise BundleError(f"input exceeds size limit: {path}")
    return info


def parse_input(value: str) -> tuple[str, Path]:
    archive_path, separator, source_value = value.partition("=")
    if not separator or not archive_path or not source_value:
        raise BundleError("--input must be payload/<safe-flat-filename>=/absolute/source/file")
    validate_archive_path(archive_path)
    source = require_absolute_path(source_value, "input source")
    return archive_path, source


def parse_inputs(values: list[str]) -> list[tuple[str, Path]]:
    if not values:
        raise BundleError("at least one explicit --input is required")
    if len(values) > MAX_INPUTS:
        raise BundleError(f"at most {MAX_INPUTS} inputs are allowed")
    entries = [parse_input(value) for value in values]
    names = [name for name, _ in entries]
    if len(names) != len(set(names)):
        raise BundleError("duplicate archive input paths are forbidden")
    total_size = 0
    for _, source in entries:
        info = assert_regular_source(source)
        total_size += info.st_size
        if total_size > MAX_TOTAL_BYTES:
            raise BundleError("combined inputs exceed size limit")
    return sorted(entries, key=lambda item: item[0])


def manifest_for(entries: list[tuple[str, Path]]) -> dict[str, Any]:
    manifest_entries: list[dict[str, Any]] = []
    for archive_path, source in entries:
        info = assert_regular_source(source)
        with source.open("rb") as handle:
            digest = sha256_checked(handle, str(source))
        manifest_entries.append(
            {
                "mode": f"{FILE_MODE:04o}",
                "path": archive_path,
                "sha256": digest,
                "size_bytes": info.st_size,
            }
        )
    return {"entries": manifest_entries, "format_version": FORMAT_VERSION}


def tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = FILE_MODE
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def write_archive(output: Path, manifest_bytes: bytes, entries: list[tuple[str, Path]], overwrite: bool) -> None:
    if output.exists() and not overwrite:
        raise BundleError("output already exists; pass --overwrite to replace it")
    if output.is_symlink():
        raise BundleError("output must not be a symlink")
    if not output.parent.is_dir():
        raise BundleError("output parent directory does not exist")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w:", format=tarfile.GNU_FORMAT) as archive:
                archive.addfile(tar_info(MANIFEST_PATH, len(manifest_bytes)), io.BytesIO(manifest_bytes))
                for archive_path, source in entries:
                    info = assert_regular_source(source)
                    with source.open("rb") as handle:
                        archive.addfile(tar_info(archive_path, info.st_size), handle)
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load_manifest(member: tarfile.TarInfo, archive: tarfile.TarFile) -> dict[str, Any]:
    if member.name != MANIFEST_PATH or not member.isfile():
        raise BundleError("first archive member must be manifest.json")
    handle = archive.extractfile(member)
    if handle is None:
        raise BundleError("manifest cannot be read")
    raw = handle.read()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError("manifest is not valid UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or canonical_json(manifest) != raw:
        raise BundleError("manifest must use the canonical JSON encoding")
    if set(manifest) != {"entries", "format_version"}:
        raise BundleError("manifest contains unsupported fields")
    if manifest.get("format_version") != FORMAT_VERSION or not isinstance(manifest.get("entries"), list):
        raise BundleError("manifest format is unsupported")
    return manifest


def assert_member_metadata(member: tarfile.TarInfo, expected_name: str) -> None:
    if member.name != expected_name or not member.isfile():
        raise BundleError(f"unexpected archive member: {member.name}")
    if member.mode != FILE_MODE or member.uid != 0 or member.gid != 0 or member.mtime != 0:
        raise BundleError(f"non-reproducible metadata on: {member.name}")
    if member.uname or member.gname or member.pax_headers:
        raise BundleError(f"unexpected owner or extended headers on: {member.name}")


def validate_archive(archive_path: Path) -> dict[str, Any]:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise BundleError("archive must be a regular non-symlink file")
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_INPUTS + 1:
                raise BundleError("archive member count is invalid")
            assert_member_metadata(members[0], MANIFEST_PATH)
            manifest = load_manifest(members[0], archive)
            entries = manifest["entries"]
            if not entries or len(entries) > MAX_INPUTS:
                raise BundleError("manifest entry count is invalid")
            expected_names: list[str] = []
            expected: dict[str, dict[str, Any]] = {}
            total_size = 0
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"mode", "path", "sha256", "size_bytes"}:
                    raise BundleError("manifest entry must be an object")
                name = entry.get("path")
                if not isinstance(name, str):
                    raise BundleError("manifest path is invalid")
                validate_archive_path(name)
                if name in expected:
                    raise BundleError("manifest contains duplicate paths")
                if entry.get("mode") != f"{FILE_MODE:04o}" or not isinstance(entry.get("size_bytes"), int) or entry["size_bytes"] < 0:
                    raise BundleError("manifest entry metadata is invalid")
                if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                    raise BundleError("manifest entry checksum is invalid")
                total_size += entry["size_bytes"]
                if total_size > MAX_TOTAL_BYTES:
                    raise BundleError("manifest total size exceeds limit")
                expected_names.append(name)
                expected[name] = entry
            if expected_names != sorted(expected_names):
                raise BundleError("manifest entries must be sorted")
            if [member.name for member in members[1:]] != expected_names:
                raise BundleError("archive members do not exactly match manifest")
            for member in members[1:]:
                assert_member_metadata(member, member.name)
                entry = expected[member.name]
                if member.size != entry["size_bytes"]:
                    raise BundleError(f"size mismatch: {member.name}")
                handle = archive.extractfile(member)
                if handle is None:
                    raise BundleError(f"cannot read payload: {member.name}")
                if sha256_checked(handle, member.name) != entry["sha256"]:
                    raise BundleError(f"checksum mismatch: {member.name}")
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("archive is not a valid uncompressed tar file") from exc
    return {
        "entries": len(expected),
        "format_version": FORMAT_VERSION,
        "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "size_bytes": archive_path.stat().st_size,
        "valid": True,
    }


def build(output: Path, input_values: list[str], overwrite: bool) -> dict[str, Any]:
    entries = parse_inputs(input_values)
    manifest = manifest_for(entries)
    write_archive(output, canonical_json(manifest), entries, overwrite)
    return validate_archive(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="build a deterministic plain-tar bundle")
    build_parser.add_argument("--output", required=True, help="absolute output .tar path")
    build_parser.add_argument("--input", action="append", default=[], help="payload/name=/absolute/source/file; repeat for each file")
    build_parser.add_argument("--overwrite", action="store_true", help="replace an existing regular output file")
    validate_parser = commands.add_parser("validate", help="validate a bundle without extracting it")
    validate_parser.add_argument("--archive", required=True, help="absolute archive path")
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(require_absolute_path(args.output, "output"), args.input, args.overwrite)
        else:
            result = validate_archive(require_absolute_path(args.archive, "archive"))
    except BundleError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 64
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
