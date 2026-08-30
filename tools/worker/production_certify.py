#!/usr/bin/env python3
"""Certify two independently built Open Card RC1 candidate sets.

This verifier is deliberately an artifact-equality gate.  It does not assert
production acceptance or substitute for security, vulnerability, or runtime
upgrade gates.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import sys
from pathlib import Path, PurePosixPath


ARCHES = ("amd64", "arm64")
VERSION = "0.8.0-rc.1"
MIGRATION = "0024"
RC0_SOURCE_COMMIT = "35a2b198ac52949af3477475d89d4813b46a9490"
RC0_LINEAGES = {
    "amd64": {
        "version": "0.8.0-rc.0",
        "migration_version": "0023",
        "source_commit": RC0_SOURCE_COMMIT,
        "release_manifest_sha256": "3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253",
        "archive_sha256": "abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc",
        "bundle_manifest_sha256": "960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392",
    },
    "arm64": {
        "version": "0.8.0-rc.0",
        "migration_version": "0023",
        "source_commit": RC0_SOURCE_COMMIT,
        "release_manifest_sha256": "e4f56105b3d184313d51365c7fff40b9f68111815def83c5e5985bc182177a57",
        "archive_sha256": "9560df1d4a739c729d857cd93b989b99976da0e86983ffa026d13202339d57b9",
        "bundle_manifest_sha256": "fdfd6b6108870118714b70c9007937585fc0429d14fa9d64010a80016edc2a15",
    },
}
ARTIFACTS = {
    "release_manifest": "release/manifest.json",
    "archive": f"open-card-{VERSION}-production.tar.gz",
    "bundle_manifest": "bundle-manifest.sha256",
    "source_manifest": "release/source-manifest.sha256",
    "sbom": "release/sbom.spdx.json",
    "live_web_attestation": "release/attestations/live-web.json",
    "production_bundle": "production-bundle.json",
}
RC1_BINARIES = [
    "open-card-server", "open-card-agent", "open-card-static-server",
    "open-card-secretctl", "open-card-security-probe", "open-card-imagegc",
    "open-card-admin", "open-card-upgrade",
]
EXPECTED_ROOT = {
    "release",
    "build-record.json",
    ARTIFACTS["archive"],
    ARTIFACTS["bundle_manifest"],
    ARTIFACTS["production_bundle"],
}
HEX_40 = re.compile(r"^[a-f0-9]{40}$")
HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class CertificationError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


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
        raise CertificationError(f"{label} is missing") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise CertificationError(f"{label} must be a regular non-symlink file")


def directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise CertificationError(f"{label} is missing") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise CertificationError(f"{label} must be a real directory")


def strict_json(path: Path, label: str) -> dict[str, object]:
    regular(path, label)
    try:
        def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = item
            return result

        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise CertificationError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise CertificationError(f"{label} must be a JSON object")
    return value


def safe_relative(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CertificationError("release manifest has an unsafe path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise CertificationError("release manifest has an unsafe path")
    return path


def verify_source(worktree: Path, commit: str) -> tuple[dict[str, bool], Path]:
    directory(worktree, "source worktree")
    try:
        head = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        detached = subprocess.run(
            ["git", "-C", str(worktree), "symbolic-ref", "-q", "HEAD"],
            text=True,
            capture_output=True,
        ).returncode == 1
        clean = not subprocess.run(
            ["git", "-C", str(worktree), "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        common_dir = Path(
            subprocess.run(
                ["git", "-C", str(worktree), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
        ).resolve()
    except subprocess.CalledProcessError as error:
        raise CertificationError("source worktree Git verification failed") from error
    if head != commit or not detached or not clean:
        raise CertificationError("source worktree is not clean, detached, and fixed at the requested commit")
    return {"clean": True, "detached": True, "exact_commit": True}, common_dir


def verify_archive(
    archive: Path,
    release_entries: dict[str, tuple[str, int]],
    manifest_path: Path,
) -> None:
    regular(archive, "candidate archive")
    expected = {f"release/{path}" for path in release_entries} | {"release/manifest.json"}
    seen: set[str] = set()
    try:
        with tarfile.open(archive, "r:gz") as source:
            for member in source.getmembers():
                path = PurePosixPath(member.name)
                if not member.name or "\\" in member.name or path.is_absolute() or ".." in path.parts:
                    raise CertificationError("candidate archive contains an unsafe member path")
                if not member.isfile():
                    raise CertificationError("candidate archive contains a non-regular member")
                normalized = path.as_posix()
                if normalized in seen:
                    raise CertificationError("candidate archive contains duplicate members")
                seen.add(normalized)
                stream = source.extractfile(member)
                if stream is None:
                    raise CertificationError("candidate archive member cannot be read")
                with stream:
                    member_digest = hashlib.sha256(stream.read()).hexdigest()
                if normalized == "release/manifest.json":
                    if member.mode & 0o777 != 0o644 or member_digest != sha256(manifest_path):
                        raise CertificationError("candidate archive manifest member is not bound to release manifest")
                else:
                    relative = normalized.removeprefix("release/")
                    expected_entry = release_entries.get(relative)
                    if expected_entry is None or member_digest != expected_entry[0] or member.mode & 0o777 != expected_entry[1]:
                        raise CertificationError("candidate archive member is not bound to release manifest")
    except tarfile.TarError as error:
        raise CertificationError("candidate archive is invalid") from error
    if len(seen) != 69 or seen != expected:
        raise CertificationError("candidate archive does not contain the fixed safe member set")


def publish_no_replace(candidate: Path, output: Path) -> None:
    if candidate.parent.resolve() != output.parent.resolve():
        raise CertificationError("certification candidate and output must share one parent")
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        try:
            rename = libc.renamex_np
        except AttributeError as error:
            raise CertificationError("atomic no-replace certification publication is unavailable") from error
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(candidate), os.fsencode(output), 0x00000004)
    elif sys.platform.startswith("linux"):
        at_fdcwd = -100
        try:
            rename = libc.renameat2
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            result = rename(at_fdcwd, os.fsencode(candidate), at_fdcwd, os.fsencode(output), 0x00000001)
        except AttributeError as error:
            raise CertificationError("atomic no-replace certification publication is unavailable") from error
    else:
        raise CertificationError("atomic no-replace certification publication is unavailable")
    if result == 0:
        return
    if ctypes.get_errno() == errno.EEXIST:
        raise CertificationError("refusing to overwrite certification output")
    raise CertificationError("atomic no-replace certification publication failed")


def normalized_build_semantics(
    record: dict[str, object], arch: str, source_commit: str, source_worktree: Path
) -> dict[str, object]:
    build_tool = record.get("build_tool")
    if not isinstance(build_tool, dict) or set(build_tool) != {"commit", "driver", "bundle"} or build_tool.get("commit") != source_commit:
        raise CertificationError("build record build-tool metadata is invalid")
    expected_paths = {
        "driver": "tools/worker/production_build.py",
        "bundle": "tools/worker/production_bundle.py",
    }
    for name in ("driver", "bundle"):
        tool = build_tool[name]
        if not isinstance(tool, dict) or set(tool) != {"commit", "relative_path", "commit_blob", "sha256"}:
            raise CertificationError("build record build-tool metadata is invalid")
        if tool["commit"] != build_tool["commit"] or not HEX_40.fullmatch(str(tool["commit"])) or not HEX_40.fullmatch(str(tool["commit_blob"])) or not HEX_64.fullmatch(str(tool["sha256"])):
            raise CertificationError("build record build-tool metadata is invalid")
        relative = tool["relative_path"]
        if relative != expected_paths[name] or Path(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
            raise CertificationError("build record build-tool metadata is invalid")
        source_path = source_worktree.joinpath(*PurePosixPath(relative).parts)
        regular(source_path, "build-tool source")
        if sha256(source_path) != tool["sha256"]:
            raise CertificationError("build record build-tool hash is not bound to source worktree")
        try:
            blob = subprocess.run(
                ["git", "-C", str(source_worktree), "rev-parse", f"{source_commit}:{relative}"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
        except subprocess.CalledProcessError as error:
            raise CertificationError("build-tool path is not tracked at the requested source commit") from error
        if blob != tool["commit_blob"]:
            raise CertificationError("build record build-tool blob is not bound to source commit")
    tools = record.get("tools")
    expected_tool_keys = {"go_environment", "git_version", "node_version", "npm_version", "python_version"}
    if not isinstance(tools, dict) or set(tools) != expected_tool_keys or not isinstance(tools.get("go_environment"), dict):
        raise CertificationError("build record tool environment is invalid")
    if any(not isinstance(tools[key], str) or not tools[key] for key in expected_tool_keys - {"go_environment"}):
        raise CertificationError("build record tool environment is invalid")
    go_environment = tools["go_environment"]
    if (
        go_environment.get("GOOS") != "linux"
        or go_environment.get("GOARCH") != arch
        or go_environment.get("CGO_ENABLED") not in {"0", 0}
        or go_environment.get("GOWORK") != "off"
    ):
        raise CertificationError("build record Go environment is invalid")
    keys = (
        "schema_version",
        "production_accepted",
        "candidate",
        "build_tool",
        "runtime_inputs",
        "tools",
        "stage_files",
        "live_web",
        "bundle",
        "n_minus_one",
    )
    value = {key: record.get(key) for key in keys}
    return value


def verify_candidate(
    root: Path, arch: str, source_commit: str, source_worktree: Path
) -> dict[str, object]:
    directory(root, f"{arch} candidate")
    if {item.name for item in root.iterdir()} != EXPECTED_ROOT:
        raise CertificationError(f"{arch} candidate root does not contain exactly the required evidence")
    release = root / "release"
    directory(release, f"{arch} release")
    manifest = strict_json(release / "manifest.json", "release manifest")
    expected_manifest_keys = {
        "schema_version", "product", "version", "release_id", "architecture",
        "migration_version", "source_commit", "protocol", "config_dir", "data_dir",
        "compatibility", "n_minus_one", "files",
    }
    if set(manifest) != expected_manifest_keys or manifest.get("schema_version") != 1 or manifest.get("product") != "open-card":
        raise CertificationError(f"{arch} release manifest schema is invalid")
    if (
        manifest.get("version"),
        manifest.get("migration_version"),
        manifest.get("source_commit"),
        manifest.get("architecture"),
    ) != (VERSION, MIGRATION, source_commit, arch):
        raise CertificationError(f"{arch} release manifest tuple is invalid")
    if manifest.get("n_minus_one") != RC0_LINEAGES[arch]:
        raise CertificationError(f"{arch} release manifest has invalid frozen N-1 lineage")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 68:
        raise CertificationError(f"{arch} release manifest must declare exactly 68 files")
    release_entries: dict[str, tuple[str, int]] = {}
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "mode"}:
            raise CertificationError("release manifest file entry is invalid")
        relative = safe_relative(entry["path"])
        digest, mode = entry["sha256"], entry["mode"]
        if relative.as_posix() in release_entries or not HEX_64.fullmatch(str(digest)) or not isinstance(mode, int) or isinstance(mode, bool):
            raise CertificationError("release manifest file entry is invalid")
        target = release.joinpath(*relative.parts)
        regular(target, "release payload")
        if sha256(target) != digest or stat.S_IMODE(target.stat().st_mode) != mode:
            raise CertificationError("release payload does not match manifest")
        release_entries[relative.as_posix()] = (digest, mode)
    actual = set()
    for item in release.rglob("*"):
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise CertificationError("release contains an unsafe entry")
        if item.is_file() and item.name != "manifest.json":
            actual.add(item.relative_to(release).as_posix())
    if actual != set(release_entries):
        raise CertificationError("release file set does not match manifest")
    archive = root / ARTIFACTS["archive"]
    verify_archive(archive, release_entries, release / "manifest.json")
    bundle_manifest = root / ARTIFACTS["bundle_manifest"]
    regular(bundle_manifest, "bundle manifest")
    expected_bundle = (
        f"{sha256(archive)}  {archive.name}\n"
        f"{sha256(release / 'manifest.json')}  release/manifest.json\n"
    )
    if bundle_manifest.read_text(encoding="utf-8") != expected_bundle:
        raise CertificationError("bundle manifest does not match candidate artifacts")
    hashes = {}
    for name, relative in ARTIFACTS.items():
        path = root / relative
        regular(path, name)
        hashes[name] = sha256(path)
    build = strict_json(root / "build-record.json", "build record")
    expected_build_keys = {
        "schema_version", "production_accepted", "candidate", "build_tool",
        "runtime_inputs", "tools", "commands", "stage_files", "live_web", "bundle",
        "n_minus_one",
    }
    if set(build) != expected_build_keys:
        raise CertificationError(f"{arch} build record schema is invalid")
    candidate = build.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {"version", "migration_version", "architecture", "source_commit"} or build.get("production_accepted") is not False or (
        candidate.get("version"), candidate.get("migration_version"), candidate.get("source_commit"), candidate.get("architecture")
    ) != (VERSION, MIGRATION, source_commit, arch):
        raise CertificationError(f"{arch} build record tuple is invalid")
    bundle_record = build.get("bundle")
    if not isinstance(bundle_record, dict) or bundle_record != {
        "archive": archive.name,
        "archive_sha256": hashes["archive"],
        "manifest_sha256": hashes["release_manifest"],
        "bundle_manifest_sha256": hashes["bundle_manifest"],
    }:
        raise CertificationError(f"{arch} build record is not bound to candidate artifacts")
    live_web = build.get("live_web")
    if (
        not isinstance(live_web, dict)
        or set(live_web) != {"build_metadata_sha256", "dist_tree_sha256", "attestation_sha256", "gate3_status"}
        or live_web.get("attestation_sha256") != hashes["live_web_attestation"]
    ):
        raise CertificationError(f"{arch} build record is not bound to live web attestation")
    expected_record_lineage = {
        **RC0_LINEAGES[arch],
        "status": "verified_local_candidate",
        "release_embedded": False,
    }
    if build.get("n_minus_one") != expected_record_lineage:
        raise CertificationError(f"{arch} build record lacks RC0 lineage")
    metadata = strict_json(root / ARTIFACTS["production_bundle"], "production bundle metadata")
    expected_metadata_keys = {
        "schema_version", "product", "version", "source_commit", "production_accepted",
        "candidate_status", "n_minus_one", "migration_version", "live_web",
        "production_binaries", "excluded",
    }
    expected_metadata_lineage = {
        "version": "0.8.0-rc.0",
        "migration_version": "0023",
        "source_commit": RC0_SOURCE_COMMIT,
        "status": "verified_local_candidate",
        "release_embedded": False,
        "manifest_sha256": RC0_LINEAGES[arch]["release_manifest_sha256"],
        "archive_sha256": RC0_LINEAGES[arch]["archive_sha256"],
        "bundle_manifest_sha256": RC0_LINEAGES[arch]["bundle_manifest_sha256"],
    }
    if (
        set(metadata) != expected_metadata_keys
        or metadata.get("schema_version") != 1
        or metadata.get("product") != "open-card"
        or metadata.get("production_accepted") is not False
        or metadata.get("candidate_status") != "upgrade_candidate"
        or (metadata.get("version"), metadata.get("migration_version"), metadata.get("source_commit")) != (VERSION, MIGRATION, source_commit)
        or metadata.get("n_minus_one") != expected_metadata_lineage
    ):
        raise CertificationError(f"{arch} production bundle metadata is invalid")
    live_web_metadata = metadata.get("live_web")
    if (
        not isinstance(live_web_metadata, dict)
        or set(live_web_metadata) != {"status", "bundle_structure_verified", "public_domain_verified", "attestation_sha256"}
        or live_web_metadata.get("attestation_sha256") != hashes["live_web_attestation"]
        or metadata.get("production_binaries") != RC1_BINARIES
        or metadata.get("excluded") != ["open-card-caddy-fixture", "integration test binaries", "fixture archives"]
    ):
        raise CertificationError(f"{arch} production bundle metadata is not bound to candidate artifacts")
    return {
        "artifact_hashes": hashes,
        "semantic_digest": hashlib.sha256(canonical_json(normalized_build_semantics(build, arch, source_commit, source_worktree))).hexdigest(),
        "lineage": RC0_LINEAGES[arch],
    }


def certify(
    source_a: Path,
    source_b: Path,
    candidates_a: Path,
    candidates_b: Path,
    output: Path,
    source_commit: str,
) -> dict[str, object]:
    if not HEX_40.fullmatch(source_commit):
        raise CertificationError("source commit must be lowercase hexadecimal")
    if source_a.resolve() == source_b.resolve():
        raise CertificationError("source worktrees must be distinct directories")
    if output.exists():
        raise CertificationError("refusing to overwrite certification output")
    directory(output.parent, "certification output parent")
    source_a_facts, source_a_common = verify_source(source_a, source_commit)
    source_b_facts, source_b_common = verify_source(source_b, source_commit)
    if source_a_common == source_b_common:
        raise CertificationError("source worktrees must not share a Git common directory")
    source_facts = [source_a_facts, source_b_facts]
    for candidate_set in (candidates_a, candidates_b):
        directory(candidate_set, "candidate set")
        if {item.name for item in candidate_set.iterdir()} != set(ARCHES):
            raise CertificationError("candidate set does not contain exactly amd64 and arm64 candidates")
    result: dict[str, object] = {}
    for arch in ARCHES:
        left = verify_candidate(candidates_a / arch, arch, source_commit, source_a)
        right = verify_candidate(candidates_b / arch, arch, source_commit, source_b)
        if left["artifact_hashes"] != right["artifact_hashes"] or left["semantic_digest"] != right["semantic_digest"]:
            raise CertificationError(f"{arch} candidate sets are not byte-equivalent")
        result[arch] = {"equality": True, **left}
    triples = {
        arch: tuple(result[arch]["artifact_hashes"][name] for name in ("release_manifest", "archive", "bundle_manifest"))
        for arch in ARCHES
    }
    if triples["amd64"] == triples["arm64"]:
        raise CertificationError("amd64 and arm64 artifact triples must be distinct")
    certification = {
        "schema": "open-card-production-certification.v1",
        "scope": "artifact_equality_only",
        "production_accepted": False,
        "source": {"commit": source_commit, "distinct_clean_detached_clones": source_facts},
        "architectures": result,
    }
    certification_bytes = canonical_json(certification)
    certification_sha256 = hashlib.sha256(certification_bytes).hexdigest()
    index = {
        "schema": "open-card-release-index.v1",
        "scope": "artifact_equality_only",
        "production_accepted": False,
        "version": VERSION,
        "migration_version": MIGRATION,
        "source_commit": source_commit,
        "certification_sha256": certification_sha256,
        "architectures": {
            arch: {
                "artifact_triple": dict(zip(("release_manifest", "archive", "bundle_manifest"), triples[arch])),
                "rc0_lineage": RC0_LINEAGES[arch],
            }
            for arch in ARCHES
        },
    }
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.certify-", dir=output.parent))
    try:
        (temporary / "certification.json").write_bytes(certification_bytes)
        (temporary / "release-index.json").write_bytes(canonical_json(index))
        for path in temporary.iterdir():
            path.chmod(0o644)
        temporary.chmod(0o750)
        publish_no_replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return certification


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-a", required=True, type=Path)
    parser.add_argument("--source-b", required=True, type=Path)
    parser.add_argument("--candidates-a", required=True, type=Path)
    parser.add_argument("--candidates-b", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        value = certify(args.source_a, args.source_b, args.candidates_a, args.candidates_b, args.output, args.source_commit)
    except CertificationError as error:
        print(f"production certification: {error}")
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
