#!/usr/bin/env python3
"""Assemble the post-RC production candidate without rewriting M7 history.

This helper is intentionally local-only: it copies only prebuilt, checksum-able
inputs into a 0.8.0-rc.1 release. It does not synthesize an N-1 binary. An
operator upgrading from 0.7.0-rc.1 must supply an authentic prior artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tarfile
from pathlib import Path

VERSION = "0.8.0-rc.1"
N_MINUS_ONE = "0.7.0-rc.1"
CURRENT_MIGRATION = "0023"
ARCHES = ("amd64", "arm64")
BINARIES = (
    "open-card-server", "open-card-agent", "open-card-static-server",
    "open-card-secretctl", "open-card-security-probe", "open-card-imagegc",
    "open-card-admin",
)
RUNTIME = ("buildkitd", "buildctl", "buildkit-runc", "rootlesskit", "docker-buildx", "caddy")
UNITS = (
    "open-card-server.service", "open-card-agent.service", "open-card-buildkit.service",
    "open-card-caddy.service", "open-card-edge.service",
)


class ProductionBundleError(RuntimeError):
    pass


def regular(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ProductionBundleError(f"required input is missing: {path}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProductionBundleError(f"required input must be a regular non-symlink file: {path}")


def directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ProductionBundleError(f"required directory is missing: {path}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProductionBundleError(f"required path must be a directory: {path}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(mode)


def copy_file(source: Path, target: Path, mode: int) -> None:
    regular(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def copy_tree(source: Path, target: Path, *, mode: int = 0o640) -> None:
    directory(source)
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if item.is_symlink():
            raise ProductionBundleError(f"symlink is forbidden in production input: {item}")
        if item.is_dir():
            (target / relative).mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            copy_file(item, target / relative, mode)
        else:
            raise ProductionBundleError(f"unsupported production input type: {item}")


def release_files(release: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for item in sorted(release.rglob("*")):
        if item.is_file() and item.name != "manifest.json":
            relative = item.relative_to(release).as_posix()
            if "/tests/" in f"/{relative}" or "fixture" in relative.lower() or relative.endswith(".test"):
                raise ProductionBundleError(f"test-only payload is forbidden in production release: {relative}")
            entries.append({"path": relative, "sha256": sha256(item), "mode": stat.S_IMODE(item.stat().st_mode)})
    return entries


def make_source_manifest(repo: Path, release: Path) -> None:
    candidates = [repo / "go.mod", repo / "go.sum", repo / "api/openapi/openapi.yaml"]
    for root in (repo / "cmd", repo / "internal"):
        candidates.extend(sorted(path for path in root.rglob("*.go") if not path.name.endswith("_test.go")))
    lines = [f"{sha256(path)}  {path.relative_to(repo).as_posix()}" for path in candidates if path.is_file()]
    target = release / "source-manifest.sha256"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    target.chmod(0o640)


def make_sbom(release: Path) -> None:
    packages = []
    for entry in release_files(release):
        packages.append({"name": entry["path"], "versionInfo": VERSION, "checksums": [{"algorithm": "SHA256", "checksumValue": entry["sha256"]}]})
    write_json(release / "sbom.spdx.json", {"spdxVersion": "SPDX-2.3", "name": f"open-card-{VERSION}", "packages": packages})


def write_tar(root: Path, release: Path) -> Path:
    archive = root / f"open-card-{VERSION}-production.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as output:
        for item in sorted(release.rglob("*")):
            if item.is_file():
                info = output.gettarinfo(str(item), arcname=f"release/{item.relative_to(release).as_posix()}")
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                with item.open("rb") as stream:
                    output.addfile(info, stream)
    return archive


def verify_n_minus_one(release: Path, expected_manifest_sha256: str, arch: str) -> dict[str, object]:
    directory(release)
    manifest_path = release / "manifest.json"
    regular(manifest_path)
    if expected_manifest_sha256 != sha256(manifest_path):
        raise ProductionBundleError("N-1 manifest checksum does not match the supplied expectation")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBundleError("N-1 manifest is not valid JSON") from error
    if not isinstance(manifest, dict) or manifest.get("version") != N_MINUS_ONE or manifest.get("migration_version") != "0021" or manifest.get("architecture") != arch:
        raise ProductionBundleError("N-1 release must be an authentic 0.7.0-rc.1/0021 manifest for the selected architecture")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ProductionBundleError("N-1 manifest has no release files")
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not isinstance(entry.get("sha256"), str):
            raise ProductionBundleError("N-1 manifest file entry is invalid")
        path = Path(entry["path"])
        if path.is_absolute() or ".." in path.parts:
            raise ProductionBundleError("N-1 manifest has an unsafe file path")
        target = release.joinpath(*path.parts)
        regular(target)
        if sha256(target) != entry["sha256"]:
            raise ProductionBundleError("N-1 release file checksum mismatch")
    raise ProductionBundleError("authentic N-1 provenance is not pinned by this repository; production publication is blocked")


def verify_live_web(dist: Path) -> None:
    directory(dist)
    regular(dist / "index.html")
    marker = dist / ".open-card-live-build.json"
    regular(marker)
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBundleError("Live web build marker is invalid") from error
    if value != {"api_mode": "live"}:
        raise ProductionBundleError("web/dist was not built with the required Live API mode")
    raise ProductionBundleError("Gate 3 has not supplied a verified Live web build attestation; production publication is blocked")


def assemble(stage: Path, repo: Path, output: Path, arch: str, n_minus_one_release: Path | None, n_minus_one_manifest_sha256: str | None, web_dist: Path, *, structure_only: bool = False) -> dict[str, object]:
    if arch not in ARCHES:
        raise ProductionBundleError(f"unsupported release architecture: {arch}")
    directory(stage)
    directory(repo)
    n_minus_one: dict[str, object] | None = None
    if not structure_only:
        if n_minus_one_release is None or not isinstance(n_minus_one_manifest_sha256, str) or len(n_minus_one_manifest_sha256) != 64 or any(character not in "0123456789abcdef" for character in n_minus_one_manifest_sha256):
            raise ProductionBundleError("N-1 manifest checksum must be lowercase SHA-256")
        n_minus_one = verify_n_minus_one(n_minus_one_release, n_minus_one_manifest_sha256, arch)
        verify_live_web(web_dist)
    if output.exists():
        raise ProductionBundleError("refusing to overwrite production bundle output")
    release = output / "release"
    output.mkdir(parents=True)
    for binary in BINARIES:
        copy_file(stage / "binaries" / arch / binary, release / "bin" / binary, 0o755)
    for binary in RUNTIME:
        copy_file(stage / "runtime" / arch / binary, release / "bin" / binary, 0o755)
    for unit in UNITS:
        copy_file(repo / "deploy/systemd" / unit, release / "systemd" / unit, 0o644)
    copy_file(repo / "deploy/caddy/open-card-edge.Caddyfile.example", release / "caddy/open-card-edge.Caddyfile.example", 0o644)
    copy_file(repo / "deploy/caddy/open-card-edge.env.example", release / "caddy/open-card-edge.env.example", 0o640)
    copy_tree(repo / "migrations/control-plane", release / "migrations/control-plane")
    if not (release / "migrations/control-plane/0023_source_uploads.sql").is_file():
        raise ProductionBundleError("production release is missing migration 0023")
    copy_tree(repo / "docs/licenses", release / "docs/licenses")
    copy_tree(web_dist, release / "web/dist")
    make_source_manifest(repo, release)
    make_sbom(release)
    if structure_only:
        metadata = {
            "schema_version": 1, "product": "open-card", "version": VERSION,
            "production_ready": False,
            "n_minus_one": {"version": N_MINUS_ONE, "status": "blocked_no_pinned_provenance"},
            "live_web": {"status": "blocked_gate3_unverified_live_input"},
            "structure_only": True,
        }
        write_json(output / "production-bundle.json", metadata)
        (output / "STRUCTURE-ONLY-NOT-INSTALLABLE").write_text("No release manifest or archive is emitted until authentic N-1 and Gate 3 Live attestations are supplied.\n", encoding="utf-8")
        return metadata
    manifest = {
        "schema_version": 1, "product": "open-card", "version": VERSION,
        "release_id": f"release-{VERSION}", "architecture": arch,
        "migration_version": CURRENT_MIGRATION, "protocol": "1.1",
        "config_dir": "/etc/open-card", "data_dir": "/var/lib/open-card",
        "compatibility": {"min_data_version": 1, "max_data_version": 22, "min_agent_protocol": "1.0", "max_agent_protocol": "1.1", "requires_data_backup": True},
        "files": release_files(release),
    }
    write_json(release / "manifest.json", manifest, 0o644)
    archive = write_tar(output, release)
    bundle_checksum = output / "bundle-manifest.sha256"
    bundle_checksum.write_text(f"{sha256(archive)}  {archive.name}\n{sha256(release / 'manifest.json')}  release/manifest.json\n", encoding="utf-8")
    bundle_checksum.chmod(0o640)
    metadata = {
        "schema_version": 1, "product": "open-card", "version": VERSION,
        "n_minus_one": {"version": N_MINUS_ONE, "status": "external_authentic_release_verified", "release_embedded": False, "manifest_sha256": n_minus_one_manifest_sha256, "release_id": n_minus_one.get("release_id") if n_minus_one else None},
        "migration_version": CURRENT_MIGRATION,
        "live_web": {"status": "verified_input", "bundle_structure_verified": True, "live_domain_verified": True},
        "production_binaries": list(BINARIES), "excluded": ["open-card-caddy-fixture", "integration test binaries", "fixture archives"],
    }
    write_json(output / "production-bundle.json", metadata)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assemble", nargs="?")
    parser.add_argument("--stage-root", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--n-minus-one-release", type=Path)
    parser.add_argument("--n-minus-one-manifest-sha256")
    parser.add_argument("--web-dist", required=True, type=Path)
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--structure-only", action="store_true")
    args = parser.parse_args()
    try:
        n_minus_one_release = args.n_minus_one_release.resolve() if args.n_minus_one_release else None
        value = assemble(args.stage_root.resolve(), args.repo_root.resolve(), args.output_root.resolve(), args.arch, n_minus_one_release, args.n_minus_one_manifest_sha256, args.web_dist.resolve(), structure_only=args.structure_only)
    except ProductionBundleError as error:
        print(f"production bundle: {error}")
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
