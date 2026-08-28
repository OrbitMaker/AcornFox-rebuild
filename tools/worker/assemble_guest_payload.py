#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tarfile
from pathlib import Path


PINNED = {
    "ubuntu_image": ("https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img", "6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733"),
    "buildkit": ("https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-amd64.tar.gz", "2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af"),
    "rootlesskit": ("https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-x86_64.tar.gz", "b1302b7395918266d561b9e3053771253f20761807e042ae80a1868d6e86b71c"),
    "buildx": ("https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-amd64", "48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778"),
    "caddy": ("https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz", "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path: Path) -> Path:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"expected regular file: {path}")
    return path


def copy(source: Path, target: Path, mode: int) -> None:
    regular(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def write_tar(output: Path, root: Path, members: list[Path]) -> None:
    if output.exists():
        regular(output)
        output.unlink()
    with tarfile.open(output, "w:", format=tarfile.GNU_FORMAT) as archive:
        directories: set[Path] = set()
        for path in members:
            relative = path.relative_to(root)
            directories.update(relative.parents)
        for relative in sorted((item for item in directories if str(item) != "."), key=lambda item: item.as_posix()):
            info = tarfile.TarInfo(relative.as_posix())
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = info.uid = info.gid = 0
            archive.addfile(info)
        for path in sorted(members, key=lambda item: item.relative_to(root).as_posix()):
            regular(path)
            relative = path.relative_to(root).as_posix()
            info = tarfile.TarInfo(relative)
            info.size = path.stat().st_size
            info.mode = path.stat().st_mode & 0o777
            info.mtime = info.uid = info.gid = 0
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    output.chmod(0o440)


def release_manifest(release: Path, version: str, protocol: str) -> None:
    files = []
    for path in sorted(item for item in release.rglob("*") if item.is_file() and item.name != "manifest.json"):
        files.append({"path": path.relative_to(release).as_posix(), "sha256": sha256(path), "mode": path.stat().st_mode & 0o777})
    manifest = {
        "schema_version": 1,
        "product": "open-card",
        "version": version,
        "release_id": f"release-{version}",
        "protocol": protocol,
        "config_dir": "/etc/open-card",
        "data_dir": "/var/lib/open-card",
        "compatibility": {"min_data_version": 1, "max_data_version": 19, "min_agent_protocol": "1.0", "max_agent_protocol": "1.1", "requires_data_backup": True},
        "files": files,
    }
    (release / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (release / "manifest.json").chmod(0o644)


def assemble(source: Path, repo: Path, output: Path) -> dict[str, object]:
    if source.is_symlink() or repo.is_symlink():
        raise ValueError("source and repo roots must not be symlinks")
    output.mkdir(parents=True, exist_ok=True)
    generated = output / "generated"
    shutil.rmtree(generated, ignore_errors=True)
    releases = generated / "releases"
    releases.mkdir(parents=True)
    binaries = {
        "open-card-server": source / "open-card-server",
        "open-card-agent": source / "open-card-agent",
        "open-card-static-server": source / "open-card-static-server",
        "open-card-secretctl": source / "open-card-secretctl",
        "open-card-security-probe": source / "open-card-security-probe",
        "open-card-imagegc": source / "open-card-imagegc",
        "open-card-caddy-fixture": source / "open-card-caddy-fixture",
        "buildkitd": source / "extracted/bin/buildkitd",
        "buildctl": source / "extracted/bin/buildctl",
        "buildkit-runc": source / "extracted/bin/buildkit-runc",
        "rootlesskit": source / "extracted/rootlesskit",
        "docker-buildx": source / "docker-buildx",
        "caddy": source / "extracted/caddy",
    }
    units = ["open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service"]
    for version, protocol in (("0.1.0", "1.0"), ("0.2.11", "1.1"), ("0.3.3", "1.1"), ("0.4.0", "1.1")):
        release = releases / f"release-{version}"
        for name, path in binaries.items():
            copy(path, release / "bin" / name, 0o755)
        for name in units:
            copy(repo / "deploy/systemd" / name, release / "systemd" / name, 0o644)
        (release / "VERSION").write_text(version + "\n", encoding="utf-8")
        (release / "VERSION").chmod(0o644)
        release_manifest(release, version, protocol)
    write_tar(output / "releases.tar", releases, [item for item in releases.rglob("*") if item.is_file()])

    migration_root = generated / "migrations"
    all_migrations = sorted((repo / "migrations/control-plane").glob("*.sql"))
    if len(all_migrations) != 19:
        raise ValueError(f"expected nineteen migrations, got {len(all_migrations)}")
    for path in all_migrations:
        copy(path, migration_root / "all" / path.name, 0o644)
        if path.name.startswith(tuple(f"000{number}_" for number in range(1, 7))):
            copy(path, migration_root / "v1" / path.name, 0o644)
    write_tar(output / "migrations.tar", migration_root, [item for item in migration_root.rglob("*") if item.is_file()])

    g7_root = generated / "g7"
    for name in ("install.sh", "upgrade.sh", "uninstall.sh", "backup-control-plane.sh", "restore-control-plane.sh", "control-plane-migrate.sh"):
        copy(repo / "scripts/mvp" / name, g7_root / name, 0o755)
    write_tar(output / "g7-scripts.tar", g7_root, [item for item in g7_root.rglob("*") if item.is_file()])

    for milestone in ("m2", "m3", "m4"):
        fixture_root = repo / "tests" / "fixtures" / milestone
        runner = repo / "tests" / "spikes" / f"clean_worker_{milestone}_guest.sh"
        members = [item for item in fixture_root.rglob("*") if item.is_file()] + [runner]
        if milestone == "m4":
            members.extend(
                [
                    repo / "tests/spikes/clean_worker_m4_log_gate_guest.sh",
                    repo / "tests/spikes/clean_worker_m4_webhook_lifecycle_guest.sh",
                ]
            )
        write_tar(output / f"{milestone}-fixtures.tar", repo, members)

    debs = sorted((source / "debs").glob("*.deb"))
    if not debs:
        raise ValueError("no offline deb packages found")
    checksum_file = source / "debs.sha256"
    expected_lines = checksum_file.read_text(encoding="utf-8").splitlines()
    expected = {line.split(None, 1)[1]: line.split(None, 1)[0] for line in expected_lines}
    for path in debs:
        relative = f"debs/{path.name}"
        if expected.get(relative) != sha256(path):
            raise ValueError(f"deb checksum mismatch: {relative}")
    write_tar(output / "debs.tar", source, [source / "packages.txt", checksum_file, *debs])

    supply_chain = {
        "schema_version": 1,
        "task_id": "opencard-mvp-fa8f8eab",
        "ubuntu_sha256s_gpg_verified_by": "UEC Image Automatic Signing Key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",
        "pinned_sources": {name: {"url": url, "sha256": digest} for name, (url, digest) in PINNED.items()},
        "release_binaries": {name: sha256(path) for name, path in binaries.items()},
        "deb_packages": len(debs),
        "binary_provenance": "task-prefixed verified OCI images plus checksum-pinned official release assets",
    }
    image_digest_path = source / "task-image-digests.txt"
    if image_digest_path.is_file():
        supply_chain["task_image_digests"] = sorted(line.strip() for line in image_digest_path.read_text(encoding="utf-8").splitlines() if line.strip())
    supply_path = output / "supply-chain.json"
    if supply_path.exists():
        regular(supply_path)
        supply_path.unlink()
    supply_path.write_text(json.dumps(supply_chain, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    supply_path.chmod(0o440)
    artifacts = ["debs.tar", "releases.tar", "migrations.tar", "g7-scripts.tar", "m2-fixtures.tar", "m3-fixtures.tar", "m4-fixtures.tar", "supply-chain.json"]
    return {"artifacts": {name: {"sha256": sha256(output / name), "size_bytes": (output / name).stat().st_size} for name in artifacts}, "deb_packages": len(debs)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--m7", action="store_true", help="assemble the 0.7.0-rc.1 canonical source contract")
    parser.add_argument("--stage-root", type=Path)
    parser.add_argument("--debs-root", type=Path)
    parser.add_argument("--assets-root", type=Path)
    args = parser.parse_args()
    if args.m7:
        required = (args.stage_root, args.output_dir, args.debs_root, args.assets_root)
        if any(value is None for value in required):
            parser.error("--m7 requires --stage-root, --output-dir, --debs-root, and --assets-root")
        from m7_canonical_bundle import M7Error, assemble as assemble_m7

        try:
            result = assemble_m7(args.stage_root.resolve(), args.repo_root.resolve(), args.output_dir.resolve(), args.debs_root.resolve(), args.assets_root.resolve())
        except M7Error as exc:
            if args.output_dir.exists() and not args.output_dir.is_symlink():
                shutil.rmtree(args.output_dir)
            print(json.dumps({"ready": False, "error": str(exc)}, sort_keys=True))
            return 64
    else:
        if args.source_root is None or args.output_dir is None:
            parser.error("legacy assembly requires --source-root and --output-dir")
        result = assemble(args.source_root.resolve(), args.repo_root.resolve(), args.output_dir.resolve())
    if args.m7:
        print(json.dumps({"ready": True, **result}, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
