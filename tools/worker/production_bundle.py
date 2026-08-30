#!/usr/bin/env python3
"""Assemble a locally verified, non-production-accepted release candidate.

The only supported candidates are the 0.8.0-rc.0/0023 bootstrap baseline and
the 0.8.0-rc.1/0024 upgrade candidate. The latter accepts a separately
supplied, manifest-pinned rc.0 artifact; neither path manufactures an N-1
artifact or asserts a verified public-domain deployment.
"""
from __future__ import annotations

import argparse
import errno
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

RC0_SOURCE_COMMIT = "35a2b198ac52949af3477475d89d4813b46a9490"
N_MINUS_ONE_RELEASE_MANIFEST_SHA256 = "3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253"
N_MINUS_ONE_ARCHIVE_SHA256 = "abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc"
N_MINUS_ONE_BUNDLE_MANIFEST_SHA256 = "960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392"
ARM64_N_MINUS_ONE_RELEASE_MANIFEST_SHA256 = "e4f56105b3d184313d51365c7fff40b9f68111815def83c5e5985bc182177a57"
ARM64_N_MINUS_ONE_ARCHIVE_SHA256 = "9560df1d4a739c729d857cd93b989b99976da0e86983ffa026d13202339d57b9"
ARM64_N_MINUS_ONE_BUNDLE_MANIFEST_SHA256 = "fdfd6b6108870118714b70c9007937585fc0429d14fa9d64010a80016edc2a15"

ARCHES = ("amd64", "arm64")
BINARIES = (
    "open-card-server",
    "open-card-agent",
    "open-card-static-server",
    "open-card-secretctl",
    "open-card-security-probe",
    "open-card-imagegc",
    "open-card-admin",
    "open-card-upgrade",
)
RC0_BINARIES = tuple(binary for binary in BINARIES if binary != "open-card-upgrade")


def release_binaries(version: str) -> tuple[str, ...]:
    """Return the exact executable payload available for one release line."""
    if version == "0.8.0-rc.0":
        return RC0_BINARIES
    if version == "0.8.0-rc.1":
        return BINARIES
    raise ProductionBundleError("unsupported release version")


RUNTIME = (
    "buildkitd",
    "buildctl",
    "buildkit-runc",
    "rootlesskit",
    "docker-buildx",
    "caddy",
)
RC0_UNITS = (
    "open-card-server.service",
    "open-card-agent.service",
    "open-card-buildkit.service",
    "open-card-caddy.service",
    "open-card-edge.service",
)
RC1_UNITS = (
    *RC0_UNITS,
    "open-card-upgrade-recover.service",
    "open-card-upgrade-safe.target",
    "open-card-upgrade-finalize.service",
)
UNITS = RC1_UNITS
UNIT_DROP_INS = (
    "open-card-edge.service.d/10-upgrade-marker.conf",
)


def systemd_files(version: str) -> tuple[str, ...]:
    """Return the immutable systemd payload allowed for one release line.

    The RC0 bootstrap source predates the boot-safe barrier.  Keeping the
    additional units RC1-only preserves its frozen artifact contract while
    requiring the complete barrier before any RC1 upgrade is staged.
    """
    if version == "0.8.0-rc.0":
        return RC0_UNITS
    if version == "0.8.0-rc.1":
        return (*UNITS, *UNIT_DROP_INS)
    raise ProductionBundleError("unsupported release version")
RC0_INSTALLER_SCRIPTS = (
    "install.sh",
    "install-host.sh",
    "upgrade.sh",
    "uninstall.sh",
    "backup-control-plane.sh",
    "restore-control-plane.sh",
    "control-plane-migrate.sh",
)
RC1_INSTALLER_SCRIPTS = (
    "install.sh",
    "install-host.sh",
    "host-preflight.sh",
    "buildkit-production-capacity.sh",
    "upgrade.sh",
    "uninstall.sh",
    "backup-control-plane.sh",
    "restore-control-plane.sh",
    "control-plane-migrate.sh",
)
INSTALLER_SCRIPTS = RC1_INSTALLER_SCRIPTS


def installer_scripts(version: str) -> tuple[str, ...]:
    """Keep the frozen RC0 source/payload independent from later host gates."""
    if version == "0.8.0-rc.0":
        return RC0_INSTALLER_SCRIPTS
    if version == "0.8.0-rc.1":
        return RC1_INSTALLER_SCRIPTS
    raise ProductionBundleError("unsupported release version")


class ProductionBundleError(RuntimeError):
    pass


def frozen_rc0_lineage(arch: str) -> dict[str, str] | None:
    """Return the frozen RC0 predecessor lineage for a release architecture."""
    if arch == "amd64":
        return {
            "architecture": arch,
            "source_commit": RC0_SOURCE_COMMIT,
            "release_manifest_sha256": N_MINUS_ONE_RELEASE_MANIFEST_SHA256,
            "archive_sha256": N_MINUS_ONE_ARCHIVE_SHA256,
            "bundle_manifest_sha256": N_MINUS_ONE_BUNDLE_MANIFEST_SHA256,
        }
    if arch == "arm64":
        return {
            "architecture": arch,
            "source_commit": RC0_SOURCE_COMMIT,
            "release_manifest_sha256": ARM64_N_MINUS_ONE_RELEASE_MANIFEST_SHA256,
            "archive_sha256": ARM64_N_MINUS_ONE_ARCHIVE_SHA256,
            "bundle_manifest_sha256": ARM64_N_MINUS_ONE_BUNDLE_MANIFEST_SHA256,
        }
    raise ProductionBundleError(f"unsupported release architecture: {arch}")


def require_frozen_rc0_lineage(arch: str) -> dict[str, str]:
    lineage = frozen_rc0_lineage(arch)
    if lineage is None:
        raise ProductionBundleError("RC1 predecessor lineage is unavailable")
    return lineage


@contextmanager
def private_temporary_directory(*, prefix: str, directory: Path):
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=directory))
    try:
        yield path
    finally:
        for attempt in range(8):
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                break
            except OSError as error:
                if error.errno != errno.ENOTEMPTY or attempt == 7:
                    raise
                time.sleep(0.01 * (attempt + 1))
            else:
                break


def lowercase_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def test_only_payload(relative: Path) -> bool:
    normalized = relative.as_posix().lower()
    parts = tuple(part.lower() for part in relative.parts)
    name = relative.name.lower()
    return (
        any(part in {"test", "tests", "testdata", "fixtures", "__tests__"} for part in parts)
        or "fixture" in normalized
        or name.endswith(".test")
        or ".test." in name
        or name.endswith(".spec")
        or ".spec." in name
    )


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


def verify_repo(repo: Path, source_commit: str, migration_version: str) -> tuple[str, ...]:
    directory(repo)
    try:
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        dirty = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        tracked = tuple(
            path
            for path in subprocess.run(
                ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "-z", source_commit],
                check=True,
                capture_output=True,
            )
            .stdout.decode("utf-8", "surrogateescape")
            .split("\0")
            if path
        )
    except subprocess.CalledProcessError as error:
        raise ProductionBundleError("repository Git verification failed") from error
    if head != source_commit or dirty:
        raise ProductionBundleError("repository HEAD or working tree does not match the declared source commit")
    if not tracked:
        raise ProductionBundleError("declared source commit has no tracked files")
    return tuple(sorted(tracked))


def verify_migrations(
    source_snapshot: Path,
    tracked: tuple[str, ...],
    migration_version: str,
) -> None:
    migrations_root = source_snapshot / "migrations/control-plane"
    directory(migrations_root)
    migrations = []
    for path in sorted(migrations_root.iterdir()):
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r"[0-9]{4}_[a-z0-9_]+\.sql", path.name):
            raise ProductionBundleError("migration input is unsafe or malformed")
        relative = path.relative_to(source_snapshot).as_posix()
        if relative not in tracked:
            raise ProductionBundleError("migration input is not Git tracked")
        regular(path)
        migrations.append(path.name[:4])
    if migrations != [f"{number:04d}" for number in range(1, int(migration_version) + 1)]:
        raise ProductionBundleError("migration inputs are not contiguous through the declared version")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    directory(root)
    digest = hashlib.sha256()
    entries = sorted(root.rglob("*"))
    for path in entries:
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ProductionBundleError("Live dist contains an unsafe entry")
    for path in (item for item in entries if item.is_file()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        value = sha256(path).encode()
        digest.update(value)
    return digest.hexdigest()


def write_json(path: Path, value: object, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(mode)


def copy_file(source: Path, target: Path, mode: int) -> None:
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProductionBundleError(f"required input cannot be opened safely: {source}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ProductionBundleError(
                f"required input must be a regular non-symlink file: {source}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.parent.chmod(0o755)
        with os.fdopen(descriptor, "rb", closefd=False) as input_stream, target.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
    except FileExistsError as error:
        raise ProductionBundleError(f"bundle destination already exists: {target}") from error
    finally:
        os.close(descriptor)
    target.chmod(mode)


def copy_tree(
    source: Path,
    target: Path,
    *,
    mode: int = 0o640,
    preserve_mode: bool = False,
) -> None:
    directory(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o755)
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0o755)
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if item.is_symlink():
            raise ProductionBundleError(f"symlink is forbidden in production input: {item}")
        if item.is_dir():
            (target / relative).mkdir(parents=True, exist_ok=True)
            (target / relative).chmod(0o755)
        elif item.is_file():
            copy_file(
                item,
                target / relative,
                stat.S_IMODE(item.stat().st_mode) if preserve_mode else mode,
            )
        else:
            raise ProductionBundleError(f"unsupported production input type: {item}")


def preflight_tree(source: Path, *, payload: bool) -> None:
    directory(source)
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if item.is_symlink():
            raise ProductionBundleError(f"symlink is forbidden in production input: {item}")
        if item.is_dir():
            if payload and test_only_payload(relative):
                raise ProductionBundleError(
                    f"test-only payload is forbidden in production input: {relative}"
                )
            continue
        regular(item)
        if payload and test_only_payload(relative):
            raise ProductionBundleError(
                f"test-only payload is forbidden in production input: {relative}"
            )


def snapshot_repo(repo: Path, source_commit: str, target: Path) -> None:
    try:
        archive = subprocess.run(
            ["git", "-C", str(repo), "archive", "--format=tar", source_commit],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ProductionBundleError("repository source snapshot failed") from error
    directory(target)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_archive:
            for member in source_archive.getmembers():
                path = Path(member.name)
                if (
                    not member.name
                    or "\\" in member.name
                    or path.is_absolute()
                    or ".." in path.parts
                    or not (member.isdir() or member.isfile())
                ):
                    raise ProductionBundleError("repository source snapshot contains an unsafe entry")
                destination = target.joinpath(*path.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = source_archive.extractfile(member)
                if stream is None:
                    raise ProductionBundleError("repository source snapshot cannot read an entry")
                with stream, destination.open("xb") as output_stream:
                    shutil.copyfileobj(stream, output_stream)
                destination.chmod(member.mode & 0o777)
    except (tarfile.TarError, OSError) as error:
        raise ProductionBundleError("repository source snapshot cannot be extracted safely") from error


def release_files(release: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for item in sorted(release.rglob("*")):
        if item.is_file() and item.name != "manifest.json":
            relative = item.relative_to(release).as_posix()
            if test_only_payload(Path(relative)):
                raise ProductionBundleError(f"test-only payload is forbidden in production release: {relative}")
            entries.append({"path": relative, "sha256": sha256(item), "mode": stat.S_IMODE(item.stat().st_mode)})
    return entries


def make_source_manifest(
    source_snapshot: Path,
    release: Path,
    source_commit: str,
    tracked: tuple[str, ...],
    installer_payload: tuple[str, ...],
) -> None:
    installers = {f"scripts/mvp/{script}" for script in installer_payload}

    def allowed(path: str) -> bool:
        if (
            path
            in {
                "go.mod",
                "go.sum",
                "web/package.json",
                "web/package-lock.json",
                "web/index.html",
                "web/vite.config.ts",
                "web/eslint.config.js",
                "web/.env.example",
            }
            or path in installers
            or (path.startswith("web/tsconfig") and path.endswith(".json"))
        ):
            return True
        if path.startswith(("api/", "migrations/", "deploy/", "web/src/", "web/scripts/", "web/config/", "web/public/")):
            return True
        if path.startswith(("cmd/", "internal/")) and path.endswith(".go") and not path.endswith("_test.go") and "caddy-fixture" not in path:
            return True
        return False
    candidates: list[Path] = []
    for relative in sorted(path for path in tracked if allowed(path)):
        path = source_snapshot / relative
        regular(path)
        candidates.append(path)
    lines = [
        f"{sha256(path)}  {path.relative_to(source_snapshot).as_posix()}"
        for path in candidates
    ]
    target = release / "source-manifest.sha256"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    target.chmod(0o640)
    (release / "source-commit.txt").write_text(source_commit + "\n", encoding="utf-8")
    (release / "source-commit.txt").chmod(0o640)


def make_sbom(release: Path, version: str) -> None:
    packages = []
    for entry in release_files(release):
        packages.append(
            {
                "name": entry["path"],
                "versionInfo": version,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": entry["sha256"]}
                ],
            }
        )
    write_json(
        release / "sbom.spdx.json",
        {
            "spdxVersion": "SPDX-2.3",
            "name": f"open-card-{version}",
            "packages": packages,
        },
    )


def write_tar(root: Path, release: Path, version: str) -> Path:
    archive = root / f"open-card-{version}-production.tar.gz"
    with (
        archive.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed,
        tarfile.open(
            fileobj=compressed,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as output,
    ):
        for item in sorted(release.rglob("*")):
            if item.is_file():
                info = output.gettarinfo(str(item), arcname=f"release/{item.relative_to(release).as_posix()}")
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                with item.open("rb") as stream:
                    output.addfile(info, stream)
    return archive


def release_spec(version: str, migration_version: str) -> dict[str, str | None]:
    if (version, migration_version) == ("0.8.0-rc.0", "0023"):
        return {"expected_n_minus_one_version": None, "expected_n_minus_one_migration": None}
    if (version, migration_version) == ("0.8.0-rc.1", "0024"):
        return {"expected_n_minus_one_version": "0.8.0-rc.0", "expected_n_minus_one_migration": "0023"}
    raise ProductionBundleError("unsupported release specification")


def verify_n_minus_one(
    release: Path,
    expected_manifest_sha256: str,
    expected_archive_sha256: str,
    expected_bundle_manifest_sha256: str,
    arch: str,
    expected_version: str,
    expected_migration: str,
) -> dict[str, object]:
    lineage = require_frozen_rc0_lineage(arch)
    directory(release)
    manifest_path = release / "manifest.json"
    regular(manifest_path)
    manifest_bytes = manifest_path.read_bytes()
    if (
        expected_manifest_sha256 != lineage["release_manifest_sha256"]
        or expected_archive_sha256 != lineage["archive_sha256"]
        or expected_bundle_manifest_sha256 != lineage["bundle_manifest_sha256"]
        or expected_manifest_sha256 != hashlib.sha256(manifest_bytes).hexdigest()
    ):
        raise ProductionBundleError("N-1 manifest checksum does not match the supplied expectation")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBundleError("N-1 manifest is not valid JSON") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != expected_version
        or manifest.get("migration_version") != expected_migration
        or manifest.get("architecture") != arch
    ):
        raise ProductionBundleError("N-1 release manifest does not match the expected version/migration/architecture")
    source_commit = manifest.get("source_commit")
    if source_commit != lineage["source_commit"]:
        raise ProductionBundleError("N-1 release manifest has an invalid source commit")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ProductionBundleError("N-1 manifest has no release files")
    declared_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "mode"}:
            raise ProductionBundleError("N-1 manifest file entry is invalid")
        relative, digest, mode = entry["path"], entry["sha256"], entry["mode"]
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not isinstance(mode, int)
            or isinstance(mode, bool)
        ):
            raise ProductionBundleError("N-1 manifest file entry is invalid")
        path = Path(relative)
        if (
            not relative
            or relative == "."
            or "\\" in relative
            or path.is_absolute()
            or ".." in path.parts
        ):
            raise ProductionBundleError("N-1 manifest has an unsafe file path")
        normalized = path.as_posix()
        if normalized in declared_paths:
            raise ProductionBundleError("N-1 manifest has duplicate release files")
        if not lowercase_hex(digest, 64):
            raise ProductionBundleError("N-1 manifest has an invalid file checksum")
        if mode < 0 or mode > 0o777 or mode & 0o022 or not mode & 0o400:
            raise ProductionBundleError("N-1 manifest has an unsafe file mode")
        target = release.joinpath(*path.parts)
        regular(target)
        target_mode = stat.S_IMODE(target.stat().st_mode)
        if (
            target.stat().st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
            or target_mode != mode
        ):
            raise ProductionBundleError("N-1 release file mode mismatch")
        if sha256(target) != digest:
            raise ProductionBundleError("N-1 release file checksum mismatch")
        declared_paths.add(normalized)
    actual_paths: set[str] = set()
    for item in release.rglob("*"):
        if item.is_symlink():
            raise ProductionBundleError("N-1 release contains a symlink")
        if item.is_dir():
            continue
        regular(item)
        if item != manifest_path:
            actual_paths.add(item.relative_to(release).as_posix())
    if actual_paths != declared_paths:
        raise ProductionBundleError("N-1 release files do not exactly match its manifest")
    return manifest


def verify_live_web(
    dist: Path,
    attestation_path: Path,
    source_commit: str,
    expected_attestation_sha256: str,
) -> None:
    directory(dist)
    regular(dist / "index.html")
    marker = dist / "build-metadata.json"
    regular(marker)
    regular(attestation_path)
    if not lowercase_hex(expected_attestation_sha256, 64):
        raise ProductionBundleError("Live attestation checksum must be lowercase SHA-256")
    if sha256(attestation_path) != expected_attestation_sha256:
        raise ProductionBundleError("Live attestation does not match the pinned evidence digest")
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBundleError("Live web build marker is invalid") from error
    if value != {"mode": "live", "apiBaseUrl": "/api/v1", "schemaVersion": "open-card-build-attestation.v1"}:
        raise ProductionBundleError("web/dist was not built with the required Live API mode")
    try:
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProductionBundleError("Live web attestation is invalid") from error
    expected = {
        "schema_version": "open-card-live-attestation.v1",
        "source_commit": source_commit,
        "build_metadata_sha256": sha256(marker),
        "dist_tree_sha256": tree_digest(dist),
        "gate3_status": "pass_limited_external_linux_required",
    }
    if attestation != expected:
        raise ProductionBundleError("Live web attestation does not match dist/source evidence")


def assemble(
    stage: Path,
    repo: Path,
    output: Path,
    arch: str,
    n_minus_one_release: Path | None,
    n_minus_one_manifest_sha256: str | None,
    web_dist: Path,
    *,
    version: str,
    migration_version: str,
    source_commit: str,
    live_attestation: Path | None = None,
    live_attestation_sha256: str | None = None,
    n_minus_one_archive_sha256: str | None = None,
    n_minus_one_bundle_manifest_sha256: str | None = None,
    structure_only: bool = False,
) -> dict[str, object]:
    if not lowercase_hex(source_commit, 40):
        raise ProductionBundleError("version, migration version, or source commit is invalid")
    if arch not in ARCHES:
        raise ProductionBundleError(f"unsupported release architecture: {arch}")
    spec = release_spec(version, migration_version)
    needs_n_minus_one = spec["expected_n_minus_one_version"] is not None
    lineage = require_frozen_rc0_lineage(arch) if needs_n_minus_one else None
    directory(stage)
    directory(repo)
    directory(output.parent)
    if output.exists():
        raise ProductionBundleError("refusing to overwrite production bundle output")

    systemd_payload = systemd_files(version)
    binaries = release_binaries(version)
    installer_payload = installer_scripts(version)
    tracked = verify_repo(repo, source_commit, migration_version)
    if not needs_n_minus_one and (
        n_minus_one_release is not None or n_minus_one_manifest_sha256 is not None or n_minus_one_archive_sha256 is not None or n_minus_one_bundle_manifest_sha256 is not None
    ):
        raise ProductionBundleError("bootstrap release must not accept an N-1 artifact")

    n_minus_one: dict[str, object] | None = None
    if not structure_only and needs_n_minus_one:
        if (
            n_minus_one_release is None
            or n_minus_one_manifest_sha256 != lineage["release_manifest_sha256"]
            or n_minus_one_archive_sha256 != lineage["archive_sha256"]
            or n_minus_one_bundle_manifest_sha256 != lineage["bundle_manifest_sha256"]
        ):
            raise ProductionBundleError("N-1 lineage digests must match the frozen local candidate")
    if not structure_only and (
        live_attestation is None
        or not lowercase_hex(live_attestation_sha256, 64)
    ):
        raise ProductionBundleError("Live attestation and its pinned SHA-256 are required")

    with private_temporary_directory(
        prefix=f".{output.name}.inputs-", directory=stage.parent
    ) as inputs:
        repo_snapshot = inputs / "repository"
        repo_snapshot.mkdir(mode=0o700)
        snapshot_repo(repo, source_commit, repo_snapshot)
        verify_migrations(repo_snapshot, tracked, migration_version)

        if not structure_only and needs_n_minus_one:
            assert n_minus_one_release is not None
            assert n_minus_one_manifest_sha256 is not None
            assert n_minus_one_archive_sha256 is not None
            assert n_minus_one_bundle_manifest_sha256 is not None
            n_minus_one_snapshot = inputs / "n-minus-one"
            copy_tree(n_minus_one_release, n_minus_one_snapshot, preserve_mode=True)
            n_minus_one = verify_n_minus_one(
                n_minus_one_snapshot,
                n_minus_one_manifest_sha256,
                n_minus_one_archive_sha256,
                n_minus_one_bundle_manifest_sha256,
                arch,
                str(spec["expected_n_minus_one_version"]),
                str(spec["expected_n_minus_one_migration"]),
            )

        stage_snapshot = inputs / "stage"
        for binary in binaries:
            copy_file(
                stage / "binaries" / arch / binary,
                stage_snapshot / "binaries" / arch / binary,
                0o755,
            )
        for binary in RUNTIME:
            copy_file(
                stage / "runtime" / arch / binary,
                stage_snapshot / "runtime" / arch / binary,
                0o755,
            )

        web_snapshot = inputs / "web-dist"
        preflight_tree(web_dist, payload=True)
        copy_tree(web_dist, web_snapshot)
        preflight_tree(web_snapshot, payload=True)

        for systemd_file in systemd_payload:
            regular(repo_snapshot / "deploy/systemd" / systemd_file)
        for script in installer_payload:
            regular(repo_snapshot / "scripts/mvp" / script)
        regular(repo_snapshot / "deploy/caddy/open-card-edge.Caddyfile.example")
        regular(repo_snapshot / "deploy/caddy/open-card-edge.env.example")
        preflight_tree(repo_snapshot / "migrations/control-plane", payload=True)
        preflight_tree(repo_snapshot / "docs/licenses", payload=True)

        attestation_snapshot: Path | None = None
        if not structure_only:
            assert live_attestation is not None
            assert live_attestation_sha256 is not None
            attestation_snapshot = inputs / "live-attestation.json"
            copy_file(live_attestation, attestation_snapshot, 0o640)
            verify_live_web(
                web_snapshot,
                attestation_snapshot,
                source_commit,
                live_attestation_sha256,
            )

        with private_temporary_directory(
            prefix=f".{output.name}.build-", directory=inputs
        ) as build_root:
            release = build_root / "release"
            release.mkdir(mode=0o755)
            for binary in binaries:
                copy_file(
                    stage_snapshot / "binaries" / arch / binary,
                    release / "bin" / binary,
                    0o755,
                )
            for binary in RUNTIME:
                copy_file(
                    stage_snapshot / "runtime" / arch / binary,
                    release / "bin" / binary,
                    0o755,
                )
            for systemd_file in systemd_payload:
                copy_file(
                    repo_snapshot / "deploy/systemd" / systemd_file,
                    release / "systemd" / systemd_file,
                    0o644,
                )
            copy_file(
                repo_snapshot / "deploy/caddy/open-card-edge.Caddyfile.example",
                release / "caddy/open-card-edge.Caddyfile.example",
                0o644,
            )
            copy_file(
                repo_snapshot / "deploy/caddy/open-card-edge.env.example",
                release / "caddy/open-card-edge.env.example",
                0o640,
            )
            copy_tree(
                repo_snapshot / "migrations/control-plane",
                release / "migrations/control-plane",
            )
            if not any(
                (release / "migrations/control-plane").glob(f"{migration_version}_*.sql")
            ):
                raise ProductionBundleError("production release is missing the declared migration")
            copy_tree(repo_snapshot / "docs/licenses", release / "docs/licenses")
            for script in installer_payload:
                copy_file(
                    repo_snapshot / "scripts/mvp" / script,
                    release / "scripts/mvp" / script,
                    0o755,
                )
            copy_tree(web_snapshot, release / "web/dist", mode=0o644)
            live_attestation_digest: str | None = None
            if attestation_snapshot is not None:
                copy_file(
                    attestation_snapshot,
                    release / "attestations/live-web.json",
                    0o640,
                )
                live_attestation_digest = sha256(release / "attestations/live-web.json")
            make_source_manifest(repo_snapshot, release, source_commit, tracked, installer_payload)
            make_sbom(release, version)

            candidate_status = (
                "bootstrap_baseline" if not needs_n_minus_one else "upgrade_candidate"
            )
            if structure_only:
                metadata = {
                    "schema_version": 1,
                    "product": "open-card",
                    "version": version,
                    "migration_version": migration_version,
                    "source_commit": source_commit,
                    "production_ready": False,
                    "production_accepted": False,
                    "candidate_status": candidate_status,
                    "n_minus_one": {
                        "version": spec["expected_n_minus_one_version"],
                        "status": (
                            "not_required_bootstrap"
                            if not needs_n_minus_one
                            else "blocked_no_pinned_provenance"
                        ),
                    },
                    "live_web": {"status": "blocked_gate3_unverified_live_input"},
                    "structure_only": True,
                }
                write_json(build_root / "production-bundle.json", metadata)
                structure_blocker = (
                    "Gate 3 Live attestation is supplied."
                    if not needs_n_minus_one
                    else "pinned N-1 provenance and Gate 3 Live attestations are supplied."
                )
                (build_root / "STRUCTURE-ONLY-NOT-INSTALLABLE").write_text(
                    "No release manifest or archive is emitted until "
                    f"{structure_blocker}\n",
                    encoding="utf-8",
                )
            else:
                manifest = {
                    "schema_version": 1,
                    "product": "open-card",
                    "version": version,
                    "release_id": f"release-{version}",
                    "architecture": arch,
                    "migration_version": migration_version,
                    "source_commit": source_commit,
                    "protocol": "1.1",
                    "config_dir": "/etc/open-card",
                    "data_dir": "/var/lib/open-card",
                    "compatibility": {
                        "min_data_version": 1,
                        "max_data_version": int(migration_version),
                        "min_agent_protocol": "1.0",
                        "max_agent_protocol": "1.1",
                        "requires_data_backup": True,
                    },
                    **(
                        {
                            "n_minus_one": {
                                "version": "0.8.0-rc.0",
                                "migration_version": "0023",
                                "source_commit": lineage["source_commit"],
                                "release_manifest_sha256": lineage["release_manifest_sha256"],
                                "archive_sha256": lineage["archive_sha256"],
                                "bundle_manifest_sha256": lineage["bundle_manifest_sha256"],
                            }
                        }
                        if needs_n_minus_one
                        else {}
                    ),
                    "files": release_files(release),
                }
                write_json(release / "manifest.json", manifest, 0o644)
                archive = write_tar(build_root, release, version)
                bundle_checksum = build_root / "bundle-manifest.sha256"
                bundle_checksum.write_text(
                    f"{sha256(archive)}  {archive.name}\n"
                    f"{sha256(release / 'manifest.json')}  release/manifest.json\n",
                    encoding="utf-8",
                )
                bundle_checksum.chmod(0o640)
                n_minus_one_metadata = (
                    {
                        "version": spec["expected_n_minus_one_version"],
                        "migration_version": spec["expected_n_minus_one_migration"],
                        "source_commit": lineage["source_commit"],
                        "status": "verified_local_candidate",
                        "release_embedded": False,
                        "manifest_sha256": n_minus_one_manifest_sha256,
                        "archive_sha256": n_minus_one_archive_sha256,
                        "bundle_manifest_sha256": n_minus_one_bundle_manifest_sha256,
                    }
                    if needs_n_minus_one
                    else {
                        "manifest_sha256": None,
                        "release_embedded": False,
                        "release_id": None,
                        "status": "not_required_bootstrap",
                        "version": None,
                    }
                )
                metadata = {
                    "schema_version": 1,
                    "product": "open-card",
                    "version": version,
                    "source_commit": source_commit,
                    "production_accepted": False,
                    "candidate_status": candidate_status,
                    "n_minus_one": n_minus_one_metadata,
                    "migration_version": migration_version,
                    "live_web": {
                        "status": "caller_evidence_digest_pinned",
                        "bundle_structure_verified": True,
                        "public_domain_verified": False,
                        "attestation_sha256": live_attestation_digest,
                    },
                    "production_binaries": list(binaries),
                    "excluded": [
                        "open-card-caddy-fixture",
                        "integration test binaries",
                        "fixture archives",
                    ],
                }
                write_json(build_root / "production-bundle.json", metadata)

            if output.exists():
                raise ProductionBundleError("refusing to overwrite production bundle output")
            os.replace(build_root, output)
            return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assemble", nargs="?")
    parser.add_argument("--stage-root", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--n-minus-one-release", type=Path)
    parser.add_argument("--n-minus-one-manifest-sha256")
    parser.add_argument("--n-minus-one-archive-sha256")
    parser.add_argument("--n-minus-one-bundle-manifest-sha256")
    parser.add_argument("--web-dist", required=True, type=Path)
    parser.add_argument("--arch", default="amd64", choices=ARCHES)
    parser.add_argument("--version", required=True)
    parser.add_argument("--migration-version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--live-attestation", type=Path)
    parser.add_argument("--live-attestation-sha256")
    parser.add_argument("--structure-only", action="store_true")
    args = parser.parse_args()
    try:
        n_minus_one_release = args.n_minus_one_release.resolve() if args.n_minus_one_release else None
        live_attestation = args.live_attestation.resolve() if args.live_attestation else None
        value = assemble(
            args.stage_root.resolve(),
            args.repo_root.resolve(),
            args.output_root.resolve(),
            args.arch,
            n_minus_one_release,
            args.n_minus_one_manifest_sha256,
            args.web_dist.resolve(),
            version=args.version,
            migration_version=args.migration_version,
            source_commit=args.source_commit,
            live_attestation=live_attestation,
            live_attestation_sha256=args.live_attestation_sha256,
            n_minus_one_archive_sha256=args.n_minus_one_archive_sha256,
            n_minus_one_bundle_manifest_sha256=args.n_minus_one_bundle_manifest_sha256,
            structure_only=args.structure_only,
        )
    except ProductionBundleError as error:
        print(f"production bundle: {error}")
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
