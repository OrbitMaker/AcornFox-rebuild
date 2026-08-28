from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/production_build.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("production_build", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProductionBuildTests(unittest.TestCase):
    def snapshot_manifest(self, tool, manifest: Path, root: Path) -> Path:
        snapshot = root / "runtime-inputs.snapshot.json"
        tool.snapshot_pinned_file(
            manifest,
            digest(manifest),
            snapshot,
            "runtime-input manifest",
            0o600,
        )
        return snapshot

    def runtime_manifest(self, root: Path) -> tuple[Path, Path]:
        tool = load_tool()
        runtime_dir = root / "runtime"
        runtime_dir.mkdir()
        records = {}
        for runtime_tool, contract in tool.RUNTIME_ASSETS.items():
            filename = contract["amd64"]["filename"]
            asset = runtime_dir / filename
            asset.write_bytes(f"{runtime_tool}-input".encode())
            records[runtime_tool] = {
                "version": tool.RUNTIME_VERSIONS[runtime_tool],
                "architectures": {
                    architecture: {
                        "url": expected["url"],
                        "filename": expected["filename"],
                        "sha256": digest(asset) if architecture == "amd64" else "0" * 64,
                    }
                    for architecture, expected in contract.items()
                },
            }
        manifest = root / "runtime-inputs.json"
        manifest.write_text(
            json.dumps({"schema_version": 1, "runtime_inputs": records}),
            encoding="utf-8",
        )
        return manifest, runtime_dir

    def write_archive(self, path: Path, entries: list[tuple[str, bytes, bytes | None]]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for name, payload, kind in entries:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                if kind is not None:
                    info.type = kind
                archive.addfile(info, io.BytesIO(payload))

    def test_runtime_inputs_require_manifest_filenames_and_hashes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest, runtime_dir = self.runtime_manifest(root)
            selected = tool.load_runtime_inputs(
                self.snapshot_manifest(tool, manifest, root), runtime_dir, "amd64"
            )
            self.assertEqual(set(selected), set(tool.RUNTIME_LAYOUT))
            original_manifest = manifest.read_text(encoding="utf-8")
            immutable_manifest = self.snapshot_manifest(tool, manifest, root / "immutable")
            manifest.write_text("{}", encoding="utf-8")
            self.assertEqual(
                set(tool.load_runtime_inputs(immutable_manifest, runtime_dir, "amd64")),
                set(tool.RUNTIME_LAYOUT),
            )
            manifest.write_text(original_manifest, encoding="utf-8")
            (runtime_dir / "docker-buildx").write_bytes(b"tampered")
            with self.assertRaisesRegex(tool.ProductionBuildError, "digest mismatch"):
                tool.load_runtime_inputs(
                    self.snapshot_manifest(tool, manifest, root / "again"), runtime_dir, "amd64"
                )
            with self.assertRaisesRegex(tool.ProductionBuildError, "pinned SHA-256"):
                tool.snapshot_pinned_file(
                    manifest,
                    "0" * 64,
                    root / "wrong-pin.json",
                    "runtime-input manifest",
                    0o600,
                )

    def test_runtime_manifest_rejects_non_https_or_wrong_tool_version(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest, runtime_dir = self.runtime_manifest(root)
            original = json.loads(manifest.read_text(encoding="utf-8"))
            for label, url in {
                "http": "http://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz",
                "host": "https://attacker.invalid/caddy.tar.gz",
                "query": "https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz?replace=1",
                "userinfo": "https://attacker@github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz",
                "port": "https://github.com:444/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz",
            }.items():
                data = json.loads(json.dumps(original))
                data["runtime_inputs"]["caddy"]["architectures"]["amd64"]["url"] = url
                manifest.write_text(json.dumps(data), encoding="utf-8")
                with self.subTest(label=label), self.assertRaisesRegex(tool.ProductionBuildError, "asset contract"):
                    tool.load_runtime_inputs(
                        self.snapshot_manifest(tool, manifest, root / label), runtime_dir, "amd64"
                    )
            data = json.loads(json.dumps(original))
            data["runtime_inputs"]["caddy"]["version"] = "wrong"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(tool.ProductionBuildError, "record is invalid"):
                tool.load_runtime_inputs(
                    self.snapshot_manifest(tool, manifest, root / "version"), runtime_dir, "amd64"
                )

    def test_runtime_archive_rejects_unsafe_or_duplicate_required_members(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            traversal = root / "traversal.tar.gz"
            self.write_archive(traversal, [("../buildkitd", b"x", None)])
            with self.assertRaisesRegex(tool.ProductionBuildError, "unsafe"):
                tool.extract_runtime_archive(traversal, root / "traversal", {"buildkitd": "buildkitd"})

            duplicate = root / "duplicate.tar.gz"
            self.write_archive(
                duplicate,
                [("buildkitd", b"one", None), ("buildkitd", b"two", None)],
            )
            with self.assertRaisesRegex(tool.ProductionBuildError, "duplicate"):
                tool.extract_runtime_archive(duplicate, root / "duplicate", {"buildkitd": "buildkitd"})

            symlink = root / "symlink.tar.gz"
            self.write_archive(symlink, [("buildkitd", b"", tarfile.SYMTYPE)])
            with self.assertRaisesRegex(tool.ProductionBuildError, "non-regular"):
                tool.extract_runtime_archive(symlink, root / "symlink", {"buildkitd": "buildkitd"})

    def test_runtime_archive_extracts_only_the_required_executables(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "buildkit.tar.gz"
            self.write_archive(
                archive,
                [
                    ("bin/buildkitd", b"daemon", None),
                    ("bin/buildctl", b"client", None),
                    ("README.md", b"ignored", None),
                ],
            )
            target = root / "stage"
            tool.extract_runtime_archive(
                archive,
                target,
                {"bin/buildkitd": "buildkitd", "bin/buildctl": "buildctl"},
            )
            self.assertEqual((target / "buildkitd").read_bytes(), b"daemon")
            self.assertEqual((target / "buildctl").read_bytes(), b"client")
            self.assertFalse((target / "README.md").exists())

    def test_publish_reservation_never_overwrites_an_existing_output(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / "payload").write_text("candidate", encoding="utf-8")
            output = root / "output"
            output.mkdir()
            sentinel = output / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(tool.ProductionBuildError, "overwrite"):
                tool.publish_no_replace(candidate, output)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertTrue((candidate / "payload").is_file())

    def test_publish_no_replace_moves_only_a_complete_candidate_directory(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate = root / "candidate"
            (candidate / "release").mkdir(parents=True)
            (candidate / "release/manifest.json").write_text("{}", encoding="utf-8")
            (candidate / "archive.tar.gz").write_bytes(b"archive")
            output = root / "output"
            tool.publish_no_replace(candidate, output)
            self.assertFalse(candidate.exists())
            self.assertTrue((output / "release/manifest.json").is_file())
            self.assertTrue((output / "archive.tar.gz").is_file())

    def test_publish_dispatches_to_linux_no_replace_primitive(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate = root / "candidate"
            candidate.mkdir()
            output = root / "output"

            def fake_linux_rename(source: Path, destination: Path) -> None:
                self.assertEqual((source.parent, destination.parent), (root, root))
                os.rename(source, destination)

            with mock.patch.object(tool.sys, "platform", "linux"), mock.patch.object(
                tool, "_linux_rename_no_replace", side_effect=fake_linux_rename
            ) as rename:
                tool.publish_no_replace(candidate, output)
            rename.assert_called_once_with(candidate, output)
            self.assertTrue(output.is_dir())

    def test_release_validation_binds_the_requested_source_commit(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            release = root / "release"
            payload = release / "bin/open-card-server"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"server")
            payload.chmod(0o755)
            source_commit = "a" * 40
            manifest = {
                "version": tool.VERSION,
                "migration_version": tool.MIGRATION_VERSION,
                "architecture": tool.ARCHITECTURE,
                "source_commit": source_commit,
                "files": [
                    {"path": "bin/open-card-server", "sha256": digest(payload), "mode": 0o755}
                ],
            }
            (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(tool.ProductionBuildError, "candidate contract"):
                tool.validate_release(
                    release,
                    version=tool.VERSION,
                    migration_version=tool.MIGRATION_VERSION,
                    arch=tool.ARCHITECTURE,
                    source_commit="b" * 40,
                )
            self.assertEqual(
                tool.validate_release(
                    release,
                    version=tool.VERSION,
                    migration_version=tool.MIGRATION_VERSION,
                    arch=tool.ARCHITECTURE,
                    source_commit=source_commit,
                ),
                digest(release / "manifest.json"),
            )

    def test_post_publish_verification_rejects_a_replaced_archive(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "candidate.tar.gz"
            archive.write_bytes(b"replaced")
            bundle_manifest = root / "bundle-manifest.sha256"
            bundle_manifest.write_text("bundle", encoding="utf-8")
            with mock.patch.object(tool, "validate_release", return_value="m" * 64):
                with self.assertRaisesRegex(tool.ProductionBuildError, "archive changed"):
                    tool.verify_published_candidate(
                        root,
                        version=tool.VERSION,
                        migration_version=tool.MIGRATION_VERSION,
                        arch=tool.ARCHITECTURE,
                        source_commit="a" * 40,
                        manifest_digest="m" * 64,
                        archive_name=archive.name,
                        archive_digest="0" * 64,
                        bundle_manifest_digest=digest(bundle_manifest),
                    )

    def test_clean_detached_worktree_and_output_aliases_fail_closed(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            repo.mkdir()
            (repo / "go.mod").write_text("module example.test/build\ngo 1.25\n", encoding="utf-8")
            bundle_tool = repo / "tools/worker/production_bundle.py"
            bundle_tool.parent.mkdir(parents=True)
            bundle_tool.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            for command in (
                ["git", "init", str(repo)],
                ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
                ["git", "-C", str(repo), "config", "user.name", "test"],
                ["git", "-C", str(repo), "add", "."],
                ["git", "-C", str(repo), "commit", "-m", "fixture"],
            ):
                subprocess.run(command, check=True, capture_output=True)
            commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            subprocess.run(["git", "-C", str(repo), "checkout", "--detach"], check=True, capture_output=True)
            with mock.patch.object(tool, "RC0_SOURCE_COMMIT", commit):
                tool.verify_clean_detached_worktree(repo, commit)
            _, tool_metadata = tool.verify_clean_tracked_tool(
                bundle_tool,
                digest(bundle_tool),
                "production bundle tool",
            )
            self.assertEqual(tool_metadata["commit"], commit)
            self.assertEqual(tool_metadata["relative_path"], "tools/worker/production_bundle.py")
            snapshot = root / "snapshot"
            snapshot.mkdir()
            tool.snapshot_source_tree(repo, commit, snapshot)
            (repo / "web/node_modules").mkdir(parents=True)
            (repo / "web/node_modules/generated.js").write_text("generated", encoding="utf-8")
            (repo / "web/dist").mkdir(parents=True)
            (repo / "web/dist/index.html").write_text("generated", encoding="utf-8")
            self.assertFalse((snapshot / "web/node_modules").exists())
            self.assertFalse((snapshot / "web/dist").exists())
            (repo / "untracked.txt").write_text("dirty", encoding="utf-8")
            with mock.patch.object(tool, "RC0_SOURCE_COMMIT", commit):
                with self.assertRaisesRegex(tool.ProductionBuildError, "clean, detached"):
                    tool.verify_clean_detached_worktree(repo, commit)
            runtime = root / "runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(tool.ProductionBuildError, "output must not alias"):
                tool.ensure_non_aliases(
                    repo / "candidate",
                    {"source worktree": repo, "runtime input": runtime},
                )


if __name__ == "__main__":
    unittest.main()
