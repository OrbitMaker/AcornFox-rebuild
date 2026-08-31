from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/production_build.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("production_build", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProductionBuildTests(unittest.TestCase):
    def test_rc3_selector_pins_rc2_lineage_and_refuses_pre_output_evidence_gaps(self) -> None:
        tool = load_tool()
        self.assertEqual(tool.release_spec("0.8.0-rc.3").migration, "0024")
        self.assertEqual(tool.go_targets(tool.RC3_SPEC)["open-card-healthcheck"], "./cmd/open-card-healthcheck")
        self.assertEqual(
            tool.frozen_predecessor_lineage("0.8.0-rc.3", "amd64"),
            {"source_commit": tool.RC2_SOURCE_COMMIT, **tool.RC2_LINEAGES["amd64"]},
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "rc3-output"
            with self.assertRaisesRegex(tool.ProductionBuildError, "N-1 evidence"):
                tool.build_candidate(
                    source_worktree=root, source_commit="a" * 40,
                    runtime_inputs=root / "inputs.json", runtime_inputs_sha256="0" * 64,
                    runtime_dir=root, output=output, bundle_tool=root / "bundle.py",
                    bundle_tool_sha256="0" * 64, driver_sha256="0" * 64,
                    version=tool.RC3_SPEC.version, arch="amd64",
                )
            self.assertFalse(output.exists())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "rc3-missing-cert-output"
            with mock.patch.object(tool, "verify_n_minus_one_candidate_root", return_value=object()):
                with self.assertRaisesRegex(tool.ProductionBuildError, "exact predecessor certification"):
                    tool.build_candidate(
                        source_worktree=root, source_commit="a" * 40,
                        runtime_inputs=root / "inputs.json", runtime_inputs_sha256="0" * 64,
                        runtime_dir=root, output=output, bundle_tool=root / "bundle.py",
                        bundle_tool_sha256="0" * 64, driver_sha256="0" * 64,
                        version=tool.RC3_SPEC.version, n_minus_one_candidate_root=root,
                        arch="amd64",
                    )
            self.assertFalse(output.exists())

    def test_rc2_selector_uses_frozen_rc1_predecessor_and_refuses_missing_evidence(self) -> None:
        tool = load_tool()
        self.assertEqual((tool.release_spec("0.8.0-rc.2").migration, tool.release_spec("0.8.0-rc.2").bootstrap), ("0024", False))
        self.assertEqual(tool.frozen_predecessor_lineage("0.8.0-rc.2", "amd64")["release_manifest_sha256"], "1cf02e4a111e38a4061c692de418b67755a2e55f97a04cbc92cee8cb9f82a7be")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "rc2-output"
            with self.assertRaisesRegex(tool.ProductionBuildError, "N-1 evidence"):
                tool.build_candidate(source_worktree=root, source_commit="a" * 40, runtime_inputs=root / "inputs.json", runtime_inputs_sha256="0" * 64, runtime_dir=root, output=output, bundle_tool=root / "bundle.py", bundle_tool_sha256="0" * 64, driver_sha256="0" * 64, version="0.8.0-rc.2", arch="amd64")
            self.assertFalse(output.exists())

    def test_frozen_rc0_lineage_descriptors_are_architecture_complete(self) -> None:
        tool = load_tool()
        expected = {
            "amd64": (
                tool.N_MINUS_ONE_RELEASE_MANIFEST_SHA256,
                tool.N_MINUS_ONE_ARCHIVE_SHA256,
                tool.N_MINUS_ONE_BUNDLE_MANIFEST_SHA256,
            ),
            "arm64": (
                tool.ARM64_N_MINUS_ONE_RELEASE_MANIFEST_SHA256,
                tool.ARM64_N_MINUS_ONE_ARCHIVE_SHA256,
                tool.ARM64_N_MINUS_ONE_BUNDLE_MANIFEST_SHA256,
            ),
        }
        for arch, hashes in expected.items():
            lineage = tool.frozen_rc0_lineage(arch)
            self.assertEqual(
                set(lineage),
                {
                    "architecture",
                    "source_commit",
                    "release_manifest_sha256",
                    "archive_sha256",
                    "bundle_manifest_sha256",
                    "declared_file_count",
                },
            )
            self.assertEqual(lineage["architecture"], arch)
            self.assertEqual(
                (
                    lineage["release_manifest_sha256"],
                    lineage["archive_sha256"],
                    lineage["bundle_manifest_sha256"],
                ),
                hashes,
            )

    def test_release_specs_select_exact_go_build_targets(self) -> None:
        tool = load_tool()
        self.assertEqual(tool.GO_TARGETS["open-card-upgrade"], "./cmd/open-card-upgrade")
        self.assertEqual(
            tuple(tool.go_targets(tool.RC0_SPEC)),
            (
                "open-card-server",
                "open-card-agent",
                "open-card-static-server",
                "open-card-secretctl",
                "open-card-security-probe",
                "open-card-imagegc",
                "open-card-admin",
            ),
        )
        self.assertEqual(tuple(tool.go_targets(tool.RC1_SPEC)), tuple(tool.GO_TARGETS))
        self.assertIn(
            "for binary, package in go_targets(spec).items():",
            TOOL.read_text(encoding="utf-8"),
        )

    def test_arch_cli_dataflow_and_rc1_arm64_requires_exact_evidence_before_output(self) -> None:
        tool = load_tool()
        help_result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--arch {amd64,arm64}", help_result.stdout)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, go_env, _ = tool.isolated_build_environments(root, "arm64")
            self.assertEqual(go_env["GOARCH"], "arm64")
            lineage = tool.require_frozen_rc0_lineage("arm64")
            self.assertEqual(
                lineage["release_manifest_sha256"],
                tool.ARM64_N_MINUS_ONE_RELEASE_MANIFEST_SHA256,
            )
            output = root / "arm64-rc1"
            with self.assertRaisesRegex(
                tool.ProductionBuildError,
                "N-1 candidate root",
            ):
                tool.build_candidate(
                    source_worktree=root,
                    source_commit="a" * 40,
                    runtime_inputs=root / "inputs.json",
                    runtime_inputs_sha256="0" * 64,
                    runtime_dir=root,
                    output=output,
                    bundle_tool=root / "bundle.py",
                    bundle_tool_sha256="0" * 64,
                    driver_sha256="0" * 64,
                    version=tool.RC1_SPEC.version,
                    n_minus_one_candidate_root=root / "missing-n-minus-one",
                    arch="arm64",
                )
            self.assertFalse(output.exists())

    def n_minus_one_candidate(
        self, tool, root: Path, arch: str = "amd64"
    ) -> tuple[Path, dict[str, object]]:
        candidate = root / "n-minus-one"
        release = candidate / "release"
        release.mkdir(parents=True)
        files = []
        for index in range(62):
            relative = f"payload/file-{index:02d}"
            payload = f"payload-{index}".encode()
            path = release / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(0o644)
            files.append({"path": relative, "sha256": hashlib.sha256(payload).hexdigest(), "mode": 0o644})
        manifest = {
            "version": tool.RC0_SPEC.version,
            "migration_version": tool.RC0_SPEC.migration,
            "architecture": arch,
            "source_commit": tool.RC0_SOURCE_COMMIT,
            "files": files,
        }
        manifest_path = release / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        manifest_path.chmod(0o644)
        archive = candidate / "open-card-0.8.0-rc.0-production.tar.gz"
        archive.write_bytes(b"frozen archive")
        archive.chmod(0o644)
        manifest_digest, archive_digest = digest(manifest_path), digest(archive)
        bundle_manifest = candidate / "bundle-manifest.sha256"
        bundle_manifest.write_text(
            f"{archive_digest}  {archive.name}\n{manifest_digest}  release/manifest.json\n",
            encoding="utf-8",
        )
        bundle_manifest.chmod(0o640)
        bundle_digest = digest(bundle_manifest)
        build_record = {
            "production_accepted": False,
            "candidate": {
                "version": tool.RC0_SPEC.version,
                "migration_version": tool.RC0_SPEC.migration,
                "architecture": arch,
                "source_commit": tool.RC0_SOURCE_COMMIT,
            },
            "bundle": {
                "archive": archive.name,
                "archive_sha256": archive_digest,
                "manifest_sha256": manifest_digest,
                "bundle_manifest_sha256": bundle_digest,
            },
        }
        (candidate / "build-record.json").write_text(json.dumps(build_record), encoding="utf-8")
        (candidate / "build-record.json").chmod(0o640)
        production_bundle = {
            "candidate_status": "bootstrap_baseline",
            "production_accepted": False,
            "source_commit": tool.RC0_SOURCE_COMMIT,
            "version": tool.RC0_SPEC.version,
            "migration_version": tool.RC0_SPEC.migration,
            "n_minus_one": {
                "manifest_sha256": None,
                "release_embedded": False,
                "release_id": None,
                "status": "not_required_bootstrap",
                "version": None,
            },
        }
        (candidate / "production-bundle.json").write_text(json.dumps(production_bundle), encoding="utf-8")
        (candidate / "production-bundle.json").chmod(0o640)
        prefix = "" if arch == "amd64" else "ARM64_"
        return candidate, {
            f"{prefix}N_MINUS_ONE_RELEASE_MANIFEST_SHA256": manifest_digest,
            f"{prefix}N_MINUS_ONE_ARCHIVE_SHA256": archive_digest,
            f"{prefix}N_MINUS_ONE_BUNDLE_MANIFEST_SHA256": bundle_digest,
            f"{prefix}N_MINUS_ONE_DECLARED_FILE_COUNT": len(files),
        }

    @contextmanager
    def pinned_n_minus_one(self, tool, pins: dict[str, object]):
        with mock.patch.multiple(tool, **pins):
            yield

    def test_n_minus_one_candidate_is_complete_and_returns_frozen_evidence(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            candidate, pins = self.n_minus_one_candidate(tool, Path(raw))
            with self.pinned_n_minus_one(tool, pins):
                evidence = tool.verify_n_minus_one_candidate_root(candidate)
            self.assertIsInstance(evidence, tool.NMinusOneEvidence)
            self.assertEqual(evidence.candidate_root, candidate.resolve())
            self.assertEqual(evidence.release_path, (candidate / "release").resolve())
            self.assertEqual((evidence.version, evidence.migration, evidence.source_commit), ("0.8.0-rc.0", "0023", tool.RC0_SOURCE_COMMIT))
            self.assertEqual(evidence.architecture, "amd64")
            self.assertEqual(evidence.archive_sha256, pins["N_MINUS_ONE_ARCHIVE_SHA256"])

    def test_arm64_n_minus_one_candidate_requires_same_architecture(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            candidate, pins = self.n_minus_one_candidate(tool, Path(raw), "arm64")
            mixed_pins = {
                **pins,
                **{
                    key.removeprefix("ARM64_"): value
                    for key, value in pins.items()
                },
            }
            with self.pinned_n_minus_one(tool, mixed_pins):
                evidence = tool.verify_n_minus_one_candidate_root(candidate, arch="arm64")
                self.assertEqual(evidence.architecture, "arm64")
                with self.assertRaisesRegex(
                    tool.ProductionBuildError, "manifest metadata is invalid"
                ):
                    tool.verify_n_minus_one_candidate_root(candidate, arch="amd64")

    def test_n_minus_one_candidate_rejects_every_frozen_boundary(self) -> None:
        tool = load_tool()
        for mutation in ("missing", "extra", "symlink", "mode", "file-hash", "archive", "bundle-line", "bundle-file-hash", "build-record", "production-metadata", "bootstrap-n1-shape", "source"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                candidate, pins = self.n_minus_one_candidate(tool, Path(raw))
                release = candidate / "release"
                if mutation == "missing":
                    (candidate / "build-record.json").unlink()
                elif mutation == "extra":
                    (candidate / "unexpected").write_text("x", encoding="utf-8")
                elif mutation == "symlink":
                    (release / "payload" / "file-00").unlink()
                    os.symlink("file-01", release / "payload" / "file-00")
                elif mutation == "mode":
                    (candidate / "production-bundle.json").chmod(0o644)
                elif mutation == "file-hash":
                    (release / "payload" / "file-00").write_text("tampered", encoding="utf-8")
                elif mutation == "archive":
                    (candidate / "open-card-0.8.0-rc.0-production.tar.gz").write_bytes(b"tampered")
                elif mutation == "bundle-line":
                    (candidate / "bundle-manifest.sha256").write_text("wrong\n", encoding="utf-8")
                    pins["N_MINUS_ONE_BUNDLE_MANIFEST_SHA256"] = digest(candidate / "bundle-manifest.sha256")
                elif mutation == "bundle-file-hash":
                    pins["N_MINUS_ONE_BUNDLE_MANIFEST_SHA256"] = "0" * 64
                elif mutation == "build-record":
                    record = json.loads((candidate / "build-record.json").read_text(encoding="utf-8"))
                    record["production_accepted"] = True
                    (candidate / "build-record.json").write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "production-metadata":
                    metadata = json.loads((candidate / "production-bundle.json").read_text(encoding="utf-8"))
                    metadata["candidate_status"] = "accepted"
                    (candidate / "production-bundle.json").write_text(json.dumps(metadata), encoding="utf-8")
                elif mutation == "bootstrap-n1-shape":
                    metadata = json.loads((candidate / "production-bundle.json").read_text(encoding="utf-8"))
                    metadata["n_minus_one"]["migration_version"] = None
                    (candidate / "production-bundle.json").write_text(json.dumps(metadata), encoding="utf-8")
                elif mutation == "source":
                    manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
                    manifest["source_commit"] = "0" * 40
                    (release / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
                    manifest_digest = digest(release / "manifest.json")
                    archive_digest = pins["N_MINUS_ONE_ARCHIVE_SHA256"]
                    bundle_manifest = candidate / "bundle-manifest.sha256"
                    bundle_manifest.write_text(
                        f"{archive_digest}  open-card-0.8.0-rc.0-production.tar.gz\n{manifest_digest}  release/manifest.json\n",
                        encoding="utf-8",
                    )
                    bundle_manifest.chmod(0o640)
                    bundle_digest = digest(bundle_manifest)
                    record = json.loads((candidate / "build-record.json").read_text(encoding="utf-8"))
                    record["bundle"]["manifest_sha256"] = manifest_digest
                    record["bundle"]["bundle_manifest_sha256"] = bundle_digest
                    (candidate / "build-record.json").write_text(json.dumps(record), encoding="utf-8")
                    pins["N_MINUS_ONE_RELEASE_MANIFEST_SHA256"] = manifest_digest
                    pins["N_MINUS_ONE_BUNDLE_MANIFEST_SHA256"] = bundle_digest
                with self.pinned_n_minus_one(tool, pins):
                    with self.assertRaises(tool.ProductionBuildError):
                        tool.verify_n_minus_one_candidate_root(candidate)

    def test_rc1_checks_n_minus_one_before_any_output_mutation_and_rc0_forbids_it(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "output"
            invalid_n_minus_one = root / "invalid-n-minus-one"
            invalid_n_minus_one.mkdir()
            with self.assertRaisesRegex(tool.ProductionBuildError, "N-1"):
                tool.build_candidate(
                    source_worktree=root,
                    source_commit="a" * 40,
                    runtime_inputs=root / "inputs.json",
                    runtime_inputs_sha256="0" * 64,
                    runtime_dir=root,
                    output=output,
                    bundle_tool=root / "bundle.py",
                    bundle_tool_sha256="0" * 64,
                    driver_sha256="0" * 64,
                    version=tool.RC1_SPEC.version,
                    n_minus_one_candidate_root=invalid_n_minus_one,
                )
            self.assertFalse(output.exists())
            with self.assertRaisesRegex(tool.ProductionBuildError, "RC0 bootstrap must not accept"):
                tool.build_candidate(
                    source_worktree=root,
                    source_commit=tool.RC0_SOURCE_COMMIT,
                    runtime_inputs=root / "inputs.json",
                    runtime_inputs_sha256="0" * 64,
                    runtime_dir=root,
                    output=output,
                    bundle_tool=root / "bundle.py",
                    bundle_tool_sha256="0" * 64,
                    driver_sha256="0" * 64,
                    version=tool.RC0_SPEC.version,
                    n_minus_one_candidate_root=invalid_n_minus_one,
                )
            self.assertFalse(output.exists())

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

    def test_private_candidate_path_is_same_parent_and_absent(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "amd64"
            candidate = tool.reserve_private_candidate_path(output)
            self.assertEqual(candidate.parent, output.parent)
            self.assertFalse(candidate.exists())
            self.assertTrue(candidate.name.startswith(".amd64.candidate-"))

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
