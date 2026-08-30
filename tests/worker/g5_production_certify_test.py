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
import gzip
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/production_certify.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("production_certify", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProductionCertificationTests(unittest.TestCase):
    def test_rc2_two_build_candidates_bind_frozen_rc1_evidence(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root, tool, tool.RC2_VERSION)
            output = root / "rc2-certification"
            result = tool.certify(source_a, source_b, candidates_a, candidates_b, output, commit, tool.RC2_VERSION)
            self.assertEqual(result["version"], tool.RC2_VERSION)
            self.assertEqual(json.loads((output / "release-index.json").read_text(encoding="utf-8"))["version"], tool.RC2_VERSION)
            for candidate_set in (candidates_a, candidates_b):
                for arch in tool.ARCHES:
                    manifest = json.loads((candidate_set / arch / "release/manifest.json").read_text(encoding="utf-8"))
                    self.assertEqual(len(manifest["files"]), 71)
                    self.assertIn("tools/evidence/g6_validate.py", {entry["path"] for entry in manifest["files"]})
            for mutation in ("missing-g6", "wrong-cert", "wrong-index", "cross-arch", "version"):
                source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root / mutation, tool, tool.RC2_VERSION)
                candidate = candidates_b / "amd64"
                if mutation == "missing-g6":
                    (candidate / "release/tools/evidence/g6_validate.py").unlink()
                elif mutation in {"wrong-cert", "wrong-index"}:
                    record = json.loads((candidate / "build-record.json").read_text(encoding="utf-8"))
                    record["predecessor_certification"]["certification_sha256" if mutation == "wrong-cert" else "release_index_sha256"] = "0" * 64
                    (candidate / "build-record.json").write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "cross-arch":
                    manifest = json.loads((candidate / "release/manifest.json").read_text(encoding="utf-8"))
                    manifest["n_minus_one"] = tool.RC1_LINEAGES["arm64"]
                    (candidate / "release/manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                else:
                    metadata = json.loads((candidate / "production-bundle.json").read_text(encoding="utf-8"))
                    metadata["version"] = tool.VERSION
                    (candidate / "production-bundle.json").write_text(json.dumps(metadata), encoding="utf-8")
                with self.assertRaises(tool.CertificationError):
                    tool.certify(source_a, source_b, candidates_a, candidates_b, root / f"bad-{mutation}", commit, tool.RC2_VERSION)

    def clean_sources(self, root: Path) -> tuple[Path, Path, str]:
        origin = root / "origin"
        origin.mkdir(parents=True)
        (origin / "tracked.txt").write_text("clean\n", encoding="utf-8")
        for relative, contents in {
            "tools/worker/production_build.py": "driver fixture\n",
            "tools/worker/production_bundle.py": "bundle fixture\n",
        }.items():
            path = origin / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        for command in (
            ["git", "init", str(origin)],
            ["git", "-C", str(origin), "config", "user.email", "test@example.invalid"],
            ["git", "-C", str(origin), "config", "user.name", "test"],
            ["git", "-C", str(origin), "add", "."],
            ["git", "-C", str(origin), "commit", "-m", "fixture"],
        ):
            subprocess.run(command, check=True, capture_output=True)
        commit = subprocess.run(
            ["git", "-C", str(origin), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        sources = []
        for name in ("source-a", "source-b"):
            target = root / name
            subprocess.run(["git", "clone", "--quiet", str(origin), str(target)], check=True)
            subprocess.run(["git", "-C", str(target), "checkout", "--detach", commit], check=True, capture_output=True)
            sources.append(target)
        return sources[0], sources[1], commit

    def candidate(self, root: Path, tool, arch: str, commit: str, source: Path, version: str = "0.8.0-rc.1") -> None:
        candidate = root / arch
        release = candidate / "release"
        release.mkdir(parents=True)
        payloads = {
            "source-manifest.sha256": b"source\n",
            "sbom.spdx.json": b"{}\n",
            "attestations/live-web.json": b"{}\n",
        }
        for index in range(65):
            payloads[f"payload/{index:02d}"] = f"{arch}:{index}\n".encode()
        if version == tool.RC2_VERSION:
            payloads.update({"scripts/mvp/g6-staging-evidence.sh": b"g6\n", "tools/evidence/g6_validate.py": b"validate\n", "tools/evidence/g6_target_receipt.py": b"receipt\n"})
        entries = []
        for relative, value in sorted(payloads.items()):
            path = release / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            mode = 0o640 if relative == "source-manifest.sha256" else 0o644
            path.chmod(mode)
            entries.append({"path": relative, "sha256": hashlib.sha256(value).hexdigest(), "mode": mode})
        manifest = {
            "schema_version": 1,
            "product": "open-card",
            "version": version,
            "release_id": f"release-{arch}",
            "architecture": arch,
            "migration_version": tool.MIGRATION,
            "source_commit": commit,
            "protocol": "1.1",
            "config_dir": "/etc/open-card",
            "data_dir": "/var/lib/open-card",
            "compatibility": {"min_data_version": 1, "max_data_version": 24, "min_agent_protocol": "1.0", "max_agent_protocol": "1.1", "requires_data_backup": True},
            "n_minus_one": tool.RC0_LINEAGES[arch] if version == tool.VERSION else tool.RC1_LINEAGES[arch],
            "files": entries,
        }
        manifest_path = release / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        manifest_path.chmod(0o644)
        artifact_paths = tool.artifacts(version)
        archive = candidate / artifact_paths["archive"]
        with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as output:
                for path in sorted(release.rglob("*")):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(candidate).as_posix()
                    info = tarfile.TarInfo(relative)
                    info.size = path.stat().st_size
                    info.mode = path.stat().st_mode & 0o777
                    info.mtime = 0
                    with path.open("rb") as stream:
                        output.addfile(info, stream)
        bundle = candidate / artifact_paths["bundle_manifest"]
        bundle.write_text(
            f"{digest(archive)}  {archive.name}\n{digest(manifest_path)}  release/manifest.json\n",
            encoding="utf-8",
        )
        bundle.chmod(0o640)
        def tool_metadata(relative: str) -> dict[str, str]:
            path = source / relative
            blob = subprocess.run(
                ["git", "-C", str(source), "rev-parse", f"{commit}:{relative}"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            return {"commit": commit, "relative_path": relative, "commit_blob": blob, "sha256": digest(path)}

        record = {
            "schema_version": "open-card-production-build.v1",
            "production_accepted": False,
            "candidate": {"version": version, "migration_version": tool.MIGRATION, "source_commit": commit, "architecture": arch},
            "build_tool": {
                "commit": commit,
                "driver": tool_metadata("tools/worker/production_build.py"),
                "bundle": tool_metadata("tools/worker/production_bundle.py"),
            },
            "runtime_inputs": {"manifest_sha256": "a" * 64, "assets": {}},
            "tools": {
                "go_environment": {"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "GOWORK": "off"},
                "git_version": "git version fixture",
                "node_version": "vfixture",
                "npm_version": "fixture",
                "python_version": "Python fixture",
            },
            "stage_files": entries,
            "live_web": {"build_metadata_sha256": "1" * 64, "dist_tree_sha256": "2" * 64, "attestation_sha256": digest(release / "attestations/live-web.json"), "gate3_status": "pass_limited_external_linux_required"},
            "bundle": {"archive": archive.name, "archive_sha256": digest(archive), "manifest_sha256": digest(manifest_path), "bundle_manifest_sha256": digest(bundle)},
            "n_minus_one": {**(tool.RC0_LINEAGES[arch] if version == tool.VERSION else tool.RC1_LINEAGES[arch]), "status": "verified_local_candidate", "release_embedded": False},
            "commands": [["go", "build", str(root)]],
        }
        if version == tool.RC2_VERSION:
            record["predecessor_certification"] = {"certification_sha256": tool.RC1_CERTIFICATION_SHA256, "release_index_sha256": tool.RC1_RELEASE_INDEX_SHA256}
        (candidate / "build-record.json").write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        (candidate / "build-record.json").chmod(0o640)
        metadata = {
            "schema_version": 1,
            "product": "open-card",
            "version": version,
            "migration_version": tool.MIGRATION,
            "source_commit": commit,
            "production_accepted": False,
            "candidate_status": "upgrade_candidate",
            "n_minus_one": {
                "version": (tool.RC0_LINEAGES if version == tool.VERSION else tool.RC1_LINEAGES)[arch]["version"],
                "migration_version": (tool.RC0_LINEAGES if version == tool.VERSION else tool.RC1_LINEAGES)[arch]["migration_version"],
                "source_commit": (tool.RC0_LINEAGES if version == tool.VERSION else tool.RC1_LINEAGES)[arch]["source_commit"],
                "status": "verified_local_candidate",
                "release_embedded": False,
                "manifest_sha256": (tool.RC0_LINEAGES if version == tool.VERSION else tool.RC1_LINEAGES)[arch]["release_manifest_sha256"],
                "archive_sha256": (tool.RC0_LINEAGES if version == tool.VERSION else tool.RC1_LINEAGES)[arch]["archive_sha256"],
                "bundle_manifest_sha256": (tool.RC0_LINEAGES if version == tool.VERSION else tool.RC1_LINEAGES)[arch]["bundle_manifest_sha256"],
            },
            "live_web": {"status": "caller_evidence_digest_pinned", "bundle_structure_verified": True, "public_domain_verified": False, "attestation_sha256": digest(release / "attestations/live-web.json")},
            "production_binaries": tool.RC1_BINARIES,
            "excluded": ["open-card-caddy-fixture", "integration test binaries", "fixture archives"],
        }
        if version == tool.RC2_VERSION:
            metadata["predecessor_certification"] = {"certification_sha256": tool.RC1_CERTIFICATION_SHA256, "release_index_sha256": tool.RC1_RELEASE_INDEX_SHA256}
        (candidate / artifact_paths["production_bundle"]).write_text(json.dumps(metadata), encoding="utf-8")
        (candidate / artifact_paths["production_bundle"]).chmod(0o640)

    def candidate_sets(
        self, root: Path, tool, commit: str, source_a: Path, source_b: Path, version: str = "0.8.0-rc.1"
    ) -> tuple[Path, Path]:
        left, right = root / "candidates-a", root / "candidates-b"
        for candidate_set, source in ((left, source_a), (right, source_b)):
            candidate_set.mkdir()
            for arch in tool.ARCHES:
                self.candidate(candidate_set, tool, arch, commit, source, version)
        return left, right

    def fixture(self, root: Path, tool, version: str = "0.8.0-rc.1"):
        source_a, source_b, commit = self.clean_sources(root)
        candidates_a, candidates_b = self.candidate_sets(root, tool, commit, source_a, source_b, version)
        return source_a, source_b, candidates_a, candidates_b, commit

    def rewrite_archive_payload(self, candidate: Path, tool) -> None:
        archive = candidate / tool.ARTIFACTS["archive"]
        release = candidate / "release"
        with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as output:
                for path in sorted(release.rglob("*")):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(candidate).as_posix()
                    payload = b"archive-only-tamper\n" if relative == "release/payload/00" else path.read_bytes()
                    info = tarfile.TarInfo(relative)
                    info.size = len(payload)
                    info.mode = path.stat().st_mode & 0o777
                    info.mtime = 0
                    output.addfile(info, io.BytesIO(payload))
        manifest = release / "manifest.json"
        bundle = candidate / tool.ARTIFACTS["bundle_manifest"]
        bundle.write_text(
            f"{digest(archive)}  {archive.name}\n{digest(manifest)}  release/manifest.json\n",
            encoding="utf-8",
        )
        record_path = candidate / "build-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["bundle"]["archive_sha256"] = digest(archive)
        record["bundle"]["bundle_manifest_sha256"] = digest(bundle)
        record_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")

    def test_certifies_two_clean_candidate_sets_deterministically_without_paths(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root, tool)
            output = root / "certification"
            certification = tool.certify(source_a, source_b, candidates_a, candidates_b, output, commit)
            self.assertEqual(certification["scope"], "artifact_equality_only")
            self.assertTrue(all(certification["architectures"][arch]["equality"] for arch in tool.ARCHES))
            index = json.loads((output / "release-index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["schema"], "open-card-release-index.v1")
            self.assertFalse(index["production_accepted"])
            self.assertNotIn(str(root), (output / "certification.json").read_text(encoding="utf-8"))
            self.assertNotIn(str(root), (output / "release-index.json").read_text(encoding="utf-8"))
            duplicate = root / "certification-copy"
            tool.certify(source_a, source_b, candidates_a, candidates_b, duplicate, commit)
            self.assertEqual(
                (output / "certification.json").read_bytes(),
                (duplicate / "certification.json").read_bytes(),
            )

    def test_rejects_each_compared_artifact_mismatch_before_output(self) -> None:
        tool = load_tool()
        for name, relative in tool.ARTIFACTS.items():
            with self.subTest(artifact=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root, tool)
                (candidates_b / "amd64" / relative).write_bytes(b"tampered\n")
                output = root / "certification"
                with self.assertRaises(tool.CertificationError):
                    tool.certify(source_a, source_b, candidates_a, candidates_b, output, commit)
                self.assertFalse(output.exists())

    def test_rejects_semantic_tool_source_and_publication_failures(self) -> None:
        tool = load_tool()
        for mutation in ("semantic", "build-tool", "go-env", "dirty-source", "shared-common-dir", "mixed-lineage", "duplicate-json", "missing", "unsafe-archive", "existing-output"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root, tool)
                output = root / "certification"
                if mutation == "semantic":
                    record = json.loads((candidates_b / "arm64/build-record.json").read_text(encoding="utf-8"))
                    record["runtime_inputs"]["manifest_sha256"] = "b" * 64
                    (candidates_b / "arm64/build-record.json").write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "build-tool":
                    record = json.loads((candidates_b / "arm64/build-record.json").read_text(encoding="utf-8"))
                    record["build_tool"]["driver"]["sha256"] = "0" * 64
                    (candidates_b / "arm64/build-record.json").write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "go-env":
                    record = json.loads((candidates_b / "arm64/build-record.json").read_text(encoding="utf-8"))
                    record["tools"]["go_environment"]["GOARCH"] = "amd64"
                    (candidates_b / "arm64/build-record.json").write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "dirty-source":
                    (source_b / "untracked").write_text("dirty\n", encoding="utf-8")
                elif mutation == "shared-common-dir":
                    source_b = root / "shared-worktree"
                    subprocess.run(["git", "-C", str(source_a), "worktree", "add", "--detach", str(source_b), commit], check=True, capture_output=True)
                elif mutation == "mixed-lineage":
                    manifest = json.loads((candidates_b / "arm64/release/manifest.json").read_text(encoding="utf-8"))
                    manifest["n_minus_one"] = tool.RC0_LINEAGES["amd64"]
                    (candidates_b / "arm64/release/manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "missing":
                    (candidates_b / "amd64/release/sbom.spdx.json").unlink()
                elif mutation == "duplicate-json":
                    (candidates_b / "amd64/production-bundle.json").write_text(
                        '{"production_accepted":false,"production_accepted":false}\n',
                        encoding="utf-8",
                    )
                elif mutation == "unsafe-archive":
                    archive = candidates_b / "amd64" / tool.ARTIFACTS["archive"]
                    with tarfile.open(archive, "w:gz") as output_tar:
                        info = tarfile.TarInfo("../escape")
                        info.size = 1
                        output_tar.addfile(info, io.BytesIO(b"x"))
                else:
                    output.mkdir()
                with self.assertRaises(tool.CertificationError):
                    tool.certify(source_a, source_b, candidates_a, candidates_b, output, commit)
                if mutation != "existing-output":
                    self.assertFalse(output.exists())

    def test_no_replace_publication_keeps_complete_candidate_on_existing_output(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate = root / ".candidate"
            candidate.mkdir()
            (candidate / "certification.json").write_text("{}\n", encoding="utf-8")
            output = root / "output"
            output.mkdir()
            with self.assertRaises(tool.CertificationError):
                tool.publish_no_replace(candidate, output)
            self.assertTrue((candidate / "certification.json").is_file())

    def test_rejects_archive_binding_build_source_hash_and_unknown_fields(self) -> None:
        tool = load_tool()
        for mutation in ("archive-binding", "build-tool-source", "bundle-hash", "unknown-manifest", "unknown-metadata"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root, tool)
                if mutation == "archive-binding":
                    for candidate_set in (candidates_a, candidates_b):
                        self.rewrite_archive_payload(candidate_set / "amd64", tool)
                elif mutation == "build-tool-source":
                    path = candidates_b / "amd64/build-record.json"
                    record = json.loads(path.read_text(encoding="utf-8"))
                    record["build_tool"]["commit"] = "0" * 40
                    path.write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "bundle-hash":
                    path = candidates_b / "amd64/build-record.json"
                    record = json.loads(path.read_text(encoding="utf-8"))
                    record["bundle"]["archive_sha256"] = "0" * 64
                    path.write_text(json.dumps(record), encoding="utf-8")
                elif mutation == "unknown-manifest":
                    path = candidates_b / "amd64/release/manifest.json"
                    manifest = json.loads(path.read_text(encoding="utf-8"))
                    manifest["unexpected"] = True
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                else:
                    path = candidates_b / "amd64/production-bundle.json"
                    metadata = json.loads(path.read_text(encoding="utf-8"))
                    metadata["unexpected"] = True
                    path.write_text(json.dumps(metadata), encoding="utf-8")
                with self.assertRaises(tool.CertificationError):
                    tool.certify(source_a, source_b, candidates_a, candidates_b, root / "certification", commit)

    def test_rejects_tool_binding_tamper_in_both_sets_and_source_file_drift(self) -> None:
        tool = load_tool()
        for mutation in ("sha-and-blob", "relative-path", "source-file"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source_a, source_b, candidates_a, candidates_b, commit = self.fixture(root, tool)
                if mutation == "source-file":
                    (source_b / "tools/worker/production_build.py").write_text("drift\n", encoding="utf-8")
                else:
                    for candidate_set in (candidates_a, candidates_b):
                        for arch in tool.ARCHES:
                            path = candidate_set / arch / "build-record.json"
                            record = json.loads(path.read_text(encoding="utf-8"))
                            driver = record["build_tool"]["driver"]
                            if mutation == "sha-and-blob":
                                driver["sha256"] = "0" * 64
                                driver["commit_blob"] = "0" * 40
                            else:
                                driver["relative_path"] = "tools/worker/other.py"
                            path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
                output = root / "certification"
                with self.assertRaises(tool.CertificationError):
                    tool.certify(source_a, source_b, candidates_a, candidates_b, output, commit)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
