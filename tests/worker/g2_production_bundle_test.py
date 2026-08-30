from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/production_bundle.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("production_bundle", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_repo(root: Path, migration_version: str) -> tuple[Path, str]:
    repo = root / "repo"
    for path, content in {
        "go.mod": "module example.test/open-card\ngo 1.25\n",
        "go.sum": "",
        "api/openapi/openapi.yaml": "openapi: 3.0.3\ninfo: {title: x, version: x}\npaths: {}\n",
        "cmd/open-card-server/main.go": "package main\n",
        "internal/example.go": "package internal\n",
        "deploy/systemd/open-card-server.service": "[Service]\n",
        "deploy/systemd/open-card-agent.service": "[Service]\n",
        "deploy/systemd/open-card-buildkit.service": "[Service]\n",
        "deploy/systemd/open-card-caddy.service": "[Service]\n",
        "deploy/systemd/open-card-edge.service": "[Service]\n",
        "deploy/systemd/open-card-upgrade-recover.service": "[Service]\n",
        "deploy/systemd/open-card-upgrade-safe.target": "[Unit]\n",
        "deploy/systemd/open-card-upgrade-finalize.service": "[Service]\n",
        "deploy/systemd/open-card-edge.service.d/10-upgrade-marker.conf": "[Unit]\n",
        "deploy/caddy/open-card-edge.Caddyfile.example": "{}\n",
        "deploy/caddy/open-card-edge.env.example": "# env\n",
        "docs/licenses/licenses-manifest.json": "{}\n",
        "web/dist/index.html": "<!doctype html>\n",
    }.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    for script in load_tool().INSTALLER_SCRIPTS:
        target = repo / "scripts/mvp" / script
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        target.chmod(0o755)
    for number in range(1, int(migration_version) + 1):
        target = repo / "migrations/control-plane" / f"{number:04d}_schema.sql"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("-- migration\n", encoding="utf-8")
    for command in (["git", "init", str(repo)], ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], ["git", "-C", str(repo), "config", "user.name", "test"], ["git", "-C", str(repo), "add", "."], ["git", "-C", str(repo), "commit", "-m", "fixture"]):
        subprocess.run(command, check=True, capture_output=True)
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    return repo, commit


class ProductionBundleTests(unittest.TestCase):

    def test_private_workspaces_stay_below_the_build_stage(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        self.assertNotIn("dir=output.parent", source)
        self.assertIn('prefix=f".{output.name}.inputs-", dir=stage.parent', source)
        self.assertIn('prefix=f".{output.name}.build-", dir=inputs', source)

    def attestation_digest(self, attestation: Path) -> str:
        return hashlib.sha256(attestation.read_bytes()).hexdigest()

    def stage(self, root: Path) -> Path:
        stage = root / "stage"
        for name in (*load_tool().BINARIES, *load_tool().RUNTIME):
            path = stage / "binaries/amd64" / name if name in load_tool().BINARIES else stage / "runtime/amd64" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            path.chmod(0o755)
        return stage

    def live_web(self, root: Path, tool, commit: str) -> tuple[Path, Path]:
        dist = root / "live-dist"
        dist.mkdir()
        (dist / "index.html").write_text("<!doctype html><title>live</title>", encoding="utf-8")
        metadata = {"mode":"live","apiBaseUrl":"/api/v1","schemaVersion":"open-card-build-attestation.v1"}
        (dist / "build-metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        attestation = root / "live-attestation.json"
        attestation.write_text(json.dumps({"schema_version":"open-card-live-attestation.v1","source_commit":commit,"build_metadata_sha256":hashlib.sha256((dist / "build-metadata.json").read_bytes()).hexdigest(),"dist_tree_sha256":tool.tree_digest(dist),"gate3_status":"pass_limited_external_linux_required"}), encoding="utf-8")
        return dist, attestation

    def test_rc1_structure_only_needs_no_attestation_or_n_minus_one(self) -> None:
        tool = load_tool()
        help_result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--source-commit", help_result.stdout)
        self.assertIn("--live-attestation-sha256", help_result.stdout)
        parse_result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "assemble",
                "--stage-root",
                "missing-stage",
                "--repo-root",
                "missing-repo",
                "--output-root",
                "missing-output",
                "--web-dist",
                "missing-web-dist",
                "--version",
                "0.8.0-rc.1",
                "--migration-version",
                "0024",
                "--source-commit",
                "0" * 40,
                "--structure-only",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(parse_result.returncode, 1)
        self.assertIn("required directory is missing", parse_result.stdout)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo, commit = minimal_repo(root, "0024")
            output = root / "production"
            dist = root / "dist"; dist.mkdir(); (dist / "index.html").write_text("x", encoding="utf-8")
            tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.1", migration_version="0024", source_commit=commit, structure_only=True)
            self.assertFalse((output / "release/manifest.json").exists())
            self.assertFalse(list(output.glob("*.tar.gz")))

    def test_boot_safe_units_are_canonical_and_included_in_release_contract(self) -> None:
        tool = load_tool()
        recovery = """[Unit]
Description=Prepare interrupted Open Card upgrade recovery
Wants=network-online.target
After=local-fs.target network-online.target
Before=open-card-upgrade-safe.target

[Service]
Type=oneshot
ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover-prepare --pending
TimeoutStartSec=15min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system
"""
        safe_target = """[Unit]
Description=Open Card upgrade-safe boot barrier
Requires=open-card-upgrade-recover.service
Wants=open-card-upgrade-finalize.service
After=open-card-upgrade-recover.service
Before=open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service open-card-upgrade-finalize.service

[Install]
WantedBy=multi-user.target
RequiredBy=open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service
"""
        finalizer = """[Unit]
Description=Finalize interrupted Open Card upgrade recovery
After=open-card-upgrade-safe.target
ConditionPathExists=/var/lib/open-card/upgrade-in-progress

[Service]
Type=oneshot
ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover-finalize --pending
TimeoutStartSec=15min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system
"""
        drop_in = """[Unit]
ConditionPathExists=!/var/lib/open-card/upgrade-in-progress
"""
        expected = {
            "open-card-upgrade-recover.service": recovery,
            "open-card-upgrade-safe.target": safe_target,
            "open-card-upgrade-finalize.service": finalizer,
            "open-card-edge.service.d/10-upgrade-marker.conf": drop_in,
        }
        for path, contents in expected.items():
            self.assertEqual((ROOT / "deploy/systemd" / path).read_text(encoding="utf-8"), contents)
        self.assertEqual(set(tool.systemd_files("0.8.0-rc.0")), set(tool.RC0_UNITS))
        self.assertEqual(
            set(tool.systemd_files("0.8.0-rc.1")),
            set(tool.UNITS) | set(tool.UNIT_DROP_INS),
        )
        self.assertFalse("[Install]" in recovery or "[Install]" in finalizer)
        self.assertNotIn("Before=open-card-edge.service", finalizer)
        self.assertIn("RequiredBy=open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service", safe_target)
        self.assertIn("open-card-upgrade", tool.BINARIES)
        self.assertIn("open-card-upgrade-recover.service", tool.RC0_UNITS)
        self.assertTrue({"open-card-upgrade-safe.target", "open-card-upgrade-finalize.service"} <= set(tool.UNITS))
        self.assertIn("open-card-edge.service.d/10-upgrade-marker.conf", tool.UNIT_DROP_INS)

    def test_rc0_bootstrap_build_contains_provenance_and_installers(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo, commit = minimal_repo(root, "0023")
            dist, attestation = self.live_web(root, tool, commit)
            output = root / "production"
            previous_umask = os.umask(0o077)
            try:
                metadata = tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
            finally:
                os.umask(previous_umask)
            manifest = json.loads((output / "release/manifest.json").read_text(encoding="utf-8"))
            self.assertEqual((manifest["version"], manifest["migration_version"], manifest["compatibility"]["max_data_version"], manifest["source_commit"]), ("0.8.0-rc.0", "0023", 23, commit))
            self.assertEqual(metadata["live_web"]["public_domain_verified"], False)
            for script in tool.INSTALLER_SCRIPTS:
                self.assertTrue((output / "release/scripts/mvp" / script).is_file())
            self.assertTrue((output / "release/attestations/live-web.json").is_file())
            self.assertTrue((output / "release/source-commit.txt").is_file())
            names = {item["path"] for item in manifest["files"]}
            self.assertFalse(any("dns-dry-run" in name or "fixture" in name for name in names))
            web_entry = next(item for item in manifest["files"] if item["path"] == "web/dist/index.html")
            self.assertEqual(web_entry["mode"], 0o644)
            self.assertEqual((output / "release/web").stat().st_mode & 0o777, 0o755)
            self.assertEqual((output / "release/web/dist").stat().st_mode & 0o777, 0o755)

    def test_rc0_bootstrap_archive_is_reproducible(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo, commit = minimal_repo(root, "0023")
            dist, attestation = self.live_web(root, tool, commit)
            first = root / "first"; second = root / "second"
            for output in (first, second):
                tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
            first_archive = next(first.glob("*.tar.gz")); second_archive = next(second.glob("*.tar.gz"))
            self.assertEqual(hashlib.sha256(first_archive.read_bytes()).hexdigest(), hashlib.sha256(second_archive.read_bytes()).hexdigest())
            self.assertEqual(hashlib.sha256((first / "release/manifest.json").read_bytes()).hexdigest(), hashlib.sha256((second / "release/manifest.json").read_bytes()).hexdigest())

    def test_rc1_requires_verified_external_rc0(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rc0_repo, rc0_commit = minimal_repo(root / "rc0", "0023")
            rc0_dist, rc0_attestation = self.live_web(root / "rc0", tool, rc0_commit)
            rc0_output = root / "rc0-output"
            tool.assemble(self.stage(root / "rc0"), rc0_repo, rc0_output, "amd64", None, None, rc0_dist, version="0.8.0-rc.0", migration_version="0023", source_commit=rc0_commit, live_attestation=rc0_attestation, live_attestation_sha256=self.attestation_digest(rc0_attestation))
            checksum = hashlib.sha256((rc0_output / "release/manifest.json").read_bytes()).hexdigest()
            archive_digest = hashlib.sha256(next(rc0_output.glob("*.tar.gz")).read_bytes()).hexdigest()
            bundle_digest = hashlib.sha256((rc0_output / "bundle-manifest.sha256").read_bytes()).hexdigest()
            tool.RC0_SOURCE_COMMIT = rc0_commit
            tool.N_MINUS_ONE_RELEASE_MANIFEST_SHA256 = checksum
            tool.N_MINUS_ONE_ARCHIVE_SHA256 = archive_digest
            tool.N_MINUS_ONE_BUNDLE_MANIFEST_SHA256 = bundle_digest
            rc1_repo, rc1_commit = minimal_repo(root / "rc1", "0024")
            rc1_dist, rc1_attestation = self.live_web(root / "rc1", tool, rc1_commit)
            output = root / "rc1-output"
            metadata = tool.assemble(self.stage(root / "rc1"), rc1_repo, output, "amd64", rc0_output / "release", checksum, rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation), n_minus_one_archive_sha256=archive_digest, n_minus_one_bundle_manifest_sha256=bundle_digest)
            self.assertEqual(metadata["n_minus_one"]["status"], "verified_local_candidate")
            manifest = json.loads((output / "release/manifest.json").read_text(encoding="utf-8"))
            paths = {item["path"] for item in manifest["files"]}
            self.assertTrue({
                "bin/open-card-upgrade",
                "systemd/open-card-upgrade-recover.service",
                "systemd/open-card-upgrade-safe.target",
                "systemd/open-card-upgrade-finalize.service",
                "systemd/open-card-edge.service.d/10-upgrade-marker.conf",
            } <= paths)
            sbom = json.loads((output / "release/sbom.spdx.json").read_text(encoding="utf-8"))
            sbom_names = {package["name"] for package in sbom["packages"]}
            self.assertIn("bin/open-card-upgrade", sbom_names)
            self.assertIn("systemd/open-card-upgrade-recover.service", sbom_names)
            self.assertIn("systemd/open-card-upgrade-safe.target", sbom_names)
            self.assertIn("systemd/open-card-upgrade-finalize.service", sbom_names)
            self.assertIn("systemd/open-card-edge.service.d/10-upgrade-marker.conf", sbom_names)
            bad = root / "bad-output"
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(self.stage(root / "rc1"), rc1_repo, bad, "amd64", rc0_output / "release", "0" * 64, rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation))
            self.assertFalse(bad.exists())
            server_binary = rc0_output / "release/bin/open-card-server"
            original_binary = server_binary.read_bytes()
            server_binary.write_bytes(b"tampered")
            bad = root / "tampered-output"
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(self.stage(root / "rc1"), rc1_repo, bad, "amd64", rc0_output / "release", checksum, rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation))
            self.assertFalse(bad.exists())
            server_binary.write_bytes(original_binary)
            manifest_path = rc0_output / "release/manifest.json"
            original_manifest = manifest_path.read_bytes()

            with self.subTest("duplicate N-1 path"):
                manifest = json.loads(original_manifest)
                manifest["files"].append(manifest["files"][0])
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                duplicate = root / "duplicate-n-minus-one"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root / "rc1"), rc1_repo, duplicate, "amd64", rc0_output / "release", self.attestation_digest(manifest_path), rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation))
                self.assertFalse(duplicate.exists())

            with self.subTest("invalid N-1 checksum"):
                manifest = json.loads(original_manifest)
                manifest["files"][0]["sha256"] = "g" * 64
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                invalid = root / "invalid-n-minus-one-digest"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root / "rc1"), rc1_repo, invalid, "amd64", rc0_output / "release", self.attestation_digest(manifest_path), rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation))
                self.assertFalse(invalid.exists())

            with self.subTest("unsafe N-1 mode"):
                manifest = json.loads(original_manifest)
                manifest["files"][0]["mode"] = 0o777
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                invalid = root / "invalid-n-minus-one-mode"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root / "rc1"), rc1_repo, invalid, "amd64", rc0_output / "release", self.attestation_digest(manifest_path), rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation))
                self.assertFalse(invalid.exists())

            manifest_path.write_bytes(original_manifest)
            with self.subTest("unlisted N-1 file"):
                extra = rc0_output / "release/extra-unlisted"
                extra.write_bytes(b"extra")
                unlisted = root / "unlisted-n-minus-one"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root / "rc1"), rc1_repo, unlisted, "amd64", rc0_output / "release", checksum, rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation))
                self.assertFalse(unlisted.exists())
                extra.unlink()

            with self.subTest("N-1 mutation after snapshot does not alter provenance"):
                original_copy_tree = tool.copy_tree
                changed = False

                def copy_then_mutate(source, *args, **kwargs):
                    nonlocal changed
                    result = original_copy_tree(source, *args, **kwargs)
                    if source == rc0_output / "release" and not changed:
                        manifest_path.write_text("{}", encoding="utf-8")
                        changed = True
                    return result

                raced = root / "n-minus-one-snapshot"
                with mock.patch.object(tool, "copy_tree", side_effect=copy_then_mutate):
                    metadata = tool.assemble(self.stage(root / "rc1"), rc1_repo, raced, "amd64", rc0_output / "release", checksum, rc1_dist, version="0.8.0-rc.1", migration_version="0024", source_commit=rc1_commit, live_attestation=rc1_attestation, live_attestation_sha256=self.attestation_digest(rc1_attestation), n_minus_one_archive_sha256=archive_digest, n_minus_one_bundle_manifest_sha256=bundle_digest)
                self.assertTrue(changed)
                self.assertEqual(metadata["n_minus_one"]["source_commit"], rc0_commit)

    def test_rc0_rejects_missing_binary_and_test_only_payload(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo, commit = minimal_repo(root, "0023")
            dist, attestation = self.live_web(root, tool, commit)
            stage = self.stage(root)
            (stage / "binaries/amd64/open-card-admin").unlink()
            missing = root / "missing"
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(stage, repo, missing, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
            self.assertFalse(missing.exists())
            (dist / "unit.test.js").write_text("fixture", encoding="utf-8")
            data = json.loads(attestation.read_text(encoding="utf-8"))
            data["dist_tree_sha256"] = tool.tree_digest(dist)
            attestation.write_text(json.dumps(data), encoding="utf-8")
            payload = root / "payload"
            with self.assertRaisesRegex(tool.ProductionBundleError, "test-only"):
                tool.assemble(self.stage(root), repo, payload, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
            self.assertFalse(payload.exists())
            checksum_only = root / "checksum-only"
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(self.stage(root), repo, checksum_only, "amd64", None, "0" * 64, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
            self.assertFalse(checksum_only.exists())
        with self.subTest("late copied license payload leaves no output"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, _ = minimal_repo(root, "0023")
                late_fixture = repo / "docs/licenses/test-fixture.json"
                late_fixture.write_text("{}", encoding="utf-8")
                subprocess.run(["git", "-C", str(repo), "add", str(late_fixture)], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(repo), "commit", "-m", "tracked test payload"], check=True, capture_output=True)
                commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
                dist, attestation = self.live_web(root, tool, commit)
                output = root / "late-license"
                with self.assertRaisesRegex(tool.ProductionBundleError, "test-only"):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertFalse(output.exists())

    def test_rc0_rejects_invalid_provenance_before_creating_output(self) -> None:
        tool = load_tool()
        with self.subTest("attestation source commit"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                dist, attestation = self.live_web(root, tool, commit)
                data = json.loads(attestation.read_text(encoding="utf-8"))
                data["source_commit"] = "0" * 40
                attestation.write_text(json.dumps(data), encoding="utf-8")
                output = root / "bad-attestation-source"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertFalse(output.exists())
        with self.subTest("dist tree digest"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                dist, attestation = self.live_web(root, tool, commit)
                (dist / "index.html").write_text("<p>changed</p>", encoding="utf-8")
                output = root / "bad-dist-tree"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertFalse(output.exists())
        with self.subTest("dirty tracked repository"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                dist, attestation = self.live_web(root, tool, commit)
                (repo / "cmd/open-card-server/main.go").write_text("package main\n// dirty\n", encoding="utf-8")
                output = root / "dirty-repository"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertFalse(output.exists())
        with self.subTest("wrong legal source commit"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                dist, attestation = self.live_web(root, tool, commit)
                output = root / "wrong-source-commit"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit="0" * 40, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertFalse(output.exists())
        with self.subTest("hidden untracked repository file"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                subprocess.run(["git", "-C", str(repo), "config", "status.showUntrackedFiles", "no"], check=True, capture_output=True)
                (repo / "internal/untracked.go").write_text("package internal\n", encoding="utf-8")
                dist, attestation = self.live_web(root, tool, commit)
                output = root / "hidden-untracked"
                with self.assertRaises(tool.ProductionBundleError):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertFalse(output.exists())
        with self.subTest("self-consistent forged attestation is not externally pinned"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                dist, attestation = self.live_web(root, tool, commit)
                trusted_digest = self.attestation_digest(attestation)
                (dist / "index.html").write_text("<p>forged but self-consistent</p>", encoding="utf-8")
                forged = json.loads(attestation.read_text(encoding="utf-8"))
                forged["dist_tree_sha256"] = tool.tree_digest(dist)
                attestation.write_text(json.dumps(forged), encoding="utf-8")
                output = root / "forged-attestation"
                with self.assertRaisesRegex(tool.ProductionBundleError, "pinned evidence"):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=trusted_digest)
                self.assertFalse(output.exists())
        with self.subTest("source manifest remains bound to the commit tree"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo, commit = minimal_repo(root, "0023")
                dist, attestation = self.live_web(root, tool, commit)
                original_run = tool.subprocess.run
                changed = False

                def status_then_mutate(*args, **kwargs):
                    nonlocal changed
                    result = original_run(*args, **kwargs)
                    command = args[0]
                    if not changed and "status" in command:
                        original_run(["git", "-C", str(repo), "update-index", "--force-remove", "internal/example.go"], check=True, capture_output=True)
                        changed = True
                    return result

                output = root / "commit-tree-snapshot"
                with mock.patch.object(tool.subprocess, "run", side_effect=status_then_mutate):
                    tool.assemble(self.stage(root), repo, output, "amd64", None, None, dist, version="0.8.0-rc.0", migration_version="0023", source_commit=commit, live_attestation=attestation, live_attestation_sha256=self.attestation_digest(attestation))
                self.assertTrue(changed)
                source_manifest = (output / "release/source-manifest.sha256").read_text(encoding="utf-8")
                self.assertIn("  internal/example.go\n", source_manifest)


if __name__ == "__main__":
    unittest.main()
