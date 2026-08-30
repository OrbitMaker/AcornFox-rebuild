#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/evidence"))
import g6_target_receipt as builder  # noqa: E402
import g6_validate as g6  # noqa: E402


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class TargetReceiptTest(unittest.TestCase):
    def temporary(self):
        return tempfile.TemporaryDirectory(dir=ROOT, prefix=".g6-target-")

    def git(self, repo: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()

    def write_json(self, path: Path, value: object, mode: int = 0o600) -> None:
        path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        path.chmod(mode)

    def fixture(self, root: Path, *, annotated: bool = True) -> dict[str, object]:
        repo = root / "repo"
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "g6@example.invalid")
        self.git(repo, "config", "user.name", "g6")
        (repo / "source.txt").write_text("source\n", encoding="utf-8")
        self.git(repo, "add", "source.txt")
        self.git(repo, "commit", "-qm", "source")
        commit = self.git(repo, "rev-parse", "HEAD")
        tag_args = ("tag", "-a", "v0.8.0-rc.1", "-m", "g6") if annotated else ("tag", "v0.8.0-rc.1")
        self.git(repo, *tag_args)

        release = root / "release"
        release.mkdir()
        payload = release / "payload"
        payload.write_bytes(b"payload")
        payload.chmod(0o755)
        manifest_path = release / "manifest.json"
        manifest = {
            "version": "0.8.0-rc.1",
            "source_commit": commit,
            "architecture": "amd64",
            "migration_version": "0024",
            "files": [{"path": "payload", "sha256": digest(b"payload"), "mode": 0o755}],
        }
        self.write_json(manifest_path, manifest)
        release_sha = digest(manifest_path.read_bytes())
        archive = root / "open-card-0.8.0-rc.1-production.tar.gz"
        archive.write_bytes(b"archive")
        archive.chmod(0o600)
        bundle = root / "bundle-manifest.sha256"
        bundle.write_bytes(f"{digest(b'archive')}  {archive.name}\n{release_sha}  release/manifest.json\n".encode())
        bundle.chmod(0o600)
        installation = root / "installation-id"
        installation.write_bytes(b"installation-id\n")
        installation.chmod(0o600)
        output = root / "output"
        output.mkdir(mode=0o700)
        return {
            "root": root,
            "repo": repo,
            "commit": commit,
            "release": release,
            "manifest": manifest,
            "manifest_path": manifest_path,
            "bundle": bundle,
            "archive": archive,
            "installation": installation,
            "output": output,
        }

    def identity(self, fixture: dict[str, object], *, with_installation: bool, name: str = "identity") -> Path:
        manifest_path = fixture["manifest_path"]
        bundle = fixture["bundle"]
        value = {
            "run_id": "g6-target-1",
            "source": {
                "tag": "v0.8.0-rc.1",
                "commit": fixture["commit"],
                "bundle_manifest_sha256": digest(bundle.read_bytes()),
            },
            "target": {
                "provider": "tencent",
                "product": "cvm",
                "instance_id": "ins-g6-target",
                "public_ipv4": "8.8.8.8",
            },
            "source_repo": str(fixture["repo"]),
            "release_manifest": str(manifest_path),
            "release_manifest_sha256": digest(manifest_path.read_bytes()),
            "bundle_manifest": str(bundle),
        }
        if with_installation:
            value["installation_id_file"] = str(fixture["installation"])
        path = fixture["root"] / f"{name}.json"
        self.write_json(path, value)
        return path

    def phase_inputs(self, fixture: dict[str, object], phase: str) -> tuple[Path, list[str]]:
        names = ["host-preflight.json"] if phase == "snapshot-preinstall" else list(builder.FACT_ARTIFACTS.values())
        hashes: dict[str, str] = {}
        declarations: list[str] = []
        for name in names:
            path = fixture["root"] / f"{phase}-{name}"
            raw = f"{phase}:{name}".encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            hashes[name] = digest(raw)
            declarations.append(f"{name}={path}")
        if phase == "snapshot-preinstall":
            facts = {
                "host_preflight_sha256": hashes["host-preflight.json"],
                "existing_installation": False,
                "colocated_workloads": False,
                "source_tag_verified": True,
                "bundle_manifest_verified": True,
            }
        else:
            facts = {
                "units": {unit: {"active": True, "enabled": True} for unit in g6.UNITS},
                "upgrade_safe_target_active": True,
                "upgrade_safe_target_enabled": True,
                "active_pointer": "activations/act-g6",
                "current_pointer": "active/release",
                "previous_active_pointer": "",
                "upgrade_marker_absent": True,
                **{field: hashes[name] for field, name in builder.FACT_ARTIFACTS.items()},
            }
            if phase == "restart-drill":
                facts |= {"action": "restart_services", "confirmation_sha256": "1" * 64}
            if phase.startswith("reboot-"):
                facts |= {
                    "boot_id": "boot-b" if phase == "reboot-verify" else "boot-a",
                    "confirmation_sha256": "1" * 64,
                    "source_tag": "v0.8.0-rc.1",
                    "source_commit": fixture["commit"],
                    "bundle_manifest_sha256": digest(fixture["bundle"].read_bytes()),
                }
        facts_path = fixture["root"] / f"{phase}-facts.json"
        self.write_json(facts_path, facts)
        return facts_path, declarations

    def publish(self, fixture: dict[str, object], phase: str, previous: Path | None = None):
        facts, declarations = self.phase_inputs(fixture, phase)
        identity = self.identity(fixture, with_installation=phase != "snapshot-preinstall", name=f"identity-{phase}")
        return builder.publish(phase, identity, facts, declarations, fixture["output"], previous, owner=os.getuid())

    def full_sequence(self, fixture: dict[str, object]) -> dict[str, Path]:
        receipts: dict[str, Path] = {}
        previous = None
        for phase in ("snapshot-preinstall", "install-verify", "restart-drill", "reboot-handoff", "reboot-verify"):
            self.assertEqual(self.publish(fixture, phase, previous)["result"], "pass")
            previous = fixture["output"] / phase / "receipt.json"
            receipts[phase] = previous
        return receipts

    def test_five_phase_publish_replay_and_order(self) -> None:
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw))
            receipts = self.full_sequence(fixture)
            facts, declarations = self.phase_inputs(fixture, "reboot-verify")
            replay = builder.publish("reboot-verify", self.identity(fixture, with_installation=True, name="replay"), facts, declarations, fixture["output"], receipts["reboot-handoff"], owner=os.getuid())
            self.assertEqual(replay["phase"], "REBOOT_VERIFY")
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "install-verify", None)
            wrong = json.loads(receipts["reboot-handoff"].read_text(encoding="utf-8"))
            wrong["facts"]["boot_id"] = "boot-b"
            self.write_json(receipts["reboot-handoff"], wrong)
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "reboot-verify", receipts["reboot-handoff"])

    def test_git_and_tag_provenance_fail_closed(self) -> None:
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw))
            (fixture["repo"] / "dirty").write_text("dirty", encoding="utf-8")
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "snapshot-preinstall")
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw), annotated=False)
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "snapshot-preinstall")
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw))
            (fixture["repo"] / "second").write_text("second", encoding="utf-8")
            self.git(fixture["repo"], "add", "second")
            self.git(fixture["repo"], "commit", "-qm", "second")
            fixture["commit"] = self.git(fixture["repo"], "rev-parse", "HEAD")
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "snapshot-preinstall")
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw))
            self.git(fixture["repo"], "tag", "-a", "other-annotated", "-m", "other")
            identity = self.identity(fixture, with_installation=False, name="wrong-tag")
            value = json.loads(identity.read_text(encoding="utf-8")); value["source"]["tag"] = "other-annotated"; self.write_json(identity, value)
            facts, declarations = self.phase_inputs(fixture, "snapshot-preinstall")
            with self.assertRaises(g6.ValidationError):
                builder.publish("snapshot-preinstall", identity, facts, declarations, fixture["output"], None, owner=os.getuid())

    def test_release_manifest_and_bundle_failures(self) -> None:
        mutations = ("source", "arch", "migration", "digest", "path", "symlink", "extra", "mode", "bundle-duplicate", "bundle-extra", "bundle-unsafe", "bundle-missing", "bundle-entry-drift")
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.temporary() as raw:
                fixture = self.fixture(Path(raw))
                manifest = fixture["manifest"]
                payload = fixture["release"] / "payload"
                if mutation == "source": manifest["source_commit"] = "f" * 40
                elif mutation == "arch": manifest["architecture"] = "arm64"
                elif mutation == "migration": manifest["migration_version"] = "0023"
                elif mutation == "digest": manifest["files"][0]["sha256"] = "0" * 64
                elif mutation == "path": manifest["files"][0]["path"] = "/etc/passwd"
                elif mutation == "symlink":
                    payload.unlink(); outside = fixture["root"] / "outside"; outside.write_bytes(b"payload"); payload.symlink_to(outside)
                elif mutation == "extra": (fixture["release"] / "extra").write_bytes(b"extra")
                elif mutation == "mode": payload.chmod(0o666)
                if mutation in {"source", "arch", "migration", "digest", "path"}:
                    self.write_json(fixture["manifest_path"], manifest)
                if mutation.startswith("bundle-"):
                    release_sha = digest(fixture["manifest_path"].read_bytes())
                    archive_line = f"{digest(fixture['archive'].read_bytes())}  {fixture['archive'].name}\n"
                    if mutation == "bundle-duplicate": content = f"{release_sha}  release/manifest.json\n{release_sha}  release/manifest.json\n"
                    elif mutation == "bundle-extra": content = archive_line + f"{release_sha}  release/manifest.json\n{'0'*64}  extra.txt\n"
                    elif mutation == "bundle-unsafe": content = f"{release_sha}  ../manifest.json\n"
                    elif mutation == "bundle-missing": content = archive_line + f"{release_sha}  release/other.json\n"
                    else:
                        content = archive_line + f"{release_sha}  release/manifest.json\n"
                        fixture["archive"].write_bytes(b"drift")
                    fixture["bundle"].write_text(content, encoding="utf-8")
                with self.assertRaises(g6.ValidationError):
                    self.publish(fixture, "snapshot-preinstall")

    def test_installation_and_artifact_safety(self) -> None:
        for mutation in ("installation-mode", "installation-symlink", "artifact-mode", "artifact-hardlink", "artifact-symlink", "fact-digest"):
            with self.subTest(mutation=mutation), self.temporary() as raw:
                fixture = self.fixture(Path(raw))
                pre = self.publish(fixture, "snapshot-preinstall")
                previous = fixture["output"] / "snapshot-preinstall/receipt.json"
                facts, declarations = self.phase_inputs(fixture, "install-verify")
                identity = self.identity(fixture, with_installation=True, name="install-negative")
                artifact_path = Path(declarations[0].split("=", 1)[1])
                if mutation == "installation-mode": fixture["installation"].chmod(0o644)
                elif mutation == "installation-symlink":
                    fixture["installation"].unlink(); target = fixture["root"] / "installation-target"; target.write_bytes(b"id"); fixture["installation"].symlink_to(target)
                elif mutation == "artifact-mode": artifact_path.chmod(0o666)
                elif mutation == "artifact-hardlink": os.link(artifact_path, fixture["root"] / "artifact-link")
                elif mutation == "artifact-symlink":
                    raw_value = artifact_path.read_bytes(); artifact_path.unlink(); target = fixture["root"] / "artifact-target"; target.write_bytes(raw_value); artifact_path.symlink_to(target)
                else:
                    value = json.loads(facts.read_text(encoding="utf-8")); value["host_preflight_sha256"] = "0" * 64; self.write_json(facts, value)
                with self.assertRaises(g6.ValidationError):
                    builder.publish("install-verify", identity, facts, declarations, fixture["output"], previous, owner=os.getuid())

    def test_replay_conflict_incomplete_and_cli_redaction(self) -> None:
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw))
            self.publish(fixture, "snapshot-preinstall")
            phase = fixture["output"] / "snapshot-preinstall"
            (phase / "extra").write_bytes(b"extra")
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "snapshot-preinstall")
        with self.temporary() as raw:
            fixture = self.fixture(Path(raw))
            incomplete = fixture["output"] / "snapshot-preinstall"
            incomplete.mkdir(mode=0o700)
            (incomplete / "host-preflight.json").write_bytes(b"incomplete")
            with self.assertRaises(g6.ValidationError):
                self.publish(fixture, "snapshot-preinstall")
        with self.temporary() as raw:
            root = Path(raw)
            bad = root / "secret-input.json"
            self.write_json(bad, {"api_key": "must-not-leak"})
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/evidence/g6_target_receipt.py"), "publish", "--phase", "snapshot-preinstall", "--identity", str(bad), "--facts", str(bad), "--artifact", f"host-preflight.json={bad}", "--output-dir", str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout.strip(), "invalid_gate6_evidence")
            self.assertNotIn("must-not-leak", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
