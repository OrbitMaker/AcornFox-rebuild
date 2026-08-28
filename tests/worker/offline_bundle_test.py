from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_TOOL = REPO_ROOT / "tools" / "worker" / "offline_bundle.py"
WRAPPER = REPO_ROOT / "scripts" / "mvp" / "prepare-clean-worker-bundle.sh"


class OfflineBundleTests(unittest.TestCase):
    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(BUNDLE_TOOL), *args],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def build(self, output: Path, *inputs: tuple[str, Path]) -> subprocess.CompletedProcess[str]:
        args = ["build", "--output", str(output)]
        for archive_path, source in inputs:
            args.extend(["--input", f"{archive_path}={source}"])
        return self.run_tool(*args)

    def test_build_001_is_reproducible_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            alpha = root / "alpha.deb"
            zulu = root / "zulu.deb"
            alpha.write_bytes(b"alpha package\n")
            zulu.write_bytes(b"zulu package\n")
            first = root / "first.tar"
            second = root / "second.tar"

            completed = self.build(first, ("payload/zulu.deb", zulu), ("payload/alpha.deb", alpha))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            completed = self.build(second, ("payload/alpha.deb", alpha), ("payload/zulu.deb", zulu))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            validated = self.run_tool("validate", "--archive", str(first))
            self.assertEqual(validated.returncode, 0, validated.stdout + validated.stderr)
            result = json.loads(validated.stdout)
            self.assertTrue(result["valid"])
            self.assertEqual(result["entries"], 2)
            with tarfile.open(first, "r:") as archive:
                self.assertEqual([member.name for member in archive.getmembers()], ["manifest.json", "payload/alpha.deb", "payload/zulu.deb"])
                manifest = json.loads(archive.extractfile("manifest.json").read())
                self.assertEqual(manifest["entries"][0]["path"], "payload/alpha.deb")
                self.assertEqual(manifest["entries"][0]["mode"], "0644")

    def test_build_002_rejects_tampered_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            source = root / "worker.deb"
            source.write_bytes(b"worker package\n")
            archive_path = root / "bundle.tar"
            built = self.build(archive_path, ("payload/worker.deb", source))
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            with tarfile.open(archive_path, "r:") as archive:
                manifest = archive.extractfile("manifest.json").read()
            tampered = root / "tampered.tar"
            with tarfile.open(tampered, "w:", format=tarfile.GNU_FORMAT) as archive:
                manifest_info = tarfile.TarInfo("manifest.json")
                manifest_info.size = len(manifest)
                manifest_info.mode = 0o644
                archive.addfile(manifest_info, io.BytesIO(manifest))
                payload = b"tamper package\n"
                payload_info = tarfile.TarInfo("payload/worker.deb")
                payload_info.size = len(payload)
                payload_info.mode = 0o644
                archive.addfile(payload_info, io.BytesIO(payload))

            validated = self.run_tool("validate", "--archive", str(tampered))
            self.assertNotEqual(validated.returncode, 0)
            self.assertIn("checksum mismatch", json.loads(validated.stdout)["error"])

    def test_build_003_rejects_unmanifested_member_with_normalized_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            source = root / "worker.deb"
            source.write_bytes(b"worker package\n")
            archive_path = root / "bundle.tar"
            built = self.build(archive_path, ("payload/worker.deb", source))
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            with tarfile.open(archive_path, "r:") as archive:
                manifest = archive.extractfile("manifest.json").read()
                payload = archive.extractfile("payload/worker.deb").read()
            forged = root / "forged.tar"
            with tarfile.open(forged, "w:", format=tarfile.GNU_FORMAT) as archive:
                for name, data in (("manifest.json", manifest), ("payload/worker.deb", payload), ("payload/extra.deb", b"extra")):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))

            validated = self.run_tool("validate", "--archive", str(forged))
            self.assertNotEqual(validated.returncode, 0)
            self.assertIn("do not exactly match manifest", json.loads(validated.stdout)["error"])

    def test_build_004_rejects_secret_like_source_and_non_explicit_input(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            secret = root / "worker.deb"
            secret.write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
            output = root / "bundle.tar"
            rejected_secret = self.build(output, ("payload/worker.deb", secret))
            self.assertNotEqual(rejected_secret.returncode, 0)
            self.assertIn("credential material", json.loads(rejected_secret.stdout)["error"])
            rejected_missing_input = self.run_tool("build", "--output", str(output))
            self.assertNotEqual(rejected_missing_input.returncode, 0)
            self.assertIn("explicit --input", json.loads(rejected_missing_input.stdout)["error"])

    def test_build_005_wrapper_only_routes_local_bundle_commands(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            source = root / "worker.deb"
            output = root / "bundle.tar"
            source.write_bytes(b"worker package\n")
            completed = subprocess.run(
                [str(WRAPPER), "build", "--output", str(output), "--input", f"payload/worker.deb={source}"],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
