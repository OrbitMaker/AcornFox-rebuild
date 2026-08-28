from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/m7_canonical_bundle.py"
ASSEMBLER = ROOT / "tools/worker/assemble_guest_payload.py"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class M7SupplyChainTests(unittest.TestCase):
    def make_inputs(self, root: Path) -> tuple[Path, Path, Path]:
        stage = root / "stage"
        for arch in ("amd64", "arm64"):
            for name in (
                "open-card-server",
                "open-card-agent",
                "open-card-static-server",
                "open-card-secretctl",
                "open-card-security-probe",
                "open-card-imagegc",
            ):
                path = stage / "binaries" / arch / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"{arch}:{name}:fixture\n".encode())
            (stage / "test-only" / "amd64").mkdir(parents=True, exist_ok=True)
        (stage / "test-only/amd64/open-card-caddy-fixture").write_bytes(b"test-only-caddy-fixture\n")

        assets = root / "assets"
        lines = []
        for arch in ("amd64", "arm64"):
            for name in ("buildkit.tar.gz", "rootlesskit.tar.gz", "docker-buildx", "caddy.tar.gz", "ubuntu-24.04-server-cloudimg.img"):
                path = assets / arch / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name.endswith(".tar.gz"):
                    members = {
                        "buildkit.tar.gz": ("bin/buildkitd", "bin/buildctl", "bin/buildkit-runc"),
                        "rootlesskit.tar.gz": ("rootlesskit",),
                        "caddy.tar.gz": ("caddy",),
                    }[name]
                    with tarfile.open(path, "w:gz") as archive:
                        for member_name in members:
                            info = tarfile.TarInfo(member_name)
                            payload = f"fixed:{arch}:{member_name}\n".encode()
                            info.size = len(payload)
                            info.mode = 0o755
                            info.mtime = info.uid = info.gid = 0
                            info.uname = info.gname = ""
                            archive.addfile(info, io.BytesIO(payload))
                else:
                    path.write_bytes(f"fixed:{arch}:{name}\n".encode())
                lines.append(f"{digest(path)}  {arch}/{name}")
        (assets / "assets.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")

        debs = root / "debs"
        package = debs / "debs/opencard-fixture.deb"
        package.parent.mkdir(parents=True, exist_ok=True)
        package.write_bytes(b"verified-debian-input\n")
        (debs / "debs.sha256").write_text(f"{digest(package)}  debs/{package.name}\n", encoding="utf-8")
        (debs / "packages.txt").write_text("opencard-fixture\n", encoding="utf-8")
        return stage, assets, debs

    def assemble(self, root: Path) -> Path:
        stage, assets, debs = self.make_inputs(root)
        output = root / "open-card-m7-canonical-source"
        completed = subprocess.run(
            [
                sys.executable,
                str(ASSEMBLER),
                "--m7",
                "--stage-root",
                str(stage),
                "--repo-root",
                str(ROOT),
                "--output-dir",
                str(output),
                "--debs-root",
                str(debs),
                "--assets-root",
                str(assets),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ready"])
        return output

    def test_assembles_rc_n_minus_one_migrations_and_cross_arch_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            output = self.assemble(Path(raw_tmp))
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["version"], "0.7.0-rc.1")
            self.assertEqual(manifest["n_minus_one"], "0.6.0")
            self.assertEqual((output / "VERSION").read_text(encoding="utf-8"), "0.7.0-rc.1\n")
            self.assertEqual((output / "N-MINUS-ONE").read_text(encoding="utf-8"), "0.6.0\n")
            self.assertEqual(manifest["test_only_payload"]["caddy_fixture_binary"], "bin/amd64/open-card-caddy-fixture")
            supply = json.loads((output / "supply-chain.json").read_text(encoding="utf-8"))
            self.assertEqual(supply["ubuntu_gpg_signer"], "UEC Image Automatic Signing Key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81")
            self.assertEqual(len(supply["fixed_assets"]), 10)
            asset_digests = {(entry["architecture"], entry["name"]): entry["sha256"] for entry in supply["fixed_assets"]}
            for arch in ("amd64", "arm64"):
                for name in ("buildkit.tar.gz", "rootlesskit.tar.gz", "docker-buildx", "caddy.tar.gz", "ubuntu-24.04-server-cloudimg.img"):
                    self.assertEqual(asset_digests[(arch, name)], digest(output / "inputs/assets" / arch / name))
            urls = {entry["url"] for entry in supply["fixed_assets"]}
            self.assertTrue(any("moby/buildkit/releases/download/v0.32.2" in url for url in urls))
            self.assertTrue(any("rootlesskit/releases/download/v3.1.0" in url for url in urls))
            self.assertTrue(any("buildx/releases/download/v0.36.1" in url for url in urls))
            self.assertTrue(any("caddy/releases/download/v2.11.4" in url for url in urls))
            self.assertTrue(any("cloud-images.ubuntu.com/releases/noble/release" in url for url in urls))
            self.assertEqual(manifest["architectures"], ["amd64", "arm64"])
            self.assertEqual(manifest["migrations"]["first"], "0001")
            self.assertEqual(manifest["migrations"]["current_count"], 21)
            self.assertEqual(manifest["migrations"]["n_minus_one_count"], 20)
            self.assertEqual(manifest["production_binaries"], [
                "open-card-server",
                "open-card-agent",
                "open-card-static-server",
                "open-card-secretctl",
                "open-card-security-probe",
                "open-card-imagegc",
            ])
            for arch in ("amd64", "arm64"):
                cross = json.loads((output / f"cross-build/{arch}/manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(cross["goarch"], arch)
                self.assertEqual(len(cross["binaries"]), 6)
                self.assertEqual({entry["name"] for entry in cross["runtime_assets"]}, {"buildkitd", "buildctl", "buildkit-runc", "rootlesskit", "docker-buildx", "caddy"})
            self.assertTrue((output / "releases/release-0.6.0/manifest.json").is_file())
            self.assertTrue((output / "releases/release-0.7.0-rc.1/manifest.json").is_file())
            self.assertTrue((output / "migrations/n-minus-one/0001_foundation.sql").is_file())
            self.assertTrue((output / "migrations/current/0021_m6_controlled_ai.sql").is_file())
            self.assertTrue((output / "systemd/open-card-server.service").is_file())
            self.assertTrue((output / "config/server.env.example").is_file())
            self.assertTrue((output / "docs/runbooks/UPGRADE.md").is_file())
            self.assertTrue((output / "docs/licenses/licenses-manifest.json").is_file())
            self.assertTrue((output / "web/dist/index.html").is_file())
            self.assertTrue((output / "sbom.spdx.json").is_file())
            self.assertTrue((output / "source-manifest.sha256").is_file())
            self.assertTrue((output / "bundle-manifest.sha256").is_file())

    def test_production_release_excludes_fixture_and_test_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            output = self.assemble(Path(raw_tmp))
            for version in ("0.6.0", "0.7.0-rc.1"):
                release = json.loads((output / f"releases/release-{version}/manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(release["architecture"], "amd64")
                self.assertEqual(release["migration_version"], "0020" if version == "0.6.0" else "0021")
                self.assertEqual(release["protocol"], "1.0" if version == "0.6.0" else "1.1")
                paths = {item["path"] for item in release["files"]}
                self.assertFalse(any("caddy-fixture" in path for path in paths))
                self.assertFalse(any("integration" in path or path.endswith(".test") for path in paths))
                for runtime_binary in ("buildkitd", "buildctl", "buildkit-runc", "rootlesskit", "docker-buildx", "caddy"):
                    self.assertIn(f"bin/{runtime_binary}", paths)
            with tarfile.open(output / "m7-fixtures.tar", "r:") as archive:
                names = {member.name for member in archive.getmembers()}
            self.assertFalse((output / "m7-fixtures-tree").exists())
            self.assertIn("bin/amd64/open-card-caddy-fixture", names)
            self.assertIn("tests/fixtures/m2/manifest.sha256", names)
            self.assertIn("tests/fixtures/m3/manifest.sha256", names)
            self.assertIn("tests/fixtures/m4/manifest.sha256", names)
            self.assertIn("tests/spikes/clean_worker_m2_guest.sh", names)
            self.assertIn("tests/spikes/clean_worker_m3_guest.sh", names)
            self.assertIn("agent-wire-root/testdata/m2/deploy-group-request-valid.json", names)
            self.assertIn("agent-wire-root/github.com/open-card/open-card/tests/fixtures/compatibility/agent-envelope-v1-legacy.json", names)
            self.assertIn("tests/spikes/clean_worker_m7_upgrade_guest.sh", names)
            self.assertIn("tests/spikes/clean_worker_m7_rc_guest.sh", names)

    def test_systemd_execstart_binaries_are_present_in_production_release(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            output = self.assemble(Path(raw_tmp))
            release = output / "releases/release-0.7.0-rc.1"
            expected = set()
            for unit in ("open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service"):
                text = (release / "systemd" / unit).read_text(encoding="utf-8")
                for command in re.findall(r"^ExecStart=.*?/bin/([A-Za-z0-9._+-]+)", text, flags=re.MULTILINE):
                    expected.add(command)
            for command in expected:
                self.assertTrue((release / "bin" / command).is_file(), command)
            self.assertNotIn("open-card-caddy-fixture", expected)

    def test_manifest_and_checksum_files_are_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            output = self.assemble(Path(raw_tmp))
            for line in (output / "bundle-manifest.sha256").read_text(encoding="utf-8").splitlines():
                checksum, relative = line.split("  ", 1)
                self.assertEqual(checksum, digest(output / relative))
            sbom = json.loads((output / "sbom.spdx.json").read_text(encoding="utf-8"))
            self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
            names = {package["name"] for package in sbom["packages"]}
            self.assertIn("source/go.mod", names)
            self.assertIn("releases/release-0.7.0-rc.1/bin/open-card-server", names)


if __name__ == "__main__":
    unittest.main()
