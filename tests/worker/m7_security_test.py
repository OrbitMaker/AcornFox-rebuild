from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/mvp/build-m7-canonical-source.sh"
TOOL = ROOT / "tools/worker/m7_canonical_bundle.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("m7_canonical_bundle", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class M7SecurityTests(unittest.TestCase):
    def test_fixed_asset_archive_rejects_extra_member(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            assets = root / "assets"
            for arch in ("amd64", "arm64"):
                for name, members in {
                    "buildkit.tar.gz": ("bin/buildkitd", "bin/buildctl", "bin/buildkit-runc"),
                    "rootlesskit.tar.gz": ("rootlesskit",),
                    "caddy.tar.gz": ("caddy",),
                }.items():
                    archive_path = assets / arch / name
                    archive_path.parent.mkdir(parents=True, exist_ok=True)
                    with tarfile.open(archive_path, "w:gz") as archive:
                        for member_name in (*members, "unexpected") if arch == "amd64" and name == "caddy.tar.gz" else members:
                            info = tarfile.TarInfo(member_name)
                            payload = b"fixture"
                            info.size = len(payload)
                            archive.addfile(info, io.BytesIO(payload))
                raw = assets / arch / "docker-buildx"
                raw.write_bytes(b"buildx")
            with self.assertRaises(tool.M7Error):
                tool.extract_fixed_assets(assets, root / "out")

    def test_shell_rejects_non_absolute_and_existing_output_without_side_effects(self) -> None:
        help_result = subprocess.run([str(SCRIPT), "--help"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(help_result.returncode, 0)
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            existing = root / "open-card-m7-canonical-source"
            existing.mkdir()
            result = subprocess.run([str(SCRIPT), "--repo-root", str(ROOT), "--output-root", str(existing), "--debs-root", str(root), "--assets-root", str(root)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to overwrite", result.stderr)
            self.assertEqual(list(existing.iterdir()), [])

    def test_fixed_input_tampering_and_credential_material_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            stage = root / "stage"
            for arch in ("amd64", "arm64"):
                for name in ("open-card-server", "open-card-agent", "open-card-static-server", "open-card-secretctl", "open-card-security-probe", "open-card-imagegc"):
                    path = stage / "binaries" / arch / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"binary")
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
                                payload = b"fixed"
                                info.size = len(payload)
                                info.mode = 0o755
                                info.mtime = info.uid = info.gid = 0
                                info.uname = info.gname = ""
                                archive.addfile(info, io.BytesIO(payload))
                    else:
                        path.write_bytes(b"fixed")
                    lines.append(f"{digest(path)}  {arch}/{name}")
            (assets / "assets.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
            debs = root / "debs"
            package = debs / "debs/opencard.deb"
            package.parent.mkdir(parents=True)
            package.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
            (debs / "debs.sha256").write_text(f"{digest(package)}  debs/opencard.deb\n", encoding="utf-8")
            (debs / "packages.txt").write_text("opencard\n", encoding="utf-8")
            output = root / "open-card-m7-canonical-source"
            result = subprocess.run([sys.executable, str(TOOL), "assemble", "--stage-root", str(stage), "--repo-root", str(ROOT), "--output-root", str(output), "--debs-root", str(debs), "--assets-root", str(assets)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("credential", result.stdout.lower())
            self.assertFalse(output.exists())

    def test_no_production_manifest_mentions_test_only_fixture(self) -> None:
        text = TOOL.read_text(encoding="utf-8")
        self.assertIn("test_only_excluded", text)
        self.assertIn("open-card-caddy-fixture", text)
        self.assertIn("test-only", text)
        self.assertIn("production_binaries", text)

    def test_uninstall_verifies_exact_buildkit_loop_source(self) -> None:
        uninstall = (ROOT / "scripts/mvp/uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('findmnt -n -o SOURCE --target "$buildkit_state"', uninstall)
        self.assertIn('losetup -j "$buildkit_image"', uninstall)
        self.assertIn('"$mounted_source" = "$expected_source"', uninstall)
        self.assertNotIn("umount -l", uninstall)

    def test_fixture_markers_never_bypass_real_secret_detection(self) -> None:
        tool = load_tool()
        tool.scan_fixture_content("negative.test", b"binary\x00-----BEGIN PRIVATE KEY-----")
        with self.assertRaisesRegex(tool.M7Error, "credential material"):
            tool.scan_fixture_content(
                "marked-fixture.txt",
                b"fixture canary test-only\n-----BEGIN PRIVATE KEY-----\n"
                + b"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n"
                + b"-----END PRIVATE KEY-----\n",
            )
        with self.assertRaisesRegex(tool.M7Error, "credential material"):
            tool.scan_fixture_content("marked-fixture.txt", b"fixture AKIAABCDEFGHIJKLMNOP")

    def test_debian_epoch_and_revision_paths_remain_relative(self) -> None:
        tool = load_tool()
        tool.safe_relative("debs/libaudit1_1%3a3.1.2-2.1~24.04_amd64.deb")
        with self.assertRaises(tool.M7Error):
            tool.safe_relative("debs/../credential.pem")

    def test_verified_deb_name_is_not_treated_as_a_credential_file(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            package = root / "passwd_1%3a4.13+dfsg1-4ubuntu3.2_amd64.deb"
            package.write_bytes(b"verified Debian package")
            tool.scan_credentials(package, skip_binary=True)
            secret = root / "password.pem"
            secret.write_text("not a key", encoding="utf-8")
            with self.assertRaises(tool.M7Error):
                tool.scan_credentials(secret)

    def test_rootless_buildkit_hardening_keeps_required_namespace_boundary(self) -> None:
        unit = (ROOT / "deploy/systemd/open-card-buildkit.service").read_text(encoding="utf-8")
        self.assertIn("Delegate=yes", unit)
        self.assertIn("PrivateTmp=yes", unit)
        self.assertNotIn("RestrictNamespaces=yes", unit)
        self.assertIn("SystemCallFilter=@system-service @mount", unit)
        self.assertNotIn("@namespace", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", unit)
        self.assertNotIn("ProtectControlGroups=yes", unit)
        self.assertNotIn("ProcSubset=pid", unit)

    def test_capacity_and_observation_units_keep_required_proc_facts(self) -> None:
        server = (ROOT / "deploy/systemd/open-card-server.service").read_text(encoding="utf-8")
        agent = (ROOT / "deploy/systemd/open-card-agent.service").read_text(encoding="utf-8")
        self.assertIn("ProtectProc=invisible", server)
        self.assertNotIn("ProcSubset=pid", server)
        self.assertNotIn("ProtectProc=", agent)
        self.assertNotIn("ProcSubset=pid", agent)


if __name__ == "__main__":
    unittest.main()
