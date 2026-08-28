from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/mvp/build-m7-canonical-source.sh"
TOOL = ROOT / "tools/worker/m7_canonical_bundle.py"


class M7CanonicalSourceTests(unittest.TestCase):
    def test_script_is_offline_cross_arch_and_fixture_is_test_only(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("0.7.0-rc.1", text)
        self.assertIn("0.6.0", text)
        self.assertIn("GOARCH=\"$arch\"", text)
        self.assertIn("for arch in amd64 arm64", text)
        self.assertIn("GOPROXY=off", text)
        self.assertIn("go test -c -tags=integration", text)
        self.assertIn("test-only/amd64", text)
        self.assertIn("production_caddy_fixture=excluded", text)
        self.assertNotIn("curl ", text)
        self.assertNotIn("wget ", text)

    def test_helper_has_no_network_or_provisioning_surface(self) -> None:
        text = TOOL.read_text(encoding="utf-8")
        self.assertNotIn("urllib", text)
        self.assertNotIn("socket", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("requests", text)
        self.assertIn("refusing to overwrite canonical M7 output", text)
        self.assertIn("0.7.0-rc.1", text)
        self.assertIn("0.6.0", text)
        self.assertIn("n-minus-one", text)
        self.assertIn("supply-chain.json", text)
        self.assertIn("UBUNTU_GPG_SIGNER", text)

    def test_existing_payload_assembler_exposes_explicit_m7_mode(self) -> None:
        assembler = (ROOT / "tools/worker/assemble_guest_payload.py").read_text(encoding="utf-8")
        self.assertIn("--m7", assembler)
        self.assertIn("m7_canonical_bundle", assembler)
        self.assertIn("--stage-root", assembler)
        self.assertIn("--assets-root", assembler)

    def test_license_source_contract_is_checked_in(self) -> None:
        license_root = ROOT / "docs/licenses"
        self.assertTrue((license_root / "README.md").is_file())
        self.assertTrue((license_root / "THIRD_PARTY_NOTICES.md").is_file())
        manifest = json.loads((license_root / "licenses-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertGreaterEqual(len(manifest["entries"]), 5)


if __name__ == "__main__":
    unittest.main()
