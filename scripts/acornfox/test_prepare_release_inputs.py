#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest.mock import patch

SCRIPT_PATH = pathlib.Path(__file__).resolve().parent / "prepare-release-inputs.py"

def load_prepare_module():
    spec = importlib.util.spec_from_file_location("prepare_release_inputs", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

prep = load_prepare_module()

class TestPrepareReleaseInputsDetailed(unittest.TestCase):
    def test_help_contains_architecture_flag(self):
        import subprocess
        res = subprocess.run([sys.executable, str(SCRIPT_PATH), "--help"], stdout=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("--architecture {amd64,arm64}", res.stdout)

    def test_host_arch_mismatch_exact_rejection(self):
        # Mock platform to Linux x86_64, but invoke with --architecture arm64
        test_args = [
            "prepare-release-inputs.py",
            "--architecture", "arm64",
            "/fake/src", "/fake/rt", "/fake/lic", "/fake/ctrl", "0.8.0-rc.1"
        ]
        with patch.object(sys, "argv", test_args):
            with patch("platform.system", return_value="Linux"):
                with patch("platform.machine", return_value="x86_64"):
                    with patch.object(prep, "clean_path") as mock_clean:
                        with self.assertRaises(ValueError) as ctx:
                            prep.main()
                        self.assertIn("native Linux host architecture amd64 does not match target architecture arm64", str(ctx.exception))
                        mock_clean.assert_not_called()

    def test_non_linux_host_rejected(self):
        test_args = [
            "prepare-release-inputs.py",
            "--architecture", "amd64",
            "/fake/src", "/fake/rt", "/fake/lic", "/fake/ctrl", "0.8.0-rc.1"
        ]
        with patch.object(sys, "argv", test_args):
            with patch("platform.system", return_value="Darwin"):
                with patch("platform.machine", return_value="x86_64"):
                    with patch.object(prep, "clean_path") as mock_clean:
                        with self.assertRaises(ValueError) as ctx:
                            prep.main()
                        self.assertIn("native Linux host architecture amd64 does not match target architecture amd64", str(ctx.exception))
                        mock_clean.assert_not_called()

    def test_supported_linux_arch_combination_proceeds_to_next_step(self):
        # When Linux and target architecture match, main proceeds past the arch check to clean_path
        test_args = [
            "prepare-release-inputs.py",
            "--architecture", "arm64",
            "/fake/src", "/fake/rt", "/fake/lic", "/fake/ctrl", "0.8.0-rc.1"
        ]
        with patch.object(sys, "argv", test_args):
            with patch("platform.system", return_value="Linux"):
                with patch("platform.machine", return_value="aarch64"):
                    with patch.object(prep, "clean_path", side_effect=RuntimeError("sentinel_passed_arch_check")):
                        with self.assertRaises(RuntimeError) as ctx:
                            prep.main()
                        self.assertEqual(str(ctx.exception), "sentinel_passed_arch_check")

    def test_targets_have_no_pi_worker(self):
        self.assertNotIn("acornfox-pi-worker", prep.TARGETS)
        self.assertNotIn("open-card-pi-worker", prep.TARGETS)

if __name__ == "__main__":
    unittest.main()
