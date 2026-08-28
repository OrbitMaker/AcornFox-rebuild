from __future__ import annotations

import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("promote_m7_real", ROOT / "tools/evidence/promote_m7_real.py")
assert SPEC and SPEC.loader
PROMOTE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROMOTE)


class PromoteM7RealTests(unittest.TestCase):
    def test_gate_matrix_is_frozen(self) -> None:
        self.assertEqual(len(PROMOTE.GATES), 16)
        self.assertEqual(set(PROMOTE.GATES), {
            "INSTALL-001", "INSTALL-002", "INSTALL-003", "UPGRADE-001", "UPGRADE-002", "UPGRADE-003", "UPGRADE-004", "UPGRADE-005",
            "RC-SUPPLY-001", "BACKUP-RESTORE-001", "REBOOT-RECOVERY-001", "FAULT-RC-001", "SECURITY-RC-001", "E2E-RC-001", "REGRESSION-RC-001", "HOST-RECLAIM-001",
        })

    def test_nested_tar_manifest_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "evidence.tar.gz"
            good = b"good\n"
            manifest = f"{hashlib.sha256(good).hexdigest()}  ./result.txt\n".encode()
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, data in (("gate/result.txt", b"tampered\n"), ("gate/manifest.sha256", manifest)):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with tarfile.open(archive_path, "r:gz") as archive:
                with self.assertRaisesRegex(PROMOTE.PromotionError, "nested checksum mismatch"):
                    PROMOTE.verify_tar_manifest(archive, "gate")

    def test_invalid_raw_never_creates_active_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "m7"
            with self.assertRaises(PROMOTE.PromotionError):
                PROMOTE.promote(root / "missing", output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
