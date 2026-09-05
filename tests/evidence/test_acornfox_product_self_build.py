import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PATH = Path(__file__).parents[2] / "tools/evidence/acornfox_product_self_build.py"
spec = importlib.util.spec_from_file_location("product_proof", PATH)
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class BuildReceiptTest(unittest.TestCase):
    def test_optimization_cannot_disable_acceptance_checks(self):
        result = subprocess.run([sys.executable, "-O", str(PATH)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("optimized Python", result.stderr)

    def test_timeout_writes_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "timeout.log"
            with self.assertRaises(RuntimeError):
                proof.run([sys.executable, "-c", "import time; time.sleep(10)"], log, timeout=0.05)
            receipt = json.loads(log.with_suffix(".log.json").read_text())
            self.assertTrue(receipt["timed_out"])
            self.assertNotEqual(receipt["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
