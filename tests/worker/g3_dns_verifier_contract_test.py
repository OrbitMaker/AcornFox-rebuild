from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests/fixtures/gate3/dns-verifier"
PROVIDER = ROOT / "internal/providers/publicdns/verifier.go"


class PublicDNSVerifierContractTests(unittest.TestCase):
    def test_fixture_manifest_and_status_matrix_are_complete(self) -> None:
        manifest = FIXTURE_ROOT / "manifest.sha256"
        self.assertTrue(manifest.is_file())
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((FIXTURE_ROOT / name).read_bytes()).hexdigest())
        matrix = json.loads((FIXTURE_ROOT / "status-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(matrix["statuses"], ["verified", "pending", "not_found", "mismatch", "timeout", "resolver_error", "conflict", "unknown"])
        self.assertEqual(matrix["max_cname_hops"], 8)
        self.assertIn("198.18.0.1", matrix["reserved_addresses"])

    def test_provider_is_explicit_read_only_and_cloud_credential_free(self) -> None:
        text = PROVIDER.read_text(encoding="utf-8")
        self.assertIn("at least %d explicit recursive resolvers are required", text)
        self.assertNotIn("net.DefaultResolver", text)
        for forbidden in ("tccli", "dnspod", "secretid", "secretkey", "token"):
            self.assertNotIn(forbidden, text.lower())
        self.assertIn("maximumCNAMEHops", text)
        self.assertIn("198.18.0.0/15", text)
        self.assertNotIn("TTL", text.split("type Config", 1)[1])


if __name__ == "__main__":
    unittest.main()
