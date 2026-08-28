from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "api/openapi/openapi.yaml"
FIXTURE = ROOT / "tests/fixtures/gate3/system-status-contract.json"

class SystemStatusContractTests(unittest.TestCase):
    def test_read_only_authenticated_contract_is_non_secret(self) -> None:
        spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        operation = spec["paths"]["/api/v1/settings/system-status"]["get"]
        self.assertEqual(operation["x-open-card-handler-status"], fixture["handler_status"])
        schema = spec["components"]["schemas"]["SystemStatus"]
        self.assertEqual(schema["required"], fixture["required"])
        encoded = json.dumps(schema).lower()
        for forbidden in fixture["forbidden"]:
            self.assertNotIn(forbidden, encoded)
        for component in fixture["not_installed"]:
            self.assertEqual(schema["properties"][component]["properties"]["status"]["enum"], ["not_installed"])
        self.assertNotIn("requestBody", operation)

if __name__ == "__main__":
    unittest.main()
