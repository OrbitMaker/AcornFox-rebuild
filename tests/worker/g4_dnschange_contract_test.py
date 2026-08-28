from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "gate4" / "dnspod-contract.json"
ADAPTER = ROOT / "internal" / "providers" / "dnspod" / "adapter.go"
MIGRATION = ROOT / "migrations" / "control-plane" / "0024_dns_change_ledger.sql"
CLI = ROOT / "cmd" / "open-card-dns-dry-run" / "main.go"


class Gate4DNSChangeContractTests(unittest.TestCase):
    def test_fixture_and_adapter_are_read_only(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        source = ADAPTER.read_text(encoding="utf-8")
        self.assertEqual(fixture["api_version"], "2021-03-23")
        self.assertEqual(fixture["read_action"], "DescribeRecordList")
        self.assertIn('const ActionDescribeRecordList = "DescribeRecordList"', source)
        for action in fixture["write_actions_for_dry_run_only"]:
            self.assertNotIn(action, source)
        for forbidden in fixture["forbidden_runtime_terms"]:
            self.assertNotIn(forbidden, source.lower())

    def test_ledger_and_cli_are_local_dry_run_only(self) -> None:
        migration = MIGRATION.read_text(encoding="utf-8").lower()
        cli = CLI.read_text(encoding="utf-8").lower()
        for required in ("dns_change_owned_records", "dns_change_plans", "dns_change_reconcile_state"):
            self.assertIn(required, migration)
        for forbidden in ("secretid", "secretkey", "tccli", "createrecord", "modifyrecord", "deleterecord"):
            self.assertNotIn(forbidden, migration)
        self.assertIn("builddryrun", cli)
        self.assertNotIn("http", cli)
        self.assertNotIn("credential", cli)


if __name__ == "__main__":
    unittest.main()
