from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "internal" / "install"


class Gate5BJournalSecurityTests(unittest.TestCase):
    def test_journal_and_projection_contracts_keep_database_environment_out_of_json(self) -> None:
        contracts = (INSTALL / "activation_contract.go").read_text(encoding="utf-8")
        legacy = (INSTALL / "legacy_projection.go").read_text(encoding="utf-8")
        engine = (INSTALL / "upgrade_engine.go").read_text(encoding="utf-8")

        self.assertIn('DatabaseEnv []byte `json:"-"`', legacy)
        self.assertIn("DatabaseEnvSHA256", contracts)
        self.assertNotIn('DatabaseEnv []byte', contracts)
        self.assertNotIn("LastError", contracts)
        self.assertIn("transitionEvidenceSHA256", engine)
        self.assertIn("never serializes database.env", engine)

    def test_postgres_boundary_has_no_drop_database_api_and_uses_real_pg_dump_flags(self) -> None:
        sources = [
            INSTALL / "postgres_candidate.go",
            INSTALL / "upgrade_database_adapter.go",
            INSTALL / "upgrade_engine.go",
        ]
        for source in sources:
            text = source.read_text(encoding="utf-8").upper()
            self.assertNotIn("DROP DATABASE", text, source.name)

        postgres = (INSTALL / "postgres_candidate.go").read_text(encoding="utf-8")
        self.assertIn('[]string{s.tool, "--format=custom", "--file", p, "--no-owner", "--no-acl"}', postgres)
        self.assertIn('[]string{s.restoreTool, "--exit-on-error", "--single-transaction"', postgres)
        self.assertIn("os.Chmod(p, 0o600)", postgres)

        adapter = (INSTALL / "upgrade_database_adapter.go").read_text(encoding="utf-8")
        self.assertIn('strings.TrimSuffix(filepath.Base(match.Path), ".sql")', adapter)

    def test_task_pg_acceptance_is_explicitly_isolated_and_does_not_log_connection_values(self) -> None:
        test = (ROOT / "tests" / "integration" / "install" / "gate5b_task_pg_test.go").read_text(encoding="utf-8")
        self.assertIn('os.MkdirTemp("/tmp", "ocg5b-")', test)
        self.assertIn("--auth=trust", test)
        self.assertIn('filepath.Join(root, "socket")', test)
        self.assertIn("pg_ctl", test)
        self.assertIn("OPEN_CARD_G5B_REQUIRE_PG", test)
        self.assertIn("TaskUpgradeDatabaseAdapter", test)
        self.assertIn("TaskPostgresSnapshotterWithRestore", test)
        self.assertIn("g5b-pg-password-sentinel", test)
        self.assertIn("func assertNoGate5BSecretLeak(t *testing.T, outcome error", test)
        self.assertIn('assertSecretFree(t, "returned upgrade error", []byte(outcome.Error()), values)', test)
        self.assertNotIn("t.Log(", test)
        self.assertNotIn("CombinedOutput", test)


if __name__ == "__main__":
    unittest.main()
