from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Gate4BCompositionContractTests(unittest.TestCase):
    def test_production_env_declares_fail_closed_production_composition(self) -> None:
        text = (ROOT / "scripts/mvp/install-host.sh").read_text(encoding="utf-8")
        self.assertIn("OPEN_CARD_M3_COMPOSITION=production", text)
        self.assertNotIn("OPEN_CARD_M3_COMPOSITION=fixture", text)
        for value in (
            "OPEN_CARD_G3_CONSOLE_LABEL=console",
            "OPEN_CARD_G3_INGRESS_LABEL=ingress",
            "OPEN_CARD_G3_APPS_LABEL=apps",
            "OPEN_CARD_G3_WILDCARD_PROBE_LABEL=wildcard-probe",
        ):
            self.assertEqual(text.count(value), 2, value)

    def test_clean_worker_explicitly_declares_the_fixture_boundary(self) -> None:
        text = (ROOT / "scripts/mvp/clean-worker-bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn("task_id=opencard-mvp-fa8f8eab", text)
        self.assertIn("OPEN_CARD_M3_COMPOSITION=fixture", text)
        self.assertIn("marker=/etc/opencard-mvp-fa8f8eab-clean-worker", text)

    def test_main_routes_fixture_imports_only_through_fixture_composition(self) -> None:
        main = (ROOT / "cmd/open-card-server/main.go").read_text(encoding="utf-8")
        adapters = (ROOT / "cmd/open-card-server/m3_adapters.go").read_text(encoding="utf-8")
        fixture = (ROOT / "cmd/open-card-server/m3_fixture_composition.go").read_text(encoding="utf-8")
        self.assertNotIn("dnsfixture", main)
        self.assertNotIn("certfixture", main)
        self.assertNotIn("dnsfixture", adapters)
        self.assertNotIn("certfixture", adapters)
        self.assertIn("resolveM3Composition", main)
        self.assertIn("authorizeM3FixtureHost", main)
        self.assertIn("dnsfixture", fixture)
        self.assertIn("certfixture", fixture)


if __name__ == "__main__":
    unittest.main()
