from __future__ import annotations
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from tools.evidence.assert_m6_foundation import M6_TEST_IDS, validate_fixture

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "m6"

class M6FixtureTests(unittest.TestCase):
    def load(self, name: str): return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    def test_exact_approved_test_ids(self): self.assertEqual(set(self.load("metadata.json")["test_ids"]), M6_TEST_IDS)
    def test_profiles_are_offline_and_disabled_is_explicit(self):
        value = self.load("metadata.json"); self.assertFalse(value["external_model_calls"]); self.assertEqual(value["profiles"], ["china", "global", "local", "disabled"])
    def test_context_marks_injection_as_data_and_redacts_secret(self):
        safe = self.load("contexts.json")["safe"]; self.assertTrue(all(not item["treated_as_instruction"] for item in safe["untrusted_data"])); self.assertTrue(all(item["value"] == "[REDACTED]" for item in safe["secret_references"]))
    def test_plan_is_structured_bounded_and_confirmed(self):
        plan = self.load("plans.json")["valid"]; self.assertEqual(plan["schema_version"], "1.0"); self.assertGreater(plan["budget"]["max_tokens"], 0); self.assertTrue(plan["requires_user_confirmation"]); self.assertTrue(all(action["tool_id"] and action["validation_id"] for action in plan["actions"]))
    def test_catalog_has_no_arbitrary_or_production_executor(self):
        value = self.load("catalog.json"); self.assertEqual(value["production_behavior"], "controller_handoff_only"); self.assertGreaterEqual(set(value["denied"]), {"shell.exec", "ssh.run", "docker.socket", "kubernetes.production", "production.restart", "core.hot_update", "secret.plaintext"})
    def test_rule_requires_review_regression_shadow_and_version(self):
        value = self.load("rules.json"); self.assertEqual(value["states"], ["proposed", "testing", "reviewed", "shadow", "approved", "promoted"]); self.assertGreaterEqual(set(value["required_for_promotion"]), {"regression_passed", "reviewed_by", "shadow_passed", "version"})
    def test_manifest_and_semantics_are_exact(self): self.assertEqual(validate_fixture(FIXTURES), [])
    def test_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "m6"; shutil.copytree(FIXTURES, target); (target / "plans.json").write_text("{}\n", encoding="utf-8"); self.assertTrue(validate_fixture(target))

if __name__ == "__main__": unittest.main()
