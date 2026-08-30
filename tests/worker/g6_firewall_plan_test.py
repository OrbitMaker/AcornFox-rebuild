from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/evidence/g6_firewall_plan.py"
FIXTURES = ROOT / "tests/fixtures/gate6_firewall"


def load_tool():
    spec = importlib.util.spec_from_file_location("g6_firewall_plan", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FirewallPlanTests(unittest.TestCase):
    def root(self, raw: str) -> Path:
        return Path(raw).resolve()

    def fixture(self, name: str) -> dict[str, object]:
        return json.loads((FIXTURES / f"{name}-input.json").read_text(encoding="utf-8"))

    def write(self, path: Path, value: object, mode: int = 0o600) -> None:
        path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        path.chmod(mode)

    def test_product_goldens_have_distinct_operations_and_exact_diffs(self) -> None:
        tool = load_tool()
        for name, operation_kind, desired_key in (
            ("cvm", "cvm_replace_security_group_ingress", "desired_ingress"),
            ("lighthouse", "lighthouse_replace_instance_firewall_rules", "desired_firewall_rules"),
        ):
            with self.subTest(product=name), tempfile.TemporaryDirectory() as raw:
                root = self.root(raw)
                source, output = root / "input.json", root / "plan.json"
                original = self.fixture(name)
                self.write(source, original)
                plan = tool.plan(source, output)
                operation = plan["operation"]
                self.assertEqual(operation["kind"], operation_kind)
                self.assertEqual([rule["port"] for rule in operation[desired_key]], ["80", "443", "22"] if name == "lighthouse" else ["80", "443", "22", "22"])
                self.assertEqual(operation["removed_old_rules"][0]["port"], "22")
                self.assertTrue(any(rule["port"] in {"8080", "8443"} for rule in operation["removed_old_rules"]))
                self.assertEqual(plan["old_rule_snapshot"]["snapshot"], plan["rollback"]["snapshot"])
                self.assertEqual(plan["rollback"]["sha256"], hashlib.sha256(tool.canonical(plan["rollback"]["snapshot"])).hexdigest())
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertEqual(output.stat().st_nlink, 1)
                self.assertNotIn(str(root), output.read_text(encoding="utf-8"))
                self.assertNotIn("command", output.read_text(encoding="utf-8").lower())

    def test_rejects_cross_fields_identity_rules_ports_cidrs_and_secrets(self) -> None:
        tool = load_tool()
        mutations = ("cross-kind", "cross-field", "identity-type", "account", "rule-port", "rule-cidr", "duplicate-index", "duplicate-rule", "secret-key", "dsn", "cookie", "authorization", "api-key", "private-material", "command", "absolute", "embedded-path", "unknown")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.root(raw)
                source, output = root / "input.json", root / "plan.json"
                value = self.fixture("cvm")
                payload = value["old_rule_snapshot"]["provider_payload"]
                if mutation == "cross-kind": value["old_rule_snapshot"]["kind"] = "lighthouse_firewall"
                elif mutation == "cross-field": payload["firewall_rules"] = []
                elif mutation == "identity-type": value["identity_type"] = "user"
                elif mutation == "account": value["account_id"] = "100"
                elif mutation == "rule-port": payload["ingress_rules"][0]["port"] = "080"
                elif mutation == "rule-cidr": payload["ingress_rules"][0]["cidr"] = "10.0.0.1/24"
                elif mutation == "duplicate-index": payload["ingress_rules"][1]["index"] = 0
                elif mutation == "duplicate-rule": payload["ingress_rules"].append(dict(payload["ingress_rules"][0]))
                elif mutation == "secret-key": payload["api_token"] = "x"
                elif mutation == "dsn": payload["ingress_rules"][0]["description"] = "postgres://x"
                elif mutation == "cookie": payload["ingress_rules"][0]["description"] = "cookie=x"
                elif mutation == "authorization": payload["ingress_rules"][0]["description"] = "Authorization Bearer abcdefghijklmnopqrstuvwxyz"
                elif mutation == "api-key": payload["ingress_rules"][0]["description"] = "api key abc"
                elif mutation == "private-material": payload["ingress_rules"][0]["description"] = "ssh private material"
                elif mutation == "command": payload["ingress_rules"][0]["description"] = "/bin/sh"
                elif mutation == "absolute": payload["ingress_rules"][0]["description"] = "/etc/passwd"
                elif mutation == "embedded-path": payload["ingress_rules"][0]["description"] = "read /etc/passwd"
                else: value["unexpected"] = True
                self.write(source, value)
                with self.assertRaises(tool.PlanError): tool.plan(source, output)
                self.assertFalse(output.exists())

    def test_rejects_duplicate_unknown_trailing_and_unsafe_filesystem_inputs(self) -> None:
        tool = load_tool()
        for mutation in ("duplicate", "trailing", "hardlink", "mode", "input-link", "nested-output-link", "existing"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.root(raw)
                source, output = root / "input.json", root / "plan.json"
                value = self.fixture("lighthouse")
                self.write(source, value)
                if mutation == "duplicate": source.write_text('{"schema":"x","schema":"x"}', encoding="utf-8"); source.chmod(0o600)
                elif mutation == "trailing": source.write_text(source.read_text(encoding="utf-8") + " {}", encoding="utf-8"); source.chmod(0o600)
                elif mutation == "hardlink": os.link(source, root / "input-link.json")
                elif mutation == "mode": source.chmod(0o666)
                elif mutation == "input-link": os.symlink(source, root / "input-symlink.json")
                elif mutation == "nested-output-link":
                    real, link = root / "real", root / "linked"
                    real.mkdir(); os.symlink(real, link); output = link / "plan.json"
                elif mutation == "existing": output.write_text("existing\n", encoding="utf-8"); output.chmod(0o600)
                selected = root / "input-link.json" if mutation == "hardlink" else root / "input-symlink.json" if mutation == "input-link" else source
                with self.assertRaises(tool.PlanError): tool.plan(selected, output)
                if mutation not in {"existing"}: self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as raw:
            root = self.root(raw)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            source = unsafe / "input.json"
            self.write(source, self.fixture("cvm"))
            with self.assertRaises(tool.PlanError):
                tool.plan(source, root / "plan.json")

    def test_deterministic_no_replace_and_canonical_path_requirement(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = self.root(raw)
            source = root / "input.json"; self.write(source, self.fixture("lighthouse"))
            first, second = root / "one.json", root / "two.json"
            tool.plan(source, first); tool.plan(source, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with self.assertRaises(tool.PlanError): tool.plan(source, first)
            with self.assertRaises(tool.PlanError): tool.plan(Path("relative.json"), root / "three.json")


if __name__ == "__main__":
    unittest.main()
