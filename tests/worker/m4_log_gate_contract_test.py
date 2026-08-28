"""Structural contracts for the directed M4 log-gate guest helper.

These tests protect the helper's fail-closed boundary.  They do not provision
or run a clean worker and never promote an M4 milestone result.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tests" / "spikes" / "clean_worker_m4_log_gate_guest.sh"


class M4LogGateGuestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = HELPER.read_text(encoding="utf-8")

    def test_shell_is_syntax_valid_and_sourceable(self) -> None:
        checked = subprocess.run(["bash", "-n", str(HELPER)], text=True, capture_output=True, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("run_m4_log_gate_guest()", self.text)
        self.assertIn('"${BASH_SOURCE[0]}" == "$0"', self.text)

    def test_execution_is_explicit_task_scoped_loopback_and_ai_disabled(self) -> None:
        for contract in (
            '[[ "$M4_LOG_GATE_EXECUTE" = "1" ]]',
            '[[ "$M4_LOG_GATE_TASK_PREFIX" = opencard-mvp-fa8f8eab ]]',
            'm4_log_gate_assert_loopback_url',
            'm4_log_gate_task_path',
            'm4_log_gate_assert_no_ai',
            '"${OPEN_CARD_RUNTIME_TASK_PREFIX:-}" = "$M4_LOG_GATE_TASK_PREFIX"',
        ):
            self.assertIn(contract, self.text)
        self.assertNotIn("http://169.254.169.254", self.text)
        self.assertNotIn("curl http://", self.text)

    def test_build_retention_uses_public_api_and_read_only_correlation(self) -> None:
        self.assertIn("for number in $(seq -w 1 21)", self.text)
        self.assertIn('"$api/api/v1/sources"', self.text)
        self.assertIn('"$api/api/v1/service-groups/import"', self.text)
        self.assertIn('"$api/api/v1/service-groups/$group/releases"', self.text)
        self.assertIn('"environment_id": environment', self.text)
        self.assertIn("M4_LOG_GATE_ENVIRONMENT_ID", self.text)
        self.assertIn('"version": int(number) + 2', self.text)
        self.assertIn('release_payload=$(python3 - "$source_id" "$number"', self.text)
        self.assertIn('value["services"]["frontend"]', self.text)
        self.assertIn(":build-plan:frontend", self.text)
        self.assertIn("services/frontend-v2", self.text)
        self.assertIn("build.state='succeeded'", self.text)
        self.assertIn("oldest of 21 BuildKit executions survived retention", self.text)
        self.assertNotIn("INSERT INTO", self.text)
        self.assertNotIn("UPDATE ", self.text)
        self.assertNotIn("DELETE FROM", self.text)
        self.assertNotIn('local tree="$work/log-002-$number" compose="$tree/compose.json"', self.text)
        self.assertIn('tree="$work/log-002-$number"', self.text)

    def test_runtime_rotation_refuses_to_manufacture_logs_outside_product_path(self) -> None:
        self.assertIn("m4_log_gate_assert_runtime_rotation", self.text)
        self.assertIn("M4_LOG_GATE_RUNTIME_STREAM", self.text)
        self.assertIn("runtime capture did not rotate one logical stream", self.text)
        self.assertIn('"$M4_LOG_GATE_API/api/v1/applications/$M4_LOG_GATE_APP_ID/logs?category=runtime&limit=100"', self.text)
        self.assertNotIn("LogCategoryRuntime", self.text)
        self.assertNotIn("/runtime/segment-000000.log", self.text)

    def test_sensitive_runtime_literal_is_rejected_before_persistence(self) -> None:
        self.assertIn("m4_log_gate_reject_sensitive_runtime_literal", self.text)
        self.assertIn("DATABASE_PASSWORD", self.text)
        self.assertIn("bare-runtime-canary", self.text)
        self.assertIn('[[ "$status" = 400 ]]', self.text)
        self.assertIn("SELECT count(*) FROM service_groups", self.text)
        self.assertIn("! grep -R -a -Fq 'bare-runtime-canary' \"$M4_LOG_GATE_LOG_ROOT\"", self.text)

    def test_restart_audit_and_redaction_are_checked_without_passing_m4(self) -> None:
        for contract in (
            "systemctl restart open-card-server",
            "m4_log_gate_wait_ready",
            "audit_evidence WHERE action LIKE 'operations.%'",
            "known log canary leaked through operator API",
            "RUNNER_CONTRACT_ONLY=1",
            "M4_GATE=NOT_CLAIMED",
        ):
            self.assertIn(contract, self.text)
        self.assertNotIn("M4_GATE=PASS", self.text)
        for gate in ("LOG-001", "LOG-002", "LOG-003"):
            self.assertNotIn(f"{gate}=PASS", self.text)


if __name__ == "__main__":
    unittest.main()
