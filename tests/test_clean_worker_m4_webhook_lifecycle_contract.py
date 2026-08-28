"""Static contract for the task-scoped M4 lifecycle guest helper.

The helper is intentionally not executed on the host.  These tests prove its
command ordering and safety boundaries; a clean VM run plus independent
evidence/JUnit is still required before any M4 gate can pass.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = REPO_ROOT / "tests" / "spikes" / "clean_worker_m4_webhook_lifecycle_guest.sh"
TASK_PREFIX = "opencard-mvp-fa8f8eab"


class M4WebhookLifecycleGuestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = HELPER.read_text(encoding="utf-8")

    def test_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(["bash", "-n", str(HELPER)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_contract_only_and_exact_task_scope(self) -> None:
        self.assertIn("runner_contract_only=1", self.source)
        self.assertIn("m4_gate=NOT_CLAIMED", self.source)
        self.assertIn("M4_WEBHOOK_LIFECYCLE_GATE=NOT_CLAIMED", self.source)
        prefixes = set(re.findall(r"\bopencard-mvp-[0-9a-f]{8}\b", self.source))
        self.assertEqual(prefixes, {TASK_PREFIX})
        self.assertNotIn('conclusion":"PASS', self.source)
        self.assertIn("OPEN_CARD_M4_WEBHOOK_LIFECYCLE_EXECUTE", self.source)
        self.assertIn("/etc/opencard-mvp-fa8f8eab-clean-worker", self.source)
        self.assertIn('task_path" = "/var/lib/$task_prefix/"*', self.source)
        self.assertIn('! -L "$task_path"', self.source)
        for marker in ("CT-NOTIFY=RUNNER_CONTRACT_ONLY", "SEC-WEBHOOK=RUNNER_CONTRACT_ONLY", "FAULT-WEBHOOK=RUNNER_CONTRACT_ONLY"):
            self.assertIn(marker, self.source)

    def test_loopback_https_receiver_and_secret_redaction_contract(self) -> None:
        for fragment in (
            "ThreadingHTTPServer(('127.0.0.1',int(port)),H)",
            "https://opencard-webhook-fixture.test:",
            "OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE",
            "tls.wrap_socket(server.socket,server_side=True)",
            "m4-fixture-signing-key",
            "X-Open-Card-Event-ID",
            "X-Open-Card-Signature",
            "m4-fixture-signing-key|BEGIN .*PRIVATE KEY|authorization: bearer|cookie=",
        ):
            self.assertIn(fragment, self.source)
        self.assertIn("OPEN_CARD_SECRETCTL_BINARY", self.source)
        self.assertNotIn("docker.sock", self.source)
        self.assertNotIn("/var/run/docker", self.source)

    def test_api_and_read_only_db_order_is_fail_fast(self) -> None:
        required = (
            "m4_authenticate",
            'Cookie: __Host-open_card_session=$m4_admin_session',
            '"$api/api/v1/applications/$app/webhooks"',
            '"$api/api/v1/applications/$app/operations"',
            '"$fault_fixture/__fixture/fault"',
            "systemctl restart open-card-server",
            "wait_operations_serving",
            "SELECT event_id,event_type,delivery_status,attempt_count",
        )
        for fragment in required:
            self.assertIn(fragment, self.source)
        self.assertNotIn("Open-Card-Role", self.source)
        self.assertNotIn("Open-Card-Actor", self.source)
        self.assertLess(self.source.index("webhook_payload="), self.source.index("failure_key="))
        self.assertLess(self.source.index("failure_key="), self.source.index("fault_curl_config="))
        self.assertLess(self.source.index("fault_curl_config="), self.source.index("systemctl restart open-card-server"))
        self.assertLess(self.source.index("systemctl restart open-card-server"), self.source.index("recovery_key="))
        self.assertNotRegex(self.source, r"psql[^\n]*(INSERT|UPDATE|DELETE|TRUNCATE|DROP)")

    def test_failure_escalation_recovery_retry_and_replay_assertions(self) -> None:
        for fragment in (
            "printf '500\\n' >\"$receiver_status\"",
            "retry_wait",
            "wait_webhook_row \"$webhook_id\" delivered 4",
            "webhook-retry-delays.tsv",
            "float(rows[1][1]) >= 0.8",
            "float(rows[2][1]) >= 4.5",
            "retry_wait\\|3\\|3[0-1]",
            "notification.occurrence",
            "notification.escalation",
            "notification.recovery",
            "first['notification.occurrence'] < first['notification.escalation'] < first['notification.recovery']",
            "event_id",
            "attempt_count",
            "received_count",
            "hmac.new",
            "systemctl restart open-card-server",
            "M4_WEBHOOK_LIFECYCLE_GATE=NOT_CLAIMED",
        ):
            self.assertIn(fragment, self.source)
        self.assertIn("failure_key=", self.source)
        self.assertIn("for failure_attempt in $(seq 1 20)", self.source)
        self.assertIn('[[ "$failure_status" = 409 ]]', self.source)
        self.assertIn('test "$failure_status" = 202', self.source)
        self.assertIn("recovery_key=", self.source)
        self.assertIn("wait_phase \"$failure_operation\" failed", self.source)
        self.assertIn("wait_operation \"$failure_operation\" failed", self.source)
        self.assertIn("wait_operation \"$recovery_operation\" succeeded", self.source)
        self.assertGreaterEqual(self.source.count("for _ in $(seq 1 2400)"), 2)


if __name__ == "__main__":
    unittest.main()
