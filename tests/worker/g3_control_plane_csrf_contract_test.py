from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
M4_GUEST = ROOT / "tests/spikes/clean_worker_m4_guest.sh"
M4_WEBHOOK = ROOT / "tests/spikes/clean_worker_m4_webhook_lifecycle_guest.sh"
M4_LOG = ROOT / "tests/spikes/clean_worker_m4_log_gate_guest.sh"
M2_GUEST = ROOT / "tests/spikes/clean_worker_m2_guest.sh"
M3_GUEST = ROOT / "tests/spikes/clean_worker_m3_guest.sh"


class ControlPlaneCSRFGateContractTests(unittest.TestCase):
    def test_historical_gate_clients_login_and_keep_csrf_task_local(self) -> None:
        for gate, path in (
            ("M2", M2_GUEST),
            ("M3", M3_GUEST),
            ("M4", M4_GUEST),
            ("M4", M4_WEBHOOK),
            ("M4", M4_LOG),
        ):
            text = path.read_text(encoding="utf-8")
            self.assertIn("__Host-open_card_csrf", text, path)
            self.assertIn("X-Open-Card-CSRF", text, path)
            self.assertIn("Origin: $OPEN_CARD_AUTH_ORIGIN", text, path)
            self.assertIn("auth-login.headers", text, path)
            self.assertIn("auth-control-plane.XXXXXX", text, path)
            self.assertIn("mktemp -d \"/tmp/", text, path)
            self.assertIn("chmod 0600", text, path)
            self.assertIn(f"export -n OPEN_CARD_{gate}_TEST_ADMIN_PASSWORD", text, path)
            self.assertIn('--data-binary "@', text, path)
            self.assertIn("rm -f --", text, path)
            variable_prefix = gate.lower()
            self.assertNotIn(f'-H "Cookie: __Host-open_card_session=${variable_prefix}_', text, path)
            self.assertNotIn(f'-H "X-Open-Card-CSRF: ${variable_prefix}_', text, path)
            self.assertNotIn('--data "$login_payload"', text, path)
            self.assertNotIn('--data "$payload"', text, path)
            self.assertNotIn(f'os.environ["OPEN_CARD_{gate}_TEST_ADMIN_PASSWORD"]', text, path)
            self.assertLess(
                text.index(f"export -n OPEN_CARD_{gate}_TEST_ADMIN_PASSWORD"),
                text.index('mktemp -d "/tmp/'),
                path,
            )
            if "run_id=$(openssl" in text:
                self.assertLess(
                    text.index(f"export -n OPEN_CARD_{gate}_TEST_ADMIN_PASSWORD"),
                    text.index("run_id=$(openssl"),
                    path,
                )
        self.assertNotIn("OPEN_CARD_M4_AUTH_SESSION", M4_GUEST.read_text(encoding="utf-8"))
        self.assertNotIn("OPEN_CARD_M4_AUTH_SESSION", M4_LOG.read_text(encoding="utf-8"))
        guest = M4_GUEST.read_text(encoding="utf-8")
        self.assertIn('M4_AUTH_PASSWORD_FILE="$m4_auth_password_file"', guest)
        self.assertNotIn('OPEN_CARD_M4_TEST_ADMIN_PASSWORD="$', guest)


if __name__ == "__main__":
    unittest.main()
