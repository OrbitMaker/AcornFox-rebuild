from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts/mvp"


class InstallerSecurityContractTests(unittest.TestCase):
    def test_production_activation_requires_password_origin_and_edge_domain(self) -> None:
        text = (SCRIPTS / "install-host.sh").read_text(encoding="utf-8")
        for value in ("--admin-password-file", "--auth-origin", "--edge-domain", "0:600", "OPEN_CARD_AUTH_ORIGIN", "open-card-admin bootstrap", "open-card-edge.service", "open-card-edge.Caddyfile"):
            self.assertIn(value, text)
        self.assertIn("remain inactive until explicit password-file and HTTPS origin activation", text)
        self.assertIn("existing production installation requires upgrade.sh", text)
        self.assertIn("activation_rollback", text)
        self.assertIn("activation_committed=1", text)
        self.assertLess(text.index("systemctl enable --now open-card-edge.service"), text.index("open-card-admin bootstrap"))

    def test_root_backup_restore_and_purge_use_installation_id_not_clean_worker_marker(self) -> None:
        backup = (SCRIPTS / "backup-control-plane.sh").read_text(encoding="utf-8")
        restore = (SCRIPTS / "restore-control-plane.sh").read_text(encoding="utf-8")
        uninstall = (SCRIPTS / "uninstall.sh").read_text(encoding="utf-8")
        for text, action in ((backup, "BACKUP:"), (restore, "RESTORE:"), (uninstall, "OPEN-CARD-PURGE:")):
            self.assertIn("/var/lib/open-card/installation-id", text)
            self.assertIn(action, text)
            self.assertNotIn("opencard-mvp-fa8f8eab-build-worker-01", text)
        self.assertIn("production PostgreSQL restore is blocked", restore)
        self.assertIn("open-card-edge.service", uninstall)
        self.assertIn("preserved $data_dir, evidence, backups, installation-id, and $edge_state", uninstall)

    def test_core_installer_stages_edge_but_does_not_activate_it_without_host_profile(self) -> None:
        text = (SCRIPTS / "install.sh").read_text(encoding="utf-8")
        self.assertIn("required current migration 0024", text)
        self.assertIn("0.8.0-rc.1 production candidate is missing open-card-edge.service", text)
        self.assertIn("bin/open-card-upgrade", text)
        self.assertIn("systemd/open-card-upgrade-recover.service", text)
        self.assertIn("--stage-upgrade-substrate", text)
        self.assertIn("prepare_upgrade_substrate", text)
        self.assertNotIn("enable open-card-upgrade-recover.service", text)
        self.assertNotIn("start open-card-upgrade-recover.service", text)
        self.assertIn("existing production installation requires upgrade.sh or --stage-upgrade-substrate", text)
        self.assertIn("0.8.0-rc.1 system-root activation requires native bootstrap activation support", text)
        self.assertIn("durability outcome is unknown", text)
        self.assertIn("E/F boot-safe activation gate", text)
        self.assertIn("0.8.0-rc.1 production candidate must declare source and migration 0024", text)
        self.assertIn("0.8.0-rc.1 production manifest contains test-only payload", text)
        self.assertIn("Edge stays disabled until install-host", text)
        self.assertIn("opencard-edge", text)

    def test_root_upgrade_fails_before_irreversible_database_migration(self) -> None:
        text = (SCRIPTS / "upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("--confirm-installation-id UPGRADE:ID", text)
        self.assertIn('backup_confirmation="BACKUP:$installation_value"', text)
        self.assertIn('restore_confirmation="RESTORE:$installation_value"', text)
        self.assertIn("production upgrade is blocked", text)


if __name__ == "__main__":
    unittest.main()
