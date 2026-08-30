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
        self.assertIn("restore-preflight --transaction-id", restore)
        self.assertIn("exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \"$helper\" restore-run", restore)
        self.assertIn("--root / refuses --database-restore-command", restore)
        self.assertIn("exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \"$helper\" backup-create", backup)
        self.assertIn("--root / refuses release, migration, and database dump overrides", backup)
        self.assertIn("unset OPEN_CARD_DATABASE_URL DATABASE_URL", backup)
        self.assertIn("unset OPEN_CARD_DATABASE_URL DATABASE_URL", restore)
        self.assertIn("open-card-edge.service", uninstall)
        self.assertIn("preserved $data_dir, evidence, backups, installation-id, and $edge_state", uninstall)

    def test_core_installer_stages_edge_but_does_not_activate_it_without_host_profile(self) -> None:
        text = (SCRIPTS / "install.sh").read_text(encoding="utf-8")
        self.assertIn("required current migration 0024", text)
        self.assertIn("0.8.0-rc.1 production candidate is missing open-card-edge.service", text)
        self.assertIn("bin/open-card-upgrade", text)
        self.assertIn("systemd/open-card-upgrade-recover.service", text)
        self.assertIn("systemd/open-card-upgrade-safe.target", text)
        self.assertIn("systemd/open-card-upgrade-finalize.service", text)
        self.assertIn("systemd/open-card-edge.service.d/10-upgrade-marker.conf", text)
        self.assertIn("--stage-upgrade-substrate", text)
        self.assertIn("prepare_upgrade_substrate", text)
        for unit in ("open-card-upgrade-recover.service", "open-card-upgrade-safe.target", "open-card-upgrade-finalize.service"):
            self.assertNotIn(f"enable {unit}", text)
            self.assertNotIn(f"start {unit}", text)
        self.assertIn("existing production installation requires upgrade.sh or --stage-upgrade-substrate", text)
        self.assertIn("0.8.0-rc.1 system-root activation requires native bootstrap activation support", text)
        self.assertIn("durability outcome is unknown", text)
        self.assertIn("E/F boot-safe activation gate", text)
        self.assertIn("0.8.0-rc.1 production candidate must declare source and migration 0024", text)
        self.assertIn("0.8.0-rc.1 production manifest contains test-only payload", text)
        self.assertIn("Edge stays disabled until install-host", text)
        self.assertIn("opencard-edge", text)

    def test_root_upgrade_delegates_only_after_exact_safety_boundary(self) -> None:
        text = (SCRIPTS / "upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("--confirm-installation-id UPGRADE:ID", text)
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", text)
        self.assertIn("verified_production_program /usr/bin/python3", text)
        self.assertIn("--root / requires --activate", text)
        self.assertIn("--root / requires --expected-manifest-sha256", text)
        self.assertIn("--root / refuses --health-command, --database-dump-command, --database-restore-command, --migration-command, and --migration-dir", text)
        self.assertIn("--root / refuses --allow-downgrade", text)
        self.assertIn("--stage-upgrade-substrate", text)
        self.assertIn("run_upgrade_helper prepare-control", text)
        self.assertIn("/usr/bin/systemctl enable --now open-card-upgrade-safe.target", text)
        self.assertIn("is-enabled --quiet open-card-upgrade-safe.target", text)
        self.assertIn("is-active --quiet open-card-upgrade-safe.target", text)
        self.assertIn("upgrade-safe target RequiredBy link is missing", text)
        self.assertIn("upgrade-safe target RequiredBy link is unsafe", text)
        self.assertIn("/proc/sys/kernel/random/uuid", text)
        self.assertIn("--expect-layout rc0-legacy", text)
        self.assertNotIn("production upgrade is blocked", text)
        production = text.index('if [[ "$root" = "/" ]]; then\n  (( activate ))')
        delegated_exit = text.index("  exit 0\nfi\n\n# First ask the installer")
        legacy_backup = text.index('backup_args=(--root "$root"')
        self.assertLess(production, delegated_exit)
        self.assertLess(delegated_exit, legacy_backup)


if __name__ == "__main__":
    unittest.main()
