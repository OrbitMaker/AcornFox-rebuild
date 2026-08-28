from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPGRADE = ROOT / "tests/spikes/clean_worker_m7_upgrade_guest.sh"
RC = ROOT / "tests/spikes/clean_worker_m7_rc_guest.sh"
POST = ROOT / "tests/spikes/clean_worker_m7_post_reboot_guest.sh"
HOST = ROOT / "tests/spikes/devbox_m7_rc.sh"
BOOTSTRAP = ROOT / "scripts/mvp/clean-worker-bootstrap.sh"
INSTALL = ROOT / "scripts/mvp/install.sh"
UNINSTALL = ROOT / "scripts/mvp/uninstall.sh"
CLOUD_INIT = ROOT / "deploy/worker/cloud-init-m7-user-data.yaml"


def positions(text: str, values: list[str]) -> list[int]:
    result = [text.index(value) for value in values]
    if result != sorted(result):
        raise AssertionError(f"runner ordering is invalid: {values}")
    return result


class M7RunnerContractTests(unittest.TestCase):
    def test_all_guest_scripts_pass_bash_parser(self) -> None:
        subprocess.run(["bash", "-n", str(UPGRADE), str(RC), str(POST), str(HOST), str(BOOTSTRAP)], check=True)

    def test_upgrade_runner_orders_negatives_before_canonical_success(self) -> None:
        text = UPGRADE.read_text(encoding="utf-8")
        positions(text, [
            "install-replay-$replay.log",
            "loopback-online-install.log",
            "tampered.log",
            "forged-manifest.log",
            "wrong-arch.log",
            "migration-failure.log",
            "health-failure.log",
            "upgrade-success.log",
            "unauthorized-downgrade.log",
        ])
        for boundary in (
            "test \"$(schema_count)\" = 20",
            "test \"$(schema_count)\" = 21",
            "--database-restore-command /usr/local/libexec/opencard-m7-pg-restore",
            'DATABASE_URL="$OPEN_CARD_DATABASE_URL" /opt/opencard-offline/g7/control-plane-migrate.sh',
            "release-0.6.0",
            "release-0.7.0-rc.1",
        ):
            self.assertIn(boundary, text)

    def test_rc_runner_covers_shared_runtime_backup_fault_and_security(self) -> None:
        text = RC.read_text(encoding="utf-8")
        positions(text, [
            "clean_worker_m4_guest.sh",
            "m5-usage.test",
            "m6-ai.test",
            "agent-wire.test",
            "agent-compat.test",
            "containers-before-restarts.txt",
            "systemctl stop postgresql",
            "backup-control-plane.sh",
            "restore-control-plane.sh",
            "corrupt-restore.log",
            "systemd-security.txt",
            "m7-pre-reboot-complete",
        ])
        self.assertIn("test ! -e /opt/open-card/current/bin/open-card-caddy-fixture", text)
        self.assertIn("OPEN_CARD_M6_ENABLED=false", text)
        self.assertIn("database-restore-command", text)
        self.assertIn("FROM m3_route_pointers", text)
        self.assertIn("http://127.0.0.1:2019/config/", text)
        self.assertIn("http://127.0.0.1:2019/config/", POST.read_text(encoding="utf-8"))
        self.assertNotIn("label=open-card.task=", text + POST.read_text(encoding="utf-8"))
        self.assertIn("'limit_memory_bytes':67108864", text)
        self.assertIn("sample('a',0,100,50,False)", text)
        self.assertIn("sample('b',60,300,150,True)", text)
        self.assertIn('corrupt_metadata="${metadata%.json}.corrupt.json"', text)
        positions(text, [
            'snapshot "$evidence/corrupt-restore-before.json"',
            '--backup "$corrupt_metadata"',
            "grep -Fxq 'open-card restore: backup checksum mismatch'",
            'snapshot "$evidence/corrupt-restore-after.json"',
            'cmp "$evidence/corrupt-restore-before.json" "$evidence/corrupt-restore-after.json"',
            'cmp "$evidence/corrupt-restore-before.sha256" "$evidence/corrupt-restore-after.sha256"',
        ])

    def test_post_reboot_requires_three_rounds_and_preserving_uninstall(self) -> None:
        text = POST.read_text(encoding="utf-8")
        self.assertIn("[[ \"$round\" =~ ^[123]$ ]]", text)
        positions(text, [
            "schema_migrations",
            "wrong-purge-token.log",
            "for replay in 1 2",
            "test -d /var/lib/open-card/evidence",
            "volumes-after-uninstall.txt",
            "m7-final-complete",
        ])
        self.assertIn("--purge --confirm WRONG", text)
        self.assertNotIn("--confirm OPEN-CARD-PURGE", text)
        self.assertIn("post-uninstall-units.txt", text)
        self.assertIn("post-uninstall-processes.txt", text)
        self.assertIn("post-uninstall-listeners.txt", text)
        self.assertIn("record_failure", text)
        positions(text, [
            "trap - ERR\nset +e\nenv",
            "wrong_purge_status=$?",
            "set -e\ntrap record_failure ERR",
        ])

    def test_rc_bootstrap_uses_test_archive_without_production_fixture(self) -> None:
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        cloud_init = CLOUD_INIT.read_text(encoding="utf-8")
        self.assertIn("required_payload+=(m7-fixtures.tar)", bootstrap)
        self.assertIn("OPEN_CARD_RC_MODE=1", cloud_init)
        self.assertIn("OPEN_CARD_BOOTSTRAP_RELEASE=release-0.6.0", cloud_init)
        self.assertIn("/opt/opencard-offline/outer/payload/bin/amd64/open-card-caddy-fixture", cloud_init)
        self.assertIn("/mnt/opencard-bundle/m7-fixtures.tar", cloud_init)
        self.assertIn("production_root && ! activate && ! dry_run", INSTALL.read_text(encoding="utf-8"))
        self.assertGreaterEqual(INSTALL.read_text(encoding="utf-8").count("systemctl reset-failed open-card-server.service"), 2)
        self.assertIn('systemctl kill --kill-who=all "$service"', UNINSTALL.read_text(encoding="utf-8"))
        self.assertIn('umount --recursive "$buildkit_state"', UNINSTALL.read_text(encoding="utf-8"))
        self.assertIn("managed processes did not stop", UNINSTALL.read_text(encoding="utf-8"))
        self.assertIn("refusing to unmount unexpected BuildKit state source", UNINSTALL.read_text(encoding="utf-8"))

    def test_host_orchestrator_reclaims_on_success_and_failure(self) -> None:
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("remote_reclaim_needed=1", text)
        self.assertIn("m7-negative/$run_id", text)
        self.assertIn("m7-raw-final/$run_id", text)
        self.assertGreaterEqual(text.count("OPEN_CARD_RECLAIM_CONFIRMATION=reclaim-$domain"), 2)
        for boundary in (
            "sudo test ! -e '$pool_path'",
            "test ! -e '$task/clean-worker-m7-canonical-source'",
            "cmp \"$local_raw/host-before.json\" \"$local_raw/host-after.json\"",
            "opencard-mvp-fa8f8eab-build-worker-01-n-minus-one-snapshot.qcow2",
            "https://release-assets.githubusercontent.com/*",
            "github-assets.txt",
        ):
            self.assertIn(boundary, text)


if __name__ == "__main__":
    unittest.main()
