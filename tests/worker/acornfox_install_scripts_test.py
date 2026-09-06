#!/usr/bin/env python3
"""Static, no-host-effect checks for the five AcornFox 00B shell wrappers."""

from __future__ import annotations

import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts" / "acornfox"
NAMES = (
    "host-preflight.sh",
    "install-host.sh",
    "install.sh",
    "control-plane-migrate.sh",
    "upgrade.sh",
)


class AcornFoxInstallScriptsTest(unittest.TestCase):
    def test_inventory_is_exact_and_executable(self) -> None:
        self.assertEqual(sorted(path.name for path in SCRIPTS.iterdir()), sorted(NAMES))
        for name in NAMES:
            path = SCRIPTS / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            self.assertTrue(path.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n"))

    def test_help_and_invalid_arguments_have_no_host_effect(self) -> None:
        for name in NAMES:
            path = SCRIPTS / name
            help_result = subprocess.run(["bash", str(path), "--help"], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
            self.assertEqual(help_result.returncode, 0, name)
            self.assertIn("usage:", help_result.stdout, name)
            self.assertEqual(help_result.stderr, "", name)
            invalid_result = subprocess.run(["bash", str(path), "--unexpected-value"], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
            self.assertEqual(invalid_result.returncode, 2, name)
            self.assertNotIn("unexpected-value", invalid_result.stderr, name)

    def test_each_script_uses_a_fixed_empty_child_environment(self) -> None:
        for name in NAMES:
            text = (SCRIPTS / name).read_text(encoding="utf-8")
            self.assertIn("/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C", text, name)
            self.assertNotIn("eval ", text, name)
            self.assertNotIn("source ", text, name)
            self.assertNotIn(". /", text, name)

    def test_thin_helper_handoffs_are_exact(self) -> None:
        install = (SCRIPTS / "install.sh").read_text(encoding="utf-8")
        migration = (SCRIPTS / "control-plane-migrate.sh").read_text(encoding="utf-8")
        upgrade = (SCRIPTS / "upgrade.sh").read_text(encoding="utf-8")
        self.assertIn('repository-bootstrap --candidate-dir "$candidate_dir" --binding-sha256 "$binding_sha256" --self-sha256 "$bootstrap_helper_sha256"', install)
        self.assertIn('readonly HELPER=/opt/acornfox/upgrade-tools/acornfox-upgrade', migration)
        self.assertIn('"$HELPER" migrate-control-plane --pending', migration)
        self.assertIn('repository-upgrade --candidate-dir "$candidate_dir" --binding-sha256 "$next_binding_sha256" --current-binding-sha256 "$current_binding_sha256" --self-sha256 "$successor_helper_sha256"', upgrade)
        for text in (install, migration, upgrade):
            for forbidden in ("tar ", "rollback", "downgrade", "backup", "restore", "psql ", "docker rm", "docker prune"):
                self.assertNotIn(forbidden, text)

    def test_host_sequence_is_linear_and_has_no_delete_compensation(self) -> None:
        text = (SCRIPTS / "install-host.sh").read_text(encoding="utf-8")
        sequence = (
            '"$PREFLIGHT" --phase pre',
            "/usr/bin/apt-get update",
            "/usr/bin/apt-get install -y --no-install-recommends ca-certificates docker.io postgresql postgresql-client uidmap util-linux apparmor apparmor-utils",
            '"$PREFLIGHT" --phase post',
            '"$INSTALL" --candidate-dir "$candidate_dir"',
            '"$MIGRATE" --pending',
            '/opt/acornfox/upgrade-tools/acornfox-upgrade configure-runtime',
            "/usr/bin/systemctl daemon-reload",
            "/usr/bin/systemctl enable acornfox-upgrade-safe.target",
            "/usr/bin/systemctl enable acornfox-buildkit.service",
            "/usr/bin/systemctl enable acornfox-caddy.service",
            "/usr/bin/systemctl enable acornfox-server.service",
            "/usr/bin/systemctl enable acornfox-agent.service",
            "/usr/bin/systemctl enable acornfox-edge.service",
            "/usr/bin/systemctl enable acornfox-healthcheck.timer",
            "/usr/bin/systemctl start acornfox-upgrade-safe.target",
            "/usr/bin/systemctl start acornfox-buildkit.service",
            "/usr/bin/systemctl start acornfox-caddy.service",
            "/usr/bin/systemctl start acornfox-server.service",
            "/usr/bin/systemctl start acornfox-agent.service",
            "/usr/bin/systemctl start acornfox-edge.service",
            "/usr/bin/systemctl start acornfox-healthcheck.timer",
            "/usr/bin/systemctl start acornfox-healthcheck.service",
        )
        positions = [text.index(item) for item in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("ACORNFOX_INSTALL_CONFIRMATION", text)
        self.assertIn("ACORNFOX_DEDICATED_HOST_CONFIRMATION", text)
        self.assertIn("/usr/bin/systemctl start acornfox-healthcheck.timer", text)
        self.assertIn("/usr/bin/systemctl start acornfox-healthcheck.service", text)
        self.assertNotIn("is-active --quiet acornfox-healthcheck.service", text)
        for forbidden in ("rm -", "docker rm", "docker system prune", "rollback", "downgrade", "backup", "restore"):
            self.assertNotIn(forbidden, text)

    def test_preflight_is_bounded_to_fixed_platform_contract(self) -> None:
        text = (SCRIPTS / "host-preflight.sh").read_text(encoding="utf-8")
        for required in ("--phase pre|post", "ID=ubuntu", "24\\.04", "x86_64", "systemctl --version", "postgresql/16/bin/postgres", "acornfox-buildkit:231072:65536", '"code":"ok"', '"systemd":"running"'):
            self.assertIn(required, text)
        for forbidden in ("MemTotal", "nproc", "df ", "free ", "curl ", "wget "):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
