#!/usr/bin/env python3
"""Static, no-host-effect checks for the five AcornFox 00B shell wrappers."""

from __future__ import annotations

import os
import pathlib
import re
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
        self.assertEqual(sorted(path.name for path in SCRIPTS.iterdir() if path.name in NAMES), sorted(NAMES))
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
            self.assertNotRegex(text, r"(?m)^\s*source\s", name)
            self.assertNotRegex(text, r"(?m)^\s*\.\s+", name)

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
        install_phase = text[text.index('"$PREFLIGHT" --phase pre'):]
        ubuntu = install_phase.index("if clean_output /usr/bin/grep -qx 'ID=ubuntu'")
        debian = install_phase.index("elif clean_output /usr/bin/grep -qx 'ID=debian'")
        ubuntu_install = install_phase.index("postgresql postgresql-client", ubuntu)
        debian_guard = install_phase.index("require_debian_pgdg", debian)
        debian_ca = install_phase.index("debian_system_apt install -y --no-install-recommends ca-certificates", debian)
        debian_publish = install_phase.index("publish_debian_pgdg", debian)
        debian_install = install_phase.index("postgresql-16 postgresql-client-16", debian)
        postflight = install_phase.index('"$PREFLIGHT" --phase post')
        self.assertLess(install_phase.index('"$PREFLIGHT" --phase pre'), ubuntu)
        self.assertLess(ubuntu, ubuntu_install)
        self.assertLess(ubuntu_install, debian)
        self.assertLess(debian, debian_guard)
        self.assertLess(debian_guard, debian_ca)
        self.assertLess(debian_ca, debian_publish)
        self.assertLess(debian_publish, debian_install)
        self.assertLess(debian_guard, debian_install)
        self.assertLess(debian_install, postflight)
        sequence = (
            postflight, '"$INSTALL" --candidate-dir "$candidate_dir"', '"$MIGRATE" --pending',
            '/opt/acornfox/upgrade-tools/acornfox-upgrade configure-runtime', "/usr/bin/systemctl daemon-reload",
            "/usr/bin/systemctl enable acornfox-upgrade-safe.target", "/usr/bin/systemctl start acornfox-healthcheck.service",
        )
        positions = [item if isinstance(item, int) else install_phase.index(item) for item in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("ACORNFOX_INSTALL_CONFIRMATION", text)
        self.assertIn("ACORNFOX_DEDICATED_HOST_CONFIRMATION", text)
        self.assertIn("/usr/bin/systemctl start acornfox-healthcheck.timer", text)
        self.assertIn("/usr/bin/systemctl start acornfox-healthcheck.service", text)
        self.assertNotIn("is-active --quiet acornfox-healthcheck.service", text)
        for forbidden in ("docker rm", "docker system prune", "rollback", "downgrade", "backup", "restore"):
            self.assertNotIn(forbidden, text)

    def test_preflight_is_bounded_to_fixed_platform_contract(self) -> None:
        text = (SCRIPTS / "host-preflight.sh").read_text(encoding="utf-8")
        for required in ("--phase pre|post", "ID=ubuntu", "ID=debian", "24\\.04", "13", "x86_64", "aarch64", "postgresql/16/bin/postgres", "postgresql/16/bin/psql", "postgresql/16/bin/pg_dump", "postgresql/16/bin/pg_restore", "acornfox-buildkit:231072:65536", '"code":"ok"', '"systemd":"running"'):
            self.assertIn(required, text)
        for forbidden in ("curl ", "wget "):
            self.assertNotIn(forbidden, text)

    def test_debian_pgdg_material_is_fixed_and_bounded(self) -> None:
        install = (SCRIPTS / "install-host.sh").read_text(encoding="utf-8")
        key = re.search(r"(?ms)^-----BEGIN PGP PUBLIC KEY BLOCK-----\n.*?^-----END PGP PUBLIC KEY BLOCK-----$", install)
        self.assertIsNotNone(key)
        self.assertEqual(
            __import__("hashlib").sha256((key.group(0) + "\n").encode()).hexdigest(),
            "0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76",
        )
        for required in (
            "Types: deb", "URIs: https://apt.postgresql.org/pub/repos/apt", "Suites: trixie-pgdg",
            "Components: main", "Architectures: amd64", "Signed-By: /etc/apt/keyrings/acornfox-postgresql.asc",
            "safe_root_file_matches", "safe_public_apt_file_matches", "/usr/bin/cmp", "/usr/bin/mktemp",
            "/usr/bin/sync -f", "/usr/bin/mv -n -T", "cleanup_own_temp_file", "debian_system_apt",
            "/run/acornfox-pgdg.XXXXXXXX", "trap 'cleanup_pgdg_tmp || true' EXIT", "pgdg_tmp_children_are_closed", "safe_root_private_directory",
        ):
            self.assertIn(required, install)
        self.assertNotIn("apt-key", install)
        self.assertNotIn("/var/tmp/acornfox-pgdg.", install)


if __name__ == "__main__":
    unittest.main()
