from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/spikes/gate2_edge_network.sh"
CONTRACT = ROOT / "tests/fixtures/gate2/port-contract.json"


class Gate2EdgeNetworkTests(unittest.TestCase):
    def make_bin(self, directory: Path, open_ports: set[int] | None = None) -> Path:
        bin_dir = directory / "bin"
        bin_dir.mkdir()
        python_link = bin_dir / "python3"
        python_link.symlink_to(sys.executable)
        for tool in ("bash", "cat", "dirname", "grep", "mkdir", "pwd", "tr"):
            resolved = shutil.which(tool)
            if resolved:
                (bin_dir / tool).symlink_to(resolved)
        if open_ports is not None:
            (bin_dir / "nc").write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "open_ports = {int(item) for item in os.environ.get('GATE2_OPEN_PORTS', '').split(',') if item}\n"
                "sys.exit(0 if int(sys.argv[-1]) in open_ports else 1)\n",
                encoding="utf-8",
            )
            (bin_dir / "nc").chmod(stat.S_IRWXU)
        return bin_dir

    def run_script(self, temporary: Path, *args: str, open_ports: set[int] | None = None) -> subprocess.CompletedProcess[str]:
        evidence = temporary / "evidence"
        bin_dir = self.make_bin(temporary, open_ports)
        environment = os.environ.copy()
        environment["PATH"] = str(bin_dir)
        if open_ports is not None:
            environment["GATE2_OPEN_PORTS"] = ",".join(str(item) for item in sorted(open_ports))
        return subprocess.run(
            [str(SCRIPT), *args, "--task-id", "gate2-test", "--evidence-dir", str(evidence), "--confirm", "GATE2-NETWORK-READONLY"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    @staticmethod
    def records(temporary: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in (temporary / "evidence" / "summary.ndjson").read_text(encoding="utf-8").splitlines()]

    def test_contract_declares_two_observation_points_and_boundaries(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["approved_tcp_ports"], [80, 443])
        self.assertEqual(value["forbidden_tcp_ports"], [8080, 18481, 2019, 2020, 5432, 8092])
        self.assertEqual(value["forbidden_unix_sockets"], ["/var/run/docker.sock", "/run/docker.sock", "/run/open-card-buildkit/buildkitd.sock"])
        self.assertEqual(value["observation_points"]["local"], ["listener", "process", "systemd", "unix_socket"])
        self.assertEqual(value["observation_points"]["external"], ["tcp_probe"])
        self.assertEqual(value["external_probe"]["unexecuted_status"], "unknown")
        self.assertEqual(value["statuses"], ["pass", "fail", "unknown"])
        self.assertNotIn("nmap", SCRIPT.read_text(encoding="utf-8"))

    def test_missing_required_arguments(self) -> None:
        result = subprocess.run([str(SCRIPT)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn("--observation-point", result.stderr)

    def test_rejects_localhost_as_external_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_script(Path(raw), "--observation-point", "external", "--target", "localhost", "--probe-origin", "probe-1")
        self.assertEqual(result.returncode, 64)
        self.assertIn("loopback/default localhost", result.stderr)

    def test_unexecuted_external_probe_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            result = self.run_script(temporary, "--observation-point", "local", "--target", "edge.example.test")
            records = self.records(temporary)
        self.assertEqual(result.returncode, 2)
        external = next(item for item in records if item.get("check_id") == "external.probe.not_executed")
        self.assertEqual(external["status"], "unknown")
        summary = records[-1]
        self.assertEqual(summary["record_type"], "summary")
        self.assertEqual(summary["status"], "unknown")

    def test_missing_external_probe_tool_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            result = self.run_script(
                temporary,
                "--observation-point",
                "external",
                "--target",
                "198.51.100.10",
                "--probe-origin",
                "external-probe-1",
            )
            records = self.records(temporary)
        self.assertEqual(result.returncode, 2)
        statuses = {item["check_id"]: item["status"] for item in records if item.get("record_type") == "check"}
        self.assertEqual(statuses["external.probe.tool"], "unknown")
        self.assertEqual(statuses["external.tcp.80"], "unknown")
        self.assertEqual(records[-1]["status"], "unknown")

    def test_forbidden_port_reachable_is_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            result = self.run_script(
                temporary,
                "--observation-point",
                "external",
                "--target",
                "198.51.100.10",
                "--probe-origin",
                "external-probe-1",
                open_ports={8080},
            )
            records = self.records(temporary)
        self.assertEqual(result.returncode, 1)
        forbidden = next(item for item in records if item.get("check_id") == "external.tcp.8080")
        self.assertEqual(forbidden["status"], "fail")
        self.assertEqual(records[-1]["status"], "fail")

    def test_approved_ports_reachable_and_forbidden_ports_closed_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            result = self.run_script(
                temporary,
                "--observation-point",
                "external",
                "--target",
                "198.51.100.10",
                "--probe-origin",
                "external-probe-1",
                open_ports={80, 443},
            )
            records = self.records(temporary)
        self.assertEqual(result.returncode, 0)
        statuses = {item["check_id"]: item["status"] for item in records if item.get("record_type") == "check"}
        self.assertEqual(statuses["external.tcp.80"], "pass")
        self.assertEqual(statuses["external.tcp.443"], "pass")
        for port in (8080, 18481, 2019, 2020, 5432, 8092):
            self.assertEqual(statuses[f"external.tcp.{port}"], "pass")
        self.assertEqual(records[-1]["status"], "pass")


if __name__ == "__main__":
    unittest.main()
