from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy/systemd/open-card-edge.service"
CADDYFILE = ROOT / "deploy/caddy/open-card-edge.Caddyfile.example"
ENV = ROOT / "deploy/caddy/open-card-edge.env.example"
FIXTURE = ROOT / "tests/fixtures/gate2/edge-config-contract.json"


class EdgeConfigContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = UNIT.read_text(encoding="utf-8")
        self.caddyfile = CADDYFILE.read_text(encoding="utf-8")
        self.environment = ENV.read_text(encoding="utf-8")
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_edge_and_internal_boundaries_are_distinct(self) -> None:
        edge = self.fixture["edge"]
        internal = self.fixture["internal_route_provider"]
        self.assertEqual(edge["admin"], "127.0.0.1:2020")
        self.assertEqual(internal["listen"], "127.0.0.1:18481")
        self.assertEqual(internal["admin"], "127.0.0.1:2019")
        self.assertIn("admin 127.0.0.1:2020", self.caddyfile)
        self.assertIn("reverse_proxy 127.0.0.1:18481", self.caddyfile)
        self.assertIn("{$OPEN_CARD_EDGE_LOG_DIR}/console-access.log", self.caddyfile)
        self.assertIn("{$OPEN_CARD_EDGE_LOG_DIR}/application-access.log", self.caddyfile)
        self.assertIn("OPEN_CARD_EDGE_LOG_DIR=/var/log/open-card-edge", self.environment)
        self.assertNotIn("admin 0.0.0.0", self.caddyfile)

    def test_console_api_precedes_spa_and_strips_external_identity(self) -> None:
        self.assertLess(self.caddyfile.index("@control_plane path /api*"), self.caddyfile.index("try_files {path} /index.html"))
        self.assertIn("reverse_proxy 127.0.0.1:8080", self.caddyfile)
        self.assertIn("header_up -Open-Card-*", self.caddyfile)
        self.assertIn("header_up -X-Open-Card-*", self.caddyfile)
        self.assertIn("flush_interval -1", self.caddyfile)

    def test_tls_and_transport_contract_is_bounded(self) -> None:
        for expected in (
            "protocols h1 h2",
            "ask http://127.0.0.1:8080/internal/tls/allow",
            "on_demand",
            "dial_timeout 3s",
            "response_header_timeout 30s",
            "keepalive 30s",
            "write 0",
            "idle 30s",
            "header_up Host {host}",
        ):
            self.assertIn(expected, self.caddyfile)
        self.assertNotIn("h3", self.caddyfile.lower())
        self.assertNotIn("udp", self.caddyfile.lower())

    def test_systemd_unit_hardens_edge_and_validates_before_reload(self) -> None:
        for expected in (
            "User=opencard-edge",
            "Group=opencard-edge",
            "StateDirectory=open-card-edge",
            "LogsDirectory=open-card-edge",
            "LimitNOFILE=1048576",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/open-card-edge /var/log/open-card-edge",
            "TimeoutStopSec=45s",
            "caddy validate",
            "caddy adapt",
            "caddy reload",
        ):
            self.assertIn(expected, self.unit)
        self.assertNotIn("CAP_SYS_ADMIN", self.unit)
        self.assertGreater(self.fixture["edge"]["stop_timeout_seconds"], self.fixture["edge"]["grace_period_seconds"])

    def test_examples_have_no_real_domain_or_secret_material(self) -> None:
        for text in (self.caddyfile, self.environment):
            self.assertNotIn(".com", text)
            self.assertNotIn(".cn", text)
            self.assertNotIn("BEGIN PRIVATE", text)
        self.assertIn("example.invalid", self.caddyfile)


if __name__ == "__main__":
    unittest.main()
