from __future__ import annotations

import json
import re
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

    def test_console_api_precedes_spa_and_rebuilds_trusted_client_source(self) -> None:
        self.assertLess(self.caddyfile.index("@control_plane path /api*"), self.caddyfile.index("try_files {path} /index.html"))
        self.assertIn("reverse_proxy 127.0.0.1:8080", self.caddyfile)
        self.assertIn("header_up -Open-Card-*", self.caddyfile)
        self.assertIn("header_up -X-Open-Card-*", self.caddyfile)
        self.assertIn("import control_plane_identity_headers", self.caddyfile)
        self.assertIn("header_up X-Open-Card-Client-IP {remote_host}", self.caddyfile)
        trusted_source = self.fixture["routes"]["trusted_client_source_header"]
        self.assertEqual(trusted_source, {"name": "X-Open-Card-Client-IP", "value": "{remote_host}", "scope": "console_api_only"})
        application_proxy = self.caddyfile.split("https:// {", 1)[1]
        self.assertIn("import identity_headers", application_proxy)
        self.assertNotIn("header_up X-Open-Card-Client-IP", application_proxy)
        self.assertIn("flush_interval -1", self.caddyfile)

    def test_upgrade_health_listener_is_loopback_only_and_has_no_public_features(self) -> None:
        listener = "http://127.0.0.1:18482 {"
        self.assertIn(listener, self.caddyfile)
        listeners = re.findall(r"(?m)^([^\s{]+):18482\s*\{", self.caddyfile)
        self.assertEqual(listeners, ["http://127.0.0.1"])
        health_start = self.caddyfile.index(listener)
        health_end = self.caddyfile.index("# Replace only this documentation hostname", health_start)
        health_block = self.caddyfile[health_start:health_end]
        self.assertIn("@edge_health path /healthz", health_block)
        self.assertIn("respond @edge_health 200", health_block)
        self.assertIn("respond 404", health_block)
        for forbidden in ("reverse_proxy", "tls", "on_demand", "admin", "log"):
            self.assertNotIn(forbidden, health_block)

    def test_tls_and_transport_contract_is_bounded(self) -> None:
        for expected in (
            "protocols h1 h2",
            "ask http://127.0.0.1:8080/internal/tls/allow",
            "on_demand",
            "dial_timeout 3s",
            "response_header_timeout 30s",
            "keepalive 30s",
            "write 0",
            "read_header 5s",
            "idle 2m",
            "header_up Host {host}",
        ):
            self.assertIn(expected, self.caddyfile)
        self.assertIn("\n\tmetrics\n", self.caddyfile)
        self.assertNotIn("read_body", self.caddyfile)
        self.assertNotIn("/metrics", self.caddyfile)
        self.assertNotIn("pprof", self.caddyfile.lower())
        self.assertTrue(self.fixture["edge"]["metrics_admin_only"])
        self.assertNotIn("h3", self.caddyfile.lower())
        self.assertNotIn("udp", self.caddyfile.lower())

    def test_application_http_redirect_preserves_host_and_uri_without_proxying(self) -> None:
        redirect = self.fixture["routes"]["application_http_redirect"]
        self.assertEqual(
            redirect,
            {
                "source": "http://",
                "target": "https://{host}{uri}",
                "status": 308,
                "scope": "application_catch_all_only",
            },
        )
        redirect_start = self.caddyfile.index("http:// {")
        https_start = self.caddyfile.index("https:// {")
        self.assertLess(self.caddyfile.index("console.example.invalid {"), redirect_start)
        self.assertLess(redirect_start, https_start)
        redirect_block = self.caddyfile[redirect_start:https_start]
        self.assertIn("redir https://{host}{uri} permanent", redirect_block)
        self.assertNotIn("reverse_proxy", redirect_block)
        self.assertNotIn("tls", redirect_block)
        self.assertNotIn("ask", redirect_block)

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
