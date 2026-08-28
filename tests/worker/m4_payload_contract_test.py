"""Structural M4 clean-worker payload contracts.

These tests intentionally inspect the checked-in bootstrap/guest-runner
sources.  They are regression guards for the payload shape and safety
boundaries; they do not claim that the clean worker has been provisioned or
that the M4 runtime gates have passed.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = REPO_ROOT / "scripts" / "mvp" / "clean-worker-bootstrap.sh"
GUEST_RUNNER = REPO_ROOT / "tests" / "spikes" / "clean_worker_m4_guest.sh"
ASSEMBLER = REPO_ROOT / "tools" / "worker" / "assemble_guest_payload.py"
TASK_PREFIX = "opencard-mvp-fa8f8eab"


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class M4PayloadContractTests(unittest.TestCase):
    def test_canonical_release_and_m4_fixture_archive_are_wired(self) -> None:
        bootstrap = read_source(BOOTSTRAP)
        guest_runner = read_source(GUEST_RUNNER)
        assembler = read_source(ASSEMBLER)

        self.assertIn("bootstrap_release=${OPEN_CARD_BOOTSTRAP_RELEASE:-release-0.4.0}", bootstrap)
        self.assertIn('--bundle "/opt/opencard-offline/releases/$bootstrap_release"', bootstrap)
        self.assertIn('"initial_release=${bootstrap_release#release-}"', bootstrap)
        self.assertIn('test "$(readlink /opt/open-card/current)" = "releases/${OPEN_CARD_M4_EXPECTED_RELEASE:-release-0.4.0}"', guest_runner)
        self.assertIn('"version":"0.4.0"', guest_runner)
        self.assertRegex(assembler, r'\("0\.4\.0",\s*"1\.1"\)')

        self.assertIn("m4-fixtures.tar", bootstrap)
        self.assertIn("sha256sum -c tests/fixtures/m4/manifest.sha256", bootstrap)
        self.assertIn('for milestone in ("m2", "m3", "m4"):', assembler)
        self.assertIn('write_tar(output / f"{milestone}-fixtures.tar"', assembler)
        self.assertIn('clean_worker_m4_log_gate_guest.sh', assembler)
        self.assertIn('clean_worker_m4_webhook_lifecycle_guest.sh', assembler)
        self.assertIn('"m4-fixtures.tar"', assembler)
        self.assertIn('"open-card-caddy-fixture"', assembler)
        self.assertIn('"max_data_version": 19', assembler)
        self.assertIn("expected nineteen migrations", assembler)

    def test_runner_executes_directed_log_and_webhook_lifecycle_helpers(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)
        log_call = 'bash "$runner_dir/clean_worker_m4_log_gate_guest.sh"'
        webhook_call = 'bash "$runner_dir/clean_worker_m4_webhook_lifecycle_guest.sh"'
        self.assertIn(log_call, guest_runner)
        self.assertIn(webhook_call, guest_runner)
        self.assertLess(guest_runner.index(log_call), guest_runner.index(webhook_call))
        self.assertIn("M4_LOG_GATE_RUNTIME_STREAM", guest_runner)
        self.assertIn("service_name='frontend'", guest_runner)
        self.assertIn("M4_LOG_GATE_RUNTIME_MAX_FILE_BYTES", guest_runner)
        self.assertIn("OPEN_CARD_M4_WEBHOOK_APPLICATION_ID", guest_runner)
        self.assertIn("find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum", guest_runner)
        self.assertIn("OPEN_CARD_LOG_MAX_FILE_BYTES=96", read_source(BOOTSTRAP))

    def test_m4_is_enabled_in_both_agent_and_server_payloads(self) -> None:
        bootstrap = read_source(BOOTSTRAP)
        guest_runner = read_source(GUEST_RUNNER)

        env_blocks = dict(
            re.findall(
                r"cat >/etc/open-card/(agent\.env|server\.env) <<-?['\"]?EOF['\"]?\n(.*?)\nEOF",
                bootstrap,
                flags=re.DOTALL,
            )
        )
        self.assertIn("agent.env", env_blocks)
        self.assertIn("server.env", env_blocks)
        self.assertIn("OPEN_CARD_M4_ENABLED=true", env_blocks["agent.env"])
        self.assertIn("OPEN_CARD_M4_ENABLED=true", env_blocks["server.env"])

        self.assertIn("open-card-server open-card-agent", bootstrap)
        self.assertIn("for service in open-card-server open-card-agent docker postgresql", guest_runner)
        self.assertIn('test "${OPEN_CARD_M4_ENABLED:-}" = true', guest_runner)

    def test_all_sources_use_the_exact_task_prefix(self) -> None:
        sources = {
            BOOTSTRAP: read_source(BOOTSTRAP),
            GUEST_RUNNER: read_source(GUEST_RUNNER),
            ASSEMBLER: read_source(ASSEMBLER),
        }
        prefix_re = re.compile(r"\bopencard-mvp-[0-9a-f]{8}\b")

        for path, text in sources.items():
            prefixes = prefix_re.findall(text)
            self.assertTrue(prefixes, path)
            self.assertEqual(set(prefixes), {TASK_PREFIX}, path)

    def test_guest_webhook_fixture_is_loopback_only_and_not_public_cert_backed(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)

        self.assertIn("ThreadingHTTPServer(('127.0.0.1',int(port)),H)", guest_runner)
        self.assertIn("127.0.0.1 opencard-webhook-fixture.test", guest_runner)
        self.assertIn("https://opencard-webhook-fixture.test:", guest_runner)
        self.assertIn('test "${OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE:-}" = true', guest_runner)

        literal_hosts = re.findall(r"https?://([^/:'\"$\s]+)", guest_runner)
        self.assertTrue(literal_hosts)
        for host in literal_hosts:
            self.assertTrue(host == "127.0.0.1" or host.endswith(".test"), host)

        source_without_comments = "\n".join(
            line for line in guest_runner.splitlines() if not line.lstrip().startswith("#")
        ).lower()
        for marker in (
            "acme",
            "certbot",
            "letsencrypt",
            "let's encrypt",
            "zerossl",
            "production-ca",
            "production_cert",
        ):
            self.assertNotIn(marker, source_without_comments, marker)

    def test_guest_runner_pins_and_authorizes_the_configured_m2_registry_before_release(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)

        self.assertRegex(guest_runner, r"(?m)^registry_port=45532$")
        self.assertIn(
            'registry_endpoint=${OPEN_CARD_M2_REGISTRY_BASE_URL:?OPEN_CARD_M2_REGISTRY_BASE_URL is required}',
            guest_runner,
        )
        endpoint_check = 'test "$registry_endpoint" = "http://127.0.0.1:$registry_port"'
        self.assertIn(endpoint_check, guest_runner)
        self.assertNotIn("45542", guest_runner)

        endpoint_check_offset = guest_runner.index(endpoint_check)
        release_payload_offset = guest_runner.index("release_payload=")
        release_submission_offset = guest_runner.index('service-groups/$group/releases')
        self.assertLess(endpoint_check_offset, release_payload_offset)
        self.assertLess(endpoint_check_offset, release_submission_offset)
        self.assertIn(
            'release_payload=$(python3 - "$source_id" "$registry_ref" "$registry_endpoint"',
            guest_runner,
        )
        self.assertIn('"endpoint":sys.argv[3]', guest_runner)

    def test_runner_is_contract_only_and_does_not_claim_unrun_m4_gates(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)

        self.assertIn("runner_contract_only=1", guest_runner)
        self.assertIn("m4_gate=NOT_CLAIMED", guest_runner)
        for marker in (
            "RUNNER_CONTRACT_ONLY=1",
            "M4_GATE=NOT_CLAIMED",
            "OBS-002=RUNNER_CONTRACT_ONLY",
            "OPS-E2E-002=RUNNER_CONTRACT_ONLY",
            "VOL-FAULT-001=RUNNER_CONTRACT_ONLY",
            "CANDIDATE-CLEANUP=RUNNER_CONTRACT_ONLY",
            "FAULT-RESTART-RECOVERY=RUNNER_CONTRACT_ONLY",
        ):
            self.assertIn(marker, guest_runner)
        self.assertNotIn("conclusion\\\":\\\"PASS", guest_runner)
        for gate in ("OBS-002", "OPS-E2E-002", "VOL-FAULT-001", "FAULT-RESTART-RECOVERY"):
            self.assertNotRegex(guest_runner, rf"['\"]{re.escape(gate)}=PASS['\"]")

    def test_obs_002_reads_independent_docker_and_cgroup_facts_and_loads_traffic(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)

        for contract in (
            "docker inspect",
            "docker stats --no-stream",
            "docker container diff",
            "container_cgroup_dir",
            '"cpu.max"',
            '"memory.max"',
            '"pids.max"',
            "RestartCount",
            "Health",
            "assert_observation_recovery_and_dedupe",
            "compare_observation_database",
            "controlled_ingress_load",
            "assert_exact_service_restart",
        ):
            self.assertIn(contract, guest_runner)
        self.assertIn("Docker inspect limits differ from kernel cgroup limits", guest_runner)
        self.assertIn("identity", guest_runner)
        self.assertIn("restart_count", guest_runner)
        self.assertIn('docker stop --time 1 "$worker"', guest_runner)
        self.assertNotIn('docker kill "$worker"', guest_runner)
        self.assertIn("SELECT e.route_id,e.old_deployment_id,e.candidate_deployment_id,s.state", guest_runner)
        self.assertIn('wait_rollout_phase "$redeploy_operation" completed', guest_runner)
        self.assertIn('wait_rollout_phase "$rollback_operation" completed', guest_runner)
        self.assertIn('value["parameters"]["preserve_volumes"] is True', guest_runner)
        self.assertIn('"version":2', guest_runner)
        self.assertIn('baseline-v1-retire.json', guest_runner)
        self.assertIn('baseline-v2-deployment.json', guest_runner)
        self.assertIn('group-v2.json', guest_runner)
        self.assertIn('service-groups/$group2/releases', guest_runner)
        self.assertIn('source-v2.json', guest_runner)
        self.assertIn('"services/frontend-v2"', guest_runner)
        self.assertIn('source_revision.content_digest', guest_runner)
        self.assertIn('["healthcheck"]["retries"] = 8', guest_runner)
        self.assertIn('m4-domain-routes.json', guest_runner)
        self.assertIn('service_name":"frontend"', guest_runner)
        self.assertIn('restart_prefix=${6:-}', guest_runner)
        self.assertIn('"$evidence/redeploy.json" "" redeploy', guest_runner)
        self.assertLess(guest_runner.index('phase_watcher_pid=$!'), guest_runner.index('curl -fsS -H \'Content-Type: application/json\' -H \'Open-Card-Role: operator\''))
        self.assertIn("ss -ltnH 'sport = :19443'", guest_runner)
        self.assertIn("tls.load_cert_chain(certfile=cert,keyfile=key)", guest_runner)
        self.assertIn("tls.wrap_socket(s.socket,server_side=True)", guest_runner)
        self.assertNotIn("wrap_socket(s.socket,server_side=True,certfile=", guest_runner)
        self.assertIn("final_deployment=$(psql", guest_runner)
        self.assertIn('label=open-card.deployment-id=$final_deployment', guest_runner)

    def test_ops_e2e_002_contract_has_phase_recovery_route_volume_and_audit_assertions(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)

        for phase in ("candidate_ready", "route_staged", "route_committed", "old_retiring"):
            self.assertIn(phase, guest_runner)
        for contract in (
            "watch_phase_restart",
            "open-card-server open-card-agent",
            "webhook_worker",
            "assert_rollout_phase_contract",
            "assert_failed_rollout_preserves_old",
            "assert_volume_preserved",
            "assert_audit_outbox_and_idempotency",
            "expected_version",
            "Idempotency-Key",
            "audit_evidence",
            "outbox_events",
            "candidate_cleaned",
            "route_set_state",
            "preserve_volumes",
            "candidate_cleanup_task_id",
        ):
            self.assertIn(contract, guest_runner)
        self.assertIn("candidate_requested", guest_runner)
        self.assertIn("candidate_ready", guest_runner)
        self.assertIn("route_staged", guest_runner)
        self.assertIn("route_committed", guest_runner)
        self.assertIn("old_retiring", guest_runner)
        self.assertIn("completed", guest_runner)

    def test_runner_executes_rollout_sequence_in_order_and_fails_closed_on_route_fixture(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)
        ordered = (
            'redeploy_operation=$(submit_rollout_operation redeploy "$redeploy_expected" "m4-redeploy-$run_id" "$evidence/redeploy.json" "" redeploy)',
            'wait_operation_state "$redeploy_operation" succeeded',
            'rollback_operation=$(submit_rollout_operation rollback "$rollback_expected" "m4-rollback-$run_id" "$evidence/rollback.json" "" rollback)',
            'wait_operation_state "$rollback_operation" rolled_back',
            "run_route_failure_contract",
        )
        offsets = [guest_runner.rindex(fragment) if fragment == "run_route_failure_contract" else guest_runner.index(fragment) for fragment in ordered]
        self.assertEqual(offsets, sorted(offsets))
        self.assertNotIn("RUNNER_CONTRACT_ONLY_UNAVAILABLE", guest_runner)
        self.assertIn("arm_route_failure", guest_runner)
        self.assertIn('submit_rollout_operation redeploy "$expected" "m4-route-failure-$run_id"', guest_runner)
        self.assertIn("assert_failed_rollout_preserves_old", guest_runner)
        self.assertIn("m4-route-recovery-$run_id", guest_runner)
        self.assertIn('wait_rollout_phase "$operation" completed', guest_runner)
        self.assertIn("assert_rollout_replay_and_stale", guest_runner)
        self.assertIn("assert_audit_outbox_and_idempotency", guest_runner)

    def test_exact_restart_refreshes_stale_facts_with_bounded_retry(self) -> None:
        guest_runner = read_source(GUEST_RUNNER)
        self.assertIn("for restart_attempt in $(seq 1 20)", guest_runner)
        self.assertIn('[[ "$restart_status" = 409 ]]', guest_runner)
        self.assertIn('test "$restart_status" = 202', guest_runner)
        self.assertIn('restart-attempt-$restart_attempt.json', guest_runner)

    def test_route_fixture_is_test_flagged_loopback_and_not_a_production_unit(self) -> None:
        bootstrap = read_source(BOOTSTRAP)
        cloud_init = (REPO_ROOT / "deploy" / "worker" / "cloud-init" / "user-data").read_text(encoding="utf-8")
        self.assertIn('if [[ "${OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE:-}" = enabled ]]', bootstrap)
        self.assertIn("127.0.0.1:2020", bootstrap)
        self.assertIn("127.0.0.1:2019", bootstrap)
        self.assertIn("open-card-caddy-fixture.service", bootstrap)
        self.assertIn("OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE_TOKEN_FILE", bootstrap)
        self.assertIn("SupplementaryGroups=opencard-buildkit", bootstrap)
        self.assertIn("route-failure-fixture-events.ndjson", read_source(GUEST_RUNNER))
        self.assertIn("matches[0].get('consumed') is True", read_source(GUEST_RUNNER))
        self.assertIn("OPEN_CARD_M4_ROUTE_FAILURE_FIXTURE=enabled", cloud_init)
        self.assertIn("/mnt/opencard-bundle/offline_bundle.py", cloud_init)
        self.assertIn("/mnt/opencard-bundle/clean-worker-bootstrap.sh", cloud_init)
        self.assertNotIn("open-card-caddy-fixture.service", (REPO_ROOT / "scripts" / "mvp" / "install.sh").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
