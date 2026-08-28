from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "m5"
sys.path.insert(0, str(ROOT / "tools" / "evidence"))

import assert_m5_foundation as foundation  # noqa: E402


def read_json(name: str) -> dict:
    value = json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{name} must contain an object")
    return value


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class M5UsageFixtureTests(unittest.TestCase):
    def test_fixture_manifest_and_foundation_validator_are_exact(self) -> None:
        summary = foundation.validate_m5_foundation(FIXTURE_ROOT)
        self.assertTrue(summary["passed"], summary)
        self.assertFalse(summary["writes_gate_evidence"])

    def test_manifest_detects_tampering_without_writing_gate_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            copied = Path(raw_tmp) / "m5"
            shutil.copytree(FIXTURE_ROOT, copied)
            (copied / "samples.json").write_text((copied / "samples.json").read_text(encoding="utf-8") + "\n", encoding="utf-8")
            issues = foundation.validate_fixture_manifest(copied)
            self.assertIn("manifest_mismatch", {issue.code for issue in issues})

    def test_fixed_samples_aggregate_independently_and_ignore_duplicate(self) -> None:
        document = read_json("samples.json")
        expected = read_json("expected-aggregates.json")
        width = int(document["bucket_width_seconds"])
        samples = document["samples"]
        by_identity: dict[str, dict] = {}
        for sample in samples:
            source_id = sample["source_id"]
            if source_id in by_identity:
                self.assertEqual(by_identity[source_id], sample, source_id)
            by_identity[source_id] = sample

        grouped: dict[tuple[str, str, str, datetime], list[dict]] = defaultdict(list)
        for sample in by_identity.values():
            observed = parse_time(sample["observed_at"])
            epoch = int(observed.timestamp())
            bucket = datetime.fromtimestamp(epoch - (epoch % width), tz=timezone.utc)
            grouped[(sample["application_id"], sample["service_name"], sample["release_id"], bucket)].append(sample)

        expected_by_key = {
            (item["application_id"], item["service_name"], item["release_id"], parse_time(item["window_start"])): item
            for item in expected["aggregates"]
        }
        self.assertEqual(set(grouped), set(expected_by_key))
        for key, facts in grouped.items():
            facts.sort(key=lambda item: parse_time(item["observed_at"]))
            result = expected_by_key[key]
            self.assertEqual(len(facts), result["sample_count"])
            self.assertEqual(max(item["cpu_millicores"] for item in facts), result["peak_cpu_millicores"])
            self.assertEqual(max(item["memory_bytes"] for item in facts), result["peak_memory_bytes"])
            self.assertEqual(max(item["disk_bytes"] for item in facts), result["peak_disk_bytes"])
            self.assertEqual(sum(item["restart_count"] for item in facts), result["restart_count"])
            self.assertEqual(sum(item["exception_count"] for item in facts), result["exception_count"])
            self.assertEqual(max(item["runtime_seconds"] for item in facts), result["runtime_seconds"])
            self.assertAlmostEqual(sum(item["cpu_millicores"] for item in facts) / len(facts), result["average_cpu_millicores"])
            self.assertAlmostEqual(sum(item["memory_bytes"] for item in facts) / len(facts), result["average_memory_bytes"])
            cpu_seconds = 0.0
            memory_byte_seconds = 0.0
            network_rx = 0
            network_tx = 0
            for before, after in zip(facts, facts[1:]):
                seconds = (parse_time(after["observed_at"]) - parse_time(before["observed_at"])).total_seconds()
                cpu_seconds += before["cpu_millicores"] * seconds / 1000
                memory_byte_seconds += before["memory_bytes"] * seconds
                network_rx += max(0, after["network_rx_bytes"] - before["network_rx_bytes"])
                network_tx += max(0, after["network_tx_bytes"] - before["network_tx_bytes"])
            self.assertAlmostEqual(cpu_seconds, result["cpu_seconds"])
            self.assertAlmostEqual(memory_byte_seconds, result["memory_byte_seconds"])
            self.assertEqual(network_rx, result["network_rx_bytes"])
            self.assertEqual(network_tx, result["network_tx_bytes"])

    def test_delivery_order_is_late_and_window_is_half_open_utc(self) -> None:
        document = read_json("samples.json")
        samples = {sample["source_id"]: sample for sample in document["samples"]}
        delivery = document["delivery_order"]
        self.assertNotEqual(delivery, sorted(delivery))
        self.assertLess(delivery.index("m5-alpha-web-003"), delivery.index("m5-alpha-web-001"))
        self.assertIn("m5-alpha-web-001", document["late_sample_ids"])
        self.assertEqual(parse_time(document["from"]), datetime(2026, 8, 25, tzinfo=timezone.utc))
        self.assertEqual(parse_time(document["to"]), datetime(2026, 8, 25, 0, 10, tzinfo=timezone.utc))
        self.assertTrue(all(parse_time(sample["observed_at"]).tzinfo == timezone.utc for sample in samples.values()))
        boundary = parse_time(document["to"])
        self.assertFalse(any(parse_time(sample["observed_at"]) == boundary for sample in samples.values()))

    def test_application_isolation_and_limits_actual_split(self) -> None:
        samples = read_json("samples.json")["samples"]
        expected = read_json("expected-aggregates.json")
        self.assertEqual({sample["application_id"] for sample in samples}, {"app-alpha", "app-beta"})
        isolation = expected["application_isolation"]
        self.assertEqual(isolation["app-alpha"]["must_not_include_application_ids"], ["app-beta"])
        self.assertEqual(isolation["app-beta"]["must_not_include_application_ids"], ["app-alpha"])
        alpha_web = next(item for item in expected["aggregates"] if item["application_id"] == "app-alpha" and item["service_name"] == "web")
        self.assertIn("configured_limits", alpha_web)
        self.assertIn("actual", alpha_web)
        self.assertNotIn("cpu_millicores", alpha_web["actual"])
        self.assertTrue(alpha_web["actual"]["cpu_limit_exceeded"])
        self.assertEqual(alpha_web["configured_limits"]["cpu_millicores"], 200)
        self.assertEqual(alpha_web["actual"]["peak_cpu_millicores"], 300)

    def test_retention_keeps_latest_aggregate_and_audit_under_watermark(self) -> None:
        retention = read_json("retention.json")
        storage = retention["storage"]
        self.assertTrue(storage["low_priority_raw_sampling_paused"])
        self.assertGreater(storage["used_bytes_before_cleanup"], storage["used_bytes_after_cleanup"])
        self.assertGreaterEqual(set(retention["must_retain"]), {"latest_aggregate", "audit_evidence", "current_observation"})
        self.assertTrue(retention["recovery"]["recompute_aggregates_from_raw_window"])
        self.assertTrue(retention["recovery"]["partial_cleanup_is_retryable"])

    def test_fixture_contains_no_out_of_scope_or_secret_fields(self) -> None:
        summary = foundation.validate_m5_foundation(FIXTURE_ROOT)
        self.assertFalse(any(issue["code"] == "forbidden_usage_field" for issue in summary["fixture_issues"]), summary)
        self.assertFalse(any(issue["code"] == "forbidden_secret_material" for issue in summary["fixture_issues"]), summary)
        for document_name in ("metadata.json", "samples.json", "expected-aggregates.json", "retention.json"):
            value = read_json(document_name)
            encoded = json.dumps(value, sort_keys=True).lower()
            for forbidden in ("price", "invoice", "payment", "currency", "balance", "billing"):
                self.assertNotIn(f'"{forbidden}"', encoded)


if __name__ == "__main__":
    unittest.main()
