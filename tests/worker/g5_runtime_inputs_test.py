from __future__ import annotations

import json
import tarfile
import unittest
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "release/runtime-inputs.json"
SUPPLY_EVIDENCE = ROOT / "artifacts/mvp/m7-raw-final/20260826T000319Z/m7-supply-evidence.tar.gz"

EXPECTED_VERSIONS = {
    "buildkit": "0.32.2",
    "rootlesskit": "3.1.0",
    "buildx": "0.36.1",
    "caddy": "2.11.4",
}
EVIDENCE_NAMES = {
    "buildkit": "buildkit.tar.gz",
    "rootlesskit": "rootlesskit.tar.gz",
    "buildx": "docker-buildx",
    "caddy": "caddy.tar.gz",
}
OFFICIAL_HOSTS = {
    "buildkit": "github.com",
    "rootlesskit": "github.com",
    "buildx": "github.com",
    "caddy": "github.com",
}
OFFICIAL_PATH_PREFIXES = {
    "buildkit": "/moby/buildkit/releases/download/v0.32.2/",
    "rootlesskit": "/rootless-containers/rootlesskit/releases/download/v3.1.0/",
    "buildx": "/docker/buildx/releases/download/v0.36.1/",
    "caddy": "/caddyserver/caddy/releases/download/v2.11.4/",
}
FILENAME_ARCHITECTURE_MARKERS = {
    "amd64": ("amd64", "x86_64"),
    "arm64": ("arm64", "aarch64"),
}
FORBIDDEN_FIELD_NAMES = {
    "credential",
    "credentials",
    "image",
    "images",
    "registry",
    "host",
    "test_host",
    "testhost",
    "token",
    "password",
    "secret",
    "private_key",
}


def load_inputs() -> dict:
    return json.loads(INPUTS.read_text(encoding="utf-8"))


def walk_field_names(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from walk_field_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_field_names(child)


class G5RuntimeInputsTests(unittest.TestCase):
    def test_schema_contains_only_the_four_cross_arch_runtime_tools(self) -> None:
        document = load_inputs()
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(set(document), {"schema_version", "runtime_inputs"})
        self.assertEqual(set(document["runtime_inputs"]), set(EXPECTED_VERSIONS))
        fields = {field.lower() for field in walk_field_names(document)}
        self.assertTrue(fields.isdisjoint(FORBIDDEN_FIELD_NAMES))

    def test_every_asset_is_official_https_with_exact_filename_and_sha256(self) -> None:
        document = load_inputs()["runtime_inputs"]
        for tool, version in EXPECTED_VERSIONS.items():
            record = document[tool]
            self.assertEqual(record["version"], version)
            self.assertEqual(set(record), {"version", "architectures"})
            self.assertEqual(set(record["architectures"]), {"amd64", "arm64"})
            for architecture, asset in record["architectures"].items():
                self.assertEqual(set(asset), {"url", "filename", "sha256"})
                parsed = urlparse(asset["url"])
                self.assertEqual(parsed.scheme, "https")
                self.assertEqual(parsed.netloc, OFFICIAL_HOSTS[tool])
                self.assertTrue(parsed.path.startswith(OFFICIAL_PATH_PREFIXES[tool]))
                self.assertEqual(Path(parsed.path).name, asset["filename"])
                self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(any(marker in asset["filename"] for marker in FILENAME_ARCHITECTURE_MARKERS[architecture]))

    def test_architecture_records_are_not_interchangeable(self) -> None:
        document = load_inputs()["runtime_inputs"]
        for tool in EXPECTED_VERSIONS:
            amd64 = document[tool]["architectures"]["amd64"]
            arm64 = document[tool]["architectures"]["arm64"]
            self.assertNotEqual(amd64, arm64)
            self.assertNotEqual(amd64["sha256"], arm64["sha256"])
            self.assertNotEqual(amd64["url"], arm64["url"])

    def test_each_record_matches_the_m7_supply_evidence(self) -> None:
        if not SUPPLY_EVIDENCE.is_file():
            self.fail(f"required M7 supply evidence is missing: {SUPPLY_EVIDENCE}")
        with tarfile.open(SUPPLY_EVIDENCE, "r:gz") as archive:
            supply = json.loads(archive.extractfile("supply-chain.json").read())
        evidence = {
            (entry["architecture"], entry["name"]): entry
            for entry in supply["fixed_assets"]
            if entry["name"] in EVIDENCE_NAMES.values()
        }
        document = load_inputs()["runtime_inputs"]
        for tool, evidence_name in EVIDENCE_NAMES.items():
            for architecture, asset in document[tool]["architectures"].items():
                source = evidence[(architecture, evidence_name)]
                self.assertEqual(asset["url"], source["url"])
                self.assertEqual(asset["filename"], Path(source["url"].split("?", 1)[0]).name)
                self.assertEqual(asset["sha256"], source["sha256"])
                self.assertEqual(source["version"], EXPECTED_VERSIONS[tool])


if __name__ == "__main__":
    unittest.main()
