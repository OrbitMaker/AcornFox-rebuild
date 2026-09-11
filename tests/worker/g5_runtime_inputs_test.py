from __future__ import annotations

import hashlib
import json
import tarfile
import unittest
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "release/runtime-inputs.json"
SUPPLY_EVIDENCE = ROOT / "artifacts/mvp/m7-raw-final/20260826T000319Z/m7-supply-evidence.tar.gz"

EXPECTED_M7_VERSIONS = {
    "buildkit": "0.32.2",
    "rootlesskit": "3.1.0",
    "buildx": "0.36.1",
    "caddy": "2.11.4",
}
EXPECTED_VERSIONS = {**EXPECTED_M7_VERSIONS, "pi": "0.85.1"}
EVIDENCE = ROOT / "release/runtime-inputs-evidence.json"
M7_EVIDENCE_FIELDS = {"tool", "architecture", "version", "url", "filename", "sha256", "sha256_source"}
PI_EVIDENCE_FIELDS = M7_EVIDENCE_FIELDS | {"sha256sums_url", "sha256sums_sha256", "asset_manifest_sha256"}
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
LOCAL_FILENAMES = {
    "buildkit": "buildkit.tar.gz",
    "rootlesskit": "rootlesskit.tar.gz",
    "buildx": "docker-buildx",
    "caddy": "caddy.tar.gz",
}
PI_ASSETS = {
    "amd64": {
        "url": "https://github.com/earendil-works/pi/releases/download/v0.85.1/pi-linux-x64.tar.gz",
        "filename": "pi-linux-x64.tar.gz",
        "sha256": "494e498f47d74d21f40b3386f6a5e921a3d49531a169cab55bbdaca0ea1fe25a",
        "sha256sums_url": "https://github.com/earendil-works/pi/releases/download/v0.85.1/SHA256SUMS",
        "sha256sums_sha256": "0b70b2e422339b7a1277c3addb3705e1239d21ca1c20a17741a7b1c06d7526b0",
        "asset_manifest_sha256": "e8d788ebaab78af97ca959b91a1abfe9fc820de4a4c6aadcd870bb500679934d",
    },
    "arm64": {
        "url": "https://github.com/earendil-works/pi/releases/download/v0.85.1/pi-linux-arm64.tar.gz",
        "filename": "pi-linux-arm64.tar.gz",
        "sha256": "042d20ae885ee4f3b102815f3280b962c377b2e9fb44de4037908cc530eae4d4",
        "sha256sums_url": "https://github.com/earendil-works/pi/releases/download/v0.85.1/SHA256SUMS",
        "sha256sums_sha256": "0b70b2e422339b7a1277c3addb3705e1239d21ca1c20a17741a7b1c06d7526b0",
        "asset_manifest_sha256": "7217207f1aeb5d298de152897e3aa6eafd7c55be1a534f3da71d0d9649131ec6",
    },
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


def load_evidence() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def walk_field_names(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from walk_field_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_field_names(child)


class G5RuntimeInputsTests(unittest.TestCase):
    def test_schema_contains_only_the_five_cross_arch_runtime_tools(self) -> None:
        document = load_inputs()
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(set(document), {"schema_version", "runtime_inputs"})
        self.assertEqual(set(document["runtime_inputs"]), set(EXPECTED_VERSIONS))
        fields = {field.lower() for field in walk_field_names(document)}
        self.assertTrue(fields.isdisjoint(FORBIDDEN_FIELD_NAMES))

    def test_tracked_evidence_has_exact_schema_and_ten_records(self) -> None:
        document = load_evidence()
        self.assertEqual(set(document), {"schema_version", "source_evidence", "runtime_inputs_sha256", "records"})
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(set(document["source_evidence"]), {"tar_sha256", "member"})
        self.assertEqual(document["source_evidence"]["member"], "supply-chain.json")
        self.assertRegex(document["source_evidence"]["tar_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(document["runtime_inputs_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(document["records"]), 10)
        self.assertEqual({record["tool"] for record in document["records"]}, set(EXPECTED_VERSIONS))
        self.assertEqual(
            {(record["tool"], record["architecture"]) for record in document["records"]},
            {(tool, architecture) for tool in EXPECTED_VERSIONS for architecture in ("amd64", "arm64")},
        )
        fields = {field.lower() for field in walk_field_names(document)}
        self.assertTrue(fields.isdisjoint(FORBIDDEN_FIELD_NAMES))
        for record in document["records"]:
            self.assertEqual(
                set(record),
                PI_EVIDENCE_FIELDS if record["tool"] == "pi" else M7_EVIDENCE_FIELDS,
            )
            self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
            parsed = urlparse(record["url"])
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.netloc, "github.com")
            if record["tool"] == "pi":
                self.assertEqual(record["sha256_source"], "SHA256SUMS")
                self.assertEqual(
                    {field: record[field] for field in PI_EVIDENCE_FIELDS - {"tool", "architecture", "version", "sha256_source"}},
                    {field: PI_ASSETS[record["architecture"]][field] for field in PI_ASSETS[record["architecture"]]},
                )
            else:
                self.assertEqual(record["sha256_source"], "assets.sha256")

    def test_tracked_evidence_binds_the_runtime_inputs_manifest_digest(self) -> None:
        expected = load_evidence()["runtime_inputs_sha256"]
        actual = hashlib.sha256(INPUTS.read_bytes()).hexdigest()
        self.assertEqual(actual, expected)

    def test_every_asset_is_official_https_with_exact_filename_and_sha256(self) -> None:
        document = load_inputs()["runtime_inputs"]
        for tool, version in EXPECTED_VERSIONS.items():
            record = document[tool]
            self.assertEqual(record["version"], version)
            self.assertEqual(set(record), {"version", "architectures"})
            self.assertEqual(set(record["architectures"]), {"amd64", "arm64"})
            for architecture, asset in record["architectures"].items():
                self.assertEqual(
                    set(asset),
                    {"url", "filename", "sha256"}
                    if tool != "pi"
                    else {"url", "filename", "sha256", "sha256sums_url", "sha256sums_sha256", "asset_manifest_sha256"},
                )
                parsed = urlparse(asset["url"])
                self.assertEqual(parsed.scheme, "https")
                if tool == "pi":
                    self.assertEqual(asset, PI_ASSETS[architecture])
                else:
                    self.assertEqual(parsed.netloc, OFFICIAL_HOSTS[tool])
                    self.assertTrue(parsed.path.startswith(OFFICIAL_PATH_PREFIXES[tool]))
                    self.assertEqual(asset["filename"], LOCAL_FILENAMES[tool])
                self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")

    def test_architecture_records_are_not_interchangeable(self) -> None:
        document = load_inputs()["runtime_inputs"]
        for tool in EXPECTED_VERSIONS:
            amd64 = document[tool]["architectures"]["amd64"]
            arm64 = document[tool]["architectures"]["arm64"]
            self.assertNotEqual(amd64, arm64)
            self.assertNotEqual(amd64["sha256"], arm64["sha256"])
            self.assertNotEqual(amd64["url"], arm64["url"])

    def test_each_record_matches_its_declared_source_evidence(self) -> None:
        tracked = load_evidence()
        runtime = load_inputs()["runtime_inputs"]
        tracked_records = {(record["tool"], record["architecture"]): record for record in tracked["records"]}
        for tool, record in runtime.items():
            for architecture, asset in record["architectures"].items():
                source = tracked_records[(tool, architecture)]
                expected = {
                    "tool": tool,
                    "architecture": architecture,
                    "version": record["version"],
                    "url": asset["url"],
                    "filename": asset["filename"],
                    "sha256": asset["sha256"],
                    "sha256_source": "SHA256SUMS" if tool == "pi" else "assets.sha256",
                }
                if tool == "pi":
                    expected.update({key: asset[key] for key in PI_ASSETS[architecture] if key not in {"url", "filename", "sha256"}})
                self.assertEqual(expected, source)

        if SUPPLY_EVIDENCE.is_file():
            self.assertEqual(hashlib.sha256(SUPPLY_EVIDENCE.read_bytes()).hexdigest(), tracked["source_evidence"]["tar_sha256"])
            with tarfile.open(SUPPLY_EVIDENCE, "r:gz") as archive:
                supply = json.loads(archive.extractfile(tracked["source_evidence"]["member"]).read())
            raw_records = {(entry["architecture"], entry["name"]): entry for entry in supply["fixed_assets"]}
            for source in tracked["records"]:
                if source["tool"] not in EXPECTED_M7_VERSIONS:
                    continue
                raw = raw_records[(source["architecture"], source["filename"])]
                self.assertEqual(source["version"], raw["version"])
                self.assertEqual(source["url"], raw["url"])
                self.assertEqual(source["sha256"], raw["sha256"])
                self.assertEqual(source["sha256_source"], raw["sha256_source"])


if __name__ == "__main__":
    unittest.main()
