from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "m1"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


class M1FixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = read_json(MANIFEST_PATH)

    def test_manifest_schema_and_exact_file_sets_and_digests(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(self.manifest["fixture_root"], "tests/fixtures/m1")
        fixtures = self.manifest["fixtures"]
        self.assertIsInstance(fixtures, list)
        self.assertEqual(
            {item["fixture_id"] for item in fixtures},
            {
                "static-site",
                "dockerfile-app",
                "malicious-traversal",
                "malicious-symlink",
                "timeout",
                "secret-canary",
            },
        )

        listed_files: set[str] = set()
        for fixture in fixtures:
            self.assertIsInstance(fixture, dict)
            fixture_id = fixture["fixture_id"]
            fixture_dir = FIXTURE_ROOT / fixture["path"]
            self.assertTrue(fixture_dir.is_dir(), fixture_id)
            self.assertFalse(fixture_dir.is_symlink(), fixture_id)
            expected_files: set[str] = set()
            for descriptor in fixture["files"]:
                self.assertEqual(set(descriptor), {"path", "size", "sha256"})
                relative_path = descriptor["path"]
                self.assertIsInstance(relative_path, str)
                self.assertNotIn("..", Path(relative_path).parts)
                self.assertFalse(Path(relative_path).is_absolute())
                self.assertRegex(descriptor["sha256"], r"^[0-9a-f]{64}$")
                path = fixture_dir / relative_path
                self.assertTrue(path.is_file(), f"missing {fixture_id}/{relative_path}")
                self.assertFalse(path.is_symlink(), f"symlink {fixture_id}/{relative_path}")
                raw = path.read_bytes()
                self.assertEqual(len(raw), descriptor["size"], relative_path)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), descriptor["sha256"], relative_path)
                expected_files.add(relative_path)
                listed_files.add(f"{fixture['path']}/{relative_path}")
            actual_files = {
                str(path.relative_to(fixture_dir))
                for path in fixture_dir.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual_files, expected_files, fixture_id)

        actual_fixture_files = {
            str(path.relative_to(FIXTURE_ROOT))
            for path in FIXTURE_ROOT.rglob("*")
            if path.is_file() and path != MANIFEST_PATH
        }
        self.assertEqual(actual_fixture_files, listed_files)

    def test_source_metadata_schema(self) -> None:
        static = read_json(FIXTURE_ROOT / "static-site" / "metadata.json")
        self.assertEqual(static, {
            "schema_version": 1,
            "fixture_id": "static-site",
            "kind": "static",
            "entrypoint": "index.html",
            "expected_files": ["index.html", "metadata.json", "style.css"],
        })
        dockerfile = read_json(FIXTURE_ROOT / "dockerfile-app" / "metadata.json")
        self.assertEqual(dockerfile["schema_version"], 1)
        self.assertEqual(dockerfile["fixture_id"], "dockerfile-app")
        self.assertEqual(dockerfile["kind"], "dockerfile")
        self.assertEqual(dockerfile["dockerfile"], "Dockerfile")
        self.assertEqual(set(dockerfile["context_files"]), {"Dockerfile", "app.txt", "metadata.json"})

    def test_adversarial_descriptors_are_metadata_only(self) -> None:
        traversal = read_json(FIXTURE_ROOT / "malicious-traversal" / "metadata.json")
        self.assertEqual(traversal["expected_error"], "path_traversal")
        self.assertGreaterEqual(len(traversal["entries"]), 2)
        self.assertTrue(any(".." in entry["name"] for entry in traversal["entries"]))
        self.assertTrue(any(Path(entry["name"]).is_absolute() for entry in traversal["entries"]))

        symlink = read_json(FIXTURE_ROOT / "malicious-symlink" / "metadata.json")
        self.assertEqual(symlink["expected_error"], "special_file")
        symlink_entries = [entry for entry in symlink["entries"] if entry["kind"] == "symlink"]
        self.assertEqual(len(symlink_entries), 1)
        self.assertIn("..", Path(symlink_entries[0]["linkname"]).parts)
        self.assertFalse(any(path.is_symlink() for path in FIXTURE_ROOT.rglob("*")))

    def test_timeout_and_secret_canary_descriptors_are_safe(self) -> None:
        timeout = read_json(FIXTURE_ROOT / "timeout" / "metadata.json")
        self.assertEqual(timeout["expected_result"], "timeout")
        self.assertGreater(timeout["timeout_seconds"], 0)
        self.assertEqual(timeout["dockerfile"], "Dockerfile")
        self.assertIn("opencard-fixture: timeout", (FIXTURE_ROOT / "timeout" / "Dockerfile").read_text(encoding="utf-8"))

        canary = read_json(FIXTURE_ROOT / "secret-canary" / "metadata.json")
        self.assertEqual(canary["expected_result"], "redacted")
        placeholder = canary["canary_placeholder"]
        self.assertRegex(placeholder, r"^fixture-canary-[a-z0-9-]+$")
        self.assertNotIn("BEGIN ", placeholder)
        self.assertEqual(canary["source_field"], "TOKEN")
        self.assertIsInstance(canary["must_not_contain"], list)


if __name__ == "__main__":
    unittest.main()
