from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/production_bundle.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("production_bundle", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionBundleTests(unittest.TestCase):
    def stage(self, root: Path) -> Path:
        stage = root / "stage"
        for name in (*load_tool().BINARIES, *load_tool().RUNTIME):
            path = stage / "binaries/amd64" / name if name in load_tool().BINARIES else stage / "runtime/amd64" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            path.chmod(0o755)
        return stage

    def n_minus_one(self, root: Path) -> tuple[Path, str]:
        release = root / "n-minus-one"
        binary = release / "bin/open-card-server"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"authentic-0.7.0-rc.1")
        binary.chmod(0o755)
        manifest = {"version": "0.7.0-rc.1", "release_id": "release-0.7.0-rc.1", "architecture": "amd64", "migration_version": "0021", "files": [{"path": "bin/open-card-server", "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "mode": 0o755}]}
        path = release / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return release, hashlib.sha256(path.read_bytes()).hexdigest()

    def live_web(self, root: Path) -> Path:
        dist = root / "live-dist"
        dist.mkdir()
        (dist / "index.html").write_text("<!doctype html><title>live</title>", encoding="utf-8")
        (dist / ".open-card-live-build.json").write_text('{"api_mode":"live"}', encoding="utf-8")
        return dist

    def test_current_candidate_requires_0023_and_never_embeds_fake_n_minus_one(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "production"
            tool.assemble(self.stage(root), ROOT, output, "amd64", None, None, self.live_web(root), structure_only=True)
            metadata = json.loads((output / "production-bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["version"], "0.8.0-rc.1")
            self.assertFalse(metadata["production_ready"])
            self.assertEqual(metadata["n_minus_one"], {"version": "0.7.0-rc.1", "status": "blocked_no_pinned_provenance"})
            self.assertEqual(metadata["live_web"], {"status": "blocked_gate3_unverified_live_input"})
            self.assertFalse((output / "release-0.7.0-rc.1").exists())
            self.assertFalse((output / "release/manifest.json").exists())
            paths = {path.relative_to(output / "release").as_posix() for path in (output / "release").rglob("*") if path.is_file()}
            for required in ("bin/open-card-admin", "systemd/open-card-edge.service", "caddy/open-card-edge.Caddyfile.example", "migrations/control-plane/0023_source_uploads.sql", "web/dist/index.html", "docs/licenses/licenses-manifest.json", "sbom.spdx.json", "source-manifest.sha256"):
                self.assertIn(required, paths)
            self.assertFalse(any("fixture" in path or path.endswith(".test") for path in paths))
            self.assertTrue((output / "STRUCTURE-ONLY-NOT-INSTALLABLE").is_file())

    def test_missing_admin_or_runtime_binary_fails_closed(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            stage = self.stage(root)
            (stage / "binaries/amd64/open-card-admin").unlink()
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(stage, ROOT, root / "production", "amd64", root / "missing", "0" * 64, self.live_web(root))

    def test_missing_authentic_n_minus_one_or_live_marker_never_publishes_output(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(self.stage(root), ROOT, root / "production", "amd64", root / "missing", "0" * 64, self.live_web(root))
            self.assertFalse((root / "production").exists())
            n_minus_one, checksum = self.n_minus_one(root)
            stub = root / "stub-dist"
            stub.mkdir(); (stub / "index.html").write_text("stub", encoding="utf-8")
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(self.stage(root), ROOT, root / "production", "amd64", n_minus_one, checksum, stub)
            self.assertFalse((root / "production").exists())

    def test_fabricated_n_minus_one_and_live_marker_never_publish_an_installable_release(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            n_minus_one, checksum = self.n_minus_one(root)
            with self.assertRaises(tool.ProductionBundleError):
                tool.assemble(self.stage(root), ROOT, root / "production", "amd64", n_minus_one, checksum, self.live_web(root))
            self.assertFalse((root / "production").exists())

    def test_repository_dist_is_not_claimed_as_gate3_live_input(self) -> None:
        tool = load_tool()
        with self.assertRaises(tool.ProductionBundleError):
            tool.verify_live_web(ROOT / "web/dist")


if __name__ == "__main__":
    unittest.main()
