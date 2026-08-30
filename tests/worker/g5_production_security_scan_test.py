from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from pathlib import PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/worker/production_security_scan.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("production_security_scan", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProductionSecurityScanTests(unittest.TestCase):
    def test_narrow_secret_policy_allows_templates_and_short_vendor_literals(self) -> None:
        tool = load_tool()
        self.assertFalse(tool.sensitive_filename(PurePosixPath("web/.env.development.example")))
        self.assertTrue(tool.sensitive_filename(PurePosixPath("web/.env.production")))
        self.assertEqual(
            tool.scan_bytes(b"sk-abcdefghijklmnopqrstu", PurePosixPath("bin/caddy"), allow_fixture=False),
            (0, 0),
        )
        self.assertEqual(
            tool.scan_bytes(b"sk-abcdefghijklmnopqrstuvwxyzABCDEF", PurePosixPath("bin/caddy"), allow_fixture=False),
            (1, 0),
        )

    def source(self, root: Path) -> tuple[Path, str]:
        repo = root / "source"
        (repo / "testdata").mkdir(parents=True)
        (repo / "main.go").write_text("package main\n", encoding="utf-8")
        (repo / "testdata/canary.txt").write_text("AKID1234567890ABCDEF\n", encoding="utf-8")
        for command in (
            ["git", "init", str(repo)],
            ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
            ["git", "-C", str(repo), "config", "user.name", "test"],
            ["git", "-C", str(repo), "add", "."],
            ["git", "-C", str(repo), "commit", "-m", "fixture"],
            ["git", "-C", str(repo), "checkout", "--detach"],
        ):
            subprocess.run(command, check=True, capture_output=True)
        commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        return repo, commit

    def candidates(self, root: Path, tool) -> Path:
        candidate_set = root / "candidates"
        for arch in tool.ARCHES:
            directory = candidate_set / arch
            release = directory / "release"
            release.mkdir(parents=True)
            payload = release / "payload.txt"
            payload.write_text(f"{arch} payload\n", encoding="utf-8")
            with tarfile.open(directory / f"{arch}.tar.gz", "w:gz") as archive:
                info = tarfile.TarInfo("release/payload.txt")
                data = payload.read_bytes()
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return candidate_set

    def certification(self, root: Path) -> Path:
        directory = root / "certification"
        directory.mkdir()
        (directory / "certification.json").write_text('{"schema":"x"}\n', encoding="utf-8")
        (directory / "release-index.json").write_text('{"schema":"y"}\n', encoding="utf-8")
        return directory

    def fake_go(self, root: Path, *, version: str = "go1.25.13", goroot: str = "/fixture/go") -> Path:
        binary = root / "go"
        binary.write_text(f"#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo 'go version {version} darwin/arm64'; exit 0; fi\nif [ \"$1\" = \"env\" ] && [ \"$2\" = \"GOROOT\" ]; then echo '{goroot}'; exit 0; fi\nexit 1\n", encoding="utf-8")
        binary.chmod(0o755)
        return binary

    def fake_govuln(self, root: Path, *, scan: str | None = None, exit_code: int = 0, version: str | None = None, requires_go: bool = False) -> Path:
        version = version or "Go: go1.25.13\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: 2026-08-28 14:47:45 +0000 UTC\n\n"
        scan = scan or json.dumps({"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": "v1.7.0", "go_version": "go1.25.13", "db": "https://vuln.go.dev", "db_last_modified": "2026-08-28T14:47:45Z", "scan_mode": "source", "scan_level": "symbol"}})
        binary = root / "govulncheck"
        require = "command -v go >/dev/null 2>&1 || exit 9\n" if requires_go else ""
        binary.write_text(f"#!/bin/sh\n{require}if [ \"$1\" = \"-version\" ]; then printf '%s' '{version}'; exit 0; fi\nprintf '%s' '{scan}'\nexit {exit_code}\n", encoding="utf-8")
        binary.chmod(0o755)
        return binary

    def fixture(self, root: Path, tool):
        source, commit = self.source(root)
        return source, commit, self.candidates(root, tool), self.certification(root), self.fake_govuln(root, requires_go=True), self.fake_go(root)

    def test_positive_fixture_canary_is_counted_and_report_is_deterministic(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, commit, candidates, certification, govuln, go = self.fixture(root, tool)
            first, second = root / "scan-a", root / "scan-b"
            report = tool.scan(source, commit, candidates, certification, govuln, go, first)
            tool.scan(source, commit, candidates, certification, govuln, go, second)
            self.assertEqual(report["scope"], "gate5_source_and_artifacts")
            self.assertEqual(report["secret_scan"], {"blocking_count": 0, "allowed_fixture_canary_count": 1})
            self.assertEqual((first / "security-scan.json").read_bytes(), (second / "security-scan.json").read_bytes())
            output = (first / "security-scan.json").read_text(encoding="utf-8")
            self.assertNotIn(str(root), output)
            self.assertNotIn("AKID1234567890ABCDEF", output)

    def test_rejects_blocking_content_unsafe_paths_and_existing_output(self) -> None:
        tool = load_tool()
        for mutation in ("source", "release", "archive", "cert", "symlink", "existing"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source, commit, candidates, certification, govuln, go = self.fixture(root, tool)
                output = root / "scan"
                if mutation == "source":
                    (source / "main.go").write_text("sk-abcdefghijklmnopqrstuvwxyzABCDEF\n", encoding="utf-8")
                    subprocess.run(["git", "-C", str(source), "add", "main.go"], check=True, capture_output=True)
                    subprocess.run(["git", "-C", str(source), "commit", "-m", "secret fixture"], check=True, capture_output=True)
                    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
                    subprocess.run(["git", "-C", str(source), "checkout", "--detach", commit], check=True, capture_output=True)
                elif mutation == "release":
                    (candidates / "amd64/release/payload.txt").write_text("AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
                elif mutation == "archive":
                    archive = candidates / "amd64/amd64.tar.gz"
                    with tarfile.open(archive, "w:gz") as value:
                        data = b"ghp_abcdefghijklmnopqrstuvwxyz123456"
                        info = tarfile.TarInfo("release/payload.txt")
                        info.size = len(data)
                        value.addfile(info, io.BytesIO(data))
                elif mutation == "cert":
                    (certification / "release-index.json").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
                elif mutation == "symlink":
                    os.symlink("payload.txt", candidates / "amd64/release/link")
                else:
                    output.mkdir()
                with self.assertRaises(tool.SecurityScanError):
                    tool.scan(source, commit, candidates, certification, govuln, go, output)
                if mutation != "existing":
                    self.assertFalse(output.exists())

    def test_rejects_govuln_findings_failures_and_metadata_drift(self) -> None:
        tool = load_tool()
        for mutation in ("finding", "nonzero", "malformed", "version-drift", "synchronized-version-drift", "db-drift", "go-drift", "time-malformed", "timezone-drift", "extra-version-line", "missing-go"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source, commit, candidates, certification, govuln, go = self.fixture(root, tool)
                if mutation == "finding":
                    config = {"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": "v1.7.0", "go_version": "go1.25.13", "db": "https://vuln.go.dev", "db_last_modified": "2026-08-28T14:47:45Z", "scan_mode": "source", "scan_level": "symbol"}}
                    govuln = self.fake_govuln(root, scan=json.dumps(config) + json.dumps({"finding": {"osv": "not-recorded"}}))
                elif mutation == "nonzero":
                    govuln = self.fake_govuln(root, exit_code=1)
                elif mutation == "malformed":
                    govuln = self.fake_govuln(root, scan="{")
                elif mutation == "version-drift":
                    govuln = self.fake_govuln(root, version="Go: go1.25.13\nScanner: govulncheck@v9.9.9\nDB: https://vuln.go.dev\nDB updated: 2026-08-28 14:47:45 +0000 UTC\n")
                elif mutation == "synchronized-version-drift":
                    scan = json.dumps({"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": "v9.9.9", "go_version": "go1.25.13", "db": "https://vuln.go.dev", "db_last_modified": "2026-08-28T14:47:45Z", "scan_mode": "source", "scan_level": "symbol"}})
                    govuln = self.fake_govuln(root, scan=scan, version="Go: go1.25.13\nScanner: govulncheck@v9.9.9\nDB: https://vuln.go.dev\nDB updated: 2026-08-28 14:47:45 +0000 UTC\n")
                elif mutation == "db-drift":
                    govuln = self.fake_govuln(root, version="Go: go1.25.13\nScanner: govulncheck@v1.7.0\nDB: https://other.example.invalid\nDB updated: 2026-08-28 14:47:45 +0000 UTC\n")
                elif mutation == "go-drift":
                    govuln = self.fake_govuln(root, version="Go: go1.99.0\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: 2026-08-28 14:47:45 +0000 UTC\n")
                elif mutation == "time-malformed":
                    govuln = self.fake_govuln(root, version="Go: go1.25.13\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: not-a-time\n")
                elif mutation == "timezone-drift":
                    govuln = self.fake_govuln(root, version="Go: go1.25.13\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: 2026-08-28 22:47:45 +0800 UTC\n")
                elif mutation == "extra-version-line":
                    govuln = self.fake_govuln(root, version="Go: go1.25.13\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: 2026-08-28 14:47:45 +0000 UTC\nextra\n")
                else:
                    go = root / "missing-go"
                with self.assertRaises(tool.SecurityScanError):
                    tool.scan(source, commit, candidates, certification, govuln, go, root / "scan")

    def test_rejects_duplicate_govuln_json(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, commit, candidates, certification, _, go = self.fixture(root, tool)
            govuln = self.fake_govuln(root, scan='{"config":{},"config":{}}')
            with self.assertRaises(tool.SecurityScanError):
                tool.scan(source, commit, candidates, certification, govuln, go, root / "scan")


if __name__ == "__main__":
    unittest.main()
