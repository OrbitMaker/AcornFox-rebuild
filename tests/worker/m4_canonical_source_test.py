import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "mvp" / "build-m4-canonical-source.sh"


class M4CanonicalSourceScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_requires_explicit_verified_deb_input_and_non_overwrite_root(self) -> None:
        self.assertIn("--debs-root", self.text)
        self.assertIn("debs.sha256", self.text)
        self.assertIn("refusing to overwrite canonical source root", self.text)
        self.assertIn("clean-worker-offline-source", self.text)

    def test_pins_all_external_assets_and_linux_binaries(self) -> None:
        for value in (
            "2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af",
            "b1302b7395918266d561b9e3053771253f20761807e042ae80a1868d6e86b71c",
            "48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778",
            "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9",
            "6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733",
        ):
            self.assertIn(value, self.text)
        self.assertIn("GOOS=linux GOARCH=amd64", self.text)
        self.assertIn("source-manifest.sha256", self.text)
        self.assertIn("open-card-caddy-fixture", self.text)
        self.assertIn("open-card-caddy-fixture.manifest.json", self.text)
        self.assertIn('"default_enabled":false', self.text)


if __name__ == "__main__":
    unittest.main()
