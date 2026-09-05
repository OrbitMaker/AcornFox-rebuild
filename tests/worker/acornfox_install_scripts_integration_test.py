#!/usr/bin/env python3
"""Task-root integration evidence for the five AcornFox host wrappers.

The production scripts never accept a path override.  This test copies their
exact bytes into a private temporary root and replaces a closed list of
absolute effect/read tokens there only.  The fakes then let the test exercise
the real bash control flow without allowing apt, systemd, Docker, PostgreSQL,
or /opt to escape the temporary root.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts" / "acornfox"
NAMES = (
    "host-preflight.sh",
    "install-host.sh",
    "install.sh",
    "control-plane-migrate.sh",
    "upgrade.sh",
)
SHA = "a" * 64

# This is deliberately an exact, reviewable contract rather than a catch-all
# regex.  If a script gains an absolute host dependency, this test fails until
# its fake behavior and expected occurrence count are consciously specified.
TOKEN_COUNTS = {
    "/usr/bin/env": 10,
    "/usr/bin/id": 5,
    "/etc/os-release": 3,
    "/usr/bin/grep": 10,
    "/usr/bin/uname": 1,
    "/usr/bin/systemctl": 26,
    "/usr/bin/docker": 1,
    "/usr/bin/psql": 1,
    "/usr/lib/postgresql/16/bin/postgres": 1,
    "/usr/bin/getent": 5,
    "/usr/bin/stat": 8,
    "/var/lib/acornfox": 1,
    "/var/lib/acornfox/install": 2,
    "/etc/subuid": 4,
    "/etc/subgid": 4,
    "/usr/bin/apt-get": 2,
    "/usr/sbin/groupadd": 1,
    "/usr/sbin/useradd": 1,
    "/usr/sbin/usermod": 1,
    "/usr/bin/install": 2,
    "/usr/bin/dirname": 1,
    "/usr/bin/sha256sum": 3,
    "/opt/acornfox/upgrade-tools/acornfox-upgrade": 1,
}

FAKE_NAMES = {
    "/usr/bin/env": "env", "/usr/bin/id": "id", "/etc/os-release": "os-release",
    "/usr/bin/grep": "grep", "/usr/bin/uname": "uname", "/usr/bin/systemctl": "systemctl",
    "/usr/bin/docker": "docker", "/usr/bin/psql": "psql", "/usr/lib/postgresql/16/bin/postgres": "postgres",
    "/usr/bin/getent": "getent", "/usr/bin/stat": "stat", "/var/lib/acornfox": "state-parent", "/var/lib/acornfox/install": "state-install",
    "/etc/subuid": "subuid", "/etc/subgid": "subgid", "/usr/bin/apt-get": "apt-get",
    "/usr/sbin/groupadd": "groupadd", "/usr/sbin/useradd": "useradd", "/usr/sbin/usermod": "usermod",
    "/usr/bin/install": "install", "/usr/bin/dirname": "dirname", "/usr/bin/sha256sum": "sha256sum",
    "/opt/acornfox/upgrade-tools/acornfox-upgrade": "current-helper",
}


FAKE_PROGRAM = r'''#!__PYTHON__
import json, os, pathlib, sys

ROOT = pathlib.Path(__ROOT__)
STATE = ROOT / "state.json"
LOG = ROOT / "calls.jsonl"
CONTROL = ROOT / "control"
SHA = "a" * 64

def load():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"accounts": {}, "groups": {}, "subid": False}

def save(value):
    STATE.write_text(json.dumps(value, sort_keys=True))

def control():
    return CONTROL.read_text().strip() if CONTROL.exists() else ""

def event(name, args, include_env=True):
    value = {"name": name, "argv": args}
    if include_env:
        # A child spawned through the rewritten CLEAN_ENV must see exactly
        # this set; do not serialize unrelated parent process variables.
        value["env"] = {key: os.environ[key] for key in sorted(os.environ)
                        if key in {"PATH", "LANG", "LC_ALL"}}
        value["env_keys"] = sorted(os.environ)
    with LOG.open("a") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")

def failed(name, args):
    marker = control()
    return marker in {name, name + ":" + " ".join(args)} or (marker == "migrate" and name == "current-helper")

def main():
    name = pathlib.Path(sys.argv[0]).name
    args = sys.argv[1:]
    if name == "env":
        # Do not expose the caller environment.  This merely models env -i.
        event(name, args, include_env=False)
        index = 0
        if index < len(args) and args[index] == "-i":
            index += 1
        child = {}
        while index < len(args) and "=" in args[index] and not args[index].startswith("/"):
            key, value = args[index].split("=", 1)
            child[key] = value
            index += 1
        if index >= len(args):
            raise SystemExit(127)
        # The rewritten scripts retain their source shebang but its env
        # interpreter is also faked.  Avoid interpreter recursion here while
        # still running the copied bash source with precisely the env -i map.
        if args[index].endswith(".sh"):
            os.execve("/bin/bash", ["/bin/bash", args[index], *args[index + 1:]], child)
        os.execve(args[index], args[index:], child)
    event(name, args)
    if failed(name, args):
        raise SystemExit(97)
    state = load()
    if name == "id":
        print("0")
    elif name == "dirname":
        print(str(pathlib.Path(args[-1]).parent))
    elif name == "uname":
        print("x86_64")
    elif name == "grep":
        needle = " ".join(args)
        if "acornfox-buildkit:231072:65536" in needle:
            raise SystemExit(0 if state["subid"] else 1)
        if "^acornfox-buildkit:" in needle:
            raise SystemExit(0 if state["subid"] else 1)
        raise SystemExit(0)
    elif name == "getent":
        kind, account = args[0], args[1]
        if kind == "passwd":
            if account not in state["accounts"]:
                raise SystemExit(2)
            uid, gid = state["accounts"][account]
            print(f"{account}:x:{uid}:{gid}::/nonexistent:/usr/sbin/nologin")
        elif kind == "group":
            if account not in state["groups"]:
                raise SystemExit(2)
            print(f"{account}:x:{state['groups'][account]}:")
        else:
            raise SystemExit(2)
    elif name == "groupadd":
        account = args[-1]
        state["groups"][account] = str(2000 + len(state["groups"]))
        save(state)
    elif name == "useradd":
        account = args[-1]
        gid = state["groups"][account]
        state["accounts"][account] = (str(1000 + len(state["accounts"])), gid)
        save(state)
    elif name == "usermod":
        state["subid"] = True
        save(state)
    elif name == "stat":
        subject = pathlib.Path(args[-1]).name
        marker = control()
        if marker == "bad-mode":
            print("0:0:777:regular file:1" if subject.endswith("helper") else "0:0:777:directory:2")
        elif marker == "bad-nlink":
            print("0:0:755:regular file:2" if subject.endswith("helper") else "0:0:755:directory:3")
        elif subject.endswith("helper"):
            print("0:0:755:regular file:1")
        elif subject == "candidate":
            print("0:0:755:directory:2")
        else:
            print("0:0:700:directory:2" if "%h" in args else "0:0:700:directory")
    elif name == "sha256sum":
        print(("b" * 64 if control() == "bad-digest" else "a" * 64) + "  " + args[-1])
    elif name == "systemctl":
        if args == ["is-system-running"]:
            print("running")
        elif args == ["--version"]:
            print("systemd 255")
    elif name == "docker":
        print("Docker version 26.0.0, build fake")
    elif name == "psql":
        print("psql (PostgreSQL) 16.3")
    elif name == "postgres":
        print("postgres (PostgreSQL) 16.3")
    elif name == "bootstrap-helper":
        if args[:1] != ["repository-bootstrap"]:
            raise SystemExit(2)
        print('{"command":"repository-bootstrap","ok":true,"receipt":{"binding_sha256":"' + SHA + '","final_evidence_sha256":"' + SHA + '","layout_sha256":"' + SHA + '","release_id":"release-1.2.3-test.1","schema_version":1,"source_commit":"0123456789abcdef0123456789abcdef01234567","state":"REPO_PREPARED","substrate_receipt_sha256":"' + SHA + '"}}')
    elif name == "current-helper":
        if args != ["migrate-control-plane", "--pending"]:
            raise SystemExit(2)
        print('{"command":"migrate-control-plane","ok":true,"receipt":{"binding_sha256":"' + SHA + '","database_env_sha256":"' + SHA + '","database_identity_sha256":"' + SHA + '","migration_rows_sha256":"' + SHA + '","migration_version":1,"release_id":"release-1.2.3-test.1","schema_version":1,"source_commit":"0123456789abcdef0123456789abcdef01234567","state":"CONTROL_PLANE_MIGRATED"}}')
    # apt-get/install/systemctl and all other modeled effects succeed.

if __name__ == "__main__":
    main()
'''


class RewrittenHost:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="acornfox-install-script-test-")
        self.root = pathlib.Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.fakes = self.root / "fakes"
        self.candidate = self.root / "candidate"
        self.bootstrap = self.root / "bootstrap-helper"
        self.current = self.root / "current-helper"
        self.log = self.root / "calls.jsonl"
        self.control = self.root / "control"
        self._prepare()

    def close(self) -> None:
        self.temp.cleanup()

    def _write_fake(self, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(FAKE_PROGRAM.replace("__PYTHON__", sys.executable).replace("__ROOT__", repr(str(self.root))), encoding="utf-8")
        path.chmod(0o755)

    def _prepare(self) -> None:
        self.scripts.mkdir()
        self.fakes.mkdir()
        self.candidate.mkdir()
        replacements = {token: str(self.fakes / FAKE_NAMES[token]) for token in TOKEN_COUNTS}
        replacements["/opt/acornfox/upgrade-tools/acornfox-upgrade"] = str(self.current)
        all_source = "".join((SOURCE / name).read_text(encoding="utf-8") for name in NAMES)
        for token, expected in TOKEN_COUNTS.items():
            count = len(re.findall(re.escape(token) + r"(?![A-Za-z0-9_./-])", all_source))
            if count != expected:
                raise AssertionError(f"token drift {token}: {count} != {expected}")
            self._write_fake(pathlib.Path(replacements[token]))
        self._write_fake(self.bootstrap)
        for name in NAMES:
            script = (SOURCE / name).read_text(encoding="utf-8")
            for token in sorted(replacements, key=len, reverse=True):
                replacement = replacements[token]
                script = script.replace(token, replacement)
            target = self.scripts / name
            target.write_text(script, encoding="utf-8")
            target.chmod(0o700)
        # These production paths must be absent after rewriting; all sibling
        # calls are intentionally relative to the rewritten SCRIPT_DIR.
        for name in NAMES:
            text = (self.scripts / name).read_text(encoding="utf-8")
            # Keep this tied to the closed effect/read map.  A data literal
            # such as /usr/sbin/nologin is not an executable target; every
            # actual absolute host effect/read path must have been rewritten.
            if any(token in text for token in replacements):
                raise AssertionError(f"unrewritten effect/read path in {name}")
            # Do not let a newly-added absolute host command evade the closed
            # map.  Normalize the private macOS temp root first; otherwise
            # its legitimate /var/folders prefix would be a false positive.
            code = "\n".join(line.split("#", 1)[0] for line in text.replace(str(self.root), "$TASK_ROOT").splitlines())
            code = code.replace("/usr/sbin/nologin", "")  # account metadata, not an invocation
            if re.search(r"/(?:opt|etc|var)/|/usr/(?:bin|sbin|lib)/", code):
                raise AssertionError(f"unrewritten absolute host command in {name}")

    def set_control(self, value: str = "") -> None:
        if value:
            self.control.write_text(value, encoding="utf-8")
        elif self.control.exists():
            self.control.unlink()

    def calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def run(self, script: str, args: list[str], confirmations: bool = False) -> subprocess.CompletedProcess[str]:
        env = {"PATH": "/usr/bin:/bin"}
        if confirmations:
            env.update({"ACORNFOX_INSTALL_CONFIRMATION": "ACORNFOX-INSTALL", "ACORNFOX_DEDICATED_HOST_CONFIRMATION": "ACORNFOX-DEDICATED-HOST"})
        return subprocess.run(["/bin/bash", str(self.scripts / script), *args], capture_output=True, text=True, env=env, check=False)

    def host_args(self) -> list[str]:
        return ["--candidate-dir", str(self.candidate), "--binding-sha256", SHA, "--bootstrap-helper", str(self.bootstrap), "--bootstrap-helper-sha256", SHA]


class AcornFoxInstallScriptIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.host = RewrittenHost()
        self.addCleanup(self.host.close)

    def assert_clean_child_env(self) -> None:
        for call in self.host.calls():
            if call["name"] == "env" or "LANG" not in call["env_keys"]:
                continue
            self.assertEqual(set(call["env_keys"]) - {"__CF_USER_TEXT_ENCODING", "PWD", "SHLVL", "_"}, {"LANG", "LC_ALL", "PATH"}, call)
            self.assertEqual(call["env"], {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, call)

    def test_install_host_runs_complete_ordered_task_root_flow(self) -> None:
        sentinel = self.host.root / "application-data"
        sentinel.write_bytes(b"application and volume data must survive")
        before = (sentinel.stat().st_ino, sentinel.read_bytes())
        result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipts = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([receipt["code"] if "code" in receipt else receipt["command"] for receipt in receipts], ["ok", "ok", "repository-bootstrap", "migrate-control-plane", "installed"])
        self.assertEqual(receipts[-1], {"code": "installed", "ok": True, "schema_version": 1})
        names = [str(call["name"]) for call in self.host.calls() if call["name"] != "env"]
        major = [name for name in names if name in {"apt-get", "groupadd", "useradd", "usermod", "install", "bootstrap-helper", "current-helper", "systemctl"}]
        self.assertLess(major.index("apt-get"), major.index("groupadd"))
        self.assertLess(major.index("groupadd"), major.index("usermod"))
        self.assertLess(major.index("usermod"), major.index("install"))
        self.assertLess(major.index("install"), major.index("bootstrap-helper"))
        self.assertLess(major.index("bootstrap-helper"), major.index("current-helper"))
        systemctl = [call["argv"] for call in self.host.calls() if call["name"] == "systemctl"]
        self.assertIn(["start", "acornfox-healthcheck.timer"], systemctl)
        self.assertIn(["start", "acornfox-healthcheck.service"], systemctl)
        self.assertNotIn(["is-active", "--quiet", "acornfox-healthcheck.service"], systemctl)
        self.assert_clean_child_env()
        self.assertEqual((sentinel.stat().st_ino, sentinel.read_bytes()), before)

    def test_invalid_forms_are_rejected_before_effects(self) -> None:
        cases = {
            "host-preflight.sh": [["--phase"], ["pre", "--phase"], ["--phase", "pre", "extra"], ["--phase", "pre", "--phase", "post"]],
            "install-host.sh": [["--candidate-dir"], [*self.host.host_args()[2:], *self.host.host_args()[:2]], [*self.host.host_args(), "extra"], ["--candidate-dir", str(self.host.candidate), "--candidate-dir", str(self.host.candidate), *self.host.host_args()[2:]]],
            "install.sh": [["--candidate-dir"], [*self.host.host_args()[2:], *self.host.host_args()[:2]], [*self.host.host_args(), "extra"], ["--candidate-dir", str(self.host.candidate), "--candidate-dir", str(self.host.candidate), *self.host.host_args()[2:]]],
            "control-plane-migrate.sh": [[], ["--pending", "extra"], ["--pending", "--pending"], ["--wrong"]],
            "upgrade.sh": [[], ["--candidate-dir"], ["--next-binding-sha256", SHA, "--candidate-dir", str(self.host.candidate), "--current-binding-sha256", "b" * 64, "--successor-helper", str(self.host.bootstrap), "--successor-helper-sha256", SHA], ["--candidate-dir", str(self.host.candidate), "--next-binding-sha256", SHA, "--next-binding-sha256", SHA, "--current-binding-sha256", "b" * 64, "--successor-helper", str(self.host.bootstrap), "--successor-helper-sha256", SHA], ["--candidate-dir", str(self.host.candidate), "--next-binding-sha256", SHA, "--current-binding-sha256", "b" * 64, "--successor-helper", str(self.host.bootstrap), "--successor-helper-sha256", SHA, "extra"]],
        }
        for script, variants in cases.items():
            for args in [["--help"], *variants]:
                self.host.log.unlink(missing_ok=True)
                result = self.host.run(script, args, confirmations=True)
                if args == ["--help"]:
                    self.assertEqual(result.returncode, 0, (script, args, result.stderr))
                else:
                    self.assertEqual(result.returncode, 2, (script, args, result.stdout, result.stderr))
                host_effects = [call for call in self.host.calls() if call["name"] not in {"dirname"}]
                self.assertEqual(host_effects, [], (script, args, host_effects))

    def test_candidate_and_helper_guards_stop_before_any_effect(self) -> None:
        variants = []
        candidate_link = self.host.root / "candidate-link"
        candidate_link.symlink_to(self.host.candidate, target_is_directory=True)
        variants.append(("candidate-link", ["--candidate-dir", str(candidate_link), *self.host.host_args()[2:]], ""))
        helper_link = self.host.root / "bootstrap-link"
        helper_link.symlink_to(self.host.bootstrap)
        variants.append(("helper-link", [*self.host.host_args()[:4], "--bootstrap-helper", str(helper_link), "--bootstrap-helper-sha256", SHA], ""))
        variants.extend((name, self.host.host_args(), control) for name, control in (("writable-mode", "bad-mode"), ("nlink", "bad-nlink"), ("digest", "bad-digest")))
        for name, args, control in variants:
            self.host.log.unlink(missing_ok=True)
            self.host.set_control(control)
            result = self.host.run("install-host.sh", args, confirmations=True)
            self.assertEqual(result.returncode, 23, (name, result.stdout, result.stderr))
            effects = [call for call in self.host.calls() if call["name"] not in {"dirname", "env", "id", "stat", "sha256sum"}]
            self.assertEqual(effects, [], (name, effects))
        self.host.set_control()

    def test_failure_stops_without_compensation_or_later_systemctl(self) -> None:
        sentinel = self.host.root / "volume-data"
        sentinel.write_bytes(b"keep")
        before = (sentinel.stat().st_ino, sentinel.read_bytes())
        for marker, forbidden in (("apt-get", "groupadd"), ("migrate", "daemon-reload")):
            self.host.log.unlink(missing_ok=True)
            self.host.set_control(marker)
            result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
            self.assertNotEqual(result.returncode, 0, (marker, result.stdout, result.stderr))
            calls = self.host.calls()
            if marker == "migrate":
                self.assertIn("current-helper", [call["name"] for call in calls], calls)
                self.assertNotIn(["daemon-reload"], [call["argv"] for call in calls if call["name"] == "systemctl"], calls)
            else:
                self.assertNotIn(forbidden, [call["name"] for call in calls], (marker, calls))
            self.assertEqual((sentinel.stat().st_ino, sentinel.read_bytes()), before)
        self.host.set_control()

    def test_real_clean_helper_contract_keeps_migrate_and_rejects_successor(self) -> None:
        # C2 owns the real Go dispatch.  This verifies the current source-level
        # unit contract, while the fake successor above remains only a script
        # guard test and makes no claim that 12B repository-upgrade exists.
        result = subprocess.run(["go", "test", "./cmd/open-card-upgrade", "-run", "TestAcornFoxCleanRejectsHostileArgumentsBeforeDependencies|TestAcornFoxCleanDispatchesOnlyOneInjectedBridgeOperation"], cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
