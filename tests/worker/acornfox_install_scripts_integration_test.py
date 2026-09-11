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
import os
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
    "/etc/os-release": 7,
    "/usr/bin/grep": 14,
    "/usr/bin/uname": 1,
    "/usr/bin/systemctl": 48,
    "/usr/bin/docker": 1,
    "/usr/lib/postgresql/16/bin/postgres": 1,
    "/usr/lib/postgresql/16/bin/psql": 1,
    "/usr/lib/postgresql/16/bin/pg_dump": 1,
    "/usr/lib/postgresql/16/bin/pg_restore": 1,
    "/usr/bin/getent": 5,
    "/usr/bin/stat": 16,
    "/var/lib/acornfox": 1,
    "/var/lib/acornfox/install": 2,
    "/etc/subuid": 4,
    "/etc/subgid": 4,
    "/usr/bin/apt-get": 1,
    "/usr/sbin/groupadd": 1,
    "/usr/sbin/useradd": 1,
    "/usr/sbin/usermod": 1,
    "/usr/bin/install": 4,
    "/usr/bin/dirname": 1,
    "/usr/bin/sha256sum": 4,
    "/usr/bin/cmp": 1,
    "/usr/bin/chmod": 2,
    "/usr/bin/tee": 3,
    "/usr/bin/mktemp": 2,
    "/usr/bin/cp": 1,
    "/usr/bin/sync": 2,
    "/usr/bin/mv": 1,
    "/usr/bin/rm": 3,
    "/usr/bin/rmdir": 2,
    "/run/acornfox-pgdg.XXXXXXXX": 1,
    "/etc/apt": 1,
    "/opt/acornfox/upgrade-tools/acornfox-upgrade": 5,
    "/usr/bin/nproc": 1,
    "/usr/bin/awk": 1,
    "/usr/bin/df": 1,
    "/usr/bin/tail": 1,
    "/usr/bin/tr": 1,
}

FAKE_NAMES = {
    "/usr/bin/env": "env", "/usr/bin/id": "id", "/etc/os-release": "os-release",
    "/usr/bin/grep": "grep", "/usr/bin/uname": "uname", "/usr/bin/systemctl": "systemctl",
    "/usr/bin/docker": "docker", "/usr/lib/postgresql/16/bin/postgres": "postgres",
    "/usr/lib/postgresql/16/bin/psql": "psql", "/usr/lib/postgresql/16/bin/pg_dump": "pg_dump", "/usr/lib/postgresql/16/bin/pg_restore": "pg_restore",
    "/usr/bin/getent": "getent", "/usr/bin/stat": "stat", "/var/lib/acornfox": "state-parent", "/var/lib/acornfox/install": "state-install",
    "/etc/subuid": "subuid", "/etc/subgid": "subgid", "/usr/bin/apt-get": "apt-get",
    "/usr/sbin/groupadd": "groupadd", "/usr/sbin/useradd": "useradd", "/usr/sbin/usermod": "usermod",
    "/usr/bin/install": "install", "/usr/bin/dirname": "dirname", "/usr/bin/sha256sum": "sha256sum",
    "/usr/bin/cmp": "cmp", "/usr/bin/chmod": "chmod", "/usr/bin/tee": "tee", "/usr/bin/mktemp": "mktemp",
    "/usr/bin/cp": "cp", "/usr/bin/sync": "sync", "/usr/bin/mv": "mv", "/usr/bin/rm": "rm", "/usr/bin/rmdir": "rmdir",
    "/run/acornfox-pgdg.XXXXXXXX": "pgdg-temp-template", "/etc/apt": "apt-root",
    "/usr/bin/nproc": "nproc", "/usr/bin/awk": "awk", "/usr/bin/df": "df", "/usr/bin/tail": "tail", "/usr/bin/tr": "tr",
    "/opt/acornfox/upgrade-tools/acornfox-upgrade": "current-helper",
}


FAKE_PROGRAM = r'''#!__PYTHON__
import hashlib, json, os, pathlib, shutil, sys

ROOT = pathlib.Path(__ROOT__)
STATE = ROOT / "state.json"
LOG = ROOT / "calls.jsonl"
CONTROL = ROOT / "control"
PLATFORM = ROOT / "platform"
SHA = "a" * 64

def load():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"accounts": {}, "groups": {}, "subid": False}

def save(value):
    STATE.write_text(json.dumps(value, sort_keys=True))

def control():
    return CONTROL.read_text().strip() if CONTROL.exists() else ""

def platform():
    return PLATFORM.read_text().strip() if PLATFORM.exists() else "ubuntu-amd64"

def event(name, args, include_env=True):
    value = {"name": name, "argv": args}
    if include_env:
        # A child spawned through the rewritten CLEAN_ENV must see exactly
        # this set; do not serialize unrelated parent process variables.
        value["env"] = {key: os.environ[key] for key in sorted(os.environ)
                        if key in {"PATH", "LANG", "LC_ALL", "DEBIAN_FRONTEND", "NEEDRESTART_MODE"}}
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
        print("aarch64" if platform().endswith("arm64") else "x86_64")
    elif name == "grep":
        needle = " ".join(args)
        if "ID=ubuntu" in needle:
            raise SystemExit(0 if platform().startswith("ubuntu-") else 1)
        if "ID=debian" in needle:
            raise SystemExit(0 if platform().startswith("debian-") else 1)
        if "VERSION_ID" in needle:
            expected = "24\\.04" if platform().startswith("ubuntu-") else "13"
            raise SystemExit(0 if expected in needle else 1)
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
        path = pathlib.Path(args[-1])
        subject = path.name
        marker = control()
        fmt = args[args.index("-c") + 1]
        if not path.exists() and not path.is_symlink():
            raise SystemExit(1)
        mode = 0o777 if marker == "bad-mode" else path.stat().st_mode & 0o777
        nlink = 2 if marker == "bad-nlink" else path.stat().st_nlink
        if fmt == "%a":
            print(f"{mode:o}")
            return
        if fmt == "%d:%i":
            print(f"1:{path.stat().st_ino}")
            return
        if fmt == "%d:%i:%u:%g:%a:%F:%h":
            kind = "directory" if path.is_dir() else ("regular empty file" if path.stat().st_size == 0 else "regular file")
            print(f"1:{path.stat().st_ino}:0:0:{mode:o}:{kind}:{nlink}")
            return
        if marker == "bad-mode":
            print("0:0:777:regular file:1" if subject.endswith("helper") else "0:0:777:directory:2")
        elif marker == "bad-nlink":
            print("0:0:755:regular file:2" if subject.endswith("helper") else "0:0:755:directory:3")
        elif path.is_file():
            kind = "regular empty file" if path.stat().st_size == 0 else "regular file"
            print(f"0:0:{'755' if subject.endswith('helper') else f'{mode:o}'}:{kind}:{nlink}")
        elif path.is_dir():
            if subject == "install":
                print("0:0:700:directory:2" if any("%h" in arg for arg in args) else "0:0:700:directory")
            else:
                print("0:0:755:directory:2" if any("%h" in arg for arg in args) else "0:0:755:directory")
        else:
            raise SystemExit(1)
    elif name == "sha256sum":
        path = pathlib.Path(args[-1])
        if path.name == "acornfox-postgresql.asc":
            print(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + args[-1])
        else:
            print(("b" * 64 if control() == "bad-digest" else "a" * 64) + "  " + args[-1])
    elif name == "mktemp":
        if "-d" in args:
            target = ROOT / "pgdg-private"
            target.mkdir(mode=0o700, exist_ok=True)
        else:
            template = pathlib.Path(args[-1])
            target = template.parent / (template.name.replace("XXXXXXXX", "fake-" + str(len(list(template.parent.glob("*.acornfox.fake-*"))))))
            target.touch(exist_ok=False)
        print(target)
    elif name == "tee":
        path = pathlib.Path(args[-1])
        path.parent.mkdir(parents=True, exist_ok=True)
        if control() == "publish-tee-failure" and ".acornfox." in path.name:
            path.write_bytes(b"partial")
            raise SystemExit(97)
        path.write_bytes(sys.stdin.buffer.read())
    elif name == "cmp":
        left, right = pathlib.Path(args[-2]), pathlib.Path(args[-1])
        raise SystemExit(0 if left.read_bytes() == right.read_bytes() else 1)
    elif name == "chmod":
        pathlib.Path(args[-1]).chmod(int(args[-2], 8))
    elif name == "cp":
        shutil.copyfile(args[-2], args[-1])
        if control() == "unknown-pgdg-child":
            pathlib.Path(args[-1]).parent.joinpath("unknown-source").write_bytes(b"unknown")
    elif name == "sync":
        pass
    elif name == "mv":
        source, target = pathlib.Path(args[-2]), pathlib.Path(args[-1])
        if control() == "target-appears":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"competing target")
        elif not target.exists() and not target.is_symlink():
            source.replace(target)
    elif name == "rm":
        pathlib.Path(args[-1]).unlink()
    elif name == "rmdir":
        pathlib.Path(args[-1]).rmdir()
    elif name == "install" and "-d" in args:
        path = pathlib.Path(args[-1])
        path.mkdir(mode=int(args[args.index("-m") + 1], 8), parents=True, exist_ok=True)
    elif name == "systemctl":
        if args == ["is-system-running"]:
            print("running")
        elif args == ["--version"]:
            print("systemd 255")
        elif args in (["is-enabled", "--quiet", "acornfox-pi-worker.service"], ["is-active", "--quiet", "acornfox-pi-worker.service"]):
            raise SystemExit(1)
    elif name == "nproc":
        print("2")
    elif name == "awk":
        print("3891200")
    elif name == "df":
        print("Avail\n10485760")
    elif name == "tail":
        print(sys.stdin.read().splitlines()[-1])
    elif name == "tr":
        sys.stdout.write(sys.stdin.read())
    elif name == "docker":
        print("Docker version 26.0.0, build fake")
    elif name == "psql":
        print("psql (PostgreSQL) 16.3")
    elif name == "postgres":
        print("postgres (PostgreSQL) 16.3")
    elif name == "pg_dump":
        print("pg_dump (PostgreSQL) 16.3")
    elif name == "pg_restore":
        print("pg_restore (PostgreSQL) 16.3")
    elif name == "bootstrap-helper":
        if args[:1] == ["validate-runtime-inputs"]:
            assert args == ["validate-runtime-inputs", "--public-origin", "https://console.example.org", "--git-resolvers", "223.5.5.5:53,223.6.6.6:53"]
            print('{"code":"runtime_inputs_valid","ok":true}')
            return
        if args[:1] != ["repository-bootstrap"]:
            raise SystemExit(2)
        print('{"command":"repository-bootstrap","ok":true,"receipt":{"binding_sha256":"' + SHA + '","final_evidence_sha256":"' + SHA + '","layout_sha256":"' + SHA + '","release_id":"release-1.2.3-test.1","schema_version":1,"source_commit":"0123456789abcdef0123456789abcdef01234567","state":"REPO_PREPARED","substrate_receipt_sha256":"' + SHA + '"}}')
    elif name == "current-helper":
        if args[:1] == ["configure-runtime"]:
            assert args == ["configure-runtime", "--public-origin", "https://console.example.org", "--git-resolvers", "223.5.5.5:53,223.6.6.6:53"]
            print('{"command":"configure-runtime","ok":true,"test_only":true}')
            return
        if args != ["migrate-control-plane", "--pending"]:
            raise SystemExit(2)
        print('{"command":"migrate-control-plane","ok":true,"receipt":{"binding_sha256":"' + SHA + '","database_env_sha256":"' + SHA + '","database_identity_sha256":"' + SHA + '","migration_rows_sha256":"' + SHA + '","migration_version":1,"release_id":"release-1.2.3-test.1","schema_version":1,"source_commit":"0123456789abcdef0123456789abcdef01234567","state":"CONTROL_PLANE_MIGRATED"}}')
    elif name == "successor-helper":
        if len(args) != 9 or args[0] != "repository-upgrade":
            raise SystemExit(2)
        print('{"command":"repository-upgrade","ok":true,"test_only":true}')
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
        self.successor = self.root / "successor-helper"
        self.log = self.root / "calls.jsonl"
        self.control = self.root / "control"
        self.platform_file = self.root / "platform"
        self.apt_root = self.root / "apt-root"
        self.apt_key = self.apt_root / "keyrings" / "acornfox-postgresql.asc"
        self.apt_source = self.apt_root / "sources.list.d" / "acornfox-postgresql.sources"
        self.system_source = self.apt_root / "sources.list.d" / "debian.sources"
        self.pgdg_private = self.root / "pgdg-private"
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
        replacements["/etc/apt"] = str(self.apt_root)
        replacements["/run/acornfox-pgdg.XXXXXXXX"] = str(self.root / "pgdg-temp-template")
        replacements["/var/lib/acornfox"] = str(self.root / "state-parent")
        replacements["/var/lib/acornfox/install"] = str(self.root / "state-parent" / "install")
        replacements["/opt/acornfox/upgrade-tools/acornfox-upgrade"] = str(self.current)
        all_source = "".join((SOURCE / name).read_text(encoding="utf-8") for name in NAMES)
        for token, expected in TOKEN_COUNTS.items():
            count = len(re.findall(re.escape(token) + r"(?![A-Za-z0-9_./-])", all_source))
            if count != expected:
                raise AssertionError(f"token drift {token}: {count} != {expected}")
            if token == "/etc/apt":
                (self.apt_root / "keyrings").mkdir(parents=True)
                (self.apt_root / "sources.list.d").mkdir()
                self.system_source.write_text("Types: deb\nURIs: http://system.example.invalid/debian\n", encoding="utf-8")
            elif token == "/run/acornfox-pgdg.XXXXXXXX":
                pathlib.Path(replacements[token]).parent.mkdir(parents=True, exist_ok=True)
            elif token in {"/var/lib/acornfox", "/var/lib/acornfox/install"}:
                continue
            else:
                self._write_fake(pathlib.Path(replacements[token]))
        self._write_fake(self.bootstrap)
        self._write_fake(self.successor)
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

    def set_platform(self, value: str = "ubuntu-amd64") -> None:
        self.platform_file.write_text(value, encoding="utf-8")

    def calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def run(self, script: str, args: list[str], confirmations: bool = False) -> subprocess.CompletedProcess[str]:
        # The fakes must prove rewritten CLEAN_ENV children do not inherit
        # these deliberately hostile parent values.
        env = {
            "PATH": "/usr/bin:/bin",
            "ACORNFOX_TEST_SECRET": "must-not-reach-child",
            "HTTPS_PROXY": "http://parent-proxy.invalid",
            "DATABASE_URL": "postgresql://parent-secret.invalid/db",
        }
        if confirmations:
            env.update({"ACORNFOX_INSTALL_CONFIRMATION": "ACORNFOX-INSTALL", "ACORNFOX_DEDICATED_HOST_CONFIRMATION": "ACORNFOX-DEDICATED-HOST", "ACORNFOX_PUBLIC_ORIGIN":"https://console.example.org", "ACORNFOX_GIT_RESOLVERS":"223.5.5.5:53,223.6.6.6:53"})
        return subprocess.run(["/bin/bash", str(self.scripts / script), *args], capture_output=True, text=True, env=env, check=False, preexec_fn=lambda: os.umask(0o022))

    def host_args(self) -> list[str]:
        return ["--candidate-dir", str(self.candidate), "--binding-sha256", SHA, "--bootstrap-helper", str(self.bootstrap), "--bootstrap-helper-sha256", SHA]


class AcornFoxInstallScriptIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.host = RewrittenHost()
        self.addCleanup(self.host.close)

    def assert_clean_child_env(self) -> None:
        direct_non_clean = set()
        injected = {"ACORNFOX_TEST_SECRET", "HTTPS_PROXY", "DATABASE_URL"}
        parent_injection_seen = False
        for call in self.host.calls():
            if call["name"] == "env":
                continue
            if "LANG" not in call["env_keys"]:
                self.assertIn(call["name"], {"id", "dirname"}, call)
                direct_non_clean.add(call["name"])
                parent_injection_seen |= injected.issubset(set(call["env_keys"]))
                continue
            expected = {"LANG", "LC_ALL", "PATH"}
            if call["name"] == "apt-get":
                expected |= {"DEBIAN_FRONTEND", "NEEDRESTART_MODE"}
                self.assertEqual(call["env"].get("DEBIAN_FRONTEND"), "noninteractive", call)
                self.assertEqual(call["env"].get("NEEDRESTART_MODE"), "l", call)
            self.assertEqual(set(call["env_keys"]) - {"__CF_USER_TEXT_ENCODING", "PWD", "SHLVL", "_"}, expected, call)
            expected_values = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
            if call["name"] == "apt-get":
                expected_values |= {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"}
            self.assertEqual(call["env"], expected_values, call)
            self.assertFalse(injected.intersection(call["env_keys"]), call)
        self.assertTrue(direct_non_clean.issubset({"id", "dirname"}))
        self.assertTrue(parent_injection_seen, "test parent did not carry injected secret/proxy/DSN")

    def test_install_host_runs_complete_ordered_task_root_flow(self) -> None:
        sentinel = self.host.root / "application-data"
        sentinel.write_bytes(b"application and volume data must survive")
        before = (sentinel.stat().st_ino, sentinel.read_bytes())
        result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipts = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([receipt["code"] if "code" in receipt else receipt["command"] for receipt in receipts], ["runtime_inputs_valid", "ok", "ok", "repository-bootstrap", "migrate-control-plane", "configure-runtime", "installed"])
        self.assertEqual(receipts[-1], {"code": "installed", "ok": True, "schema_version": 1})
        names = [str(call["name"]) for call in self.host.calls() if call["name"] != "env" and call["argv"][:1] != ["validate-runtime-inputs"]]
        major = [name for name in names if name in {"apt-get", "groupadd", "useradd", "usermod", "install", "bootstrap-helper", "current-helper", "systemctl"}]
        calls = self.host.calls()
        ubuntu_apt = [call["argv"] for call in calls if call["name"] == "apt-get"]
        self.assertEqual(len(ubuntu_apt), 2, ubuntu_apt)
        self.assertIn("git", ubuntu_apt[1])
        self.assertNotIn("docker-cli", ubuntu_apt[1])
        validation = next(i for i,c in enumerate(calls) if c["name"] == "bootstrap-helper" and c["argv"][:1] == ["validate-runtime-inputs"])
        self.assertLess(validation, next(i for i,c in enumerate(calls) if c["name"] == "apt-get"))
        self.assertLess(major.index("apt-get"), major.index("groupadd"))
        self.assertLess(major.index("groupadd"), major.index("usermod"))
        self.assertLess(major.index("usermod"), major.index("install"))
        self.assertLess(major.index("install"), major.index("bootstrap-helper"))
        self.assertLess(major.index("bootstrap-helper"), major.index("current-helper"))
        systemctl = [call["argv"] for call in self.host.calls() if call["name"] == "systemctl"]
        self.assertLess(systemctl.index(["start", "acornfox-build-network.service"]), systemctl.index(["start", "acornfox-buildkit.service"]))
        self.assertLess(systemctl.index(["start", "acornfox-runtime-network.service"]), systemctl.index(["start", "acornfox-agent.service"]))
        self.assertIn(["start", "acornfox-healthcheck.timer"], systemctl)
        self.assertIn(["start", "acornfox-healthcheck.service"], systemctl)
        self.assertNotIn(["is-active", "--quiet", "acornfox-healthcheck.service"], systemctl)
        self.assert_clean_child_env()
        self.assertEqual((sentinel.stat().st_ino, sentinel.read_bytes()), before)

    def test_preflight_reports_supported_matrix_and_rejects_mismatches(self) -> None:
        for platform, expected in (
            ("ubuntu-amd64", {"architecture": "amd64", "os_id": "ubuntu", "os_version": "24.04"}),
            ("ubuntu-arm64", {"architecture": "arm64", "os_id": "ubuntu", "os_version": "24.04"}),
            ("debian-amd64", {"architecture": "amd64", "os_id": "debian", "os_version": "13"}),
        ):
            self.host.log.unlink(missing_ok=True)
            self.host.set_platform(platform)
            result = self.host.run("host-preflight.sh", ["--phase", "pre"])
            self.assertEqual(result.returncode, 0, (platform, result.stdout, result.stderr))
            receipt = json.loads(result.stdout)
            self.assertEqual({key: receipt[key] for key in expected}, expected)
            self.assertEqual(receipt["prerequisites"], "unchecked")
            self.assertEqual([call for call in self.host.calls() if call["name"] == "apt-get"], [], platform)
        for platform in ("debian-arm64", "other-amd64"):
            self.host.log.unlink(missing_ok=True)
            self.host.set_platform(platform)
            result = self.host.run("host-preflight.sh", ["--phase", "pre"])
            self.assertEqual(result.returncode, 23, (platform, result.stdout, result.stderr))
            self.assertEqual([call for call in self.host.calls() if call["name"] == "apt-get"], [], platform)

    def test_debian_bootstraps_ca_from_system_sources_then_publishes_pg16(self) -> None:
        self.host.set_platform("debian-amd64")
        first = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        apt_calls = [call["argv"] for call in self.host.calls() if call["name"] == "apt-get"]
        system_options = [
            "-o", f"Dir::Etc::sourcelist={self.host.apt_root / 'sources.list'}",
            "-o", f"Dir::Etc::sourceparts={self.host.pgdg_private / 'system-sourceparts'}",
        ]
        self.assertEqual(len(apt_calls), 4, apt_calls)
        apt_envs = [call["env"] for call in self.host.calls() if call["name"] == "apt-get"]
        self.assertEqual(len(apt_envs), 4, apt_envs)
        self.assertTrue(all(env.get("DEBIAN_FRONTEND") == "noninteractive" and env.get("NEEDRESTART_MODE") == "l" for env in apt_envs), apt_envs)
        self.assertEqual(apt_calls[0], [*system_options, "update"])
        self.assertEqual(apt_calls[1], [*system_options, "install", "-y", "--no-install-recommends", "ca-certificates"])
        self.assertEqual(apt_calls[2], ["update"])
        self.assertIn("postgresql-16", apt_calls[3])
        self.assertIn("postgresql-client-16", apt_calls[3])
        self.assertIn("docker-cli", apt_calls[3])
        self.assertIn("git", apt_calls[3])
        self.assertNotIn("postgresql", apt_calls[3])
        copy_calls = [call["argv"] for call in self.host.calls() if call["name"] == "cp"]
        self.assertEqual(len(copy_calls), 1, copy_calls)
        self.assertEqual(copy_calls[0][-2], str(self.host.system_source))
        self.assertIn("system-sourceparts/debian.sources", copy_calls[0][-1])
        calls = self.host.calls()
        ca_install = next(index for index, call in enumerate(calls) if call["name"] == "apt-get" and "ca-certificates" in call["argv"])
        first_publish = next(index for index, call in enumerate(calls) if call["name"] == "mv")
        second_update = next(index for index, call in enumerate(calls) if call["name"] == "apt-get" and call["argv"] == ["update"])
        self.assertLess(ca_install, first_publish)
        self.assertLess(first_publish, second_update)
        self.assertEqual(self.host.apt_key.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.host.apt_source.stat().st_mode & 0o777, 0o644)
        self.assertIn(b"Suites: trixie-pgdg\n", self.host.apt_source.read_bytes())
        self.assertFalse(self.host.pgdg_private.exists())
        sync_calls = [call["argv"] for call in self.host.calls() if call["name"] == "sync"]
        self.assertEqual(len(sync_calls), 4, sync_calls)
        self.assertEqual(sync_calls[1][-1], str(self.host.apt_key.parent))
        self.assertEqual(sync_calls[3][-1], str(self.host.apt_source.parent))
        self.host.apt_key.chmod(0o600)
        self.host.apt_source.chmod(0o600)
        self.host.log.unlink()
        second = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len([call for call in self.host.calls() if call["name"] == "mv"]), 0)
        self.assertEqual(self.host.apt_key.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.host.apt_source.stat().st_mode & 0o777, 0o644)

    def test_debian_cleanup_preserves_unknown_private_snapshot_child(self) -> None:
        self.host.set_platform("debian-amd64")
        self.host.set_control("unknown-pgdg-child")
        result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.host.pgdg_private / "system-sourceparts" / "unknown-source").read_bytes(),
            b"unknown",
        )

    def test_debian_atomic_publication_leaves_no_partial_final_and_retries(self) -> None:
        self.host.set_platform("debian-amd64")
        self.host.set_control("publish-tee-failure")
        failed = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(failed.returncode, 23, failed.stderr)
        self.assertFalse(self.host.apt_key.exists())
        self.assertFalse(self.host.apt_source.exists())
        self.assertEqual(list((self.host.apt_root / "keyrings").glob(".acornfox-postgresql.asc.acornfox.*")), [])
        failed_apt = [call["argv"] for call in self.host.calls() if call["name"] == "apt-get"]
        self.assertEqual(len(failed_apt), 2, failed_apt)
        self.assertIn("ca-certificates", failed_apt[1])
        cleanup_calls = [call["argv"] for call in self.host.calls() if call["name"] == "rm"]
        self.assertEqual(len(cleanup_calls), 4, cleanup_calls)
        self.assertEqual(sum(".acornfox." in call[-1] for call in cleanup_calls), 1, cleanup_calls)
        self.assertTrue(all("pgdg-private" in call[-1] or ".acornfox." in call[-1] for call in cleanup_calls), cleanup_calls)
        self.assertEqual([call for call in self.host.calls() if call["name"] == "groupadd"], [])
        self.host.set_control()
        self.host.log.unlink()
        retried = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(self.host.apt_key.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.host.apt_source.stat().st_mode & 0o777, 0o644)

    def test_debian_atomic_publication_does_not_overwrite_competing_target(self) -> None:
        self.host.set_platform("debian-amd64")
        self.host.set_control("target-appears")
        result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(self.host.apt_key.read_bytes(), b"competing target")
        self.assertFalse(self.host.apt_source.exists())
        self.assertEqual(list((self.host.apt_root / "keyrings").glob(".acornfox-postgresql.asc.acornfox.*")), [])
        self.assertEqual([call for call in self.host.calls() if call["name"] == "groupadd"], [])
        cleanup_calls = [call["argv"] for call in self.host.calls() if call["name"] == "rm"]
        self.assertEqual(len(cleanup_calls), 4, cleanup_calls)
        self.assertEqual(sum(".acornfox." in call[-1] for call in cleanup_calls), 1, cleanup_calls)
        self.assertTrue(all("pgdg-private" in call[-1] or ".acornfox." in call[-1] for call in cleanup_calls), cleanup_calls)

    def test_debian_rejects_hardlinked_exact_apt_material_before_apt_or_accounts(self) -> None:
        self.host.set_platform("debian-amd64")
        first = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        alias = self.host.root / "pgdg-key-alias"
        os.link(self.host.apt_key, alias)
        self.host.log.unlink()
        second = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(second.returncode, 23, second.stderr)
        names = [call["name"] for call in self.host.calls()]
        self.assertEqual(names.count("apt-get"), 0, names)
        self.assertEqual(names.count("groupadd"), 0, names)

    def test_debian_rejects_foreign_apt_material_before_apt_or_accounts(self) -> None:
        self.host.set_platform("debian-amd64")
        cases = ((self.host.apt_key, b"foreign key\n"), (self.host.apt_source, b"foreign source\n"))
        for path, content in cases:
            self.host.log.unlink(missing_ok=True)
            path.write_bytes(content)
            path.chmod(0o644)
            result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
            self.assertEqual(result.returncode, 23, (path, result.stdout, result.stderr))
            names = [call["name"] for call in self.host.calls()]
            self.assertEqual(names.count("apt-get"), 0, (path, names))
            self.assertEqual(names.count("groupadd"), 0, (path, names))
            path.unlink()
        self.host.apt_key.symlink_to(self.host.root / "foreign-key")
        result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(result.returncode, 23, (result.stdout, result.stderr))
        names = [call["name"] for call in self.host.calls()]
        self.assertEqual(names.count("apt-get"), 0, names)
        self.assertEqual(names.count("groupadd"), 0, names)
        self.host.apt_key.unlink()
        self.host.apt_key.mkdir()
        self.host.log.unlink()
        result = self.host.run("install-host.sh", self.host.host_args(), confirmations=True)
        self.assertEqual(result.returncode, 23, (result.stdout, result.stderr))
        names = [call["name"] for call in self.host.calls()]
        self.assertEqual(names.count("apt-get"), 0, names)
        self.assertEqual(names.count("groupadd"), 0, names)

    def test_upgrade_wrapper_handoffs_only_to_a_test_successor(self) -> None:
        next_binding = "b" * 64
        current_binding = "c" * 64
        args = [
            "--candidate-dir", str(self.host.candidate),
            "--next-binding-sha256", next_binding,
            "--current-binding-sha256", current_binding,
            "--successor-helper", str(self.host.successor),
            "--successor-helper-sha256", SHA,
        ]
        result = self.host.run("upgrade.sh", args, confirmations=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"command": "repository-upgrade", "ok": True, "test_only": True})
        calls = [call for call in self.host.calls() if call["name"] == "successor-helper"]
        self.assertEqual(len(calls), 1, calls)
        self.assertEqual(calls[0]["argv"], [
            "repository-upgrade", "--candidate-dir", str(self.host.candidate),
            "--binding-sha256", next_binding,
            "--current-binding-sha256", current_binding,
            "--self-sha256", SHA,
        ])
        self.assert_clean_child_env()

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
