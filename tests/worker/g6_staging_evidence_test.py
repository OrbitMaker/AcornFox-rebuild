#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/mvp/g6-staging-evidence.sh"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class G6CollectorTest(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def write_json(self, path: Path, value: object, mode: int = 0o600) -> None:
        path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        path.chmod(mode)

    def setup_fixture(self, root: Path) -> dict[str, Path | str]:
        repo = root / "repo"; repo.mkdir()
        self.git(repo, "init", "-q"); self.git(repo, "config", "user.email", "g6@example.invalid"); self.git(repo, "config", "user.name", "g6")
        (repo / "source").write_text("source\n", encoding="utf-8"); self.git(repo, "add", "source"); self.git(repo, "commit", "-qm", "source")
        commit = self.git(repo, "rev-parse", "HEAD"); self.git(repo, "tag", "-a", "v0.8.0-rc.1", "-m", "g6")
        release = root / "release"; release.mkdir(); payload = release / "payload"; payload.write_bytes(b"payload"); payload.chmod(0o755)
        manifest = release / "manifest.json"
        self.write_json(manifest, {"version":"0.8.0-rc.1","source_commit":commit,"architecture":"amd64","migration_version":"0024","files":[{"path":"payload","sha256":digest(b"payload"),"mode":0o755}]})
        archive = root / "open-card-0.8.0-rc.1-production.tar.gz"; archive.write_bytes(b"archive"); archive.chmod(0o600)
        bundle = root / "bundle-manifest.sha256"; bundle.write_text(f"{digest(b'archive')}  {archive.name}\n{digest(manifest.read_bytes())}  release/manifest.json\n", encoding="utf-8"); bundle.chmod(0o600)
        install_id = root / "installation-id"; install_id.write_text("installation-g6\n", encoding="utf-8"); install_id.chmod(0o600)
        cookie = root / "session.cookie"; cookie.write_text("open_card_session=test-cookie\n", encoding="utf-8"); cookie.chmod(0o600)
        source = {"tag":"v0.8.0-rc.1","commit":commit,"bundle_manifest_sha256":digest(bundle.read_bytes())}
        target = {"provider":"tencent","product":"cvm","instance_id":"ins-g6-collector","public_ipv4":"8.8.8.8"}
        common = {"run_id":"g6-collector-1","source":source,"target":target,"source_repo":str(repo),"release_manifest":str(manifest),"release_manifest_sha256":digest(manifest.read_bytes()),"bundle_manifest":str(bundle)}
        identity_pre = root / "identity-pre.json"; self.write_json(identity_pre, common)
        identity_post = root / "identity-post.json"; self.write_json(identity_post, {**common,"installation_id_file":str(install_id)})
        fixtures = root / "fixtures"; fixtures.mkdir()
        host_common = {"schema_version":1,"status":"pass","architecture":"x86_64","vcpus":4,"memory_total_kib":8388608,"memory_available_kib":4194304,"root_total_kib":104857600,"root_free_kib":83886080,"inode_total":1000000,"inode_free":900000,"time_synchronized":True,"docker":"available","docker_containers":0,"listener_conflicts":0,"service_conflicts":0,"reasons":[]}
        self.write_json(fixtures / "host-preflight-pending.json", {**host_common,"mode":"early"})
        self.write_json(fixtures / "host-preflight.json", {**host_common,"mode":"post"})
        (fixtures / "listeners.txt").write_text("LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n", encoding="utf-8")
        (fixtures / "processes.txt").write_text("1 opencard open-card-server\n", encoding="utf-8")
        self.write_json(fixtures / "api.json", {"authenticated":True})
        (fixtures / "sse.ndjson").write_text('{"http_status":200,"content_type":"text/event-stream","request_last_event_id":"evt-1","first_event_id":"evt-2","event_count":1,"replayed":true,"body_sha256":"'+'2'*64+'"}\n', encoding="utf-8")
        self.write_json(fixtures / "app-route.json", {"http_status":200,"host":"app.example.test","body_sha256":"1"*64})
        for path in fixtures.iterdir(): path.chmod(0o600)
        self.write_state(fixtures / "state.json", "boot-a")
        return {"root":root,"identity_pre":identity_pre,"identity_post":identity_post,"install_id":install_id,"cookie":cookie,"fixtures":fixtures}

    def write_state(self, path: Path, boot_id: str, *, enabled: bool = True, marker_absent: bool = True, active: str = "activations/act-g6") -> None:
        units = {name:{"active":True,"enabled":enabled} for name in ("open-card-server.service","open-card-agent.service","open-card-buildkit.service","open-card-caddy.service","open-card-edge.service")}
        self.write_json(path, {"units":units,"upgrade_safe_target_active":True,"upgrade_safe_target_enabled":True,"active_pointer":active,"current_pointer":"active/release","previous_active_pointer":"","upgrade_marker_absent":marker_absent,"boot_id":boot_id})

    def run_phase(self, fixture: dict[str, Path | str], phase: str, confirmation: str, *, app: bool = True) -> subprocess.CompletedProcess[str]:
        identity = fixture["identity_pre"] if phase == "snapshot-preinstall" else fixture["identity_post"]
        command = [str(SCRIPT),"--phase",phase,"--identity",str(identity),"--confirm",confirmation,"--task-root",str(fixture["root"])]
        if phase != "snapshot-preinstall" and app:
            command += ["--app-host","app.example.test","--session-cookie-file",str(fixture["cookie"]),"--sse-last-event-id","evt-1"]
        return subprocess.run(command, cwd=ROOT, env={"PATH":os.environ["PATH"],"OPEN_CARD_G6_STAGING_TEST":"1"}, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def full_sequence(self, fixture: dict[str, Path | str]) -> None:
        phases = (
            ("snapshot-preinstall","G6-SNAPSHOT-READONLY"),
            ("install-verify","G6-INSTALL-VERIFY-READONLY"),
            ("restart-drill","G6:restart-services:installation-g6"),
            ("reboot-handoff","G6:reboot:installation-g6"),
        )
        for phase, confirmation in phases:
            result = self.run_phase(fixture, phase, confirmation)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["result"], "pass")
        self.write_state(fixture["fixtures"] / "state.json", "boot-b")
        result = self.run_phase(fixture, "reboot-verify", "G6-REBOOT-VERIFY-READONLY")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dynamic_five_phase_sequence_replay_and_restart_order(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".g6-collector-") as raw:
            fixture = self.setup_fixture(Path(raw))
            self.full_sequence(fixture)
            action_log = fixture["root"] / "restart-actions.log"
            expected = ["open-card-buildkit.service","open-card-server.service","open-card-agent.service","open-card-caddy.service","open-card-edge.service"]
            self.assertEqual(action_log.read_text(encoding="utf-8").splitlines(), expected)
            self.assertFalse((fixture["root"] / "var/lib/open-card/evidence/gate6/g6-collector-1/.restart-drill.in-progress").exists())
            replay = self.run_phase(fixture, "restart-drill", "G6:restart-services:installation-g6")
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(action_log.read_text(encoding="utf-8").splitlines(), expected)
            evidence = fixture["root"] / "var/lib/open-card/evidence/gate6/g6-collector-1"
            for phase in ("snapshot-preinstall","install-verify","restart-drill","reboot-handoff","reboot-verify"):
                receipt = json.loads((evidence/phase/"receipt.json").read_text(encoding="utf-8"))
                encoded = json.dumps(receipt, sort_keys=True)
                self.assertNotIn("installation-g6", encoded)
                self.assertNotIn("test-cookie", encoded)

    def test_v2_alibaba_identity_runs_through_local_collector(self) -> None:
        target = {"provider":"aliyun","product":"ecs","account_id":"<account-id>","region":"cn-shanghai","instance_id":"i-REDACTED","public_ipv4":"<server-ip>","private_ipv4":"172.20.81.108"}
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".g6-collector-") as raw:
            fixture = self.setup_fixture(Path(raw))
            for identity in (fixture["identity_pre"], fixture["identity_post"]):
                value = json.loads(Path(identity).read_text(encoding="utf-8")); value["target"] = target; self.write_json(Path(identity), value)
            self.full_sequence(fixture)
            receipt = json.loads((fixture["root"] / "var/lib/open-card/evidence/gate6/g6-collector-1/reboot-verify/receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], "open-card-g6-receipt.v2")
            self.assertEqual(receipt["target"], target)

    def test_confirmation_state_cookie_and_order_fail_closed(self) -> None:
        for mutation in ("missing-predecessor","wrong-confirmation","cookie-mode","cookie-symlink","disabled-unit","marker","pointer","post-host-status","post-host-mode","post-host-capacity","sse-no-event","same-boot"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=ROOT,prefix=".g6-collector-") as raw:
                fixture = self.setup_fixture(Path(raw))
                if mutation == "missing-predecessor":
                    result = self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY")
                else:
                    self.assertEqual(self.run_phase(fixture,"snapshot-preinstall","G6-SNAPSHOT-READONLY").returncode,0)
                    if mutation == "wrong-confirmation": result=self.run_phase(fixture,"install-verify","wrong")
                    elif mutation == "cookie-mode": fixture["cookie"].chmod(0o644); result=self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY")
                    elif mutation == "cookie-symlink":
                        fixture["cookie"].unlink(); target=fixture["root"]/"cookie-target"; target.write_text("cookie"); fixture["cookie"].symlink_to(target); result=self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY")
                    elif mutation in {"disabled-unit","marker","pointer"}:
                        self.write_state(fixture["fixtures"]/"state.json","boot-a",enabled=mutation!="disabled-unit",marker_absent=mutation!="marker",active="/absolute" if mutation=="pointer" else "activations/act-g6")
                        result=self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY")
                    elif mutation.startswith("post-host-"):
                        host=json.loads((fixture["fixtures"]/"host-preflight.json").read_text(encoding="utf-8"))
                        if mutation=="post-host-status": host["status"]="fail"
                        elif mutation=="post-host-mode": host["mode"]="early"
                        else: host["root_free_kib"]=1
                        self.write_json(fixture["fixtures"]/"host-preflight.json",host)
                        result=self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY")
                    elif mutation=="sse-no-event":
                        sse=json.loads((fixture["fixtures"]/"sse.ndjson").read_text(encoding="utf-8")); sse["event_count"]=0; sse["replayed"]=False
                        (fixture["fixtures"]/"sse.ndjson").write_text(json.dumps(sse)+"\n",encoding="utf-8"); (fixture["fixtures"]/"sse.ndjson").chmod(0o600)
                        result=self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY")
                    else:
                        for phase,confirm in (("install-verify","G6-INSTALL-VERIFY-READONLY"),("restart-drill","G6:restart-services:installation-g6"),("reboot-handoff","G6:reboot:installation-g6")):
                            self.assertEqual(self.run_phase(fixture,phase,confirm).returncode,0)
                        result=self.run_phase(fixture,"reboot-verify","G6-REBOOT-VERIFY-READONLY")
                self.assertNotEqual(result.returncode,0,result.stdout)
                self.assertIn("invalid_gate6_evidence",result.stderr)

        for mutation in ("early-host-fail","existing-installation"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=ROOT,prefix=".g6-collector-") as raw:
                fixture=self.setup_fixture(Path(raw))
                if mutation=="early-host-fail":
                    host=json.loads((fixture["fixtures"]/"host-preflight-pending.json").read_text(encoding="utf-8")); host["docker_containers"]=1; self.write_json(fixture["fixtures"]/"host-preflight-pending.json",host)
                else:
                    (fixture["fixtures"]/"existing-installation").write_text("present",encoding="utf-8")
                result=self.run_phase(fixture,"snapshot-preinstall","G6-SNAPSHOT-READONLY")
                self.assertNotEqual(result.returncode,0)

        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".g6-collector-") as raw:
            fixture=self.setup_fixture(Path(raw))
            self.assertEqual(self.run_phase(fixture,"snapshot-preinstall","G6-SNAPSHOT-READONLY").returncode,0)
            self.assertEqual(self.run_phase(fixture,"install-verify","G6-INSTALL-VERIFY-READONLY").returncode,0)
            marker=fixture["root"] / "var/lib/open-card/evidence/gate6/g6-collector-1/.restart-drill.in-progress"
            marker.write_text('{"confirmation_sha256":"foreign","run_id":"g6-collector-1"}\n',encoding="utf-8"); marker.chmod(0o600)
            result=self.run_phase(fixture,"restart-drill","G6:restart-services:installation-g6")
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((fixture["root"] / "restart-actions.log").exists())

    def test_contract_and_runbook_forbid_external_acceptance_substitution(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("tccli", "DescribeInstances", "CreateFirewallRules", "dig ", "playwright", "g6-final-manifest"):
            self.assertNotIn(forbidden, source)
        runbook = (ROOT/"docs/runbooks/gate6-staging.md").read_text(encoding="utf-8")
        self.assertIn("RUNBOOK_CONTRACT_ONLY",runbook); self.assertIn("NOT_RUN",runbook); self.assertIn("predates Gate 6",runbook)
        self.assertIn("signed",runbook.lower()); self.assertIn("DRAFT_UNEXECUTABLE",runbook)


if __name__ == "__main__":
    unittest.main()
