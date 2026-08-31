#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/evidence"))
import g6_import_external as imp  # noqa: E402
import g6_validate as g6  # noqa: E402


def digest(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()


class Gate6EvidenceTest(unittest.TestCase):
    def temporary(self): return tempfile.TemporaryDirectory(dir=ROOT, prefix=".g6-test-")
    def source(self): return {"tag": "v0.8.0-rc.1", "commit": "a" * 40, "bundle_manifest_sha256": "b" * 64}
    def target(self): return {"provider": "tencent", "product": "cvm", "instance_id": "ins-g6-evidence", "public_ipv4": "8.8.8.8"}
    def aliyun_target(self): return {"provider": "ALIYUN", "product": "ECS", "account_id": "<account-id>", "region": "cn-shanghai", "instance_id": "i-REDACTED", "public_ipv4": "<server-ip>", "private_ipv4": "172.20.81.108"}

    def post(self, sequence, source, *, restart=False, boot=None):
        values = {"sequence": sequence, "units": {unit: {"active": True, "enabled": True} for unit in g6.UNITS}, "upgrade_safe_target_active": True, "active_pointer": "activations/activation-g6", "current_pointer": "active/release", "previous_active_pointer": "", "upgrade_marker_absent": True,
                  "host_preflight_sha256": "1" * 64, "listeners_sha256": "2" * 64, "processes_sha256": "3" * 64, "api_sha256": "4" * 64, "sse_sha256": "5" * 64, "app_route_sha256": "6" * 64, "upgrade_safe_target_enabled": True}
        if restart: values |= {"action": "restart_services", "confirmation_sha256": "7" * 64}
        if boot: values |= {"boot_id": boot, "confirmation_sha256": "7" * 64, "source_tag": source["tag"], "source_commit": source["commit"], "bundle_manifest_sha256": source["bundle_manifest_sha256"]}
        return values

    def receipt(self, phase, root, *, method=None, installation="c" * 64, target=None):
        source = self.source(); root.mkdir(parents=True, exist_ok=True)
        if phase == "SNAPSHOT_PREINSTALL": facts = {"sequence": 1, "host_preflight_sha256": "1" * 64, "existing_installation": False, "colocated_workloads": False, "source_tag_verified": True, "bundle_manifest_verified": True}
        elif phase == "INSTALL_VERIFY": facts = self.post(2, source)
        elif phase == "RESTART_DRILL": facts = self.post(3, source, restart=True)
        elif phase == "REBOOT_HANDOFF": facts = self.post(4, source, boot="boot-a")
        elif phase == "REBOOT_VERIFY": facts = self.post(5, source, boot="boot-b")
        else: facts = {"sequence": g6.EXTERNAL[method], "method": method, "observer_id": "observer-g6", "environment": "outside_target", "signature_verified": True, "signer_identity_sha256": "7" * 64, "allowed_signers_sha256": "8" * 64, "statement_sha256": "9" * 64}
        suffixes = [".txt"]
        if method == "curl_resolve": suffixes = [".json", ".txt"]
        if method == "external_tcp": suffixes = [".ndjson"]
        if method == "browser": suffixes = [".json", ".png"]
        artifacts = []
        for index, suffix in enumerate(suffixes):
            path = root / "artifacts" / f"evidence-{index}{suffix}"; path.parent.mkdir(exist_ok=True); raw = f"{phase}:{index}".encode(); path.write_bytes(raw); os.chmod(path, 0o600); artifacts.append({"path": str(path.relative_to(root)), "sha256": digest(raw), "mode": 0o600})
        target = self.target() if target is None else target
        receipt = {"schema": g6.receipt_schema_for_target(g6.target(target)), "run_id": "g6-run-1", "phase": phase, "source": source, "target": target, "facts": facts, "artifacts": artifacts, "result": "pass"}
        if phase != "SNAPSHOT_PREINSTALL": receipt["installation_id_sha256"] = installation
        return receipt

    def test_strict_schema_phase_and_artifact_contract(self):
        self.assertEqual(g6.UNITS, ("open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service", "open-card-edge.service"))
        with self.assertRaises(g6.ValidationError): g6.strict_json_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(g6.ValidationError): g6.strict_json_bytes(b'{} trailing')
        with self.temporary() as tmp:
            root = Path(tmp); receipt = self.receipt("INSTALL_VERIFY", root)
            self.assertEqual(g6.validate_receipt(receipt, root)["phase"], "INSTALL_VERIFY")
            cases = []
            bad = json.loads(json.dumps(receipt)); bad["facts"].pop("api_sha256"); cases.append(bad)
            bad = json.loads(json.dumps(receipt)); bad["facts"]["units"].pop("open-card-edge.service"); cases.append(bad)
            bad = json.loads(json.dumps(receipt)); bad["facts"]["authorization"] = "x"; cases.append(bad)
            bad = json.loads(json.dumps(receipt)); bad["artifacts"][0]["path"] = "/Users/a/path"; cases.append(bad)
            bad = self.receipt("SNAPSHOT_PREINSTALL", root / "pre"); bad["installation_id_sha256"] = "c" * 64; cases.append(bad)
            for value in cases:
                with self.assertRaises(g6.ValidationError): g6.validate_receipt(value, root)
            external = self.receipt("EXTERNAL_IMPORT", root / "external", method="curl_resolve")
            extra = root / "external/artifacts/extra.bin"
            extra.write_bytes(b"extra"); os.chmod(extra, 0o600)
            external["artifacts"].append({"path": "artifacts/extra.bin", "sha256": digest(b"extra"), "mode": 0o600})
            with self.assertRaises(g6.ValidationError):
                g6.validate_receipt(external, root / "external")
            bad_subject = self.receipt("EXTERNAL_IMPORT", root / "bad-subject", method="external_tcp")
            bad_subject["facts"]["subject"] = ".."
            with self.assertRaises(g6.ValidationError):
                g6.validate_receipt(bad_subject, root / "bad-subject")
        fixture = ROOT / "tests/fixtures/gate6_evidence/receipt-v1-example.json"
        self.assertEqual(g6.validate_receipt(json.loads(fixture.read_text()), fixture.parent)["phase"], "SNAPSHOT_PREINSTALL")

    def test_artifact_filesystem_policy(self):
        with self.temporary() as tmp:
            root = Path(tmp)
            for action in ("mode", "hardlink", "symlink", "drift"):
                with self.subTest(action=action):
                    child = root / action; receipt = self.receipt("INSTALL_VERIFY", child); path = child / receipt["artifacts"][0]["path"]
                    if action == "mode": os.chmod(path, 0o666)
                    elif action == "hardlink": os.link(path, child / "duplicate")
                    elif action == "symlink": path.unlink(); (child / "target").write_bytes(b"x"); path.symlink_to(child / "target")
                    else: path.write_bytes(b"changed")
                    with self.assertRaises(g6.ValidationError): g6.validate_receipt(receipt, child)

    def test_ancestor_symlink_and_owner_are_rejected(self):
        with self.temporary() as tmp:
            root = Path(tmp); real = root / "real"; receipt = self.receipt("INSTALL_VERIFY", real)
            link = root / "link"; link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(g6.ValidationError): g6.validate_receipt(receipt, link)
            artifact = real / receipt["artifacts"][0]["path"]
            with self.assertRaises(g6.ValidationError): g6.secure_file(artifact, owner=os.getuid() + 1, modes={0o600})

    def entries(self, root, *, target=None):
        values = []
        for phase in ("SNAPSHOT_PREINSTALL", "INSTALL_VERIFY", "RESTART_DRILL", "REBOOT_HANDOFF", "REBOOT_VERIFY"):
            child = root / phase; values.append((self.receipt(phase, child, target=target), child))
        for method in ("curl_resolve", "external_tcp", "browser"):
            child = root / method; values.append((self.receipt("EXTERNAL_IMPORT", child, method=method, target=target), child))
        return values

    def signed_entries(self, root, *, target=None):
        values = self.entries(root, target=target)[:5]
        key = allowed = None
        for method in ("curl_resolve", "external_tcp", "browser"):
            metadata, sources, generated_allowed, signature, key = self.signed_import(root / ("signed-" + method), method, key=key, allowed=allowed, target=target)
            allowed = generated_allowed
            imported_root = root / ("signed-" + method) / "import"
            values.append((imp.import_external(metadata, sources, imported_root, allowed, signature), imported_root))
        return values, allowed

    def test_final_order_boot_methods_and_no_replace(self):
        with self.temporary() as tmp:
            root = Path(tmp); entries, allowed = self.signed_entries(root)
            first = root / "a" / "g6-final-manifest.json"; second = root / "b" / "g6-final-manifest.json"
            (root / "a").mkdir(); (root / "b").mkdir()
            self.assertFalse(g6.finalize(entries, first, allowed, owner=os.getuid())["production_accepted"])
            g6.finalize(entries, second, allowed, owner=os.getuid()); self.assertEqual(first.read_bytes(), second.read_bytes())
            with self.assertRaises(g6.ValidationError): g6.finalize(entries, first, allowed, owner=os.getuid())
            forged = json.loads(json.dumps(entries[5][0])); forged["facts"]["signature_verified"] = True; forged["facts"]["statement_sha256"] = "0" * 64
            with self.assertRaises(g6.ValidationError): g6.finalize(entries[:5] + [(forged, entries[5][1])] + entries[6:], root / "forged" / "final.json", allowed, owner=os.getuid())
            statement = entries[5][1] / "trust/statement.json"; original = statement.read_bytes(); statement.write_bytes(b"modified")
            with self.assertRaises(g6.ValidationError): g6.finalize(entries, root / "modified-statement" / "final.json", allowed, owner=os.getuid())
            statement.write_bytes(original)
            signature = entries[5][1] / "trust/observer.sig"; original_signature = signature.read_bytes(); signature.write_bytes(b"modified")
            with self.assertRaises(g6.ValidationError): g6.finalize(entries, root / "modified-signature" / "final.json", allowed, owner=os.getuid())
            signature.write_bytes(original_signature)
            missing = subprocess.run([sys.executable, str(ROOT / "tools/evidence/g6_validate.py"), "finalize", "--receipt", str(entries[0][1] / "receipt.json"), "--output", str(root / "missing" / "final.json")], text=True, capture_output=True, check=False)
            self.assertNotEqual(missing.returncode, 0)
            for mutate in (lambda e: e.__setitem__(3, e[2]), lambda e: e[4][0]["facts"].__setitem__("boot_id", "boot-a"), lambda e: e[7][0]["facts"].__setitem__("method", "external_tcp"), lambda e: e[1][0].__setitem__("installation_id_sha256", "d" * 64)):
                broken = self.entries(root / f"broken-{len(os.listdir(root))}"); mutate(broken)
                out = root / f"out-{len(os.listdir(root))}"; out.mkdir()
                with self.assertRaises(g6.ValidationError): g6.finalize(broken, out / "final.json", allowed, owner=os.getuid())

    def test_v2_alibaba_target_full_signed_finalization(self):
        with self.temporary() as tmp:
            root = Path(tmp); target = self.aliyun_target(); entries, allowed = self.signed_entries(root, target=target)
            out = root / "final"; out.mkdir()
            manifest = g6.finalize(entries, out / "g6-final-manifest.json", allowed, owner=os.getuid())
            normalized = {**target, "provider": "aliyun", "product": "ecs"}
            self.assertEqual(manifest["schema"], g6.FINAL_SCHEMA_V2)
            self.assertEqual(manifest["target"], normalized)
            self.assertTrue(all(value[0]["schema"] == g6.SCHEMA_V2 for value in entries))

    def test_target_v2_rejects_cross_provider_and_unsafe_addresses(self):
        cases = []
        valid = self.aliyun_target()
        for key, value in (("product", "cvm"), ("instance_id", "ins-g6"), ("private_ipv4", "127.0.0.1"), ("private_ipv4", "169.254.1.1"), ("private_ipv4", "100.64.0.1"), ("public_ipv4", "172.20.81.108"), ("account_id", "account"), ("region", "CN_SHANGHAI")):
            broken = dict(valid); broken[key] = value; cases.append(broken)
        for key in valid:
            broken = dict(valid); broken.pop(key); cases.append(broken)
            broken = dict(valid); broken[key] = None; cases.append(broken)
        cases.append({**valid, "unexpected": "field"})
        cases.append({**valid, "provider": "tencent", "product": "cvm", "instance_id": "i-REDACTED"})
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(g6.ValidationError): g6.target(value)

    def signed_import(self, root, method="external_tcp", *, key=None, allowed=None, target=None):
        root.mkdir()
        if key is None:
            key = root / "key"; subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pub = key.with_suffix(".pub").read_text().strip(); allowed = root / "allowed"; allowed.write_text("observer-g6 " + pub + "\n"); os.chmod(allowed, 0o600)
        suffixes = [".ndjson"] if method == "external_tcp" else [".json", ".txt"] if method == "curl_resolve" else [".json", ".png"]
        source_files = []
        for suffix in suffixes:
            path = root / ("outside" + suffix); path.write_bytes(b"outside"); os.chmod(path, 0o600); source_files.append(path)
        meta = {"run_id": "g6-run-1", "source": self.source(), "target": self.target() if target is None else target, "observer_id": "observer-g6", "environment": "outside_target", "method": method, "installation_id_sha256": "c" * 64, "observed_at": "2026-08-31T00:00:00Z", "subject": "console.example.test"}
        metadata = root / "metadata.json"; metadata.write_text(json.dumps(meta)); os.chmod(metadata, 0o600)
        parsed = imp.metadata(meta); artifacts = [{k: v for k, v in item.items() if k != "raw"} for item in imp.source_artifacts(source_files, owner=os.getuid())]
        draft = {"schema": g6.receipt_schema_for_target(parsed["target"]), "run_id": parsed["run_id"], "phase": "EXTERNAL_IMPORT", "source": parsed["source"], "target": parsed["target"], "installation_id_sha256": parsed["installation_id_sha256"], "facts": {"sequence": g6.EXTERNAL[method], "method": method, "observer_id": "observer-g6", "environment": "outside_target", "observed_at": parsed["observed_at"], "subject": parsed["subject"], "signature_verified": True, "signer_identity_sha256": "0" * 64, "allowed_signers_sha256": "0" * 64, "statement_sha256": "0" * 64, "statement_artifact_path": "trust/statement.json", "signature_artifact_path": "trust/observer.sig"}, "artifacts": artifacts + [{"path":"trust/statement.json","sha256":"0"*64,"mode":0o600},{"path":"trust/observer.sig","sha256":"0"*64,"mode":0o600}], "result":"pass"}
        statement = g6.external_statement(draft, artifacts); statement_path = root / "statement"; statement_path.write_bytes(statement); os.chmod(statement_path, 0o600)
        subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", g6.SIGN_NAMESPACE, str(statement_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        signature = statement_path.with_suffix(".sig"); os.chmod(signature, 0o600)
        return metadata, source_files, allowed, signature, key

    def test_signed_external_import_and_tamper_rejection(self):
        with self.temporary() as tmp:
            root = Path(tmp)
            for method in g6.EXTERNAL:
                child = root / method; metadata, sources, allowed, signature, _ = self.signed_import(child, method)
                receipt = imp.import_external(metadata, sources, child / "import", allowed, signature)
                self.assertTrue(receipt["facts"]["signature_verified"])
            metadata, sources, allowed, signature, _ = self.signed_import(root / "bad")
            sources[0].write_bytes(b"tampered")
            with self.assertRaises(g6.ValidationError): imp.import_external(metadata, sources, root / "bad" / "out", allowed, signature)
            metadata, sources, allowed, signature, _ = self.signed_import(root / "wrong-signer")
            allowed.write_text("other-observer " + (root / "wrong-signer" / "key.pub").read_text().strip() + "\n"); os.chmod(allowed, 0o600)
            with self.assertRaises(g6.ValidationError): imp.import_external(metadata, sources, root / "wrong-signer" / "out", allowed, signature)
            meta = json.loads(metadata.read_text()); meta["observer_id"] = "ins-g6-evidence"; metadata.write_text(json.dumps(meta)); os.chmod(metadata, 0o600)
            with self.assertRaises(g6.ValidationError): imp.import_external(metadata, sources, root / "bad" / "same", allowed, signature)

    def test_signature_verification_uses_validated_descriptor_snapshots(self):
        with self.temporary() as tmp:
            root = Path(tmp); child = root / "signed"
            metadata, sources, allowed, signature, _ = self.signed_import(child, "external_tcp")
            receipt = imp.import_external(metadata, sources, child / "import", allowed, signature)
            allowed_original = allowed.read_bytes(); signature_path = child / "import/trust/observer.sig"; signature_original = signature_path.read_bytes()
            real_run = g6.subprocess.run
            def replace_original_paths(command, *args, **kwargs):
                self.assertIn("/dev/fd/", " ".join(command))
                allowed.write_bytes(b"replaced allowed signers\n"); os.chmod(allowed, 0o600)
                signature_path.write_bytes(b"replaced signature\n"); os.chmod(signature_path, 0o600)
                try:
                    return real_run(command, *args, **kwargs)
                finally:
                    allowed.write_bytes(allowed_original); os.chmod(allowed, 0o600)
                    signature_path.write_bytes(signature_original); os.chmod(signature_path, 0o600)
            g6.subprocess.run = replace_original_paths
            try:
                g6.verify_external_receipt(receipt, child / "import", allowed_original, owner=os.getuid())
            finally:
                g6.subprocess.run = real_run

    def test_finalizer_pins_one_allowed_signers_snapshot_across_receipts(self):
        with self.temporary() as tmp:
            root = Path(tmp); entries, allowed = self.signed_entries(root)
            original_allowed = allowed.read_bytes(); real_run = g6.subprocess.run; calls = 0
            def mutate_trust_after_first_snapshot(command, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    allowed.write_bytes(b"replacement trust policy\n"); os.chmod(allowed, 0o600)
                return real_run(command, *args, **kwargs)
            g6.subprocess.run = mutate_trust_after_first_snapshot
            try:
                out = root / "final"; out.mkdir()
                manifest = g6.finalize(entries, out / "g6-final-manifest.json", allowed, owner=os.getuid())
            finally:
                g6.subprocess.run = real_run
            self.assertEqual(calls, 3)
            self.assertEqual(manifest["allowed_signers_sha256"], digest(original_allowed))
            self.assertNotEqual(allowed.read_bytes(), original_allowed)

    def test_interrupted_import_retains_incomplete_directory_and_cli_redacts(self):
        with self.temporary() as tmp:
            root = Path(tmp); metadata, sources, allowed, signature, _ = self.signed_import(root / "interrupted")
            output = root / "interrupted" / "out"; original = g6.atomic_no_replace
            def interrupted(path, raw, mode=0o600, **kwargs):
                if path.parent.name == "artifacts": raise g6.ValidationError("invalid_gate6_evidence")
                return original(path, raw, mode, **kwargs)
            g6.atomic_no_replace = interrupted
            try:
                with self.assertRaises(g6.ValidationError): imp.import_external(metadata, sources, output, allowed, signature)
            finally:
                g6.atomic_no_replace = original
            self.assertTrue(output.is_dir()); self.assertFalse((output / "receipt.json").exists())
            bad = root / "bad.json"; bad.write_text('{"token":"super-secret"}'); os.chmod(bad, 0o600)
            result = subprocess.run([sys.executable, str(ROOT / "tools/evidence/g6_validate.py"), "validate", "--receipt", str(bad)], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2); self.assertEqual(result.stdout.strip(), "invalid_gate6_evidence")
            self.assertNotIn("secret", result.stdout + result.stderr)


if __name__ == "__main__": unittest.main()
