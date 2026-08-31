#!/usr/bin/env python3
"""Strict, local-only validation and finalization for Gate 6 receipts."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

SCHEMA = "open-card-g6-receipt.v1"
SCHEMA_V2 = "open-card-g6-receipt.v2"
FINAL_SCHEMA = "open-card-g6-final-manifest.v1"
FINAL_SCHEMA_V2 = "open-card-g6-final-manifest.v2"
PHASES = ("SNAPSHOT_PREINSTALL", "INSTALL_VERIFY", "RESTART_DRILL", "REBOOT_HANDOFF", "REBOOT_VERIFY", "EXTERNAL_IMPORT")
EXTERNAL = {"curl_resolve": 6, "external_tcp": 7, "browser": 8}
UNITS = ("open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service", "open-card-edge.service")
SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
SIGN_NAMESPACE = "open-card-g6"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
ACCOUNT_ID = re.compile(r"^[0-9]{6,20}$")
REGION = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ALIYUN_INSTANCE = re.compile(r"^i-[a-z0-9]{8,63}$")
SENSITIVE = re.compile(r"(?:api[_-]?key|authorization|password|dsn|cookie|token|private.?key|key.?material|credential|secret|confirmation|(?:^|[_-])installation_id(?:$|[_-])(?!sha256))", re.I)
FORBIDDEN_VALUE = re.compile(r"(?:https?://|postgres(?:ql)?://|[A-Za-z]:[\\/]|/(?:Users|home|var|etc|opt|tmp)/)", re.I)
ALLOWED_MODES = {0o600, 0o640, 0o644}


class ValidationError(ValueError):
    pass


def fail() -> None:
    raise ValidationError("invalid_gate6_evidence")


def strict_json_bytes(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
        def pairs(entries: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in entries:
                if key in result:
                    fail()
                result[key] = value
            return result
        decoder = json.JSONDecoder(object_pairs_hook=pairs)
        value, end = decoder.raw_decode(text)
        if text[end:].strip():
            fail()
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        fail()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_id(value: Any) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value) or SENSITIVE.search(value):
        fail()
    return value


def safe_sha(value: Any) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail()
    return value


def safe_relative(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or FORBIDDEN_VALUE.search(value) or SENSITIVE.search(value):
        fail()
    path = Path(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        fail()
    return value


def exact(value: Any, required: set[str], optional: set[str] = set()) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - required - optional or required - set(value):
        fail()
    if any(value[name] is None for name in required):
        fail()
    return value


def safe_root(path: Path, *, owner: int | None = None) -> Path:
    if not path.is_absolute():
        fail()
    parts = path.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError:
            break
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
            fail()
    try:
        info = path.lstat()
    except OSError:
        fail()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022 or owner is not None and info.st_uid != owner:
        fail()
    return path


def secure_file(path: Path, *, owner: int | None = None, modes: set[int] | None = None) -> tuple[bytes, os.stat_result]:
    if not path.is_absolute():
        fail()
    safe_root(path.parent, owner=owner)
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or owner is not None and before.st_uid != owner or modes is not None and stat.S_IMODE(before.st_mode) not in modes:
            fail()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or owner is not None and opened.st_uid != owner or modes is not None and stat.S_IMODE(opened.st_mode) not in modes:
                fail()
            chunks: list[bytes] = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        after = path.lstat()
        if after.st_ino != before.st_ino or after.st_dev != before.st_dev or after.st_nlink != 1:
            fail()
        return raw, after
    except OSError:
        fail()


def strict_json_path(path: Path, *, owner: int | None = None) -> Any:
    raw, _ = secure_file(path, owner=owner, modes=ALLOWED_MODES)
    return strict_json_bytes(raw)


def source(value: Any) -> dict[str, str]:
    value = exact(value, {"tag", "commit", "bundle_manifest_sha256"})
    if not isinstance(value["tag"], str) or not SAFE_ID.fullmatch(value["tag"]) or not isinstance(value["commit"], str) or not HEX40.fullmatch(value["commit"]):
        fail()
    return {"tag": value["tag"], "commit": value["commit"], "bundle_manifest_sha256": safe_sha(value["bundle_manifest_sha256"])}


def public_ipv4(value: Any) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        fail()
    if not address.is_global or address.is_loopback:
        fail()
    return str(address)


def private_ipv4(value: Any) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        fail()
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(address in network for network in private_ranges):
        fail()
    return str(address)


def target(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        fail()
    v1_fields = {"provider", "product", "instance_id", "public_ipv4"}
    v2_fields = {"provider", "product", "account_id", "region", "instance_id", "public_ipv4", "private_ipv4"}
    fields = set(value)
    if fields == v1_fields:
        provider, product, instance = value["provider"], value["product"], value["instance_id"]
        if provider != "tencent" or product not in {"cvm", "lighthouse"} or not isinstance(instance, str):
            fail()
        prefix = "ins-" if product == "cvm" else "lhins-"
        if not instance.startswith(prefix) or not SAFE_ID.fullmatch(instance):
            fail()
        return {"provider": "tencent", "product": product, "instance_id": instance, "public_ipv4": public_ipv4(value["public_ipv4"])}
    if fields != v2_fields or any(value[name] is None for name in v2_fields):
        fail()
    provider, product, instance = value["provider"], value["product"], value["instance_id"]
    if not isinstance(provider, str) or not isinstance(product, str) or not isinstance(instance, str):
        fail()
    provider, product = provider.lower(), product.lower()
    if provider == "tencent" and product in {"cvm", "lighthouse"}:
        prefix = "ins-" if product == "cvm" else "lhins-"
        if not instance.startswith(prefix) or not SAFE_ID.fullmatch(instance):
            fail()
    elif provider == "aliyun" and product == "ecs":
        if not ALIYUN_INSTANCE.fullmatch(instance):
            fail()
    else:
        fail()
    account_id, region = value["account_id"], value["region"]
    if not isinstance(account_id, str) or not ACCOUNT_ID.fullmatch(account_id) or not isinstance(region, str) or not REGION.fullmatch(region):
        fail()
    return {"provider": provider, "product": product, "account_id": account_id, "region": region, "instance_id": instance, "public_ipv4": public_ipv4(value["public_ipv4"]), "private_ipv4": private_ipv4(value["private_ipv4"])}


def receipt_schema_for_target(value: dict[str, str]) -> str:
    return SCHEMA_V2 if "account_id" in value else SCHEMA


def final_schema_for_receipt(schema: str) -> str:
    if schema == SCHEMA:
        return FINAL_SCHEMA
    if schema == SCHEMA_V2:
        return FINAL_SCHEMA_V2
    fail()


def artifact_list(value: Any, root: Path | None = None, *, owner: int | None = None) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        fail()
    seen: set[str] = set(); result: list[dict[str, Any]] = []
    for item in value:
        item = exact(item, {"path", "sha256", "mode"})
        path = safe_relative(item["path"])
        mode = item["mode"]
        if path in seen or not isinstance(mode, int) or mode not in ALLOWED_MODES:
            fail()
        seen.add(path)
        artifact = {"path": path, "sha256": safe_sha(item["sha256"]), "mode": mode}
        if root is not None:
            raw, _ = secure_file(root.joinpath(*Path(path).parts), owner=owner, modes={mode})
            if sha(raw) != artifact["sha256"]:
                fail()
        result.append(artifact)
    return result


def unit_map(value: Any) -> dict[str, dict[str, bool]]:
    value = exact(value, set(UNITS))
    for unit in UNITS:
        if value[unit] != {"active": True, "enabled": True}:
            fail()
    return value


POST_SHAS = {"host_preflight_sha256", "listeners_sha256", "processes_sha256", "api_sha256", "sse_sha256", "app_route_sha256"}
POST_BASE = {"sequence", "units", "upgrade_safe_target_active", "upgrade_safe_target_enabled", "active_pointer", "current_pointer", "previous_active_pointer", "upgrade_marker_absent", *POST_SHAS}


def safe_pointer(value: Any, *, current: bool = False) -> str:
    if not isinstance(value, str):
        fail()
    if current:
        if value != "active/release": fail()
    elif value and (not value.startswith("activations/") or not SAFE_ID.fullmatch(value.split("/", 1)[1]) or value != f"activations/{value.split('/', 1)[1]}"):
        fail()
    return value


def observation_subject(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 253:
        fail()
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            fail()
        return str(address)
    except ValueError:
        labels = value.split(".")
        if len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
            fail()
        return value.lower()


def post_facts(value: Any, sequence: int, *, restart: bool = False, reboot: bool = False, receipt_source: dict[str, str] | None = None) -> dict[str, Any]:
    required = set(POST_BASE)
    if restart: required |= {"action", "confirmation_sha256"}
    if reboot: required |= {"boot_id", "confirmation_sha256", "source_tag", "source_commit", "bundle_manifest_sha256"}
    value = exact(value, required)
    if value["sequence"] != sequence or value["upgrade_safe_target_active"] is not True or value["upgrade_safe_target_enabled"] is not True or value["upgrade_marker_absent"] is not True:
        fail()
    unit_map(value["units"])
    active = safe_pointer(value["active_pointer"])
    if not active: fail()
    safe_pointer(value["current_pointer"], current=True); safe_pointer(value["previous_active_pointer"])
    for key in POST_SHAS:
        safe_sha(value[key])
    if restart and (value["action"] != "restart_services" or not safe_sha(value["confirmation_sha256"])):
        fail()
    if reboot:
        if not safe_id(value["boot_id"]) or not safe_sha(value["confirmation_sha256"]) or receipt_source is None or value["source_tag"] != receipt_source["tag"] or value["source_commit"] != receipt_source["commit"] or value["bundle_manifest_sha256"] != receipt_source["bundle_manifest_sha256"]:
            fail()
    return value


def phase_facts(phase: str, value: Any, receipt_source: dict[str, str]) -> dict[str, Any]:
    if phase == "SNAPSHOT_PREINSTALL":
        value = exact(value, {"sequence", "host_preflight_sha256", "existing_installation", "colocated_workloads", "source_tag_verified", "bundle_manifest_verified"})
        if value["sequence"] != 1 or value["existing_installation"] is not False or value["colocated_workloads"] is not False or value["source_tag_verified"] is not True or value["bundle_manifest_verified"] is not True:
            fail()
        safe_sha(value["host_preflight_sha256"]); return value
    if phase == "INSTALL_VERIFY": return post_facts(value, 2)
    if phase == "RESTART_DRILL": return post_facts(value, 3, restart=True)
    if phase == "REBOOT_HANDOFF": return post_facts(value, 4, reboot=True, receipt_source=receipt_source)
    if phase == "REBOOT_VERIFY": return post_facts(value, 5, reboot=True, receipt_source=receipt_source)
    value = exact(value, {"sequence", "method", "observer_id", "environment", "observed_at", "subject", "signature_verified", "signer_identity_sha256", "allowed_signers_sha256", "statement_sha256", "statement_artifact_path", "signature_artifact_path"})
    if value["method"] not in EXTERNAL or value["sequence"] != EXTERNAL[value["method"]] or not safe_id(value["observer_id"]) or value["environment"] != "outside_target" or value["signature_verified"] is not True:
        fail()
    try:
        observed = datetime.strptime(value["observed_at"], "%Y-%m-%dT%H:%M:%SZ")
        if observed.tzinfo is not None: fail()
    except (TypeError, ValueError): fail()
    observation_subject(value["subject"])
    if value["statement_artifact_path"] != "trust/statement.json" or value["signature_artifact_path"] != "trust/observer.sig": fail()
    for key in ("signer_identity_sha256", "allowed_signers_sha256", "statement_sha256"): safe_sha(value[key])
    return value


def external_artifacts(method: str, artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trust = {entry["path"]: entry for entry in artifacts if entry["path"].startswith("trust/")}
    if set(trust) != {"trust/statement.json", "trust/observer.sig"} or any(entry["mode"] != 0o600 for entry in trust.values()): fail()
    observation = [entry for entry in artifacts if entry["path"].startswith("artifacts/")]
    if len(observation) + 2 != len(artifacts): fail()
    paths = {entry["path"] for entry in observation}
    suffixes = {Path(path).suffix for path in paths}
    if method == "curl_resolve" and suffixes != {".json", ".txt"}: fail()
    if method == "external_tcp" and suffixes != {".ndjson"}: fail()
    if method == "browser" and suffixes not in ({".json", ".png"}, {".json", ".zip"}): fail()
    return observation


def validate_receipt(value: Any, artifact_root: Path | None = None, *, owner: int | None = None) -> dict[str, Any]:
    receipt = exact(value, {"schema", "run_id", "phase", "source", "target", "facts", "artifacts", "result"}, {"installation_id_sha256"})
    if receipt["schema"] not in {SCHEMA, SCHEMA_V2} or receipt["phase"] not in PHASES or receipt["result"] not in {"pass", "fail"}:
        fail()
    s = source(receipt["source"]); phase = receipt["phase"]
    normalized_target = target(receipt["target"])
    if receipt["schema"] != receipt_schema_for_target(normalized_target):
        fail()
    if not isinstance(receipt["facts"], dict): fail()
    facts = phase_facts(phase, receipt["facts"], s)
    if phase == "SNAPSHOT_PREINSTALL":
        if "installation_id_sha256" in receipt: fail()
    elif "installation_id_sha256" not in receipt:
        fail()
    installation = safe_sha(receipt["installation_id_sha256"]) if "installation_id_sha256" in receipt else None
    artifacts = artifact_list(receipt["artifacts"], artifact_root, owner=owner)
    if phase == "EXTERNAL_IMPORT": external_artifacts(facts["method"], artifacts)
    return {"schema": receipt["schema"], "run_id": safe_id(receipt["run_id"]), "phase": phase, "source": s, "target": normalized_target, **({"installation_id_sha256": installation} if installation else {}), "facts": facts, "artifacts": artifacts, "result": receipt["result"]}


def receipt_from_path(path: Path, *, owner: int | None = None) -> dict[str, Any]:
    return validate_receipt(strict_json_path(path, owner=owner), path.parent, owner=owner)


def atomic_no_replace(path: Path, raw: bytes, mode: int = 0o600, *, owner: int | None = None) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink(): fail()
    safe_root(path.parent, owner=owner)
    fd, temporary = tempfile.mkstemp(prefix=".g6-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        info = os.lstat(temporary)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode: fail()
        try: os.link(temporary, path)
        except FileExistsError: fail()
        final = os.lstat(path)
        if final.st_nlink != 2: fail()
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(directory); os.close(directory)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
    if os.lstat(path).st_nlink != 1: fail()


def safe_system_ssh_keygen() -> None:
    raw, _ = secure_file(SSH_KEYGEN, owner=0, modes={0o755})
    if not raw: fail()

def signer_identity_digest(allowed: bytes, observer: str) -> str:
    matches = [line for line in allowed.splitlines() if line.startswith((observer + " ").encode())]
    if len(matches) != 1: fail()
    return sha(matches[0])

def external_statement(receipt: dict[str, Any], observation: list[dict[str, Any]]) -> bytes:
    facts = receipt["facts"]
    return canonical_bytes({"schema": "open-card-g6-external-statement.v1", "run_id": receipt["run_id"], "source": receipt["source"], "target": receipt["target"], "installation_id_sha256": receipt["installation_id_sha256"], "observer_id": facts["observer_id"], "environment": facts["environment"], "method": facts["method"], "observed_at": facts["observed_at"], "subject": facts["subject"], "artifacts": observation})

def verify_external_receipt(receipt: dict[str, Any], root: Path, allowed_raw: bytes, *, owner: int) -> None:
    safe_system_ssh_keygen()
    facts = receipt["facts"]
    if facts["allowed_signers_sha256"] != sha(allowed_raw) or facts["signer_identity_sha256"] != signer_identity_digest(allowed_raw, facts["observer_id"]): fail()
    artifacts = {entry["path"]: entry for entry in receipt["artifacts"]}; statement_raw, _ = secure_file(root / "trust/statement.json", owner=owner, modes={0o600}); signature, _ = secure_file(root / "trust/observer.sig", owner=owner, modes={0o600})
    if sha(statement_raw) != facts["statement_sha256"] or sha(statement_raw) != artifacts["trust/statement.json"]["sha256"] or sha(signature) != artifacts["trust/observer.sig"]["sha256"]: fail()
    expected = external_statement(receipt, external_artifacts(facts["method"], receipt["artifacts"]))
    if statement_raw != expected: fail()
    try:
        with tempfile.TemporaryFile() as allowed_snapshot, tempfile.TemporaryFile() as signature_snapshot:
            allowed_snapshot.write(allowed_raw); allowed_snapshot.flush(); os.fsync(allowed_snapshot.fileno()); allowed_snapshot.seek(0)
            signature_snapshot.write(signature); signature_snapshot.flush(); os.fsync(signature_snapshot.fileno()); signature_snapshot.seek(0)
            allowed_fd, signature_fd = allowed_snapshot.fileno(), signature_snapshot.fileno()
            result = subprocess.run([str(SSH_KEYGEN), "-Y", "verify", "-f", f"/dev/fd/{allowed_fd}", "-I", facts["observer_id"], "-n", SIGN_NAMESPACE, "-s", f"/dev/fd/{signature_fd}"], input=statement_raw, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, timeout=10, check=False, pass_fds=(allowed_fd, signature_fd))
    except Exception: fail()
    if result.returncode != 0: fail()

def finalize(receipts: list[tuple[dict[str, Any], Path]], output: Path, allowed_signers: Path, *, owner: int | None = None) -> dict[str, Any]:
    if len(receipts) != 8: fail()
    values = [validate_receipt(receipt, root, owner=owner) for receipt, root in receipts]
    phases = [value["phase"] for value in values]
    if phases[:5] != ["SNAPSHOT_PREINSTALL", "INSTALL_VERIFY", "RESTART_DRILL", "REBOOT_HANDOFF", "REBOOT_VERIFY"] or [value["facts"]["method"] for value in values[5:]] != ["curl_resolve", "external_tcp", "browser"]:
        fail()
    first = values[0]; identity = (first["run_id"], first["source"], first["target"], first["schema"])
    installation: str | None = None
    for index, value in enumerate(values):
        if value["result"] != "pass" or (value["run_id"], value["source"], value["target"], value["schema"]) != identity:
            fail()
        if index == 0:
            if "installation_id_sha256" in value: fail()
        elif installation is None:
            installation = value.get("installation_id_sha256")
            if installation is None: fail()
        elif value.get("installation_id_sha256") != installation:
            fail()
    if values[3]["facts"]["boot_id"] == values[4]["facts"]["boot_id"]: fail()
    trust_owner = owner if owner is not None else os.getuid()
    allowed_raw, _ = secure_file(allowed_signers, owner=trust_owner, modes=ALLOWED_MODES)
    for receipt, (_, root) in zip(values[5:], receipts[5:]): verify_external_receipt(receipt, root, allowed_raw, owner=trust_owner)
    manifest = {"schema": final_schema_for_receipt(first["schema"]), "run_id": first["run_id"], "source": first["source"], "target": first["target"], "installation_id_sha256": installation, "receipt_sha256": [sha(canonical_bytes(value)) for value in values], "allowed_signers_sha256": sha(allowed_raw), "production_accepted": False, "scope": "staging_pre_dns_only"}
    atomic_no_replace(output, canonical_bytes(manifest), owner=owner)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate"); check.add_argument("--receipt", type=Path, required=True); check.add_argument("--artifact-root", type=Path)
    final = sub.add_parser("finalize"); final.add_argument("--receipt", type=Path, action="append", required=True); final.add_argument("--output", type=Path, required=True); final.add_argument("--allowed-signers", type=Path, required=True)
    args = parser.parse_args()
    try:
        owner = os.getuid()
        if args.command == "validate":
            root = args.artifact_root or args.receipt.parent
            print(canonical_bytes(validate_receipt(strict_json_path(args.receipt, owner=owner), root, owner=owner)).decode(), end="")
        else:
            pairs = [(strict_json_path(path, owner=owner), path.parent) for path in args.receipt]
            print(canonical_bytes(finalize(pairs, args.output, args.allowed_signers, owner=owner)).decode(), end="")
        return 0
    except Exception:
        print("invalid_gate6_evidence")
        return 2


if __name__ == "__main__": raise SystemExit(main())
