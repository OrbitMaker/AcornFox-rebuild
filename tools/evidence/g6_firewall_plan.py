#!/usr/bin/env python3
"""Render a pure, non-executable Tencent Gate6 firewall replacement plan."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

INPUT_SCHEMA = "open-card-g6-firewall-input.v1"
OUTPUT_SCHEMA = "open-card-g6-firewall-plan.v1"
TOP_KEYS = {"schema", "provider", "product", "profile", "account_id", "identity_type", "principal_id", "region", "instance_id", "public_ipv4", "management_cidrs", "old_rule_snapshot"}
RULE_KEYS = {"index", "action", "protocol", "port", "cidr", "description"}
ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REGION = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
INSTANCE = re.compile(r"^(?:ins|lhins)-[A-Za-z0-9]+$")
GROUP = re.compile(r"^sg-[A-Za-z0-9]+$")
DESCRIPTION = re.compile(r"^[A-Za-z0-9 .,:;_()/-]{0,120}$")
FORBIDDEN_KEY = re.compile(r"(?:secret|token|key|password|credential|dsn|cookie|authorization|confirmation|command|environment|private)", re.I)
FORBIDDEN_VALUE = re.compile(r"(?:AKID[A-Za-z0-9]{16,}|-----BEGIN|(?:sk|gh[pousr])-[A-Za-z0-9_]{20,}|postgres(?:ql)?://|https?://|[A-Za-z]:[\\/])", re.I)
EMBEDDED_PATH = re.compile(r"(?:^|[\s=:])/(?:[A-Za-z._-][A-Za-z0-9._-]*/)*[A-Za-z._-][A-Za-z0-9._-]*")
SENSITIVE_TEXT = re.compile(r"(?:cookie|authorization|bearer\s+|api[\s_-]*key|ssh\s+private|private\s+(?:key|material)|credential|password|secret|token)", re.I)


class PlanError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def canonical_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise PlanError(f"{label} path must be canonical absolute")
    return path


def safe_parent(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            raise PlanError(f"{label} parent is missing")
        if stat.S_ISLNK(info.st_mode):
            raise PlanError(f"{label} path contains a symlink")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PlanError(f"{label} parent must be a real directory")


def open_input(path: Path) -> bytes:
    parent = path.parent
    safe_parent(parent, "input")
    parent_info = parent.lstat()
    if parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o022:
        raise PlanError("input parent ownership or mode is unsafe")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in {0o600, 0o640, 0o644} or info.st_uid != os.getuid():
                raise PlanError("input must be a current-owner regular single-link file with safe mode")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(open_input(path).decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise PlanError("input is not strict JSON") from error
    if not isinstance(value, dict):
        raise PlanError("input must be a JSON object")
    return value


def reject_forbidden(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if FORBIDDEN_KEY.search(str(key)):
                raise PlanError("input contains a forbidden field")
            reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            reject_forbidden(item)
    elif isinstance(value, str) and (FORBIDDEN_VALUE.search(value) or EMBEDDED_PATH.search(value) or SENSITIVE_TEXT.search(value)):
        raise PlanError("input contains a forbidden value")


def require(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PlanError(f"{label} is invalid")
    return value


def canonical_port(value: Any, protocol: str) -> str:
    if not isinstance(value, str):
        raise PlanError("rule port is invalid")
    if value == "ALL":
        if protocol != "ALL":
            raise PlanError("rule port ALL requires protocol ALL")
        return value
    if protocol == "ALL":
        raise PlanError("protocol ALL requires port ALL")
    match = re.fullmatch(r"([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?", value)
    if not match:
        raise PlanError("rule port is invalid")
    first, last = int(match.group(1)), int(match.group(2) or match.group(1))
    if first > 65535 or last > 65535 or first > last or ("-" in value and (str(first) != match.group(1) or str(last) != match.group(2))):
        raise PlanError("rule port is not canonical")
    return value


def normalized_rule(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RULE_KEYS:
        raise PlanError("firewall rule fields are invalid")
    reject_forbidden(value)
    index = value["index"]
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise PlanError("firewall rule index is invalid")
    action, protocol = value["action"], value["protocol"]
    if action not in {"ACCEPT", "DROP"} or protocol not in {"TCP", "UDP", "ALL"}:
        raise PlanError("firewall rule action or protocol is invalid")
    port = canonical_port(value["port"], protocol)
    try:
        cidr = ipaddress.ip_network(value["cidr"], strict=True)
    except ValueError as error:
        raise PlanError("firewall rule CIDR is invalid") from error
    if str(cidr) != value["cidr"]:
        raise PlanError("firewall rule CIDR is not canonical")
    description = value["description"]
    if not isinstance(description, str) or not DESCRIPTION.fullmatch(description):
        raise PlanError("firewall rule description is invalid")
    return {"index": index, "action": action, "protocol": protocol, "port": port, "cidr": str(cidr), "description": description}


def normalized_rules(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PlanError("firewall rules must be a list")
    rules = [normalized_rule(item) for item in value]
    if len({rule["index"] for rule in rules}) != len(rules) or len({canonical(rule) for rule in rules}) != len(rules):
        raise PlanError("firewall rules contain duplicates")
    return sorted(rules, key=lambda rule: rule["index"])


def canonical_cidrs(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PlanError("management_cidrs must be a non-empty list")
    networks = []
    for item in value:
        try:
            network = ipaddress.ip_network(item, strict=True)
        except (TypeError, ValueError) as error:
            raise PlanError("management CIDR is invalid") from error
        if network.prefixlen == 0 or str(network) != item:
            raise PlanError("management CIDR must be canonical and non-global")
        networks.append(network)
    ordered = sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))
    if networks != ordered or len(set(networks)) != len(networks):
        raise PlanError("management CIDRs must be canonical, unique, and sorted")
    for index, network in enumerate(networks):
        if any(network.overlaps(other) for other in networks[:index]):
            raise PlanError("management CIDRs must not overlap")
    return [str(network) for network in networks]


def validate(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != TOP_KEYS:
        raise PlanError("input fields are invalid")
    reject_forbidden(value)
    if value["schema"] != INPUT_SCHEMA or value["provider"] != "tencent" or value["product"] not in {"cvm", "lighthouse"}:
        raise PlanError("input provider schema is invalid")
    product = value["product"]
    profile = require(value["profile"], ALIAS, "profile")
    account_id = require(value["account_id"], ACCOUNT, "account_id")
    principal_id = require(value["principal_id"], ACCOUNT, "principal_id")
    if value["identity_type"] not in {"CAMUser", "Root", "Role"}:
        raise PlanError("identity_type is invalid")
    region = require(value["region"], REGION, "region")
    instance_id = require(value["instance_id"], INSTANCE, "instance_id")
    if (product == "cvm") != instance_id.startswith("ins-"):
        raise PlanError("product and instance_id do not match")
    try:
        public = ipaddress.ip_address(value["public_ipv4"])
    except ValueError as error:
        raise PlanError("public_ipv4 is invalid") from error
    if public.version != 4 or not public.is_global:
        raise PlanError("public_ipv4 must be public IPv4")
    snapshot = value["old_rule_snapshot"]
    if not isinstance(snapshot, dict) or set(snapshot) != {"kind", "provider_payload"}:
        raise PlanError("old_rule_snapshot is invalid")
    expected_kind = "cvm_security_group" if product == "cvm" else "lighthouse_firewall"
    if snapshot["kind"] != expected_kind or not isinstance(snapshot["provider_payload"], dict):
        raise PlanError("product and old_rule_snapshot kind do not match")
    payload = snapshot["provider_payload"]
    if product == "cvm":
        if set(payload) != {"security_group_id", "ingress_rules", "egress_rules"}:
            raise PlanError("CVM snapshot payload fields are invalid")
        require(payload["security_group_id"], GROUP, "security_group_id")
        normalized_payload = {"security_group_id": payload["security_group_id"], "ingress_rules": normalized_rules(payload["ingress_rules"]), "egress_rules": normalized_rules(payload["egress_rules"])}
    else:
        if set(payload) != {"instance_id", "firewall_rules"} or payload["instance_id"] != instance_id:
            raise PlanError("Lighthouse snapshot payload fields are invalid")
        normalized_payload = {"instance_id": instance_id, "firewall_rules": normalized_rules(payload["firewall_rules"])}
    return {"product": product, "profile": profile, "account_id": account_id, "identity_type": value["identity_type"], "principal_id": principal_id, "region": region, "instance_id": instance_id, "public_ipv4": str(public), "management_cidrs": canonical_cidrs(value["management_cidrs"]), "old_rule_snapshot": {"kind": expected_kind, "provider_payload": normalized_payload}}


def desired_rules(cidr_list: list[str]) -> list[dict[str, Any]]:
    values = [("80", "0.0.0.0/0", "http_public"), ("443", "0.0.0.0/0", "https_public")]
    values.extend(("22", cidr, "ssh_management") for cidr in cidr_list)
    return [{"index": index, "action": "ACCEPT", "protocol": "TCP", "port": port, "cidr": cidr, "description": description} for index, (port, cidr, description) in enumerate(values)]


def difference(old: list[dict[str, Any]], desired: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    old_set, desired_set = {canonical(rule) for rule in old}, {canonical(rule) for rule in desired}
    return [rule for rule in old if canonical(rule) not in desired_set], [rule for rule in desired if canonical(rule) not in old_set]


def render(value: dict[str, Any]) -> dict[str, Any]:
    snapshot = value["old_rule_snapshot"]
    kind, payload = snapshot["kind"], snapshot["provider_payload"]
    desired = desired_rules(value["management_cidrs"])
    identity = {"provider": "tencent", **{key: value[key] for key in ("product", "profile", "account_id", "identity_type", "principal_id", "region", "instance_id", "public_ipv4")}}
    if kind == "cvm_security_group":
        old = payload["ingress_rules"]
        removed, added = difference(old, desired)
        operation = {"kind": "cvm_replace_security_group_ingress", "security_group_id": payload["security_group_id"], "old_ingress_sha256": digest(old), "desired_ingress_sha256": digest(desired), "desired_ingress": desired, "removed_old_rules": removed, "added_desired_rules": added, "preserved_egress_sha256": digest(payload["egress_rules"])}
        branch = "tencent_cvm"
    else:
        old = payload["firewall_rules"]
        removed, added = difference(old, desired)
        operation = {"kind": "lighthouse_replace_instance_firewall_rules", "instance_id": value["instance_id"], "old_firewall_sha256": digest(old), "desired_firewall_sha256": digest(desired), "desired_firewall_rules": desired, "removed_old_rules": removed, "added_desired_rules": added}
        branch = "tencent_lighthouse"
    return {"schema": OUTPUT_SCHEMA, "status": "DRAFT_UNEXECUTABLE", "provider_branch": branch, "identity": {"digest": digest(identity), "facts": identity}, "selection": {"management_cidrs": value["management_cidrs"]}, "old_rule_snapshot": {"sha256": digest(snapshot), "snapshot": snapshot}, "operation": operation, "impact": {"removed_rule_count": len(removed), "added_rule_count": len(added), "removed_public_ingress": [rule for rule in removed if rule["cidr"] in {"0.0.0.0/0", "::/0"}]}, "rollback": {"sha256": digest(snapshot), "snapshot": snapshot}, "requires_live_reread": True, "requires_identity_match": True, "requires_user_confirmation": True}


def publish(output: Path, data: bytes) -> None:
    parent = output.parent
    safe_parent(parent, "output")
    info = parent.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise PlanError("output parent ownership or mode is unsafe")
    if output.exists() or output.is_symlink():
        raise PlanError("refusing to overwrite output")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    temporary_name = f".{output.name}.{next(tempfile._get_candidate_names())}"
    try:
        descriptor = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise PlanError("could not write complete output")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary_name, output.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError as error:
            raise PlanError("refusing to overwrite output") from error
        os.unlink(temporary_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        final = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1 or stat.S_IMODE(final.st_mode) != 0o600 or final.st_uid != os.getuid():
            raise PlanError("published output integrity is invalid")
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def plan(input_path: Path, output_path: Path) -> dict[str, Any]:
    try:
        input_path = canonical_absolute(input_path, "input")
        output_path = canonical_absolute(output_path, "output")
        value = validate(load(input_path))
        result = render(value)
        publish(output_path, canonical(result))
        return result
    except PlanError:
        raise
    except Exception as error:
        raise PlanError("firewall plan operation failed") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = plan(args.input, args.output)
    except PlanError:
        print("g6 firewall plan: invalid input or output", file=sys.stderr)
        return 1
    print(json.dumps({"schema": result["schema"], "status": result["status"], "provider_branch": result["provider_branch"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
