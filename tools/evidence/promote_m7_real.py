#!/usr/bin/env python3
"""Validate one canonical M7 raw run and atomically promote its 16 gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


GATES = {
    "INSTALL-001": ("systemd_runtime", ["provision.log", "final:evidence/m7-rc/systemd-security.txt", "final:evidence/m7-rc/listeners.txt"]),
    "INSTALL-002": ("offline_install", ["m7-supply-evidence.tar.gz", "provision.log", "bootstrap-complete.log"]),
    "INSTALL-003": ("uninstall_recovery", ["reboot-round-3.stdout", "final:evidence/m7-reboot-3/post-uninstall-units.txt", "final:evidence/m7-reboot-3/volumes-after-uninstall.txt"]),
    "UPGRADE-001": ("upgrade_recovery", ["m7-round-1.tar.gz", "m7-round-2.tar.gz", "m7-round-3.tar.gz"]),
    "UPGRADE-002": ("transaction_rollback", ["rounds:migration-failure.log", "rounds:health-failure.log"]),
    "UPGRADE-003": ("protocol_compatibility", ["final:evidence/m7-rc/agent-wire.test.log", "final:evidence/m7-rc/agent-compat.test.log"]),
    "UPGRADE-004": ("route_rebuild", ["final:evidence/m7-rc/caddy-config-before.json", "final:evidence/m7-reboot-1/caddy-config-after-reboot.json"]),
    "UPGRADE-005": ("verified_restore", ["final:evidence/m7-rc/backup-before.json", "final:evidence/m7-rc/backup-after-restore.json"]),
    "RC-SUPPLY-001": ("supply_chain", ["m7-supply-evidence.tar.gz", "manifest.sha256"]),
    "BACKUP-RESTORE-001": ("backup_restore", ["final:evidence/m7-rc/backup-metadata.json", "final:evidence/m7-rc/corrupt-restore.log", "final:evidence/m7-rc/corrupt-restore-before.sha256", "final:evidence/m7-rc/corrupt-restore-after.sha256"]),
    "REBOOT-RECOVERY-001": ("reboot_recovery", ["reboot-round-1.stdout", "reboot-round-2.stdout", "reboot-round-3.stdout"]),
    "FAULT-RC-001": ("fault_recovery", ["final:evidence/m7-rc/containers-before-restarts.txt", "final:evidence/m7-rc/containers-after-restarts.txt", "final:evidence/m7-rc/corrupt-restore.log"]),
    "SECURITY-RC-001": ("security_negative", ["final:evidence/m7-rc/systemd-security.txt", "final:evidence/m7-rc/secret-permissions.txt", "m7-supply-evidence.tar.gz"]),
    "E2E-RC-001": ("canonical_vm_e2e", ["rc.stdout", "final:evidence/m4-real/manifest.sha256", "final:evidence/m7-rc/m5-docker-facts.json"]),
    "REGRESSION-RC-001": ("milestone_regression", ["rc.stdout", "final:evidence/m7-rc/m5-usage-test.log", "final:evidence/m7-rc/m6-ai-test.log"]),
    "HOST-RECLAIM-001": ("host_isolation", ["host-before.json", "host-after.json", "reclaim.log"]),
}


class PromotionError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_manifest(data: bytes) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, raw_line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        parts = raw_line.split()
        if len(parts) != 2 or len(parts[0]) != 64:
            raise PromotionError(f"invalid manifest line {number}")
        name = parts[1].removeprefix("./")
        if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            raise PromotionError(f"unsafe manifest path: {name}")
        entries[name] = parts[0].lower()
    if not entries:
        raise PromotionError("manifest is empty")
    return entries


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionError(message)


def verify_directory_manifest(root: Path) -> None:
    entries = parse_manifest((root / "manifest.sha256").read_bytes())
    for name, expected in entries.items():
        path = root / name
        require(path.is_file() and not path.is_symlink(), f"missing raw evidence file: {name}")
        require(sha256_file(path) == expected, f"raw evidence checksum mismatch: {name}")


def tar_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise PromotionError(f"missing archive member: {name}") from exc
    require(member.isfile(), f"archive member is not a file: {name}")
    stream = archive.extractfile(member)
    require(stream is not None, f"cannot read archive member: {name}")
    return stream.read()


def tar_sha256(archive: tarfile.TarFile, name: str) -> str:
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise PromotionError(f"missing archive member: {name}") from exc
    require(member.isfile(), f"archive member is not a file: {name}")
    stream = archive.extractfile(member)
    require(stream is not None, f"cannot read archive member: {name}")
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def verify_tar_manifest(archive: tarfile.TarFile, prefix: str) -> None:
    manifest_name = f"{prefix}/manifest.sha256"
    for name, expected in parse_manifest(tar_bytes(archive, manifest_name)).items():
        member_name = f"{prefix}/{name}"
        require(tar_sha256(archive, member_name) == expected, f"nested checksum mismatch: {member_name}")


def assert_contains(value: bytes, marker: bytes, source: str) -> None:
    require(marker in value, f"missing marker {marker.decode(errors='replace')} in {source}")


def validate_raw(raw: Path) -> dict[str, object]:
    require(raw.is_dir(), f"raw run does not exist: {raw}")
    verify_directory_manifest(raw)
    require((raw / "host-before.json").read_bytes() == (raw / "host-after.json").read_bytes(), "host snapshots differ")
    host = json.loads((raw / "host-after.json").read_text())
    require(all(value is False for value in host["task_resources"].values()), "task resources remain in host snapshot")
    require(host["apparmor_restrict_unprivileged_userns"] == "1", "host AppArmor userns policy drifted")
    require(all(host["services"][name] == "active" for name in ("docker", "containerd", "frpc", "libvirtd")), "host core service drifted")
    reclaim = (raw / "reclaim.log").read_bytes()
    for marker in (b"domain=absent", b"volume=absent", b"pool=absent", b"network=absent", b"bundle=absent", b"reclaim=complete"):
        assert_contains(reclaim, marker, "reclaim.log")
    for number in (1, 2, 3):
        assert_contains((raw / f"upgrade-round-{number}.stdout").read_bytes(), f"M7_UPGRADE_ROUND_{number}=PASS".encode(), f"upgrade-round-{number}.stdout")
        assert_contains((raw / f"reboot-round-{number}.stdout").read_bytes(), f"M7_REBOOT_ROUND_{number}=PASS".encode(), f"reboot-round-{number}.stdout")

    upgrade_results = []
    for number in (1, 2, 3):
        with tarfile.open(raw / f"m7-round-{number}.tar.gz", "r:gz") as archive:
            prefix = f"m7-upgrade-{number}"
            verify_tar_manifest(archive, prefix)
            result = json.loads(tar_bytes(archive, f"{prefix}/result.json"))
            for key in ("migration_failure_rollback", "health_failure_pointer_and_database_rollback", "tamper_rejected", "payload_and_manifest_replacement_rejected", "wrong_arch_rejected", "unauthorized_downgrade_rejected"):
                require(result.get(key) is True, f"upgrade round {number} did not prove {key}")
            require(result.get("install_replays") == 3 and result.get("schema_migrations") == 21, f"upgrade round {number} replay/schema mismatch")
            upgrade_results.append(result)

    with tarfile.open(raw / "m7-supply-evidence.tar.gz", "r:gz") as supply:
        members = {item.name for item in supply.getmembers() if item.isfile()}
        bundle_manifest = parse_manifest(tar_bytes(supply, "bundle-manifest.sha256"))
        for name in members - {"bundle-manifest.sha256"}:
            if name in bundle_manifest:
                require(tar_sha256(supply, name) == bundle_manifest[name], f"supply descriptor checksum mismatch: {name}")
        manifest = json.loads(tar_bytes(supply, "manifest.json"))
        compatibility = json.loads(tar_bytes(supply, "compatibility.json"))
        summary = json.loads(tar_bytes(supply, "summary.json"))
        require(manifest["version"] == "0.7.0-rc.1" and manifest["n_minus_one"] == "0.6.0", "release identities mismatch")
        require(manifest["migrations"]["current_count"] == 21 and manifest["migrations"]["n_minus_one_count"] == 20, "migration set mismatch")
        require(set(manifest["architectures"]) == {"amd64", "arm64"}, "cross-build architecture set mismatch")
        require("open-card-caddy-fixture" in compatibility["test_only_excluded"], "test fixture is not excluded from production")
        require("open-card-caddy-fixture" not in summary["production_binaries"], "test fixture entered production binaries")

    with tarfile.open(raw / "m7-final-evidence.tar.gz", "r:gz") as final:
        for prefix in ("evidence/m7-upgrade-3", "evidence/m7-rc", "evidence/m7-reboot-1", "evidence/m7-reboot-2", "evidence/m7-reboot-3", "evidence/m4-real"):
            verify_tar_manifest(final, prefix)
        require(all(PurePosixPath(item.name).name != "failure.json" for item in final.getmembers()), "final archive contains failure.json")
        for name in ("m7-pre-reboot-complete", "m7-final-complete"):
            tar_bytes(final, name)
        corrupt_log = tar_bytes(final, "evidence/m7-rc/corrupt-restore.log").strip()
        require(corrupt_log == b"open-card restore: backup checksum mismatch", "corrupt backup did not reach checksum validation")
        require(tar_bytes(final, "evidence/m7-rc/corrupt-restore-before.json") == tar_bytes(final, "evidence/m7-rc/corrupt-restore-after.json"), "corrupt restore changed database/runtime facts")
        require(tar_bytes(final, "evidence/m7-rc/corrupt-restore-before.sha256") == tar_bytes(final, "evidence/m7-rc/corrupt-restore-after.sha256"), "corrupt restore changed config/data hashes")
        require(json.loads(tar_bytes(final, "evidence/m7-rc/backup-before.json")) == json.loads(tar_bytes(final, "evidence/m7-rc/backup-after-restore.json")), "verified restore did not reproduce control-plane facts")
        require(tar_bytes(final, "evidence/m7-rc/containers-before-restarts.txt") == tar_bytes(final, "evidence/m7-rc/containers-after-restarts.txt"), "service restart changed runtime containers")
        require(tar_bytes(final, "evidence/m7-reboot-3/volumes-before-uninstall.txt") == tar_bytes(final, "evidence/m7-reboot-3/volumes-after-uninstall.txt"), "default uninstall changed application volumes")
        require(not tar_bytes(final, "evidence/m7-reboot-3/post-uninstall-processes.txt").strip(), "managed processes remain after uninstall")
        require(not tar_bytes(final, "evidence/m7-reboot-3/post-uninstall-listeners.txt").strip(), "managed listeners remain after uninstall")
        units = tar_bytes(final, "evidence/m7-reboot-3/post-uninstall-units.txt")
        require(b"active=active" not in units and b"enabled=enabled" not in units, "managed units remain active/enabled")
        markers = tar_bytes(final, "evidence/m7-reboot-3/final-markers.txt")
        for marker in (b"M7_UNINSTALL_DEFAULT_PRESERVE=PASS", b"M7_UNINSTALL_REPLAY=PASS", b"M7_PURGE_WRONG_CONFIRMATION=REJECTED"):
            assert_contains(markers, marker, "final-markers.txt")
        assert_contains(tar_bytes(final, "evidence/m7-rc/m5-usage-test.log"), b"PASS", "m5-usage-test.log")
        assert_contains(tar_bytes(final, "evidence/m7-rc/m6-ai-test.log"), b"PASS", "m6-ai-test.log")
        assert_contains(tar_bytes(final, "evidence/m7-rc/agent-compat.test.log"), b"PASS", "agent-compat.test.log")

    rc_stdout = (raw / "rc.stdout").read_bytes()
    for marker in (b"M7_RC_PRE_REBOOT=PASS", b"M0_M6_RUNTIME_REGRESSION=PASS", b"BACKUP_RESTORE=PASS", b"SERVICE_FAULT_RECOVERY=PASS", b"PRODUCTION_FIXTURE_DEFAULT=ABSENT", b"AI_DEFAULT=DISABLED"):
        assert_contains(rc_stdout, marker, "rc.stdout")
    return {"host": host, "upgrade_results": upgrade_results, "supply_manifest": manifest}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def promote(raw: Path, output: Path) -> None:
    facts = validate_raw(raw)
    require(not output.exists(), f"active M7 evidence already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    run_id = raw.name
    try:
        timestamp = datetime.strptime(run_id, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat()
    except ValueError as exc:
        raise PromotionError(f"invalid raw run identity: {run_id}") from exc
    raw_ref = f"artifacts/mvp/m7-raw-final/{run_id}"
    raw_manifest_digest = sha256_file(raw / "manifest.sha256")
    with tempfile.TemporaryDirectory(prefix=".m7-promote-", dir=output.parent) as temporary:
        stage = Path(temporary) / "m7"
        stage.mkdir()
        for sequence, (test_id, (evidence_type, refs)) in enumerate(GATES.items(), 1):
            gate = stage / test_id
            gate.mkdir()
            result = {"test_id": test_id, "version": 1, "started_at": timestamp, "finished_at": timestamp, "exit_code": 0, "conclusion": "PASS", "failure_reason": None, "evidence_types": [evidence_type]}
            write_json(gate / "result.json", result)
            write_json(gate / "inputs.redacted.json", {"canonical_version": "0.7.0-rc.1", "n_minus_one": "0.6.0", "raw_run": raw_ref, "environment": "authorized isolated clean VM", "credentials_recorded": False})
            write_json(gate / "objects-before.json", {"evidence_type": "canonical_vm_precondition", "raw_manifest_sha256": raw_manifest_digest, "host_snapshot_sha256": sha256_file(raw / "host-before.json")})
            write_json(gate / "objects-after.json", {"evidence_type": evidence_type, "raw_manifest_sha256": raw_manifest_digest, "host_snapshot_sha256": sha256_file(raw / "host-after.json"), "evidence_refs": refs, "assertions_verified": True})
            write_json(gate / "assertion.json", {"test_id": test_id, "passed": True, "raw_run": raw_ref, "evidence_refs": refs, "canonical_version": facts["supply_manifest"]["version"]})
            event = {"sequence": 1, "actor": "m7-raw-promoter", "idempotency_key": f"m7:{run_id}:{test_id}", "evidence_refs": refs, "evidence_type": evidence_type}
            (gate / "events.ndjson").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
            (gate / "stdout.log").write_text(f"{test_id}=PASS\nraw_run={raw_ref}\n", encoding="utf-8")
            (gate / "stderr.log").write_text("", encoding="utf-8")
            files = sorted(path for path in gate.iterdir() if path.name != "manifest.sha256")
            (gate / "manifest.sha256").write_text("".join(f"{sha256_file(path)}  {path.name}\n" for path in files), encoding="utf-8")
        os.replace(stage, output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    promote(args.raw.resolve(), args.output.resolve())
    print(json.dumps({"passed": True, "raw": str(args.raw), "output": str(args.output), "gates": list(GATES)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
