#!/usr/bin/env python3
"""Signed outside-target evidence import. It never opens a network connection."""
from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path
from typing import Any

import g6_validate as g6

def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(fd)
    finally: os.close(fd)



def metadata(value: Any) -> dict[str, Any]:
    value = g6.exact(value, {"run_id", "source", "target", "observer_id", "environment", "method", "installation_id_sha256", "observed_at", "subject"})
    observer = g6.safe_id(value["observer_id"]); target = g6.target(value["target"])
    if observer.lower() in {"self", "local", target["instance_id"].lower()} or value["environment"] != "outside_target" or value["method"] not in g6.EXTERNAL:
        g6.fail()
    facts = {"sequence": g6.EXTERNAL[value["method"]], "method": value["method"], "observer_id": observer, "environment": "outside_target", "observed_at": value["observed_at"], "subject": value["subject"], "signature_verified": True, "signer_identity_sha256": "0" * 64, "allowed_signers_sha256": "0" * 64, "statement_sha256": "0" * 64, "statement_artifact_path": "trust/statement.json", "signature_artifact_path": "trust/observer.sig"}
    # Parse the facts through the same shared strict contract before signing.
    g6.phase_facts("EXTERNAL_IMPORT", facts, g6.source(value["source"]))
    return {"run_id": g6.safe_id(value["run_id"]), "source": g6.source(value["source"]), "target": target, "observer_id": observer, "environment": "outside_target", "method": value["method"], "installation_id_sha256": g6.safe_sha(value["installation_id_sha256"]), "observed_at": value["observed_at"], "subject": value["subject"]}


def source_artifacts(paths: list[Path], *, owner: int) -> list[dict[str, Any]]:
    if not paths: g6.fail()
    names: set[str] = set(); result: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_absolute() or not g6.SAFE_ID.fullmatch(path.name) or path.name in names: g6.fail()
        raw, info = g6.secure_file(path, owner=owner, modes=g6.ALLOWED_MODES)
        names.add(path.name); result.append({"path": f"artifacts/{path.name}", "sha256": g6.sha(raw), "mode": stat.S_IMODE(info.st_mode), "raw": raw})
    return sorted(result, key=lambda value: value["path"])


def import_external(metadata_path: Path, sources: list[Path], output_dir: Path, allowed_signers: Path, signature: Path, *, owner: int | None = None) -> dict[str, Any]:
    owner = os.getuid() if owner is None else owner
    try:
        meta = metadata(g6.strict_json_path(metadata_path, owner=owner)); staged = source_artifacts(sources, owner=owner)
        public_artifacts = [{key: value for key, value in artifact.items() if key != "raw"} for artifact in staged]
        g6.external_artifacts(meta["method"], public_artifacts + [{"path": "trust/statement.json", "sha256": "0" * 64, "mode": 0o600}, {"path": "trust/observer.sig", "sha256": "0" * 64, "mode": 0o600}])
        allowed_raw, _ = g6.secure_file(allowed_signers, owner=owner, modes=g6.ALLOWED_MODES); signature_raw, _ = g6.secure_file(signature, owner=owner, modes=g6.ALLOWED_MODES)
        if not output_dir.is_absolute() or output_dir.exists() or output_dir.is_symlink(): g6.fail()
        g6.safe_root(output_dir.parent, owner=owner)
        try: output_dir.mkdir(mode=0o700)
        except FileExistsError: g6.fail()
        sync_dir(output_dir.parent)
        artifacts_dir = output_dir / "artifacts"; artifacts_dir.mkdir(mode=0o700); sync_dir(output_dir)
        for artifact in staged:
            g6.atomic_no_replace(artifacts_dir / Path(artifact["path"]).name, artifact["raw"], artifact["mode"], owner=owner)
        facts = {"sequence": g6.EXTERNAL[meta["method"]], "method": meta["method"], "observer_id": meta["observer_id"], "environment": "outside_target", "observed_at": meta["observed_at"], "subject": meta["subject"], "signature_verified": True, "signer_identity_sha256": g6.signer_identity_digest(allowed_raw, meta["observer_id"]), "allowed_signers_sha256": g6.sha(allowed_raw), "statement_sha256": "0" * 64, "statement_artifact_path": "trust/statement.json", "signature_artifact_path": "trust/observer.sig"}
        draft = {"schema": g6.receipt_schema_for_target(meta["target"]), "run_id": meta["run_id"], "phase": "EXTERNAL_IMPORT", "source": meta["source"], "target": meta["target"], "installation_id_sha256": meta["installation_id_sha256"], "facts": facts, "artifacts": public_artifacts + [{"path": "trust/statement.json", "sha256": "0" * 64, "mode": 0o600}, {"path": "trust/observer.sig", "sha256": g6.sha(signature_raw), "mode": 0o600}], "result": "pass"}
        statement = g6.external_statement(draft, public_artifacts)
        trust_dir = output_dir / "trust"; trust_dir.mkdir(mode=0o700); sync_dir(output_dir)
        g6.atomic_no_replace(trust_dir / "statement.json", statement, 0o600, owner=owner); g6.atomic_no_replace(trust_dir / "observer.sig", signature_raw, 0o600, owner=owner)
        receipt = {**draft, "facts": {**facts, "statement_sha256": g6.sha(statement)}, "artifacts": public_artifacts + [{"path": "trust/statement.json", "sha256": g6.sha(statement), "mode": 0o600}, {"path": "trust/observer.sig", "sha256": g6.sha(signature_raw), "mode": 0o600}]}
        g6.verify_external_receipt(receipt, output_dir, allowed_raw, owner=owner)
        validated = g6.validate_receipt(receipt, output_dir, owner=owner)
        # Receipt is the final completion marker. On failure the reserved
        # directory intentionally remains incomplete and cannot be reused.
        g6.atomic_no_replace(output_dir / "receipt.json", g6.canonical_bytes(validated), 0o600, owner=owner)
        return validated
    except g6.ValidationError:
        raise
    except Exception:
        g6.fail()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True); parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True); parser.add_argument("--allowed-signers", type=Path, required=True); parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(g6.canonical_bytes(import_external(args.metadata, args.source, args.output_dir, args.allowed_signers, args.signature)).decode(), end="")
        return 0
    except Exception:
        print("invalid_gate6_evidence"); return 2


if __name__ == "__main__": raise SystemExit(main())
