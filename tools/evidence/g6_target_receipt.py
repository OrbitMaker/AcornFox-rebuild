#!/usr/bin/env python3
"""Pure-local builder for target-side Gate 6 receipts."""
from __future__ import annotations

import argparse, json, os, re, stat, subprocess, sys
from pathlib import Path
from typing import Any

import g6_validate as g6

PHASES = {"snapshot-preinstall": ("SNAPSHOT_PREINSTALL", 1), "install-verify": ("INSTALL_VERIFY", 2), "restart-drill": ("RESTART_DRILL", 3), "reboot-handoff": ("REBOOT_HANDOFF", 4), "reboot-verify": ("REBOOT_VERIFY", 5)}
FACT_ARTIFACTS = {"host_preflight_sha256": "host-preflight.json", "listeners_sha256": "listeners.txt", "processes_sha256": "processes.txt", "api_sha256": "api.json", "sse_sha256": "sse.ndjson", "app_route_sha256": "app-route.json"}
RELEASE_MODES = {0o600, 0o640, 0o644, 0o755}

def strict(path: Path, owner: int) -> Any: return g6.strict_json_path(path, owner=owner)

def git(args: list[str], repo: Path) -> str:
    tool=Path("/usr/bin/git"); g6.safe_root(tool.parent, owner=0)
    try:
        before=tool.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0 or stat.S_IMODE(before.st_mode)!=0o755: g6.fail()
        fd=os.open(tool,os.O_RDONLY|os.O_NOFOLLOW)
        try: opened=os.fstat(fd)
        finally: os.close(fd)
        after=tool.lstat()
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino) or (after.st_dev,after.st_ino)!=(before.st_dev,before.st_ino): g6.fail()
    except OSError: g6.fail()
    try: return subprocess.run(["/usr/bin/git", "-C", str(repo), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"}, timeout=10, check=True).stdout.strip()
    except Exception: g6.fail()

def identity(value: Any, owner: int) -> dict[str, Any]:
    value = g6.exact(value, {"run_id","source","target","source_repo","release_manifest","release_manifest_sha256","bundle_manifest"}, {"installation_id_file"})
    repo, release, bundle = Path(value["source_repo"]), Path(value["release_manifest"]), Path(value["bundle_manifest"])
    for path in (repo,): g6.safe_root(path, owner=owner)
    if not repo.is_absolute() or repo.is_symlink() or git(["status","--porcelain"], repo) != "": g6.fail()
    source = g6.source(value["source"]); tag = source["tag"]
    if git(["cat-file","-t",tag], repo) != "tag" or git(["rev-parse",tag+"^{}"], repo) != source["commit"]: g6.fail()
    release_raw, _ = g6.secure_file(release, owner=owner, modes=g6.ALLOWED_MODES)
    if g6.sha(release_raw) != g6.safe_sha(value["release_manifest_sha256"]): g6.fail()
    manifest = g6.strict_json_bytes(release_raw)
    version=manifest.get("version") if isinstance(manifest,dict) else None
    if not isinstance(manifest, dict) or not isinstance(version,str) or not re.fullmatch(r"0\.8\.0-rc\.[1-9][0-9]*",version) or source["tag"] != "v"+version or manifest.get("source_commit") != source["commit"] or manifest.get("architecture") != "amd64" or manifest.get("migration_version") != "0024" or not isinstance(manifest.get("files"), list) or not manifest["files"]: g6.fail()
    # Every declared release file is hash-bound and may not be a symlink.
    release_root = release.parent; declared=set()
    for item in manifest["files"]:
        item = g6.exact(item, {"path","sha256","mode"}); path=g6.safe_relative(item["path"])
        if path in declared or not isinstance(item["mode"], int) or isinstance(item["mode"], bool) or item["mode"] not in RELEASE_MODES: g6.fail()
        expected_digest = g6.safe_sha(item["sha256"])
        declared.add(path); raw, _ = g6.secure_file(release_root / path, owner=owner, modes={item["mode"]})
        if g6.sha(raw) != expected_digest: g6.fail()
    actual=set()
    try:
        for candidate in release_root.rglob("*"):
            info=candidate.lstat()
            if stat.S_ISLNK(info.st_mode): g6.fail()
            if stat.S_ISDIR(info.st_mode): continue
            if not stat.S_ISREG(info.st_mode): g6.fail()
            if candidate != release: actual.add(candidate.relative_to(release_root).as_posix())
    except OSError: g6.fail()
    if actual != declared: g6.fail()
    raw_bundle, _ = g6.secure_file(bundle, owner=owner, modes=g6.ALLOWED_MODES)
    if g6.sha(raw_bundle) != source["bundle_manifest_sha256"]: g6.fail()
    try:
        lines=raw_bundle.decode().splitlines(); entries={}
        archive_name=f"open-card-{version}-production.tar.gz"
        expected_bundle_paths={archive_name,"release/manifest.json"}
        if len(lines)!=2: g6.fail()
        for line in lines:
            digest,path=line.split("  ",1)
            if not g6.HEX64.fullmatch(digest) or path != g6.safe_relative(path) or path in entries: g6.fail()
            entries[path]=digest
        if set(entries)!=expected_bundle_paths or [line.split("  ",1)[1] for line in lines] != [archive_name,"release/manifest.json"] or entries.get("release/manifest.json") != value["release_manifest_sha256"]: g6.fail()
        for path, expected in entries.items():
            raw,_=g6.secure_file(bundle.parent/path,owner=owner,modes=g6.ALLOWED_MODES)
            if g6.sha(raw)!=expected: g6.fail()
        expected_bundle=(f"{entries[archive_name]}  {archive_name}\n{entries['release/manifest.json']}  release/manifest.json\n").encode()
        if raw_bundle!=expected_bundle: g6.fail()
    except Exception: g6.fail()
    output = {"run_id": g6.safe_id(value["run_id"]), "source": source, "target": g6.target(value["target"])}
    if "installation_id_file" in value:
        raw, _ = g6.secure_file(Path(value["installation_id_file"]), owner=owner, modes={0o600}); output["installation_id_sha256"] = g6.sha(raw)
    return output

def artifacts(values: list[str], owner: int) -> tuple[list[dict[str,Any]], dict[str,str], dict[str,bytes]]:
    seen=set(); result=[]; paths={}; raw_map={}
    for value in values:
        if value.count("=") != 1: g6.fail()
        relative, absolute = value.split("=",1); relative=g6.safe_relative(relative); path=Path(absolute)
        if relative in seen or not path.is_absolute(): g6.fail()
        raw, info=g6.secure_file(path, owner=owner, modes=g6.ALLOWED_MODES); seen.add(relative); paths[relative]=g6.sha(raw); raw_map[relative]=raw
        result.append({"path":relative,"sha256":g6.sha(raw),"mode":stat.S_IMODE(info.st_mode)})
    if not result: g6.fail()
    return result, paths, raw_map

def bind_facts(phase: str, facts: dict[str,Any], hashes: dict[str,str]) -> dict[str,Any]:
    if not isinstance(facts,dict): g6.fail()
    if phase == "SNAPSHOT_PREINSTALL": required={"host_preflight_sha256":"host-preflight.json"}
    else: required=FACT_ARTIFACTS
    for field, name in required.items():
        if facts.get(field) != hashes.get(name): g6.fail()
    return facts

def predecessor(phase: str, previous: Path | None, current: dict[str,Any], owner: int) -> None:
    needed={"INSTALL_VERIFY":"SNAPSHOT_PREINSTALL","RESTART_DRILL":"INSTALL_VERIFY","REBOOT_HANDOFF":"RESTART_DRILL","REBOOT_VERIFY":"REBOOT_HANDOFF"}.get(phase)
    if needed is None:
        if previous is not None: g6.fail()
        return
    if previous is None: g6.fail()
    prior=g6.receipt_from_path(previous, owner=owner)
    expected={"receipt.json",*(item["path"] for item in prior["artifacts"])}
    if {path.relative_to(previous.parent).as_posix() for path in previous.parent.iterdir()} != expected: g6.fail()
    if prior["phase"] != needed or prior["run_id"] != current["run_id"] or prior["source"] != current["source"] or prior["target"] != current["target"]: g6.fail()
    if needed != "SNAPSHOT_PREINSTALL" and prior.get("installation_id_sha256") != current.get("installation_id_sha256"): g6.fail()
    if phase == "REBOOT_VERIFY" and prior["facts"]["boot_id"] == current["facts"]["boot_id"]: g6.fail()

def publish(phase_arg: str, identity_path: Path, facts_path: Path, declarations: list[str], output_dir: Path, previous_path: Path | None, owner: int | None=None) -> dict[str,Any]:
    owner=os.getuid() if owner is None else owner
    try:
        if phase_arg not in PHASES or not output_dir.is_absolute(): g6.fail()
        phase, sequence=PHASES[phase_arg]; ident=identity(strict(identity_path,owner),owner); declared, hashes, raw_map=artifacts(declarations,owner); facts=bind_facts(phase, strict(facts_path,owner),hashes)
        expected={"host-preflight.json"} if phase=="SNAPSHOT_PREINSTALL" else set(FACT_ARTIFACTS.values())
        if {item["path"] for item in declared} != expected: g6.fail()
        if phase=="SNAPSHOT_PREINSTALL":
            if "installation_id_sha256" in ident: g6.fail()
        elif "installation_id_sha256" not in ident: g6.fail()
        facts={**facts,"sequence":sequence}; receipt={"schema":g6.receipt_schema_for_target(ident["target"]),"run_id":ident["run_id"],"phase":phase,"source":ident["source"],"target":ident["target"],"facts":facts,"artifacts":declared,"result":"pass",**({"installation_id_sha256":ident["installation_id_sha256"]} if "installation_id_sha256" in ident else {})}
        validated=g6.validate_receipt(receipt)
        predecessor(phase,previous_path,validated,owner)
        g6.safe_root(output_dir,owner=owner); final=output_dir/phase_arg
        encoded=g6.canonical_bytes(validated)
        if final.exists():
            existing=final/"receipt.json"
            if not existing.exists() or g6.receipt_from_path(existing,owner=owner)!=validated: g6.fail()
            existing_raw, _ = g6.secure_file(existing, owner=owner, modes={0o600})
            if existing_raw != encoded: g6.fail()
            if {path.relative_to(final).as_posix() for path in final.iterdir()} != {"receipt.json",*expected}: g6.fail()
            return validated
        final.mkdir(mode=0o700); g6.safe_root(final, owner=owner); fd=os.open(output_dir,os.O_RDONLY); os.fsync(fd); os.close(fd)
        for artifact in declared: g6.atomic_no_replace(final/artifact["path"],raw_map[artifact["path"]],artifact["mode"],owner=owner)
        if {path.relative_to(final).as_posix() for path in final.iterdir()} != expected: g6.fail()
        # Validate exact copied bytes before receipt publication.
        validated=g6.validate_receipt(validated,final,owner=owner); g6.atomic_no_replace(final/"receipt.json",encoded,0o600,owner=owner)
        if {path.relative_to(final).as_posix() for path in final.iterdir()} != {"receipt.json",*expected}: g6.fail()
        return validated
    except g6.ValidationError: raise
    except Exception: g6.fail()

def main()->int:
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True); p=sub.add_parser("publish")
    p.add_argument("--phase",required=True); p.add_argument("--identity",type=Path,required=True); p.add_argument("--facts",type=Path,required=True); p.add_argument("--artifact",action="append",required=True); p.add_argument("--output-dir",type=Path,required=True); p.add_argument("--previous-receipt",type=Path); p.add_argument("--handoff-receipt",type=Path)
    args=parser.parse_args()
    try:
        previous=args.handoff_receipt if args.phase=="reboot-verify" else args.previous_receipt
        if args.phase=="reboot-verify" and args.previous_receipt is not None: g6.fail()
        if args.phase!="reboot-verify" and args.handoff_receipt is not None: g6.fail()
        print(g6.canonical_bytes(publish(args.phase,args.identity,args.facts,args.artifact,args.output_dir,previous)).decode(),end=""); return 0
    except Exception: print("invalid_gate6_evidence"); return 2
if __name__=="__main__": raise SystemExit(main())
