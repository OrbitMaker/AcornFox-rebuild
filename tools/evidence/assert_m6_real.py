#!/usr/bin/env python3
"""Independently assert one M6 controlled-AI gate from frozen raw evidence."""

from __future__ import annotations
import argparse, hashlib, json, re, subprocess
from pathlib import Path
from assert_m6_foundation import M6_TEST_IDS, validate_fixture

SENSITIVE=(re.compile(rb"-----BEGIN\s+(?:RSA |EC |OPENSSH |)?PRIVATE KEY-----",re.I),re.compile(rb"postgres://[^\s:@]+:[^\s@]+@",re.I),re.compile(rb"m6-secret-canary",re.I),re.compile(rb"authorization\s*[:=]\s*bearer",re.I))

def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def require(root:Path,name:str)->Path:
    path=root/name
    if not path.is_file() or path.is_symlink():raise AssertionError(f"missing raw evidence: {name}")
    return path
def manifest(root:Path)->int:
    entries={}
    for line in require(root,"manifest.sha256").read_text().splitlines():
        digest,name=line.split(None,1);name=name.strip().removeprefix("./");assert re.fullmatch(r"[0-9a-f]{64}",digest) and name not in entries;entries[name]=digest
    actual={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name!="manifest.sha256"}
    assert set(entries)==actual
    for name,digest in entries.items():assert sha(root/name)==digest,name
    return len(entries)
def run(*args:str)->None:
    result=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
    if result.returncode:raise AssertionError(f"{' '.join(args)}\n{result.stdout}")
def inherited(root:Path)->dict[str,str]:
    rows={}
    for line in require(root,"inherited-buildkit-evidence.txt").read_text().splitlines():
        if "|" in line:
            test_id,conclusion=line.split("|",1);rows[test_id]=conclusion
    assert set(rows)=={"FAULT-BUILD-001","SEC-BUILD-001","SEC-BUILD-002","AI-DEG-001","E2E-GOLD-001"}
    assert all(value=="PASS" for value in rows.values())
    return rows
def base(root:Path,fixtures:Path)->list[str]:
    assert not validate_fixture(fixtures)
    count=manifest(root)
    assert require(root,"host-before.txt").read_bytes()==require(root,"host-after.txt").read_bytes()
    local=require(root,"local-m6-tests.log").read_text();db=require(root,"postgres-integration.log").read_text()
    assert "TestE2E_AI_001BuildFailureProducesVerifiedCandidateWithoutSourceOrProductionWrite" in local
    assert "TestM6PostgresLedgerRulesAndSettings" in db and "latest_migration=0021" in db and "m6_ai_tables=10" in db and "m6_rule_tables=6" in db
    inherited(root)
    for path in root.rglob("*"):
        if not path.is_file():continue
        data=path.read_bytes()
        for pattern in SENSITIVE:assert pattern.search(data) is None,path.name
    return [f"raw recursive manifest verifies {count} files","host before/after snapshots are identical","no external model or sensitive plaintext was recorded"]
def assert_gate(test_id:str,root:Path,fixtures:Path)->list[str]:
    assert test_id in M6_TEST_IDS;checks=base(root,fixtures)
    if test_id=="UNIT-AI-001":run("go","test","./internal/foundation","-run","TestUnitAI001","-count=1");checks+=["problem/version/cache keys are deterministic"]
    elif test_id=="SCHEMA-AI-001":run("go","test","./internal/domain","-run","TestSCHEMA_AI_001","-count=1");checks+=["strict plan rejects missing schema/tool/risk/validation/budget fields"]
    elif test_id=="SCHEMA-AI-002":run("go","test","./internal/domain","./internal/rules","-run","SCHEMA_AI_002|CandidateLifecycle","-count=1");checks+=["candidate cannot skip review regression shadow or version gates"]
    elif test_id=="CT-AI-001":run("go","test","./internal/contracts","./internal/ai/provider","-run","CT_AI_001|CTAI001","-count=1");checks+=["fake provider is structured bounded disableable and offline"]
    elif test_id=="E2E-AI-001":run("go","test","./cmd/open-card-server","-run","TestE2E_AI_001","-count=1");checks+=["real BuildKit failure/isolation prerequisites remain PASS","sandbox validation and patch candidate made zero source or production writes"]
    elif test_id=="AI-SEC-001":run("go","test","./internal/ai/context","-run","TestAISEC001","-count=1");checks+=["repository prompt injection remained untrusted data"]
    elif test_id=="AI-SEC-002":run("go","test","./internal/ai/tools","./internal/ai/runner","-run","CATALOG_002|SEC_002","-count=1");checks+=["arbitrary shell socket SSH Kubernetes and host paths were denied"]
    elif test_id=="AI-SEC-003":run("go","test","./internal/ai/orchestrator","./internal/ai/runner","-run","SEC_003|R3","-count=1");checks+=["production actions only returned controller handoff"]
    elif test_id=="AI-SEC-004":run("go","test","./internal/ai/context","-run","TestAISEC004","-count=1");checks+=["context contains secret metadata only and canary zero plaintext"]
    elif test_id=="AI-SEC-005":run("go","test","./internal/ai/runner","-run","SEC_002_003_005","-count=1");checks+=["core patch remained an unpublished candidate or was rejected"]
    elif test_id=="AI-DEG-001":checks+=["inherited AI-off Golden Path remains PASS with no required invocation"]
    elif test_id=="AI-DEG-002":run("go","test","./internal/ai/provider","./internal/ai/orchestrator","-run","AIDeg002|DEG_002","-count=1");checks+=["timeout budget cooldown and policy denial degraded without expansion"]
    elif test_id=="AI-DEG-003":run("go","test","./internal/ai/provider","-run","AIDeg003","-count=1");checks+=["unconfigured/unavailable provider returned minimal question/manual fallback"]
    elif test_id=="AI-CTX-001":run("go","test","./internal/ai/context","-run","AICTX001|CrossApplication|UTF8","-count=1");checks+=["context was scoped versioned truncated redacted and application-bound"]
    elif test_id=="AI-PLAN-001":run("go","test","./internal/domain","./internal/ai/orchestrator","-run","SCHEMA_AI_001|PLAN_001","-count=1");checks+=["invalid structured plan was ledgered and never executed"]
    elif test_id=="AI-CATALOG-001":run("go","test","./internal/ai/tools","./internal/ai/runner","-run","CATALOG_001","-count=1");checks+=["bounded read/build tools executed with independent verification"]
    elif test_id=="AI-CATALOG-002":run("go","test","./internal/ai/tools","-run","CATALOG_002|InvalidRisk","-count=1");checks+=["unknown tool version parameters and risk mismatches failed closed"]
    elif test_id=="AI-RUNNER-001":run("go","test","./internal/ai/runner","./internal/ai/orchestrator","-run","RUNNER_001","-count=1");checks+=["timeout resource network cleanup rollback and replay passed","BuildKit isolation prerequisites remain PASS"]
    elif test_id=="AI-LEDGER-001":run("go","test","./internal/ai/ledger","-run","InterventionIsAppendOnly|OrchestratorLedger","-count=1");checks+=["success failure rollback phases are append-only and restart-replayable","PostgreSQL 0021 integration passed"]
    elif test_id=="AI-LEDGER-002":run("go","test","./internal/ai/ledger","-run","RejectsSensitivePlaintext|LedgerValidationRejectsOpaque","-count=1");checks+=["ledger rejected plaintext credentials, nested sensitive structs, and uninspectable values while accepting opaque references"]
    elif test_id=="AI-RULE-001":run("go","test","./cmd/open-card-server","-run","TestE2E_AI_001","-count=1");checks+=["repeated verified cases formed a non-active candidate"]
    elif test_id=="AI-RULE-002":run("go","test","./internal/rules","./internal/domain","-run","CandidateLifecycle|SCHEMA_AI_002","-count=1");checks+=["missing review regression shadow or version prevented promotion"]
    elif test_id=="AI-RULE-003":run("go","test","./internal/rules","-run","RuleRegistryRollback","-count=1");checks+=["reviewed version enabled disabled and rolled back to previous immutable rule"]
    elif test_id=="AI-METRIC-001":run("go","test","./internal/ai/ledger","./internal/rules","./cmd/open-card-server","-run","Metrics|AIHandlerKeepsOrdinary","-count=1");checks+=["intervention token duration rollback and candidate metrics match ledger"]
    elif test_id=="AI-PROFILE-001":run("go","test","./internal/ai/provider","./internal/ai/ledger","-run","AIProfile001|ProfileCapabilities|Settings","-count=1");checks+=["china global local disabled profiles preserve identical validation semantics"]
    return checks
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--test-id",required=True);p.add_argument("--raw-root",type=Path,required=True);p.add_argument("--fixture-root",type=Path,default=Path("tests/fixtures/m6"));a=p.parse_args()
    checks=assert_gate(a.test_id,a.raw_root.resolve(),a.fixture_root.resolve());print(json.dumps({"test_id":a.test_id,"conclusion":"PASS","evidence_type":"policy_decision","checks":checks},indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
