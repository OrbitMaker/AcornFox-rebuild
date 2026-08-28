package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type contextFixture struct {
	value domain.AIContextPackage
	err   error
}

func (f contextFixture) Build(context.Context, Request) (domain.AIContextPackage, error) {
	return f.value, f.err
}

type catalogFixture struct {
	err   error
	calls int
}

func (f *catalogFixture) Authorize(context.Context, domain.AIActionPlan, Request) error {
	f.calls++
	return f.err
}

type runnerFixture struct {
	result           ExecutionResult
	err              error
	calls, rollbacks int
}

func (f *runnerFixture) Execute(context.Context, domain.AIActionPlan, Request) (ExecutionResult, error) {
	f.calls++
	return f.result, f.err
}
func (f *runnerFixture) Rollback(context.Context, domain.AIActionPlan, Request) ([]domain.EvidenceRef, error) {
	f.rollbacks++
	return []domain.EvidenceRef{{ID: "ev_rollback", Kind: "rollback", Digest: "sha256:rollback"}}, nil
}

type ledgerFixture struct {
	records map[domain.ID]LedgerEntry
}

func (f *ledgerFixture) Append(_ context.Context, value LedgerEntry) (LedgerEntry, error) {
	if old, ok := f.records[value.Record.ID]; ok {
		return old, nil
	}
	f.records[value.Record.ID] = value
	return value, nil
}
func (f *ledgerFixture) Lookup(_ context.Context, id domain.ID) (LedgerEntry, bool, error) {
	value, ok := f.records[id]
	return value, ok, nil
}

func validContext() domain.AIContextPackage {
	return domain.AIContextPackage{ID: "ctx_1", ApplicationID: "app_1", TaskType: "build_failure_diagnosis", Profile: "local", Scope: []string{"Dockerfile", "build/log-window"}, ObjectVersions: map[string]string{"source": "v1"}, SourceRefs: []domain.EvidenceRef{{ID: "ev_ctx", Kind: "manifest", Digest: "sha256:ctx"}}, ManifestDigest: "sha256:ctx", Bytes: 128, Authorized: true, Redacted: true, UntrustedData: true, TemplateVersion: "ctx-v1"}
}
func requestFixture() Request {
	return Request{ApplicationID: "app_1", TaskType: "build_failure_diagnosis", Reason: TriggerRuleMiss, ProblemFingerprint: "sha256:problem", ObjectVersions: map[string]string{"source": "v1"}, Profile: "local", IdempotencyKey: "ai:test-1", Actor: "operator", MaxTokens: 128, MaxDuration: time.Second}
}
func providerWithPlan(t *testing.T, mutate func(*domain.AIActionPlan)) contracts.AIProvider {
	t.Helper()
	provider := contracts.NewFakeAIProvider(true)
	// The fake emits the canonical policy/tool; mutation is applied through a wrapper.
	if mutate == nil {
		return provider
	}
	return providerWrapper{base: provider, mutate: mutate}
}

type providerWrapper struct {
	base   contracts.AIProvider
	mutate func(*domain.AIActionPlan)
}

func (p providerWrapper) Metadata(ctx context.Context) contracts.ProviderMetadata {
	return p.base.Metadata(ctx)
}
func (p providerWrapper) StructuredCall(ctx context.Context, r contracts.AIRequest) (contracts.AIResult, error) {
	v, e := p.base.StructuredCall(ctx, r)
	if e == nil {
		p.mutate(&v.Plan)
	}
	return v, e
}

func orchestratorFixture(t *testing.T, mutate func(*domain.AIActionPlan)) (*Orchestrator, *catalogFixture, *runnerFixture, *ledgerFixture) {
	t.Helper()
	catalog := &catalogFixture{}
	runner := &runnerFixture{result: ExecutionResult{Verified: true, Verification: []domain.EvidenceRef{{ID: "ev_verify", Kind: "test", Digest: "sha256:verify"}}, CandidateDiff: "candidate diff"}}
	ledger := &ledgerFixture{records: map[domain.ID]LedgerEntry{}}
	return &Orchestrator{Enabled: true, Context: contextFixture{value: validContext()}, Provider: providerWithPlan(t, mutate), Catalog: catalog, Runner: runner, Ledger: ledger, PolicyVersion: "fake-policy-v1"}, catalog, runner, ledger
}

func TestAI_DEG_001RuleFirstAndDisabledDoNotExecuteAI(t *testing.T) {
	o, _, runner, ledger := orchestratorFixture(t, nil)
	request := requestFixture()
	request.RuleResolved = true
	got, err := o.Process(context.Background(), request)
	if err != nil || got.Status != "rule_resolved" || runner.calls != 0 || len(ledger.records) != 0 {
		t.Fatalf("rule-first=%+v err=%v", got, err)
	}
	request.RuleResolved = false
	o.Enabled = false
	got, err = o.Process(context.Background(), request)
	if !errors.Is(err, ErrDisabled) || !got.Degraded || runner.calls != 0 || len(ledger.records) != 0 {
		t.Fatalf("disabled=%+v err=%v", got, err)
	}
}

func TestAI_PLAN_001InvalidPlanIsRecordedAndNeverExecuted(t *testing.T) {
	o, _, runner, ledger := orchestratorFixture(t, func(plan *domain.AIActionPlan) { plan.SchemaVersion = "" })
	got, err := o.Process(context.Background(), requestFixture())
	if err == nil || got.Status != "plan_rejected" || runner.calls != 0 || len(ledger.records) != 1 {
		t.Fatalf("result=%+v err=%v records=%d", got, err, len(ledger.records))
	}
}

func TestAI_SEC_003R3OnlyCreatesControllerHandoff(t *testing.T) {
	o, _, runner, _ := orchestratorFixture(t, func(plan *domain.AIActionPlan) {
		plan.Actions[0].Risk = domain.AIRiskProductionChange
		plan.Actions[0].ToolID = "production.restart"
		plan.Actions[0].ExpectedResult = "restart requested through controller"
		plan.RequiresUserConfirmation = true
	})
	got, err := o.Process(context.Background(), requestFixture())
	if !errors.Is(err, ErrControllerHandoff) || !got.ControllerHandoff || runner.calls != 0 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestAI_DEG_002BudgetAndCatalogDenialDoNotExpandAuthority(t *testing.T) {
	o, catalog, runner, _ := orchestratorFixture(t, func(plan *domain.AIActionPlan) { plan.Budget.MaxTokens = 1000 })
	got, err := o.Process(context.Background(), requestFixture())
	if !errors.Is(err, ErrPolicyDenied) || got.Status != "budget_or_policy_denied" || runner.calls != 0 {
		t.Fatalf("budget=%+v err=%v", got, err)
	}
	o, catalog, runner, _ = orchestratorFixture(t, nil)
	catalog.err = errors.New("arbitrary shell denied")
	got, err = o.Process(context.Background(), requestFixture())
	if !errors.Is(err, ErrPolicyDenied) || got.Status != "tool_denied" || runner.calls != 0 {
		t.Fatalf("catalog=%+v err=%v", got, err)
	}
}

func TestAI_RUNNER_001VerificationFailureRollsBackAndReplayIsIdempotent(t *testing.T) {
	o, _, runner, ledger := orchestratorFixture(t, nil)
	runner.result.Verified = false
	runner.err = errors.New("sandbox timeout")
	got, err := o.Process(context.Background(), requestFixture())
	if !errors.Is(err, ErrVerificationFailed) || !got.Execution.RolledBack || runner.rollbacks != 1 || len(ledger.records) != 1 {
		t.Fatalf("first=%+v err=%v", got, err)
	}
	got, err = o.Process(context.Background(), requestFixture())
	if err != nil || got.Status != "rolled_back" || runner.calls != 1 || len(ledger.records) != 1 {
		t.Fatalf("replay=%+v err=%v records=%d", got, err, len(ledger.records))
	}
}
