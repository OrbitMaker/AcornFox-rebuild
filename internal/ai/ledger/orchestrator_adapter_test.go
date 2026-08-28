package ledger

import (
	"context"
	"testing"

	"github.com/open-card/open-card/internal/ai/orchestrator"
	"github.com/open-card/open-card/internal/domain"
)

func TestLocalImplementsOrchestratorLedgerWithoutRawBodies(t *testing.T) {
	var _ orchestrator.Ledger = (*LocalStore)(nil)
	store := NewLocal()
	entry := orchestrator.LedgerEntry{
		Record:         domain.AIInterventionRecord{ID: "airec_adapter", ApplicationID: "app_adapter", ProblemFingerprint: "sha256:adapter", InvocationID: "aiinv_adapter", PlanID: "aiplan_adapter", Outcome: "succeeded", Tokens: 3, DurationMS: 4},
		Invocation:     domain.AIInvocation{ID: "aiinv_adapter", Provider: "fake", Model: "fake-v1", Profile: "local", PolicyVersion: "policy-v1", ProblemFingerprint: "sha256:adapter", ContextID: "aictx_adapter", Tokens: 3, DurationMS: 4, Status: "succeeded"},
		Context:        domain.AIContextPackage{ID: "aictx_adapter", ApplicationID: "app_adapter", TaskType: "diagnose", Profile: "local", Scope: []string{"objects.versions"}, ObjectVersions: map[string]string{"build": "v1"}, SourceRefs: []domain.EvidenceRef{{ID: "ev_adapter", Kind: "summary", Digest: "sha256:adapter"}}, ManifestDigest: "sha256:adapter-manifest", Bytes: 10, Authorized: true, Redacted: true, UntrustedData: true, TemplateVersion: "context-v1"},
		Plan:           domain.AIActionPlan{ID: "aiplan_adapter", SchemaVersion: "1.0", PolicyVersion: "policy-v1", TaskType: "diagnose", TargetRefs: map[string]string{"build": "build-1"}, EvidenceRefs: []domain.EvidenceRef{{ID: "ev_adapter", Kind: "summary"}}, Actions: []domain.AIAction{{ToolID: "fake.readonly", ToolVersion: "v1", Risk: domain.AIRiskReadOnly, ValidationID: "independent"}}, Confidence: .9},
		Execution:      &orchestrator.ExecutionResult{Verified: true, Verification: []domain.EvidenceRef{{ID: "ev_verify", Kind: "verification", Digest: "sha256:verify"}}},
		IdempotencyKey: "adapter-1", RequestDigest: "sha256:adapter-request",
	}
	stored, err := store.Append(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Lookup(context.Background(), entry.Record.ID)
	if err != nil || !ok || got.Record.Outcome != "succeeded" || got.Plan.ID == "" || len(got.Plan.Actions) != 1 {
		t.Fatalf("lookup ok=%v err=%v entry=%+v", ok, err, got)
	}
	if stored.Record.ID != entry.Record.ID {
		t.Fatalf("stored entry changed identity: %+v", stored)
	}
	second := entry
	second.Record.ID = "airec_adapter_2"
	second.IdempotencyKey = "adapter-2"
	second.RequestDigest = "sha256:adapter-request-2"
	if _, err := store.Append(context.Background(), second); err != nil {
		t.Fatalf("repeated provider invocation ID must be occurrence-namespaced: %v", err)
	}
}
