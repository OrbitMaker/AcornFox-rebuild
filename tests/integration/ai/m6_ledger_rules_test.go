//go:build integration

package ai_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/ai/ledger"
	"github.com/open-card/open-card/internal/rules"
)

func TestM6PostgresLedgerRulesAndSettings(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	store := ledger.NewPostgres(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	invocation := ledger.Invocation{ID: "m6-inv-1", TaskType: "build_failure_diagnosis", ProblemFingerprint: "sha256:m6-problem", VersionKey: "sha256:m6-version", Provider: "fake", Model: "fake-v1", PolicyVersion: "policy-v1", Status: ledger.OutcomeSucceeded, Outcome: ledger.OutcomeSucceeded, Tokens: 7, DurationMS: 13, CreatedAt: now}
	first, replayed, err := store.AppendInvocation(ctx, ledger.AppendInvocationRequest{IdempotencyKey: "m6-ledger-1", RequestDigest: "sha256:m6-ledger-1", Record: invocation})
	if err != nil || replayed || first.ID != invocation.ID {
		t.Fatalf("append invocation: replay=%v record=%+v err=%v", replayed, first, err)
	}
	second, replayed, err := store.AppendInvocation(ctx, ledger.AppendInvocationRequest{IdempotencyKey: "m6-ledger-1", RequestDigest: "sha256:m6-ledger-1", Record: invocation})
	if err != nil || !replayed || second.ID != invocation.ID {
		t.Fatalf("replay invocation: replay=%v record=%+v err=%v", replayed, second, err)
	}
	if _, _, err := store.AppendInvocation(ctx, ledger.AppendInvocationRequest{IdempotencyKey: "m6-ledger-1", RequestDigest: "sha256:m6-conflict", Record: invocation}); !errors.Is(err, ledger.ErrConflict) {
		t.Fatalf("idempotency conflict=%v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m6_ai_invocations SET status='failed' WHERE id=$1`, invocation.ID); err == nil {
		t.Fatal("immutable invocation accepted UPDATE")
	}
	unsafe := invocation
	unsafe.ID = "m6-inv-secret"
	unsafe.Payload = map[string]any{"token": "plaintext-secret"}
	if _, _, err := store.AppendInvocation(ctx, ledger.AppendInvocationRequest{IdempotencyKey: "m6-ledger-secret", Record: unsafe}); !errors.Is(err, ledger.ErrSensitivePlaintext) {
		t.Fatalf("sensitive invocation was accepted: %v", err)
	}
	complete := ledger.Intervention{
		ID:            "m6-intervention-1",
		Invocation:    ledger.Invocation{ID: "m6-complete-inv", TaskType: "build_failure_diagnosis", ProblemFingerprint: "sha256:m6-complete", VersionKey: "sha256:m6-version", Provider: "fake", Model: "fake-v1", PolicyVersion: "policy-v1", Status: ledger.OutcomeSucceeded, Outcome: ledger.OutcomeSucceeded, Tokens: 9, DurationMS: 21, CreatedAt: now},
		Context:       &ledger.ContextPackage{ID: "m6-complete-context", Scope: []string{"build/log-window"}, Authorized: true, Redacted: true, TemplateVersion: "ctx-v1", SourceRefs: []ledger.Reference{{ID: "m6-evidence", Kind: "build-log", Digest: "sha256:m6-evidence"}}},
		Plan:          &ledger.ActionPlan{ID: "m6-complete-plan", TaskType: "build_failure_diagnosis", TargetRefs: map[string]string{"build": "m6-build"}, EvidenceRefs: []ledger.Reference{{ID: "m6-evidence", Kind: "build-log"}}, Actions: []string{"m6-complete-action"}, SchemaVersion: "1.0", Confidence: .7},
		Actions:       []ledger.ToolAction{{ID: "m6-complete-action", ToolID: "workspace.build_test", ToolVersion: "v1", RiskClass: "R1", ValidationID: "build.exit", Status: ledger.OutcomeSucceeded}},
		Verifications: []ledger.Verification{{ID: "m6-complete-verification", ValidatorID: "build.exit", Passed: true, EvidenceRefs: []ledger.Reference{{ID: "m6-verification", Kind: "verification", Digest: "sha256:m6-verification"}}}},
		Outcome:       &ledger.Outcome{ID: "m6-complete-outcome", Status: ledger.OutcomeSucceeded, Tokens: 9, DurationMS: 21, Summary: "isolated validation passed"},
		CandidateRef:  &ledger.CandidateRef{ID: "m6-complete-candidate-ref", CandidateID: "m6-candidate", Fingerprint: "sha256:m6-complete", Aggregation: "same-fingerprint"},
	}
	stored, replayed, err := store.AppendIntervention(ctx, ledger.AppendInterventionRequest{IdempotencyKey: "m6-intervention-key", RequestDigest: "sha256:m6-intervention", Record: complete})
	if err != nil || replayed || stored.Outcome == nil || len(stored.Actions) != 1 {
		t.Fatalf("complete intervention append: replay=%v stored=%+v err=%v", replayed, stored, err)
	}
	replayedRecord, replayed, err := store.AppendIntervention(ctx, ledger.AppendInterventionRequest{IdempotencyKey: "m6-intervention-key", RequestDigest: "sha256:m6-intervention", Record: complete})
	if err != nil || !replayed || replayedRecord.ID != complete.ID {
		t.Fatalf("complete intervention replay: replay=%v record=%+v err=%v", replayed, replayedRecord, err)
	}

	settings := ledger.AISettings{Version: 1, Enabled: true, Profile: ledger.ProfileLocal, Provider: "fake", Model: "fake-v1", DataScopes: []string{"summary"}, MaxTokens: 128, MaxDurationMS: 1000, Actor: "operator-1", CreatedAt: now}
	if _, _, err := store.AppendSettings(ctx, ledger.SettingsRequest{IdempotencyKey: "m6-settings-1", RequestDigest: "sha256:m6-settings-1", Settings: settings}); err != nil {
		t.Fatal(err)
	}
	current, err := store.CurrentSettings(ctx)
	if err != nil || current.Version != 1 || current.Profile != ledger.ProfileLocal {
		t.Fatalf("settings=%+v err=%v", current, err)
	}

	registry := rules.NewPostgres(db)
	fingerprint := "sha256:m6-rule"
	var candidate rules.RuleCandidate
	for i := 0; i < 2; i++ {
		candidate, _, err = registry.Aggregate(ctx, rules.Observation{IdempotencyKey: "m6-rule-observation-" + string(rune('a'+i)), Fingerprint: fingerprint, ApplicationID: "m6-app", Success: true, At: now.Add(time.Duration(i) * time.Second)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if candidate.SuccessCount != 2 || candidate.ApplicationCount != 1 || candidate.Status != rules.StatusDraft {
		t.Fatalf("candidate aggregation=%+v", candidate)
	}
	transition := func(to rules.Status, key string, extra rules.TransitionRequest) {
		extra.CandidateID, extra.To, extra.IdempotencyKey, extra.At = candidate.ID, to, key, now
		candidate, err = registry.Transition(ctx, extra)
		if err != nil {
			t.Fatal(err)
		}
	}
	transition(rules.StatusTesting, "m6-rule-testing", rules.TransitionRequest{})
	transition(rules.StatusReviewed, "m6-rule-reviewed", rules.TransitionRequest{Actor: "operator-1", ReviewDecision: "approved"})
	transition(rules.StatusShadow, "m6-rule-shadow", rules.TransitionRequest{RegressionPassed: true, TestEvidence: []rules.EvidenceRef{{ID: "m6-regression", Kind: "regression", Digest: "sha256:m6-regression"}}})
	transition(rules.StatusApproved, "m6-rule-approved", rules.TransitionRequest{ShadowPassed: true, ProposedVersion: "v1"})
	version, _, err := registry.Promote(ctx, rules.PromotionRequest{CandidateID: candidate.ID, Version: "v1", CodeDigest: "sha256:m6-rule-v1", IdempotencyKey: "m6-rule-promote-v1", Actor: "operator-1", At: now})
	if err != nil {
		t.Fatal(err)
	}
	if active, err := registry.Active(ctx, fingerprint); err != nil || active.ID != version.ID {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	if _, err := registry.Disable(ctx, rules.RegistryRequest{RuleVersionID: version.ID, IdempotencyKey: "m6-rule-disable-v1", Actor: "operator-1", At: now}); err != nil {
		t.Fatal(err)
	}
	metrics, err := registry.Metrics(ctx)
	if err != nil || metrics.Promoted != 1 || metrics.Versions != 1 {
		t.Fatalf("rule metrics=%+v err=%v", metrics, err)
	}
	if strings.TrimSpace(version.CodeDigest) == "" {
		t.Fatal("version lost immutable digest")
	}
}
