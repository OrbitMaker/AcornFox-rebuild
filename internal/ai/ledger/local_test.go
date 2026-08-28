package ledger

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLocalInterventionIsAppendOnlyAndRestartReplayable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := NewLocal()
	input := AppendInterventionRequest{
		IdempotencyKey: "ai-int-1",
		RequestDigest:  "sha256:ai-int-1",
		Record: Intervention{
			ID:            "intervention-1",
			Invocation:    Invocation{ID: "inv-1", TaskType: "build_failure_diagnosis", ProblemFingerprint: "sha256:problem", VersionKey: "sha256:version", Provider: "fake", Model: "fake-v1", PolicyVersion: "policy-v1", Status: OutcomeSucceeded, Outcome: OutcomeSucceeded, Tokens: 11, DurationMS: 23, CreatedAt: now},
			Context:       &ContextPackage{ID: "ctx-1", Scope: []string{"build/log-window"}, Authorized: true, Redacted: true, TemplateVersion: "ctx-v1", SourceRefs: []Reference{{ID: "ev-1", Kind: "build-log", Digest: "sha256:evidence"}}},
			Plan:          &ActionPlan{ID: "plan-1", TaskType: "build_failure_diagnosis", TargetRefs: map[string]string{"build": "build-1"}, EvidenceRefs: []Reference{{ID: "ev-1", Kind: "build-log"}}, Actions: []string{"action-1"}, SchemaVersion: "1.0", Confidence: .8},
			Actions:       []ToolAction{{ID: "action-1", ToolID: "workspace.build_test", ToolVersion: "v1", RiskClass: "R1", ValidationID: "build.exit", Sequence: 0, Status: OutcomeSucceeded, TimeoutMS: 5000}},
			Verifications: []Verification{{ID: "verify-1", ValidatorID: "build.exit", Passed: true, EvidenceRefs: []Reference{{ID: "ev-2", Kind: "verification"}}}},
			Outcome:       &Outcome{ID: "outcome-1", Status: OutcomeSucceeded, Tokens: 11, DurationMS: 23, Summary: "validated in isolated workspace"},
			CandidateRef:  &CandidateRef{ID: "candidate-ref-1", CandidateID: "candidate-1", Fingerprint: "sha256:problem", Aggregation: "same-fingerprint"},
		},
	}
	first, replayed, err := store.AppendIntervention(context.Background(), input)
	if err != nil || replayed || first.Invocation.ID != "inv-1" || first.Context == nil || first.Plan == nil || len(first.Actions) != 1 || first.Outcome == nil {
		t.Fatalf("first append: replay=%v err=%v result=%+v", replayed, err, first)
	}
	second, replayed, err := store.AppendIntervention(context.Background(), input)
	if err != nil || !replayed || second.ID != first.ID {
		t.Fatalf("replay: replay=%v err=%v result=%+v", replayed, err, second)
	}
	conflict := input
	conflict.RequestDigest = "sha256:different"
	if _, _, err := store.AppendIntervention(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency conflict = %v", err)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewLocalFromSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetIntervention(context.Background(), "intervention-1")
	if err != nil || got.Invocation.Tokens != 11 || got.Outcome == nil || got.Outcome.DurationMS != 23 {
		t.Fatalf("restart replay: got=%+v err=%v", got, err)
	}
}

func TestLocalLedgerRejectsSensitivePlaintextAndAllowsReferences(t *testing.T) {
	store := NewLocal()
	base := Invocation{ID: "inv-secret", TaskType: "diagnose", ProblemFingerprint: "sha256:p", VersionKey: "sha256:v", Provider: "fake", Model: "fake", PolicyVersion: "v1", Status: OutcomeFailed, CreatedAt: time.Now().UTC()}
	base.Payload = map[string]any{"token": "do-not-store"}
	if _, _, err := store.AppendInvocation(context.Background(), AppendInvocationRequest{IdempotencyKey: "secret-1", Record: base}); !errors.Is(err, ErrSensitivePlaintext) {
		t.Fatalf("plaintext token accepted: %v", err)
	}
	base.ID = "inv-reference"
	base.Payload = map[string]any{"token_ref": "secret://provider/key/1", "summary": "redacted"}
	if _, _, err := store.AppendInvocation(context.Background(), AppendInvocationRequest{IdempotencyKey: "secret-2", Record: base}); err != nil {
		t.Fatalf("secret reference rejected: %v", err)
	}
	if err := ValidateNoPlaintext(map[string]any{"authorization": "Bearer abcdefgh"}); !errors.Is(err, ErrSensitivePlaintext) {
		t.Fatalf("bearer token accepted: %v", err)
	}
}

func TestLedgerValidationRejectsOpaqueAndNestedSensitiveValues(t *testing.T) {
	type nestedPayload struct {
		Token string `json:"token"`
	}
	if err := ValidateNoPlaintext(nestedPayload{Token: "plaintext-value"}); !errors.Is(err, ErrSensitivePlaintext) {
		t.Fatalf("nested sensitive struct was accepted: %v", err)
	}
	type opaquePayload struct {
		Callback func() `json:"callback"`
	}
	if err := ValidateNoPlaintext(opaquePayload{Callback: func() {}}); !errors.Is(err, ErrSensitivePlaintext) {
		t.Fatalf("uninspectable structured value was accepted: %v", err)
	}
}

func TestLocalSettingsAreStrictlyVersionedAndDisabledFailsClosed(t *testing.T) {
	store := NewLocal()
	_, _, err := store.AppendSettings(context.Background(), SettingsRequest{IdempotencyKey: "settings-1", Settings: AISettings{Version: 1, Enabled: true, Profile: ProfileDisabled, Provider: "fake", Model: "v1", DataScopes: []string{"summary"}, Actor: "operator", CreatedAt: time.Now().UTC()}})
	if err == nil {
		t.Fatal("disabled profile was enabled")
	}
	settings := AISettings{Version: 1, Enabled: true, Profile: ProfileLocal, Provider: "fake", Model: "v1", DataScopes: []string{"summary"}, MaxTokens: 128, MaxDurationMS: 1000, Actor: "operator", CreatedAt: time.Now().UTC()}
	if _, replayed, err := store.AppendSettings(context.Background(), SettingsRequest{IdempotencyKey: "settings-1", RequestDigest: "sha256:settings-1", Settings: settings}); err != nil || replayed {
		t.Fatalf("settings append: replay=%v err=%v", replayed, err)
	}
	if _, replayed, err := store.AppendSettings(context.Background(), SettingsRequest{IdempotencyKey: "settings-1", RequestDigest: "sha256:settings-1", Settings: settings}); err != nil || !replayed {
		t.Fatalf("settings replay: replay=%v err=%v", replayed, err)
	}
	settings.Version = 2
	settings.Enabled = false
	settings.Profile = ProfileDisabled
	settings.Provider, settings.Model = "", ""
	settings.CreatedAt = settings.CreatedAt.Add(time.Second)
	if _, _, err := store.AppendSettings(context.Background(), SettingsRequest{IdempotencyKey: "settings-2", Settings: settings}); err != nil {
		t.Fatalf("disabled settings append: %v", err)
	}
	current, err := store.CurrentSettings(context.Background())
	if err != nil || current.Version != 2 || current.Profile != ProfileDisabled || current.Enabled {
		t.Fatalf("current settings=%+v err=%v", current, err)
	}
}
