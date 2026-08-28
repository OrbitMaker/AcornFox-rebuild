package rules

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCandidateLifecycleRequiresReviewRegressionVersionAndShadow(t *testing.T) {
	registry := NewLocal()
	now := time.Unix(1_700_000_000, 0).UTC()
	fingerprint := "sha256:dockerfile-port"
	for i := 0; i < 2; i++ {
		candidate, replayed, err := registry.Aggregate(context.Background(), Observation{IdempotencyKey: "obs-" + string(rune('a'+i)), Fingerprint: fingerprint, InvocationID: "inv-" + string(rune('a'+i)), ApplicationID: "app-1", Success: true, At: now.Add(time.Duration(i) * time.Second)})
		if err != nil || replayed || candidate.SuccessCount != int64(i+1) {
			t.Fatalf("aggregate %d: candidate=%+v replay=%v err=%v", i, candidate, replayed, err)
		}
	}
	candidate, err := registry.GetCandidate(context.Background(), deterministicID("candidate", fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusApproved, IdempotencyKey: "skip-approved"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("direct approval accepted: %v", err)
	}
	if _, err := registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusTesting, IdempotencyKey: "candidate-testing"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusReviewed, IdempotencyKey: "candidate-reviewed", Actor: "operator-1", ReviewDecision: "approved", At: now}); err != nil {
		t.Fatal(err)
	}
	evidence := []EvidenceRef{{ID: "regression-1", Kind: "regression", Digest: "sha256:regression"}}
	if _, err := registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusShadow, IdempotencyKey: "candidate-shadow", RegressionPassed: true, TestEvidence: evidence, At: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusApproved, IdempotencyKey: "candidate-approved", ShadowPassed: true, ProposedVersion: "v1", At: now}); err != nil {
		t.Fatal(err)
	}
	version, replayed, err := registry.Promote(context.Background(), PromotionRequest{CandidateID: candidate.ID, Version: "v1", CodeDigest: "sha256:rule-v1", IdempotencyKey: "promote-v1", Actor: "operator-1", At: now})
	if err != nil || replayed || version.Version != "v1" {
		t.Fatalf("promotion: version=%+v replay=%v err=%v", version, replayed, err)
	}
	if duplicate, duplicateReplay, err := registry.Promote(context.Background(), PromotionRequest{CandidateID: candidate.ID, Version: "v1", CodeDigest: "sha256:rule-v1", IdempotencyKey: "promote-v1"}); err != nil || !duplicateReplay || duplicate.ID != version.ID {
		t.Fatalf("duplicate promotion replay=%v version=%+v err=%v", duplicateReplay, duplicate, err)
	}
	active, err := registry.Active(context.Background(), fingerprint)
	if err != nil || active.ID != version.ID {
		t.Fatalf("active v1=%+v err=%v", active, err)
	}
	if _, err := registry.Disable(context.Background(), RegistryRequest{RuleVersionID: version.ID, IdempotencyKey: "disable-v1", Actor: "operator-1", At: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Active(context.Background(), fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled rule remained active: %v", err)
	}
}

func TestRuleRegistryRollbackPreviousVersionAndMetrics(t *testing.T) {
	registry := NewLocal()
	now := time.Unix(1_700_000_100, 0).UTC()
	makeVersion := func(suffix, version string) RuleVersion {
		t.Helper()
		var candidate RuleCandidate
		for i := 0; i < 2; i++ {
			var err error
			candidate, _, err = registry.Aggregate(context.Background(), Observation{IdempotencyKey: suffix + "-obs-" + string(rune('a'+i)), Fingerprint: "sha256:rollback", ApplicationID: "app-" + suffix, Success: true, At: now.Add(time.Duration(i) * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
		}
		candidateID := candidate.ID
		var err error
		if candidate.Status == StatusDraft {
			_, err = registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusTesting, IdempotencyKey: suffix + "-testing"})
			if err != nil {
				t.Fatal(err)
			}
		}
		if candidate.Status <= StatusTesting {
			_, err = registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusReviewed, IdempotencyKey: suffix + "-reviewed", Actor: "operator", ReviewDecision: "approved"})
			if err != nil {
				t.Fatal(err)
			}
		}
		candidate, _ = registry.GetCandidate(context.Background(), candidateID)
		if candidate.Status == StatusReviewed {
			_, err = registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusShadow, IdempotencyKey: suffix + "-shadow", RegressionPassed: true, TestEvidence: []EvidenceRef{{ID: suffix + "-reg", Kind: "regression"}}})
			if err != nil {
				t.Fatal(err)
			}
		}
		candidate, _ = registry.GetCandidate(context.Background(), candidateID)
		if candidate.Status == StatusShadow {
			_, err = registry.Transition(context.Background(), TransitionRequest{CandidateID: candidate.ID, To: StatusApproved, IdempotencyKey: suffix + "-approved", ShadowPassed: true, ProposedVersion: version})
			if err != nil {
				t.Fatal(err)
			}
		}
		got, _, err := registry.Promote(context.Background(), PromotionRequest{CandidateID: candidate.ID, Version: version, CodeDigest: "sha256:" + suffix, IdempotencyKey: suffix + "-promote"})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	first := makeVersion("first", "v1")
	if _, err := registry.Disable(context.Background(), RegistryRequest{RuleVersionID: first.ID, IdempotencyKey: "disable-first"}); err != nil {
		t.Fatal(err)
	}
	second := makeVersion("second", "v2")
	rolled, err := registry.Rollback(context.Background(), RegistryRequest{RuleVersionID: second.ID, IdempotencyKey: "rollback-second", Actor: "operator", At: now})
	if err != nil || rolled.ID != first.ID {
		t.Fatalf("rollback=%+v err=%v", rolled, err)
	}
	active, err := registry.Active(context.Background(), "sha256:rollback")
	if err != nil || active.ID != first.ID {
		t.Fatalf("active after rollback=%+v err=%v", active, err)
	}
	metrics, err := registry.Metrics(context.Background())
	if err != nil || metrics.Rollbacks != 1 || metrics.Versions != 2 || metrics.Observations != 4 {
		t.Fatalf("metrics=%+v err=%v", metrics, err)
	}
}
