package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestUNIT_STATE_001_StateMachinesRejectIllegalTransitions(t *testing.T) {
	tests := []struct {
		name       string
		from       string
		to         string
		valid      bool
		transition func() error
	}{
		{"release draft ready", string(ReleaseDraft), string(ReleaseReady), true, func() error { return ReleaseDraft.Transition(ReleaseReady) }},
		{"release ready draft", string(ReleaseReady), string(ReleaseDraft), false, func() error { return ReleaseReady.Transition(ReleaseDraft) }},
		{"release failed ready", string(ReleaseFailed), string(ReleaseReady), false, func() error { return ReleaseFailed.Transition(ReleaseReady) }},
		{"deployment pending preparing", string(DeploymentPending), string(DeploymentPreparing), true, func() error { return DeploymentPending.Transition(DeploymentPreparing) }},
		{"deployment pending serving", string(DeploymentPending), string(DeploymentServing), false, func() error { return DeploymentPending.Transition(DeploymentServing) }},
		{"deployment runtime ready serving", string(DeploymentRuntimeReady), string(DeploymentServing), true, func() error { return DeploymentRuntimeReady.Transition(DeploymentServing) }},
		{"deployment serving preparing", string(DeploymentServing), string(DeploymentPreparing), false, func() error { return DeploymentServing.Transition(DeploymentPreparing) }},
		{"operation pending running", string(OperationPending), string(OperationRunning), true, func() error { return OperationPending.Transition(OperationRunning) }},
		{"operation pending leased", string(OperationPending), string(OperationLeased), true, func() error { return OperationPending.Transition(OperationLeased) }},
		{"operation leased running", string(OperationLeased), string(OperationRunning), true, func() error { return OperationLeased.Transition(OperationRunning) }},
		{"operation running cancelling", string(OperationRunning), string(OperationCancelling), true, func() error { return OperationRunning.Transition(OperationCancelling) }},
		{"operation cancelling cancelled", string(OperationCancelling), string(OperationCancelled), true, func() error { return OperationCancelling.Transition(OperationCancelled) }},
		{"operation succeeded running", string(OperationSucceeded), string(OperationRunning), false, func() error { return OperationSucceeded.Transition(OperationRunning) }},
		{"operation running cancelled", string(OperationRunning), string(OperationCancelled), true, func() error { return OperationRunning.Transition(OperationCancelled) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.transition()
			if test.valid && err != nil {
				t.Fatalf("expected transition to be valid: %v", err)
			}
			if !test.valid {
				if err == nil {
					t.Fatal("expected illegal transition to be rejected")
				}
				var domainErr *DomainError
				if !errors.As(err, &domainErr) || domainErr.Code != ErrInvalidTransition {
					t.Fatalf("expected invalid_transition, got %T %v", err, err)
				}
			}
		})
	}
}

func TestOperationTerminalStatesAreExplicit(t *testing.T) {
	for _, status := range []OperationStatus{OperationSucceeded, OperationFailed, OperationCancelled, OperationRolledBack} {
		if !status.IsTerminal() {
			t.Fatalf("expected %s to be terminal", status)
		}
	}
	for _, status := range []OperationStatus{OperationPending, OperationLeased, OperationRunning, OperationWaiting, OperationCancelling, OperationRollingBack} {
		if status.IsTerminal() {
			t.Fatalf("expected %s to remain non-terminal", status)
		}
	}
}

func TestSCHEMA_RELEASE_001_ReleaseIsImmutableAndDigestSetIsCopied(t *testing.T) {
	applicationID := ID("app_test")
	groupID := ID("group_test")
	digest := ImageDigest{Repository: "example/app", Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	input := map[string]ImageDigest{"web": digest}
	release, err := NewRelease(applicationID, groupID, 1, "sha256:abcdef", input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !release.IsImmutable() {
		t.Fatal("complete release must be immutable")
	}
	if err := release.AddServiceDigest("worker", digest); !IsCode(err, ErrImmutable) {
		t.Fatalf("expected immutable error, got %v", err)
	}
	copyOfDigests := release.ServiceDigests()
	copyOfDigests["web"] = ImageDigest{Repository: "tampered", Digest: digest.Digest}
	if got := release.ServiceDigests()["web"].Repository; got != digest.Repository {
		t.Fatalf("release digest map leaked mutable alias: %q", got)
	}
	input["web"] = ImageDigest{Repository: "tampered", Digest: digest.Digest}
	if got := release.ServiceDigests()["web"].Repository; got != digest.Repository {
		t.Fatalf("release constructor retained mutable input alias: %q", got)
	}
	encoded, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Release
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.IsImmutable() || len(decoded.ServiceDigests()) != 1 {
		t.Fatalf("release JSON did not preserve immutable digest set: %#v", decoded)
	}
	if err := decoded.AddServiceDigest("worker", digest); !IsCode(err, ErrImmutable) {
		t.Fatalf("decoded release became mutable: %v", err)
	}
}

func TestSCHEMA_DEF_002_DefinitionSeparatesFactsObservationsAndRecommendations(t *testing.T) {
	evidence := EvidenceRef{ID: ID("ev_1"), Kind: "scanner", Digest: "sha256:evidence"}
	definition := ApplicationDeliveryDefinition{
		ID: ID("def_1"), ApplicationID: ID("app_1"), SourceRevisionID: ID("src_1"), Version: 1, Immutable: true,
		Facts:           map[string]FieldFact{"port": {Value: 8080, Source: FactSourceRepository, Confidence: 1, Evidence: []EvidenceRef{evidence}, Status: FactConfirmed}},
		Observations:    []Observation{{ID: ID("obs_1"), TargetRef: "deployment/1", Kind: "health", Value: "healthy", Source: "agent", Evidence: []EvidenceRef{evidence}}},
		Recommendations: []Recommendation{{ID: ID("rec_1"), TargetRef: "port", Reason: "observed mismatch", Proposed: 8081, Status: RecommendationOpen, Evidence: []EvidenceRef{evidence}}},
	}
	if err := definition.Validate(); err != nil {
		t.Fatal(err)
	}
	if definition.Facts["port"].Value != 8080 {
		t.Fatal("configuration fact was overwritten by observation/recommendation")
	}
	if got, ok := definition.ConfigFact("port"); !ok || got.Value != 8080 {
		t.Fatal("configuration fact lookup failed")
	}
}

func TestSCHEMA_DEF_001_DefinitionRejectsAutomaticFactWithoutMetadata(t *testing.T) {
	definition := ApplicationDeliveryDefinition{ID: ID("def_1"), ApplicationID: ID("app_1"), SourceRevisionID: ID("src_1"), Version: 1, Immutable: true, Facts: map[string]FieldFact{"port": {Value: 8080, Source: FactSourceAI, Confidence: 0.8, Status: FactProposed}}}
	if err := definition.Validate(); err == nil {
		t.Fatal("expected automatic fact without evidence to be rejected")
	}
}

func TestUNIT_DAG_001_And_002_ServiceDependencyOrderRejectsCycles(t *testing.T) {
	image := ImageDigest{Repository: "example/app", Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	group := ServiceGroup{ID: ID("group_1"), ApplicationID: ID("app_1"), Services: []ServiceSpec{
		{Name: "api", Role: RoleIngress, Required: true, Source: ServiceSource{Kind: ServicePrebuilt, Prebuilt: &PrebuiltSource{Image: image}}, Dependencies: []ServiceDependency{{Service: "db", Condition: DependsHealthy}}},
		{Name: "db", Role: RoleStateful, Required: true, Source: ServiceSource{Kind: ServicePrebuilt, Prebuilt: &PrebuiltSource{Image: image}}},
	}}
	order, err := group.DependencyOrder()
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "db" || order[1] != "api" {
		t.Fatalf("unexpected dependency order: %#v", order)
	}
	group.Services[1].Dependencies = []ServiceDependency{{Service: "api", Condition: DependsStarted}}
	if _, err := group.DependencyOrder(); err == nil {
		t.Fatal("expected dependency cycle to be rejected")
	}
}
