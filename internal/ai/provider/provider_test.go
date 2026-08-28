package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func testRequest(key string) contracts.AIRequest {
	return contracts.AIRequest{
		TaskType: "build_failure_diagnosis",
		Context: domain.AIContextPackage{
			ID: domain.ID("ctx_build_1"), ApplicationID: domain.ID("app_1"), TaskType: "build_failure_diagnosis", Profile: string(ProfileLocal),
			Scope: []string{"source.files", "build.logs", "objects.versions"}, ObjectVersions: map[string]string{"build": "build-v1"},
			SourceRefs: []domain.EvidenceRef{{ID: domain.ID("ev_context"), Kind: "ai.context", Digest: "sha256:context"}}, ManifestDigest: "sha256:manifest", Bytes: 64,
			Authorized: true, Redacted: true, UntrustedData: true, TemplateVersion: "ctx-v1",
		},
		Budget:    contracts.TokenBudget{MaxTokens: 64, MaxDuration: time.Second},
		Operation: contracts.OperationContext{IdempotencyKey: key},
	}
}

func TestCTAI001ProfileCapabilitiesAndStructuredOnlyResponse(t *testing.T) {
	for _, profile := range []Profile{ProfileChina, ProfileGlobal, ProfileLocal} {
		p := NewFake(profile)
		caps := p.Capabilities()
		if !caps.StructuredOutput || !caps.ToolPlanning || caps.ExternalNetwork {
			t.Fatalf("profile %s capability matrix is unsafe: %#v", profile, caps)
		}
		request := testRequest(string(profile))
		request.Context.Profile = string(profile)
		result, err := p.StructuredCall(context.Background(), request)
		if err != nil {
			t.Fatalf("profile %s call: %v", profile, err)
		}
		if result.Invocation.Provider == "" || result.Invocation.Model == "" || result.Plan.ID.Empty() || len(result.Plan.Actions) != 1 {
			t.Fatalf("profile %s incomplete structured response: %#v", profile, result)
		}
		if err := result.Plan.Validate(); err != nil {
			t.Fatalf("profile %s returned invalid plan: %v", profile, err)
		}
		if result.Invocation.Profile != string(profile) || result.Plan.SchemaVersion != "1.0" || result.Plan.PolicyVersion == "" || result.Plan.Actions[0].Risk != domain.AIRiskReadOnly || result.Plan.Actions[0].ExpectedResult == "" || result.Plan.Budget.MaxActions != 1 {
			t.Fatalf("profile %s response missed strict structured fields: %#v", profile, result)
		}
		if result.Evidence.Redacted == false || result.Evidence.Summary == "" {
			t.Fatalf("profile %s response is not marked redacted: %#v", profile, result.Evidence)
		}
	}
	disabled := NewFake(ProfileDisabled)
	if disabled.Metadata(context.Background()).Capabilities.Has(contracts.CapabilityAI) {
		t.Fatal("disabled profile declared callable AI capability")
	}
	disabledRequest := testRequest("disabled")
	disabledRequest.Context.Profile = string(ProfileDisabled)
	_, err := disabled.StructuredCall(context.Background(), disabledRequest)
	if !errors.Is(err, ErrDisabled) || !contracts.IsUnsupported(err) || DegradationOf(err) != DegradationDisabled {
		t.Fatalf("disabled profile was not classified: err=%v degradation=%s", err, DegradationOf(err))
	}
	if fallback := FallbackFor(err); !fallback.ContinueCoreFlow || !fallback.UseDeterministicRule {
		t.Fatalf("disabled profile did not preserve deterministic fallback: %#v", fallback)
	}
}

func TestAIDeg002TimeoutBudgetCooldownAndCacheDegradeWithoutPermissionExpansion(t *testing.T) {
	p, err := New(Config{Profile: ProfileLocal, Available: true, CacheEnabled: true, Delay: 20 * time.Millisecond, Clock: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil || p == nil {
		t.Fatal("provider unexpectedly nil")
	}
	request := testRequest("first")
	request.Budget.MaxDuration = time.Millisecond
	_, err = p.StructuredCall(context.Background(), request)
	if DegradationOf(err) != DegradationTimeout {
		t.Fatalf("timeout was not classified: err=%v degradation=%s", err, DegradationOf(err))
	}

	p2 := NewFake(ProfileLocal)
	request = testRequest("budget")
	request.Budget.MaxTokens = 0
	outcome, err := p2.Invoke(context.Background(), request)
	if !errors.Is(err, ErrBudgetExceeded) || outcome.Degradation != DegradationBudget || !outcome.Fallback.ContinueCoreFlow {
		t.Fatalf("budget fallback is unsafe or misclassified: outcome=%#v err=%v", outcome, err)
	}

	now := time.Unix(200, 0).UTC()
	p3, err := New(Config{Profile: ProfileLocal, Available: true, CacheEnabled: false, Cooldown: time.Minute, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request = testRequest("cooldown")
	if _, err := p3.StructuredCall(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	outcome, err = p3.Invoke(context.Background(), request)
	if !errors.Is(err, ErrCooldownActive) || outcome.Degradation != DegradationCooldown {
		t.Fatalf("cooldown was not classified: outcome=%#v err=%v", outcome, err)
	}

	p4, err := New(Config{Profile: ProfileLocal, Available: true, CacheEnabled: true, Cooldown: time.Minute, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request = testRequest("cache")
	first, err := p4.Invoke(context.Background(), request)
	if err != nil || first.Status != OutcomeSucceeded {
		t.Fatalf("initial call did not succeed: %#v %v", first, err)
	}
	p4.SetAvailable(false)
	cached, err := p4.Invoke(context.Background(), request)
	if err != nil || cached.Status != OutcomeCached || !cached.ServedFromCache || cached.Degradation != DegradationCache {
		t.Fatalf("cache degradation did not preserve bounded result: %#v %v", cached, err)
	}
	if !cached.Result.Invocation.Cached {
		t.Fatal("cached invocation did not expose cache provenance")
	}
	if cached.Fallback.UseDeterministicRule || !cached.Fallback.ContinueCoreFlow {
		t.Fatalf("cache path unexpectedly changed fallback policy: %#v", cached.Fallback)
	}
}

func TestAIDeg003UnavailableFallsBackWithoutExternalAccess(t *testing.T) {
	p := NewFake(ProfileGlobal)
	p.SetAvailable(false)
	request := testRequest("unavailable")
	request.Context.Profile = string(ProfileGlobal)
	outcome, err := p.Invoke(context.Background(), request)
	if err == nil || DegradationOf(err) != DegradationUnavailable {
		t.Fatalf("unavailable provider was not classified: outcome=%#v err=%v", outcome, err)
	}
	if !outcome.Fallback.ContinueCoreFlow || !outcome.Fallback.AskMinimalQuestion || !outcome.Fallback.ManualDraft || !outcome.Fallback.UseDeterministicRule {
		t.Fatalf("unavailable fallback is incomplete: %#v", outcome.Fallback)
	}
}

func TestAIDeg003ExplicitUnavailableConfigDoesNotCallOutsideProcess(t *testing.T) {
	p, err := New(Config{Profile: ProfileChina, Unavailable: true, CacheEnabled: false})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("explicit-unavailable")
	request.Context.Profile = string(ProfileChina)
	if _, err := p.StructuredCall(context.Background(), request); DegradationOf(err) != DegradationUnavailable {
		t.Fatalf("explicit unavailable config was not classified: %v", err)
	}
	if p.Capabilities().ExternalNetwork {
		t.Fatal("fake provider advertised external network access")
	}
}

func TestAIProfile001UnknownProfileRejected(t *testing.T) {
	if _, err := New(Config{Profile: Profile("remote")}); err == nil {
		t.Fatal("unknown profile was silently accepted")
	}
	for input, expected := range map[string]Profile{"cn": ProfileChina, "global": ProfileGlobal, "本地": ProfileLocal, "off": ProfileDisabled} {
		got, err := ParseProfile(input)
		if err != nil || got != expected {
			t.Fatalf("profile %q parsed as %q/%v, want %q", input, got, err, expected)
		}
	}
}

func TestAICacheKeySeparatesContextManifestVersions(t *testing.T) {
	p := NewFake(ProfileLocal)
	first := testRequest("cache-version-1")
	first.Context.Profile = string(ProfileLocal)
	second := first
	second.Operation.IdempotencyKey = "cache-version-2"
	second.Context.ManifestDigest = "sha256:changed"
	if p.CacheKey(first) == p.CacheKey(second) {
		t.Fatal("cache key ignored the context manifest version")
	}
}

func TestAIProviderIdempotencyKeyRejectsDifferentRequest(t *testing.T) {
	p := NewFake(ProfileLocal)
	first := testRequest("same-operation")
	first.Context.Profile = string(ProfileLocal)
	if _, err := p.StructuredCall(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TaskType = "definition_fill"
	if _, err := p.StructuredCall(context.Background(), second); err == nil {
		t.Fatal("idempotency conflict was not classified")
	} else {
		var providerErr *contracts.ProviderError
		if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrConflict {
			t.Fatalf("idempotency conflict was not classified: %v", err)
		}
	}
}

func TestAIProviderContextDeadlineClassifiesConfiguredDelay(t *testing.T) {
	p := NewFake(ProfileLocal)
	p.SetDelay(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	request := testRequest("context-deadline")
	request.Context.Profile = string(ProfileLocal)
	_, err := p.StructuredCall(ctx, request)
	if DegradationOf(err) != DegradationTimeout {
		t.Fatalf("context deadline was not classified: %v", err)
	}
}
