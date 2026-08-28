package dnsfixture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

func operation(key string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key}
}

func providerCode(err error) contracts.ErrorCode {
	var value *contracts.ProviderError
	if errors.As(err, &value) {
		return value.Code
	}
	return ""
}

func TestPlatformDomainCNAMEAndRestartFixture(t *testing.T) {
	state := filepath.Join(t.TempDir(), "dns-state.json")
	provider, err := New(Config{StatePath: state})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := provider.BindPlatformDomain(context.Background(), "Platform.Fixture.Test.", "gateway.fixture.test", operation("platform-bind"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.VerifyPlatformDomain(context.Background(), binding, operation("platform-verify")); err != nil {
		t.Fatal(err)
	}
	if binding.Wildcard != "*.platform.fixture.test" || StableSlug("Hello, World!") != StableSlug("Hello, World!") {
		t.Fatalf("binding or stable slug was not deterministic: %#v", binding)
	}

	app := CNAMEBinding{Host: "app.customer.fixture.test", Target: "gateway.fixture.test"}
	if _, err := provider.VerifyApplicationCNAME(context.Background(), app, operation("app-verify-missing")); providerCode(err) != contracts.ErrNotFound {
		t.Fatalf("unbound CNAME was accepted: %v", err)
	}
	app, err = provider.BindApplicationCNAME(context.Background(), app.Host, app.Target, operation("app-bind"))
	if err != nil {
		t.Fatal(err)
	}
	app, err = provider.VerifyApplicationCNAME(context.Background(), app, operation("app-verify"))
	if err != nil || !app.Verified {
		t.Fatalf("CNAME was not verified: %#v %v", app, err)
	}

	restarted, err := New(Config{StatePath: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.VerifyApplicationCNAME(context.Background(), app, operation("app-verify-after-restart")); err != nil {
		t.Fatalf("file fixture did not survive restart: %v", err)
	}
	contents, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "PRIVATE KEY") {
		t.Fatalf("DNS fixture persisted key material")
	}
}

func TestDNS01IdempotencyTimeoutAndRedaction(t *testing.T) {
	provider, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := provider.PresentDNS01(context.Background(), "app.fixture.test", "challenge-secret-token", operation("present"))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := provider.PresentDNS01(context.Background(), "app.fixture.test", "challenge-secret-token", operation("present"))
	if err != nil || retry.Name != challenge.Name {
		t.Fatalf("DNS-01 retry was not idempotent: %#v %v", retry, err)
	}
	if _, err := provider.PresentDNS01(context.Background(), "other.fixture.test", "changed-token", operation("present")); providerCode(err) != contracts.ErrConflict {
		t.Fatalf("idempotency conflict was not rejected: %v", err)
	}
	encoded, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "challenge-secret-token") || strings.Contains(provider.String(), "challenge-secret-token") {
		t.Fatalf("DNS-01 token leaked through safe output")
	}
	if err := provider.SetFault(Fault{Operation: "verify_dns01", Delay: 20 * time.Millisecond, Remaining: 1}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Millisecond)
	err = provider.VerifyDNS01(context.Background(), challenge, contracts.OperationContext{IdempotencyKey: "timeout", Deadline: deadline})
	if providerCode(err) != contracts.ErrTimeout {
		t.Fatalf("fault did not honor deadline: %v", err)
	}
	if err := provider.CleanupDNS01(context.Background(), challenge, operation("cleanup")); err != nil {
		t.Fatal(err)
	}
	for _, record := range provider.Records() {
		if strings.HasPrefix(record.Name, "_acme-challenge.") {
			t.Fatalf("DNS-01 record survived cleanup: %#v", record)
		}
	}
}

func TestFaultInjectionDoesNotNeedNetwork(t *testing.T) {
	provider, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.SetFault(Fault{Operation: "bind_cname", Code: contracts.ErrUnavailable, Message: "test outage", Remaining: 1}); err != nil {
		t.Fatal(err)
	}
	_, err = provider.BindApplicationCNAME(context.Background(), "app.fixture.test", "gateway.fixture.test", operation("outage"))
	if providerCode(err) != contracts.ErrUnavailable {
		t.Fatalf("fixture fault was not returned: %v", err)
	}
}
