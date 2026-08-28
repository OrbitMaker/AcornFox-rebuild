package domain

import "testing"

func TestTLSAllowStateRequiresVerifiedDesiredHealthyAndEnabledFacts(t *testing.T) {
	allowed := TLSAllowState{Domain: "app.example.test", DNSVerified: true, RouteDesired: true, RuntimeReady: true}
	if !allowed.Allowed() {
		t.Fatal("complete TLS allow state was rejected")
	}
	for _, value := range []TLSAllowState{
		{Domain: "app.example.test", RouteDesired: true, RuntimeReady: true},
		{Domain: "app.example.test", DNSVerified: true, RuntimeReady: true},
		{Domain: "app.example.test", DNSVerified: true, RouteDesired: true},
		{Domain: "app.example.test", DNSVerified: true, RouteDesired: true, RuntimeReady: true, DisabledOrFailed: true},
	} {
		if value.Allowed() {
			t.Fatalf("incomplete TLS allow state passed: %#v", value)
		}
	}
}

func TestNormalizeTLSAllowDomainRejectsNonDNSNames(t *testing.T) {
	if value, err := NormalizeTLSAllowDomain("App.Example.Test."); err != nil || value != "app.example.test" {
		t.Fatalf("normalized TLS allow domain = %q, %v", value, err)
	}
	for _, value := range []string{"", "localhost", "127.0.0.1", "app.example.test/path", "bad host.example.test"} {
		if _, err := NormalizeTLSAllowDomain(value); err == nil {
			t.Fatalf("invalid TLS allow domain accepted: %q", value)
		}
	}
}
