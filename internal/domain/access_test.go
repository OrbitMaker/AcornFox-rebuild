package domain

import "testing"

func TestStableApplicationHost(t *testing.T) {
	first, err := StableApplicationHost("CRM Console", "app_123", "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	second, err := StableApplicationHost("CRM Console", "app_123", "example.com")
	if err != nil || first != second || first[:12] != "crm-console-" {
		t.Fatalf("unstable application host: %q %q %v", first, second, err)
	}
}

func TestStablePlatformApplicationDomainID(t *testing.T) {
	first, err := StablePlatformApplicationDomainID("platform_1", "app_1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := StablePlatformApplicationDomainID("platform_1", "app_1")
	if err != nil || first != second || first.Empty() {
		t.Fatalf("unstable platform application domain ID: %q %q %v", first, second, err)
	}
	if other, err := StablePlatformApplicationDomainID("platform_2", "app_1"); err != nil || other == first {
		t.Fatalf("platform identity collision: %q %q %v", first, other, err)
	}
}

func TestNormalizeRoutePathAndConflict(t *testing.T) {
	if path, err := NormalizeRoutePath("/api/"); err != nil || path != "/api" {
		t.Fatalf("path=%q err=%v", path, err)
	}
	if RoutePathsConflict("/", "/api") {
		t.Fatal("root fallback must coexist with a more-specific route")
	}
	if !RoutePathsConflict("/api", "/api/v1") || !RoutePathsConflict("/api", "/api") {
		t.Fatal("ambiguous nested or duplicate prefixes were accepted")
	}
}

func TestDomainBindingRequiresVerifiedCertificateForReady(t *testing.T) {
	binding := DomainBinding{ID: "domain_1", Kind: DomainBindingApplication, ApplicationID: "app_1", Host: "app.example.test", ExpectedCNAME: "target.apps.example.test", Status: DomainReady}
	if err := binding.Validate(); err == nil {
		t.Fatal("ready domain without certificate was accepted")
	}
	binding.CertificateRef = "certificate_1"
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
}
