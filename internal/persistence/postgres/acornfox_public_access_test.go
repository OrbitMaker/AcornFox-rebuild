package postgres

import "testing"

func TestAcornFoxPublicAccessPlatformRootRejectsGenericOrUnownedHostnames(t *testing.T) {
	const host = "delivery-0123456789abcdef0123.apps.example.test"
	root, slug, err := afpaPlatformRoot(host)
	if err != nil || root != "apps.example.test" || slug != "delivery-0123456789abcdef0123" {
		t.Fatalf("owned hostname root=%q slug=%q err=%v", root, slug, err)
	}
	for _, value := range []string{
		"console.example.test",
		"delivery-0123456789abcdef0123.example.test",
		"delivery-0123456789abcdef012g.apps.example.test",
		"delivery-0123456789abcdef0123.apps.local",
	} {
		if _, _, err := afpaPlatformRoot(value); err == nil {
			t.Fatalf("unexpectedly accepted unowned public hostname %q", value)
		}
	}
}

func TestAcornFoxPublicAccessDeterministicIDsSeparateOwnershipKinds(t *testing.T) {
	route := afpaID("route", "app_a", "dep_a")
	if route == afpaID("route", "app_a", "dep_b") || route == afpaID("lease", route.String()) || afpaID("domain", "app_a", "dep_a") == afpaID("domain", "app_b", "dep_a") {
		t.Fatal("deterministic public-access ownership IDs unexpectedly overlap")
	}
}
