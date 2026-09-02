package contracts

import (
	"strings"
	"testing"
)

func TestAcornFoxPublicHostnameIsStableScopedAndNonReversible(t *testing.T) {
	first, err := AcornFoxPublicHostname("Example.Test.", "app_public_1", "dep_public_1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := AcornFoxPublicHostname("example.test", "app_public_1", "dep_public_1")
	if err != nil || first != second {
		t.Fatalf("hostname is not canonical and stable: first=%q second=%q err=%v", first, second, err)
	}
	other, err := AcornFoxPublicHostname("example.test", "app_public_1", "dep_public_2")
	if err != nil || first == other {
		t.Fatalf("deployment identity did not scope hostname: first=%q other=%q err=%v", first, other, err)
	}
	if !strings.HasSuffix(first, ".apps.example.test") || strings.Contains(first, "app_public_1") || strings.Contains(first, "dep_public_1") {
		t.Fatalf("hostname is not an owned opaque subdomain: %q", first)
	}
}

func TestAcornFoxPublicRouteIntentRequiresExactAcceptedEndpoint(t *testing.T) {
	endpoint := AcornFoxRoutableEndpoint{ApplicationID: "app_public_1", DeploymentID: "dep_public_1", ServiceName: "web", Port: 8080, Accepted: true}
	intent, err := NewAcornFoxPublicRouteIntent("example.test", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	route, err := intent.RouteSpec()
	if err != nil || route.Host != intent.Hostname || route.DeploymentID != endpoint.DeploymentID || route.ServiceName != endpoint.ServiceName || route.Port != endpoint.Port || !route.Verified {
		t.Fatalf("route intent did not preserve exact local endpoint: intent=%+v route=%+v err=%v", intent, route, err)
	}
	for _, invalid := range []AcornFoxRoutableEndpoint{
		{ApplicationID: endpoint.ApplicationID, DeploymentID: endpoint.DeploymentID, ServiceName: endpoint.ServiceName, Port: endpoint.Port},
		{ApplicationID: endpoint.ApplicationID, DeploymentID: endpoint.DeploymentID, ServiceName: endpoint.ServiceName, Port: 0, Accepted: true},
		{ApplicationID: endpoint.ApplicationID, DeploymentID: endpoint.DeploymentID, ServiceName: "bad service", Port: endpoint.Port, Accepted: true},
	} {
		if _, err := NewAcornFoxPublicRouteIntent("example.test", invalid); err == nil {
			t.Fatalf("invalid endpoint became a public route intent: %+v", invalid)
		}
	}
}

func TestAcornFoxPublicAccessFactExposesOnlyLocalStates(t *testing.T) {
	base := AcornFoxPublicAccessFact{ApplicationID: "app_public_1", DeploymentID: "dep_public_1", Hostname: "delivery-1234567890abcdef1234.apps.example.test"}
	for _, fact := range []AcornFoxPublicAccessFact{
		{ApplicationID: base.ApplicationID, DeploymentID: base.DeploymentID, Hostname: base.Hostname, Status: AcornFoxPublicDisabled, InternalEndpoint: AcornFoxInternalEndpointNotObserved, LocalRoute: AcornFoxLocalRouteDisabled},
		{ApplicationID: base.ApplicationID, DeploymentID: base.DeploymentID, Hostname: base.Hostname, Status: AcornFoxPublicPendingExternalValidation, DesiredPublic: true, InternalEndpoint: AcornFoxInternalEndpointAccepted, LocalRoute: AcornFoxLocalRouteConfigured},
		{ApplicationID: base.ApplicationID, DeploymentID: base.DeploymentID, Hostname: base.Hostname, Status: AcornFoxPublicDisabled, InternalEndpoint: AcornFoxInternalEndpointAccepted, LocalRoute: AcornFoxLocalRouteReconcileRequired},
	} {
		if err := fact.Validate(); err != nil {
			t.Fatalf("local fact %+v invalid: %v", fact, err)
		}
	}
	base.Status = "PUBLIC_READY"
	base.InternalEndpoint = AcornFoxInternalEndpointNotObserved
	base.LocalRoute = AcornFoxLocalRouteDisabled
	if err := base.Validate(); err == nil {
		t.Fatal("local contract accepted an external-ready claim")
	}
}

func TestAcornFoxPublicHostnameRejectsCallerDomainShaping(t *testing.T) {
	for _, root := range []string{"", "*.example.test", "apps.example.test", "example.test/path", "example..test", "EXAMPLE TEST"} {
		if _, err := AcornFoxPublicHostname(root, "app_public_1", "dep_public_1"); err == nil {
			t.Fatalf("unsafe authorized root was accepted: %q", root)
		}
	}
}

func TestAcornFoxPublicRouteInventoryHasOnlyExactPublicAccessMethods(t *testing.T) {
	path := "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/public-access"
	found := false
	for _, route := range AcornFoxPublicRouteMethodInventory() {
		if route.Path != path {
			continue
		}
		found = true
		if len(route.Methods) != 2 || route.Methods[0] != "get" || route.Methods[1] != "put" {
			t.Fatalf("public-access methods=%v", route.Methods)
		}
	}
	if !found {
		t.Fatal("public-access route missing from AcornFox inventory")
	}
}
