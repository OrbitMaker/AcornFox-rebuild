package postgres

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestM3MigrationIsAdditiveAndKeepsPrivateKeysOutOfRouteFacts(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0013_m3_access_routes.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS m3_platform_domains",
		"CREATE TABLE IF NOT EXISTS m3_application_domains",
		"CREATE TABLE IF NOT EXISTS m3_certificate_references",
		"CREATE TABLE IF NOT EXISTS m3_desired_routes",
		"CREATE TABLE IF NOT EXISTS m3_port_leases",
		"CREATE TABLE IF NOT EXISTS m3_route_pointers",
		"CREATE TABLE IF NOT EXISTS m3_traffic_switches",
		"m3_desired_routes_host_path_uidx",
		"m3_port_leases_active_endpoint_uidx",
		"m3_traffic_switches_are_immutable",
		"secret_reference_id text NOT NULL",
		"verification_method = 'cname'",
		"verification_method = 'dns01'",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("M3 migration is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"private_key", "certificate_pem", "key_pem", "key_material"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("M3 migration must not persist certificate material %q", forbidden)
		}
	}
}

func TestM3DomainRecordsFailClosedByOwnershipAndVerificationMethod(t *testing.T) {
	verified := time.Unix(1700000000, 0).UTC()
	platform := PlatformDomainRecord{ID: "platform_1", Hostname: "apps.example.test", DNSProviderRef: "fixture:dns", VerificationStatus: DomainVerificationVerified, WildcardEnabled: true, VerifiedAt: &verified}
	if err := platform.Validate(); err != nil {
		t.Fatalf("valid platform domain rejected: %v", err)
	}
	custom := ApplicationDomainRecord{ID: "domain_1", ApplicationID: "app_1", Hostname: "api.customer.example", Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationPending}
	if err := custom.Validate(); err != nil {
		t.Fatalf("valid custom CNAME domain rejected: %v", err)
	}
	platformName := ApplicationDomainRecord{ID: "domain_2", ApplicationID: "app_1", PlatformDomainID: "platform_1", Hostname: "card-abc.apps.example.test", Kind: "platform", StableSlug: "card-abc", VerificationMethod: "dns01", VerificationStatus: DomainVerificationPending}
	if err := platformName.Validate(); err != nil {
		t.Fatalf("valid stable platform domain rejected: %v", err)
	}
	invalid := []ApplicationDomainRecord{
		{ID: "domain_3", ApplicationID: "app_1", Hostname: "Bad.Example.Test", Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationPending},
		{ID: "domain_4", ApplicationID: "app_1", Hostname: "api.customer.example", Kind: "custom", VerificationMethod: "dns01", VerificationStatus: DomainVerificationPending},
		{ID: "domain_5", ApplicationID: "app_1", PlatformDomainID: "platform_1", Hostname: "card.apps.example.test", Kind: "platform", StableSlug: "card", VerificationMethod: "cname", VerificationStatus: DomainVerificationPending},
	}
	for _, record := range invalid {
		if err := record.Validate(); err == nil {
			t.Errorf("invalid application domain accepted: %#v", record)
		}
	}
}

func TestM3DesiredRouteUsesCanonicalHostPathAndCertificateReference(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	route := DesiredRouteRecord{Route: domain.Route{ID: "route_1", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "frontend", Host: "app.example.test", Path: "/api", CertificateRef: "cert_1", Verified: true, Serving: true, CreatedAt: now}, CertificateID: "cert_1", State: DesiredRouteActive}
	if err := route.Validate(); err != nil {
		t.Fatalf("valid desired route rejected: %v", err)
	}
	ipFallback := route
	ipFallback.Route.ID, ipFallback.Route.Host, ipFallback.Route.CertificateRef = "route_ip", "192.0.2.10", ""
	ipFallback.CertificateID, ipFallback.Route.Verified, ipFallback.Route.Serving, ipFallback.State = "", true, true, DesiredRouteActive
	if err := ipFallback.Validate(); err != nil {
		t.Fatalf("IP+port fallback route fact rejected: %v", err)
	}
	prepared := DesiredRouteRecord{Route: domain.Route{ID: "route_tls_allow", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "frontend", Host: "app.example.test", Path: "/tls", Verified: true, Serving: false, CreatedAt: now}, ApplicationDomainID: "domain_1", State: DesiredRoutePending}
	if err := prepared.Validate(); err != nil {
		t.Fatalf("TLS allow desired route rejected: %v", err)
	}
	for _, path := range []string{"/api/", "api", "/api//v1", "/api?x=1", "/../api"} {
		if _, err := NormalizeM3PathPrefix(path); err == nil {
			t.Errorf("noncanonical path %q accepted", path)
		}
	}
	for _, candidate := range []DesiredRouteRecord{
		{Route: domain.Route{ID: "route_2", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "frontend", Host: "APP.example.test", Path: "/", CreatedAt: now}, State: DesiredRoutePending},
		{Route: domain.Route{ID: "route_3", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "frontend", Host: "app.example.test", Path: "/", CertificateRef: "unknown", CreatedAt: now}, State: DesiredRoutePending},
		{Route: domain.Route{ID: "route_4", ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "frontend", Host: "app.example.test", Path: "/", Serving: true, CreatedAt: now}, State: DesiredRoutePending},
	} {
		if err := candidate.Validate(); err == nil {
			t.Errorf("invalid desired route accepted: %#v", candidate)
		}
	}
}

func TestM3CertificateReferenceContainsOnlyOpaqueSecretReference(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	certificate := CertificateReference{ID: "cert_1", ApplicationDomainID: "domain_1", SecretReferenceID: "secret_1", SubjectHostname: "app.example.test", Issuer: "acme-staging", Status: CertificateReferenceReady, NotBefore: &now, NotAfter: pointerM3Time(now.Add(time.Hour))}
	if err := certificate.Validate(); err != nil {
		t.Fatalf("opaque certificate reference rejected: %v", err)
	}
	if err := (CertificateReference{ID: "cert_1", ApplicationDomainID: "domain_1", PlatformDomainID: "platform_1", SecretReferenceID: "secret_1", SubjectHostname: "app.example.test", Issuer: "acme", Status: CertificateReferenceReady}).Validate(); err == nil {
		t.Fatal("dual certificate owner was accepted")
	}
}

func TestM3RoutePointerAndTrafficSwitchFailClosed(t *testing.T) {
	pointer := RoutePointer{RouteID: "route_1", DeploymentID: "dep_2", PortLeaseID: "lease_2", Revision: 1}
	if err := pointer.Validate(); err != nil {
		t.Fatalf("valid pointer rejected: %v", err)
	}
	if err := (RoutePointer{RouteID: "route_1", DeploymentID: "dep_2", PortLeaseID: "lease_2", Revision: -1}).Validate(); err == nil {
		t.Fatal("negative pointer revision accepted")
	}
	switchRecord := TrafficSwitchRecord{ID: "switch_1", ApplicationID: "app_1", RouteID: "route_1", PreviousDeploymentID: "dep_1", NextDeploymentID: "dep_2", Status: TrafficSwitchSwitched, Reason: "new target passed health"}
	if err := switchRecord.Validate(); err != nil {
		t.Fatalf("valid switch rejected: %v", err)
	}
	switchRecord.PreviousDeploymentID = switchRecord.NextDeploymentID
	if err := switchRecord.Validate(); err == nil {
		t.Fatal("switch to same deployment accepted")
	}
}

func pointerM3Time(value time.Time) *time.Time { return &value }
