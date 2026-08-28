package controllers

// G3 access is the UI-facing facade over the durable M3 access facts. It
// deliberately owns no DNS, certificate, Caddy, or route-provider mutation:
// public DNS is a read-only injected dependency and certificate/Caddy
// observation stays a future convergence step.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type G3VerificationStatus string

const (
	G3VerificationPending  G3VerificationStatus = "pending"
	G3VerificationVerified G3VerificationStatus = "verified"
	G3VerificationFailed   G3VerificationStatus = "failed"
)

// G3CertificateFact is an opaque certificate observation. The facade never
// creates certificate material and never reports ready without a future Caddy
// certificate observation adapter.
type G3CertificateFact struct {
	ID       domain.ID
	Status   string
	Subject  string
	NotAfter *time.Time
	Observed bool
}

type G3PlatformDomainFact struct {
	ID                 domain.ID
	BaseDomain         string
	VerificationRef    string
	VerificationStatus G3VerificationStatus
	VerifiedAt         *time.Time
	Certificate        *G3CertificateFact
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

const g3PlatformDNSVerificationRef = "public-dns-read-only/v2-console-ingress-wildcard"

type G3ApplicationDomainFact struct {
	ID                 domain.ID
	ApplicationID      domain.ID
	Hostname           string
	Kind               string
	CNAME              string
	VerificationStatus G3VerificationStatus
	VerifiedAt         *time.Time
	Certificate        *G3CertificateFact
	Serving            bool
	RouteID            domain.ID
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type G3RouteFact struct {
	ID          domain.ID
	DomainID    domain.ID
	Hostname    string
	Desired     bool
	Serving     bool
	Certificate *G3CertificateFact
}

type G3RuntimeFact struct {
	RuntimeReady bool
	IPFallback   *string
}

type G3ApplicationAccessFacts struct {
	Runtime G3RuntimeFact
	Routes  []G3RouteFact
}

type G3Idempotency struct {
	Scope  string
	Key    string
	Digest string
}

// G3AccessStore is a deliberately small view of M3 durable facts. Implementors
// must make UnbindCustomDomain atomic: serving routes are a conflict and no
// Caddy removal is inferred from a database-only update.
type G3AccessStore interface {
	ApplicationName(context.Context, domain.ID) (string, bool, error)
	PlatformDomain(context.Context) (G3PlatformDomainFact, bool, error)
	ReplayG3Idempotency(context.Context, G3Idempotency) ([]byte, bool, error)
	PutPlatformDomain(context.Context, G3PlatformDomainFact, G3Idempotency) (G3PlatformDomainFact, bool, error)
	ListApplicationDomains(context.Context, domain.ID) ([]G3ApplicationDomainFact, error)
	ApplicationDomain(context.Context, domain.ID, domain.ID) (G3ApplicationDomainFact, bool, error)
	BindCustomDomain(context.Context, G3ApplicationDomainFact, G3Idempotency) (G3ApplicationDomainFact, bool, error)
	SetApplicationDomainVerification(context.Context, domain.ID, domain.ID, G3VerificationStatus, *time.Time, G3Idempotency) (G3ApplicationDomainFact, bool, error)
	UnbindCustomDomain(context.Context, domain.ID, domain.ID, string, G3Idempotency) (bool, error)
	ApplicationAccessFacts(context.Context, domain.ID) (G3ApplicationAccessFacts, error)
}

type G3AccessConfig struct {
	PublicDNSVerifier  contracts.PublicDNSVerifier
	ExpectedPublicIP   string
	ConsoleLabel       string
	IngressLabel       string
	AppsLabel          string
	WildcardProbeLabel string
}

type G3AccessController struct {
	Store  G3AccessStore
	Config G3AccessConfig
	Clock  func() time.Time
}

type G3DomainVerification struct {
	Method     string     `json:"method"`
	Status     string     `json:"status"`
	Name       *string    `json:"name"`
	Value      *string    `json:"value"`
	ObservedAt *time.Time `json:"observed_at"`
}

type G3CertificateStatus struct {
	Status   string     `json:"status"`
	Subject  *string    `json:"subject"`
	NotAfter *time.Time `json:"not_after"`
}

type G3FailureState struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type G3PlatformSettings struct {
	Status          string               `json:"status"`
	BaseDomain      *string              `json:"base_domain"`
	ConsoleDomain   *string              `json:"console_domain"`
	WildcardPattern *string              `json:"wildcard_pattern"`
	DNSRecords      []G3DNSRecord        `json:"dns_records"`
	Verification    G3DomainVerification `json:"verification"`
	Certificate     G3CertificateStatus  `json:"certificate"`
	Failure         *G3FailureState      `json:"failure"`
	NextAction      string               `json:"next_action"`
}

// G3DNSRecord is an operator-visible publication instruction. It deliberately
// exposes no DNS provider credentials or provider record identifiers.
type G3DNSRecord struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Purpose  string `json:"purpose"`
}

type G3ApplicationDomain struct {
	ID           string               `json:"id"`
	Hostname     string               `json:"hostname"`
	Kind         string               `json:"kind"`
	Status       string               `json:"status"`
	CNAME        *string              `json:"cname_target"`
	Verification G3DomainVerification `json:"verification"`
	Certificate  G3CertificateStatus  `json:"certificate"`
	Failure      *G3FailureState      `json:"failure"`
	Serving      bool                 `json:"serving"`
}

type G3AccessRouteStatus struct {
	Desired bool    `json:"desired"`
	Serving bool    `json:"serving"`
	RouteID *string `json:"route_id"`
}

type G3ApplicationAccess struct {
	RuntimeReady    bool                  `json:"runtimeReady"`
	IPFallback      *string               `json:"ipFallback"`
	PlatformAddress *G3ApplicationDomain  `json:"platformAddress"`
	CustomDomains   []G3ApplicationDomain `json:"customDomains"`
	Route           G3AccessRouteStatus   `json:"route"`
	Certificate     G3CertificateStatus   `json:"certificate"`
	Serving         bool                  `json:"serving"`
}

func (c *G3AccessController) GetPlatformSettings(ctx context.Context) (G3PlatformSettings, error) {
	if c.Store == nil {
		return G3PlatformSettings{}, g3Unavailable("platform domain facts are unavailable", nil)
	}
	if !c.configured() {
		return g3UnconfiguredPlatformSettings(), nil
	}
	fact, found, err := c.Store.PlatformDomain(ctx)
	if err != nil {
		return G3PlatformSettings{}, g3Unavailable("platform domain facts are unavailable", err)
	}
	if !found {
		return g3PlatformSettingsForAbsentConfig(), nil
	}
	return c.platformSettings(fact)
}

// ConfigurePlatformDomain records a singleton base domain and synchronously
// performs only public DNS reads. It never calls a certificate issuer or Caddy.
func (c *G3AccessController) ConfigurePlatformDomain(ctx context.Context, baseDomain, idempotencyKey, actor string) (G3PlatformSettings, bool, error) {
	if err := c.requireConfiguredWrite(idempotencyKey, actor); err != nil {
		return G3PlatformSettings{}, false, err
	}
	base, err := domain.NormalizeDNSName(baseDomain)
	if err != nil {
		return G3PlatformSettings{}, false, err
	}
	request := g3Idempotency("g3.platform-domain.put.v2", idempotencyKey, base)
	if replay, found, err := c.replayPlatformDomain(ctx, request); err != nil {
		return G3PlatformSettings{}, false, err
	} else if found {
		view, viewErr := c.platformSettings(replay)
		return view, true, viewErr
	}
	existing, found, err := c.Store.PlatformDomain(ctx)
	if err != nil {
		return G3PlatformSettings{}, false, g3Unavailable("platform domain facts are unavailable", err)
	}
	if found && existing.BaseDomain != base {
		return G3PlatformSettings{}, false, domain.NewError(domain.ErrConflict, "a different platform base domain is already configured")
	}
	verification, verifiedAt, err := c.verifyPlatform(ctx, base)
	if err != nil {
		return G3PlatformSettings{}, false, err
	}
	fact := G3PlatformDomainFact{
		ID:                 g3AccessID("platform-domain", base),
		BaseDomain:         base,
		VerificationRef:    g3PlatformDNSVerificationRef,
		VerificationStatus: verification,
		VerifiedAt:         verifiedAt,
		CreatedAt:          c.now(),
		UpdatedAt:          c.now(),
	}
	if found {
		fact.ID, fact.CreatedAt = existing.ID, existing.CreatedAt
	}
	fact, _, err = c.Store.PutPlatformDomain(ctx, fact, request)
	if err != nil {
		return G3PlatformSettings{}, false, g3StoreError(err, "platform domain idempotency conflict")
	}
	view, err := c.platformSettings(fact)
	return view, false, err
}

func (c *G3AccessController) ListApplicationDomains(ctx context.Context, applicationID domain.ID) ([]G3ApplicationDomain, error) {
	name, exists, err := c.applicationName(ctx, applicationID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, domain.NewError(domain.ErrNotFound, "application not found")
	}
	domains, err := c.Store.ListApplicationDomains(ctx, applicationID)
	if err != nil {
		return nil, g3Unavailable("application domain facts are unavailable", err)
	}
	if _, err := c.Store.ApplicationAccessFacts(ctx, applicationID); err != nil {
		return nil, g3Unavailable("application access facts are unavailable", err)
	}
	result := make([]G3ApplicationDomain, 0, len(domains)+1)
	if platform, found, platformErr := c.platformFact(ctx); platformErr != nil {
		return nil, platformErr
	} else if found {
		result = append(result, c.platformApplicationDomain(name, applicationID, platform))
	}
	for _, item := range domains {
		if item.Kind == "custom" {
			result = append(result, c.applicationDomain(item))
		}
	}
	return result, nil
}

func (c *G3AccessController) BindCustomDomain(ctx context.Context, applicationID domain.ID, hostname, idempotencyKey, actor string) (G3ApplicationDomain, bool, error) {
	if err := c.requireConfiguredWrite(idempotencyKey, actor); err != nil {
		return G3ApplicationDomain{}, false, err
	}
	if _, exists, err := c.applicationName(ctx, applicationID); err != nil {
		return G3ApplicationDomain{}, false, err
	} else if !exists {
		return G3ApplicationDomain{}, false, domain.NewError(domain.ErrNotFound, "application not found")
	}
	base, found, err := c.Store.PlatformDomain(ctx)
	if err != nil {
		return G3ApplicationDomain{}, false, g3Unavailable("platform domain facts are unavailable", err)
	}
	if !found {
		return G3ApplicationDomain{}, false, domain.NewError(domain.ErrConflict, "platform base domain must be configured before custom domain binding")
	}
	host, err := domain.NormalizeDNSName(hostname)
	if err != nil {
		return G3ApplicationDomain{}, false, err
	}
	request := g3Idempotency("g3.application-domain.bind", idempotencyKey, applicationID.String(), host)
	if replay, found, err := c.replayApplicationDomain(ctx, request); err != nil {
		return G3ApplicationDomain{}, false, err
	} else if found {
		return c.applicationDomain(replay), false, nil
	}
	cname := c.ingressHostname(base.BaseDomain)
	fact, created, err := c.Store.BindCustomDomain(ctx, G3ApplicationDomainFact{
		ID:                 g3AccessID("custom-domain", applicationID.String()+":"+host),
		ApplicationID:      applicationID,
		Hostname:           host,
		Kind:               "custom",
		CNAME:              cname,
		VerificationStatus: G3VerificationPending,
		CreatedAt:          c.now(),
		UpdatedAt:          c.now(),
	}, request)
	if err != nil {
		return G3ApplicationDomain{}, false, g3StoreError(err, "custom domain is already bound to another application")
	}
	return c.applicationDomain(fact), created, nil
}

func (c *G3AccessController) VerifyApplicationDomain(ctx context.Context, applicationID, domainID domain.ID, idempotencyKey, actor string) (G3ApplicationDomain, error) {
	if err := c.requireConfiguredWrite(idempotencyKey, actor); err != nil {
		return G3ApplicationDomain{}, err
	}
	request := g3Idempotency("g3.application-domain.verify", idempotencyKey, applicationID.String(), domainID.String())
	if replay, found, err := c.replayApplicationDomain(ctx, request); err != nil {
		return G3ApplicationDomain{}, err
	} else if found {
		return c.applicationDomain(replay), nil
	}
	fact, found, err := c.Store.ApplicationDomain(ctx, applicationID, domainID)
	if err != nil {
		return G3ApplicationDomain{}, g3Unavailable("application domain facts are unavailable", err)
	}
	if !found {
		return G3ApplicationDomain{}, domain.NewError(domain.ErrNotFound, "application domain not found")
	}
	if fact.Kind != "custom" {
		return G3ApplicationDomain{}, domain.NewError(domain.ErrConflict, "only custom domains may use the public verification endpoint")
	}
	platform, found, err := c.Store.PlatformDomain(ctx)
	if err != nil {
		return G3ApplicationDomain{}, g3Unavailable("platform domain facts are unavailable", err)
	}
	if !found || fact.CNAME != c.ingressHostname(platform.BaseDomain) {
		return G3ApplicationDomain{}, domain.NewError(domain.ErrConflict, "custom domain does not target the configured ingress hostname")
	}
	result, err := c.Config.PublicDNSVerifier.VerifyCustomerIngress(ctx, fact.Hostname, platform.BaseDomain)
	if err != nil {
		return G3ApplicationDomain{}, g3Unavailable("public DNS verification is unavailable", err)
	}
	verification, verifiedAt, err := g3VerificationOutcome([]contracts.PublicDNSVerification{result}, c.now())
	if err != nil {
		return G3ApplicationDomain{}, err
	}
	fact, _, err = c.Store.SetApplicationDomainVerification(ctx, applicationID, domainID, verification, verifiedAt, request)
	if err != nil {
		return G3ApplicationDomain{}, g3StoreError(err, "application domain idempotency conflict")
	}
	return c.applicationDomain(fact), nil
}

func (c *G3AccessController) UnbindCustomDomain(ctx context.Context, applicationID, domainID domain.ID, idempotencyKey, actor string) error {
	if err := c.requireConfiguredWrite(idempotencyKey, actor); err != nil {
		return err
	}
	request := g3Idempotency("g3.application-domain.unbind", idempotencyKey, applicationID.String(), domainID.String())
	if _, found, err := c.replayEmpty(ctx, request); err != nil {
		return err
	} else if found {
		return nil
	}
	if _, exists, err := c.applicationName(ctx, applicationID); err != nil {
		return err
	} else if !exists {
		return domain.NewError(domain.ErrNotFound, "application not found")
	}
	if _, err := c.Store.UnbindCustomDomain(ctx, applicationID, domainID, actor, request); err != nil {
		return g3StoreError(err, "custom domain cannot be unbound while serving")
	}
	return nil
}

func (c *G3AccessController) ApplicationAccess(ctx context.Context, applicationID domain.ID) (G3ApplicationAccess, error) {
	name, exists, err := c.applicationName(ctx, applicationID)
	if err != nil {
		return G3ApplicationAccess{}, err
	}
	if !exists {
		return G3ApplicationAccess{}, domain.NewError(domain.ErrNotFound, "application not found")
	}
	domains, err := c.Store.ListApplicationDomains(ctx, applicationID)
	if err != nil {
		return G3ApplicationAccess{}, g3Unavailable("application domain facts are unavailable", err)
	}
	facts, err := c.Store.ApplicationAccessFacts(ctx, applicationID)
	if err != nil {
		return G3ApplicationAccess{}, g3Unavailable("application access facts are unavailable", err)
	}
	result := G3ApplicationAccess{RuntimeReady: facts.Runtime.RuntimeReady, IPFallback: facts.Runtime.IPFallback, CustomDomains: make([]G3ApplicationDomain, 0, len(domains)), Certificate: G3CertificateStatus{Status: "pending"}}
	for _, item := range domains {
		if item.Kind == "custom" {
			result.CustomDomains = append(result.CustomDomains, c.applicationDomain(item))
		}
	}
	if platform, found, platformErr := c.platformFact(ctx); platformErr != nil {
		return G3ApplicationAccess{}, platformErr
	} else if found {
		result.PlatformAddress = ptrG3Domain(c.platformApplicationDomain(name, applicationID, platform))
	}
	// Gate4B-1 exposes a durable desired route, but the legacy internal route
	// provider cannot prove public Edge TLS/SNI serving. Gate4B-2 owns that
	// observation, so Route.Serving and Serving deliberately remain false here.
	for _, route := range facts.Routes {
		if !result.Route.Desired && route.Desired {
			result.Route.Desired = true
			if !route.ID.Empty() {
				id := route.ID.String()
				result.Route.RouteID = &id
			}
		}
		if route.Certificate != nil {
			result.Certificate = g3Certificate(route.Certificate)
		}
	}
	return result, nil
}

func (c *G3AccessController) verifyPlatform(ctx context.Context, base string) (G3VerificationStatus, *time.Time, error) {
	consoleResult, err := c.Config.PublicDNSVerifier.VerifyPlatformAddress(ctx, c.consoleHostname(base), c.Config.ExpectedPublicIP)
	if err != nil {
		return "", nil, g3Unavailable("public DNS verification is unavailable", err)
	}
	ingressResult, err := c.Config.PublicDNSVerifier.VerifyPlatformAddress(ctx, c.ingressHostname(base), c.Config.ExpectedPublicIP)
	if err != nil {
		return "", nil, g3Unavailable("public DNS verification is unavailable", err)
	}
	wildcardResult, err := c.Config.PublicDNSVerifier.VerifyPlatformAddress(ctx, c.wildcardProbeHostname(base), c.Config.ExpectedPublicIP)
	if err != nil {
		return "", nil, g3Unavailable("public DNS verification is unavailable", err)
	}
	return g3VerificationOutcome([]contracts.PublicDNSVerification{consoleResult, ingressResult, wildcardResult}, c.now())
}

func g3VerificationOutcome(results []contracts.PublicDNSVerification, now time.Time) (G3VerificationStatus, *time.Time, error) {
	for _, result := range results {
		switch result.Status {
		case contracts.PublicDNSResolverError, contracts.PublicDNSUnknown:
			return "", nil, g3Unavailable("public DNS verification is unavailable", nil)
		case contracts.PublicDNSMismatch, contracts.PublicDNSConflict:
			return G3VerificationFailed, nil, nil
		case contracts.PublicDNSPending, contracts.PublicDNSNotFound, contracts.PublicDNSTimeout:
			return G3VerificationPending, nil, nil
		case contracts.PublicDNSVerified:
		default:
			return "", nil, g3Unavailable("public DNS verification is unavailable", nil)
		}
	}
	observed := now.UTC()
	return G3VerificationVerified, &observed, nil
}

func (c *G3AccessController) platformFact(ctx context.Context) (G3PlatformDomainFact, bool, error) {
	if c.Store == nil {
		return G3PlatformDomainFact{}, false, g3Unavailable("platform domain facts are unavailable", nil)
	}
	if !c.configured() {
		return G3PlatformDomainFact{}, false, nil
	}
	fact, found, err := c.Store.PlatformDomain(ctx)
	if err != nil {
		return G3PlatformDomainFact{}, false, g3Unavailable("platform domain facts are unavailable", err)
	}
	return fact, found, nil
}

func (c *G3AccessController) applicationName(ctx context.Context, applicationID domain.ID) (string, bool, error) {
	if c.Store == nil {
		return "", false, g3Unavailable("application facts are unavailable", nil)
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return "", false, err
	}
	name, found, err := c.Store.ApplicationName(ctx, applicationID)
	if err != nil {
		return "", false, g3Unavailable("application facts are unavailable", err)
	}
	return name, found, nil
}

func (c *G3AccessController) requireConfiguredWrite(idempotencyKey, actor string) error {
	if c.Store == nil || !c.configured() {
		return g3Unavailable("public DNS access configuration is unavailable", nil)
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return domain.ValidationError("Idempotency-Key is required")
	}
	if strings.TrimSpace(actor) == "" {
		return domain.NewError(domain.ErrUnauthorized, "authenticated administrator identity is required")
	}
	return nil
}

func (c *G3AccessController) configured() bool {
	return c.Config.PublicDNSVerifier != nil && g3IPv4(c.Config.ExpectedPublicIP) && g3DNSLabel(c.Config.ConsoleLabel) && g3DNSLabel(c.Config.IngressLabel) && g3DNSLabel(c.Config.AppsLabel) && g3DNSLabel(c.Config.WildcardProbeLabel)
}

func (c *G3AccessController) consoleHostname(base string) string {
	return strings.ToLower(c.Config.ConsoleLabel) + "." + base
}
func (c *G3AccessController) ingressHostname(base string) string {
	return strings.ToLower(c.Config.IngressLabel) + "." + base
}
func (c *G3AccessController) wildcardProbeHostname(base string) string {
	return strings.ToLower(c.Config.WildcardProbeLabel) + "." + strings.ToLower(c.Config.AppsLabel) + "." + base
}
func (c *G3AccessController) now() time.Time {
	if c.Clock != nil {
		return c.Clock().UTC()
	}
	return time.Now().UTC()
}

func (c *G3AccessController) platformSettings(fact G3PlatformDomainFact) (G3PlatformSettings, error) {
	if fact.BaseDomain == "" {
		return G3PlatformSettings{}, domain.NewError(domain.ErrConflict, "platform domain fact is malformed")
	}
	fact = g3PresentationPlatformFact(fact)
	base := fact.BaseDomain
	console := c.consoleHostname(base)
	ingress := c.ingressHostname(base)
	wildcard := "*." + strings.ToLower(c.Config.AppsLabel) + "." + base
	status := g3Lifecycle(fact.VerificationStatus)
	return G3PlatformSettings{
		Status:          status,
		BaseDomain:      &base,
		ConsoleDomain:   &console,
		WildcardPattern: &wildcard,
		DNSRecords: []G3DNSRecord{
			{Hostname: console, Type: "A", Value: c.Config.ExpectedPublicIP, Purpose: "console"},
			{Hostname: ingress, Type: "A", Value: c.Config.ExpectedPublicIP, Purpose: "ingress"},
			{Hostname: wildcard, Type: "A", Value: c.Config.ExpectedPublicIP, Purpose: "platform_app_wildcard"},
		},
		Verification: g3Verification("public_dns_read_only", status, console, c.Config.ExpectedPublicIP, fact.VerifiedAt),
		Certificate:  g3Certificate(fact.Certificate),
		Failure:      g3Failure(fact.VerificationStatus),
		NextAction:   g3NextAction(status, true),
	}, nil
}

func (c *G3AccessController) platformApplicationDomain(name string, applicationID domain.ID, platform G3PlatformDomainFact) G3ApplicationDomain {
	platform = g3PresentationPlatformFact(platform)
	host, err := domain.StableApplicationHost(name, applicationID, platform.BaseDomain)
	if err != nil {
		host = ""
	}
	status := g3Lifecycle(platform.VerificationStatus)
	return G3ApplicationDomain{ID: g3AccessID("platform-address", applicationID.String()+":"+platform.BaseDomain).String(), Hostname: host, Kind: "platform", Status: status, Verification: g3Verification("public_dns_read_only", status, c.wildcardProbeHostname(platform.BaseDomain), c.Config.ExpectedPublicIP, platform.VerifiedAt), Certificate: g3Certificate(platform.Certificate), Failure: g3Failure(platform.VerificationStatus)}
}

func g3PresentationPlatformFact(fact G3PlatformDomainFact) G3PlatformDomainFact {
	if fact.VerificationStatus == G3VerificationVerified && fact.VerificationRef != g3PlatformDNSVerificationRef {
		// Legacy apex-plus-probe evidence cannot satisfy the v2 console,
		// ingress, and wildcard-probe contract. A new v2 PUT revalidates it;
		// reads stay fail-closed and never recast it as certificate_pending.
		fact.VerificationStatus, fact.VerifiedAt, fact.Certificate = G3VerificationPending, nil, nil
	}
	return fact
}

func (c *G3AccessController) applicationDomain(fact G3ApplicationDomainFact) G3ApplicationDomain {
	status := g3Lifecycle(fact.VerificationStatus)
	var target *string
	if fact.CNAME != "" {
		value := fact.CNAME
		target = &value
	}
	return G3ApplicationDomain{ID: fact.ID.String(), Hostname: fact.Hostname, Kind: fact.Kind, Status: status, CNAME: target, Verification: g3Verification("public_dns_read_only", status, fact.Hostname, fact.CNAME, fact.VerifiedAt), Certificate: g3Certificate(fact.Certificate), Failure: g3Failure(fact.VerificationStatus)}
}

func g3UnconfiguredPlatformSettings() G3PlatformSettings {
	return G3PlatformSettings{Status: "unconfigured", DNSRecords: []G3DNSRecord{}, Verification: G3DomainVerification{Method: "public_dns_read_only", Status: "unconfigured"}, Certificate: G3CertificateStatus{Status: "pending"}, NextAction: "configure_base_domain"}
}

func g3PlatformSettingsForAbsentConfig() G3PlatformSettings {
	return G3PlatformSettings{Status: "pending", DNSRecords: []G3DNSRecord{}, Verification: G3DomainVerification{Method: "public_dns_read_only", Status: "pending"}, Certificate: G3CertificateStatus{Status: "pending"}, NextAction: "configure_base_domain"}
}

func g3Lifecycle(status G3VerificationStatus) string {
	switch status {
	case G3VerificationVerified:
		return "certificate_pending"
	case G3VerificationFailed:
		return "failed"
	default:
		return "pending"
	}
}

func g3Verification(method, status, name, value string, observedAt *time.Time) G3DomainVerification {
	var namePointer, valuePointer *string
	if name != "" {
		namePointer = &name
	}
	if value != "" {
		valuePointer = &value
	}
	return G3DomainVerification{Method: method, Status: status, Name: namePointer, Value: valuePointer, ObservedAt: observedAt}
}

func g3Certificate(fact *G3CertificateFact) G3CertificateStatus {
	if fact == nil || fact.Status != "failed" {
		// G3-02B1 has no Caddy certificate observation adapter. Even a legacy
		// M3 certificate reference cannot prove the live edge is serving it.
		return G3CertificateStatus{Status: "pending"}
	}
	return G3CertificateStatus{Status: "failed"}
}

func g3Failure(status G3VerificationStatus) *G3FailureState {
	if status != G3VerificationFailed {
		return nil
	}
	return &G3FailureState{Code: "public_dns_mismatch", Message: "public DNS does not match the expected ingress target", Retryable: true}
}

func g3NextAction(status string, configured bool) string {
	if !configured || status == "unconfigured" {
		return "configure_base_domain"
	}
	switch status {
	case "failed":
		return "retry"
	case "pending", "verifying":
		return "wait_for_verification"
	case "certificate_pending":
		return "wait_for_certificate"
	default:
		return "ready"
	}
}

func g3DNSLabel(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
			return false
		}
	}
	return true
}

func g3IPv4(value string) bool {
	value = strings.TrimSpace(value)
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.To4() != nil && parsed.To4().String() == value
}

func (c *G3AccessController) replayPlatformDomain(ctx context.Context, request G3Idempotency) (G3PlatformDomainFact, bool, error) {
	raw, found, err := c.Store.ReplayG3Idempotency(ctx, request)
	if err != nil {
		return G3PlatformDomainFact{}, false, g3StoreError(err, "idempotency key was reused with different input")
	}
	if !found {
		return G3PlatformDomainFact{}, false, nil
	}
	var fact G3PlatformDomainFact
	if err := json.Unmarshal(raw, &fact); err != nil || fact.ID.Empty() {
		return G3PlatformDomainFact{}, false, g3Unavailable("stored idempotency response is invalid", err)
	}
	return fact, true, nil
}

func (c *G3AccessController) replayApplicationDomain(ctx context.Context, request G3Idempotency) (G3ApplicationDomainFact, bool, error) {
	raw, found, err := c.Store.ReplayG3Idempotency(ctx, request)
	if err != nil {
		return G3ApplicationDomainFact{}, false, g3StoreError(err, "idempotency key was reused with different input")
	}
	if !found {
		return G3ApplicationDomainFact{}, false, nil
	}
	var fact G3ApplicationDomainFact
	if err := json.Unmarshal(raw, &fact); err != nil || fact.ID.Empty() {
		return G3ApplicationDomainFact{}, false, g3Unavailable("stored idempotency response is invalid", err)
	}
	return fact, true, nil
}

func (c *G3AccessController) replayEmpty(ctx context.Context, request G3Idempotency) ([]byte, bool, error) {
	raw, found, err := c.Store.ReplayG3Idempotency(ctx, request)
	if err != nil {
		return nil, false, g3StoreError(err, "idempotency key was reused with different input")
	}
	if found && !json.Valid(raw) {
		return nil, false, g3Unavailable("stored idempotency response is invalid", nil)
	}
	return raw, found, nil
}

func g3Idempotency(scope, key string, values ...string) G3Idempotency {
	payload := strings.Join(append([]string{scope}, values...), "\x00")
	sum := sha256.Sum256([]byte(payload))
	return G3Idempotency{Scope: scope, Key: strings.TrimSpace(key), Digest: "sha256:" + hex.EncodeToString(sum[:])}
}

func g3AccessID(prefix, value string) domain.ID {
	sum := sha256.Sum256([]byte(prefix + "\x00" + value))
	return domain.ID(prefix + "_" + hex.EncodeToString(sum[:16]))
}

func ptrG3Domain(value G3ApplicationDomain) *G3ApplicationDomain { return &value }

func g3Unavailable(message string, cause error) error {
	return domain.WrapError(domain.ErrUnavailable, message, cause)
}

func g3StoreError(err error, conflictMessage string) error {
	if errors.Is(err, ErrG3AccessConflict) || errors.Is(err, ErrG3IdempotencyConflict) || domain.IsCode(err, domain.ErrConflict) {
		return domain.NewError(domain.ErrConflict, conflictMessage)
	}
	if domain.IsCode(err, domain.ErrNotFound) {
		return err
	}
	return g3Unavailable("access facts could not converge", err)
}

// ErrG3AccessConflict permits persistence adapters to map PostgreSQL uniqueness and
// serving-route guards without leaking backend error text through HTTP.
var ErrG3AccessConflict = errors.New("g3 access conflict")

var ErrG3IdempotencyConflict = errors.New("g3 idempotency conflict")
