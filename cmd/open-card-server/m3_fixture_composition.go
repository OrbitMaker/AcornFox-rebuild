package main

import (
	"context"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	caddyprovider "github.com/open-card/open-card/internal/providers/caddy"
	"github.com/open-card/open-card/internal/providers/certfixture"
	"github.com/open-card/open-card/internal/providers/dnsfixture"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

// newM3FixtureAccessController is reachable only after resolveM3Composition
// validates the fixed clean-worker fixture identity.
func newM3FixtureAccessController(caddy *caddyprovider.Provider, store *postgres.Store, secrets *secretprovider.Provider, statePath string, dnsFault, certificateFault bool) (*controllers.M3AccessController, error) {
	dnsProvider, err := dnsfixture.New(dnsfixture.Config{StatePath: statePath})
	if err != nil {
		return nil, err
	}
	if dnsFault {
		if err := dnsProvider.SetFault(dnsfixture.Fault{Operation: "verify_cname", Code: contracts.ErrUnavailable, Message: "isolated DNS verification failure"}); err != nil {
			return nil, err
		}
	}
	dnsAuthority := certfixture.DNSAdapter{
		Present: func(ctx context.Context, name, token string, operation contracts.OperationContext) (certfixture.DNS01Challenge, error) {
			challenge, err := dnsProvider.PresentDNS01(ctx, name, token, operation)
			return certfixture.DNS01Challenge{Domain: challenge.Domain, Name: challenge.Name, Token: challenge.Token}, err
		},
		Verify: func(ctx context.Context, challenge certfixture.DNS01Challenge, operation contracts.OperationContext) error {
			return dnsProvider.VerifyDNS01(ctx, dnsfixture.DNS01Challenge{Domain: challenge.Domain, Name: challenge.Name, Token: challenge.Token}, operation)
		},
		Cleanup: func(ctx context.Context, challenge certfixture.DNS01Challenge, operation contracts.OperationContext) error {
			return dnsProvider.CleanupDNS01(ctx, dnsfixture.DNS01Challenge{Domain: challenge.Domain, Name: challenge.Name, Token: challenge.Token}, operation)
		},
	}
	certificateProvider, err := certfixture.New(certfixture.Config{Secrets: secrets, DNS: dnsAuthority, Validity: 24 * time.Hour})
	if err != nil {
		return nil, err
	}
	if certificateFault {
		if err := certificateProvider.SetFault(certfixture.Fault{Operation: "issue", Code: contracts.ErrUnavailable, Message: "isolated certificate issuance failure"}); err != nil {
			return nil, err
		}
	}
	return &controllers.M3AccessController{Routes: caddy, Store: &m3PostgresAdapter{store: store}, DNS: &m3DNSAdapter{provider: dnsProvider}, Certificates: &m3CertificateAdapter{provider: certificateProvider}}, nil
}

type m3DNSAdapter struct {
	provider *dnsfixture.Provider
	clock    func() time.Time
}

func (a *m3DNSAdapter) VerifyPlatform(ctx context.Context, baseDomain, target string, operation contracts.OperationContext) (domain.DomainBinding, error) {
	managedZone := "apps." + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	bound, err := a.provider.BindPlatformDomain(ctx, managedZone, target, childM3Operation(operation, "bind"))
	if err != nil {
		return domain.DomainBinding{}, err
	}
	verified, err := a.provider.VerifyPlatformDomain(ctx, bound, childM3Operation(operation, "verify"))
	if err != nil {
		return domain.DomainBinding{}, err
	}
	now := a.now()
	return domain.DomainBinding{ID: m3AdapterID("domain", "platform:"+baseDomain), Kind: domain.DomainBindingPlatform, Host: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(baseDomain)), "."), Status: domain.DomainVerified, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now, FailureReason: map[bool]string{false: "platform DNS verification did not converge"}[verified.Verified]}, nil
}

func (a *m3DNSAdapter) VerifyApplication(ctx context.Context, applicationID domain.ID, host, target string, operation contracts.OperationContext) (domain.DomainBinding, error) {
	bound, err := a.provider.BindApplicationCNAME(ctx, host, target, childM3Operation(operation, "bind"))
	if err != nil {
		return domain.DomainBinding{}, err
	}
	verified, err := a.provider.VerifyApplicationCNAME(ctx, bound, childM3Operation(operation, "verify"))
	if err != nil {
		return domain.DomainBinding{}, err
	}
	now := a.now()
	return domain.DomainBinding{ID: m3AdapterID("domain", "application:"+applicationID.String()+":"+host), Kind: domain.DomainBindingApplication, ApplicationID: applicationID, Host: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."), ExpectedCNAME: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), "."), Status: domain.DomainVerified, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now, FailureReason: map[bool]string{false: "application CNAME verification did not converge"}[verified.Verified]}, nil
}

func (a *m3DNSAdapter) now() time.Time {
	if a.clock == nil {
		return time.Now().UTC()
	}
	return a.clock().UTC()
}

type m3CertificateAdapter struct {
	provider *certfixture.Provider
	clock    func() time.Time
}

func (a *m3CertificateAdapter) Issue(ctx context.Context, binding domain.DomainBinding, operation contracts.OperationContext) (domain.CertificateReference, error) {
	domains := []string{binding.Host}
	if binding.Kind == domain.DomainBindingPlatform {
		domains = []string{"*.apps." + binding.Host, "apps." + binding.Host}
	}
	secretID := m3AdapterID("secret", binding.ID.String()+":"+operation.IdempotencyKey)
	issued, err := a.provider.Issue(ctx, certfixture.CertificateRequest{Domains: domains, SecretID: secretID, SecretName: "tls-" + binding.ID.String(), SecretProvider: "local-secret", Operation: operation})
	if err != nil {
		return domain.CertificateReference{}, err
	}
	now := a.now()
	return domain.CertificateReference{ID: m3AdapterID("certificate", binding.ID.String()+":"+issued.Serial), DomainBindingID: binding.ID, Host: domains[0], SecretRef: issued.Reference, Status: domain.CertificateReady, Fingerprint: "sha256:" + issued.Fingerprint, NotBefore: issued.NotBefore, NotAfter: issued.NotAfter, RenewAfter: issued.NotBefore.Add(issued.NotAfter.Sub(issued.NotBefore) * 2 / 3), UpdatedAt: now}, nil
}

func (a *m3CertificateAdapter) Renew(ctx context.Context, previous domain.CertificateReference, operation contracts.OperationContext) (domain.CertificateReference, error) {
	binding := domain.DomainBinding{ID: previous.DomainBindingID, Kind: domain.DomainBindingApplication, Host: previous.Host}
	if strings.HasPrefix(previous.Host, "*.") {
		binding.Kind = domain.DomainBindingPlatform
		binding.Host = strings.TrimPrefix(strings.TrimPrefix(previous.Host, "*.apps."), "*.")
	}
	return a.Issue(ctx, binding, operation)
}

func (a *m3CertificateAdapter) now() time.Time {
	if a.clock == nil {
		return time.Now().UTC()
	}
	return a.clock().UTC()
}
