package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/certfixture"
	"github.com/open-card/open-card/internal/providers/dnsfixture"
)

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

type m3PostgresAdapter struct{ store *postgres.Store }

func (a *m3PostgresAdapter) PutDomainBinding(ctx context.Context, value domain.DomainBinding) error {
	now := value.UpdatedAt
	status := postgres.DomainVerificationPending
	if value.Status == domain.DomainVerified || value.Status == domain.DomainCertificatePending || value.Status == domain.DomainReady {
		status = postgres.DomainVerificationVerified
	}
	if value.Status == domain.DomainFailed {
		status = postgres.DomainVerificationFailed
	}
	if value.Kind == domain.DomainBindingPlatform {
		return a.store.UpsertPlatformDomain(ctx, postgres.PlatformDomainRecord{ID: value.ID, Hostname: value.Host, DNSProviderRef: "isolated-dns-fixture", VerificationStatus: status, WildcardEnabled: value.Status == domain.DomainReady, VerificationRef: value.ID.String(), VerifiedAt: value.VerifiedAt, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}, now)
	}
	kind, method, slug := "custom", "cname", ""
	if value.Managed {
		kind, method = "platform", "dns01"
		hostParts := strings.Split(value.Host, ".")
		slug = hostParts[0]
	}
	return a.store.UpsertApplicationDomain(ctx, postgres.ApplicationDomainRecord{ID: value.ID, ApplicationID: value.ApplicationID, PlatformDomainID: value.PlatformDomainID, Hostname: value.Host, Kind: kind, StableSlug: slug, VerificationMethod: method, VerificationStatus: status, VerificationRef: value.ExpectedCNAME, VerifiedAt: value.VerifiedAt, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}, now)
}

func (a *m3PostgresAdapter) PutCertificateReference(ctx context.Context, value domain.CertificateReference) error {
	var platformID, applicationID domain.ID
	var kind string
	err := a.store.DB().QueryRowContext(ctx, `SELECT 'platform',id FROM m3_platform_domains WHERE id=$1 UNION ALL SELECT 'application',id FROM m3_application_domains WHERE id=$1`, value.DomainBindingID.String()).Scan(&kind, new(string))
	if err != nil {
		return err
	}
	if kind == "platform" {
		platformID = value.DomainBindingID
	} else {
		applicationID = value.DomainBindingID
	}
	notBefore, notAfter, renewAfter := value.NotBefore, value.NotAfter, value.RenewAfter
	return a.store.UpsertCertificateReference(ctx, postgres.CertificateReference{ID: value.ID, PlatformDomainID: platformID, ApplicationDomainID: applicationID, SecretReferenceID: value.SecretRef.ID, SubjectHostname: value.Host, Issuer: "Open Card isolated test CA", Status: postgres.CertificateReferenceReady, NotBefore: &notBefore, NotAfter: &notAfter, RenewalDueAt: &renewAfter, CreatedAt: value.UpdatedAt, UpdatedAt: value.UpdatedAt}, value.UpdatedAt)
}

func (a *m3PostgresAdapter) PutDesiredRoute(ctx context.Context, route domain.Route, port int) error {
	leaseID := m3AdapterID("lease", route.ID.String()+":"+route.DeploymentID.String()+":"+fmt.Sprint(port))
	var existingPort int
	err := a.store.DB().QueryRowContext(ctx, `SELECT port FROM m3_port_leases WHERE id=$1`, leaseID.String()).Scan(&existingPort)
	if errors.Is(err, sql.ErrNoRows) {
		err = a.store.CreatePortLease(ctx, postgres.PortLease{ID: leaseID, ApplicationID: route.ApplicationID, DeploymentID: route.DeploymentID, ServiceName: route.ServiceName, BindHost: "127.0.0.1", Port: port, AcquiredAt: route.CreatedAt}, route.CreatedAt)
	} else if err == nil && existingPort != port {
		return domain.NewError(domain.ErrConflict, "port lease identity conflicts")
	}
	if err != nil {
		return err
	}
	var applicationDomainID, certificateID domain.ID
	if route.CertificateRef != "" {
		certificateID = domain.ID(route.CertificateRef)
		var domainID sql.NullString
		if err := a.store.DB().QueryRowContext(ctx, `SELECT application_domain_id FROM m3_certificate_references WHERE id=$1`, route.CertificateRef).Scan(&domainID); err != nil {
			return err
		}
		if domainID.Valid {
			applicationDomainID = domain.ID(domainID.String)
		}
	}
	return a.store.UpsertDesiredRoute(ctx, postgres.DesiredRouteRecord{Route: route, ApplicationDomainID: applicationDomainID, CertificateID: certificateID, State: postgres.DesiredRouteActive, UpdatedAt: route.CreatedAt}, route.CreatedAt)
}

func (a *m3PostgresAdapter) ListDesiredRoutes(ctx context.Context) ([]domain.DesiredRoute, error) {
	items, err := a.store.ListDesiredRoutes(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.DesiredRoute, 0, len(items))
	for _, item := range items {
		if item.State != postgres.DesiredRouteActive || !item.Route.Verified || !item.Route.Serving || item.Pointer == nil || item.Lease == nil || item.Lease.ReleasedAt != nil {
			continue
		}
		route := item.Route
		route.DeploymentID = item.Pointer.DeploymentID
		result = append(result, domain.DesiredRoute{Route: route, Port: item.Lease.Port})
	}
	return result, nil
}

func (a *m3PostgresAdapter) SetRoutePointer(ctx context.Context, routeID, deploymentID domain.ID, key string) error {
	var applicationID domain.ID
	var serviceName string
	var port int
	if err := a.store.DB().QueryRowContext(ctx, `SELECT r.application_id,r.service_name,l.port FROM m3_desired_routes r JOIN m3_port_leases l ON l.application_id=r.application_id AND l.deployment_id=$2 AND l.service_name=r.service_name AND l.released_at IS NULL WHERE r.id=$1 ORDER BY l.acquired_at DESC LIMIT 1`, routeID.String(), deploymentID.String()).Scan(&applicationID, &serviceName, &port); err != nil {
		return err
	}
	_ = serviceName
	leaseID := m3AdapterID("lease", routeID.String()+":"+deploymentID.String()+":"+fmt.Sprint(port))
	var previous sql.NullString
	var revision int64
	err := a.store.DB().QueryRowContext(ctx, `SELECT deployment_id,revision FROM m3_route_pointers WHERE route_id=$1`, routeID.String()).Scan(&previous, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		revision = 0
	} else if err != nil {
		return err
	}
	if previous.Valid && previous.String == deploymentID.String() {
		return nil
	}
	record := postgres.TrafficSwitchRecord{ID: m3AdapterID("switch", key+":"+routeID.String()+":pointer"), ApplicationID: applicationID, RouteID: routeID, NextDeploymentID: deploymentID, Status: postgres.TrafficSwitchSwitched, Reason: "route pointer moved", ObservedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}
	if previous.Valid {
		record.PreviousDeploymentID = domain.ID(previous.String)
	}
	_, err = a.store.CommitTrafficSwitch(ctx, record, postgres.RoutePointer{RouteID: routeID, DeploymentID: deploymentID, PortLeaseID: leaseID}, revision, time.Now().UTC())
	return err
}

func (a *m3PostgresAdapter) RecordTrafficSwitch(ctx context.Context, value domain.TrafficSwitch) error {
	return a.store.RecordTrafficSwitch(ctx, postgres.TrafficSwitchRecord{ID: value.ID, ApplicationID: value.ApplicationID, RouteID: value.RouteID, PreviousDeploymentID: value.PreviousDeploymentID, NextDeploymentID: value.NextDeploymentID, Status: postgres.TrafficSwitchStatus(value.Status), Reason: value.Reason, ObservedAt: value.ObservedAt, CreatedAt: value.ObservedAt}, value.ObservedAt)
}

func (a *m3PostgresAdapter) AppendAccessEvent(ctx context.Context, applicationID domain.ID, key, kind, message string, succeeded bool) error {
	status := domain.PublishDeploying
	if succeeded {
		status = domain.PublishSucceeded
	} else {
		status = domain.PublishFailed
	}
	_, err := a.store.AppendPublishEvent(ctx, m3AdapterID("operation", key), applicationID, status, kind, message, nil, time.Now().UTC())
	return err
}

func childM3Operation(operation contracts.OperationContext, suffix string) contracts.OperationContext {
	operation.IdempotencyKey += ":" + suffix
	return operation
}
func m3AdapterID(prefix, value string) domain.ID {
	sum := sha256.Sum256([]byte(value))
	return domain.ID(prefix + "_" + hex.EncodeToString(sum[:16]))
}

var _ controllers.M3DNSManager = (*m3DNSAdapter)(nil)
var _ controllers.M3CertificateManager = (*m3CertificateAdapter)(nil)
var _ controllers.M3AccessStore = (*m3PostgresAdapter)(nil)
