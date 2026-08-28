package postgres

// M3 access persistence keeps the desired routing model separate from Caddy.
// A running Caddy instance is an eventually reconstructed projection; these
// rows, secret references and immutable switch history are the durable facts.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var ErrRoutePointerConflict = errors.New("route pointer revision conflict")

type DomainVerificationStatus string

const (
	DomainVerificationPending  DomainVerificationStatus = "pending"
	DomainVerificationVerified DomainVerificationStatus = "verified"
	DomainVerificationFailed   DomainVerificationStatus = "failed"
)

type CertificateReferenceStatus string

const (
	CertificateReferencePending    CertificateReferenceStatus = "pending"
	CertificateReferenceReady      CertificateReferenceStatus = "ready"
	CertificateReferenceRenewalDue CertificateReferenceStatus = "renewal_due"
	CertificateReferenceFailed     CertificateReferenceStatus = "failed"
	CertificateReferenceRevoked    CertificateReferenceStatus = "revoked"
)

type DesiredRouteState string

const (
	DesiredRoutePending  DesiredRouteState = "pending"
	DesiredRouteActive   DesiredRouteState = "active"
	DesiredRouteDisabled DesiredRouteState = "disabled"
	DesiredRouteFailed   DesiredRouteState = "failed"
)

// PlatformDomainRecord represents an operator-owned suffix. dns_provider_ref
// is an opaque fixture/provider reference, never credential material.
type PlatformDomainRecord struct {
	ID                 domain.ID                `json:"id"`
	Hostname           string                   `json:"hostname"`
	DNSProviderRef     string                   `json:"dns_provider_ref"`
	VerificationStatus DomainVerificationStatus `json:"verification_status"`
	WildcardEnabled    bool                     `json:"wildcard_enabled"`
	VerificationRef    string                   `json:"verification_ref,omitempty"`
	VerifiedAt         *time.Time               `json:"verified_at,omitempty"`
	CreatedAt          time.Time                `json:"created_at"`
	UpdatedAt          time.Time                `json:"updated_at"`
}

// ApplicationDomainRecord is either a platform-generated name or a user
// custom CNAME. DNS provider credentials are deliberately not accepted here.
type ApplicationDomainRecord struct {
	ID                 domain.ID                `json:"id"`
	ApplicationID      domain.ID                `json:"application_id"`
	PlatformDomainID   domain.ID                `json:"platform_domain_id,omitempty"`
	Hostname           string                   `json:"hostname"`
	Kind               string                   `json:"kind"`
	StableSlug         string                   `json:"stable_slug,omitempty"`
	VerificationMethod string                   `json:"verification_method"`
	VerificationStatus DomainVerificationStatus `json:"verification_status"`
	VerificationRef    string                   `json:"verification_ref,omitempty"`
	VerifiedAt         *time.Time               `json:"verified_at,omitempty"`
	CreatedAt          time.Time                `json:"created_at"`
	UpdatedAt          time.Time                `json:"updated_at"`
}

// CertificateReference intentionally carries only an opaque SecretProvider
// reference. There is no private-key value, PEM, or key passphrase field.
type CertificateReference struct {
	ID                  domain.ID                  `json:"id"`
	PlatformDomainID    domain.ID                  `json:"platform_domain_id,omitempty"`
	ApplicationDomainID domain.ID                  `json:"application_domain_id,omitempty"`
	SecretReferenceID   domain.ID                  `json:"secret_reference_id"`
	SubjectHostname     string                     `json:"subject_hostname"`
	Issuer              string                     `json:"issuer"`
	Status              CertificateReferenceStatus `json:"status"`
	NotBefore           *time.Time                 `json:"not_before,omitempty"`
	NotAfter            *time.Time                 `json:"not_after,omitempty"`
	RenewalDueAt        *time.Time                 `json:"renewal_due_at,omitempty"`
	CreatedAt           time.Time                  `json:"created_at"`
	UpdatedAt           time.Time                  `json:"updated_at"`
}

type PortLease struct {
	ID            domain.ID  `json:"id"`
	ApplicationID domain.ID  `json:"application_id"`
	DeploymentID  domain.ID  `json:"deployment_id"`
	ServiceName   string     `json:"service_name"`
	BindHost      string     `json:"bind_host"`
	Port          int        `json:"port"`
	AcquiredAt    time.Time  `json:"acquired_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ReleasedAt    *time.Time `json:"released_at,omitempty"`
}

// DesiredRouteRecord persists the complete domain.Route fact plus M3's domain
// binding/state. Its selected upstream lives in RoutePointer/PortLease so it
// can move atomically without treating a Caddy config file as authoritative.
type DesiredRouteRecord struct {
	Route               domain.Route      `json:"route"`
	ApplicationDomainID domain.ID         `json:"application_domain_id,omitempty"`
	CertificateID       domain.ID         `json:"certificate_id,omitempty"`
	State               DesiredRouteState `json:"state"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

type RoutePointer struct {
	RouteID      domain.ID `json:"route_id"`
	DeploymentID domain.ID `json:"deployment_id"`
	PortLeaseID  domain.ID `json:"port_lease_id"`
	Revision     int64     `json:"revision"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type DesiredRouteProjection struct {
	DesiredRouteRecord
	Pointer *RoutePointer `json:"pointer,omitempty"`
	Lease   *PortLease    `json:"lease,omitempty"`
}

type TrafficSwitchStatus string

const (
	TrafficSwitchStarted    TrafficSwitchStatus = "started"
	TrafficSwitchHealthy    TrafficSwitchStatus = "healthy"
	TrafficSwitchSwitched   TrafficSwitchStatus = "switched"
	TrafficSwitchFailed     TrafficSwitchStatus = "failed"
	TrafficSwitchOldServing TrafficSwitchStatus = "old_serving"
	TrafficSwitchStable     TrafficSwitchStatus = "stable"
)

type TrafficSwitchRecord struct {
	ID                   domain.ID           `json:"id"`
	ApplicationID        domain.ID           `json:"application_id"`
	RouteID              domain.ID           `json:"route_id"`
	PreviousDeploymentID domain.ID           `json:"previous_deployment_id,omitempty"`
	NextDeploymentID     domain.ID           `json:"next_deployment_id"`
	Status               TrafficSwitchStatus `json:"status"`
	Reason               string              `json:"reason"`
	ObservedAt           time.Time           `json:"observed_at"`
	CreatedAt            time.Time           `json:"created_at"`
}

func NormalizeM3Hostname(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !m3Hostname(value, false) {
		return "", domain.ValidationError("hostname must be a normalized DNS name")
	}
	return value, nil
}

func normalizeM3RouteHost(value string) (string, error) {
	return domain.NormalizeRouteHost(value)
}

func normalizeM3CertificateHostname(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !m3Hostname(value, true) {
		return "", domain.ValidationError("certificate subject must be a normalized DNS name")
	}
	return value, nil
}

func m3Hostname(value string, wildcard bool) bool {
	if wildcard && strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func NormalizeM3PathPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "/" {
		return value, nil
	}
	if !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsAny(value, "?#") || strings.Contains(value, "//") {
		return "", domain.ValidationError("route path prefix must be normalized and absolute")
	}
	for _, part := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return "", domain.ValidationError("route path prefix contains an unsafe segment")
		}
	}
	return value, nil
}

func (r PlatformDomainRecord) Validate() error {
	if err := domain.RequireID(r.ID, "platform domain id"); err != nil {
		return err
	}
	canonicalHost, err := NormalizeM3Hostname(r.Hostname)
	if err != nil || canonicalHost != r.Hostname {
		if err != nil {
			return err
		}
		return domain.ValidationError("platform hostname must be normalized")
	}
	if strings.TrimSpace(r.DNSProviderRef) == "" {
		return domain.ValidationError("platform DNS provider reference is required")
	}
	if !m3VerificationStatus(r.VerificationStatus) {
		return domain.ValidationError("platform domain verification status is unsupported")
	}
	if (r.VerificationStatus == DomainVerificationVerified) != (r.VerifiedAt != nil) {
		return domain.ValidationError("platform verified timestamp does not match status")
	}
	return nil
}

func (r ApplicationDomainRecord) Validate() error {
	if err := domain.RequireID(r.ID, "application domain id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.ApplicationID, "application domain application id"); err != nil {
		return err
	}
	canonicalHost, err := NormalizeM3Hostname(r.Hostname)
	if err != nil || canonicalHost != r.Hostname {
		if err != nil {
			return err
		}
		return domain.ValidationError("application hostname must be normalized")
	}
	if !m3VerificationStatus(r.VerificationStatus) {
		return domain.ValidationError("application domain verification status is unsupported")
	}
	if (r.VerificationStatus == DomainVerificationVerified) != (r.VerifiedAt != nil) {
		return domain.ValidationError("application domain verified timestamp does not match status")
	}
	switch r.Kind {
	case "platform":
		if r.PlatformDomainID.Empty() || r.VerificationMethod != "dns01" || !m3Slug(r.StableSlug) {
			return domain.ValidationError("platform domain requires DNS-01, platform reference, and stable slug")
		}
	case "custom":
		if !r.PlatformDomainID.Empty() || r.VerificationMethod != "cname" || r.StableSlug != "" {
			return domain.ValidationError("custom domain must be CNAME-only and cannot carry a platform slug")
		}
	default:
		return domain.ValidationError("application domain kind is unsupported")
	}
	return nil
}

func m3Slug(value string) bool {
	value = strings.TrimSpace(value)
	if value != strings.ToLower(value) || len(value) < 2 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
			return false
		}
	}
	return true
}

func (r CertificateReference) Validate() error {
	if err := domain.RequireID(r.ID, "certificate reference id"); err != nil {
		return err
	}
	if r.PlatformDomainID.Empty() == r.ApplicationDomainID.Empty() {
		return domain.ValidationError("certificate reference must have exactly one domain owner")
	}
	if err := domain.RequireID(r.SecretReferenceID, "certificate secret reference id"); err != nil {
		return err
	}
	canonicalSubject, err := normalizeM3CertificateHostname(r.SubjectHostname)
	if err != nil || canonicalSubject != r.SubjectHostname {
		if err != nil {
			return err
		}
		return domain.ValidationError("certificate subject must be normalized")
	}
	if strings.TrimSpace(r.Issuer) == "" {
		return domain.ValidationError("certificate issuer is required")
	}
	if r.Status != CertificateReferencePending && r.Status != CertificateReferenceReady && r.Status != CertificateReferenceRenewalDue && r.Status != CertificateReferenceFailed && r.Status != CertificateReferenceRevoked {
		return domain.ValidationError("certificate reference status is unsupported")
	}
	if (r.NotBefore == nil) != (r.NotAfter == nil) || (r.NotBefore != nil && !r.NotAfter.After(*r.NotBefore)) {
		return domain.ValidationError("certificate validity must be a complete positive interval")
	}
	return nil
}

func (r PortLease) Validate() error {
	if err := domain.RequireID(r.ID, "port lease id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.ApplicationID, "port lease application id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.DeploymentID, "port lease deployment id"); err != nil {
		return err
	}
	if strings.TrimSpace(r.ServiceName) == "" || strings.TrimSpace(r.BindHost) == "" || r.Port < 1 || r.Port > 65535 {
		return domain.ValidationError("port lease service, bind host, and port are required")
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(r.AcquiredAt) {
		return domain.ValidationError("port lease expiry must follow acquisition")
	}
	if r.ReleasedAt != nil && r.ReleasedAt.Before(r.AcquiredAt) {
		return domain.ValidationError("port lease release cannot predate acquisition")
	}
	return nil
}

func (r DesiredRouteRecord) Validate() error {
	if err := r.Route.Validate(); err != nil {
		return err
	}
	canonicalHost, err := normalizeM3RouteHost(r.Route.Host)
	if err != nil || canonicalHost != r.Route.Host {
		if err != nil {
			return err
		}
		return domain.ValidationError("desired route hostname must be normalized")
	}
	canonicalPath, err := NormalizeM3PathPrefix(r.Route.Path)
	if err != nil || canonicalPath != r.Route.Path {
		if err != nil {
			return err
		}
		return domain.ValidationError("desired route path must be normalized")
	}
	if r.Route.ServiceName == "" {
		return domain.ValidationError("desired route service name is required")
	}
	if r.State != DesiredRoutePending && r.State != DesiredRouteActive && r.State != DesiredRouteDisabled && r.State != DesiredRouteFailed {
		return domain.ValidationError("desired route state is unsupported")
	}
	if r.Route.Verified && r.State == DesiredRoutePending && (r.Route.Serving || !r.CertificateID.Empty() || r.Route.CertificateRef != "") {
		return domain.ValidationError("TLS allow desired route must be verified, non-serving, and certificate-free")
	}
	if r.Route.Serving && (!r.Route.Verified || r.State != DesiredRouteActive) {
		return domain.ValidationError("serving route must be verified and active")
	}
	if !r.CertificateID.Empty() && r.Route.CertificateRef != r.CertificateID.String() {
		return domain.ValidationError("route certificate reference does not match certificate fact")
	}
	if r.CertificateID.Empty() && r.Route.CertificateRef != "" {
		return domain.ValidationError("route certificate reference must be an M3 certificate id")
	}
	return nil
}

func (r RoutePointer) Validate() error {
	if err := domain.RequireID(r.RouteID, "route pointer route id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.DeploymentID, "route pointer deployment id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.PortLeaseID, "route pointer port lease id"); err != nil {
		return err
	}
	if r.Revision < 0 {
		return domain.ValidationError("route pointer revision cannot be negative")
	}
	return nil
}

func (r TrafficSwitchRecord) Validate() error {
	if err := domain.RequireID(r.ID, "traffic switch id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.ApplicationID, "traffic switch application id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.RouteID, "traffic switch route id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.NextDeploymentID, "traffic switch next deployment id"); err != nil {
		return err
	}
	if !r.PreviousDeploymentID.Empty() && r.PreviousDeploymentID == r.NextDeploymentID {
		return domain.ValidationError("traffic switch targets must differ")
	}
	if r.Status != TrafficSwitchStarted && r.Status != TrafficSwitchHealthy && r.Status != TrafficSwitchSwitched && r.Status != TrafficSwitchFailed && r.Status != TrafficSwitchOldServing && r.Status != TrafficSwitchStable {
		return domain.ValidationError("traffic switch status is unsupported")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return domain.ValidationError("traffic switch reason is required")
	}
	return nil
}

func m3VerificationStatus(value DomainVerificationStatus) bool {
	return value == DomainVerificationPending || value == DomainVerificationVerified || value == DomainVerificationFailed
}

func (s *Store) UpsertPlatformDomain(ctx context.Context, record PlatformDomainRecord, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	record.Hostname = strings.ToLower(strings.TrimSpace(record.Hostname))
	record.DNSProviderRef = strings.TrimSpace(record.DNSProviderRef)
	record.VerificationRef = strings.TrimSpace(record.VerificationRef)
	if err := record.Validate(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO m3_platform_domains(id,hostname,dns_provider_ref,verification_status,wildcard_enabled,verification_ref,verified_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET hostname=EXCLUDED.hostname,dns_provider_ref=EXCLUDED.dns_provider_ref,verification_status=EXCLUDED.verification_status,wildcard_enabled=EXCLUDED.wildcard_enabled,verification_ref=EXCLUDED.verification_ref,verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at`, record.ID.String(), record.Hostname, record.DNSProviderRef, record.VerificationStatus, record.WildcardEnabled, nullableM3String(record.VerificationRef), record.VerifiedAt, record.CreatedAt.UTC(), now)
	return err
}

func (s *Store) UpsertApplicationDomain(ctx context.Context, record ApplicationDomainRecord, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	record.Hostname = strings.ToLower(strings.TrimSpace(record.Hostname))
	record.StableSlug = strings.ToLower(strings.TrimSpace(record.StableSlug))
	record.VerificationMethod = strings.TrimSpace(record.VerificationMethod)
	record.VerificationRef = strings.TrimSpace(record.VerificationRef)
	if err := record.Validate(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO m3_application_domains(id,application_id,platform_domain_id,hostname,domain_kind,stable_slug,verification_method,verification_status,verification_ref,verified_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET platform_domain_id=EXCLUDED.platform_domain_id,hostname=EXCLUDED.hostname,domain_kind=EXCLUDED.domain_kind,stable_slug=EXCLUDED.stable_slug,verification_method=EXCLUDED.verification_method,verification_status=EXCLUDED.verification_status,verification_ref=EXCLUDED.verification_ref,verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at`, record.ID.String(), record.ApplicationID.String(), nullableM3ID(record.PlatformDomainID), record.Hostname, record.Kind, nullableM3String(record.StableSlug), record.VerificationMethod, record.VerificationStatus, nullableM3String(record.VerificationRef), record.VerifiedAt, record.CreatedAt.UTC(), now)
	return err
}

func (s *Store) UpsertCertificateReference(ctx context.Context, record CertificateReference, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	record.SubjectHostname = strings.ToLower(strings.TrimSpace(record.SubjectHostname))
	record.Issuer = strings.TrimSpace(record.Issuer)
	if err := record.Validate(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO m3_certificate_references(id,platform_domain_id,application_domain_id,secret_reference_id,subject_hostname,issuer,status,not_before,not_after,renewal_due_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET platform_domain_id=EXCLUDED.platform_domain_id,application_domain_id=EXCLUDED.application_domain_id,secret_reference_id=EXCLUDED.secret_reference_id,subject_hostname=EXCLUDED.subject_hostname,issuer=EXCLUDED.issuer,status=EXCLUDED.status,not_before=EXCLUDED.not_before,not_after=EXCLUDED.not_after,renewal_due_at=EXCLUDED.renewal_due_at,updated_at=EXCLUDED.updated_at`, record.ID.String(), nullableM3ID(record.PlatformDomainID), nullableM3ID(record.ApplicationDomainID), record.SecretReferenceID.String(), record.SubjectHostname, record.Issuer, record.Status, record.NotBefore, record.NotAfter, record.RenewalDueAt, record.CreatedAt.UTC(), now)
	return err
}

func (s *Store) UpsertDesiredRoute(ctx context.Context, record DesiredRouteRecord, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	normalizedHost, err := normalizeM3RouteHost(record.Route.Host)
	if err != nil {
		return err
	}
	record.Route.Host = normalizedHost
	normalizedPath, err := NormalizeM3PathPrefix(record.Route.Path)
	if err != nil {
		return err
	}
	record.Route.Path = normalizedPath
	if err := record.Validate(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if record.Route.CreatedAt.IsZero() {
		record.Route.CreatedAt = now
	}
	record.UpdatedAt = now
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	var existingApplication string
	err = tx.QueryRowContext(ctx, `SELECT application_id FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, record.Route.ID.String()).Scan(&existingApplication)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rollbackTx(tx, fmt.Errorf("read desired route owner: %w", err))
	}
	if err == nil && existingApplication != record.Route.ApplicationID.String() {
		return rollbackTx(tx, domain.ValidationError("desired route id belongs to a different application"))
	}
	if err := m3AssertDeploymentApplicationTx(ctx, tx, record.Route.DeploymentID, record.Route.ApplicationID); err != nil {
		return rollbackTx(tx, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,certificate_reference_id,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(id) DO UPDATE SET application_domain_id=EXCLUDED.application_domain_id,deployment_id=EXCLUDED.deployment_id,service_name=EXCLUDED.service_name,hostname=EXCLUDED.hostname,path_prefix=EXCLUDED.path_prefix,certificate_reference_id=EXCLUDED.certificate_reference_id,desired_state=EXCLUDED.desired_state,verified=EXCLUDED.verified,serving=EXCLUDED.serving,updated_at=EXCLUDED.updated_at`, record.Route.ID.String(), record.Route.ApplicationID.String(), nullableM3ID(record.ApplicationDomainID), record.Route.DeploymentID.String(), record.Route.ServiceName, record.Route.Host, record.Route.Path, nullableM3ID(record.CertificateID), record.State, record.Route.Verified, record.Route.Serving, record.Route.CreatedAt.UTC(), now)
	if err != nil {
		return rollbackTx(tx, err)
	}
	return tx.Commit()
}

func (s *Store) CreatePortLease(ctx context.Context, lease PortLease, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if lease.AcquiredAt.IsZero() {
		lease.AcquiredAt = now
	}
	lease.ServiceName = strings.TrimSpace(lease.ServiceName)
	lease.BindHost = strings.TrimSpace(lease.BindHost)
	if err := lease.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := m3AssertDeploymentApplicationTx(ctx, tx, lease.DeploymentID, lease.ApplicationID); err != nil {
		return rollbackTx(tx, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at,expires_at,released_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, lease.ID.String(), lease.ApplicationID.String(), lease.DeploymentID.String(), lease.ServiceName, lease.BindHost, lease.Port, lease.AcquiredAt.UTC(), lease.ExpiresAt, lease.ReleasedAt)
	if err != nil {
		return rollbackTx(tx, err)
	}
	return tx.Commit()
}

// ReleasePortLease preserves the lease fact while making its endpoint reusable.
func (s *Store) ReleasePortLease(ctx context.Context, leaseID domain.ID, releasedAt time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(leaseID, "port lease id"); err != nil {
		return err
	}
	releasedAt = m3Now(s, releasedAt)
	result, err := s.db.ExecContext(ctx, `UPDATE m3_port_leases SET released_at=$2 WHERE id=$1 AND released_at IS NULL AND acquired_at <= $2`, leaseID.String(), releasedAt)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

// ListDesiredRoutes returns all desired facts in Caddy rebuild order. Callers
// must treat disabled/failed state as removal, rather than deleting the fact.
func (s *Store) ListDesiredRoutes(ctx context.Context) ([]DesiredRouteProjection, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.application_id,r.application_domain_id,r.deployment_id,r.service_name,r.hostname,r.path_prefix,r.certificate_reference_id,r.desired_state,r.verified,r.serving,r.created_at,r.updated_at,p.deployment_id,p.port_lease_id,p.revision,p.updated_at,l.application_id,l.deployment_id,l.service_name,l.bind_host,l.port,l.acquired_at,l.expires_at,l.released_at FROM m3_desired_routes r LEFT JOIN m3_route_pointers p ON p.route_id=r.id LEFT JOIN m3_port_leases l ON l.id=p.port_lease_id ORDER BY r.hostname,r.path_prefix,r.id`)
	if err != nil {
		return nil, fmt.Errorf("list desired routes: %w", err)
	}
	defer rows.Close()
	result := make([]DesiredRouteProjection, 0)
	for rows.Next() {
		item, err := scanM3DesiredRouteProjection(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate desired routes: %w", err)
	}
	return result, nil
}

func (s *Store) RecordTrafficSwitch(ctx context.Context, record TrafficSwitchRecord, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if record.ObservedAt.IsZero() {
		record.ObservedAt = now
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.Reason = foundation.RedactText(strings.TrimSpace(record.Reason))
	if err := record.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := m3AssertRouteAndDeploymentTx(ctx, tx, record.RouteID, record.ApplicationID, record.NextDeploymentID); err != nil {
		return rollbackTx(tx, err)
	}
	if !record.PreviousDeploymentID.Empty() {
		if err := m3AssertDeploymentApplicationTx(ctx, tx, record.PreviousDeploymentID, record.ApplicationID); err != nil {
			return rollbackTx(tx, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m3_traffic_switches(id,application_id,route_id,previous_deployment_id,next_deployment_id,status,reason,observed_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.ID.String(), record.ApplicationID.String(), record.RouteID.String(), nullableM3ID(record.PreviousDeploymentID), record.NextDeploymentID.String(), record.Status, record.Reason, record.ObservedAt.UTC(), record.CreatedAt.UTC()); err != nil {
		return rollbackTx(tx, err)
	}
	return tx.Commit()
}

// CommitTrafficSwitch atomically moves the durable route pointer and appends
// the switched history fact. expectedRevision is zero for a first pointer.
func (s *Store) CommitTrafficSwitch(ctx context.Context, record TrafficSwitchRecord, pointer RoutePointer, expectedRevision int64, now time.Time) (RoutePointer, error) {
	if err := s.requireDB(); err != nil {
		return RoutePointer{}, err
	}
	if expectedRevision < 0 {
		return RoutePointer{}, domain.ValidationError("expected route pointer revision cannot be negative")
	}
	now = m3Now(s, now)
	if record.ObservedAt.IsZero() {
		record.ObservedAt = now
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.Reason = foundation.RedactText(strings.TrimSpace(record.Reason))
	if err := record.Validate(); err != nil {
		return RoutePointer{}, err
	}
	if record.Status != TrafficSwitchSwitched {
		return RoutePointer{}, domain.ValidationError("atomic route pointer requires switched status")
	}
	pointer.RouteID = record.RouteID
	pointer.DeploymentID = record.NextDeploymentID
	if err := pointer.Validate(); err != nil {
		return RoutePointer{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RoutePointer{}, err
	}
	rollback := func(cause error) (RoutePointer, error) { return RoutePointer{}, rollbackTx(tx, cause) }
	if err := m3AssertRouteAndDeploymentTx(ctx, tx, record.RouteID, record.ApplicationID, pointer.DeploymentID); err != nil {
		return rollback(err)
	}
	if err := m3AssertLeaseTx(ctx, tx, pointer.PortLeaseID, record.ApplicationID, pointer.DeploymentID); err != nil {
		return rollback(err)
	}
	var previous sql.NullString
	var currentRevision int64
	err = tx.QueryRowContext(ctx, `SELECT deployment_id,revision FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, pointer.RouteID.String()).Scan(&previous, &currentRevision)
	if errors.Is(err, sql.ErrNoRows) {
		if expectedRevision != 0 {
			return rollback(ErrRoutePointerConflict)
		}
		currentRevision = 0
	} else if err != nil {
		return rollback(fmt.Errorf("load route pointer: %w", err))
	} else if currentRevision != expectedRevision {
		return rollback(ErrRoutePointerConflict)
	}
	if previous.Valid != !record.PreviousDeploymentID.Empty() || (previous.Valid && previous.String != record.PreviousDeploymentID.String()) {
		return rollback(domain.ValidationError("traffic switch previous deployment does not match route pointer"))
	}
	pointer.Revision = currentRevision + 1
	pointer.UpdatedAt = now
	if currentRevision == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,$4,$5)`, pointer.RouteID.String(), pointer.DeploymentID.String(), pointer.PortLeaseID.String(), pointer.Revision, now)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE m3_route_pointers SET deployment_id=$2,port_lease_id=$3,revision=$4,updated_at=$5 WHERE route_id=$1 AND revision=$6`, pointer.RouteID.String(), pointer.DeploymentID.String(), pointer.PortLeaseID.String(), pointer.Revision, now, currentRevision)
	}
	if err != nil {
		return rollback(fmt.Errorf("move route pointer: %w", err))
	}
	if _, err = tx.ExecContext(ctx, `UPDATE m3_desired_routes SET deployment_id=$2,updated_at=$3 WHERE id=$1`, pointer.RouteID.String(), pointer.DeploymentID.String(), now); err != nil {
		return rollback(fmt.Errorf("update desired route deployment: %w", err))
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO m3_traffic_switches(id,application_id,route_id,previous_deployment_id,next_deployment_id,status,reason,observed_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.ID.String(), record.ApplicationID.String(), record.RouteID.String(), nullableM3ID(record.PreviousDeploymentID), record.NextDeploymentID.String(), record.Status, record.Reason, record.ObservedAt.UTC(), record.CreatedAt.UTC()); err != nil {
		return rollback(fmt.Errorf("append route switch: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return RoutePointer{}, fmt.Errorf("%w: commit route switch: %v", ErrOutcomeUnknown, err)
	}
	return pointer, nil
}

func (s *Store) ListTrafficSwitches(ctx context.Context, routeID domain.ID, limit int) ([]TrafficSwitchRecord, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(routeID, "traffic switch route id"); err != nil {
		return nil, err
	}
	limit = normalizeM3Limit(limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id,application_id,route_id,previous_deployment_id,next_deployment_id,status,reason,observed_at,created_at FROM m3_traffic_switches WHERE route_id=$1 ORDER BY observed_at DESC,id DESC LIMIT $2`, routeID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TrafficSwitchRecord, 0)
	for rows.Next() {
		var item TrafficSwitchRecord
		var previous sql.NullString
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.RouteID, &previous, &item.NextDeploymentID, &item.Status, &item.Reason, &item.ObservedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		if previous.Valid {
			item.PreviousDeploymentID = domain.ID(previous.String)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func m3AssertDeploymentApplicationTx(ctx context.Context, tx *sql.Tx, deploymentID, applicationID domain.ID) error {
	var actual string
	err := tx.QueryRowContext(ctx, `SELECT e.application_id FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`, deploymentID.String()).Scan(&actual)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if actual != applicationID.String() {
		return domain.ValidationError("deployment does not belong to application")
	}
	return nil
}

func m3AssertRouteAndDeploymentTx(ctx context.Context, tx *sql.Tx, routeID, applicationID, deploymentID domain.ID) error {
	var actual string
	err := tx.QueryRowContext(ctx, `SELECT application_id FROM m3_desired_routes WHERE id=$1`, routeID.String()).Scan(&actual)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if actual != applicationID.String() {
		return domain.ValidationError("route does not belong to application")
	}
	return m3AssertDeploymentApplicationTx(ctx, tx, deploymentID, applicationID)
}

func m3AssertLeaseTx(ctx context.Context, tx *sql.Tx, leaseID, applicationID, deploymentID domain.ID) error {
	var app, deployment string
	var released sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT application_id,deployment_id,released_at FROM m3_port_leases WHERE id=$1 FOR SHARE`, leaseID.String()).Scan(&app, &deployment, &released)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if released.Valid || app != applicationID.String() || deployment != deploymentID.String() {
		return domain.ValidationError("route pointer lease does not belong to active target")
	}
	return nil
}

func scanM3DesiredRouteProjection(rows interface{ Scan(...any) error }) (DesiredRouteProjection, error) {
	var item DesiredRouteProjection
	var applicationDomain, certificate, pointerDeployment, pointerLease sql.NullString
	var pointerRevision sql.NullInt64
	var pointerUpdated sql.NullTime
	var leaseApp, leaseDeployment, leaseService, leaseHost sql.NullString
	var leasePort sql.NullInt64
	var acquired, expires, released sql.NullTime
	err := rows.Scan(&item.Route.ID, &item.Route.ApplicationID, &applicationDomain, &item.Route.DeploymentID, &item.Route.ServiceName, &item.Route.Host, &item.Route.Path, &certificate, &item.State, &item.Route.Verified, &item.Route.Serving, &item.Route.CreatedAt, &item.UpdatedAt, &pointerDeployment, &pointerLease, &pointerRevision, &pointerUpdated, &leaseApp, &leaseDeployment, &leaseService, &leaseHost, &leasePort, &acquired, &expires, &released)
	if err != nil {
		return DesiredRouteProjection{}, fmt.Errorf("scan desired route: %w", err)
	}
	if applicationDomain.Valid {
		item.ApplicationDomainID = domain.ID(applicationDomain.String)
	}
	if certificate.Valid {
		item.CertificateID = domain.ID(certificate.String)
		item.Route.CertificateRef = certificate.String
	}
	if pointerDeployment.Valid {
		item.Pointer = &RoutePointer{RouteID: item.Route.ID, DeploymentID: domain.ID(pointerDeployment.String), PortLeaseID: domain.ID(pointerLease.String), Revision: pointerRevision.Int64, UpdatedAt: pointerUpdated.Time.UTC()}
		item.Route.DeploymentID = item.Pointer.DeploymentID
		item.Lease = &PortLease{ID: item.Pointer.PortLeaseID, ApplicationID: domain.ID(leaseApp.String), DeploymentID: domain.ID(leaseDeployment.String), ServiceName: leaseService.String, BindHost: leaseHost.String, Port: int(leasePort.Int64), AcquiredAt: acquired.Time.UTC()}
		if expires.Valid {
			value := expires.Time.UTC()
			item.Lease.ExpiresAt = &value
		}
		if released.Valid {
			value := released.Time.UTC()
			item.Lease.ReleasedAt = &value
		}
	}
	if err := item.DesiredRouteRecord.Validate(); err != nil {
		return DesiredRouteProjection{}, fmt.Errorf("invalid persisted desired route: %w", err)
	}
	return item, nil
}

func m3Now(s *Store, value time.Time) time.Time {
	if value.IsZero() {
		value = s.now()
	}
	return value.UTC()
}
func nullableM3ID(value domain.ID) any {
	if value.Empty() {
		return nil
	}
	return value.String()
}
func nullableM3String(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
func normalizeM3Limit(limit int) int {
	if limit <= 0 {
		return defaultQueryLimit
	}
	if limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}
