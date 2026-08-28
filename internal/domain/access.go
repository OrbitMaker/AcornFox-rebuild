package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
	"time"
)

type DomainBindingKind string

const (
	DomainBindingPlatform    DomainBindingKind = "platform"
	DomainBindingApplication DomainBindingKind = "application"
)

type DomainStatus string

const (
	DomainPending            DomainStatus = "pending"
	DomainVerifying          DomainStatus = "verifying"
	DomainVerified           DomainStatus = "verified"
	DomainCertificatePending DomainStatus = "certificate_pending"
	DomainReady              DomainStatus = "ready"
	DomainFailed             DomainStatus = "failed"
)

type CertificateStatus string

const (
	CertificatePending  CertificateStatus = "pending"
	CertificateReady    CertificateStatus = "ready"
	CertificateRenewing CertificateStatus = "renewing"
	CertificateFailed   CertificateStatus = "failed"
)

type DomainBinding struct {
	ID               ID                `json:"id"`
	Kind             DomainBindingKind `json:"kind"`
	ApplicationID    ID                `json:"application_id,omitempty"`
	PlatformDomainID ID                `json:"platform_domain_id,omitempty"`
	Managed          bool              `json:"managed"`
	Host             string            `json:"host"`
	ExpectedCNAME    string            `json:"expected_cname,omitempty"`
	Status           DomainStatus      `json:"status"`
	CertificateRef   string            `json:"certificate_ref,omitempty"`
	FailureReason    string            `json:"failure_reason,omitempty"`
	VerifiedAt       *time.Time        `json:"verified_at,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

func (b DomainBinding) Validate() error {
	if err := RequireID(b.ID, "domain binding id"); err != nil {
		return err
	}
	if _, err := NormalizeDNSName(b.Host); err != nil {
		return err
	}
	switch b.Kind {
	case DomainBindingPlatform:
		if !b.ApplicationID.Empty() || !b.PlatformDomainID.Empty() || b.ExpectedCNAME != "" || b.Managed {
			return ValidationError("platform domain cannot belong to an application or require CNAME")
		}
	case DomainBindingApplication:
		if err := RequireID(b.ApplicationID, "application domain application id"); err != nil {
			return err
		}
		if b.Managed {
			if b.PlatformDomainID.Empty() || b.ExpectedCNAME != "" {
				return ValidationError("managed application domain requires its platform domain and no CNAME")
			}
		} else if _, err := NormalizeDNSName(b.ExpectedCNAME); err != nil {
			return ValidationError("custom application domain requires a valid CNAME target")
		}
	default:
		return ValidationError("domain binding kind is unsupported")
	}
	switch b.Status {
	case DomainPending, DomainVerifying, DomainVerified, DomainCertificatePending, DomainReady, DomainFailed:
	default:
		return ValidationError("domain binding status is unsupported")
	}
	if b.Status == DomainReady && strings.TrimSpace(b.CertificateRef) == "" {
		return ValidationError("ready domain requires a certificate reference")
	}
	return nil
}

type CertificateReference struct {
	ID              ID                `json:"id"`
	DomainBindingID ID                `json:"domain_binding_id"`
	Host            string            `json:"host"`
	SecretRef       SecretReference   `json:"secret_ref"`
	Status          CertificateStatus `json:"status"`
	Fingerprint     string            `json:"fingerprint,omitempty"`
	NotBefore       time.Time         `json:"not_before,omitempty"`
	NotAfter        time.Time         `json:"not_after,omitempty"`
	RenewAfter      time.Time         `json:"renew_after,omitempty"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

func (c CertificateReference) Validate() error {
	if err := RequireID(c.ID, "certificate reference id"); err != nil {
		return err
	}
	if err := RequireID(c.DomainBindingID, "certificate domain binding id"); err != nil {
		return err
	}
	if _, err := NormalizeDNSName(strings.TrimPrefix(c.Host, "*.")); err != nil {
		return err
	}
	switch c.Status {
	case CertificatePending, CertificateReady, CertificateRenewing, CertificateFailed:
	default:
		return ValidationError("certificate status is unsupported")
	}
	if c.Status == CertificateReady {
		if err := c.SecretRef.Validate(); err != nil {
			return ValidationError("ready certificate requires a valid secret reference")
		}
		if c.NotAfter.IsZero() || !c.NotAfter.After(c.NotBefore) || c.Fingerprint == "" {
			return ValidationError("ready certificate metadata is incomplete")
		}
	}
	return nil
}

type AccessState struct {
	ApplicationID ID           `json:"application_id"`
	DeploymentID  ID           `json:"deployment_id"`
	RuntimeReady  bool         `json:"runtime_ready"`
	IPAvailable   bool         `json:"ip_available"`
	IPAddress     string       `json:"ip_address,omitempty"`
	DomainStatus  DomainStatus `json:"domain_status,omitempty"`
	Domain        string       `json:"domain,omitempty"`
	HTTPSReady    bool         `json:"https_ready"`
	Serving       bool         `json:"serving"`
	ServingOld    bool         `json:"serving_old_release"`
	Message       string       `json:"message"`
}

type DesiredRoute struct {
	Route Route `json:"route"`
	Port  int   `json:"port"`
}

type TrafficSwitch struct {
	ID                   ID        `json:"id"`
	ApplicationID        ID        `json:"application_id"`
	RouteID              ID        `json:"route_id"`
	PreviousDeploymentID ID        `json:"previous_deployment_id,omitempty"`
	NextDeploymentID     ID        `json:"next_deployment_id"`
	Status               string    `json:"status"`
	Reason               string    `json:"reason"`
	ObservedAt           time.Time `json:"observed_at"`
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func NormalizeDNSName(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@[] \\") {
		return "", ValidationError("DNS name is invalid")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", ValidationError("DNS name must contain a suffix")
	}
	for _, part := range parts {
		if !dnsLabel.MatchString(part) {
			return "", ValidationError("DNS label is invalid")
		}
	}
	return value, nil
}

func NormalizeRouteHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	return NormalizeDNSName(value)
}

func NormalizeRoutePath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/", nil
	}
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\") || strings.Contains(value, "//") || strings.Contains(value, "..") {
		return "", ValidationError("route path prefix is invalid")
	}
	if len(value) > 1 {
		value = strings.TrimSuffix(value, "/")
	}
	return value, nil
}

func RoutePathsConflict(left, right string) bool {
	left, leftErr := NormalizeRoutePath(left)
	right, rightErr := NormalizeRoutePath(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	if left == right {
		return true
	}
	if left == "/" || right == "/" {
		return false
	}
	return strings.HasPrefix(left+"/", right+"/") || strings.HasPrefix(right+"/", left+"/")
}

var slugUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

func StableApplicationHost(name string, applicationID ID, baseDomain string) (string, error) {
	if err := RequireID(applicationID, "application id"); err != nil {
		return "", err
	}
	base, err := NormalizeDNSName(baseDomain)
	if err != nil {
		return "", err
	}
	slug := strings.Trim(slugUnsafe.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
	if slug == "" {
		slug = "app"
	}
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	sum := sha256.Sum256([]byte(applicationID))
	short := hex.EncodeToString(sum[:4])
	return slug + "-" + short + ".apps." + base, nil
}
