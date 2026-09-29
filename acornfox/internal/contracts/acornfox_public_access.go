package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/acornfox/acornfox/internal/domain"
)

// AcornFoxPublicAccessStatus is deliberately smaller than a DNS or TLS state
// machine. The standalone control plane can record that it asked its local
// router to expose an application, but it must never turn that request into a
// claim that public DNS, certificates, or Internet reachability are ready.
type AcornFoxPublicAccessStatus string

const (
	AcornFoxPublicDisabled                  AcornFoxPublicAccessStatus = "PUBLIC_DISABLED"
	AcornFoxPublicPendingExternalValidation AcornFoxPublicAccessStatus = "PENDING_EXTERNAL_VALIDATION"
)

// AcornFoxInternalEndpointState describes only whether the canonical M3 route
// graph proves an accepted loopback endpoint. It is deliberately not a
// reachability or public-network observation.
type AcornFoxInternalEndpointState string

const (
	AcornFoxInternalEndpointAccepted    AcornFoxInternalEndpointState = "accepted"
	AcornFoxInternalEndpointNotObserved AcornFoxInternalEndpointState = "not_observed"
)

// AcornFoxLocalRouteState separates the desired route fact from the outcome
// of asking the local route provider to apply it. In particular, a command
// that survived a provider error must remain reconcile_required rather than
// being presented as configured.
type AcornFoxLocalRouteState string

const (
	AcornFoxLocalRouteDesired           AcornFoxLocalRouteState = "desired"
	AcornFoxLocalRouteReconcileRequired AcornFoxLocalRouteState = "reconcile_required"
	AcornFoxLocalRouteConfigured        AcornFoxLocalRouteState = "configured"
	AcornFoxLocalRouteDisabled          AcornFoxLocalRouteState = "disabled"
)

// AcornFoxRoutableEndpoint is the narrow accepted endpoint fact needed to
// build an owned local route. It intentionally has no hostname, public IP,
// DNS provider, certificate, or caller-selected network target.
type AcornFoxRoutableEndpoint struct {
	ApplicationID domain.ID `json:"application_id"`
	DeploymentID  domain.ID `json:"deployment_id"`
	ServiceName   string    `json:"service_name"`
	Port          int       `json:"port"`
	Accepted      bool      `json:"accepted"`
}

func (endpoint AcornFoxRoutableEndpoint) Validate() error {
	if endpoint.ApplicationID.Empty() || endpoint.DeploymentID.Empty() || !endpoint.Accepted || !acornFoxRuntimeServiceName.MatchString(endpoint.ServiceName) || endpoint.Port < 1 || endpoint.Port > 65535 {
		return fmt.Errorf("AcornFox routable endpoint is invalid")
	}
	return nil
}

// AcornFoxPublicRouteIntent is the complete owned Caddy route intent. DNS and
// TLS orchestration intentionally do not appear here; later adapters may use
// this immutable identity when they add those separate facts.
type AcornFoxPublicRouteIntent struct {
	ApplicationID domain.ID `json:"application_id"`
	DeploymentID  domain.ID `json:"deployment_id"`
	Hostname      string    `json:"hostname"`
	ServiceName   string    `json:"service_name"`
	Port          int       `json:"port"`
}

// AcornFoxApprovedHostnameRoute is a Core-persisted custom-domain approval,
// not a caller-selected proxy target. A projector must match this exact value
// to a Source.WithRoutes row before touching Caddy. EndpointVersion fences the
// inspected deployment/port fact; Core owns its construction and durability.
type AcornFoxApprovedHostnameRoute struct {
	Route           AcornFoxPublicRouteIntent `json:"route"`
	Endpoint        AcornFoxRoutableEndpoint  `json:"endpoint"`
	ApprovalID      domain.ID                 `json:"approval_id"`
	EndpointVersion string                    `json:"endpoint_version"`
}

func (approval AcornFoxApprovedHostnameRoute) Validate() error {
	host := approval.Route.Hostname
	if approval.Route.Validate() != nil || approval.Endpoint.Validate() != nil ||
		approval.Endpoint.ApplicationID != approval.Route.ApplicationID || approval.Endpoint.DeploymentID != approval.Route.DeploymentID ||
		approval.Endpoint.ServiceName != approval.Route.ServiceName || approval.Endpoint.Port != approval.Route.Port ||
		approval.ApprovalID.Empty() || !IsSHA256Digest(approval.EndpointVersion) ||
		!strings.Contains(host, ".") || net.ParseIP(host) != nil || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("AcornFox approved hostname route is invalid")
	}
	return nil
}

func (intent AcornFoxPublicRouteIntent) Validate() error {
	if intent.ApplicationID.Empty() || intent.DeploymentID.Empty() || !validAcornFoxPublicHostname(intent.Hostname) || !acornFoxRuntimeServiceName.MatchString(intent.ServiceName) || intent.Port < 1 || intent.Port > 65535 {
		return fmt.Errorf("AcornFox public route intent is invalid")
	}
	return nil
}

// RouteSpec returns the existing provider-neutral route seam. Verified means
// the route is an accepted, exact local target; it is not DNS/TLS/public
// readiness, which remains represented by PENDING_EXTERNAL_VALIDATION.
func (intent AcornFoxPublicRouteIntent) RouteSpec() (RouteSpec, error) {
	if err := intent.Validate(); err != nil {
		return RouteSpec{}, err
	}
	return RouteSpec{Host: intent.Hostname, Path: "/", DeploymentID: intent.DeploymentID, ServiceName: intent.ServiceName, Port: intent.Port, Verified: true}, nil
}

// AcornFoxPublicAccessFact is a durable command result. Its two statuses are
// intentionally the only states exposed by the single-node local leaf.
type AcornFoxPublicAccessFact struct {
	ApplicationID    domain.ID                     `json:"application_id"`
	DeploymentID     domain.ID                     `json:"deployment_id"`
	Hostname         string                        `json:"hostname"`
	Status           AcornFoxPublicAccessStatus    `json:"status"`
	DesiredPublic    bool                          `json:"desired_public"`
	InternalEndpoint AcornFoxInternalEndpointState `json:"internal_endpoint"`
	LocalRoute       AcornFoxLocalRouteState       `json:"local_route"`
}

func (fact AcornFoxPublicAccessFact) Validate() error {
	if fact.ApplicationID.Empty() || fact.DeploymentID.Empty() || !validAcornFoxPublicHostname(fact.Hostname) {
		return fmt.Errorf("AcornFox public access fact is invalid")
	}
	if fact.InternalEndpoint != AcornFoxInternalEndpointAccepted && fact.InternalEndpoint != AcornFoxInternalEndpointNotObserved {
		return fmt.Errorf("AcornFox public internal endpoint state is invalid")
	}
	switch fact.LocalRoute {
	case AcornFoxLocalRouteDesired, AcornFoxLocalRouteReconcileRequired, AcornFoxLocalRouteConfigured, AcornFoxLocalRouteDisabled:
	default:
		return fmt.Errorf("AcornFox public local route state is invalid")
	}
	switch fact.Status {
	case AcornFoxPublicPendingExternalValidation:
		if !fact.DesiredPublic || fact.InternalEndpoint != AcornFoxInternalEndpointAccepted || (fact.LocalRoute != AcornFoxLocalRouteDesired && fact.LocalRoute != AcornFoxLocalRouteReconcileRequired && fact.LocalRoute != AcornFoxLocalRouteConfigured) {
			return fmt.Errorf("AcornFox pending public access fact is inconsistent")
		}
	case AcornFoxPublicDisabled:
		if fact.DesiredPublic || (fact.LocalRoute != AcornFoxLocalRouteDisabled && fact.LocalRoute != AcornFoxLocalRouteReconcileRequired) {
			return fmt.Errorf("AcornFox disabled public access fact is inconsistent")
		}
	default:
		return fmt.Errorf("AcornFox public access status is invalid")
	}
	return nil
}

// AcornFoxPublicHostname derives a stable DNS-safe name from immutable
// identities. The configured value is an authorized root (for example,
// example.test), never a caller-provided hostname; every resulting host lives
// below apps.<authorized-root>.
func AcornFoxPublicHostname(authorizedRoot string, applicationID, deploymentID domain.ID) (string, error) {
	if applicationID.Empty() || deploymentID.Empty() {
		return "", fmt.Errorf("AcornFox public hostname identity is invalid")
	}
	root, err := normalizeAcornFoxAuthorizedRoot(authorizedRoot)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte("acornfox-public-access\x00" + applicationID.String() + "\x00" + deploymentID.String()))
	// 20 hex characters leave a short label and retain a collision-resistant,
	// non-reversible identity projection. Both identities feed the digest.
	return "delivery-" + hex.EncodeToString(digest[:10]) + ".apps." + root, nil
}

// NewAcornFoxPublicRouteIntent accepts only a persisted exact endpoint fact.
// It has no DNS/provider parameter by design.
func NewAcornFoxPublicRouteIntent(authorizedRoot string, endpoint AcornFoxRoutableEndpoint) (AcornFoxPublicRouteIntent, error) {
	if err := endpoint.Validate(); err != nil {
		return AcornFoxPublicRouteIntent{}, err
	}
	hostname, err := AcornFoxPublicHostname(authorizedRoot, endpoint.ApplicationID, endpoint.DeploymentID)
	if err != nil {
		return AcornFoxPublicRouteIntent{}, err
	}
	intent := AcornFoxPublicRouteIntent{ApplicationID: endpoint.ApplicationID, DeploymentID: endpoint.DeploymentID, Hostname: hostname, ServiceName: endpoint.ServiceName, Port: endpoint.Port}
	if err := intent.Validate(); err != nil {
		return AcornFoxPublicRouteIntent{}, err
	}
	return intent, nil
}

func normalizeAcornFoxAuthorizedRoot(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || strings.HasPrefix(value, "*.") || strings.HasPrefix(value, "apps.") || !validAcornFoxPublicHostname(value) {
		return "", fmt.Errorf("AcornFox authorized root is invalid")
	}
	return value, nil
}

func validAcornFoxPublicHostname(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}
