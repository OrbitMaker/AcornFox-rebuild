package contracts

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const ImagePublicAccessTaskKind = "image.public_access"

type ImagePublicAccessAction string

const (
	ImagePublicAccessEnsure ImagePublicAccessAction = "ensure"
	ImagePublicAccessRemove ImagePublicAccessAction = "remove"
)

// ImagePublicAccessCommand is a durable Core command, not a claim of DNS,
// certificate issuance, or public reachability.
type ImagePublicAccessCommand struct {
	OperationID     domain.ID               `json:"operation_id"`
	TaskID          domain.ID               `json:"task_id"`
	ApprovalID      domain.ID               `json:"approval_id"`
	DeploymentID    domain.ID               `json:"deployment_id"`
	ApplicationID   domain.ID               `json:"application_id"`
	EnvironmentID   domain.ID               `json:"environment_id"`
	ReleaseID       domain.ID               `json:"release_id"`
	Hostname        string                  `json:"hostname"`
	EndpointVersion string                  `json:"endpoint_version"`
	ContainerID     string                  `json:"container_id"`
	HostPort        int                     `json:"host_port"`
	ContainerPort   int                     `json:"container_port"`
	Action          ImagePublicAccessAction `json:"action"`
	State           string                  `json:"state"`
	CreatedAt       time.Time               `json:"created_at"`
}

type ImagePublicAccessRequest struct {
	DeploymentID   domain.ID
	Hostname       string
	Action         ImagePublicAccessAction
	IdempotencyKey string
}

// The public command accepts no proxy target or certificate material.
type ImagePublicAccessCommandInput struct {
	Hostname       string                  `json:"hostname"`
	Action         ImagePublicAccessAction `json:"action"`
	IdempotencyKey string                  `json:"idempotency_key"`
}

type ImagePublicAccessAuthority struct {
	BeginImageExecutionInput
	ApprovalID      domain.ID
	DeploymentID    domain.ID
	EndpointVersion string
	ContainerID     string
	Action          ImagePublicAccessAction
}

// TLS metadata is an observed fingerprint only. PEM and private keys never
// enter this contract or the SQLite domain tables.
type ImagePublicAccessObservation struct {
	// Set only after the scoped projector has returned success for this exact
	// approved route. The Store itself never calls Caddy.
	RouteApplied           bool
	CertificateFingerprint string
	CertificateExpiresAt   time.Time
	ObservedAt             time.Time
}

type ImagePublicAccessApproval struct {
	Command                ImagePublicAccessCommand `json:"command"`
	DesiredPublic          bool                     `json:"desired_public"`
	LocalRouteState        string                   `json:"local_route_state"`
	DeploymentStatus       string                   `json:"deployment_status"`
	CertificateFingerprint string                   `json:"certificate_fingerprint,omitempty"`
	CertificateExpiresAt   *time.Time               `json:"certificate_expires_at,omitempty"`
	ObservedAt             *time.Time               `json:"observed_at,omitempty"`
}

// Public result proves only the scoped local Caddy route observation at the
// recorded time. It does not claim DNS, TLS issuance or external reachability.
type ImagePublicAccessPublicResult struct {
	ObservedAt             time.Time  `json:"observed_at"`
	CertificateFingerprint string     `json:"certificate_fingerprint,omitempty"`
	CertificateExpiresAt   *time.Time `json:"certificate_expires_at,omitempty"`
}

type ImagePublicAccessOperation struct {
	OperationID  domain.ID                      `json:"operation_id"`
	TaskID       domain.ID                      `json:"task_id"`
	ApprovalID   domain.ID                      `json:"approval_id"`
	DeploymentID domain.ID                      `json:"deployment_id"`
	Hostname     string                         `json:"hostname"`
	Action       ImagePublicAccessAction        `json:"action"`
	State        string                         `json:"state"`
	CreatedAt    time.Time                      `json:"created_at"`
	Reason       string                         `json:"reason,omitempty"`
	Result       *ImagePublicAccessPublicResult `json:"result,omitempty"`
}

type ImagePublicAccessCurrent struct {
	Operation        ImagePublicAccessOperation `json:"operation"`
	DesiredPublic    bool                       `json:"desired_public"`
	LocalRouteState  string                     `json:"local_route_state"`
	DeploymentStatus string                     `json:"deployment_status"`
	Availability     string                     `json:"availability"` // disabled|pending|degraded|unverified
}

// The inventory includes disabled rows so the route projector can prove
// ownership while removing a previously managed hostname.
type ImagePublicAccessRoute struct {
	ApprovalID      domain.ID
	OperationID     domain.ID
	ApplicationID   domain.ID
	DeploymentID    domain.ID
	Hostname        string
	ServiceName     string
	HostPort        int
	EndpointVersion string
	Enabled         bool
}

type ImagePublicAccessStore interface {
	BeginImagePublicAccess(context.Context, domain.ID, ImagePublicAccessRequest) (ImagePublicAccessCommand, error)
	ReplayImagePublicAccess(context.Context, domain.ID, ImagePublicAccessRequest) (ImagePublicAccessCommand, error)
	AuthorizeImagePublicAccess(context.Context, ImagePublicAccessAuthority) (ImagePublicAccessCommand, error)
	CommitImagePublicAccess(context.Context, ImagePublicAccessAuthority, ImagePublicAccessObservation) error
	RecordImagePublicAccessUnknown(context.Context, ImagePublicAccessAuthority, string) error
	FailImagePublicAccess(context.Context, ImagePublicAccessAuthority, string) error
	GetImagePublicAccess(context.Context, domain.ID, domain.ID) (ImagePublicAccessApproval, error)
	ReadImagePublicAccessOperation(context.Context, domain.ID, domain.ID) (ImagePublicAccessOperation, error)
	ListImagePublicAccessRoutes(context.Context) ([]ImagePublicAccessRoute, error)
	CheckImagePublicAccessRoute(context.Context, ImagePublicAccessRoute) error
}

// ValidateImagePublicHostname accepts a canonical exact DNS hostname only.
// It is intentionally stricter than a general DNS name parser.
func ValidateImagePublicHostname(host string) error {
	if len(host) < 4 || len(host) > 253 || strings.ToLower(host) != host || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || host == "localhost" {
		return fmt.Errorf("invalid public hostname")
	}
	for _, suffix := range []string{".localhost", ".local", ".internal"} {
		if strings.HasSuffix(host, suffix) {
			return fmt.Errorf("reserved public hostname")
		}
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("public hostname needs at least two labels")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid public hostname label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("invalid public hostname character")
			}
		}
	}
	return nil
}
