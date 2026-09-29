package imageexecution

import (
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// DeployRequest carries the approved deployment execution parameters over Unix RPC.
type DeployRequest struct {
	DeploymentID    domain.ID                            `json:"deployment_id"`
	ReleaseID       domain.ID                            `json:"release_id"`
	ApplicationID   domain.ID                            `json:"application_id"`
	EnvironmentID   domain.ID                            `json:"environment_id"`
	OperationID     domain.ID                            `json:"operation_id"`
	TaskID          domain.ID                            `json:"task_id"`
	TaskOwner       string                               `json:"task_owner"`
	CoreGeneration  int64                                `json:"core_generation"`
	LeaseGeneration int64                                `json:"lease_generation"`
	PlanDigest      string                               `json:"plan_digest"`
	ImageOrigin     string                               `json:"image_origin,omitempty"`
	CanonicalInput  appcontracts.CanonicalExecutionInput `json:"canonical_input"`
	ResolvedImage   appcontracts.ResolvedImage           `json:"resolved_image"`
	TimeoutSeconds  int64                                `json:"timeout_seconds,omitempty"`
}

// DeployResponse returns the observed container facts and artifact receipt.
type DeployResponse struct {
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
	OutcomeUnknown bool      `json:"outcome_unknown,omitempty"`
	ContainerID    string    `json:"container_id,omitempty"`
	ContainerName  string    `json:"container_name,omitempty"`
	ImageID        string    `json:"image_id,omitempty"`
	ManifestDigest string    `json:"manifest_digest,omitempty"`
	StorageRef     string    `json:"storage_ref,omitempty"`
	ContentDigest  string    `json:"content_digest,omitempty"`
	SizeBytes      int64     `json:"size_bytes,omitempty"`
	HostPort       int       `json:"host_port,omitempty"`
	ContainerPort  int       `json:"container_port,omitempty"`
	HostIP         string    `json:"host_ip,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
}

// ObserveRequest queries the live runtime state of a deployed container.
type ObserveRequest struct {
	DeploymentID domain.ID `json:"deployment_id"`
	OperationID  domain.ID `json:"operation_id"`
}

// ObserveResponse returns the inspected runtime facts.
type ObserveResponse struct {
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
	Status         string    `json:"status,omitempty"`
	Running        bool      `json:"running"`
	ContainerID    string    `json:"container_id,omitempty"`
	ContainerName  string    `json:"container_name,omitempty"`
	ImageID        string    `json:"image_id,omitempty"`
	ManifestDigest string    `json:"manifest_digest,omitempty"`
	StorageRef     string    `json:"storage_ref,omitempty"`
	ContentDigest  string    `json:"content_digest,omitempty"`
	SizeBytes      int64     `json:"size_bytes,omitempty"`
	HostPort       int       `json:"host_port,omitempty"`
	ContainerPort  int       `json:"container_port,omitempty"`
	HostIP         string    `json:"host_ip,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
}

// AuthorityCheckRequest is sent by Container role to Core to verify lease fencing before an effect.
type AuthorityCheckRequest struct {
	TaskID          domain.ID `json:"task_id"`
	OperationID     domain.ID `json:"operation_id"`
	DeploymentID    domain.ID `json:"deployment_id"`
	PlanDigest      string    `json:"plan_digest"`
	Owner           string    `json:"owner"`
	CoreGeneration  int64     `json:"core_generation"`
	LeaseGeneration int64     `json:"lease_generation"`
}

// AuthorityCheckResponse returns Core's lease authority verdict and the verified plan binding facts.
type AuthorityCheckResponse struct {
	Authorized     bool                                  `json:"authorized"`
	PlanDigest     string                                `json:"plan_digest,omitempty"`
	ApplicationID  domain.ID                             `json:"application_id,omitempty"`
	EnvironmentID  domain.ID                             `json:"environment_id,omitempty"`
	ReleaseID      domain.ID                             `json:"release_id,omitempty"`
	ApprovedPort   int                                   `json:"approved_port,omitempty"`
	ImageOrigin    string                                `json:"image_origin,omitempty"`
	SourceArtifact *appcontracts.SourceBuiltArtifactFact `json:"source_artifact,omitempty"`
	Error          string                                `json:"error,omitempty"`
}

// ObserveBindingRequest queries Core's read-only authority facts linking an operation and deployment.
type ObserveBindingRequest struct {
	OperationID  domain.ID `json:"operation_id"`
	DeploymentID domain.ID `json:"deployment_id"`
}

// ObserveBindingResponse returns the verified plan and release binding facts.
type ObserveBindingResponse struct {
	Valid          bool                                  `json:"valid"`
	ApplicationID  domain.ID                             `json:"application_id,omitempty"`
	EnvironmentID  domain.ID                             `json:"environment_id,omitempty"`
	ReleaseID      domain.ID                             `json:"release_id,omitempty"`
	Repository     string                                `json:"repository,omitempty"`
	Digest         string                                `json:"digest,omitempty"`
	ApprovedPort   int                                   `json:"approved_port,omitempty"`
	PlanDigest     string                                `json:"plan_digest,omitempty"`
	OperationState string                                `json:"operation_state,omitempty"`
	ImageOrigin    string                                `json:"image_origin,omitempty"`
	SourceArtifact *appcontracts.SourceBuiltArtifactFact `json:"source_artifact,omitempty"`
	CanonicalInput *appcontracts.CanonicalExecutionInput `json:"canonical_input,omitempty"`
	Error          string                                `json:"error,omitempty"`
}

// BuiltOCIImportRequest is private between the attested Core and Container
// roles. Core constructs Artifact only from the original owned SQLite result.
type BuiltOCIImportRequest struct {
	DeploymentID    domain.ID                            `json:"deployment_id"`
	OperationID     domain.ID                            `json:"operation_id"`
	TaskID          domain.ID                            `json:"task_id"`
	Owner           string                               `json:"owner"`
	CoreGeneration  int64                                `json:"core_generation"`
	LeaseGeneration int64                                `json:"lease_generation"`
	PlanDigest      string                               `json:"plan_digest"`
	Artifact        appcontracts.SourceBuiltArtifactFact `json:"artifact"`
}
type BuiltOCIImportResponse struct {
	Present        bool               `json:"present"`
	Image          domain.ImageDigest `json:"image,omitempty"`
	StorageRef     string             `json:"storage_ref,omitempty"`
	ContentDigest  string             `json:"content_digest,omitempty"`
	SizeBytes      int64              `json:"size_bytes,omitempty"`
	ManifestDigest string             `json:"manifest_digest,omitempty"`
	ConfigDigest   string             `json:"config_digest,omitempty"`
}
