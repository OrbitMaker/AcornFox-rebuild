package contracts

import (
	"context"
	"io"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
)

// ImageExecutionState represents the durable state of a deployment execution.
type ImageExecutionState string

const (
	ImageExecutionStateDeploying ImageExecutionState = "deploying"
	ImageExecutionStateRunning   ImageExecutionState = "running"
	ImageExecutionStateFailed    ImageExecutionState = "failed"
	ImageExecutionStateStopped   ImageExecutionState = "stopped"
)

// ImageRelease represents an immutable release record bound to an approved plan and verified digest.
type ImageRelease struct {
	ID            domain.ID `json:"id"`
	ApplicationID domain.ID `json:"application_id"`
	PlanID        domain.ID `json:"plan_id"`
	PlanDigest    string    `json:"plan_digest"`
	Repository    string    `json:"repository"`
	Digest        string    `json:"digest"`
	Platform      string    `json:"platform"`
	CreatedAt     time.Time `json:"created_at"`
}

// ImageDeployment represents a stable execution deployment identity and status.
type ImageDeployment struct {
	ID            domain.ID           `json:"id"`
	ReleaseID     domain.ID           `json:"release_id"`
	ApplicationID domain.ID           `json:"application_id"`
	EnvironmentID domain.ID           `json:"environment_id"`
	OperationID   domain.ID           `json:"operation_id"`
	TaskID        domain.ID           `json:"task_id"`
	Status        ImageExecutionState `json:"status"`
	ContainerID   string              `json:"container_id,omitempty"`
	ContainerName string              `json:"container_name,omitempty"`
	ImageID       string              `json:"image_id,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
}

// ImageArtifact represents the verified OCI artifact receipt bound to the release.
type ImageArtifact struct {
	ID            domain.ID `json:"id"`
	ReleaseID     domain.ID `json:"release_id"`
	Repository    string    `json:"repository"`
	Digest        string    `json:"digest"`
	ImageID       string    `json:"image_id"`
	ContentDigest string    `json:"content_digest"`
	SizeBytes     int64     `json:"size_bytes"`
	StorageRef    string    `json:"storage_ref"`
	CreatedAt     time.Time `json:"created_at"`
}

// ImageEndpoint represents the observed loopback endpoint for a running container.
type ImageEndpoint struct {
	ID            domain.ID `json:"id"`
	DeploymentID  domain.ID `json:"deployment_id"`
	ApplicationID domain.ID `json:"application_id"`
	EnvironmentID domain.ID `json:"environment_id"`
	Protocol      string    `json:"protocol"`
	HostIP        string    `json:"host_ip"`
	HostPort      int       `json:"host_port"`
	ContainerPort int       `json:"container_port"`
	ObservedAt    time.Time `json:"observed_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// BeginImageExecutionInput initiates the execution preparation transaction.
type BeginImageExecutionInput struct {
	TaskID          domain.ID
	OperationID     domain.ID
	Owner           string
	CoreGeneration  int64
	LeaseGeneration int64
	Now             time.Time
}

// ImageExecutionBinding holds the verified stored plan and stable execution identities.
type ImageExecutionBinding struct {
	ReleaseID       domain.ID
	DeploymentID    domain.ID
	ApplicationID   domain.ID
	EnvironmentID   domain.ID
	OperationID     domain.ID
	TaskID          domain.ID
	Plan            ImagePlan
	SourceArtifact  *SourceBuiltArtifactFact
	Owner           string
	CoreGeneration  int64
	LeaseGeneration int64
}

// AuthorizeImageExecutionInput supplies the tuple needed to verify live authority.
type AuthorizeImageExecutionInput struct {
	TaskID          domain.ID `json:"task_id"`
	OperationID     domain.ID `json:"operation_id"`
	DeploymentID    domain.ID `json:"deployment_id"`
	PlanDigest      string    `json:"plan_digest"`
	Owner           string    `json:"owner"`
	CoreGeneration  int64     `json:"core_generation"`
	LeaseGeneration int64     `json:"lease_generation"`
	Now             time.Time `json:"now"`
}

// StorageArtifactReceipt carries verified OCI storage facts from the image store.
type StorageArtifactReceipt struct {
	StorageRef    string `json:"storage_ref"`
	ContentDigest string `json:"content_digest"`
	SizeBytes     int64  `json:"size_bytes"`
}

// CommitImageExecutionResultInput supplies observed container effects to commit atomically.
type CommitImageExecutionResultInput struct {
	TaskID          domain.ID
	OperationID     domain.ID
	DeploymentID    domain.ID
	ReleaseID       domain.ID
	Owner           string
	CoreGeneration  int64
	LeaseGeneration int64
	Now             time.Time

	// Observed effects
	ContainerID    string
	ContainerName  string
	ImageID        string
	ManifestDigest string
	Artifact       StorageArtifactReceipt
	HostPort       int
	ContainerPort  int
	ObservedAt     time.Time
}

// FailImageExecutionInput records a failure outcome under lease fencing.
type FailImageExecutionInput struct {
	TaskID          domain.ID
	OperationID     domain.ID
	DeploymentID    domain.ID
	Owner           string
	CoreGeneration  int64
	LeaseGeneration int64
	Reason          string
	Now             time.Time
}

// RecordImageExecutionUnknownInput records an unknown outcome without consuming attempt limits.
type RecordImageExecutionUnknownInput struct {
	TaskID          domain.ID
	OperationID     domain.ID
	DeploymentID    domain.ID
	Owner           string
	CoreGeneration  int64
	LeaseGeneration int64
	Reason          string
	Now             time.Time
}

// ContainerExecutionClient executes deployments via the trusted container role process.
type ContainerExecutionClient interface {
	ExecuteDeployment(ctx context.Context, binding ImageExecutionBinding) (CommitImageExecutionResultInput, error)
	ObserveDeployment(ctx context.Context, deploymentID domain.ID, operationID domain.ID) (ImageExecutionResult, error)
}

// ImageExecutionResult holds observed container facts and storage receipt for recovery.
type ImageExecutionResult struct {
	Status         string                 `json:"status"`
	Running        bool                   `json:"running"`
	ContainerID    string                 `json:"container_id,omitempty"`
	ContainerName  string                 `json:"container_name,omitempty"`
	ImageID        string                 `json:"image_id,omitempty"`
	ManifestDigest string                 `json:"manifest_digest,omitempty"`
	Artifact       StorageArtifactReceipt `json:"artifact,omitempty"`
	HostPort       int                    `json:"host_port,omitempty"`
	ContainerPort  int                    `json:"container_port,omitempty"`
	ObservedAt     time.Time              `json:"observed_at,omitempty"`
}

// AuthorityBindingFacts holds verified stored facts returned from authority validation.
type AuthorityBindingFacts struct {
	PlanDigest     string                   `json:"plan_digest"`
	ApplicationID  domain.ID                `json:"application_id"`
	EnvironmentID  domain.ID                `json:"environment_id"`
	ReleaseID      domain.ID                `json:"release_id"`
	ApprovedPort   int                      `json:"approved_port"`
	ImageOrigin    string                   `json:"image_origin,omitempty"`
	SourceArtifact *SourceBuiltArtifactFact `json:"source_artifact,omitempty"`
}

// ImageObservationBinding holds read-only authority facts linking an operation and deployment for observe recovery.
type ImageObservationBinding struct {
	ApplicationID  domain.ID                `json:"application_id"`
	EnvironmentID  domain.ID                `json:"environment_id"`
	ReleaseID      domain.ID                `json:"release_id"`
	Repository     string                   `json:"repository"`
	Digest         string                   `json:"digest"`
	ApprovedPort   int                      `json:"approved_port"`
	PlanDigest     string                   `json:"plan_digest"`
	OperationState string                   `json:"operation_state"`
	ImageOrigin    string                   `json:"image_origin,omitempty"`
	SourceArtifact *SourceBuiltArtifactFact `json:"source_artifact,omitempty"`
	CanonicalInput *CanonicalExecutionInput `json:"canonical_input,omitempty"`
}

// ImageExecutionStore defines SQLite persistence entry points for execution.
type ImageExecutionStore interface {
	BeginImageExecution(ctx context.Context, input BeginImageExecutionInput) (ImageExecutionBinding, error)
	AuthorizeImageExecution(ctx context.Context, input AuthorizeImageExecutionInput) (AuthorityBindingFacts, error)
	CommitImageExecutionResult(ctx context.Context, input CommitImageExecutionResultInput) error
	FailImageExecution(ctx context.Context, input FailImageExecutionInput) error
	RecordImageExecutionUnknown(ctx context.Context, input RecordImageExecutionUnknownInput) error
	ReadImageObservationBinding(ctx context.Context, operationID, deploymentID domain.ID) (ImageObservationBinding, error)
}

// ImageOperationExecutionResult holds the durable result facts of an executed deployment.
type ImageOperationExecutionResult struct {
	DeploymentID  domain.ID `json:"deployment_id"`
	ReleaseID     domain.ID `json:"release_id"`
	Status        string    `json:"status"`
	ContainerID   string    `json:"container_id,omitempty"`
	ImageID       string    `json:"image_id,omitempty"`
	HostIP        string    `json:"host_ip,omitempty"`
	HostPort      int       `json:"host_port,omitempty"`
	ContainerPort int       `json:"container_port,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
}

// ImageOperationDetailWithResult embeds ImageOperationDetail with durable execution results if present.
type ImageOperationDetailWithResult struct {
	ImageOperationDetail
	Result *ImageOperationExecutionResult `json:"result,omitempty"`
}

// SourceBuiltContainerReceipt is a verified read-back of the Container role's
// private OCI store, before any Docker mutation. It retains the source archive
// SHA separately from the OCI manifest/config and observed engine image ID.
type SourceBuiltContainerReceipt struct {
	Image          domain.ImageDigest `json:"image"`
	StorageRef     string             `json:"storage_ref"`
	ArchiveSHA256  string             `json:"archive_sha256"`
	SizeBytes      int64              `json:"size_bytes"`
	ManifestDigest string             `json:"manifest_digest"`
	ConfigDigest   string             `json:"config_digest"`
}

// SourceBuiltContainerClient is an optional capability of the existing
// attested Container client. Legacy registry deployments do not call it.
type SourceBuiltContainerClient interface {
	ProbeBuiltOCI(context.Context, ImageExecutionBinding) (SourceBuiltContainerReceipt, bool, error)
	ImportBuiltOCI(context.Context, ImageExecutionBinding, io.Reader) (SourceBuiltContainerReceipt, error)
}
