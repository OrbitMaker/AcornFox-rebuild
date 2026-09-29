package contracts

import (
	"context"
	"github.com/acornfox/acornfox/internal/domain"
	"time"
)

// Lifecycle commands preserve the deployment's original deploy operation and container.
type ImageLifecycleAction string

const (
	ImageLifecycleStop     ImageLifecycleAction = "stop"
	ImageLifecycleStart    ImageLifecycleAction = "start"
	ImageLifecycleRestart  ImageLifecycleAction = "restart"
	ImageLifecycleTaskKind                      = "image.lifecycle"
)

type CreateImageLifecycleInput struct {
	DeploymentID   domain.ID
	Action         ImageLifecycleAction
	IdempotencyKey string
}
type ImageLifecycleBinding struct {
	// Reason is a read-only diagnostic, excluded from immutable authority/task JSON.
	Reason            string               `json:"-"`
	OperationID       domain.ID            `json:"operation_id"`
	TaskID            domain.ID            `json:"task_id"`
	DeploymentID      domain.ID            `json:"deployment_id"`
	ReleaseID         domain.ID            `json:"release_id"`
	ApplicationID     domain.ID            `json:"application_id"`
	EnvironmentID     domain.ID            `json:"environment_id"`
	DeployOperationID domain.ID            `json:"deploy_operation_id"`
	PlanID            domain.ID            `json:"plan_id"`
	Plan              ImagePlan            `json:"plan"`
	PlanDigest        string               `json:"plan_digest"`
	ManifestDigest    string               `json:"manifest_digest"`
	ContainerID       string               `json:"container_id"`
	ImageID           string               `json:"image_id"`
	HostPort          int                  `json:"host_port"`
	ContainerPort     int                  `json:"container_port"`
	Action            ImageLifecycleAction `json:"action"`
	State             string               `json:"state"`
	RecoveryRequired  bool                 `json:"recovery_required"`
	CreatedAt         time.Time            `json:"created_at"`
	// Result is exclusively this command's observed outcome; nil before success.
	Result *ImageLifecycleResult `json:"result,omitempty"`
}
type ImageLifecycleAuthorityInput struct {
	BeginImageExecutionInput
	DeploymentID domain.ID
	ReleaseID    domain.ID
	PlanDigest   string
	ContainerID  string
	Action       ImageLifecycleAction
}

// VerifiedIdentity requires the runtime to inspect labels/config/network/volumes against
// the original plan. It is never inferred from the requested action or old deploy result.
type ImageLifecycleResult struct {
	Running          bool      `json:"running"`
	VerifiedIdentity bool      `json:"verified_identity"`
	ContainerID      string    `json:"container_id"`
	ImageID          string    `json:"image_id"`
	ManifestDigest   string    `json:"manifest_digest"`
	HostPort         int       `json:"host_port"`
	ContainerPort    int       `json:"container_port"`
	EndpointReady    bool      `json:"endpoint_ready"`
	ObservedAt       time.Time `json:"observed_at"`
}
type CommitImageLifecycleInput struct {
	ImageLifecycleAuthorityInput
	Result ImageLifecycleResult
}
type ImageLifecycleOutcomeInput struct {
	ImageLifecycleAuthorityInput
	Reason string
}
type ImageLifecycleStore interface {
	CreateImageLifecycle(context.Context, domain.ID, CreateImageLifecycleInput) (ImageLifecycleBinding, error)
	BeginImageLifecycle(context.Context, BeginImageExecutionInput) (ImageLifecycleBinding, error)
	AuthorizeImageLifecycle(context.Context, ImageLifecycleAuthorityInput) (ImageLifecycleBinding, error)
	CommitImageLifecycleResult(context.Context, CommitImageLifecycleInput) error
	RecordImageLifecycleUnknown(context.Context, ImageLifecycleOutcomeInput) error
	FailImageLifecycle(context.Context, ImageLifecycleOutcomeInput) error
	ReadImageLifecycle(context.Context, domain.ID, domain.ID) (ImageLifecycleBinding, error)
}

// ContainerLifecycleClient uses fresh command authority, separately from deploy clients.
type ContainerLifecycleClient interface {
	ExecuteLifecycle(context.Context, ImageLifecycleBinding, ImageLifecycleAuthorityInput) (ImageLifecycleResult, error)
}

// ImageLifecycleCommandInput is the public fixed-action body; deployment comes
// exclusively from the URL, never an alternate body target or runtime plan.
type ImageLifecycleCommandInput struct {
	Action         ImageLifecycleAction `json:"action"`
	IdempotencyKey string               `json:"idempotency_key"`
}

// ImageLifecycleOperation exposes command provenance and its own observation.
// The original runtime plan, environment values and lease authority stay private.
// Result describes this command's observed outcome, not continuous app health.
type ImageLifecycleOperation struct {
	Reason            string                `json:"reason,omitempty"`
	OperationID       domain.ID             `json:"operation_id"`
	TaskID            domain.ID             `json:"task_id"`
	DeploymentID      domain.ID             `json:"deployment_id"`
	ReleaseID         domain.ID             `json:"release_id"`
	ApplicationID     domain.ID             `json:"application_id"`
	EnvironmentID     domain.ID             `json:"environment_id"`
	DeployOperationID domain.ID             `json:"deploy_operation_id"`
	PlanID            domain.ID             `json:"plan_id"`
	PlanDigest        string                `json:"plan_digest"`
	ManifestDigest    string                `json:"manifest_digest"`
	ContainerID       string                `json:"container_id"`
	ImageID           string                `json:"image_id"`
	HostPort          int                   `json:"host_port"`
	ContainerPort     int                   `json:"container_port"`
	Action            ImageLifecycleAction  `json:"action"`
	State             string                `json:"state"`
	CreatedAt         time.Time             `json:"created_at"`
	RecoveryRequired  bool                  `json:"recovery_required"`
	Result            *ImageLifecycleResult `json:"result,omitempty"`
}
