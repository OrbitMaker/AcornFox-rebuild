package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// ImagePlanStatus declares the state of an immutable image delivery plan.
type ImagePlanStatus string

const (
	ImagePlanStatusPlanned    ImagePlanStatus = "planned"
	ImagePlanStatusNeedsInput ImagePlanStatus = "needs_input"
)

// Supported canonical registries for the first slice.
const (
	RegistryDockerHub = "registry-1.docker.io"
	RegistryGHCR      = "ghcr.io"
)

// RuntimeEnvironmentVariable holds a non-secret string literal.
type RuntimeEnvironmentVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Kind  string `json:"kind,omitempty"`
}

// RuntimeVolume declares a validated named volume contract.
type RuntimeVolume struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	SizeBytes int64  `json:"size_bytes"`
	ReadOnly  bool   `json:"read_only,omitempty"`
}

// RuntimeRequestedResources declares resource limits and reservation.
type RuntimeRequestedResources struct {
	CPUMillis            int64 `json:"cpu_millis"`
	MemoryBytes          int64 `json:"memory_bytes"`
	DiskReservationBytes int64 `json:"disk_reservation_bytes,omitempty"`
	PIDs                 int64 `json:"pids,omitempty"`
}

// ImagePlanInput captures user-supplied input before resolution.
type ImagePlanInput struct {
	AppName     string                     `json:"app_name"`
	Image       string                     `json:"image"`
	Port        int                        `json:"port,omitempty"`
	Environment map[string]string          `json:"environment,omitempty"`
	Resources   *RuntimeRequestedResources `json:"resources,omitempty"`
	Volumes     []RuntimeVolume            `json:"volumes,omitempty"`

	// Unsupported forbidden inputs to reject explicitly
	Secrets    any `json:"secrets,omitempty"`
	HostMounts any `json:"host_mounts,omitempty"`
	Privileged any `json:"privileged,omitempty"`
	Command    any `json:"command,omitempty"`
	Entrypoint any `json:"entrypoint,omitempty"`
}

// CanonicalExecutionInput captures normalized behavior-affecting parameters.
type CanonicalExecutionInput struct {
	AppName     string                       `json:"app_name"`
	Repository  string                       `json:"repository"`
	ResolvedRef string                       `json:"resolved_ref"`
	Port        int                          `json:"port,omitempty"`
	Environment []RuntimeEnvironmentVariable `json:"environment,omitempty"`
	Resources   RuntimeRequestedResources    `json:"resources"`
	Volumes     []RuntimeVolume              `json:"volumes,omitempty"`
}

// ResolvedImage holds verified immutable digest provenance.
type ResolvedImage struct {
	Repository   string `json:"repository"`
	Digest       string `json:"digest"`
	ResolvedTag  string `json:"resolved_tag,omitempty"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// ResolverProvenance records the metadata resolution outcome.
type ResolverProvenance struct {
	Provider    string    `json:"provider"`
	EvidenceRef string    `json:"evidence_ref"`
	Digest      string    `json:"digest"`
	ResolvedAt  time.Time `json:"resolved_at"`
}

// ImagePlan represents a bounded, immutable, verified deployment plan.
type ImagePlan struct {
	ID                 domain.ID               `json:"id"`
	AdminID            domain.ID               `json:"admin_id"`
	AppName            string                  `json:"app_name"`
	Status             ImagePlanStatus         `json:"status"`
	PlanDigest         string                  `json:"plan_digest"`
	CanonicalInput     CanonicalExecutionInput `json:"canonical_input"`
	ResolvedImage      ResolvedImage           `json:"resolved_image"`
	ResolverProvenance ResolverProvenance      `json:"resolver_provenance"`
	MissingInputs      []string                `json:"missing_inputs,omitempty"`
	CreatedAt          time.Time               `json:"created_at"`
	UpdatedAt          time.Time               `json:"updated_at"`
}

// ComputePlanDigest deterministically calculates the canonical digest covering all behavior-affecting execution fields.
func ComputePlanDigest(input CanonicalExecutionInput, resolvedImageDigest string) (string, error) {
	type executionIdentity struct {
		AppName             string                       `json:"app_name"`
		Repository          string                       `json:"repository"`
		ResolvedRef         string                       `json:"resolved_ref"`
		ResolvedImageDigest string                       `json:"resolved_image_digest"`
		Platform            string                       `json:"platform"`
		Port                int                          `json:"port"`
		Environment         []RuntimeEnvironmentVariable `json:"environment,omitempty"`
		Resources           RuntimeRequestedResources    `json:"resources"`
		Volumes             []RuntimeVolume              `json:"volumes,omitempty"`
	}

	identity := executionIdentity{
		AppName:             input.AppName,
		Repository:          input.Repository,
		ResolvedRef:         input.ResolvedRef,
		ResolvedImageDigest: resolvedImageDigest,
		Platform:            "linux/amd64",
		Port:                input.Port,
		Environment:         input.Environment,
		Resources:           input.Resources,
		Volumes:             input.Volumes,
	}

	raw, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// ValidatePlanConsistency verifies all structural invariants and checks the digest against execution contents.
func ValidatePlanConsistency(plan ImagePlan) error {
	if plan.ID.Empty() || plan.AdminID.Empty() {
		return domain.ValidationError("plan identity or admin id is empty")
	}
	if plan.AppName == "" || plan.CanonicalInput.AppName != plan.AppName {
		return domain.ValidationError("plan app_name does not match canonical input")
	}
	if plan.CanonicalInput.Repository == "" || plan.CanonicalInput.Repository != plan.ResolvedImage.Repository {
		return domain.ValidationError("plan repository does not match resolved image repository")
	}
	if plan.ResolvedImage.OS != "linux" || plan.ResolvedImage.Architecture != "amd64" {
		return domain.ValidationError("resolved image must be linux/amd64 platform")
	}
	if plan.ResolvedImage.Digest == "" || len(plan.ResolvedImage.Digest) != 71 || !strings.HasPrefix(plan.ResolvedImage.Digest, "sha256:") {
		return domain.ValidationError("resolved image digest is invalid")
	}
	hexPart := strings.TrimPrefix(plan.ResolvedImage.Digest, "sha256:")
	if len(hexPart) != 64 || hexPart != strings.ToLower(hexPart) {
		return domain.ValidationError("resolved image digest must be sha256 with 64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return domain.ValidationError("resolved image digest contains non-hex characters")
	}

	expectedDigest, err := ComputePlanDigest(plan.CanonicalInput, plan.ResolvedImage.Digest)
	if err != nil {
		return domain.WrapError(domain.ErrUnavailable, "recompute plan digest", err)
	}
	if plan.PlanDigest != expectedDigest {
		return domain.ValidationError("plan digest does not match execution content")
	}

	switch plan.Status {
	case ImagePlanStatusPlanned:
		if len(plan.MissingInputs) != 0 {
			return domain.ValidationError("planned image plan must have empty missing_inputs")
		}
		if plan.CanonicalInput.Port <= 0 || plan.CanonicalInput.Port > 65535 {
			return domain.ValidationError("planned image plan requires a valid container port")
		}
	case ImagePlanStatusNeedsInput:
		if len(plan.MissingInputs) != 1 || plan.MissingInputs[0] != "container_port" {
			return domain.ValidationError("needs_input plan must have missing_inputs [container_port]")
		}
		if plan.CanonicalInput.Port > 0 && plan.CanonicalInput.Port <= 65535 {
			return domain.ValidationError("needs_input plan must not have a valid container port")
		}
	default:
		return domain.ValidationError("unsupported image plan status")
	}

	if plan.ResolverProvenance.Provider != "registryhttp" && plan.ResolverProvenance.Provider != "source-build" {
		return domain.ValidationError("resolver provenance provider must be registryhttp")
	}
	if plan.ResolverProvenance.Provider == "source-build" && domain.RequireID(domain.ID(plan.ResolverProvenance.EvidenceRef), "source-built artifact") != nil {
		return domain.ValidationError("source-built plan requires original artifact identity")
	}
	if plan.ResolverProvenance.Digest != plan.ResolvedImage.Digest {
		return domain.ValidationError("resolver provenance digest must match resolved image digest")
	}
	if plan.ResolverProvenance.ResolvedAt.IsZero() {
		return domain.ValidationError("resolver provenance resolved_at is required")
	}

	return nil
}

// ResolvedMetadataResult is the typed output from image resolution.
type ResolvedMetadataResult struct {
	Repository  string
	Digest      string
	ResolvedTag string
	EvidenceRef string
}

// ImageMetadataResolver defines the narrow external registry metadata resolution seam.
type ImageMetadataResolver interface {
	ResolveMetadata(ctx context.Context, repository, reference string) (ResolvedMetadataResult, error)
}

// ConfirmImagePlanInput is submitted to atomic confirmation.
type ConfirmImagePlanInput struct {
	PlanID         domain.ID `json:"plan_id"`
	PlanDigest     string    `json:"plan_digest"`
	IdempotencyKey string    `json:"idempotency_key"`
}

// ConfirmImagePlanResult is the durable result of confirmation.
type ConfirmImagePlanResult struct {
	ApplicationID domain.ID `json:"application_id"`
	EnvironmentID domain.ID `json:"environment_id"`
	OperationID   domain.ID `json:"operation_id"`
	TaskID        domain.ID `json:"task_id"`
	PlanID        domain.ID `json:"plan_id"`
	PlanDigest    string    `json:"plan_digest"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

// ImageOperationDetail provides authenticated visibility into pending accepted intent.
type ImageOperationDetail struct {
	Reason         string    `json:"reason,omitempty"`
	ActionRequired bool      `json:"action_required,omitempty"`
	OperationID    domain.ID `json:"operation_id"`
	ApplicationID  domain.ID `json:"application_id"`
	EnvironmentID  domain.ID `json:"environment_id"`
	OperationType  string    `json:"operation_type"`
	State          string    `json:"state"`
	PlanID         domain.ID `json:"plan_id"`
	PlanDigest     string    `json:"plan_digest"`
	TaskID         domain.ID `json:"task_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Managed-image discovery is a bounded public projection, not the full plan,
// a new execution intent or a continuous health/readiness claim.
type ManagedImageCommandSummary struct {
	OperationID domain.ID            `json:"operation_id"`
	Action      ImageLifecycleAction `json:"action"`
	State       string               `json:"state"`
}
type ManagedImageApplicationSummary struct {
	ApplicationID     domain.ID                   `json:"application_id"`
	Name              string                      `json:"name"`
	EnvironmentID     domain.ID                   `json:"environment_id"`
	PlanID            domain.ID                   `json:"plan_id"`
	PlanDigest        string                      `json:"plan_digest"`
	DeployOperationID domain.ID                   `json:"deploy_operation_id"`
	DeployState       string                      `json:"deploy_state"`
	DeploymentID      domain.ID                   `json:"deployment_id,omitempty"`
	DeploymentState   string                      `json:"deployment_state,omitempty"`
	UpdatedAt         time.Time                   `json:"updated_at"`
	ActiveCommand     *ManagedImageCommandSummary `json:"active_command,omitempty"`
	LastCommand       *ManagedImageCommandSummary `json:"last_command,omitempty"`
}
type ManagedImageApplicationList struct {
	Items     []ManagedImageApplicationSummary `json:"items"`
	Truncated bool                             `json:"truncated"`
}

// SourceRunPlanInput previews an owned built artifact for the same application.
// Repository, image digest, provenance and source/private OCI refs are never
// caller-supplied. Confirmation is a separate explicit request.
type SourceRunPlanInput struct {
	BuildIntentID  domain.ID                  `json:"build_intent_id"`
	ArtifactID     domain.ID                  `json:"artifact_id"`
	Port           int                        `json:"port,omitempty"`
	Environment    map[string]string          `json:"environment,omitempty"`
	Resources      *RuntimeRequestedResources `json:"resources,omitempty"`
	Volumes        []RuntimeVolume            `json:"volumes,omitempty"`
	IdempotencyKey string                     `json:"idempotency_key"`
}

// SourceRunOCIIdentity is the bounded actual archive/manifest/config relation
// observed by the authenticated Source role and checked before persisting a
// source-origin runtime preview.
type SourceRunOCIIdentity struct {
	ArchiveSize    int64
	ManifestDigest string
	ConfigDigest   string
	OS             string
	Architecture   string
}
type SourceBuiltRunStore interface {
	SourceBuildSchemaReady(context.Context) error
	ReadSourceBuiltArtifact(context.Context, domain.ID, domain.ID, domain.ID) (SourceBuiltArtifactFact, error)
	ReadSourceRunPlanReplay(context.Context, domain.ID, SourceRunPlanInput, CanonicalExecutionInput) (ImagePlan, bool, error)
	CreateSourceRunPlan(context.Context, domain.ID, SourceRunPlanInput, CanonicalExecutionInput, SourceRunOCIIdentity) (ImagePlan, error)
	ConfirmSourceRunPlan(context.Context, domain.ID, ConfirmImagePlanInput) (ConfirmImagePlanResult, error)
	ReadSourceRunPlan(context.Context, domain.ID, domain.ID) (ImagePlan, error)
}
