package contracts

import (
	"context"
	"regexp"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
)

type SourceBuildStage string

const (
	SourceBuildPrepare SourceBuildStage = "prepare"
	SourceBuildBuild   SourceBuildStage = "build"
	SourceBuildCancel  SourceBuildStage = "cancel"
	SourceBuildRelease SourceBuildStage = "release"
)

type SourceBuildBinding struct {
	TaskID          domain.ID `json:"task_id"`
	OperationID     domain.ID `json:"operation_id"`
	ApplicationID   domain.ID `json:"application_id"`
	Owner           string    `json:"owner"`
	CoreGeneration  uint64    `json:"core_generation"`
	LeaseGeneration uint64    `json:"lease_generation"`
}

type SourceBuildPermit struct {
	CommandSHA256 string `json:"command_sha256"`
}

// Native source/build facts contain only domain objects and primitive values.
// No provider type is imported here: the Core adapter performs that mapping.
type SourceBuildEvidenceFact struct {
	Digest   string               `json:"digest"`
	Summary  string               `json:"summary,omitempty"`
	Refs     []domain.EvidenceRef `json:"refs"`
	Redacted bool                 `json:"redacted"`
}

type SourceBuildResourcesFact struct {
	CPUMillis       int64 `json:"cpu_millis"`
	MemoryBytes     int64 `json:"memory_bytes"`
	DiskBytes       int64 `json:"disk_bytes"`
	TimeoutSeconds  int64 `json:"timeout_seconds"`
	ConcurrencySlot int   `json:"concurrency_slot"`
	PIDs            int64 `json:"pids"`
}

type SourceBuildPolicyFact struct {
	Resources          SourceBuildResourcesFact `json:"resources"`
	NetworkMode        string                   `json:"network_mode"`
	WorkerPolicyDigest string                   `json:"worker_policy_digest"`
}

type CreateSourcePrepareIntentInput struct {
	AppName               string `json:"app_name"`
	Repository            string `json:"repository"`
	Commit                string `json:"commit"`
	ExpectedContentDigest string `json:"expected_content_digest,omitempty"`
	TimeoutSeconds        int64  `json:"timeout_seconds"`
	IdempotencyKey        string `json:"idempotency_key"`
}

type ApproveSourceBuildPlanInput struct {
	PrepareIntentID domain.ID             `json:"prepare_intent_id"`
	Plan            domain.BuildPlan      `json:"plan"`
	Policy          SourceBuildPolicyFact `json:"policy"`
	IdempotencyKey  string                `json:"idempotency_key"`
}

type SourceBuildIntentFact struct {
	ID                   domain.ID                      `json:"id"`
	AdminID              domain.ID                      `json:"admin_id"`
	ApplicationID        domain.ID                      `json:"application_id"`
	EnvironmentID        domain.ID                      `json:"environment_id"`
	OperationID          domain.ID                      `json:"operation_id"`
	TaskID               domain.ID                      `json:"task_id"`
	PrepareIntentID      domain.ID                      `json:"prepare_intent_id,omitempty"`
	BuildID              domain.ID                      `json:"build_id,omitempty"`
	Stage                SourceBuildStage               `json:"stage"`
	State                string                         `json:"state"`
	Prepare              CreateSourcePrepareIntentInput `json:"prepare"`
	Source               *domain.SourceRevision         `json:"source,omitempty"`
	Plan                 *domain.BuildPlan              `json:"plan,omitempty"`
	Policy               SourceBuildPolicyFact          `json:"policy"`
	Deadline             time.Time                      `json:"deadline"`
	ProviderOperationKey string                         `json:"provider_operation_key"`
	ProviderActor        string                         `json:"provider_actor"`
	RecoveryRequired     bool                           `json:"recovery_required"`
	CommandSHA256        string                         `json:"command_sha256"`
}

type BeginSourceBuildStageInput struct {
	Binding SourceBuildBinding
	Stage   SourceBuildStage
	Now     time.Time
}

// SourceBuildDefinitionFact is a bounded, private observation from the
// installed Source role's real Dockerfile importer. No ENV/commands are sent.
type SourceBuildDefinitionFact struct {
	Status           string    `json:"status"`
	SourceRevisionID domain.ID `json:"source_revision_id"`
	SourceDigest     string    `json:"source_digest"`
	DefinitionDigest string    `json:"definition_digest"`
	DockerfileDigest string    `json:"dockerfile_digest,omitempty"`
}

type CommitPreparedSourceInput struct {
	Binding       SourceBuildBinding
	Revision      domain.SourceRevision
	Definition    SourceBuildDefinitionFact
	CommandSHA256 string
	Evidence      SourceBuildEvidenceFact
	Now           time.Time
}

type CommitSourceBuildOutputInput struct {
	Binding       SourceBuildBinding
	Build         domain.Build
	CommandSHA256 string
	Artifact      domain.Artifact
	LogRef        string
	Evidence      SourceBuildEvidenceFact
	Now           time.Time
}

type SourceBuildFactsStore interface {
	CreateSourcePrepareIntent(context.Context, domain.ID, CreateSourcePrepareIntentInput) (SourceBuildIntentFact, error)
	ReadPreparedSource(context.Context, domain.ID, domain.ID) (domain.SourceRevision, error)
	ApproveSourceBuildPlan(context.Context, domain.ID, ApproveSourceBuildPlanInput) (SourceBuildIntentFact, error)
	CommitPreparedSource(context.Context, CommitPreparedSourceInput) error
	CommitSourceBuildOutput(context.Context, CommitSourceBuildOutputInput) error
	RecordSourceBuildUnknown(context.Context, SourceBuildBinding, SourceBuildStage, string, time.Time) error
	BeginSourceBuildStage(context.Context, BeginSourceBuildStageInput) (SourceBuildIntentFact, error)
	BindSourceBuildCommand(context.Context, SourceBuildBinding, SourceBuildStage, string, time.Time) error
	ReadSourceBuildAuthority(context.Context, SourceBuildBinding, SourceBuildStage, time.Time) (SourceBuildIntentFact, error)
}

// SourceBuildExecutionClient transports only the canonical, fixed stage command
// composed and sealed by Core. Its bytes are not an arbitrary approval payload.
// The role decoder must strictly decode sourcebuildexecution.SourceBuildCommand.
type SourceBuildExecutionClient interface {
	ExecuteSourceBuild(context.Context, []byte) (SourceBuildExecutionReceipt, error)
}
type SourceBuildExecutionReceipt struct {
	Binding       SourceBuildBinding            `json:"binding"`
	Stage         SourceBuildStage              `json:"stage"`
	CommandSHA256 string                        `json:"command_sha256"`
	Prepared      *CommitPreparedSourceInput    `json:"prepared,omitempty"`
	Built         *CommitSourceBuildOutputInput `json:"built,omitempty"`
}

// Public projections never include the provider workspace, raw authority seal,
// task lease, environment/secret values, OCI storage reference or error cause.
type SourceBuildPublicIntent struct {
	IntentID         domain.ID           `json:"intent_id"`
	Stage            SourceBuildStage    `json:"stage"`
	State            string              `json:"state"`
	ApplicationID    domain.ID           `json:"application_id"`
	OperationID      domain.ID           `json:"operation_id"`
	PrepareIntentID  domain.ID           `json:"prepare_intent_id,omitempty"`
	SourceRevisionID domain.ID           `json:"source_revision_id,omitempty"`
	SourceDigest     string              `json:"source_digest,omitempty"`
	DefinitionStatus string              `json:"definition_status,omitempty"`
	PlanID           domain.ID           `json:"plan_id,omitempty"`
	BuildID          domain.ID           `json:"build_id,omitempty"`
	ArtifactID       domain.ID           `json:"artifact_id,omitempty"`
	Image            *domain.ImageDigest `json:"image,omitempty"`
	Reason           string              `json:"reason,omitempty"`
	ActionRequired   bool                `json:"action_required,omitempty"`
}

// These finite public BuildKit limits match the installed rootless worker's
// fixed CPU/memory/PID contract. Other trusted legacy Plan callers are unchanged.
const SourceBuildPublicCPUMillis int64 = 500
const SourceBuildPublicMemoryBytes int64 = 512 << 20

var sourceBuildPublicName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func ValidPublicSourceBuildServiceName(name string) bool {
	return len(name) > 0 && len(name) <= 64 && sourceBuildPublicName.MatchString(name)
}
func ValidPublicSourceBuildResources(r SourceBuildResourcesFact) bool {
	return r.CPUMillis == SourceBuildPublicCPUMillis && r.MemoryBytes == SourceBuildPublicMemoryBytes && r.PIDs == 0 && r.DiskBytes > 0 && r.ConcurrencySlot == 1 && r.TimeoutSeconds > 0 && r.TimeoutSeconds <= 3600
}

type SourceBuildPublicApprovalInput struct {
	PrepareIntentID  domain.ID                `json:"prepare_intent_id"`
	SourceRevisionID domain.ID                `json:"source_revision_id"`
	SourceDigest     string                   `json:"source_digest"`
	ServiceName      string                   `json:"service_name"`
	ContextPath      string                   `json:"context_path"`
	DockerfilePath   string                   `json:"dockerfile_path"`
	TargetRepository string                   `json:"target_repository"`
	Resources        SourceBuildResourcesFact `json:"resources"`
	IdempotencyKey   string                   `json:"idempotency_key"`
}
type SourceBuildPublicStore interface {
	SourceBuildSchemaReady(context.Context) error
	CreateSourcePrepareIntent(context.Context, domain.ID, CreateSourcePrepareIntentInput) (SourceBuildIntentFact, error)
	ApprovePublicSourceBuildPlan(context.Context, domain.ID, SourceBuildPublicApprovalInput, SourceBuildPolicyFact) (SourceBuildIntentFact, error)
	ReadPublicSourceBuildIntent(context.Context, domain.ID, domain.ID) (SourceBuildPublicIntent, error)
}

// SourceBuiltArtifactFact is private Core authority for an immutable, actually
// persisted Build result. Three digests stay distinct: source tree, OCI manifest,
// and entire OCI archive. Public APIs return only the owned image identity.
type SourceBuiltArtifactFact struct {
	AppName          string             `json:"app_name,omitempty"`
	AdminID          domain.ID          `json:"admin_id"`
	ApplicationID    domain.ID          `json:"application_id"`
	EnvironmentID    domain.ID          `json:"environment_id"`
	BuildIntentID    domain.ID          `json:"build_intent_id"`
	BuildID          domain.ID          `json:"build_id"`
	SourceRevisionID domain.ID          `json:"source_revision_id"`
	BuildPlanID      domain.ID          `json:"build_plan_id"`
	ArtifactID       domain.ID          `json:"artifact_id"`
	Image            domain.ImageDigest `json:"image"`
	StorageRef       string             `json:"storage_ref"`
	ArchiveSHA256    string             `json:"archive_sha256"`
	SizeBytes        int64              `json:"size_bytes"`
}
