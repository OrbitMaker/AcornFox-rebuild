package contracts

import (
	"context"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packprotocol"
)

var ErrNotFound = domain.ErrObjectNotFound

type PackTrustMaterialRecord struct {
	MaterialID        string    `json:"material_id"`
	OperationID       string    `json:"operation_id"`
	PackID            string    `json:"pack_id"`
	Version           string    `json:"version"`
	PlanSHA256        string    `json:"plan_sha256"`
	CatalogSHA256     string    `json:"catalog_sha256"`
	CatalogSequence   int64     `json:"catalog_sequence"`
	ManifestSHA256    string    `json:"manifest_sha256"`
	ArtifactSHA256    string    `json:"artifact_sha256"`
	CatalogEnvelope   []byte    `json:"-"`
	ManifestBytes     []byte    `json:"-"`
	AuthorityKind     string    `json:"authority_kind"`
	AuthoritySequence int64     `json:"authority_sequence"`
	CreatedAt         time.Time `json:"created_at"`
}

type PackLifecycleJournalRecord struct {
	JournalID              string    `json:"journal_id"`
	OperationID            string    `json:"operation_id"`
	PackID                 string    `json:"pack_id"`
	Version                string    `json:"version"`
	PlanSHA256             string    `json:"plan_sha256"`
	Phase                  string    `json:"phase"`
	Revision               int64     `json:"revision"`
	CoreGeneration         int64     `json:"core_generation"`
	LeaseGeneration        int64     `json:"lease_generation"`
	OwnerID                string    `json:"owner_id"`
	StageDirectory         string    `json:"stage_directory"`
	AuthorityCatalogSHA256 string    `json:"authority_catalog_sha256"`
	AuthoritySequence      int64     `json:"authority_sequence"`
	AuthorityExpiresAt     time.Time `json:"authority_expires_at"`
	FailureReason          string    `json:"failure_reason,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type PackArtifactReceipt struct {
	ReceiptID          string    `json:"receipt_id"`
	OperationID        string    `json:"operation_id"`
	PackID             string    `json:"pack_id"`
	Version            string    `json:"version"`
	PlanSHA256         string    `json:"plan_sha256"`
	ArchiveSHA256      string    `json:"archive_sha256"`
	ManifestSHA256     string    `json:"manifest_sha256"`
	ExecutableSHA256   string    `json:"executable_sha256"`
	ExecutablePath     string    `json:"executable_path"`
	CatalogSHA256      string    `json:"catalog_sha256"`
	CatalogSequence    int64     `json:"catalog_sequence"`
	ArchiveSize        int64     `json:"archive_size"`
	UnpackedTotalBytes int64     `json:"unpacked_total_bytes"`
	RelativeStagePath  string    `json:"relative_stage_path"`
	StageIdentity      string    `json:"stage_identity"`
	MemberCount        int       `json:"member_count"`
	VerifiedAt         time.Time `json:"verified_at"`
	CreatedAt          time.Time `json:"created_at"`
}

type StageArtifactIntent struct {
	OperationID            string
	TaskID                 string
	PackID                 string
	Version                string
	PlanSHA256             string
	CoreGeneration         int64
	LeaseGeneration        int64
	OwnerID                string
	StageDirectory         string
	AuthorityCatalogSHA256 string
	AuthoritySequence      int64
	AuthorityExpiresAt     time.Time
	Audit                  AuditContext
}

type CommitArtifactReceiptRecord struct {
	TaskID                  string
	Receipt                 PackArtifactReceipt
	CoreGeneration          int64
	LeaseGeneration         int64
	OwnerID                 string
	ExpectedJournalRevision int64
	Audit                   AuditContext
}

type LifecycleFailureRecord struct {
	OperationID     string
	TaskID          string
	CoreGeneration  int64
	LeaseGeneration int64
	OwnerID         string
	Reason          string
	Audit           AuditContext
}

type AuthorizationRequiredRecord struct {
	OperationID     string
	TaskID          string
	CoreGeneration  int64
	LeaseGeneration int64
	OwnerID         string
	Reason          string
	Audit           AuditContext
}

type PackActivationJournalRecord struct {
	JournalID             string    `json:"journal_id"`
	OperationID           string    `json:"operation_id"`
	PackID                string    `json:"pack_id"`
	Version               string    `json:"version"`
	PlanSHA256            string    `json:"plan_sha256"`
	ArtifactReceiptID     string    `json:"artifact_receipt_id"`
	Phase                 string    `json:"phase"`
	Revision              int64     `json:"revision"`
	CoreGeneration        int64     `json:"core_generation"`
	LeaseGeneration       int64     `json:"lease_generation"`
	OwnerID               string    `json:"owner_id"`
	PublishID             string    `json:"publish_id"`
	InstalledRoot         string    `json:"installed_root"`
	UnitName              string    `json:"unit_name"`
	InstanceID            string    `json:"instance_id,omitempty"`
	MainPID               int32     `json:"main_pid,omitempty"`
	SocketPath            string    `json:"socket_path,omitempty"`
	ProcessStartIdentity  string    `json:"process_start_identity,omitempty"`
	CandidateCapabilities []string  `json:"candidate_capabilities,omitempty"`
	CurrentPointerEffect  string    `json:"current_pointer_effect,omitempty"`
	ActivationGeneration  int64     `json:"activation_generation,omitempty"`
	FailureReason         string    `json:"failure_reason,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type PackActivationReceipt struct {
	ReceiptID             string    `json:"receipt_id"`
	OperationID           string    `json:"operation_id"`
	PackID                string    `json:"pack_id"`
	Version               string    `json:"version"`
	PlanSHA256            string    `json:"plan_sha256"`
	ArtifactReceiptID     string    `json:"artifact_receipt_id"`
	InstalledRoot         string    `json:"installed_root"`
	RelativeCurrentTarget string    `json:"relative_current_target"`
	UnitName              string    `json:"unit_name"`
	ServiceIdentity       string    `json:"service_identity"`
	InstanceID            string    `json:"instance_id"`
	MainPID               int32     `json:"main_pid"`
	ProcessStartIdentity  string    `json:"process_start_identity"`
	SocketPath            string    `json:"socket_path"`
	Capabilities          []string  `json:"capabilities"`
	ActivationGeneration  int64     `json:"activation_generation"`
	ActivatedAt           time.Time `json:"activated_at"`
	CreatedAt             time.Time `json:"created_at"`
}

type PackActiveRuntimeRecord struct {
	PackID              string    `json:"pack_id"`
	ActiveVersion       string    `json:"active_version"`
	ActivationReceiptID string    `json:"activation_receipt_id"`
	OperationID         string    `json:"operation_id"`
	InstanceID          string    `json:"instance_id"`
	UnitName            string    `json:"unit_name"`
	SocketPath          string    `json:"socket_path"`
	Capabilities        []string  `json:"capabilities"`
	RuntimeStatus       string    `json:"runtime_status"`
	CoreGeneration      int64     `json:"core_generation"`
	LastObservedAt      time.Time `json:"last_observed_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type UpdateActiveRuntimeStatusRequest struct {
	PackID              string    `json:"pack_id"`
	ActivationReceiptID string    `json:"activation_receipt_id"`
	InstanceID          string    `json:"instance_id"`
	CoreGeneration      int64     `json:"core_generation"`
	RuntimeStatus       string    `json:"runtime_status"`
	ObservedAt          time.Time `json:"observed_at"`
}

type PackUnifiedStatus struct {
	PackID            string                   `json:"pack_id"`
	DesiredVersion    string                   `json:"desired_version"`
	IntentPhase       string                   `json:"intent_phase"`
	ArtifactStatus    string                   `json:"artifact_status"`
	InstalledVersion  string                   `json:"installed_version,omitempty"`
	RuntimeReady      bool                     `json:"runtime_ready"`
	RuntimeStatus     string                   `json:"runtime_status,omitempty"`
	ArtifactReceipt   *PackArtifactReceipt     `json:"artifact_receipt,omitempty"`
	ActivationReceipt *PackActivationReceipt   `json:"activation_receipt,omitempty"`
	ActiveRuntime     *PackActiveRuntimeRecord `json:"active_runtime,omitempty"`
}

type RecordActivationJournalIntent struct {
	OperationID             string
	TaskID                  string
	PackID                  string
	Version                 string
	PlanSHA256              string
	ArtifactReceiptID       string
	Phase                   string
	CoreGeneration          int64
	LeaseGeneration         int64
	OwnerID                 string
	PublishID               string
	InstalledRoot           string
	UnitName                string
	InstanceID              string
	MainPID                 int32
	SocketPath              string
	ProcessStartIdentity    string
	CandidateCapabilities   []string
	CurrentPointerEffect    string
	ActivationGeneration    int64
	FailureReason           string
	ExpectedJournalRevision int64
	Audit                   AuditContext
}

type CommitActivationRecord struct {
	TaskID                  string
	Receipt                 PackActivationReceipt
	ExpectedUID             uint32
	CoreGeneration          int64
	LeaseGeneration         int64
	OwnerID                 string
	ExpectedJournalRevision int64
	Audit                   AuditContext
}

type PackObservedEffect struct {
	ActionID         string `json:"action_id"`
	OperationID      string `json:"operation_id"`
	PackID           string `json:"pack_id"`
	Version          string `json:"version"`
	Action           string `json:"action"`
	Status           string `json:"status"`
	CoreGeneration   int64  `json:"core_generation"`
	LeaseGeneration  int64  `json:"lease_generation"`
	Sequence         int64  `json:"sequence"`
	RequestDigest    string `json:"request_digest"`
	InstanceID       string `json:"instance_id,omitempty"`
	MainPID          int32  `json:"main_pid,omitempty"`
	ExecutablePath   string `json:"executable_path,omitempty"`
	ExecutableSHA    string `json:"executable_sha,omitempty"`
	ProcessStartTime string `json:"process_start_time,omitempty"`
	SocketPath       string `json:"socket_path,omitempty"`
	CurrentTarget    string `json:"current_target,omitempty"`
}

type PackObservedSnapshot struct {
	OperationID          string              `json:"operation_id"`
	PackID               string              `json:"pack_id"`
	Version              string              `json:"version"`
	MaxOperationSequence int64               `json:"max_operation_sequence"`
	ObservedStopped      bool                `json:"observed_stopped"`
	ObservedAt           time.Time           `json:"observed_at"`
	UID                  uint32              `json:"uid,omitempty"`
	PublishEffect        *PackObservedEffect `json:"publish_effect,omitempty"`
	StartEffect          *PackObservedEffect `json:"start_effect,omitempty"`
	StopEffect           *PackObservedEffect `json:"stop_effect,omitempty"`
	AbortEffect          *PackObservedEffect `json:"abort_effect,omitempty"`
	SwitchEffect         *PackObservedEffect `json:"switch_effect,omitempty"`
}

type ResumePackInstallRequest struct {
	OperationID                 string                             `json:"operation_id"`
	ExpectedOperationVersion    int64                              `json:"expected_operation_version"`
	TaskID                      string                             `json:"task_id"`
	ExpectedTaskAttempt         int                                `json:"expected_task_attempt"`
	ExpectedTaskCoreGeneration  int64                              `json:"expected_task_core_generation"`
	ExpectedTaskLeaseGeneration int64                              `json:"expected_task_lease_generation"`
	PackID                      string                             `json:"pack_id"`
	Version                     string                             `json:"version"`
	PlanSHA256                  string                             `json:"plan_sha256"`
	Selection                   packprotocol.VerifiedPackSelection `json:"-"`
	ExpectedAuthoritySequence   int64                              `json:"expected_authority_sequence"`
	ArtifactReceiptID           string                             `json:"artifact_receipt_id,omitempty"`
	ExpectedJournalRevision     int64                              `json:"expected_journal_revision"`
	ExpectedPhase               string                             `json:"expected_phase"`
	ObservedEffects             *PackObservedSnapshot              `json:"observed_effects,omitempty"`
	CoreGeneration              int64                              `json:"core_generation"`
	Audit                       AuditContext                       `json:"audit"`
}

type WaitingOperationRecord struct {
	OperationID                 string `json:"operation_id"`
	OperationVersion            int64  `json:"operation_version"`
	TaskID                      string `json:"task_id"`
	TaskAttempt                 int    `json:"task_attempt"`
	TaskCoreGeneration         int64  `json:"task_core_generation"`
	TaskLeaseGeneration        int64  `json:"task_lease_generation"`
	PackID                      string `json:"pack_id"`
	Version                     string `json:"version"`
	PlanSHA256                  string `json:"plan_sha256"`
}

type ActivePackSource struct {
	PackID               string    `json:"pack_id"`
	ActiveVersion        string    `json:"active_version"`
	ActivationReceiptID  string    `json:"activation_receipt_id"`
	OperationID          string    `json:"operation_id"`
	InstanceID           string    `json:"instance_id"`
	InstanceGeneration   int64     `json:"instance_generation"`
	UnitName             string    `json:"unit_name"`
	SocketPath           string    `json:"socket_path"`
	Capabilities         []string  `json:"capabilities"`
	RuntimeStatus        string    `json:"runtime_status"`
	CoreGeneration       int64     `json:"core_generation"`
	LastObservedAt       time.Time `json:"last_observed_at"`
	ExpectedUID          uint32    `json:"expected_uid"`
	ExpectedPID          int32     `json:"expected_pid"`
	ExecutableSHA256     string    `json:"executable_sha256"`
	ExecutablePath       string    `json:"executable_path"`
	ProcessStartIdentity string    `json:"process_start_identity"`
}

type AuthorizePackActivationActionRequest struct {
	TaskID                  string       `json:"task_id"`
	OperationID             string       `json:"operation_id"`
	PackID                  string       `json:"pack_id"`
	Version                 string       `json:"version"`
	PlanSHA256              string       `json:"plan_sha256"`
	Action                  string       `json:"action"` // "prepare", "publish", "start", "switch", "stop", "abort"
	CoreGeneration          int64        `json:"core_generation"`
	LeaseGeneration         int64        `json:"lease_generation"`
	OwnerID                 string       `json:"owner_id"`
	ExpectedJournalRevision int64        `json:"expected_journal_revision"`
	Audit                   AuditContext `json:"audit"`
}

type AuthorizePackActivationActionResult struct {
	Authorized      bool      `json:"authorized"`
	Deadline        time.Time `json:"deadline"`
	JournalRevision int64     `json:"journal_revision"`
}

type RequestPackInstallCancellationRecord struct {
	OperationID              string       `json:"operation_id"`
	ExpectedOperationVersion int64        `json:"expected_operation_version"`
	Reason                   string       `json:"reason"`
	Audit                    AuditContext `json:"audit"`
}

type FailPackInstallRecord struct {
	TaskID                  string       `json:"task_id"`
	OperationID             string       `json:"operation_id"`
	CoreGeneration          int64        `json:"core_generation"`
	LeaseGeneration         int64        `json:"lease_generation"`
	OwnerID                 string       `json:"owner_id"`
	ExpectedJournalRevision int64        `json:"expected_journal_revision"`
	Classification          string       `json:"classification"` // "known_failure", "waiting_authorization", "waiting_reconcile"
	Reason                  string       `json:"reason"`
	Audit                   AuditContext `json:"audit"`
}

type CancelActivationRecord struct {
	OperationID             string
	TaskID                  string
	CoreGeneration          int64
	LeaseGeneration         int64
	OwnerID                 string
	Reason                  string
	AbortReceiptID          string
	UnitName                string
	InstanceID              string
	ObservedStopped         bool
	ObservedStoppedAt       time.Time
	ExpectedJournalRevision int64
	Audit                   AuditContext
}

type PackLifecycleRepository interface {
	RecordStageIntent(ctx context.Context, intent StageArtifactIntent) (int64, error)
	CommitArtifactReceipt(ctx context.Context, record CommitArtifactReceiptRecord) error
	RecordLifecycleFailure(ctx context.Context, record LifecycleFailureRecord) error
	RecordAuthorizationRequired(ctx context.Context, record AuthorizationRequiredRecord) error
	GetArtifactReceipt(ctx context.Context, operationID string) (PackArtifactReceipt, error)
	GetPackLifecycleJournal(ctx context.Context, operationID string) (PackLifecycleJournalRecord, error)
	GetPackTrustMaterial(ctx context.Context, operationID string) (PackTrustMaterialRecord, error)
	ResupplyPackTrustMaterial(ctx context.Context, operationID string, selection packprotocol.VerifiedPackSelection, authorityKind string) error
	GetPackStatus(ctx context.Context, packID string) (status string, receipt *PackArtifactReceipt, err error)

	AuthorizePackActivationAction(ctx context.Context, req AuthorizePackActivationActionRequest) (AuthorizePackActivationActionResult, error)
	RequestPackInstallCancellation(ctx context.Context, record RequestPackInstallCancellationRecord) error
	FailPackInstall(ctx context.Context, record FailPackInstallRecord) error
	ResumePackInstall(ctx context.Context, req ResumePackInstallRequest) error
	ListWaitingOperations(ctx context.Context, limit int) ([]WaitingOperationRecord, error)

	RecordActivationJournal(ctx context.Context, intent RecordActivationJournalIntent) (int64, error)
	CommitActivation(ctx context.Context, record CommitActivationRecord) error
	CancelActivation(ctx context.Context, record CancelActivationRecord) error
	GetActivationJournal(ctx context.Context, operationID string) (PackActivationJournalRecord, error)
	GetActivationReceipt(ctx context.Context, operationID string) (PackActivationReceipt, error)
	GetActiveRuntime(ctx context.Context, packID string) (PackActiveRuntimeRecord, error)
	GetActivePackSource(ctx context.Context, packID string) (ActivePackSource, error)
	ListActiveRuntimes(ctx context.Context, cursorPackID string, limit int) ([]PackActiveRuntimeRecord, error)
	UpdateActiveRuntimeStatus(ctx context.Context, req UpdateActiveRuntimeStatusRequest) error
	GetPackUnifiedStatus(ctx context.Context, packID string) (PackUnifiedStatus, error)
}
