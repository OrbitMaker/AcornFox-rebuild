package contracts

import (
	"context"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packprotocol"
)

// DiagnosticInputContext alias to the leaf packprotocol definition.
type DiagnosticInputContext = packprotocol.DiagnosticInputContext

// DiagnosticObservation alias to the leaf packprotocol definition.
type DiagnosticObservation = packprotocol.DiagnosticObservation

// PackProtocolInstance records durable attested state for a running adapter process.
type PackProtocolInstance struct {
	InstanceID          string     `json:"instance_id"`
	PackID              string     `json:"pack_id"`
	Version             string     `json:"version"`
	OperationID         string     `json:"operation_id"`
	InstallationBinding string     `json:"installation_binding"`
	ManifestSHA256      string     `json:"manifest_sha256"`
	ExecutableSHA256    string     `json:"executable_sha256"`
	ExecutablePath      string     `json:"executable_path"`
	ProtocolVersion     string     `json:"protocol_version"`
	Capabilities        []string   `json:"capabilities"`
	ExpectedUID         uint32     `json:"expected_uid"`
	ExpectedPID         int32      `json:"expected_pid"`
	ProcessStartTime    string     `json:"process_start_time"`
	SocketPath          string     `json:"socket_path"`
	CoreGeneration      int64      `json:"core_generation"`
	InstanceGeneration  int64      `json:"instance_generation"`
	RetiredAt           *time.Time `json:"retired_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// RegisterPackProtocolInstanceRequest parameters for registering a verified process.
type RegisterPackProtocolInstanceRequest struct {
	InstanceID       string `json:"instance_id"`
	PackID           string `json:"pack_id"`
	OperationID      string `json:"operation_id"`
	ExecutablePath   string `json:"executable_path"`
	ExpectedUID      uint32 `json:"expected_uid"`
	ExpectedPID      int32  `json:"expected_pid"`
	ProcessStartTime string `json:"process_start_time"`
	ExecutableSHA256 string `json:"executable_sha256"`
	SocketPath       string `json:"socket_path"`
	ManifestRaw      []byte `json:"-"` // Opaque verified manifest bytes from trusted core
}

// PackProtocolCheck records a diagnostic check child task bound to an install operation.
type PackProtocolCheck struct {
	TaskID                  domain.ID              `json:"task_id"`
	OperationID             domain.ID              `json:"operation_id"`
	PackID                  string                 `json:"pack_id"`
	InstanceID              string                 `json:"instance_id"`
	InstanceGeneration      int64                  `json:"instance_generation"`
	Kind                    string                 `json:"kind"`
	Capability              string                 `json:"capability"`
	Scope                   string                 `json:"scope"`
	IdempotencyKey          string                 `json:"idempotency_key"`
	InputDigest             string                 `json:"input_digest"`
	InputContext            DiagnosticInputContext `json:"input_context"`
	CancellationRequested   bool                   `json:"cancellation_requested"`
	CancellationReason      string                 `json:"cancellation_reason,omitempty"`
	CancellationRequestedAt *time.Time             `json:"cancellation_requested_at,omitempty"`
	CreatedAt               time.Time              `json:"created_at"`
	UpdatedAt               time.Time              `json:"updated_at"`
}

// BeginPackProtocolCheckRequest parameters to create an immutable diagnostic check task.
type BeginPackProtocolCheckRequest struct {
	PackID         string                 `json:"pack_id"`
	OperationID    string                 `json:"operation_id"`
	InstanceID     string                 `json:"instance_id"`
	IdempotencyKey string                 `json:"idempotency_key"`
	Kind           string                 `json:"kind"`
	Capability     string                 `json:"capability"`
	InputContext   DiagnosticInputContext `json:"input_context"`
	Audit          AuditContext           `json:"audit"`
}

// BeginPackProtocolCheckResult projection returned when a diagnostic check is created or replayed.
type BeginPackProtocolCheckResult struct {
	TaskID      string    `json:"task_id"`
	OperationID string    `json:"operation_id"`
	InstanceID  string    `json:"instance_id"`
	InputDigest string    `json:"input_digest"`
	State       TaskState `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
}

// PackProtocolReceipt represents the durable acknowledgment for a processed event.
type PackProtocolReceipt struct {
	ReceiptID   string    `json:"receipt_id"`
	TaskID      string    `json:"task_id"`
	InstanceID  string    `json:"instance_id"`
	Sequence    uint64    `json:"sequence"`
	EventDigest string    `json:"event_digest"`
	CommittedAt time.Time `json:"committed_at"`
	Status      string    `json:"status"`
}

// CommitPackProtocolEventRequest parameters for atomically recording check observation results.
type CommitPackProtocolEventRequest struct {
	TaskID             domain.ID             `json:"task_id"`
	InstanceID         string                `json:"instance_id"`
	CoreGeneration     int64                 `json:"core_generation"`
	LeaseGeneration    int64                 `json:"lease_generation"`
	InstanceGeneration int64                 `json:"instance_generation"`
	Owner              string                `json:"owner"`
	Sequence           uint64                `json:"sequence"`
	InputDigest        string                `json:"input_digest"`
	EventDigest        string                `json:"event_digest"`
	Kind               string                `json:"kind"`
	Observation        DiagnosticObservation `json:"observation"`
	Terminal           bool                  `json:"terminal"`
	TerminalStatus     string                `json:"terminal_status"`
	TerminalState      TaskState             `json:"terminal_state"`
	OccurredAt         time.Time             `json:"occurred_at"`
	Audit              AuditContext          `json:"audit"`
	Now                time.Time             `json:"now"`
}

// AuthorizePackProtocolDispatchRequest parameters to validate fresh authorization before dispatch.
type AuthorizePackProtocolDispatchRequest struct {
	TaskID          domain.ID `json:"task_id"`
	InstanceID      string    `json:"instance_id"`
	Owner           string    `json:"owner"`
	CoreGeneration  int64     `json:"core_generation"`
	LeaseGeneration int64     `json:"lease_generation"`
	Now             time.Time `json:"now"`
}

// PackProtocolDispatchAuthorization returns authoritative current persistence facts for dispatch.
type PackProtocolDispatchAuthorization struct {
	TaskID             domain.ID              `json:"task_id"`
	OperationID        domain.ID              `json:"operation_id"`
	PackID             string                 `json:"pack_id"`
	InstanceID         string                 `json:"instance_id"`
	InstanceGeneration int64                  `json:"instance_generation"`
	CoreGeneration     int64                  `json:"core_generation"`
	LeaseGeneration    int64                  `json:"lease_generation"`
	LeaseOwner         string                 `json:"lease_owner"`
	LeaseUntil         time.Time              `json:"lease_until"`
	Kind               string                 `json:"kind"`
	Capability         string                 `json:"capability"`
	InputDigest        string                 `json:"input_digest"`
	InputContext       DiagnosticInputContext `json:"input_context"`
	SocketPath         string                 `json:"socket_path"`
	ExpectedPID        int32                  `json:"expected_pid"`
	ExpectedUID        uint32                 `json:"expected_uid"`
	ExecutableSHA256   string                 `json:"executable_sha256"`
	ProcessStartTime   string                 `json:"process_start_time"`
}

// PackExecutionRepository defines the narrow persistence boundary for pack protocol execution.
type PackExecutionRepository interface {
	RegisterPackProtocolInstance(context.Context, RegisterPackProtocolInstanceRequest) (PackProtocolInstance, error)
	BeginPackProtocolCheck(context.Context, BeginPackProtocolCheckRequest) (BeginPackProtocolCheckResult, error)
	CommitPackProtocolEvent(context.Context, CommitPackProtocolEventRequest) (PackProtocolReceipt, error)
	GetPackProtocolCheck(context.Context, domain.ID) (PackProtocolCheck, error)
	RequestPackProtocolCancellation(context.Context, domain.ID, string) error
	AuthorizePackProtocolDispatch(context.Context, AuthorizePackProtocolDispatchRequest) (PackProtocolDispatchAuthorization, error)
}
