package hosthelper

import (
	"time"
)

const (
	DefaultHelperSocketPath = "/run/acornfox-helper/helper.sock"
	DefaultHelperStateDir   = "/var/lib/acornfox-host-helper"

	ActionPrepare         = "prepare"
	ActionPublish         = "publish"
	ActionStart           = "start"
	ActionStopForRecovery = "stop_for_recovery"
	ActionAbort           = "abort"
	ActionSwitch          = "switch"

	StatusSucceeded          = "succeeded"
	StatusStoppedForRecovery = "stopped_for_recovery"
	StatusAborted            = "aborted"
	StatusFailed             = "failed"
)

type ActionPermit struct {
	OperationID     string    `json:"operation_id"`
	PackID          string    `json:"pack_id"`
	Version         string    `json:"version"`
	CoreGeneration  int64     `json:"core_generation"`
	LeaseGeneration int64     `json:"lease_generation"`
	OwnerID         string    `json:"owner_id"`
	Deadline        time.Time `json:"deadline"`
	ActionID        string    `json:"action_id"`
	Sequence        int64     `json:"sequence"`
}

type CoreRegistration struct {
	CorePID             int32  `json:"core_pid"`
	CoreUID             uint32 `json:"core_uid"`
	CoreStartTime       string `json:"core_start_time"`
	CoreExecutableSHA   string `json:"core_executable_sha"`
	InstallationBinding string `json:"installation_binding"`
	CoreGeneration      int64  `json:"core_generation"`
}

type RegisterCoreRequest struct {
	Registration CoreRegistration `json:"registration"`
}

type RegisterCoreResponse struct {
	Registered bool   `json:"registered"`
	Message    string `json:"message,omitempty"`
}

type PrepareDirsRequest struct {
	Permit ActionPermit `json:"permit"`
}

type PrepareDirsResponse struct {
	PackUID       uint32 `json:"pack_uid"`
	PackGID       uint32 `json:"pack_gid"`
	PackUser      string `json:"pack_user"`
	PackGroup     string `json:"pack_group"`
	PublishedRoot string `json:"published_root"`
	StateRoot     string `json:"state_root"`
	RunRoot       string `json:"run_root"`
}

type PublishPackRequest struct {
	Permit                     ActionPermit `json:"permit"`
	ArtifactReceiptID          string       `json:"artifact_receipt_id"`
	PlanSHA256                 string       `json:"plan_sha256"`
	CatalogEnvelopeRaw         []byte       `json:"catalog_envelope_raw"`
	ManifestRaw                []byte       `json:"manifest_raw"`
	StageIdentity              string       `json:"stage_identity"`
	ExpectedArchiveSHA         string       `json:"expected_archive_sha"`
	ExpectedManifestSHA        string       `json:"expected_manifest_sha"`
	ExpectedExecutablePath     string       `json:"expected_executable_path"`
	ExpectedExecutableSHA      string       `json:"expected_executable_sha"`
	ExpectedMemberCount        int          `json:"expected_member_count"`
	ExpectedUnpackedTotalBytes int64        `json:"expected_unpacked_total_bytes"`
}

type PublishPackResponse struct {
	PublishedRoot  string `json:"published_root"`
	ExecutablePath string `json:"executable_path"`
	ExecutableSHA  string `json:"executable_sha"`
}

type StartPackRequest struct {
	Permit        ActionPermit `json:"permit"`
	GateDelaySecs int          `json:"gate_delay_secs,omitempty"`
}

type StartPackResponse struct {
	UnitName             string `json:"unit_name"`
	MainPID              int32  `json:"main_pid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	SocketPath           string `json:"socket_path"`
	ExecutableSHA256     string `json:"executable_sha256"`
	UID                  uint32 `json:"uid"`
	InstanceID           string `json:"instance_id"`
}

type PeerAttestRequest struct {
	PID                   int32  `json:"pid"`
	UID                   uint32 `json:"uid"`
	ExpectedPackID        string `json:"expected_pack_id"`
	ExpectedVersion       string `json:"expected_version"`
	ExpectedInstanceID    string `json:"expected_instance_id"`
	ExpectedExecutableSHA string `json:"expected_executable_sha"`
	ExpectedStartTime     string `json:"expected_start_time"`
}

type PeerAttestResponse struct {
	Attested             bool   `json:"attested"`
	ExecutablePath       string `json:"executable_path"`
	ExecutableSHA256     string `json:"executable_sha256"`
	ProcessStartIdentity string `json:"process_start_identity"`
	UID                  uint32 `json:"uid"`
	Error                string `json:"error,omitempty"`
}

type ObservePackRequest struct {
	PackID      string             `json:"pack_id"`
	Version     string             `json:"version,omitempty"`
	OperationID string             `json:"operation_id,omitempty"`
	PeerAttest  *PeerAttestRequest `json:"peer_attest,omitempty"`
}

type OperationCancellationSnapshot struct {
	OperationID          string               `json:"operation_id"`
	PackID               string               `json:"pack_id"`
	Version              string               `json:"version"`
	MaxOperationSequence int64                `json:"max_operation_sequence"`
	UID                  uint32               `json:"uid,omitempty"`
	PublishEffect        *HelperEffectReceipt `json:"publish_effect,omitempty"`
	StartEffect          *HelperEffectReceipt `json:"start_effect,omitempty"`
	StopEffect           *HelperEffectReceipt `json:"stop_effect,omitempty"`
	AbortEffect          *HelperEffectReceipt `json:"abort_effect,omitempty"`
	SwitchEffect         *HelperEffectReceipt `json:"switch_effect,omitempty"`
	UnitName             string               `json:"unit_name,omitempty"`
	InstanceID           string               `json:"instance_id,omitempty"`
	ObservedStopped      bool                 `json:"observed_stopped"`
	ObservedAt           time.Time            `json:"observed_at"`
}

type ObservePackResponse struct {
	Active               bool                           `json:"active"`
	UnitStatus           string                         `json:"unit_status"`
	MainPID              int32                          `json:"main_pid"`
	ProcessStartIdentity string                         `json:"process_start_identity"`
	PeerAttestResult     *PeerAttestResponse            `json:"peer_attest_result,omitempty"`
	CancellationSnapshot *OperationCancellationSnapshot `json:"cancellation_snapshot,omitempty"`
}

type StopPendingRequest struct {
	Permit ActionPermit `json:"permit"`
	Reason string       `json:"reason,omitempty"`
}

type StopPendingResponse struct {
	Stopped        bool   `json:"stopped"`
	AbortReceiptID string `json:"abort_receipt_id,omitempty"`
	Message        string `json:"message,omitempty"`
}

type AbortPendingRequest struct {
	Permit ActionPermit `json:"permit"`
	Reason string       `json:"reason"`
}

type AbortPendingResponse struct {
	Aborted        bool   `json:"aborted"`
	AbortReceiptID string `json:"abort_receipt_id"`
}

type SwitchCurrentRequest struct {
	Permit         ActionPermit `json:"permit"`
	RelativeTarget string       `json:"relative_target"`
}

type SwitchCurrentResponse struct {
	Effect  string `json:"effect"` // "created", "existing_matched"
	Message string `json:"message,omitempty"`
}

type HelperEffectReceipt struct {
	ActionID         string    `json:"action_id"`
	OperationID      string    `json:"operation_id"`
	PackID           string    `json:"pack_id"`
	Version          string    `json:"version"`
	Action           string    `json:"action"` // prepare, publish, start, stop_for_recovery, abort, switch
	Status           string    `json:"status"` // succeeded, stopped_for_recovery, aborted, failed
	CoreGeneration   int64     `json:"core_generation"`
	LeaseGeneration  int64     `json:"lease_generation"`
	Sequence         int64     `json:"sequence"`
	RequestDigest    string    `json:"request_digest"`
	InstanceID       string    `json:"instance_id,omitempty"`
	MainPID          int32     `json:"main_pid,omitempty"`
	ExecutablePath   string    `json:"executable_path,omitempty"`
	ExecutableSHA    string    `json:"executable_sha,omitempty"`
	ProcessStartTime string    `json:"process_start_identity,omitempty"`
	SocketPath       string    `json:"socket_path,omitempty"`
	CurrentTarget    string    `json:"current_target,omitempty"`
	Detail           string    `json:"detail,omitempty"`
	RecordedAt       time.Time `json:"recorded_at"`
}

// RuntimePeerAttestRequest asks the root host helper to attest a connected peer process.
type RuntimePeerAttestRequest struct {
	TargetRole    string `json:"target_role"` // Fixed counterpart: "core", "container", or optional "source-build"; helper validates the pair.
	PeerPID       int32  `json:"peer_pid"`
	PeerUID       uint32 `json:"peer_uid"`
	BindingDigest string `json:"binding_digest"`
}

// RuntimePeerAttestResponse returns the root-attested process credentials and binding verification.
type RuntimePeerAttestResponse struct {
	Valid         bool      `json:"valid"`
	PID           int32     `json:"pid"`
	UID           uint32    `json:"uid"`
	ExeSHA        string    `json:"exe_sha"`
	StartTime     string    `json:"start_time"`
	ObservedAt    time.Time `json:"observed_at"`
	BindingDigest string    `json:"binding_digest"`
	Error         string    `json:"error,omitempty"`
}
