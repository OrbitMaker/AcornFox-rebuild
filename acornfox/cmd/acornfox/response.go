package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type apiSession struct {
	Authenticated     *bool     `json:"authenticated"`
	IdleExpiresAt     time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
}
type apiApplication struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type apiSource struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	Kind          string    `json:"kind"`
	LocatorSHA256 string    `json:"locator_sha256"`
	Ref           string    `json:"ref,omitempty"`
	Commit        string    `json:"commit,omitempty"`
	ContentDigest string    `json:"content_digest"`
	CreatedAt     time.Time `json:"created_at"`
	Immutable     *bool     `json:"immutable"`
}
type apiDeployment struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	EnvironmentID string    `json:"environment_id"`
	ReleaseID     string    `json:"release_id"`
	Stage         string    `json:"stage"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type apiCommand struct {
	DeploymentID string `json:"deployment_id"`
	OperationID  string `json:"operation_id"`
	TaskID       string `json:"task_id"`
	Status       string `json:"status"`
}
type apiApps struct {
	Items []apiApplication `json:"items"`
}
type apiCreateApp struct {
	Application      apiApplication `json:"application"`
	SourceRevisionID string         `json:"source_revision_id"`
	OperationID      string         `json:"operation_id"`
}
type apiSources struct {
	Items      []apiSource `json:"items"`
	NextCursor *string     `json:"next_cursor"`
}
type apiDeployments struct {
	Items      []apiDeployment `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}
type apiImage struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}
type apiResources struct {
	CPUMillis            *int64 `json:"cpu_millis"`
	MemoryBytes          *int64 `json:"memory_bytes"`
	Pids                 *int64 `json:"pids"`
	DiskReservationBytes *int64 `json:"disk_reservation_bytes"`
}
type apiRelease struct {
	SchemaVersion *int                                    `json:"schema_version,omitempty"`
	Configuration *contracts.AcornFoxRuntimeConfiguration `json:"configuration,omitempty"`
	ConfigDigest  *string                                 `json:"config_digest,omitempty"`
	ApplicationID string                                  `json:"application_id"`
	EnvironmentID string                                  `json:"environment_id"`
	ReleaseID     string                                  `json:"release_id"`
	ServiceName   string                                  `json:"service_name"`
	Image         apiImage                                `json:"image"`
	Resources     apiResources                            `json:"resources"`
	ContainerPort *int                                    `json:"container_port,omitempty"`
	AcceptedAt    time.Time                               `json:"accepted_at"`
	Immutable     *bool                                   `json:"immutable"`
}
type apiLimits struct {
	CPUMillis   *int64 `json:"cpu_millis"`
	MemoryBytes *int64 `json:"memory_bytes"`
	Pids        *int64 `json:"pids"`
}
type apiDisk struct {
	ReservationBytes     *int64 `json:"reservation_bytes"`
	AccountingReconciled *bool  `json:"accounting_reconciled"`
	PerContainerEnforced *bool  `json:"per_container_enforced"`
}
type apiRuntime struct {
	DeploymentID       string       `json:"deployment_id"`
	ServiceName        string       `json:"service_name"`
	ContainerID        string       `json:"container_id,omitempty"`
	RuntimeState       string       `json:"runtime_state"`
	RestartCount       *int64       `json:"restart_count"`
	InternalAddress    string       `json:"internal_address,omitempty"`
	RequestedResources apiResources `json:"requested_resources"`
	AppliedLimits      apiLimits    `json:"applied_limits"`
	Disk               apiDisk      `json:"disk"`
	ObservedAt         time.Time    `json:"observed_at"`
}
type apiProbe struct {
	Protocol   string    `json:"protocol"`
	Outcome    string    `json:"outcome"`
	HTTPStatus *int      `json:"http_status,omitempty"`
	LatencyMS  *int64    `json:"latency_ms,omitempty"`
	ErrorCode  *string   `json:"error_code,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	FactDigest string    `json:"fact_digest"`
}
type apiStatus struct {
	Deployment apiDeployment `json:"deployment"`
	Desired    *apiRelease   `json:"desired"`
	Runtime    *apiRuntime   `json:"runtime"`
	Response   *apiProbe     `json:"response"`
}
type apiLogItem struct {
	Stream     string    `json:"stream"`
	RecordedAt time.Time `json:"recorded_at"`
	Content    *string   `json:"content"`
	Truncation string    `json:"truncation"`
}
type apiLogs struct {
	Source           string       `json:"source"`
	Availability     string       `json:"availability"`
	Items            []apiLogItem `json:"items"`
	NextCursor       *string      `json:"next_cursor"`
	RetentionLimited *bool        `json:"retention_limited"`
}
type apiEndpoint struct {
	DeploymentID string `json:"deployment_id"`
}
type apiComponents struct {
	InternalEndpoint string `json:"internal_endpoint"`
	LocalRoute       string `json:"local_route"`
	DNS              string `json:"dns"`
	TLS              string `json:"tls"`
	External         string `json:"external"`
}
type apiPublicAccess struct {
	DesiredPublic *bool         `json:"desired_public"`
	URL           string        `json:"url"`
	Endpoint      apiEndpoint   `json:"endpoint"`
	Components    apiComponents `json:"components"`
	Status        string        `json:"status"`
}
type apiSourceMetadata struct {
	SourceRevisionID string  `json:"source_revision_id"`
	Availability     string  `json:"availability"`
	RepositoryURL    *string `json:"repository_url,omitempty"`
}
type apiDeploymentPlanDockerfile struct {
	Status     string                    `json:"status"`
	Path       string                    `json:"path"`
	Digest     string                    `json:"digest,omitempty"`
	StageCount int                       `json:"stage_count"`
	FinalStage *apiDeploymentPlanStage   `json:"final_stage,omitempty"`
	Workdir    string                    `json:"workdir,omitempty"`
	Entrypoint *apiDeploymentPlanCommand `json:"entrypoint,omitempty"`
	Command    *apiDeploymentPlanCommand `json:"command,omitempty"`
}
type apiDeploymentPlanStage struct {
	Name     string `json:"name"`
	Index    int    `json:"index"`
	From     string `json:"from"`
	Platform string `json:"platform,omitempty"`
}
type apiDeploymentPlanCommand struct {
	Form   string   `json:"form,omitempty"`
	Values []string `json:"values,omitempty"`
}
type apiDeploymentPlanPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
}
type apiDeploymentPlanPortSelection struct {
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	SelectedPort   *int   `json:"selected_port,omitempty"`
	Candidates     []int  `json:"candidates"`
	SuggestedPorts []int  `json:"suggested_ports,omitempty"`
}
type apiDeploymentPlanHealthcheck struct {
	Present            bool     `json:"present"`
	Disabled           bool     `json:"disabled,omitempty"`
	Form               string   `json:"form,omitempty"`
	Test               []string `json:"test,omitempty"`
	IntervalSeconds    int      `json:"interval_seconds,omitempty"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
	StartPeriodSeconds int      `json:"start_period_seconds,omitempty"`
	Retries            int      `json:"retries,omitempty"`
}
type apiDeploymentPlanEnvironment struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
}
type apiDeploymentPlan struct {
	SourceType       *string                        `json:"source_type,omitempty"`
	ApplicationID    string                         `json:"application_id"`
	SourceRevisionID string                         `json:"source_revision_id"`
	RepositoryURL    string                         `json:"repository_url"`
	Ref              string                         `json:"ref"`
	Commit           string                         `json:"commit"`
	Dockerfile       apiDeploymentPlanDockerfile    `json:"dockerfile"`
	Ports            []apiDeploymentPlanPort        `json:"ports"`
	PortSelection    apiDeploymentPlanPortSelection `json:"port_selection"`
	Healthcheck      apiDeploymentPlanHealthcheck   `json:"healthcheck"`
	Environment      []apiDeploymentPlanEnvironment `json:"environment"`
	Gaps             []string                       `json:"gaps"`
	Warnings         []string                       `json:"warnings"`
	RequiredActions  []string                       `json:"required_actions"`
	ReadyToDeploy    bool                           `json:"ready_to_deploy"`
}
type apiDeliverySource struct {
	DeploymentID     string  `json:"deployment_id"`
	Availability     string  `json:"availability"`
	SourceRevisionID *string `json:"source_revision_id,omitempty"`
	Commit           *string `json:"commit,omitempty"`
	Ref              *string `json:"ref,omitempty"`
	RepositoryURL    *string `json:"repository_url,omitempty"`
}
type apiHostCPU struct {
	LogicalCores int      `json:"logical_cores"`
	UsagePercent *float64 `json:"usage_percent,omitempty"`
}
type apiHostMemory struct {
	TotalBytes     int64 `json:"total_bytes"`
	AvailableBytes int64 `json:"available_bytes"`
	UsedBytes      int64 `json:"used_bytes"`
}
type apiHostDisk struct {
	Mountpoint string `json:"mountpoint"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
}
type apiHostNetwork struct {
	Interface        string   `json:"interface"`
	RXBytesPerSecond *float64 `json:"rx_bytes_per_second,omitempty"`
	TXBytesPerSecond *float64 `json:"tx_bytes_per_second,omitempty"`
}
type apiHostMetrics struct {
	SchemaVersion     int             `json:"schema_version"`
	Availability      string          `json:"availability"`
	ObservedAt        *time.Time      `json:"observed_at,omitempty"`
	StaleAfterSeconds int             `json:"stale_after_seconds"`
	CPU               *apiHostCPU     `json:"cpu,omitempty"`
	Memory            *apiHostMemory  `json:"memory,omitempty"`
	Disk              *apiHostDisk    `json:"disk,omitempty"`
	Network           *apiHostNetwork `json:"network,omitempty"`
}
type apiHostMetricsRecent struct {
	SchemaVersion    int              `json:"schema_version"`
	Availability     string           `json:"availability"`
	GeneratedAt      time.Time        `json:"generated_at"`
	Capacity         int              `json:"capacity"`
	RetentionSeconds int              `json:"retention_seconds"`
	Points           []apiHostMetrics `json:"points"`
}
type apiOperationEvidence struct {
	Kind       string    `json:"kind"`
	Verdict    string    `json:"verdict"`
	ObservedAt time.Time `json:"observed_at"`
	HTTPStatus *int      `json:"http_status,omitempty"`
}
type apiOperationResult struct {
	OperationID   string                `json:"operation_id"`
	OperationType string                `json:"operation_type"`
	Status        string                `json:"status"`
	TaskID        *string               `json:"task_id,omitempty"`
	DeploymentID  *string               `json:"deployment_id,omitempty"`
	AcceptedAt    time.Time             `json:"accepted_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	Evidence      *apiOperationEvidence `json:"evidence,omitempty"`
}
type apiSourceUpdate struct {
	SourceRevisionID string `json:"source_revision_id"`
	Status           string `json:"status"`
}
type apiFixCandidateRuntime struct {
	TaskID           string   `json:"task_id"`
	Image            apiImage `json:"image"`
	RuntimeState     string   `json:"runtime_state"`
	ProbeOutcome     string   `json:"probe_outcome"`
	HTTPStatus       *int     `json:"http_status,omitempty"`
	CleanupConfirmed *bool    `json:"cleanup_confirmed"`
	EvidenceDigest   string   `json:"evidence_digest"`
}
type apiFixCandidate struct {
	CandidateID             string                 `json:"candidate_id"`
	ApplicationID           string                 `json:"application_id"`
	BaseSourceRevisionID    string                 `json:"base_source_revision_id"`
	BaseRepositoryURL       string                 `json:"base_repository_url"`
	BaseCommit              string                 `json:"base_commit"`
	BaseTreeDigest          string                 `json:"base_tree_digest"`
	PatchDigest             string                 `json:"patch_digest"`
	ResultTreeDigest        string                 `json:"result_tree_digest"`
	ContainerPort           int                    `json:"container_port"`
	ChangedPaths            []string               `json:"changed_paths"`
	CanonicalDiff           string                 `json:"canonical_diff"`
	ValidatedImage          apiImage               `json:"validated_image"`
	BuildLogRef             string                 `json:"build_log_ref"`
	BuildEvidenceDigest     string                 `json:"build_evidence_digest"`
	Runtime                 apiFixCandidateRuntime `json:"runtime"`
	MatchedSourceRevisionID *string                `json:"matched_source_revision_id,omitempty"`
	MatchedCommit           *string                `json:"matched_commit,omitempty"`
	Status                  string                 `json:"status"`
	CreatedAt               time.Time              `json:"created_at"`
	ExpiresAt               time.Time              `json:"expires_at"`
}

func (v apiFixCandidate) MarshalJSON() ([]byte, error) {
	if v.Status == "preparing" || v.Status == "failed" {
		return json.Marshal(struct {
			CandidateID          string    `json:"candidate_id"`
			ApplicationID        string    `json:"application_id"`
			BaseSourceRevisionID string    `json:"base_source_revision_id"`
			Status               string    `json:"status"`
			CreatedAt            time.Time `json:"created_at"`
		}{CandidateID: v.CandidateID, ApplicationID: v.ApplicationID, BaseSourceRevisionID: v.BaseSourceRevisionID, Status: v.Status, CreatedAt: v.CreatedAt})
	}
	type wire apiFixCandidate
	return json.Marshal(wire(v))
}

type apiFixCandidates struct {
	Items []apiFixCandidate `json:"items"`
}

func decodeResponse(body io.Reader, shape responseShape) (any, error) {
	limit := maxResponseBytes
	if shape == shapeImageMetrics {
		limit = appcontracts.ImageMetricsJSONBytes
	}
	if shape == shapeImageMetricsRecent {
		limit = appcontracts.ImageMetricsHistoryJSONBytes
	}
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil || len(data) == 0 || len(data) > limit {
		return nil, invalidResponse("server response is invalid")
	}
	if !requiredResponseFields(data, shape) {
		return nil, invalidResponse("server response does not match the AcornFox API contract")
	}
	if optionalNonNullableNull(data, shape) {
		return nil, invalidResponse("server response does not match the AcornFox API contract")
	}
	switch shape {
	case shapeImageMetrics:
		var v appcontracts.ImageMetricsResult
		return decodeTyped(data, &v, validateImageMetrics)
	case shapeImageMetricsRecent:
		var v appcontracts.ImageMetricsRecentResult
		return decodeTyped(data, &v, validateImageMetricsRecent)
	case shapeImageObservation, shapeImageLogObservation:
		var v appcontracts.ImageObservationResult
		return decodeTyped(data, &v, validateImageObservation)
	case shapeManagedImageApps:
		var v appcontracts.ManagedImageApplicationList
		return decodeTyped(data, &v, validateManagedImageApps)
	case shapeNativeImageLifecycle:
		var v appcontracts.ImageLifecycleOperation
		return decodeTyped(data, &v, validateNativeImageLifecycle)
	case shapeNativeImageDomainOperation:
		var v appcontracts.ImagePublicAccessOperation
		return decodeTyped(data, &v, validateNativeImageDomainOperation)
	case shapeNativeImageDomainCurrent:
		var v appcontracts.ImagePublicAccessCurrent
		return decodeTyped(data, &v, validateNativeImageDomainCurrent)
	case shapeNativeImagePlan:
		var v appcontracts.ImagePlan
		return decodeTyped(data, &v, validateNativeImagePlan)
	case shapeSourceBuildIntent:
		var v appcontracts.SourceBuildPublicIntent
		return decodeTyped(data, &v, validateSourceBuildIntent)
	case shapeNativeImageConfirm:
		var v appcontracts.ConfirmImagePlanResult
		return decodeTyped(data, &v, validateNativeImageConfirm)
	case shapeNativeImageOperation:
		var v appcontracts.ImageOperationDetailWithResult
		return decodeTyped(data, &v, validateNativeImageOperation)
	case shapeSession:
		var v apiSession
		return decodeTyped(data, &v, validateSession)
	case shapeApps:
		var v apiApps
		return decodeTyped(data, &v, validateApps)
	case shapeCreateApp:
		var v apiCreateApp
		return decodeTyped(data, &v, validateCreateApp)
	case shapeApplication:
		var v apiApplication
		return decodeTyped(data, &v, validateApplication)
	case shapeSourceList:
		var v apiSources
		return decodeTyped(data, &v, validateSources)
	case shapeSource:
		var v apiSource
		return decodeTyped(data, &v, validateSource)
	case shapeDeploymentList:
		var v apiDeployments
		return decodeTyped(data, &v, validateDeployments)
	case shapeCommand:
		var v apiCommand
		return decodeTyped(data, &v, validateCommand)
	case shapeStatus:
		var v apiStatus
		return decodeTyped(data, &v, validateStatus)
	case shapeLogs:
		var v apiLogs
		return decodeTyped(data, &v, validateLogs)
	case shapePublicAccess:
		var v apiPublicAccess
		return decodeTyped(data, &v, validatePublicAccess)
	case shapeHostMetrics:
		var v apiHostMetrics
		return decodeTyped(data, &v, validateHostMetrics)
	case shapeHostMetricsRecent:
		var v apiHostMetricsRecent
		return decodeTyped(data, &v, validateHostMetricsRecent)
	case shapeSourceMetadata:
		var v apiSourceMetadata
		return decodeTyped(data, &v, validateSourceMetadata)
	case shapeDeploymentPlan:
		var v apiDeploymentPlan
		return decodeTyped(data, &v, validateDeploymentPlan)
	case shapeDeliverySource:
		var v apiDeliverySource
		return decodeTyped(data, &v, validateDeliverySource)
	case shapeOperationResult:
		var v apiOperationResult
		return decodeTyped(data, &v, validateOperationResult)
	case shapeSourceUpdate:
		var v apiSourceUpdate
		return decodeTyped(data, &v, validateSourceUpdate)
	case shapeFixCandidate:
		var v apiFixCandidate
		return decodeTyped(data, &v, validateFixCandidate)
	case shapeFixCandidateList:
		var v apiFixCandidates
		return decodeTyped(data, &v, validateFixCandidates)
	}
	return nil, invalidResponse("server response is invalid")
}

// OpenAPI permits these properties to be absent, but not present as null.
// Keep this small and shape-aware because the typed Go zero values cannot
// otherwise distinguish omission from an explicit JSON null.
func optionalNonNullableNull(data []byte, shape responseShape) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return true
	}
	nullField := func(item map[string]json.RawMessage, fields ...string) bool {
		for _, field := range fields {
			if raw, ok := item[field]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return true
			}
		}
		return false
	}
	if shape == shapeImageMetrics {
		return nullField(object, "unavailable_reason", "sampled_at", "process_started_at", "limits")
	}
	if shape == shapeImageMetricsRecent {
		if nullField(object, "history_start", "segment_start", "reason") {
			return true
		}
		var points []map[string]json.RawMessage
		if json.Unmarshal(object["samples"], &points) != nil {
			return true
		}
		for _, point := range points {
			if nullField(point, "process_started_at", "unavailable_reason", "limits") {
				return true
			}
		}
		return false
	}
	if shape == shapeImageObservation || shape == shapeImageLogObservation {
		return nullField(object, "records")
	}
	if shape == shapeManagedImageApps {
		var items []map[string]json.RawMessage
		if json.Unmarshal(object["items"], &items) != nil {
			return true
		}
		for _, item := range items {
			if nullField(item, "deployment_id", "deployment_state", "active_command", "last_command") {
				return true
			}
		}
		return false
	}
	if shape == shapeNativeImageLifecycle {
		return nullField(object, "result")
	}
	if shape == shapeNativeImageDomainOperation {
		return nullField(object, "reason", "result")
	}
	if shape == shapeNativeImageDomainCurrent {
		if nullField(object, "operation") {
			return true
		}
		return optionalNonNullableNull(object["operation"], shapeNativeImageDomainOperation)
	}
	if shape == shapeNativeImageOperation {
		return nullField(object, "reason", "action_required", "result")
	}
	if shape == shapeSourceBuildIntent {
		return nullField(object, "prepare_intent_id", "source_revision_id", "source_digest", "definition_status", "plan_id", "build_id", "artifact_id", "image", "reason", "action_required")
	}
	if shape == shapeSource {
		return nullField(object, "ref", "commit")
	}
	if shape == shapeSourceList {
		raw := object["items"]
		var items []map[string]json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return true
		}
		for _, item := range items {
			if nullField(item, "ref", "commit") {
				return true
			}
		}
		return false
	}
	if shape == shapeSourceMetadata {
		return nullField(object, "repository_url")
	}
	if shape == shapeDeploymentPlan {
		if nullField(object, "selected_port", "source_type") {
			return true
		}
		raw, present := object["port_selection"]
		if !present {
			return false
		}
		var selection map[string]json.RawMessage
		return json.Unmarshal(raw, &selection) != nil || nullField(selection, "selected_port")
	}
	if shape == shapeDeliverySource {
		return nullField(object, "source_revision_id", "commit", "ref", "repository_url")
	}
	if shape == shapeOperationResult {
		if nullField(object, "task_id", "deployment_id", "evidence") {
			return true
		}
		raw, present := object["evidence"]
		if !present {
			return false
		}
		var evidence map[string]json.RawMessage
		return json.Unmarshal(raw, &evidence) != nil || nullField(evidence, "http_status")
	}
	if shape == shapeFixCandidate {
		return nullField(object, "matched_source_revision_id", "matched_commit")
	}
	if shape == shapeHostMetrics || shape == shapeHostMetricsRecent {
		checkItemNulls := func(item map[string]json.RawMessage) bool {
			if nullField(item, "schema_version", "availability", "stale_after_seconds", "observed_at", "cpu", "memory", "disk", "network") {
				return true
			}
			for _, name := range []string{"cpu", "memory", "disk", "network"} {
				raw, ok := item[name]
				if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					continue
				}
				var nested map[string]json.RawMessage
				if json.Unmarshal(raw, &nested) != nil {
					return true
				}
				switch name {
				case "cpu":
					if nullField(nested, "logical_cores", "usage_percent") {
						return true
					}
				case "memory":
					if nullField(nested, "total_bytes", "available_bytes", "used_bytes") {
						return true
					}
				case "disk":
					if nullField(nested, "mountpoint", "total_bytes", "free_bytes", "used_bytes") {
						return true
					}
				case "network":
					if nullField(nested, "interface", "rx_bytes_per_second", "tx_bytes_per_second") {
						return true
					}
				}
			}
			return false
		}
		if shape == shapeHostMetrics {
			return checkItemNulls(object)
		}
		if nullField(object, "schema_version", "availability", "generated_at", "capacity", "retention_seconds", "points") {
			return true
		}
		var points []map[string]json.RawMessage
		if json.Unmarshal(object["points"], &points) != nil {
			return true
		}
		for _, pt := range points {
			if checkItemNulls(pt) {
				return true
			}
		}
		return false
	}
	if shape != shapeStatus {
		return false
	}
	for field, prohibited := range map[string][]string{"desired": {"container_port", "schema_version", "configuration", "config_digest"}, "runtime": {"container_id", "internal_address"}, "response": {"latency_ms", "error_code"}} {
		raw, present := object[field]
		if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) != nil || nullField(nested, prohibited...) {
			return true
		}
	}
	return false
}
func requiredResponseFields(data []byte, shape responseShape) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return false
	}
	keys, nullable := []string{}, map[string]bool{}
	switch shape {
	case shapeImageMetrics:
		keys = []string{"state", "available"}
		var state map[string]json.RawMessage
		if json.Unmarshal(object["state"], &state) != nil || state == nil {
			return false
		}
		for _, field := range []string{"running", "verified_identity", "container_id", "image_id", "manifest_digest", "host_port", "container_port", "endpoint_ready", "observed_at"} {
			if raw, ok := state[field]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return false
			}
		}
		var available bool
		if json.Unmarshal(object["available"], &available) != nil {
			return false
		}
		if available {
			for _, field := range []string{"sampled_at", "process_started_at"} {
				if raw, ok := object[field]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return false
				}
			}
		} else {
			if raw, ok := object["unavailable_reason"]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return false
			}
		}
		if !validMetricLimitsObject(object["limits"]) {
			return false
		}
	case shapeImageMetricsRecent:
		keys = []string{"deployment_id", "container_id", "history_epoch", "current_segment_id", "scheduled", "selection_limited", "stale_after_seconds", "stale", "recording_status", "samples"}
		var points []map[string]json.RawMessage
		if json.Unmarshal(object["samples"], &points) != nil || points == nil {
			return false
		}
		for _, point := range points {
			for _, field := range []string{"segment_id", "container_id", "observed_at", "available"} {
				if raw, ok := point[field]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return false
				}
			}
			var available bool
			if json.Unmarshal(point["available"], &available) != nil {
				return false
			}
			if available {
				if raw, ok := point["process_started_at"]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return false
				}
			} else {
				if raw, ok := point["unavailable_reason"]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return false
				}
			}
			if !validMetricLimitsObject(point["limits"]) {
				return false
			}
		}
	case shapeImageObservation, shapeImageLogObservation:
		keys = []string{"state", "source_limited"}
		var state map[string]json.RawMessage
		if json.Unmarshal(object["state"], &state) != nil || state == nil {
			return false
		}
		for _, field := range []string{"running", "verified_identity", "container_id", "image_id", "manifest_digest", "host_port", "container_port", "endpoint_ready", "observed_at"} {
			if raw, ok := state[field]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return false
			}
		}
		if raw, present := object["records"]; present {
			var records []map[string]json.RawMessage
			if json.Unmarshal(raw, &records) != nil || records == nil {
				return false
			}
			for _, record := range records {
				for _, field := range []string{"stream", "data"} {
					if value, ok := record[field]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
						return false
					}
				}
			}
		}
	case shapeManagedImageApps:
		keys = []string{"items", "truncated"}
		var items []map[string]json.RawMessage
		if json.Unmarshal(object["items"], &items) != nil || items == nil {
			return false
		}
		for _, item := range items {
			for _, field := range []string{"application_id", "name", "environment_id", "plan_id", "plan_digest", "deploy_operation_id", "deploy_state", "updated_at"} {
				if raw, ok := item[field]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return false
				}
			}
			for _, field := range []string{"active_command", "last_command"} {
				if raw, ok := item[field]; ok {
					var command map[string]json.RawMessage
					if json.Unmarshal(raw, &command) != nil || command == nil {
						return false
					}
					for _, required := range []string{"operation_id", "action", "state"} {
						if value, present := command[required]; !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
							return false
						}
					}
				}
			}
		}
	case shapeNativeImageLifecycle:
		keys = []string{"operation_id", "task_id", "deployment_id", "release_id", "application_id", "environment_id", "deploy_operation_id", "plan_id", "plan_digest", "manifest_digest", "container_id", "image_id", "host_port", "container_port", "action", "state", "created_at", "recovery_required"}
		if raw, present := object["result"]; present {
			var result map[string]json.RawMessage
			if json.Unmarshal(raw, &result) != nil || result == nil {
				return false
			}
			for _, field := range []string{"running", "verified_identity", "container_id", "image_id", "manifest_digest", "host_port", "container_port", "endpoint_ready", "observed_at"} {
				value, ok := result[field]
				if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return false
				}
			}
		}
	case shapeNativeImageDomainOperation:
		keys = []string{"operation_id", "task_id", "approval_id", "deployment_id", "hostname", "action", "state", "created_at"}
		if raw, present := object["result"]; present {
			var result map[string]json.RawMessage
			if json.Unmarshal(raw, &result) != nil || result == nil {
				return false
			}
			if value, ok := result["observed_at"]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return false
			}
		}
	case shapeNativeImageDomainCurrent:
		keys = []string{"operation", "desired_public", "local_route_state", "deployment_status", "availability"}
		if !requiredResponseFields(object["operation"], shapeNativeImageDomainOperation) {
			return false
		}

	case shapeNativeImagePlan:
		keys = []string{"id", "admin_id", "app_name", "status", "plan_digest", "canonical_input", "resolved_image", "resolver_provenance", "created_at", "updated_at"}
	case shapeSourceBuildIntent:
		keys = []string{"intent_id", "stage", "state", "application_id", "operation_id"}
	case shapeNativeImageConfirm:
		keys = []string{"application_id", "environment_id", "operation_id", "task_id", "plan_id", "plan_digest", "status", "created_at"}
	case shapeNativeImageOperation:
		keys = []string{"operation_id", "application_id", "environment_id", "operation_type", "state", "plan_id", "plan_digest", "task_id", "created_at", "updated_at"}
	case shapeSourceUpload:
		keys = []string{"id", "kind", "status", "digest", "bytes", "file_count", "expires_at"}
	case shapeSession:
		keys = []string{"authenticated", "idle_expires_at", "absolute_expires_at"}
	case shapeApps:
		keys = []string{"items"}
	case shapeCreateApp:
		keys = []string{"application", "source_revision_id", "operation_id"}
	case shapeApplication:
		keys = []string{"id", "name", "created_at", "updated_at"}
	case shapeSourceList, shapeDeploymentList:
		keys = []string{"items", "next_cursor"}
		nullable["next_cursor"] = true
	case shapeSource:
		keys = []string{"id", "application_id", "kind", "locator_sha256", "content_digest", "created_at", "immutable"}
	case shapeCommand:
		keys = []string{"deployment_id", "operation_id", "task_id", "status"}
	case shapeStatus:
		keys = []string{"deployment", "desired", "runtime", "response"}
		nullable["desired"] = true
		nullable["runtime"] = true
		nullable["response"] = true
	case shapeLogs:
		keys = []string{"source", "availability", "items", "next_cursor", "retention_limited"}
		nullable["next_cursor"] = true
	case shapePublicAccess:
		keys = []string{"desired_public", "url", "endpoint", "components", "status"}
	case shapeHostMetrics:
		keys = []string{"schema_version", "availability", "stale_after_seconds"}
		if !checkHostMetricsFieldPresence(object) {
			return false
		}
	case shapeHostMetricsRecent:
		keys = []string{"schema_version", "availability", "generated_at", "capacity", "retention_seconds", "points"}
		var points []map[string]json.RawMessage
		if json.Unmarshal(object["points"], &points) != nil {
			return false
		}
		for _, pt := range points {
			if !checkHostMetricsFieldPresence(pt) {
				return false
			}
		}
	case shapeSourceMetadata:
		keys = []string{"source_revision_id", "availability"}
	case shapeDeploymentPlan:
		keys = []string{"application_id", "source_revision_id", "repository_url", "ref", "commit", "dockerfile", "ports", "port_selection", "healthcheck", "environment", "gaps", "warnings", "required_actions", "ready_to_deploy"}
	case shapeDeliverySource:
		keys = []string{"deployment_id", "availability"}
	case shapeOperationResult:
		keys = []string{"operation_id", "operation_type", "status", "accepted_at", "updated_at"}
	case shapeSourceUpdate:
		keys = []string{"source_revision_id", "status"}
	case shapeFixCandidate:
		var status string
		_ = json.Unmarshal(object["status"], &status)
		if status == "preparing" || status == "failed" {
			keys = []string{"candidate_id", "application_id", "base_source_revision_id", "status", "created_at"}
			if len(object) != len(keys) {
				return false
			}
		} else {
			keys = []string{"candidate_id", "application_id", "base_source_revision_id", "base_repository_url", "base_commit", "base_tree_digest", "patch_digest", "result_tree_digest", "container_port", "changed_paths", "canonical_diff", "validated_image", "build_log_ref", "build_evidence_digest", "runtime", "status", "created_at", "expires_at"}
		}
	case shapeFixCandidateList:
		keys = []string{"items"}
		var items []json.RawMessage
		if json.Unmarshal(object["items"], &items) != nil || len(items) > 50 {
			return false
		}
		for _, item := range items {
			if !requiredResponseFields(item, shapeFixCandidate) {
				return false
			}
		}
	}
	for _, key := range keys {
		raw, ok := object[key]
		if !ok || (!nullable[key] && bytes.Equal(bytes.TrimSpace(raw), []byte("null"))) {
			return false
		}
	}
	return true
}
func decodeTyped[T any](data []byte, value *T, validate func(*T) bool) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validate(value) {
		return nil, invalidResponse("server response does not match the AcornFox API contract")
	}
	return *value, nil
}
func nonempty(values ...string) bool {
	for _, value := range values {
		if value == "" {
			return false
		}
	}
	return true
}
func validTime(value time.Time) bool { return !value.IsZero() }
func validateSession(v *apiSession) bool {
	return v.Authenticated != nil && validTime(v.IdleExpiresAt) && validTime(v.AbsoluteExpiresAt)
}
func validateApplication(v *apiApplication) bool {
	return nonempty(v.ID, v.Name) && validTime(v.CreatedAt) && validTime(v.UpdatedAt)
}
func validateApps(v *apiApps) bool {
	for i := range v.Items {
		if !validateApplication(&v.Items[i]) {
			return false
		}
	}
	return true
}
func validateCreateApp(v *apiCreateApp) bool {
	return validateApplication(&v.Application) && nonempty(v.SourceRevisionID, v.OperationID)
}
func validateSource(v *apiSource) bool {
	return v.Immutable != nil && (v.Kind == "git_https" || (v.Kind == "upload" && v.Commit == "")) && nonempty(v.ID, v.ApplicationID, v.LocatorSHA256, v.ContentDigest) && validTime(v.CreatedAt)
}
func validateSources(v *apiSources) bool {
	for i := range v.Items {
		if !validateSource(&v.Items[i]) {
			return false
		}
	}
	return true
}
func validateDeployment(v *apiDeployment) bool {
	if !nonempty(v.ID, v.ApplicationID, v.EnvironmentID, v.ReleaseID) || !validTime(v.CreatedAt) || !validTime(v.UpdatedAt) {
		return false
	}
	return v.Stage == "starting" || v.Stage == "runtime_observed" || v.Stage == "failed" || v.Stage == "unknown"
}
func validateDeployments(v *apiDeployments) bool {
	for i := range v.Items {
		if !validateDeployment(&v.Items[i]) {
			return false
		}
	}
	return true
}
func validateCommand(v *apiCommand) bool {
	return nonempty(v.DeploymentID, v.OperationID, v.TaskID) && v.Status == "accepted"
}
func validateResources(v apiResources) bool {
	return v.CPUMillis != nil && v.MemoryBytes != nil && v.Pids != nil && v.DiskReservationBytes != nil && *v.CPUMillis >= 0 && *v.MemoryBytes >= 0 && *v.Pids >= 0 && *v.DiskReservationBytes >= 0
}
func validateRelease(v *apiRelease) bool {
	if v.SchemaVersion != nil || v.Configuration != nil || v.ConfigDigest != nil {
		if v.SchemaVersion == nil || *v.SchemaVersion != 2 || v.Configuration == nil || v.ConfigDigest == nil || !validateResources(v.Resources) || len(v.Configuration.Secrets) > 0 {
			return false
		}
		port := 0
		if v.ContainerPort != nil {
			port = *v.ContainerPort
		}
		digest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(*v.Configuration, contracts.AcornFoxRuntimeRequestedResources{CPUMillis: *v.Resources.CPUMillis, MemoryBytes: *v.Resources.MemoryBytes, PIDs: *v.Resources.Pids, DiskReservationBytes: *v.Resources.DiskReservationBytes}, port)
		if err != nil || digest != *v.ConfigDigest {
			return false
		}
	}
	return v.Immutable != nil && nonempty(v.ApplicationID, v.EnvironmentID, v.ReleaseID, v.ServiceName, v.Image.Repository, v.Image.Digest) && validateResources(v.Resources) && validTime(v.AcceptedAt) && (v.ContainerPort == nil || (*v.ContainerPort >= 0 && *v.ContainerPort <= 65535))
}
func validateRuntime(v *apiRuntime) bool {
	return v.RestartCount != nil && v.AppliedLimits.CPUMillis != nil && v.AppliedLimits.MemoryBytes != nil && v.AppliedLimits.Pids != nil && v.Disk.ReservationBytes != nil && v.Disk.AccountingReconciled != nil && v.Disk.PerContainerEnforced != nil && nonempty(v.DeploymentID, v.ServiceName, v.RuntimeState) && *v.RestartCount >= 0 && validateResources(v.RequestedResources) && *v.AppliedLimits.CPUMillis >= 0 && *v.AppliedLimits.MemoryBytes >= 0 && *v.AppliedLimits.Pids >= 0 && *v.Disk.ReservationBytes >= 0 && validTime(v.ObservedAt)
}
func validateProbe(v *apiProbe) bool {
	if !(v.Protocol == "tcp" || v.Protocol == "http") || !nonempty(v.Outcome, v.FactDigest) || !validTime(v.ObservedAt) {
		return false
	}
	if v.HTTPStatus != nil && (*v.HTTPStatus < 100 || *v.HTTPStatus > 599) {
		return false
	}
	return v.LatencyMS == nil || *v.LatencyMS >= 0
}
func validateStatus(v *apiStatus) bool {
	return validateDeployment(&v.Deployment) && (v.Desired == nil || validateRelease(v.Desired)) && (v.Runtime == nil || validateRuntime(v.Runtime)) && (v.Response == nil || validateProbe(v.Response))
}
func validateLogs(v *apiLogs) bool {
	if (v.Source != "build" && v.Source != "runtime") || (v.Availability != "available" && v.Availability != "not_collected" && v.Availability != "retired") {
		return false
	}
	for _, item := range v.Items {
		if item.Content == nil || !(item.Stream == "stdout" || item.Stream == "stderr" || item.Stream == "combined" || item.Stream == "unknown") || !(item.Truncation == "complete" || item.Truncation == "source_limited" || item.Truncation == "response_limited" || item.Truncation == "unknown") || !validTime(item.RecordedAt) {
			return false
		}
	}
	return v.RetentionLimited != nil
}
func validatePublicAccess(v *apiPublicAccess) bool {
	parsed, err := url.Parse(v.URL)
	if err != nil || v.DesiredPublic == nil || parsed.Scheme != "https" || parsed.Host == "" || v.Endpoint.DeploymentID == "" || !(v.Status == "PUBLIC_DISABLED" || v.Status == "PENDING_EXTERNAL_VALIDATION") {
		return false
	}
	return (v.Components.InternalEndpoint == "accepted" || v.Components.InternalEndpoint == "not_observed") && (v.Components.LocalRoute == "desired" || v.Components.LocalRoute == "reconcile_required" || v.Components.LocalRoute == "configured" || v.Components.LocalRoute == "disabled") && v.Components.DNS == "not_validated" && v.Components.TLS == "not_validated" && v.Components.External == "not_validated"
}
func validateSourceMetadata(v *apiSourceMetadata) bool {
	if !nonempty(v.SourceRevisionID) || !(v.Availability == "available" || v.Availability == "unavailable") {
		return false
	}
	if v.Availability == "unavailable" {
		return v.RepositoryURL == nil
	}
	if v.RepositoryURL == nil {
		return true
	}
	parsed, err := url.Parse(*v.RepositoryURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}
func validateDeploymentPlan(v *apiDeploymentPlan) bool {
	if !nonempty(v.ApplicationID, v.SourceRevisionID, v.Dockerfile.Path) || (!validCLIHash(v.Dockerfile.Digest) && v.Dockerfile.Digest != "") {
		return false
	}
	if v.SourceType == nil {
		parsed, err := url.Parse(v.RepositoryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || !nonempty(v.Ref, v.Commit) {
			return false
		}
	} else if *v.SourceType != "upload" || v.RepositoryURL != "" || v.Commit != "" {
		return false
	}
	if v.Dockerfile.Status != "ready" && v.Dockerfile.Status != "waiting_later" && v.Dockerfile.Status != "unsupported" {
		return false
	}
	if v.PortSelection.Status != "selected" && v.PortSelection.Status != "required" && v.PortSelection.Status != "unavailable" {
		return false
	}
	if v.PortSelection.Status == "selected" {
		if v.PortSelection.SelectedPort == nil || *v.PortSelection.SelectedPort < 1 || *v.PortSelection.SelectedPort > 65535 {
			return false
		}
	} else if v.PortSelection.SelectedPort != nil {
		return false
	}
	for _, port := range v.Ports {
		if port.Port < 1 || port.Port > 65535 || (port.Protocol != "tcp" && port.Protocol != "udp") || port.Source != "dockerfile_expose" {
			return false
		}
	}
	for _, item := range v.Environment {
		if !nonempty(item.Name) || item.Redacted && item.Value != "" {
			return false
		}
	}
	return v.ReadyToDeploy == (v.Dockerfile.Status == "ready" && v.PortSelection.Status == "selected")
}
func validateDeliverySource(v *apiDeliverySource) bool {
	if !nonempty(v.DeploymentID) || !(v.Availability == "available" || v.Availability == "unavailable") {
		return false
	}
	if v.Availability == "unavailable" {
		return v.SourceRevisionID == nil && v.Commit == nil && v.Ref == nil && v.RepositoryURL == nil
	}
	if v.RepositoryURL != nil {
		parsed, err := url.Parse(*v.RepositoryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return false
		}
	}
	return true
}
func checkHostMetricsFieldPresence(item map[string]json.RawMessage) bool {
	if _, ok := item["schema_version"]; !ok {
		return false
	}
	availRaw, ok := item["availability"]
	if !ok {
		return false
	}
	var avail string
	if json.Unmarshal(availRaw, &avail) != nil {
		return false
	}
	if _, ok := item["stale_after_seconds"]; !ok {
		return false
	}

	if avail == "unavailable" || avail == "unsupported" {
		if _, has := item["cpu"]; has {
			return false
		}
		if _, has := item["memory"]; has {
			return false
		}
		if _, has := item["disk"]; has {
			return false
		}
		if _, has := item["network"]; has {
			return false
		}
		return true
	}

	if avail == "warming_up" {
		_, hasObs := item["observed_at"]
		_, hasCPU := item["cpu"]
		_, hasMem := item["memory"]
		_, hasDisk := item["disk"]
		_, hasNet := item["network"]
		if !hasObs && !hasCPU && !hasMem && !hasDisk && !hasNet {
			return true
		}
		if !hasObs || !hasCPU || !hasMem || !hasDisk {
			return false
		}
	}

	if avail == "available" {
		if _, has := item["observed_at"]; !has {
			return false
		}
		if _, has := item["cpu"]; !has {
			return false
		}
		if _, has := item["memory"]; !has {
			return false
		}
		if _, has := item["disk"]; !has {
			return false
		}
	}

	if raw, has := item["cpu"]; has {
		var cpuMap map[string]json.RawMessage
		if json.Unmarshal(raw, &cpuMap) != nil || cpuMap["logical_cores"] == nil {
			return false
		}
		if avail == "available" && cpuMap["usage_percent"] == nil {
			return false
		}
	}
	if raw, has := item["memory"]; has {
		var memMap map[string]json.RawMessage
		if json.Unmarshal(raw, &memMap) != nil || memMap["total_bytes"] == nil || memMap["available_bytes"] == nil || memMap["used_bytes"] == nil {
			return false
		}
	}
	if raw, has := item["disk"]; has {
		var diskMap map[string]json.RawMessage
		if json.Unmarshal(raw, &diskMap) != nil || diskMap["mountpoint"] == nil || diskMap["total_bytes"] == nil || diskMap["free_bytes"] == nil || diskMap["used_bytes"] == nil {
			return false
		}
	}
	if raw, has := item["network"]; has {
		var netMap map[string]json.RawMessage
		if json.Unmarshal(raw, &netMap) != nil || netMap["interface"] == nil {
			return false
		}
	}
	return true
}

func validateHostMetrics(v *apiHostMetrics) bool {
	if v.SchemaVersion != 1 || v.StaleAfterSeconds < 1 || !(v.Availability == "available" || v.Availability == "warming_up" || v.Availability == "unavailable" || v.Availability == "unsupported") {
		return false
	}
	if v.Availability == "unavailable" || v.Availability == "unsupported" {
		return v.CPU == nil && v.Memory == nil && v.Disk == nil && v.Network == nil
	}
	if v.Availability == "warming_up" {
		if v.ObservedAt == nil && v.CPU == nil && v.Memory == nil && v.Disk == nil && v.Network == nil {
			return true
		}
		if !validTimePointer(v.ObservedAt) || v.CPU == nil || v.Memory == nil || v.Disk == nil {
			return false
		}
		if v.CPU.LogicalCores < 1 || (v.CPU.UsagePercent != nil && (*v.CPU.UsagePercent < 0 || *v.CPU.UsagePercent > 100)) {
			return false
		}
		if v.Memory.TotalBytes <= 0 || v.Memory.AvailableBytes < 0 || v.Memory.UsedBytes < 0 || v.Memory.AvailableBytes > v.Memory.TotalBytes || v.Memory.UsedBytes > v.Memory.TotalBytes {
			return false
		}
		if v.Disk.Mountpoint != "/" || v.Disk.TotalBytes <= 0 || v.Disk.FreeBytes < 0 || v.Disk.UsedBytes < 0 || v.Disk.FreeBytes > v.Disk.TotalBytes || v.Disk.UsedBytes > v.Disk.TotalBytes {
			return false
		}
		if v.Network != nil && (!nonempty(v.Network.Interface) || len(v.Network.Interface) > 15 || (v.Network.RXBytesPerSecond != nil && *v.Network.RXBytesPerSecond < 0) || (v.Network.TXBytesPerSecond != nil && *v.Network.TXBytesPerSecond < 0)) {
			return false
		}
		return true
	}
	// Available requires strictly valid complete metrics
	if !validTimePointer(v.ObservedAt) || v.CPU == nil || v.Memory == nil || v.Disk == nil {
		return false
	}
	if v.CPU.LogicalCores < 1 || v.CPU.UsagePercent == nil || *v.CPU.UsagePercent < 0 || *v.CPU.UsagePercent > 100 {
		return false
	}
	if v.Memory.TotalBytes <= 0 || v.Memory.AvailableBytes < 0 || v.Memory.UsedBytes < 0 || v.Memory.AvailableBytes > v.Memory.TotalBytes || v.Memory.UsedBytes > v.Memory.TotalBytes {
		return false
	}
	if v.Disk.Mountpoint != "/" || v.Disk.TotalBytes <= 0 || v.Disk.FreeBytes < 0 || v.Disk.UsedBytes < 0 || v.Disk.FreeBytes > v.Disk.TotalBytes || v.Disk.UsedBytes > v.Disk.TotalBytes {
		return false
	}
	if v.Network != nil && (!nonempty(v.Network.Interface) || len(v.Network.Interface) > 15 || (v.Network.RXBytesPerSecond != nil && *v.Network.RXBytesPerSecond < 0) || (v.Network.TXBytesPerSecond != nil && *v.Network.TXBytesPerSecond < 0)) {
		return false
	}
	return true
}

func validateHostMetricsRecent(v *apiHostMetricsRecent) bool {
	if v.SchemaVersion != 1 || v.Capacity != 360 || v.RetentionSeconds != 1800 || !validTime(v.GeneratedAt) {
		return false
	}
	if !(v.Availability == "available" || v.Availability == "warming_up" || v.Availability == "unavailable" || v.Availability == "unsupported") {
		return false
	}
	if v.Points == nil || len(v.Points) > 360 {
		return false
	}
	minValidTime := v.GeneratedAt.Add(-30 * time.Minute).Add(-5 * time.Second)
	maxValidTime := v.GeneratedAt.Add(2 * time.Second)

	var lastTime *time.Time
	for i := range v.Points {
		pt := &v.Points[i]
		if !validateHostMetrics(pt) {
			return false
		}
		if pt.ObservedAt == nil || !validTime(*pt.ObservedAt) {
			return false
		}
		if pt.ObservedAt.Before(minValidTime) || pt.ObservedAt.After(maxValidTime) {
			return false
		}
		if lastTime != nil && pt.ObservedAt.Before(*lastTime) {
			return false
		}
		lastTime = pt.ObservedAt
	}
	return true
}
func validateOperationResult(v *apiOperationResult) bool {
	if !nonempty(v.OperationID, v.OperationType) || !validTime(v.AcceptedAt) || !validTime(v.UpdatedAt) || v.UpdatedAt.Before(v.AcceptedAt) {
		return false
	}
	if v.TaskID != nil && *v.TaskID == "" || v.DeploymentID != nil && *v.DeploymentID == "" {
		return false
	}
	switch v.Status {
	case "accepted", "running", "failed", "unknown":
		return v.Evidence == nil
	case "verified":
		return v.Evidence != nil && validateOperationEvidence(v.Evidence)
	default:
		return false
	}
}
func validateOperationEvidence(v *apiOperationEvidence) bool {
	if v == nil || !validTime(v.ObservedAt) {
		return false
	}
	switch v.Kind {
	case "runtime_observation":
		return v.Verdict == "observed" && v.HTTPStatus == nil
	case "response_observation":
		return (v.Verdict == "observed" || v.Verdict == "unhealthy") && (v.HTTPStatus == nil || (*v.HTTPStatus >= 100 && *v.HTTPStatus <= 599))
	default:
		return false
	}
}
func validateSourceUpdate(v *apiSourceUpdate) bool {
	return nonempty(v.SourceRevisionID) && v.Status == "imported"
}
func validateFixCandidate(v *apiFixCandidate) bool {
	if !validCandidateCLIIdentity(v.CandidateID) || !nonempty(v.ApplicationID, v.BaseSourceRevisionID) || !validTime(v.CreatedAt) {
		return false
	}
	if v.Status == "preparing" || v.Status == "failed" {
		return v.BaseRepositoryURL == "" && v.BaseCommit == "" && v.BaseTreeDigest == "" && v.PatchDigest == "" && v.ResultTreeDigest == "" && v.ContainerPort == 0 && len(v.ChangedPaths) == 0 && v.CanonicalDiff == "" && v.ValidatedImage == (apiImage{}) && v.BuildLogRef == "" && v.BuildEvidenceDigest == "" && v.Runtime == (apiFixCandidateRuntime{}) && v.MatchedSourceRevisionID == nil && v.MatchedCommit == nil && v.ExpiresAt.IsZero()
	}
	if !nonempty(v.BaseRepositoryURL, v.BaseCommit, v.CanonicalDiff, v.BuildLogRef, v.Runtime.TaskID) || v.ContainerPort < 1 || v.ContainerPort > 65535 || len(v.ChangedPaths) < 1 || len(v.ChangedPaths) > 32 || !v.ExpiresAt.After(v.CreatedAt) {
		return false
	}
	parsed, err := url.Parse(v.BaseRepositoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || !validCLIHash(v.BaseTreeDigest) || !validCLIHash(v.PatchDigest) || !validCLIHash(v.ResultTreeDigest) || !validCLIHash(v.BuildEvidenceDigest) || !validCLIHash(v.Runtime.EvidenceDigest) || !validCLIHash(v.ValidatedImage.Digest) || v.Runtime.Image != v.ValidatedImage || v.Runtime.RuntimeState != "stopped" || v.Runtime.ProbeOutcome != "responded" || v.Runtime.CleanupConfirmed == nil || !*v.Runtime.CleanupConfirmed {
		return false
	}
	seen := map[string]bool{}
	for _, path := range v.ChangedPaths {
		if path == "" || seen[path] {
			return false
		}
		seen[path] = true
	}
	if v.Status == "validated" {
		return v.MatchedSourceRevisionID == nil && v.MatchedCommit == nil
	}
	return v.Status == "source_matched" && v.MatchedSourceRevisionID != nil && *v.MatchedSourceRevisionID != "" && v.MatchedCommit != nil && *v.MatchedCommit != ""
}
func validateFixCandidates(v *apiFixCandidates) bool {
	if v.Items == nil || len(v.Items) > 50 {
		return false
	}
	for index := range v.Items {
		if !validateFixCandidate(&v.Items[index]) {
			return false
		}
	}
	return true
}
func validCandidateCLIIdentity(value string) bool {
	if len(value) != len("candidate_")+32 || !strings.HasPrefix(value, "candidate_") {
		return false
	}
	for _, character := range value[len("candidate_"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
func validCLIHash(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
func validTimePointer(value *time.Time) bool { return value != nil && validTime(*value) }

func validImageDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
func validateNativeImageConfirm(v *appcontracts.ConfirmImagePlanResult) bool {
	return nonempty(v.ApplicationID.String(), v.EnvironmentID.String(), v.OperationID.String(), v.TaskID.String(), v.PlanID.String()) &&
		validImageDigest(v.PlanDigest) && v.Status == "pending" && validTime(v.CreatedAt)
}
func validateNativeImageOperation(v *appcontracts.ImageOperationDetailWithResult) bool {
	if !nonempty(v.OperationID.String(), v.ApplicationID.String(), v.EnvironmentID.String(), v.PlanID.String(), v.TaskID.String()) ||
		v.OperationType != "deploy_image" || !validImageDigest(v.PlanDigest) || !validTime(v.CreatedAt) || !validTime(v.UpdatedAt) {
		return false
	}
	switch v.State {
	case "pending", "leased", "running", "unknown", "cancelling", "succeeded", "failed", "cancelled", "rolling_back", "rolled_back":
	default:
		return false
	}
	if (v.Reason != "" || v.ActionRequired) && v.State != "failed" && v.State != "unknown" {
		return false
	}
	if r := v.Result; r != nil {
		if r.DeploymentID.Empty() || r.ReleaseID.Empty() {
			return false
		}
		switch r.Status {
		case "deploying", "running", "failed", "stopped":
		default:
			return false
		}
		if r.HostPort < 0 || r.HostPort > 65535 || r.ContainerPort < 0 || r.ContainerPort > 65535 {
			return false
		}
		if r.Endpoint != "" {
			// Native image endpoints are addresses on the server machine.
			if r.Status != "running" || r.HostPort == 0 || r.HostIP != "127.0.0.1" || r.Endpoint != "http://127.0.0.1:"+strconv.Itoa(r.HostPort) {
				return false
			}
		}
	}
	return true
}

func validateNativeImagePlan(p *appcontracts.ImagePlan) bool {
	if appcontracts.ValidatePlanConsistency(*p) != nil || !validTime(p.CreatedAt) || !validTime(p.UpdatedAt) {
		return false
	}
	for _, env := range p.CanonicalInput.Environment {
		// Apply the same non-secret environment contract as the Native plan service.
		variable := contracts.RuntimeEnvironmentVariable{Name: env.Name, Value: env.Value, Kind: contracts.RuntimeEnvironmentKind(env.Kind)}
		if variable.Kind != contracts.RuntimeEnvironmentLiteral || variable.Validate() != nil {
			return false
		}
	}
	return true
}

func validateSourceBuildIntent(v *appcontracts.SourceBuildPublicIntent) bool {
	if !nonempty(v.IntentID.String(), v.ApplicationID.String(), v.OperationID.String()) {
		return false
	}
	switch v.Stage {
	case appcontracts.SourceBuildPrepare:
		if v.State != "pending" && v.State != "running" && v.State != "waiting" && v.State != "prepared" && v.State != "failed" {
			return false
		}
		if !v.PrepareIntentID.Empty() || !v.PlanID.Empty() || !v.BuildID.Empty() || !v.ArtifactID.Empty() || v.Image != nil {
			return false
		}
		if v.State == "prepared" && (v.SourceRevisionID.Empty() || !validImageDigest(v.SourceDigest)) {
			return false
		}
	case appcontracts.SourceBuildBuild:
		if v.State != "pending" && v.State != "running" && v.State != "waiting" && v.State != "succeeded" && v.State != "failed" {
			return false
		}
		if v.PrepareIntentID.Empty() || v.SourceRevisionID.Empty() || !validImageDigest(v.SourceDigest) || v.PlanID.Empty() || v.BuildID.Empty() {
			return false
		}
		if v.State == "succeeded" {
			if v.ArtifactID.Empty() || v.Image == nil || v.Image.Validate() != nil {
				return false
			}
		} else if !v.ArtifactID.Empty() || v.Image != nil {
			return false
		}
	default:
		return false
	}
	if v.DefinitionStatus != "" && v.DefinitionStatus != string(contracts.AcornFoxDockerfileReady) && v.DefinitionStatus != string(contracts.AcornFoxDockerfileWaitingLater) && v.DefinitionStatus != string(contracts.AcornFoxDockerfileUnsupported) {
		return false
	}
	if v.SourceDigest != "" && !validImageDigest(v.SourceDigest) {
		return false
	}
	if v.ActionRequired && v.Reason == "" && !(v.Stage == appcontracts.SourceBuildPrepare && v.State == "prepared" && v.DefinitionStatus != "ready") {
		return false
	}
	if v.Reason != "" && !v.ActionRequired {
		return false
	}
	return true
}

func validateNativeImageLifecycle(v *appcontracts.ImageLifecycleOperation) bool {
	if !nonempty(v.OperationID.String(), v.TaskID.String(), v.DeploymentID.String(), v.ReleaseID.String(), v.ApplicationID.String(), v.EnvironmentID.String(), v.DeployOperationID.String(), v.PlanID.String(), v.ContainerID) || v.OperationID == v.DeployOperationID || !validImageDigest(v.PlanDigest) || !validImageDigest(v.ManifestDigest) || !validImageDigest(v.ImageID) || !validTime(v.CreatedAt) || v.HostPort <= 0 || v.HostPort > 65535 || v.ContainerPort <= 0 || v.ContainerPort > 65535 {
		return false
	}
	switch v.Action {
	case appcontracts.ImageLifecycleStop, appcontracts.ImageLifecycleStart, appcontracts.ImageLifecycleRestart:
	default:
		return false
	}
	switch v.State {
	case "pending", "running", "succeeded", "failed", "cancelled":
		if v.RecoveryRequired {
			return false
		}
	case "unknown":
		if !v.RecoveryRequired {
			return false
		}
	default:
		return false
	}
	if v.State != "succeeded" {
		return v.Result == nil
	}
	r := v.Result
	if r == nil || !r.VerifiedIdentity || r.ContainerID != v.ContainerID || r.ImageID != v.ImageID || r.ManifestDigest != v.ManifestDigest || !validTime(r.ObservedAt) || r.ObservedAt.Before(v.CreatedAt) {
		return false
	}
	if v.Action == appcontracts.ImageLifecycleStop {
		return !r.Running && !r.EndpointReady && (r.HostPort == 0 || r.HostPort == v.HostPort) && (r.ContainerPort == 0 || r.ContainerPort == v.ContainerPort)
	}
	return r.Running && r.EndpointReady && r.HostPort == v.HostPort && r.ContainerPort == v.ContainerPort
}

func validateNativeImageDomainOperation(v *appcontracts.ImagePublicAccessOperation) bool {
	if !nonempty(v.OperationID.String(), v.TaskID.String(), v.ApprovalID.String(), v.DeploymentID.String()) || appcontracts.ValidateImagePublicHostname(v.Hostname) != nil || !validTime(v.CreatedAt) {
		return false
	}
	if v.Action != appcontracts.ImagePublicAccessEnsure && v.Action != appcontracts.ImagePublicAccessRemove {
		return false
	}
	switch v.State {
	case "pending", "running":
		return v.Reason == "" && v.Result == nil
	case "unknown":
		return v.Reason == "local route outcome requires reconciliation" && v.Result == nil
	case "failed":
		return v.Reason == "local route command failed" && v.Result == nil
	case "succeeded":
		return v.Reason == "" && v.Result != nil && validTime(v.Result.ObservedAt) && !v.Result.ObservedAt.Before(v.CreatedAt) && (v.Result.CertificateFingerprint == "" && v.Result.CertificateExpiresAt == nil || validImageDigest(v.Result.CertificateFingerprint) && validTimePointer(v.Result.CertificateExpiresAt) && v.Result.CertificateExpiresAt.After(v.Result.ObservedAt))
	default:
		return false
	}
}

func validateNativeImageDomainCurrent(v *appcontracts.ImagePublicAccessCurrent) bool {
	if !validateNativeImageDomainOperation(&v.Operation) {
		return false
	}
	switch v.DeploymentStatus {
	case "running", "stopped", "deploying", "failed":
	default:
		return false
	}
	switch v.LocalRouteState {
	case "desired", "configured", "disabled", "reconcile_required":
	default:
		return false
	}
	expected := "pending"
	if v.LocalRouteState == "disabled" {
		expected = "disabled"
	} else if v.DeploymentStatus != "running" || v.LocalRouteState == "reconcile_required" || v.Operation.State == "unknown" || v.Operation.State == "failed" {
		expected = "degraded"
	} else if v.DesiredPublic && v.LocalRouteState == "configured" && v.Operation.State == "succeeded" {
		expected = "unverified"
	}
	return v.Availability == expected
}

func validateManagedImageApps(list *appcontracts.ManagedImageApplicationList) bool {
	if list.Items == nil || len(list.Items) > 100 {
		return false
	}
	seen := map[domain.ID]bool{}
	validState := func(state string) bool {
		switch state {
		case "pending", "running", "unknown", "succeeded", "failed", "cancelled":
			return true
		}
		return false
	}
	for _, item := range list.Items {
		if seen[item.ApplicationID] || item.Name == "" || !validTime(item.UpdatedAt) || !validImageDigest(item.PlanDigest) || !validState(item.DeployState) {
			return false
		}
		seen[item.ApplicationID] = true
		for _, id := range []domain.ID{item.ApplicationID, item.EnvironmentID, item.PlanID, item.DeployOperationID} {
			if _, err := requireID(id.String(), "image identity"); err != nil {
				return false
			}
		}
		if item.DeploymentID.Empty() != (item.DeploymentState == "") {
			return false
		}
		if !item.DeploymentID.Empty() {
			if _, err := requireID(item.DeploymentID.String(), "deployment identity"); err != nil {
				return false
			}
			switch item.DeploymentState {
			case "deploying", "running", "failed", "stopped":
			default:
				return false
			}
		}
		for _, command := range []*appcontracts.ManagedImageCommandSummary{item.ActiveCommand, item.LastCommand} {
			if command == nil {
				continue
			}
			if item.DeploymentID.Empty() || command.OperationID == item.DeployOperationID || !validState(command.State) {
				return false
			}
			if _, err := requireID(command.OperationID.String(), "command identity"); err != nil {
				return false
			}
			switch command.Action {
			case appcontracts.ImageLifecycleStop, appcontracts.ImageLifecycleStart, appcontracts.ImageLifecycleRestart:
			default:
				return false
			}
		}
		if c := item.ActiveCommand; c != nil && c.State != "pending" && c.State != "running" && c.State != "unknown" {
			return false
		}
	}
	return true
}

func validateImageObservation(v *appcontracts.ImageObservationResult) bool {
	// Core/role enforce host-local sample freshness. The CLI checks a well-formed,
	// nonzero timestamp without assuming its clock exactly matches the server.
	if !validTime(v.State.ObservedAt) || v.Validate(v.State.ObservedAt) != nil || !validImageDigest(v.State.ImageID) || !validImageDigest(v.State.ManifestDigest) {
		return false
	}
	_, err := requireID(v.State.ContainerID, "container identity")
	return err == nil
}

func validMetricLimitsObject(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return false
	}
	for _, field := range []string{"cpu_millis", "memory_bytes", "pids"} {
		if value, ok := object[field]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
func validMetricValue(percent *float64, usage *uint64, rx, tx *uint64, limits *appcontracts.ImageMetricLimits) bool {
	if percent != nil && (usage == nil || math.IsNaN(*percent) || math.IsInf(*percent, 0) || *percent < 0) {
		return false
	}
	if (rx == nil) != (tx == nil) {
		return false
	}
	return limits == nil || (limits.CPUMillis >= 0 && limits.MemoryBytes >= 0 && limits.PIDs >= 0)
}
func validateImageMetrics(v *appcontracts.ImageMetricsResult) bool {
	if !validTime(v.State.ObservedAt) || !validImageDigest(v.State.ImageID) || !validImageDigest(v.State.ManifestDigest) {
		return false
	}
	if _, err := requireID(v.State.ContainerID, "container identity"); err != nil {
		return false
	}
	// Server validates the ten-second sample window on its own clock. Use the
	// observation/sample time for structural validation across small host skew.
	at := v.State.ObservedAt
	if v.SampledAt.After(at) {
		at = v.SampledAt
	}
	now := time.Now().UTC()
	if at.Before(now.Add(-20*time.Second)) || at.After(now.Add(2*time.Minute)) {
		return false
	}
	return v.Validate(at) == nil && (v.Available || v.MemoryLimitBytes == nil) && validMetricValue(v.CPUPercent, v.CPUUsageMillis, v.NetworkRxBytes, v.NetworkTxBytes, v.Limits)
}
func validateImageMetricsRecent(v *appcontracts.ImageMetricsRecentResult) bool {
	if v.DeploymentID.Empty() || v.ContainerID == "" || !validTime(v.HistoryEpoch) || v.Samples == nil || len(v.Samples) > appcontracts.ImageMetricsHistorySamples {
		return false
	}
	if _, err := requireID(v.DeploymentID.String(), "deployment identity"); err != nil {
		return false
	}
	if _, err := requireID(v.ContainerID, "container identity"); err != nil {
		return false
	}
	now := time.Now().UTC()
	if v.HistoryEpoch.After(now.Add(2*time.Minute)) || (v.StaleAfterSeconds != 30 && (v.StaleAfterSeconds < 40 || v.StaleAfterSeconds > 250 || (v.StaleAfterSeconds-40)%15 != 0)) {
		return false
	}
	if (v.HistoryStart == nil) != (len(v.Samples) == 0) || (v.SegmentStart == nil) != (len(v.Samples) == 0) {
		return false
	}
	if v.HistoryStart != nil && (!validTime(*v.HistoryStart) || v.HistoryStart.Before(v.HistoryEpoch)) {
		return false
	}
	if v.SegmentStart != nil && (!validTime(*v.SegmentStart) || v.SegmentStart.Before(v.HistoryEpoch)) {
		return false
	}
	if len(v.Samples) == 0 {
		if v.CurrentSegmentID != 0 || !v.Stale {
			return false
		}
		switch v.RecordingStatus {
		case "not_selected":
			return !v.Scheduled && v.Reason == "outside_sampling_selection"
		case "warming_up":
			return v.Scheduled && (v.Reason == "first_sample_pending" || v.Reason == "read_failed")
		case "stale":
			return v.Scheduled && (v.Reason == "sample_expired" || v.Reason == "read_failed")
		default:
			return false
		}
	}
	if !v.Scheduled || v.CurrentSegmentID == 0 || v.CurrentSegmentID != v.Samples[len(v.Samples)-1].SegmentID || v.HistoryStart.After(v.Samples[0].ObservedAt) || v.SegmentStart.After(v.Samples[len(v.Samples)-1].ObservedAt) {
		return false
	}
	switch v.RecordingStatus {
	case "recording":
		if v.Stale || v.Reason != "" || !v.Samples[len(v.Samples)-1].Available || v.Samples[len(v.Samples)-1].ContainerID != v.ContainerID {
			return false
		}
	case "stale":
		if !v.Stale || (v.Reason != "sample_expired" && v.Reason != "read_failed" && v.Reason != "not_running" && v.Reason != "read_unavailable" && v.Reason != "runtime_changed") {
			return false
		}
		last := v.Samples[len(v.Samples)-1]
		if v.Reason == "not_running" || v.Reason == "read_unavailable" {
			if last.ContainerID != v.ContainerID || last.Available || last.UnavailableReason != v.Reason {
				return false
			}
		}
		if v.Reason == "runtime_changed" && last.ContainerID == v.ContainerID && last.UnavailableReason != "runtime_changed" {
			return false
		}
	default:
		return false
	}
	var previous *appcontracts.ImageMetricsHistoryPoint
	for i := range v.Samples {
		point := &v.Samples[i]
		if point.SegmentID == 0 || point.SegmentID > v.CurrentSegmentID || !validTime(point.ObservedAt) || point.ObservedAt.Before(v.HistoryEpoch) || point.ObservedAt.Before(now.Add(-32*time.Minute)) || point.ObservedAt.After(now.Add(2*time.Minute)) {
			return false
		}
		if _, err := requireID(point.ContainerID, "container identity"); err != nil {
			return false
		}
		if previous != nil {
			if !point.ObservedAt.After(previous.ObservedAt) || point.SegmentID < previous.SegmentID {
				return false
			}
			if point.SegmentID == previous.SegmentID && point.ContainerID != previous.ContainerID {
				return false
			}
			if point.SegmentID == previous.SegmentID && point.ProcessStartedAt != nil && previous.ProcessStartedAt != nil && !point.ProcessStartedAt.Equal(*previous.ProcessStartedAt) {
				return false
			}
		}
		if point.Available {
			if point.UnavailableReason != "" || point.ProcessStartedAt == nil || !validTime(*point.ProcessStartedAt) || point.ProcessStartedAt.After(point.ObservedAt) || (point.CPUUsageMillis == nil && point.MemoryUsageBytes == nil && point.NetworkRxBytes == nil && point.PIDsCurrent == nil) {
				return false
			}
		} else if (point.UnavailableReason != "not_running" && point.UnavailableReason != "read_unavailable" && point.UnavailableReason != "runtime_changed") || point.ProcessStartedAt != nil || point.CPUPercent != nil || point.CPUUsageMillis != nil || point.MemoryUsageBytes != nil || point.MemoryLimitBytes != nil || point.NetworkRxBytes != nil || point.NetworkTxBytes != nil || point.PIDsCurrent != nil || point.Limits != nil {
			return false
		}
		if !validMetricValue(point.CPUPercent, point.CPUUsageMillis, point.NetworkRxBytes, point.NetworkTxBytes, point.Limits) {
			return false
		}
		previous = point
	}
	return true
}
