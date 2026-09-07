package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
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
	ApplicationID string       `json:"application_id"`
	EnvironmentID string       `json:"environment_id"`
	ReleaseID     string       `json:"release_id"`
	ServiceName   string       `json:"service_name"`
	Image         apiImage     `json:"image"`
	Resources     apiResources `json:"resources"`
	ContainerPort *int         `json:"container_port,omitempty"`
	AcceptedAt    time.Time    `json:"accepted_at"`
	Immutable     *bool        `json:"immutable"`
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
type apiFixCandidates struct {
	Items []apiFixCandidate `json:"items"`
}

func decodeResponse(body io.Reader, shape responseShape) (any, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxResponseBytes {
		return nil, invalidResponse("server response is invalid")
	}
	if !requiredResponseFields(data, shape) {
		return nil, invalidResponse("server response does not match the AcornFox API contract")
	}
	if optionalNonNullableNull(data, shape) {
		return nil, invalidResponse("server response does not match the AcornFox API contract")
	}
	switch shape {
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
	case shapeSourceMetadata:
		var v apiSourceMetadata
		return decodeTyped(data, &v, validateSourceMetadata)
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
	if shape == shapeHostMetrics {
		if nullField(object, "observed_at", "cpu", "memory", "disk", "network") {
			return true
		}
		for _, name := range []string{"cpu", "network"} {
			raw, ok := object[name]
			if !ok {
				continue
			}
			var nested map[string]json.RawMessage
			if json.Unmarshal(raw, &nested) != nil {
				return true
			}
			if name == "cpu" && nullField(nested, "usage_percent") || name == "network" && nullField(nested, "rx_bytes_per_second", "tx_bytes_per_second") {
				return true
			}
		}
		return false
	}
	if shape != shapeStatus {
		return false
	}
	for field, prohibited := range map[string][]string{"desired": {"container_port"}, "runtime": {"container_id", "internal_address"}, "response": {"latency_ms", "error_code"}} {
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
	case shapeSourceMetadata:
		keys = []string{"source_revision_id", "availability"}
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
	return v.Immutable != nil && v.Kind == "git_https" && nonempty(v.ID, v.ApplicationID, v.LocatorSHA256, v.ContentDigest) && validTime(v.CreatedAt)
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
	return nonempty(v.DeploymentID, v.OperationID, v.TaskID, v.Status)
}
func validateResources(v apiResources) bool {
	return v.CPUMillis != nil && v.MemoryBytes != nil && v.Pids != nil && v.DiskReservationBytes != nil && *v.CPUMillis >= 0 && *v.MemoryBytes >= 0 && *v.Pids >= 0 && *v.DiskReservationBytes >= 0
}
func validateRelease(v *apiRelease) bool {
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
func validateHostMetrics(v *apiHostMetrics) bool {
	if v.SchemaVersion != 1 || v.StaleAfterSeconds < 1 || !(v.Availability == "available" || v.Availability == "warming_up" || v.Availability == "unavailable" || v.Availability == "unsupported") {
		return false
	}
	if v.Availability == "unavailable" || v.Availability == "unsupported" {
		return v.CPU == nil && v.Memory == nil && v.Disk == nil && v.Network == nil
	}
	if !validTimePointer(v.ObservedAt) || v.CPU == nil || v.Memory == nil || v.Disk == nil {
		return false
	}
	if v.CPU.LogicalCores < 1 || (v.CPU.UsagePercent != nil && (*v.CPU.UsagePercent < 0 || *v.CPU.UsagePercent > 100)) {
		return false
	}
	if v.Memory.TotalBytes < 0 || v.Memory.AvailableBytes < 0 || v.Memory.UsedBytes < 0 || v.Memory.AvailableBytes > v.Memory.TotalBytes || v.Memory.UsedBytes > v.Memory.TotalBytes {
		return false
	}
	if v.Disk.Mountpoint != "/" || v.Disk.TotalBytes < 0 || v.Disk.FreeBytes < 0 || v.Disk.UsedBytes < 0 || v.Disk.FreeBytes > v.Disk.TotalBytes || v.Disk.UsedBytes > v.Disk.TotalBytes {
		return false
	}
	if v.Network == nil {
		return true
	}
	return v.Network.Interface != "" && (v.Network.RXBytesPerSecond == nil || *v.Network.RXBytesPerSecond >= 0) && (v.Network.TXBytesPerSecond == nil || *v.Network.TXBytesPerSecond >= 0)
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
