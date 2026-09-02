package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
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
