// Package compose contains the controlled Docker Compose import boundary.
//
// Compose is an input format only.  This package accepts the dependency-free
// JSON-shaped domain schema, normalizes its order and harmless formatting, and
// converts it to a domain.ServiceGroup.  It never returns an executable
// Compose document and it fails closed when the document contains an unknown
// or unsafe field.
package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	// ImporterVersion identifies the report/normalization behavior.  It is
	// deliberately independent from the Compose file's optional version field.
	ImporterVersion = "m2"

	statusMapped   = "mapped"
	statusRejected = "rejected"
)

// Options contains the domain context needed to materialize a ServiceGroup.
// Now is intentionally caller supplied: callers that need reproducible
// evidence should pass a fixed value rather than allowing the importer to
// observe wall-clock time.
type Options struct {
	ApplicationID domain.ID
	Name          string
	Now           time.Time
}

// Request is the explicit input form for Import. Exactly one of JSON or
// Document must be supplied. JSON is preferred at an untrusted boundary
// because the strict decoder can detect unknown and duplicate fields.
type Request struct {
	JSON     []byte
	Document *domain.ComposeFile
	Options  Options
}

// FieldMapping records one source-to-controlled-model decision. A rejected
// field is retained in the report even when import fails, so callers can show
// an actionable fail-closed explanation without executing anything.
type FieldMapping struct {
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Mapping is a short alias useful to callers that refer to the report as a
// mapping rather than a field mapping.
type Mapping = FieldMapping

// Report is the durable, deterministic import decision. All slices are
// sorted and de-duplicated before the result is returned.
type Report struct {
	Version         string         `json:"version"`
	Accepted        bool           `json:"accepted"`
	RawDigest       string         `json:"raw_digest,omitempty"`
	CanonicalDigest string         `json:"canonical_digest,omitempty"`
	MappedFields    []string       `json:"mapped_fields,omitempty"`
	RejectedFields  []string       `json:"rejected_fields,omitempty"`
	Warnings        []string       `json:"warnings,omitempty"`
	DependencyOrder []string       `json:"dependency_order,omitempty"`
	Mappings        []FieldMapping `json:"mappings,omitempty"`
}

// ImportReport is the descriptive alias used by API adapters.
type ImportReport = Report

// Result contains only the normalized, controlled representation. Canonical
// is a compact JSON snapshot of the normalized input for evidence; it is not
// suitable for direct execution by Docker Compose.
type Result struct {
	Document     domain.ComposeFile  `json:"document"`
	ServiceGroup domain.ServiceGroup `json:"service_group"`
	Report       Report              `json:"report"`
	Canonical    []byte              `json:"-"`
}

// Importer is stateless and safe to reuse across requests.
type Importer struct{}

// New returns a stateless controlled Compose importer.
func New() Importer { return Importer{} }

// NewImporter is an explicit constructor alias for registries.
func NewImporter() Importer { return New() }

// ImportJSON strictly decodes, normalizes, policy-checks, and converts a JSON
// shaped Compose document into a ServiceGroup.
func ImportJSON(data []byte, options Options) (Result, error) {
	return New().ImportJSON(data, options)
}

// ImportDocument imports a document that was already decoded by a trusted
// adapter (for example, a YAML adapter that has converted YAML to the domain
// JSON-shaped schema). It still performs all normalization and policy checks.
func ImportDocument(document domain.ComposeFile, options Options) (Result, error) {
	return New().ImportDocument(document, options)
}

// Import is the request-oriented entry point. It is intentionally explicit so
// callers cannot accidentally pass a raw Compose file to a runtime driver.
func Import(request Request) (Result, error) {
	return New().Import(request)
}

// CanonicalJSON parses and normalizes JSON without creating a ServiceGroup.
// The returned bytes are stable for semantically equivalent supported input.
func CanonicalJSON(data []byte) (domain.ComposeFile, []byte, Report, error) {
	return New().CanonicalJSON(data)
}

// Normalize returns a validated, deterministic copy of a domain Compose
// document. It never mutates the caller's maps or slices.
func Normalize(document domain.ComposeFile) (domain.ComposeFile, error) {
	return New().Normalize(document)
}

// Import handles either the strict JSON or trusted document path.
func (Importer) Import(request Request) (Result, error) {
	if len(request.JSON) > 0 && request.Document != nil {
		return failedResult(reportForRequest(request.JSON), "compose import request must contain either JSON or Document")
	}
	if len(request.JSON) > 0 {
		return New().ImportJSON(request.JSON, request.Options)
	}
	if request.Document != nil {
		return New().ImportDocument(*request.Document, request.Options)
	}
	return failedResult(Report{Version: ImporterVersion}, "compose import request is empty")
}

// ImportJSON is the method form of the package-level entry point.
func (Importer) ImportJSON(data []byte, options Options) (Result, error) {
	report := reportForRequest(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return failedResult(report, "compose JSON input is empty")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		report.reject(pathFromError(err), "duplicate JSON object key")
		report.finish()
		return failedResult(report, err.Error(), err)
	}
	document, err := domain.DecodeComposeJSON(data)
	if err != nil {
		report.reject(pathFromError(err), err.Error())
		report.finish()
		return failedResult(report, err.Error(), err)
	}
	return New().importDocument(document, options, report)
}

// ImportDocument is the method form of the package-level entry point.
func (Importer) ImportDocument(document domain.ComposeFile, options Options) (Result, error) {
	return New().importDocument(document, options, reportForDocument(document))
}

// CanonicalJSON parses and normalizes JSON without creating a ServiceGroup.
func (Importer) CanonicalJSON(data []byte) (domain.ComposeFile, []byte, Report, error) {
	report := reportForRequest(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return domain.ComposeFile{}, nil, report, fmt.Errorf("compose JSON input is empty")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		report.reject(pathFromError(err), "duplicate JSON object key")
		report.finish()
		return domain.ComposeFile{}, nil, report, err
	}
	document, err := domain.DecodeComposeJSON(data)
	if err != nil {
		report.reject(pathFromError(err), err.Error())
		report.finish()
		return domain.ComposeFile{}, nil, report, err
	}
	normalized, canonical, report, err := New().normalizeDocument(document, report)
	if err != nil {
		return domain.ComposeFile{}, nil, report, err
	}
	return normalized, canonical, report, nil
}

// Normalize returns a validated, deterministic copy of a domain Compose
// document. The policy checks here are also applied by ImportDocument.
func (Importer) Normalize(document domain.ComposeFile) (domain.ComposeFile, error) {
	normalized, _, _, err := New().normalizeDocument(document, reportForDocument(document))
	return normalized, err
}

func (Importer) importDocument(document domain.ComposeFile, options Options, report Report) (Result, error) {
	normalized, canonical, report, err := New().normalizeDocument(document, report)
	if err != nil {
		return failedResult(report, err.Error(), err)
	}
	group, domainReport, err := normalized.ToServiceGroup(options.ApplicationID, options.Name, options.Now)
	mapNormalizedDocument(&report, normalized)
	for _, warning := range domainReport.Warnings {
		report.warn(warning)
	}
	if err != nil {
		report.reject(pathFromError(err), err.Error())
		report.finish()
		return failedResult(report, err.Error(), err)
	}
	order, err := group.DependencyOrder()
	if err != nil {
		report.reject("dependency_graph", err.Error())
		report.finish()
		return failedResult(report, err.Error(), err)
	}
	report.DependencyOrder = append([]string(nil), order...)
	report.Accepted = true
	report.finish()
	return Result{Document: normalized, ServiceGroup: group, Report: report, Canonical: append([]byte(nil), canonical...)}, nil
}

func (i Importer) normalizeDocument(document domain.ComposeFile, report Report) (domain.ComposeFile, []byte, Report, error) {
	normalized, violations, warnings := normalize(document)
	mapNormalizedDocument(&report, normalized)
	for _, violation := range violations {
		report.reject(violation.path, violation.reason)
	}
	for _, warning := range warnings {
		report.warn(warning)
	}
	if len(violations) > 0 {
		report.finish()
		err := domain.ValidationError("compose import rejected: " + violations[0].reason)
		return domain.ComposeFile{}, nil, report, err
	}
	if err := normalized.Validate(); err != nil {
		report.reject(pathFromError(err), err.Error())
		report.finish()
		return domain.ComposeFile{}, nil, report, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		report.finish()
		return domain.ComposeFile{}, nil, report, fmt.Errorf("compose canonicalization failed: %w", err)
	}
	report.CanonicalDigest = digest(canonical)
	report.finish()
	return normalized, canonical, report, nil
}

type violation struct {
	path   string
	reason string
}

func normalize(document domain.ComposeFile) (domain.ComposeFile, []violation, []string) {
	var violations []violation
	var warnings []string
	normalized := domain.ComposeFile{Version: strings.TrimSpace(document.Version)}
	if normalized.Version != "" {
		warnings = append(warnings, "compose.version is retained as compatibility metadata; runtime behavior comes from the controlled ServiceGroup")
	}

	normalized.Networks, violations = normalizeNetworks(document.Networks, violations)
	normalized.Volumes, violations = normalizeVolumes(document.Volumes, violations)

	serviceNames := sortedKeys(document.Services)
	normalized.Services = make(map[string]domain.ComposeService, len(serviceNames))
	for _, rawName := range serviceNames {
		name := strings.TrimSpace(rawName)
		if name == "" {
			violations = append(violations, violation{path: "services", reason: "compose service name is required"})
			continue
		}
		if name != rawName {
			if _, exists := normalized.Services[name]; exists {
				violations = append(violations, violation{path: "services." + rawName, reason: "service name becomes a duplicate after normalization"})
				continue
			}
		}
		service, serviceViolations, serviceWarnings := normalizeService(name, document.Services[rawName])
		violations = append(violations, serviceViolations...)
		warnings = append(warnings, serviceWarnings...)
		normalized.Services[name] = service
	}
	for _, serviceName := range sortedKeys(normalized.Services) {
		service := normalized.Services[serviceName]
		for dependency := range service.DependsOn {
			if _, ok := normalized.Services[dependency]; !ok {
				violations = append(violations, violation{path: "services." + serviceName + ".depends_on." + dependency, reason: "dependency target service does not exist"})
			}
		}
		for _, network := range service.Networks {
			if len(normalized.Networks) > 0 {
				if _, ok := normalized.Networks[network]; !ok {
					violations = append(violations, violation{path: "services." + serviceName + ".networks." + network, reason: "referenced network is not declared"})
				}
			}
		}
		for _, volume := range service.Volumes {
			if len(normalized.Volumes) > 0 {
				if _, ok := normalized.Volumes[volume.Source]; !ok {
					violations = append(violations, violation{path: "services." + serviceName + ".volumes." + volume.Source, reason: "referenced volume is not declared"})
				}
			}
		}
	}
	return normalized, violations, warnings
}

func normalizeNetworks(input map[string]domain.ComposeNetwork, violations []violation) (map[string]domain.ComposeNetwork, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make(map[string]domain.ComposeNetwork, len(input))
	for _, rawName := range sortedKeys(input) {
		name := strings.TrimSpace(rawName)
		if name == "" {
			violations = append(violations, violation{path: "networks", reason: "compose network name is required"})
			continue
		}
		if !input[rawName].Internal {
			violations = append(violations, violation{path: "networks." + rawName + ".internal", reason: "compose networks must be explicitly internal to the controlled runtime"})
		}
		if _, exists := output[name]; exists {
			violations = append(violations, violation{path: "networks." + rawName, reason: "network name becomes a duplicate after normalization"})
			continue
		}
		output[name] = domain.ComposeNetwork{Internal: true}
	}
	return output, violations
}

func normalizeVolumes(input map[string]domain.ComposeVolume, violations []violation) (map[string]domain.ComposeVolume, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make(map[string]domain.ComposeVolume, len(input))
	for _, rawName := range sortedKeys(input) {
		name := strings.TrimSpace(rawName)
		if name == "" {
			violations = append(violations, violation{path: "volumes", reason: "compose volume name is required"})
			continue
		}
		if _, exists := output[name]; exists {
			violations = append(violations, violation{path: "volumes." + rawName, reason: "volume name becomes a duplicate after normalization"})
			continue
		}
		output[name] = domain.ComposeVolume{}
	}
	return output, violations
}

func normalizeService(name string, input domain.ComposeService) (domain.ComposeService, []violation, []string) {
	var violations []violation
	var warnings []string
	prefix := "services." + name
	output := input
	output.Image = strings.TrimSpace(input.Image)
	output.Restart = strings.ToLower(strings.TrimSpace(input.Restart))
	output.Command = cloneStrings(input.Command)
	output.Entrypoint = cloneStrings(input.Entrypoint)
	output.Environment, violations = normalizeEnvironment(prefix, input.Environment, violations)

	if input.Build != nil {
		build := *input.Build
		build.Context = normalizeWorkspacePath(build.Context)
		build.Dockerfile = normalizeWorkspacePath(build.Dockerfile)
		output.Build = &build
		if unsafeWorkspacePath(build.Context) {
			violations = append(violations, violation{path: prefix + ".build.context", reason: "build context must remain inside the source workspace"})
		}
		if unsafeWorkspacePath(build.Dockerfile) {
			violations = append(violations, violation{path: prefix + ".build.dockerfile", reason: "Dockerfile path must remain inside the source workspace"})
		}
	}

	output.Networks, violations = normalizeNames(prefix+".networks", input.Networks, violations)
	output.Ports, violations = normalizePorts(prefix+".ports", input.Ports, violations)
	output.Volumes, violations = normalizeMounts(prefix+".volumes", input.Volumes, violations)
	output.DependsOn, violations = normalizeDependencies(prefix+".depends_on", input.DependsOn, violations)

	if input.Healthcheck != nil {
		health := *input.Healthcheck
		health.Test = cloneStrings(input.Healthcheck.Test)
		health.Interval = strings.ToLower(strings.TrimSpace(health.Interval))
		health.Timeout = strings.ToLower(strings.TrimSpace(health.Timeout))
		health.StartPeriod = strings.ToLower(strings.TrimSpace(health.StartPeriod))
		output.Healthcheck = &health
	}
	if input.Resources != nil {
		limits := *input.Resources
		limits.CPUs = strings.ToLower(strings.TrimSpace(limits.CPUs))
		limits.Memory = strings.ToLower(strings.TrimSpace(limits.Memory))
		output.Resources = &limits
	}
	if input.Deploy != nil {
		deploy := *input.Deploy
		if input.Deploy.Resources != nil {
			resources := *input.Deploy.Resources
			if input.Deploy.Resources.Limits != nil {
				limits := *input.Deploy.Resources.Limits
				limits.CPUs = strings.ToLower(strings.TrimSpace(limits.CPUs))
				limits.Memory = strings.ToLower(strings.TrimSpace(limits.Memory))
				resources.Limits = &limits
			}
			deploy.Resources = &resources
		}
		output.Deploy = &deploy
	}

	// The domain schema owns the exact capability deny-list; the importer adds
	// field paths so a rejected report remains actionable.
	if input.Privileged != nil {
		violations = append(violations, violation{path: prefix + ".privileged", reason: "privileged execution is forbidden"})
	}
	if input.NetworkMode != nil {
		violations = append(violations, violation{path: prefix + ".network_mode", reason: "host/network mode overrides are forbidden"})
	}
	if input.PID != nil {
		violations = append(violations, violation{path: prefix + ".pid", reason: "host PID namespace is forbidden"})
	}
	if input.IPC != nil {
		violations = append(violations, violation{path: prefix + ".ipc", reason: "host IPC namespace is forbidden"})
	}
	if input.UTS != nil {
		violations = append(violations, violation{path: prefix + ".uts", reason: "host UTS namespace is forbidden"})
	}
	if len(input.Devices) > 0 {
		violations = append(violations, violation{path: prefix + ".devices", reason: "device mappings are forbidden"})
	}
	if len(input.CapAdd) > 0 {
		violations = append(violations, violation{path: prefix + ".cap_add", reason: "capability additions are forbidden"})
	}
	if len(input.CapDrop) > 0 {
		violations = append(violations, violation{path: prefix + ".cap_drop", reason: "capability overrides are forbidden"})
	}
	if len(input.Ports) > 0 {
		for index, port := range input.Ports {
			if port.Published != 0 {
				violations = append(violations, violation{path: fmt.Sprintf("%s.ports[%d].published", prefix, index), reason: "published host ports are forbidden; the runtime allocates ports"})
			}
			if strings.TrimSpace(port.HostIP) != "" {
				violations = append(violations, violation{path: fmt.Sprintf("%s.ports[%d].host_ip", prefix, index), reason: "host IP bindings are forbidden"})
			}
		}
	}
	if input.Resources != nil && input.Deploy != nil && input.Deploy.Resources != nil && input.Deploy.Resources.Limits != nil {
		violations = append(violations, violation{path: prefix + ".resources", reason: "resource limits must use exactly one supported Compose form"})
		violations = append(violations, violation{path: prefix + ".deploy.resources", reason: "resource limits must use exactly one supported Compose form"})
	}
	if strings.Contains(output.Image, "@sha256:") == false && output.Image != "" {
		warnings = append(warnings, prefix+".image is a mutable reference and requires digest resolution before release creation")
	}
	return output, violations, warnings
}

func normalizeEnvironment(prefix string, input map[string]string, violations []violation) (map[string]string, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make(map[string]string, len(input))
	for _, rawName := range sortedKeys(input) {
		name := strings.TrimSpace(rawName)
		if name == "" || strings.Contains(name, "=") {
			violations = append(violations, violation{path: prefix + ".environment." + rawName, reason: "environment name is invalid"})
			continue
		}
		if strings.Contains(name, "\x00") || strings.Contains(input[rawName], "\x00") {
			violations = append(violations, violation{path: prefix + ".environment." + name, reason: "environment values must not contain NUL bytes"})
			continue
		}
		if _, exists := output[name]; exists {
			violations = append(violations, violation{path: prefix + ".environment." + rawName, reason: "environment name becomes a duplicate after normalization"})
			continue
		}
		output[name] = input[rawName]
	}
	return output, violations
}

func normalizeNames(prefix string, input []string, violations []violation) ([]string, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, rawName := range input {
		name := strings.TrimSpace(rawName)
		if name == "" {
			violations = append(violations, violation{path: fmt.Sprintf("%s[%d]", prefix, index), reason: "name is required"})
			continue
		}
		if _, exists := seen[name]; exists {
			violations = append(violations, violation{path: fmt.Sprintf("%s[%d]", prefix, index), reason: "duplicate names are not allowed"})
			continue
		}
		seen[name] = struct{}{}
		output = append(output, name)
	}
	sort.Strings(output)
	return output, violations
}

func normalizePorts(prefix string, input []domain.ComposePort, violations []violation) ([]domain.ComposePort, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make([]domain.ComposePort, len(input))
	copy(output, input)
	for index := range output {
		output[index].Protocol = strings.ToLower(strings.TrimSpace(output[index].Protocol))
		output[index].HostIP = strings.TrimSpace(output[index].HostIP)
	}
	sort.SliceStable(output, func(i, j int) bool {
		if output[i].Target != output[j].Target {
			return output[i].Target < output[j].Target
		}
		return output[i].Protocol < output[j].Protocol
	})
	return output, violations
}

func normalizeMounts(prefix string, input []domain.ComposeVolumeMount, violations []violation) ([]domain.ComposeVolumeMount, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make([]domain.ComposeVolumeMount, len(input))
	copy(output, input)
	seenTargets := make(map[string]struct{}, len(input))
	for index := range output {
		output[index].Source = strings.TrimSpace(output[index].Source)
		output[index].Target = path.Clean(strings.TrimSpace(output[index].Target))
		output[index].Type = strings.ToLower(strings.TrimSpace(output[index].Type))
		if output[index].Type == "" {
			output[index].Type = "volume"
		}
		if output[index].Type != "volume" {
			violations = append(violations, violation{path: fmt.Sprintf("%s[%d].type", prefix, index), reason: "bind/device volume types are forbidden"})
		}
		if output[index].Source == "" {
			violations = append(violations, violation{path: fmt.Sprintf("%s[%d].source", prefix, index), reason: "named volume source is required"})
		}
		if output[index].Target == "." || !strings.HasPrefix(output[index].Target, "/") {
			violations = append(violations, violation{path: fmt.Sprintf("%s[%d].target", prefix, index), reason: "volume target must be absolute"})
		}
		if _, exists := seenTargets[output[index].Target]; exists {
			violations = append(violations, violation{path: fmt.Sprintf("%s[%d].target", prefix, index), reason: "volume mount targets must be unique"})
		}
		seenTargets[output[index].Target] = struct{}{}
	}
	sort.SliceStable(output, func(i, j int) bool {
		if output[i].Target != output[j].Target {
			return output[i].Target < output[j].Target
		}
		if output[i].Source != output[j].Source {
			return output[i].Source < output[j].Source
		}
		return !output[i].ReadOnly && output[j].ReadOnly
	})
	return output, violations
}

func normalizeDependencies(prefix string, input map[string]domain.ComposeDependency, violations []violation) (map[string]domain.ComposeDependency, []violation) {
	if len(input) == 0 {
		return nil, violations
	}
	output := make(map[string]domain.ComposeDependency, len(input))
	for _, rawName := range sortedKeys(input) {
		name := strings.TrimSpace(rawName)
		dependency := input[rawName]
		dependency.Condition = strings.ToLower(strings.TrimSpace(dependency.Condition))
		if name == "" {
			violations = append(violations, violation{path: prefix, reason: "dependency service name is required"})
			continue
		}
		if _, exists := output[name]; exists {
			violations = append(violations, violation{path: prefix + "." + rawName, reason: "dependency name becomes a duplicate after normalization"})
			continue
		}
		output[name] = dependency
	}
	return output, violations
}

func normalizeWorkspacePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	if unsafeWorkspacePath(value) {
		// Preserve the unsafe spelling so the report can identify the source
		// field; Normalize never turns a traversal into a safe-looking path.
		return value
	}
	return path.Clean(value)
}

func unsafeWorkspacePath(value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\x00") {
		return value != ""
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func mapNormalizedDocument(report *Report, document domain.ComposeFile) {
	if report == nil {
		return
	}
	if document.Version != "" {
		report.mapField("version", "definition.compose_version")
	}
	for _, network := range sortedKeys(document.Networks) {
		report.mapField("networks."+network+".internal", "runtime.private_networks."+network)
	}
	for _, volume := range sortedKeys(document.Volumes) {
		report.mapField("volumes."+volume, "runtime.named_volumes."+volume)
	}
	for _, serviceName := range sortedKeys(document.Services) {
		service := document.Services[serviceName]
		prefix := "services." + serviceName
		if service.Image != "" {
			report.mapField(prefix+".image", "service."+serviceName+".source.prebuilt")
		}
		if service.Build != nil {
			report.mapField(prefix+".build.context", "service."+serviceName+".source.dockerfile.context")
			// An omitted Dockerfile is normalized by the domain conversion to
			// Dockerfile, so it still has an explicit controlled target.
			report.mapField(prefix+".build.dockerfile", "service."+serviceName+".source.dockerfile.path")
		}
		if len(service.Command) > 0 {
			report.mapField(prefix+".command", "service."+serviceName+".command")
		}
		if len(service.Entrypoint) > 0 {
			report.mapField(prefix+".entrypoint", "service."+serviceName+".entrypoint")
		}
		if len(service.Environment) > 0 {
			report.mapField(prefix+".environment", "service."+serviceName+".environment")
		}
		if len(service.Ports) > 0 {
			report.mapField(prefix+".ports", "service."+serviceName+".ports")
		}
		if len(service.Volumes) > 0 {
			report.mapField(prefix+".volumes", "service."+serviceName+".volumes")
		}
		if len(service.DependsOn) > 0 {
			report.mapField(prefix+".depends_on", "service."+serviceName+".dependencies")
		}
		if service.Healthcheck != nil {
			report.mapField(prefix+".healthcheck", "service."+serviceName+".healthcheck")
		}
		if service.Restart != "" {
			report.mapField(prefix+".restart", "service."+serviceName+".restart")
		}
		if len(service.Networks) > 0 {
			report.mapField(prefix+".networks", "service."+serviceName+".networks")
		}
		if service.Resources != nil {
			report.mapField(prefix+".resources", "service."+serviceName+".resources")
		}
		if service.Deploy != nil && service.Deploy.Resources != nil && service.Deploy.Resources.Limits != nil {
			report.mapField(prefix+".deploy.resources", "service."+serviceName+".resources")
		}
	}
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (r *Report) mapField(source, target string) {
	if r == nil || strings.TrimSpace(source) == "" {
		return
	}
	r.Mappings = append(r.Mappings, FieldMapping{Source: source, Target: target, Status: statusMapped})
	r.MappedFields = append(r.MappedFields, source)
}

func (r *Report) reject(source, reason string) {
	if r == nil {
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "compose"
	}
	r.Mappings = append(r.Mappings, FieldMapping{Source: source, Status: statusRejected, Reason: strings.TrimSpace(reason)})
	r.RejectedFields = append(r.RejectedFields, source)
}

func (r *Report) warn(value string) {
	if r != nil && strings.TrimSpace(value) != "" {
		r.Warnings = append(r.Warnings, strings.TrimSpace(value))
	}
}

func (r *Report) finish() {
	if r == nil {
		return
	}
	r.Version = ImporterVersion
	r.MappedFields = uniqueSorted(r.MappedFields)
	r.RejectedFields = uniqueSorted(r.RejectedFields)
	r.Warnings = uniqueSorted(r.Warnings)
	sort.Slice(r.Mappings, func(i, j int) bool {
		if r.Mappings[i].Source != r.Mappings[j].Source {
			return r.Mappings[i].Source < r.Mappings[j].Source
		}
		if r.Mappings[i].Status != r.Mappings[j].Status {
			return r.Mappings[i].Status < r.Mappings[j].Status
		}
		return r.Mappings[i].Target < r.Mappings[j].Target
	})
	r.Mappings = uniqueMappings(r.Mappings)
	if r.Accepted {
		r.RejectedFields = nil
	}
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	output := values[:0]
	for _, value := range values {
		if len(output) == 0 || output[len(output)-1] != value {
			output = append(output, value)
		}
	}
	return output
}

func uniqueMappings(values []FieldMapping) []FieldMapping {
	if len(values) == 0 {
		return nil
	}
	output := values[:0]
	for _, value := range values {
		if len(output) == 0 || output[len(output)-1] != value {
			output = append(output, value)
		}
	}
	return output
}

func reportForRequest(data []byte) Report {
	return Report{Version: ImporterVersion, RawDigest: digest(bytes.TrimSpace(data))}
}

func reportForDocument(document domain.ComposeFile) Report {
	data, err := json.Marshal(document)
	if err != nil {
		return Report{Version: ImporterVersion}
	}
	return Report{Version: ImporterVersion, RawDigest: digest(data)}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func failedResult(report Report, message string, causes ...error) (Result, error) {
	report.Accepted = false
	report.finish()
	for _, cause := range causes {
		if cause != nil {
			return Result{Report: report}, fmt.Errorf("compose import rejected: %w", cause)
		}
	}
	return Result{Report: report}, fmt.Errorf("compose import rejected: %s", strings.TrimSpace(message))
}

func pathFromError(err error) string {
	if err == nil {
		return "compose"
	}
	message := err.Error()
	if marker := "compose unknown field "; strings.Contains(message, marker) {
		value := message[strings.Index(message, marker)+len(marker):]
		value = strings.TrimSpace(value)
		if index := strings.Index(value, " ("); index >= 0 {
			value = value[:index]
		}
		value = strings.TrimPrefix(value, "compose.")
		return value
	}
	if marker := "compose duplicate field "; strings.Contains(message, marker) {
		value := message[strings.Index(message, marker)+len(marker):]
		if index := strings.Index(value, " ("); index >= 0 {
			value = value[:index]
		}
		return strings.TrimPrefix(strings.TrimSpace(value), "compose.")
	}
	return "compose"
}

// rejectDuplicateJSONKeys performs a streaming structural scan before the
// domain decoder. encoding/json otherwise keeps the last duplicate key, which
// would make a security decision depend on source ordering.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder, "compose"); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return domain.ValidationError("compose contains trailing data")
		}
		return domain.ValidationError(fmt.Sprintf("compose contains invalid trailing data: %v", err))
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, currentPath string) error {
	token, err := decoder.Token()
	if err != nil {
		return domain.ValidationError(fmt.Sprintf("%s is not valid JSON: %v", currentPath, err))
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return domain.ValidationError(fmt.Sprintf("%s object key is invalid: %v", currentPath, err))
				}
				key, ok := keyToken.(string)
				if !ok {
					return domain.ValidationError(fmt.Sprintf("%s object key is invalid", currentPath))
				}
				if _, exists := seen[key]; exists {
					return domain.ValidationError(fmt.Sprintf("compose duplicate field %s", joinPath(currentPath, key)))
				}
				seen[key] = struct{}{}
				if err := scanJSONValue(decoder, joinPath(currentPath, key)); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return domain.ValidationError(fmt.Sprintf("%s object is not closed: %v", currentPath, err))
			}
		case '[':
			index := 0
			for decoder.More() {
				if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", currentPath, index)); err != nil {
					return err
				}
				index++
			}
			if _, err := decoder.Token(); err != nil {
				return domain.ValidationError(fmt.Sprintf("%s array is not closed: %v", currentPath, err))
			}
		case '}', ']':
			return domain.ValidationError(fmt.Sprintf("%s has an unexpected delimiter", currentPath))
		}
	}
	return nil
}

func joinPath(left, right string) string {
	if left == "" {
		return right
	}
	return left + "." + right
}
