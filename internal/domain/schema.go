package domain

// This file contains the small, dependency-free schema gates that sit below
// the API and persistence layers.  The database remains authoritative for
// transaction-time uniqueness and foreign-key checks; these validators make
// invalid domain values fail before they reach either layer.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

// VolumeMount is the controlled local-volume shape understood by a service.
// It intentionally has no host-path field: host bind mounts are an import and
// runtime policy violation for the MVP.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	ReadOnly  bool   `json:"read_only,omitempty"`
}

func (v VolumeMount) Validate() error {
	if strings.TrimSpace(v.Name) == "" {
		return ValidationError("volume name is required")
	}
	if strings.HasPrefix(v.Name, "/") || strings.Contains(v.Name, "..") {
		return ValidationError("volume name must be a controlled named volume")
	}
	if strings.TrimSpace(v.MountPath) == "" || !strings.HasPrefix(v.MountPath, "/") {
		return ValidationError("volume mount path must be absolute")
	}
	if strings.Contains(v.MountPath, "\x00") {
		return ValidationError("volume mount path contains a NUL byte")
	}
	return nil
}

// HealthcheckSpec is deliberately runtime-neutral.  Duration conversion is
// done by the Compose import gate; the domain stores bounded seconds.
type HealthcheckSpec struct {
	Test               []string `json:"test"`
	IntervalSeconds    int      `json:"interval_seconds,omitempty"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
	StartPeriodSeconds int      `json:"start_period_seconds,omitempty"`
	Retries            int      `json:"retries,omitempty"`
	Disabled           bool     `json:"disabled,omitempty"`
}

func (h HealthcheckSpec) Validate() error {
	if !h.Disabled && len(h.Test) == 0 {
		return ValidationError("healthcheck test is required unless disabled")
	}
	if h.IntervalSeconds < 0 || h.TimeoutSeconds < 0 || h.StartPeriodSeconds < 0 || h.Retries < 0 {
		return ValidationError("healthcheck limits must not be negative")
	}
	for _, item := range h.Test {
		if strings.TrimSpace(item) == "" {
			return ValidationError("healthcheck test entries must not be empty")
		}
	}
	return nil
}

// ResourceLimits contains only resource quantities enforced by the runtime.
// Zero means that no product-level override was supplied.
type ResourceLimits struct {
	CPUMillis   int64 `json:"cpu_millis,omitempty"`
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
}

func (r ResourceLimits) Validate() error {
	if r.CPUMillis < 0 || r.MemoryBytes < 0 {
		return ValidationError("resource limits must not be negative")
	}
	return nil
}

func validRestartPolicy(policy string) bool {
	switch strings.TrimSpace(policy) {
	case "no", "always", "on-failure", "unless-stopped":
		return true
	default:
		return false
	}
}

// OperationStatusIsActive mirrors the domain-level part of the database
// partial unique index.  The DB still has to enforce this under concurrency.
func (s OperationStatus) IsActive() bool {
	switch s {
	case OperationPending, OperationRunning, OperationWaiting, OperationRollingBack:
		return true
	default:
		return false
	}
}

func (o Operation) IsActive() bool { return o.Status.IsActive() }

// ValidateActiveOperations is a pre-transaction guard for the invariant that
// an environment has at most one active operation.  It is intentionally
// deterministic so callers can include the conflicting operation IDs in an
// evidence report.
func ValidateActiveOperations(operations []Operation) error {
	active := make(map[ID]ID)
	for _, operation := range operations {
		if err := operation.Validate(); err != nil {
			return err
		}
		if !operation.IsActive() {
			continue
		}
		if previous, ok := active[operation.EnvironmentID]; ok && previous != operation.ID {
			return ValidationError(fmt.Sprintf("environment %q has more than one active operation (%q and %q)", operation.EnvironmentID, previous, operation.ID))
		}
		active[operation.EnvironmentID] = operation.ID
	}
	return nil
}

// ValidateOperations is an alias with a name suitable for repository code.
// It retains the same fail-closed active-operation check.
func ValidateOperations(operations []Operation) error {
	return ValidateActiveOperations(operations)
}

// RouteKey is the canonical uniqueness key used by the API and DB adapter.
func (r Route) RouteKey() string {
	host := strings.ToLower(strings.TrimSpace(r.Host))
	path := strings.TrimSpace(r.Path)
	if path != "/" {
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
	}
	return host + "\x00" + path
}

// ValidateRoutes checks structural validity and host/path uniqueness.  It
// does not infer a service role; use ValidateRouteSet when a ServiceGroup is
// available so non-ingress targets are rejected as well.
func ValidateRoutes(routes []Route) error {
	seen := make(map[string]ID, len(routes))
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return err
		}
		key := route.RouteKey()
		if previous, ok := seen[key]; ok && previous != route.ID {
			return ValidationError(fmt.Sprintf("route host/path is already claimed by %q", previous))
		}
		seen[key] = route.ID
	}
	return nil
}

// ValidateRouteSet adds the product invariant that only an ingress service
// may receive an external route.  Route.ServiceName is required here because
// a deployment alone cannot prove which service is the public entrypoint.
func ValidateRouteSet(routes []Route, group ServiceGroup) error {
	if err := group.Validate(); err != nil {
		return err
	}
	if err := ValidateRoutes(routes); err != nil {
		return err
	}
	roles := make(map[string]ServiceRole, len(group.Services))
	for _, service := range group.Services {
		roles[service.Name] = service.Role
	}
	for _, route := range routes {
		serviceName := strings.TrimSpace(route.ServiceName)
		if serviceName == "" {
			return ValidationError("route service name is required to prove the entry target")
		}
		role, ok := roles[serviceName]
		if !ok {
			return ValidationError("route target service does not exist")
		}
		if role != RoleIngress {
			return ValidationError("only an ingress service may receive an external route")
		}
		if route.ApplicationID != group.ApplicationID {
			return ValidationError("route application does not match service group application")
		}
	}
	return nil
}

// ValidateRouteSetForServiceGroup is a discoverable method form of the
// package-level gate.
func (g ServiceGroup) ValidateRouteSet(routes []Route) error {
	return ValidateRouteSet(routes, g)
}

// ComposeFile is the deliberately small JSON-shaped representation consumed
// by the dependency-free Compose importer.  A YAML decoder may normalize a
// Compose file into this representation before calling Validate/ToServiceGroup.
// Unknown fields are rejected by UnmarshalJSON; callers must not silently
// discard fields from an untrusted Compose document.
type ComposeFile struct {
	Version  string                    `json:"version,omitempty"`
	Services map[string]ComposeService `json:"services"`
	Networks map[string]ComposeNetwork `json:"networks,omitempty"`
	Volumes  map[string]ComposeVolume  `json:"volumes,omitempty"`
}

// ComposeDocument is the descriptive name used by import callers.
type ComposeDocument = ComposeFile

type ComposeNetwork struct {
	Internal bool `json:"internal,omitempty"`
}

type ComposeVolume struct{}

type ComposeBuild struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile,omitempty"`
}

type ComposePort struct {
	Target    int    `json:"target"`
	Published int    `json:"published,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	HostIP    string `json:"host_ip,omitempty"`
}

type ComposeVolumeMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Type     string `json:"type,omitempty"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type ComposeDependency struct {
	Condition string `json:"condition"`
}

type ComposeHealthcheck struct {
	Test        []string `json:"test"`
	Interval    string   `json:"interval,omitempty"`
	Timeout     string   `json:"timeout,omitempty"`
	StartPeriod string   `json:"start_period,omitempty"`
	Retries     int      `json:"retries,omitempty"`
	Disable     bool     `json:"disable,omitempty"`
}

type ComposeResourceLimits struct {
	CPUs   string `json:"cpus,omitempty"`
	Memory string `json:"memory,omitempty"`
}

type ComposeResources struct {
	Limits *ComposeResourceLimits `json:"limits,omitempty"`
}

type ComposeDeploy struct {
	Resources *ComposeResources `json:"resources,omitempty"`
}

type ComposeService struct {
	Image       string                       `json:"image,omitempty"`
	Build       *ComposeBuild                `json:"build,omitempty"`
	Command     []string                     `json:"command,omitempty"`
	Entrypoint  []string                     `json:"entrypoint,omitempty"`
	Environment map[string]string            `json:"environment,omitempty"`
	Ports       []ComposePort                `json:"ports,omitempty"`
	Volumes     []ComposeVolumeMount         `json:"volumes,omitempty"`
	DependsOn   map[string]ComposeDependency `json:"depends_on,omitempty"`
	Healthcheck *ComposeHealthcheck          `json:"healthcheck,omitempty"`
	Restart     string                       `json:"restart,omitempty"`
	Networks    []string                     `json:"networks,omitempty"`
	Resources   *ComposeResourceLimits       `json:"resources,omitempty"`
	Deploy      *ComposeDeploy               `json:"deploy,omitempty"`
	Privileged  *bool                        `json:"privileged,omitempty"`
	NetworkMode *string                      `json:"network_mode,omitempty"`
	PID         *string                      `json:"pid,omitempty"`
	IPC         *string                      `json:"ipc,omitempty"`
	UTS         *string                      `json:"uts,omitempty"`
	Devices     []string                     `json:"devices,omitempty"`
	CapAdd      []string                     `json:"cap_add,omitempty"`
	CapDrop     []string                     `json:"cap_drop,omitempty"`
}

type ComposeImportReport struct {
	MappedFields []string `json:"mapped_fields"`
	Warnings     []string `json:"warnings,omitempty"`
}

func strictJSONObject(data []byte, allowed map[string]struct{}, path string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var raw map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, ValidationError(fmt.Sprintf("%s must be a JSON object: %v", path, err))
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, ValidationError(fmt.Sprintf("%s contains trailing data", path))
		}
		return nil, ValidationError(fmt.Sprintf("%s contains invalid trailing data: %v", path, err))
	}
	if raw == nil {
		return nil, ValidationError(fmt.Sprintf("%s must not be null", path))
	}
	for key := range raw {
		if _, ok := allowed[key]; !ok {
			return nil, ValidationError(fmt.Sprintf("compose unknown field %s.%s", path, key))
		}
	}
	return raw, nil
}

func unmarshalStrict(data []byte, dst any, allowed map[string]struct{}, path string) error {
	if _, err := strictJSONObject(data, allowed, path); err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func (n *ComposeNetwork) UnmarshalJSON(data []byte) error {
	type networkAlias ComposeNetwork
	return unmarshalStrict(data, (*networkAlias)(n), map[string]struct{}{"internal": {}}, "compose.network")
}

func (v *ComposeVolume) UnmarshalJSON(data []byte) error {
	type volumeAlias ComposeVolume
	return unmarshalStrict(data, (*volumeAlias)(v), map[string]struct{}{}, "compose.volume")
}

func (b *ComposeBuild) UnmarshalJSON(data []byte) error {
	type buildAlias ComposeBuild
	return unmarshalStrict(data, (*buildAlias)(b), map[string]struct{}{"context": {}, "dockerfile": {}}, "compose.build")
}

func (p *ComposePort) UnmarshalJSON(data []byte) error {
	type portAlias ComposePort
	return unmarshalStrict(data, (*portAlias)(p), map[string]struct{}{"target": {}, "published": {}, "protocol": {}, "host_ip": {}}, "compose.port")
}

func (v *ComposeVolumeMount) UnmarshalJSON(data []byte) error {
	type volumeMountAlias ComposeVolumeMount
	return unmarshalStrict(data, (*volumeMountAlias)(v), map[string]struct{}{"source": {}, "target": {}, "type": {}, "read_only": {}}, "compose.volume_mount")
}

func (d *ComposeDependency) UnmarshalJSON(data []byte) error {
	type dependencyAlias ComposeDependency
	return unmarshalStrict(data, (*dependencyAlias)(d), map[string]struct{}{"condition": {}}, "compose.dependency")
}

func (h *ComposeHealthcheck) UnmarshalJSON(data []byte) error {
	type healthcheckAlias ComposeHealthcheck
	return unmarshalStrict(data, (*healthcheckAlias)(h), map[string]struct{}{"test": {}, "interval": {}, "timeout": {}, "start_period": {}, "retries": {}, "disable": {}}, "compose.healthcheck")
}

func (r *ComposeResourceLimits) UnmarshalJSON(data []byte) error {
	type resourceLimitsAlias ComposeResourceLimits
	return unmarshalStrict(data, (*resourceLimitsAlias)(r), map[string]struct{}{"cpus": {}, "memory": {}}, "compose.resource_limits")
}

func (r *ComposeResources) UnmarshalJSON(data []byte) error {
	type resourcesAlias ComposeResources
	return unmarshalStrict(data, (*resourcesAlias)(r), map[string]struct{}{"limits": {}}, "compose.resources")
}

func (d *ComposeDeploy) UnmarshalJSON(data []byte) error {
	type deployAlias ComposeDeploy
	return unmarshalStrict(data, (*deployAlias)(d), map[string]struct{}{"resources": {}}, "compose.deploy")
}

func (s *ComposeService) UnmarshalJSON(data []byte) error {
	type serviceAlias ComposeService
	return unmarshalStrict(data, (*serviceAlias)(s), map[string]struct{}{
		"image": {}, "build": {}, "command": {}, "entrypoint": {}, "environment": {}, "ports": {}, "volumes": {}, "depends_on": {}, "healthcheck": {}, "restart": {}, "networks": {}, "resources": {}, "deploy": {},
		"privileged": {}, "network_mode": {}, "pid": {}, "ipc": {}, "uts": {}, "devices": {}, "cap_add": {}, "cap_drop": {},
	}, "compose.service")
}

func qualifyComposeFieldError(err error, prefix string) error {
	var domainErr *DomainError
	if !errors.As(err, &domainErr) || !strings.HasPrefix(domainErr.Message, "compose unknown field ") {
		return err
	}
	field := strings.TrimPrefix(domainErr.Message, "compose unknown field ")
	field = strings.TrimPrefix(field, "compose.")
	field = strings.TrimPrefix(field, "service.")
	return ValidationError("compose unknown field " + prefix + "." + field)
}

func (f *ComposeFile) UnmarshalJSON(data []byte) error {
	raw, err := strictJSONObject(data, map[string]struct{}{"version": {}, "services": {}, "networks": {}, "volumes": {}}, "compose")
	if err != nil {
		return err
	}
	var version string
	if value, ok := raw["version"]; ok {
		if err := json.Unmarshal(value, &version); err != nil {
			return ValidationError(fmt.Sprintf("compose.version: %v", err))
		}
	}
	servicesRaw, ok := raw["services"]
	if !ok {
		return ValidationError("compose.services is required")
	}
	var serviceValues map[string]json.RawMessage
	if err := json.Unmarshal(servicesRaw, &serviceValues); err != nil {
		return ValidationError(fmt.Sprintf("compose.services: %v", err))
	}
	services := make(map[string]ComposeService, len(serviceValues))
	for name, value := range serviceValues {
		var service ComposeService
		if err := json.Unmarshal(value, &service); err != nil {
			return ValidationError(fmt.Sprintf("compose.services.%s: %v", name, qualifyComposeFieldError(err, "services."+name)))
		}
		services[name] = service
	}

	networks := map[string]ComposeNetwork{}
	if value, ok := raw["networks"]; ok {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(value, &values); err != nil {
			return ValidationError(fmt.Sprintf("compose.networks: %v", err))
		}
		for name, item := range values {
			var network ComposeNetwork
			if err := json.Unmarshal(item, &network); err != nil {
				return ValidationError(fmt.Sprintf("compose.networks.%s: %v", name, qualifyComposeFieldError(err, "networks."+name)))
			}
			networks[name] = network
		}
	}

	volumes := map[string]ComposeVolume{}
	if value, ok := raw["volumes"]; ok {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(value, &values); err != nil {
			return ValidationError(fmt.Sprintf("compose.volumes: %v", err))
		}
		for name, item := range values {
			var volume ComposeVolume
			if err := json.Unmarshal(item, &volume); err != nil {
				return ValidationError(fmt.Sprintf("compose.volumes.%s: %v", name, qualifyComposeFieldError(err, "volumes."+name)))
			}
			volumes[name] = volume
		}
	}
	*f = ComposeFile{Version: version, Services: services, Networks: networks, Volumes: volumes}
	return nil
}

func (f ComposeFile) Validate() error {
	if len(f.Services) == 0 {
		return ValidationError("compose must contain at least one service")
	}
	for name, service := range f.Services {
		if strings.TrimSpace(name) == "" {
			return ValidationError("compose service name is required")
		}
		if err := service.Validate(); err != nil {
			return fmt.Errorf("compose service %q: %w", name, err)
		}
		for _, network := range service.Networks {
			if len(f.Networks) > 0 {
				if _, ok := f.Networks[network]; !ok {
					return ValidationError(fmt.Sprintf("compose service %q references unknown network %q", name, network))
				}
			}
		}
		for _, volume := range service.Volumes {
			if len(f.Volumes) > 0 {
				if _, ok := f.Volumes[volume.Source]; !ok {
					return ValidationError(fmt.Sprintf("compose service %q references unknown volume %q", name, volume.Source))
				}
			}
		}
	}
	return nil
}

func (s ComposeService) Validate() error {
	imageSet := strings.TrimSpace(s.Image) != ""
	buildSet := s.Build != nil
	if imageSet == buildSet {
		return ValidationError("compose service must specify exactly one of image or build")
	}
	if s.Build != nil {
		if strings.TrimSpace(s.Build.Context) == "" {
			return ValidationError("compose build context is required")
		}
		if strings.HasPrefix(s.Build.Context, "/") || strings.Contains(s.Build.Context, "..") {
			return ValidationError("compose build context must stay inside the source workspace")
		}
	}
	for _, port := range s.Ports {
		if port.Target < 1 || port.Target > 65535 {
			return ValidationError("compose port target must be between 1 and 65535")
		}
		if port.Published != 0 {
			return ValidationError("compose published host ports are not allowed")
		}
		if strings.TrimSpace(port.HostIP) != "" {
			return ValidationError("compose host IP bindings are not allowed")
		}
		if protocol := strings.ToLower(strings.TrimSpace(port.Protocol)); protocol != "" && protocol != "tcp" && protocol != "udp" {
			return ValidationError("compose port protocol is unsupported")
		}
	}
	for _, volume := range s.Volumes {
		if strings.TrimSpace(volume.Type) != "" && strings.TrimSpace(volume.Type) != "volume" {
			return ValidationError("compose bind/device volume types are not allowed")
		}
		if strings.TrimSpace(volume.Source) == "" || strings.HasPrefix(volume.Source, "/") || strings.Contains(volume.Source, "..") {
			return ValidationError("compose volume source must be a named volume")
		}
		if strings.TrimSpace(volume.Target) == "" || !strings.HasPrefix(volume.Target, "/") {
			return ValidationError("compose volume target must be absolute")
		}
	}
	for service, dependency := range s.DependsOn {
		if strings.TrimSpace(service) == "" {
			return ValidationError("compose dependency service name is required")
		}
		if _, err := composeDependencyCondition(dependency.Condition); err != nil {
			return err
		}
	}
	if s.Healthcheck != nil {
		if err := s.Healthcheck.Validate(); err != nil {
			return err
		}
	}
	if s.Restart != "" && !validRestartPolicy(s.Restart) {
		return ValidationError("compose restart policy is unsupported")
	}
	if s.Resources != nil {
		if err := s.Resources.Validate(); err != nil {
			return err
		}
	}
	if s.Deploy != nil && s.Deploy.Resources != nil && s.Deploy.Resources.Limits != nil {
		if s.Resources != nil {
			return ValidationError("compose resources must use one supported form")
		}
		if err := s.Deploy.Resources.Limits.Validate(); err != nil {
			return err
		}
	}
	for _, network := range s.Networks {
		if strings.TrimSpace(network) == "" {
			return ValidationError("compose network name is required")
		}
	}
	if s.Privileged != nil || s.NetworkMode != nil || s.PID != nil || s.IPC != nil || s.UTS != nil || len(s.Devices) > 0 || len(s.CapAdd) > 0 || len(s.CapDrop) > 0 {
		return ValidationError("compose service contains a forbidden privileged/host capability")
	}
	return nil
}

func (r ComposeResourceLimits) Validate() error {
	if strings.TrimSpace(r.CPUs) == "" && strings.TrimSpace(r.Memory) == "" {
		return ValidationError("compose resource limits must contain cpu or memory")
	}
	if strings.HasPrefix(strings.TrimSpace(r.CPUs), "-") || strings.HasPrefix(strings.TrimSpace(r.Memory), "-") {
		return ValidationError("compose resource limits must not be negative")
	}
	return nil
}

func (h ComposeHealthcheck) Validate() error {
	if h.Disable {
		return nil
	}
	if len(h.Test) == 0 {
		return ValidationError("compose healthcheck test is required unless disabled")
	}
	if h.Retries < 0 {
		return ValidationError("compose healthcheck retries must not be negative")
	}
	if _, err := parseComposeDurationSeconds(h.Interval); err != nil {
		return err
	}
	if _, err := parseComposeDurationSeconds(h.Timeout); err != nil {
		return err
	}
	if _, err := parseComposeDurationSeconds(h.StartPeriod); err != nil {
		return err
	}
	return nil
}

func composeDependencyCondition(condition string) (DependencyCondition, error) {
	switch strings.ToLower(strings.TrimSpace(condition)) {
	case "started", "service_started":
		return DependsStarted, nil
	case "healthy", "service_healthy":
		return DependsHealthy, nil
	case "completed", "service_completed_successfully":
		return DependsCompleted, nil
	default:
		return "", ValidationError("compose dependency condition is unsupported")
	}
}

func parseComposeDurationSeconds(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasSuffix(value, "ms") {
		return 0, ValidationError("compose healthcheck millisecond durations are below the supported precision")
	}
	if strings.HasSuffix(value, "s") {
		var seconds int
		if _, err := fmt.Sscanf(strings.TrimSuffix(value, "s"), "%d", &seconds); err != nil || seconds < 0 {
			return 0, ValidationError("compose healthcheck duration is invalid")
		}
		return seconds, nil
	}
	return 0, ValidationError("compose healthcheck duration must use seconds")
}

func parseComposeMemory(value string) (int64, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		factor int64
	}{
		{"gib", 1024 * 1024 * 1024},
		{"gb", 1000 * 1000 * 1000},
		{"mib", 1024 * 1024},
		{"mb", 1000 * 1000},
		{"kib", 1024},
		{"kb", 1000},
		{"b", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			var amount int64
			if _, err := fmt.Sscanf(strings.TrimSpace(strings.TrimSuffix(value, unit.suffix)), "%d", &amount); err != nil || amount < 0 {
				return 0, ValidationError("compose memory limit is invalid")
			}
			return amount * unit.factor, nil
		}
	}
	return 0, ValidationError("compose memory limit must use a supported unit")
}

func parseComposeCPU(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	var millis int64
	if strings.HasSuffix(value, "m") {
		if _, err := fmt.Sscanf(strings.TrimSuffix(value, "m"), "%d", &millis); err != nil || millis < 0 {
			return 0, ValidationError("compose cpu limit is invalid")
		}
		return millis, nil
	}
	var whole int64
	if _, err := fmt.Sscanf(value, "%d", &whole); err != nil || whole < 0 {
		return 0, ValidationError("compose cpu limit must be an integer number of cores or millicores")
	}
	return whole * 1000, nil
}

func parseComposeImage(value string) (ImageDigest, error) {
	value = strings.TrimSpace(value)
	marker := "@sha256:"
	index := strings.LastIndex(value, marker)
	if index <= 0 {
		return ImageDigest{}, ValidationError("compose prebuilt image reference is empty or malformed")
	}
	return ParseImageDigest(value[:index], value[index+1:])
}

func parseComposePrebuiltSource(value string) (PrebuiltSource, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return PrebuiltSource{}, ValidationError("compose prebuilt image reference is invalid")
	}
	if strings.Contains(value, "@sha256:") {
		image, err := parseComposeImage(value)
		if err != nil {
			return PrebuiltSource{}, err
		}
		return PrebuiltSource{Image: image}, nil
	}
	return PrebuiltSource{Reference: value}, nil
}

func (h ComposeHealthcheck) ToDomain() (HealthcheckSpec, error) {
	test := append([]string(nil), h.Test...)
	domain := HealthcheckSpec{Test: test, Disabled: h.Disable || (len(test) == 1 && strings.EqualFold(strings.TrimSpace(test[0]), "none")), Retries: h.Retries}
	var err error
	if domain.IntervalSeconds, err = parseComposeDurationSeconds(h.Interval); err != nil {
		return HealthcheckSpec{}, err
	}
	if domain.TimeoutSeconds, err = parseComposeDurationSeconds(h.Timeout); err != nil {
		return HealthcheckSpec{}, err
	}
	if domain.StartPeriodSeconds, err = parseComposeDurationSeconds(h.StartPeriod); err != nil {
		return HealthcheckSpec{}, err
	}
	if err := domain.Validate(); err != nil {
		return HealthcheckSpec{}, err
	}
	return domain, nil
}

func (s ComposeService) ToServiceSpec(name string) (ServiceSpec, []string, error) {
	if err := s.Validate(); err != nil {
		return ServiceSpec{}, nil, err
	}
	spec := ServiceSpec{Name: strings.TrimSpace(name), Role: RoleWorker, Required: true, Command: append([]string(nil), s.Command...), Entrypoint: append([]string(nil), s.Entrypoint...), Networks: append([]string(nil), s.Networks...), Restart: strings.TrimSpace(s.Restart)}
	mapped := []string{}
	if len(s.Environment) > 0 {
		spec.Environment = make(map[string]string, len(s.Environment))
		for key, value := range s.Environment {
			spec.Environment[key] = value
		}
		mapped = append(mapped, "environment")
	}
	if len(s.Command) > 0 {
		mapped = append(mapped, "command")
	}
	if len(s.Entrypoint) > 0 {
		mapped = append(mapped, "entrypoint")
	}
	if len(s.Ports) > 0 {
		spec.Role = RoleIngress
		spec.Ports = make([]int, 0, len(s.Ports))
		for _, port := range s.Ports {
			spec.Ports = append(spec.Ports, port.Target)
		}
		spec.Port = spec.Ports[0]
		mapped = append(mapped, "ports")
	}
	if len(s.Volumes) > 0 {
		spec.Volumes = make([]VolumeMount, 0, len(s.Volumes))
		for _, volume := range s.Volumes {
			spec.Volumes = append(spec.Volumes, VolumeMount{Name: volume.Source, MountPath: volume.Target, ReadOnly: volume.ReadOnly})
		}
		mapped = append(mapped, "volumes")
		if spec.Role != RoleIngress {
			for _, volume := range spec.Volumes {
				if !volume.ReadOnly {
					spec.Role = RoleStateful
					break
				}
			}
		}
	}
	if len(s.DependsOn) > 0 {
		keys := make([]string, 0, len(s.DependsOn))
		for service := range s.DependsOn {
			keys = append(keys, service)
		}
		sort.Strings(keys)
		for _, service := range keys {
			condition, err := composeDependencyCondition(s.DependsOn[service].Condition)
			if err != nil {
				return ServiceSpec{}, nil, err
			}
			spec.Dependencies = append(spec.Dependencies, ServiceDependency{Service: service, Condition: condition})
		}
		mapped = append(mapped, "depends_on")
	}
	if s.Healthcheck != nil {
		healthcheck, err := s.Healthcheck.ToDomain()
		if err != nil {
			return ServiceSpec{}, nil, err
		}
		spec.Healthcheck = &healthcheck
		mapped = append(mapped, "healthcheck")
	}
	if s.Restart != "" {
		mapped = append(mapped, "restart")
	}
	if limits := s.Resources; limits != nil {
		cpu, err := parseComposeCPU(limits.CPUs)
		if err != nil {
			return ServiceSpec{}, nil, err
		}
		memory, err := parseComposeMemory(limits.Memory)
		if err != nil {
			return ServiceSpec{}, nil, err
		}
		spec.Resources = ResourceLimits{CPUMillis: cpu, MemoryBytes: memory}
		mapped = append(mapped, "resources")
	} else if s.Deploy != nil && s.Deploy.Resources != nil && s.Deploy.Resources.Limits != nil {
		limits := s.Deploy.Resources.Limits
		cpu, err := parseComposeCPU(limits.CPUs)
		if err != nil {
			return ServiceSpec{}, nil, err
		}
		memory, err := parseComposeMemory(limits.Memory)
		if err != nil {
			return ServiceSpec{}, nil, err
		}
		spec.Resources = ResourceLimits{CPUMillis: cpu, MemoryBytes: memory}
		mapped = append(mapped, "deploy.resources")
	}
	if len(s.Networks) > 0 {
		mapped = append(mapped, "networks")
	}
	if strings.TrimSpace(s.Image) != "" {
		prebuilt, err := parseComposePrebuiltSource(s.Image)
		if err != nil {
			return ServiceSpec{}, nil, err
		}
		spec.Source = ServiceSource{Kind: ServicePrebuilt, Prebuilt: &prebuilt}
		mapped = append(mapped, "image")
	} else {
		dockerfile := strings.TrimSpace(s.Build.Dockerfile)
		if dockerfile == "" {
			dockerfile = "Dockerfile"
		}
		spec.Source = ServiceSource{Kind: ServiceDockerfile, Dockerfile: &DockerfileSource{Context: strings.TrimSpace(s.Build.Context), Dockerfile: dockerfile}}
		mapped = append(mapped, "build.context", "build.dockerfile")
	}
	if err := spec.Validate(); err != nil {
		return ServiceSpec{}, nil, err
	}
	sort.Strings(mapped)
	return spec, mapped, nil
}

// ToServiceGroup converts a validated Compose document into the controlled
// ServiceGroup model.  It never preserves arbitrary Compose fields.
func (f ComposeFile) ToServiceGroup(applicationID ID, name string, now time.Time) (ServiceGroup, ComposeImportReport, error) {
	if err := RequireID(applicationID, "compose application id"); err != nil {
		return ServiceGroup{}, ComposeImportReport{}, err
	}
	if err := f.Validate(); err != nil {
		return ServiceGroup{}, ComposeImportReport{}, err
	}
	id, err := NewID("group")
	if err != nil {
		return ServiceGroup{}, ComposeImportReport{}, WrapError(ErrUnavailable, "generate compose service group id", err)
	}
	serviceNames := make([]string, 0, len(f.Services))
	for service := range f.Services {
		serviceNames = append(serviceNames, service)
	}
	sort.Strings(serviceNames)
	group := ServiceGroup{ID: id, ApplicationID: applicationID, Name: strings.TrimSpace(name), CreatedAt: now.UTC()}
	if group.Name == "" {
		group.Name = "compose"
	}
	report := ComposeImportReport{}
	for _, serviceName := range serviceNames {
		spec, mapped, err := f.Services[serviceName].ToServiceSpec(serviceName)
		if err != nil {
			return ServiceGroup{}, report, fmt.Errorf("compose service %q: %w", serviceName, err)
		}
		group.Services = append(group.Services, spec)
		for _, field := range mapped {
			report.MappedFields = append(report.MappedFields, "services."+serviceName+"."+field)
		}
	}
	serviceIndexes := make(map[string]int, len(group.Services))
	for index := range group.Services {
		serviceIndexes[group.Services[index].Name] = index
	}
	for _, service := range group.Services {
		for _, dependency := range service.Dependencies {
			if dependency.Condition != DependsCompleted {
				continue
			}
			index := serviceIndexes[dependency.Service]
			target := &group.Services[index]
			if target.Role != RoleWorker || len(target.Volumes) > 0 || len(target.Ports) > 0 {
				return ServiceGroup{}, report, ValidationError("completed Compose dependency target must be a volume-free non-ingress one-shot service")
			}
			target.Role = RoleOneShot
		}
	}
	sort.Strings(report.MappedFields)
	if err := group.Validate(); err != nil {
		return ServiceGroup{}, report, err
	}
	return group, report, nil
}

// DecodeComposeJSON provides a strict, no-dependency JSON entry point for
// tests and adapters that already parsed YAML into JSON-shaped data.
func DecodeComposeJSON(data []byte) (ComposeFile, error) {
	var file ComposeFile
	if err := json.Unmarshal(data, &file); err != nil {
		return ComposeFile{}, err
	}
	if err := file.Validate(); err != nil {
		return ComposeFile{}, err
	}
	return file, nil
}

// AIAction.Validate enforces the action-level contract before any catalog or
// runner is consulted.  The catalog decides whether a particular tool is
// allowed; this gate only ensures the plan is structurally complete.
func (a AIAction) Validate() error {
	if strings.TrimSpace(a.ToolID) == "" {
		return ValidationError("AI action tool id is required")
	}
	if strings.TrimSpace(a.ToolVersion) == "" {
		return ValidationError("AI action tool version is required")
	}
	if !ValidAIRisk(a.Risk) {
		return ValidationError("AI action risk must be R0, R1, R2, or R3")
	}
	if strings.TrimSpace(a.ExpectedResult) == "" {
		return ValidationError("AI action expected result is required")
	}
	if strings.TrimSpace(a.ValidationID) == "" {
		return ValidationError("AI action validation id is required")
	}
	return nil
}

const (
	AIRiskReadOnly          = "R0"
	AIRiskSandboxValidation = "R1"
	AIRiskCandidateChange   = "R2"
	AIRiskProductionChange  = "R3"
)

func ValidAIRisk(value string) bool {
	switch strings.TrimSpace(value) {
	case AIRiskReadOnly, AIRiskSandboxValidation, AIRiskCandidateChange, AIRiskProductionChange:
		return true
	default:
		return false
	}
}

func (c AIContextPackage) Validate() error {
	if err := RequireID(c.ID, "AI context id"); err != nil {
		return err
	}
	if err := RequireID(c.ApplicationID, "AI context application id"); err != nil {
		return err
	}
	if strings.TrimSpace(c.TaskType) == "" || strings.TrimSpace(c.Profile) == "" || strings.TrimSpace(c.TemplateVersion) == "" {
		return ValidationError("AI context task type, profile, and template version are required")
	}
	if len(c.Scope) == 0 || len(c.ObjectVersions) == 0 || len(c.SourceRefs) == 0 {
		return ValidationError("AI context scope, object versions, and source refs are required")
	}
	if !c.Authorized || !c.Redacted || !c.UntrustedData {
		return ValidationError("AI context must be authorized, redacted, and mark repository/log content as untrusted data")
	}
	if c.Bytes <= 0 || strings.TrimSpace(c.ManifestDigest) == "" {
		return ValidationError("AI context byte count and manifest digest are required")
	}
	for _, ref := range c.SourceRefs {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("AI context source ref: %w", err)
		}
	}
	return nil
}

func (p AIActionPlan) Validate() error {
	if err := RequireID(p.ID, "AI action plan id"); err != nil {
		return err
	}
	if strings.TrimSpace(p.TaskType) == "" {
		return ValidationError("AI action plan task type is required")
	}
	if strings.TrimSpace(p.SchemaVersion) != "1.0" || strings.TrimSpace(p.PolicyVersion) == "" {
		return ValidationError("AI action plan schema 1.0 and policy version are required")
	}
	if len(p.TargetRefs) == 0 {
		return ValidationError("AI action plan target refs are required")
	}
	for key, value := range p.TargetRefs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return ValidationError("AI action plan target refs must not contain empty keys or values")
		}
	}
	if len(p.EvidenceRefs) == 0 {
		return ValidationError("AI action plan evidence refs are required")
	}
	if len(p.Sources) == 0 {
		return ValidationError("AI action plan sources are required")
	}
	for _, source := range p.Sources {
		if strings.TrimSpace(source) == "" {
			return ValidationError("AI action plan sources must not contain empty values")
		}
	}
	for _, evidence := range p.EvidenceRefs {
		if err := evidence.Validate(); err != nil {
			return fmt.Errorf("AI action plan evidence: %w", err)
		}
	}
	if len(p.Actions) == 0 {
		return ValidationError("AI action plan must contain at least one action")
	}
	for _, action := range p.Actions {
		if err := action.Validate(); err != nil {
			return err
		}
	}
	if p.Budget.MaxTokens <= 0 || p.Budget.MaxDurationMS <= 0 || p.Budget.MaxActions <= 0 || len(p.Actions) > p.Budget.MaxActions {
		return ValidationError("AI action plan token, duration, and action budgets are required and must bound all actions")
	}
	requiresConfirmation := false
	requiresRollback := false
	for _, action := range p.Actions {
		if action.Risk == AIRiskCandidateChange || action.Risk == AIRiskProductionChange {
			requiresConfirmation = true
		}
		if action.Risk == AIRiskSandboxValidation || action.Risk == AIRiskCandidateChange {
			requiresRollback = true
		}
	}
	if requiresConfirmation && !p.RequiresUserConfirmation {
		return ValidationError("R2/R3 AI action plan requires explicit user confirmation")
	}
	if requiresRollback && strings.TrimSpace(p.RollbackID) == "" {
		return ValidationError("R1/R2 AI action plan requires a rollback id")
	}
	if math.IsNaN(p.Confidence) || math.IsInf(p.Confidence, 0) || p.Confidence < 0 || p.Confidence > 1 {
		return ValidationError("AI action plan confidence must be between 0 and 1")
	}
	return nil
}

const (
	RuleCandidateProposed = "proposed"
	RuleCandidateTesting  = "testing"
	RuleCandidateReviewed = "reviewed"
	RuleCandidateShadow   = "shadow"
	RuleCandidateApproved = "approved"
	RuleCandidateRejected = "rejected"
	RuleCandidatePromoted = "promoted"
	RuleCandidateActive   = "active" // reserved and deliberately invalid
)

// Aliases make status usage explicit at call sites without changing the
// serialized string field kept by the original domain object.
const (
	RuleCandidateStatusProposed = RuleCandidateProposed
	RuleCandidateStatusTesting  = RuleCandidateTesting
	RuleCandidateStatusReviewed = RuleCandidateReviewed
	RuleCandidateStatusShadow   = RuleCandidateShadow
	RuleCandidateStatusApproved = RuleCandidateApproved
	RuleCandidateStatusRejected = RuleCandidateRejected
	RuleCandidateStatusPromoted = RuleCandidatePromoted
)

func (c RuleCandidate) Validate() error {
	if err := RequireID(c.ID, "rule candidate id"); err != nil {
		return err
	}
	if strings.TrimSpace(c.Fingerprint) == "" {
		return ValidationError("rule candidate fingerprint is required")
	}
	switch strings.TrimSpace(c.Status) {
	case RuleCandidateProposed, RuleCandidateTesting, RuleCandidateReviewed, RuleCandidateShadow, RuleCandidateApproved, RuleCandidateRejected, RuleCandidatePromoted:
	default:
		return ValidationError("rule candidate status is unsupported; active is not a candidate state")
	}
	if c.SuccessCount < 2 || c.ApplicationCount < 1 {
		return ValidationError("rule candidate requires repeated successful cases")
	}
	for _, evidence := range c.TestEvidence {
		if err := evidence.Validate(); err != nil {
			return fmt.Errorf("rule candidate test evidence: %w", err)
		}
	}
	if (c.Status == RuleCandidateReviewed || c.Status == RuleCandidateShadow || c.Status == RuleCandidateApproved || c.Status == RuleCandidatePromoted) && (len(c.TestEvidence) == 0 || !c.RegressionPassed) {
		return ValidationError("reviewed rule candidate requires passed regression evidence")
	}
	if (c.Status == RuleCandidateReviewed || c.Status == RuleCandidateShadow || c.Status == RuleCandidateApproved || c.Status == RuleCandidatePromoted) && (strings.TrimSpace(c.ReviewedBy) == "" || c.ReviewDecision != "approved") {
		return ValidationError("approved rule candidate requires a reviewer")
	}
	if (c.Status == RuleCandidateApproved || c.Status == RuleCandidatePromoted) && (!c.ShadowPassed || strings.TrimSpace(c.ProposedVersion) == "") {
		return ValidationError("approved rule candidate requires passed shadow validation and a proposed version")
	}
	return nil
}

func (c RuleCandidate) CanPromote() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Status != RuleCandidateApproved {
		return ValidationError("rule candidate requires approval before promotion")
	}
	if len(c.TestEvidence) == 0 || strings.TrimSpace(c.ReviewedBy) == "" || !c.RegressionPassed || !c.ShadowPassed || c.ReviewDecision != "approved" {
		return ValidationError("rule candidate promotion requires review, regression, and shadow evidence")
	}
	return nil
}

func validRuleCandidateStatus(status string) bool {
	switch status {
	case RuleCandidateProposed, RuleCandidateTesting, RuleCandidateReviewed, RuleCandidateShadow, RuleCandidateApproved, RuleCandidateRejected, RuleCandidatePromoted:
		return true
	default:
		return false
	}
}

func (c RuleCandidate) CanTransition(to string) bool {
	if !validRuleCandidateStatus(c.Status) || !validRuleCandidateStatus(to) {
		return false
	}
	switch c.Status {
	case RuleCandidateProposed:
		return to == RuleCandidateTesting || to == RuleCandidateRejected
	case RuleCandidateTesting:
		return to == RuleCandidateReviewed || to == RuleCandidateRejected
	case RuleCandidateReviewed:
		return to == RuleCandidateShadow || to == RuleCandidateRejected
	case RuleCandidateShadow:
		return to == RuleCandidateApproved || to == RuleCandidateRejected
	case RuleCandidateApproved:
		return to == RuleCandidatePromoted
	default:
		return false
	}
}

func (c *RuleCandidate) Transition(to string) error {
	if c == nil {
		return ValidationError("rule candidate is nil")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if !c.CanTransition(to) {
		return TransitionError("rule_candidate", c.Status, to)
	}
	if to == RuleCandidateReviewed || to == RuleCandidateShadow || to == RuleCandidateApproved {
		candidate := *c
		candidate.Status = to
		if err := candidate.Validate(); err != nil {
			return err
		}
	}
	c.Status = to
	return nil
}

// Promote is the only domain path that creates an enabled DeterministicRule.
// The optional reviewer argument supports both callers that set ReviewedBy
// while collecting evidence and callers that supply it at promotion time.
func (c *RuleCandidate) Promote(version string, reviewer ...string) (DeterministicRule, error) {
	if c == nil {
		return DeterministicRule{}, ValidationError("rule candidate is nil")
	}
	if len(reviewer) > 0 && strings.TrimSpace(reviewer[0]) != "" {
		c.ReviewedBy = strings.TrimSpace(reviewer[0])
	}
	if err := c.CanPromote(); err != nil {
		return DeterministicRule{}, err
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return DeterministicRule{}, ValidationError("deterministic rule version is required")
	}
	if c.ProposedVersion != version {
		return DeterministicRule{}, ValidationError("deterministic rule version must match the reviewed candidate version")
	}
	id, err := NewID("rule")
	if err != nil {
		return DeterministicRule{}, WrapError(ErrUnavailable, "generate deterministic rule id", err)
	}
	c.Status = RuleCandidatePromoted
	rule := DeterministicRule{ID: id, CandidateID: c.ID, Version: version, Enabled: true, ShadowVerified: true, ReviewedBy: c.ReviewedBy}
	if err := rule.Validate(); err != nil {
		return DeterministicRule{}, err
	}
	return rule, nil
}

func (r DeterministicRule) Validate() error {
	if err := RequireID(r.ID, "deterministic rule id"); err != nil {
		return err
	}
	if err := RequireID(r.CandidateID, "deterministic rule candidate id"); err != nil {
		return err
	}
	if strings.TrimSpace(r.Version) == "" {
		return ValidationError("deterministic rule version is required")
	}
	if !r.ShadowVerified || strings.TrimSpace(r.ReviewedBy) == "" {
		return ValidationError("deterministic rule requires shadow verification and reviewer")
	}
	return nil
}

// NewDeterministicRule keeps construction behind the promotion gate.  Direct
// struct literals remain useful for deserialization, but Validate alone cannot
// establish that a candidate was reviewed; callers creating a new rule must
// use this constructor or RuleCandidate.Promote.
func NewDeterministicRule(candidate RuleCandidate, version string) (DeterministicRule, error) {
	return candidate.Promote(version)
}
