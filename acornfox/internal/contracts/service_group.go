package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/acornfox/acornfox/internal/domain"
)

const (
	CapabilityRuntimeDeployGroup         Capability = "runtime.deploy_group"
	CapabilityRuntimeObserveGroup        Capability = "runtime.observe_group"
	CapabilityRuntimeLogsGroup           Capability = "runtime.logs_group"
	CapabilityRuntimeRollbackGroup       Capability = "runtime.rollback_group"
	CapabilityRuntimeDestroyGroup        Capability = "runtime.destroy_group"
	CapabilityRuntimeRestartGroupService Capability = "runtime.restart_group_service"
	CapabilityRuntimeRestartGroup        Capability = "runtime.restart_group"
	ServiceGroupRuntimeSchema            string     = "1"
)

// ServiceRuntimeSpec is the resolved, digest-only execution contract sent to
// a node. Source locations, tags, Compose extensions and host paths are
// deliberately absent: controllers must resolve them before dispatch.
type ServiceRuntimeSpec struct {
	Name           string                       `json:"name"`
	Role           domain.ServiceRole           `json:"role"`
	Required       bool                         `json:"required"`
	Image          domain.ImageDigest           `json:"image"`
	Resources      ResourceLimits               `json:"resources"`
	Volumes        []domain.VolumeMount         `json:"volumes,omitempty"`
	Dependencies   []domain.ServiceDependency   `json:"dependencies,omitempty"`
	Entrypoint     []string                     `json:"entrypoint,omitempty"`
	Command        []string                     `json:"command,omitempty"`
	Environment    []RuntimeEnvironmentVariable `json:"environment,omitempty"`
	ContainerPorts []int                        `json:"container_ports,omitempty"`
	Healthcheck    *domain.HealthcheckSpec      `json:"healthcheck,omitempty"`
	Restart        string                       `json:"restart,omitempty"`
}

type RuntimeVolumeClaim struct {
	ID        domain.ID `json:"id"`
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	Retain    bool      `json:"retain"`
}

type RuntimeEnvironmentKind string

const (
	RuntimeEnvironmentLiteral RuntimeEnvironmentKind = "literal"
	RuntimeEnvironmentSecret  RuntimeEnvironmentKind = "secret_ref"
)

type RuntimeEnvironmentVariable struct {
	Name      string                  `json:"name"`
	Kind      RuntimeEnvironmentKind  `json:"kind"`
	Value     string                  `json:"value,omitempty"`
	SecretRef *domain.SecretReference `json:"secret_ref,omitempty"`
}

func (v RuntimeEnvironmentVariable) Validate() error {
	if strings.TrimSpace(v.Name) == "" || strings.ContainsAny(v.Name, "=\r\n\x00") {
		return domain.ValidationError("runtime environment name is invalid")
	}
	switch v.Kind {
	case RuntimeEnvironmentLiteral:
		if v.SecretRef != nil || strings.Contains(v.Value, "\x00") {
			return domain.ValidationError("literal runtime environment value is invalid")
		}
		if v.Value != "" && runtimeEnvironmentNameIsSensitive(v.Name) {
			return domain.ValidationError("sensitive runtime environment values require a SecretReference")
		}
	case RuntimeEnvironmentSecret:
		if v.SecretRef == nil || v.Value != "" {
			return domain.ValidationError("secret runtime environment requires only a secret reference")
		}
		if err := v.SecretRef.Validate(); err != nil {
			return err
		}
	default:
		return domain.ValidationError("runtime environment kind is unsupported")
	}
	return nil
}

func runtimeEnvironmentNameIsSensitive(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	for _, marker := range []string{"TOKEN", "PASSWORD", "SECRET", "COOKIE", "AUTHORIZATION", "API_KEY", "PRIVATE_KEY"} {
		if upper == marker || strings.HasPrefix(upper, marker+"_") || strings.HasSuffix(upper, "_"+marker) || strings.Contains(upper, "_"+marker+"_") {
			return true
		}
	}
	return false
}

func (s ServiceRuntimeSpec) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return domain.ValidationError("runtime service name is required")
	}
	if s.Role != domain.RoleIngress && s.Role != domain.RoleWorker && s.Role != domain.RoleStateful && s.Role != domain.RoleOneShot {
		return domain.ValidationError("runtime service role is unsupported")
	}
	if err := s.Image.Validate(); err != nil {
		return err
	}
	if s.Resources.CPUMillis <= 0 || s.Resources.MemoryBytes <= 0 || s.Resources.DiskBytes <= 0 || s.Resources.PIDs <= 0 {
		return domain.ValidationError("runtime service CPU, memory, disk and PID limits must be positive")
	}
	seenPorts := make(map[int]struct{}, len(s.ContainerPorts))
	for _, port := range s.ContainerPorts {
		if port < 1 || port > 65535 {
			return domain.ValidationError("runtime service ports must be between 1 and 65535")
		}
		if _, exists := seenPorts[port]; exists {
			return domain.ValidationError("runtime service ports must be unique")
		}
		seenPorts[port] = struct{}{}
	}
	if s.Role == domain.RoleIngress && len(s.ContainerPorts) == 0 {
		return domain.ValidationError("ingress runtime service requires a container port")
	}
	seenVolumes := make(map[string]struct{}, len(s.Volumes))
	for _, volume := range s.Volumes {
		if err := volume.Validate(); err != nil {
			return err
		}
		mountPath := strings.TrimRight(volume.MountPath, "/")
		if mountPath == "/var/run/docker.sock" || mountPath == "/run/docker.sock" {
			return domain.ValidationError("runtime service cannot mount over the Docker socket path")
		}
		if _, exists := seenVolumes[mountPath]; exists {
			return domain.ValidationError("runtime service volume mount paths must be unique")
		}
		seenVolumes[mountPath] = struct{}{}
	}
	seenDependencies := make(map[string]struct{}, len(s.Dependencies))
	for _, dependency := range s.Dependencies {
		name := strings.TrimSpace(dependency.Service)
		if name == "" || name == s.Name {
			return domain.ValidationError("runtime service dependency target is invalid")
		}
		if dependency.Condition != domain.DependsStarted && dependency.Condition != domain.DependsHealthy && dependency.Condition != domain.DependsCompleted {
			return domain.ValidationError("runtime service dependency condition is unsupported")
		}
		if _, exists := seenDependencies[name]; exists {
			return domain.ValidationError("runtime service dependencies must be unique")
		}
		seenDependencies[name] = struct{}{}
	}
	seenEnvironment := make(map[string]struct{}, len(s.Environment))
	for _, variable := range s.Environment {
		if err := variable.Validate(); err != nil {
			return err
		}
		if _, exists := seenEnvironment[variable.Name]; exists {
			return domain.ValidationError("runtime environment names must be unique")
		}
		seenEnvironment[variable.Name] = struct{}{}
	}
	if s.Healthcheck != nil {
		if err := s.Healthcheck.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ServiceGroupRuntimeSpec freezes one complete Release combination. All
// services are dispatched together; partial digest sets are invalid.
type ServiceGroupRuntimeSpec struct {
	SchemaVersion  string               `json:"schema_version"`
	ApplicationID  domain.ID            `json:"application_id"`
	EnvironmentID  domain.ID            `json:"environment_id"`
	ReleaseID      domain.ID            `json:"release_id"`
	ServiceGroupID domain.ID            `json:"service_group_id"`
	ConfigDigest   string               `json:"config_digest"`
	EntryService   string               `json:"entry_service"`
	Services       []ServiceRuntimeSpec `json:"services"`
	VolumeClaims   []RuntimeVolumeClaim `json:"volume_claims,omitempty"`
	Rollout        RuntimeRolloutPolicy `json:"rollout"`
}

// DecodeServiceGroupRuntimeSpec is the strict Agent/controller boundary. It
// rejects unknown fields and trailing values instead of relying on a lenient
// generic JSON unmarshal at a security-sensitive runtime boundary.
func DecodeServiceGroupRuntimeSpec(data []byte) (ServiceGroupRuntimeSpec, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var spec ServiceGroupRuntimeSpec
	if err := decoder.Decode(&spec); err != nil {
		return ServiceGroupRuntimeSpec{}, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ServiceGroupRuntimeSpec{}, domain.ValidationError("runtime service group contains trailing JSON values")
	}
	if err := spec.Validate(); err != nil {
		return ServiceGroupRuntimeSpec{}, err
	}
	return spec, nil
}

type RuntimeRolloutMode string

const (
	RuntimeRolloutInitial  RuntimeRolloutMode = "initial"
	RuntimeRolloutRolling  RuntimeRolloutMode = "rolling"
	RuntimeRolloutRecreate RuntimeRolloutMode = "recreate"
)

type RuntimeRolloutPolicy struct {
	Mode                    RuntimeRolloutMode `json:"mode"`
	PreviousDeploymentID    domain.ID          `json:"previous_deployment_id,omitempty"`
	PreserveOldUntilHealthy bool               `json:"preserve_old_until_healthy"`
	// DeferOldTeardown is a control-plane-only handoff. A RuntimeDriver may
	// create and health-check the candidate, but it must not stop the previous
	// group until the RouteProvider has durably confirmed the new route is
	// serving and its observation window has passed.
	DeferOldTeardown bool `json:"defer_old_teardown"`
	DowntimeApproved bool `json:"downtime_approved"`
}

func (s ServiceGroupRuntimeSpec) Validate() error {
	ids := []struct {
		name string
		id   domain.ID
	}{
		{name: "application", id: s.ApplicationID},
		{name: "environment", id: s.EnvironmentID},
		{name: "release", id: s.ReleaseID},
		{name: "service group", id: s.ServiceGroupID},
	}
	for _, value := range ids {
		if err := domain.RequireID(value.id, value.name+" id"); err != nil {
			return err
		}
	}
	if !validSHA256Digest(s.ConfigDigest) {
		return domain.ValidationError("runtime service group config digest must be sha256")
	}
	if s.SchemaVersion != ServiceGroupRuntimeSchema {
		return domain.ValidationError("runtime service group schema version is unsupported")
	}
	if err := s.Rollout.Validate(); err != nil {
		return err
	}
	if len(s.Services) == 0 {
		return domain.ValidationError("runtime service group requires at least one service")
	}
	names := make(map[string]struct{}, len(s.Services))
	services := make(map[string]ServiceRuntimeSpec, len(s.Services))
	for _, service := range s.Services {
		if err := service.Validate(); err != nil {
			return err
		}
		if _, exists := names[service.Name]; exists {
			return domain.ValidationError("runtime service names must be unique")
		}
		names[service.Name] = struct{}{}
		services[service.Name] = service
	}
	entry, exists := services[s.EntryService]
	if strings.TrimSpace(s.EntryService) == "" || !exists || entry.Role != domain.RoleIngress {
		return domain.ValidationError("runtime service group entry service must name an ingress service")
	}
	claims := make(map[string]RuntimeVolumeClaim, len(s.VolumeClaims))
	claimIDs := make(map[domain.ID]struct{}, len(s.VolumeClaims))
	for _, claim := range s.VolumeClaims {
		name := strings.TrimSpace(claim.Name)
		if err := domain.RequireID(claim.ID, "runtime volume claim id"); err != nil {
			return err
		}
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || claim.SizeBytes <= 0 || !claim.Retain {
			return domain.ValidationError("runtime volume claim name and positive size are required")
		}
		if _, exists := claimIDs[claim.ID]; exists {
			return domain.ValidationError("runtime volume claim ids must be unique")
		}
		if _, exists := claims[name]; exists {
			return domain.ValidationError("runtime volume claim names must be unique")
		}
		claims[name] = claim
		claimIDs[claim.ID] = struct{}{}
	}
	for _, service := range s.Services {
		for _, volume := range service.Volumes {
			if _, exists := claims[volume.Name]; !exists {
				return domain.ValidationError("runtime service volume has no declared claim")
			}
		}
		for _, dependency := range service.Dependencies {
			target, exists := services[dependency.Service]
			if !exists {
				return domain.ValidationError("runtime service dependency target does not exist")
			}
			if dependency.Condition == domain.DependsHealthy && (target.Healthcheck == nil || target.Healthcheck.Disabled) {
				return domain.ValidationError("healthy runtime dependency requires a target healthcheck")
			}
			if dependency.Condition == domain.DependsCompleted && target.Role != domain.RoleOneShot {
				return domain.ValidationError("completed runtime dependency requires a one-shot target")
			}
		}
	}
	if _, err := s.DependencyOrder(); err != nil {
		return err
	}
	_, err := s.AggregateResources()
	return err
}

func (p RuntimeRolloutPolicy) Validate() error {
	switch p.Mode {
	case RuntimeRolloutInitial:
		if !p.PreviousDeploymentID.Empty() || p.PreserveOldUntilHealthy || p.DeferOldTeardown || p.DowntimeApproved {
			return domain.ValidationError("initial rollout cannot reference or preserve a previous deployment")
		}
	case RuntimeRolloutRolling:
		if err := domain.RequireID(p.PreviousDeploymentID, "rolling rollout previous deployment id"); err != nil {
			return err
		}
		if !p.PreserveOldUntilHealthy || p.DowntimeApproved {
			return domain.ValidationError("rolling rollout must preserve old traffic and cannot approve downtime")
		}
	case RuntimeRolloutRecreate:
		if err := domain.RequireID(p.PreviousDeploymentID, "recreate rollout previous deployment id"); err != nil {
			return err
		}
		if p.PreserveOldUntilHealthy || p.DeferOldTeardown || !p.DowntimeApproved {
			return domain.ValidationError("recreate rollout requires explicit downtime approval")
		}
	default:
		return domain.ValidationError("runtime rollout mode is unsupported")
	}
	return nil
}

func validSHA256Digest(value string) bool {
	hexValue := strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	if len(hexValue) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexValue)
	return err == nil
}

// DependencyOrder is deterministic and independent of declaration order.
func (s ServiceGroupRuntimeSpec) DependencyOrder() ([]string, error) {
	indegree := make(map[string]int, len(s.Services))
	children := make(map[string][]string, len(s.Services))
	for _, service := range s.Services {
		indegree[service.Name] = 0
	}
	for _, service := range s.Services {
		for _, dependency := range service.Dependencies {
			if _, exists := indegree[dependency.Service]; !exists {
				return nil, domain.ValidationError("runtime service dependency target does not exist")
			}
			indegree[service.Name]++
			children[dependency.Service] = append(children[dependency.Service], service.Name)
		}
	}
	queue := make([]string, 0, len(indegree))
	for name, degree := range indegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)
	order := make([]string, 0, len(indegree))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)
		sort.Strings(children[name])
		for _, child := range children[name] {
			indegree[child]--
			if indegree[child] == 0 {
				queue = append(queue, child)
				sort.Strings(queue)
			}
		}
	}
	if len(order) != len(indegree) {
		path := runtimeDependencyCycle(s.Services)
		if len(path) > 0 {
			return nil, domain.ValidationError(fmt.Sprintf("runtime service dependency graph contains cycle: %s", strings.Join(path, " -> ")))
		}
		return nil, domain.ValidationError("runtime service dependency graph contains a cycle")
	}
	return order, nil
}

func runtimeDependencyCycle(services []ServiceRuntimeSpec) []string {
	graph := make(map[string][]string, len(services))
	names := make([]string, 0, len(services))
	for _, service := range services {
		names = append(names, service.Name)
		for _, dependency := range service.Dependencies {
			graph[service.Name] = append(graph[service.Name], dependency.Service)
		}
		sort.Strings(graph[service.Name])
	}
	sort.Strings(names)
	state := make(map[string]uint8, len(names))
	position := make(map[string]int, len(names))
	stack := make([]string, 0, len(names))
	var visit func(string) []string
	visit = func(name string) []string {
		state[name] = 1
		position[name] = len(stack)
		stack = append(stack, name)
		for _, dependency := range graph[name] {
			switch state[dependency] {
			case 0:
				if cycle := visit(dependency); len(cycle) > 0 {
					return cycle
				}
			case 1:
				start := position[dependency]
				cycle := append([]string(nil), stack[start:]...)
				return append(cycle, dependency)
			}
		}
		stack = stack[:len(stack)-1]
		delete(position, name)
		state[name] = 2
		return nil
	}
	for _, name := range names {
		if state[name] == 0 {
			if cycle := visit(name); len(cycle) > 0 {
				return cycle
			}
		}
	}
	return nil
}

func (s ServiceGroupRuntimeSpec) AggregateResources() (ResourceLimits, error) {
	var total ResourceLimits
	for _, service := range s.Services {
		values := [4]*int64{&total.CPUMillis, &total.MemoryBytes, &total.DiskBytes, &total.PIDs}
		additions := [4]int64{service.Resources.CPUMillis, service.Resources.MemoryBytes, service.Resources.DiskBytes, service.Resources.PIDs}
		for index, target := range values {
			if additions[index] < 0 || *target > math.MaxInt64-additions[index] {
				return ResourceLimits{}, domain.ValidationError("runtime service group resources overflow")
			}
			*target += additions[index]
		}
	}
	writableClaims := make(map[string]struct{}, len(s.VolumeClaims))
	claimSizes := make(map[string]int64, len(s.VolumeClaims))
	for _, claim := range s.VolumeClaims {
		claimSizes[claim.Name] = claim.SizeBytes
	}
	for _, service := range s.Services {
		for _, volume := range service.Volumes {
			if !volume.ReadOnly {
				writableClaims[volume.Name] = struct{}{}
			}
		}
	}
	for name := range writableClaims {
		size, exists := claimSizes[name]
		if !exists || size <= 0 {
			return ResourceLimits{}, domain.ValidationError("runtime service volume has no declared positive-size claim")
		}
		if total.DiskBytes > math.MaxInt64-size {
			return ResourceLimits{}, domain.ValidationError("runtime service group resources overflow")
		}
		total.DiskBytes += size
	}
	return total, nil
}

// ValidateRelease proves that the runtime request is the complete immutable
// Release, not a subset assembled from whichever builds happened to finish.
func (s ServiceGroupRuntimeSpec) ValidateRelease(release domain.Release) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := release.Validate(); err != nil {
		return err
	}
	if release.ID != s.ReleaseID || release.ApplicationID != s.ApplicationID || release.ServiceGroupID != s.ServiceGroupID {
		return domain.ValidationError("runtime service group does not match release identity")
	}
	if release.ConfigDigest != s.ConfigDigest {
		return domain.ValidationError("runtime service group config digest does not match release")
	}
	digests := release.ServiceDigests()
	if len(digests) != len(s.Services) {
		return domain.ValidationError("runtime service set does not match complete release digest set")
	}
	for _, service := range s.Services {
		image, exists := digests[service.Name]
		if !exists || image != service.Image {
			return domain.ValidationError("runtime service image does not match release digest set")
		}
	}
	return nil
}

// CanonicalServiceGroupReleaseDigest covers the complete executable Release:
// definition version, resolved image digests, command/environment references,
// limits, health, entrypoint, dependencies, retained claims and rollout.
// Ordering-only differences are normalized; command and entrypoint order is
// preserved because it is semantically significant.
func CanonicalServiceGroupReleaseDigest(definitionID domain.ID, version int64, spec ServiceGroupRuntimeSpec) (string, error) {
	if err := domain.RequireID(definitionID, "canonical release definition id"); err != nil {
		return "", err
	}
	if version < 1 {
		return "", domain.ValidationError("canonical release version must be positive")
	}
	if err := spec.Validate(); err != nil {
		return "", err
	}
	normalized := spec
	// Target environment and rollout predecessor are execution facts, not part
	// of the immutable Release configuration. The same Release may be deployed
	// to another environment or used as a rollback target without changing its
	// canonical service identity.
	normalized.EnvironmentID = ""
	normalized.Rollout = RuntimeRolloutPolicy{}
	normalized.Services = append([]ServiceRuntimeSpec(nil), spec.Services...)
	for index := range normalized.Services {
		service := &normalized.Services[index]
		service.Dependencies = append([]domain.ServiceDependency(nil), service.Dependencies...)
		sort.Slice(service.Dependencies, func(i, j int) bool {
			if service.Dependencies[i].Service == service.Dependencies[j].Service {
				return service.Dependencies[i].Condition < service.Dependencies[j].Condition
			}
			return service.Dependencies[i].Service < service.Dependencies[j].Service
		})
		service.Volumes = append([]domain.VolumeMount(nil), service.Volumes...)
		sort.Slice(service.Volumes, func(i, j int) bool {
			if service.Volumes[i].Name == service.Volumes[j].Name {
				return service.Volumes[i].MountPath < service.Volumes[j].MountPath
			}
			return service.Volumes[i].Name < service.Volumes[j].Name
		})
		service.Environment = append([]RuntimeEnvironmentVariable(nil), service.Environment...)
		sort.Slice(service.Environment, func(i, j int) bool { return service.Environment[i].Name < service.Environment[j].Name })
		service.ContainerPorts = append([]int(nil), service.ContainerPorts...)
		sort.Ints(service.ContainerPorts)
	}
	sort.Slice(normalized.Services, func(i, j int) bool { return normalized.Services[i].Name < normalized.Services[j].Name })
	normalized.VolumeClaims = append([]RuntimeVolumeClaim(nil), spec.VolumeClaims...)
	sort.Slice(normalized.VolumeClaims, func(i, j int) bool {
		if normalized.VolumeClaims[i].Name == normalized.VolumeClaims[j].Name {
			return normalized.VolumeClaims[i].ID < normalized.VolumeClaims[j].ID
		}
		return normalized.VolumeClaims[i].Name < normalized.VolumeClaims[j].Name
	})
	payload := struct {
		DefinitionID domain.ID               `json:"definition_id"`
		Version      int64                   `json:"version"`
		Runtime      ServiceGroupRuntimeSpec `json:"runtime"`
	}{DefinitionID: definitionID, Version: version, Runtime: normalized}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type DeployGroupRequest struct {
	DeploymentID domain.ID               `json:"deployment_id"`
	Spec         ServiceGroupRuntimeSpec `json:"spec"`
	Operation    OperationContext        `json:"operation"`
	// ForceRecreate is an operation-scoped recovery instruction.  It is not
	// part of the immutable ServiceGroup release and therefore must not be
	// persisted in or influence the release canonical digest.  A controller
	// uses it only for an explicit M4 redeploy/rollback so a matching service
	// spec cannot silently reuse the previous container instead of exercising
	// a replacement deployment.
	ForceRecreate bool `json:"force_recreate,omitempty"`
}

type ObserveGroupRequest struct {
	DeploymentID domain.ID        `json:"deployment_id"`
	Operation    OperationContext `json:"operation"`
}

type RollbackGroupRequest struct {
	// DeploymentID is the currently usable deployment. TargetDeploymentID is
	// allocated by the controller before the Agent task is leased, which makes
	// retries deterministic and lets the control-plane bind observations and
	// traffic switching to the actual rollback candidate.
	DeploymentID       domain.ID               `json:"deployment_id"`
	TargetDeploymentID domain.ID               `json:"target_deployment_id"`
	Target             ServiceGroupRuntimeSpec `json:"target"`
	Operation          OperationContext        `json:"operation"`
}

type ServiceGroupRuntimeObservation struct {
	DeploymentID domain.ID            `json:"deployment_id"`
	ReleaseID    domain.ID            `json:"release_id"`
	Status       string               `json:"status"`
	Effect       RuntimeEffectState   `json:"effect"`
	RolledBack   bool                 `json:"rolled_back"`
	Services     []RuntimeObservation `json:"services"`
	Evidence     Evidence             `json:"evidence"`
}

type RuntimeEffectState string

const (
	RuntimeEffectKnown   RuntimeEffectState = "effect_known"
	RuntimeEffectUnknown RuntimeEffectState = "effect_unknown"
)

func (o ServiceGroupRuntimeObservation) ValidateFor(spec ServiceGroupRuntimeSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if o.DeploymentID.Empty() || o.ReleaseID != spec.ReleaseID {
		return domain.ValidationError("aggregate runtime observation identity is invalid")
	}
	if o.Effect != RuntimeEffectKnown && o.Effect != RuntimeEffectUnknown {
		return domain.ValidationError("aggregate runtime observation effect is invalid")
	}
	if o.Effect == RuntimeEffectUnknown {
		if o.Status != "unknown" {
			return domain.ValidationError("unknown aggregate runtime effect requires unknown status")
		}
		return nil
	}
	if o.Status != "runtime_ready" && o.Status != "degraded" && o.Status != "failed" {
		return domain.ValidationError("aggregate runtime observation status is invalid")
	}
	if len(o.Services) != len(spec.Services) {
		return domain.ValidationError("aggregate runtime observation service set is incomplete")
	}
	serviceSpecs := make(map[string]ServiceRuntimeSpec, len(spec.Services))
	for _, service := range spec.Services {
		serviceSpecs[service.Name] = service
	}
	seen := make(map[string]struct{}, len(o.Services))
	optionalFailure := false
	for _, observed := range o.Services {
		service, exists := serviceSpecs[observed.ServiceName]
		if !exists || observed.DeploymentID != o.DeploymentID {
			return domain.ValidationError("aggregate runtime observation contains an unknown service")
		}
		if _, duplicate := seen[observed.ServiceName]; duplicate {
			return domain.ValidationError("aggregate runtime observation service names must be unique")
		}
		seen[observed.ServiceName] = struct{}{}
		if observed.Limits != service.Resources {
			return domain.ValidationError("aggregate runtime observation limits do not match requested limits")
		}
		if observed.ServiceName == spec.EntryService {
			if (o.Status == "runtime_ready" || o.Status == "degraded") && (!observed.Healthy || observed.HostPort < 1 || observed.HostPort > 65535) {
				return domain.ValidationError("aggregate runtime entry service is not healthy and exposed")
			}
		} else if observed.HostPort != 0 {
			return domain.ValidationError("non-entry aggregate runtime service exposed a host port")
		}
		if service.Required && !observed.Healthy && o.Status != "failed" {
			return domain.ValidationError("required aggregate runtime service is unhealthy")
		}
		if !service.Required && !observed.Healthy {
			optionalFailure = true
		}
	}
	if optionalFailure && o.Status != "degraded" {
		return domain.ValidationError("optional aggregate runtime failure requires degraded status")
	}
	if !optionalFailure && o.Status == "degraded" {
		return domain.ValidationError("degraded aggregate runtime status has no optional failure")
	}
	return nil
}

type ServiceGroupRuntimeDriver interface {
	Provider
	DeployGroup(context.Context, DeployGroupRequest) (domain.Deployment, error)
	ObserveGroup(context.Context, ObserveGroupRequest) (ServiceGroupRuntimeObservation, error)
	RollbackGroup(context.Context, RollbackGroupRequest) (domain.Deployment, error)
	DestroyGroup(context.Context, DestroyRequest) error
}

// ServiceGroupLogReader is an optional, typed capability implemented by a
// ServiceGroup runtime that can read one owned service's Docker logs. Keeping
// it separate from ServiceGroupRuntimeDriver preserves fail-closed behavior
// for older drivers: an aggregate log task cannot silently fall back to the
// single-container runtime or an arbitrary command runner.
type ServiceGroupLogReader interface {
	Logs(context.Context, LogsRequest) (<-chan string, error)
}

// RestartGroupServiceRequest is the narrow M4 recovery effect for one
// existing service in one owned ServiceGroup deployment. It intentionally has
// no command, container name, shell, host path, or environment fields.
type RestartGroupServiceRequest struct {
	DeploymentID   domain.ID        `json:"deployment_id"`
	ServiceGroupID domain.ID        `json:"service_group_id"`
	ReleaseID      domain.ID        `json:"release_id"`
	ServiceName    string           `json:"service_name"`
	Operation      OperationContext `json:"operation"`
}

func (r RestartGroupServiceRequest) Validate() error {
	if r.DeploymentID.Empty() || r.ServiceGroupID.Empty() || r.ReleaseID.Empty() || strings.TrimSpace(r.ServiceName) == "" {
		return domain.ValidationError("group service restart identity is incomplete")
	}
	return r.Operation.Validate()
}

// ServiceGroupServiceRestarter is optional so existing M2 drivers fail closed
// when a controller asks for a service-level restart rather than silently
// falling back to an arbitrary group or shell operation.
type ServiceGroupServiceRestarter interface {
	RestartGroupService(context.Context, RestartGroupServiceRequest) error
}

// RestartGroupRequest is the explicit M4 fallback when several services are
// unhealthy.  It carries only immutable ownership identity; callers cannot
// select containers, commands, paths, environments, or host resources.
type RestartGroupRequest struct {
	DeploymentID   domain.ID        `json:"deployment_id"`
	ServiceGroupID domain.ID        `json:"service_group_id"`
	ReleaseID      domain.ID        `json:"release_id"`
	Operation      OperationContext `json:"operation"`
}

func (r RestartGroupRequest) Validate() error {
	if r.DeploymentID.Empty() || r.ServiceGroupID.Empty() || r.ReleaseID.Empty() {
		return domain.ValidationError("group restart identity is incomplete")
	}
	return r.Operation.Validate()
}

// ServiceGroupRestarter remains optional so an older aggregate runtime fails
// closed instead of silently treating a full-group recovery as a shell or a
// collection of unscoped container operations.
type ServiceGroupRestarter interface {
	RestartGroup(context.Context, RestartGroupRequest) error
}
