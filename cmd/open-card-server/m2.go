package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	composeimport "github.com/open-card/open-card/internal/importers/compose"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const maxM2UploadBytes = 128 << 20

func (s *Server) handleM2(writer http.ResponseWriter, request *http.Request) bool {
	path := strings.Trim(request.URL.Path, "/")
	switch path {
	case "api/v1/agents/capabilities":
		s.handleM2AgentCapabilities(writer, request)
		return true
	case "api/v1/agents/capabilities/legacy-negative":
		s.handleM2LegacyAgentNegative(writer, request)
		return true
	case "api/v1/sources":
		s.handleM2Source(writer, request)
		return true
	case "api/v1/service-groups/import":
		s.handleM2Import(writer, request)
		return true
	case "api/v1/images/resolve":
		s.handleM2ImageResolve(writer, request)
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 5 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "service-groups" {
		switch parts[4] {
		case "releases":
			s.handleM2Release(writer, request, domain.ID(parts[3]))
			return true
		case "deployments":
			s.handleM2Deploy(writer, request, domain.ID(parts[3]))
			return true
		}
	}
	if len(parts) >= 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "deployments" {
		deploymentID := domain.ID(parts[3])
		if len(parts) == 4 {
			s.handleM2Deployment(writer, request, deploymentID)
			return true
		}
		if len(parts) == 5 && parts[4] == "events" {
			operationID, err := s.m2Store.GetDeploymentOperationID(request.Context(), deploymentID)
			if err != nil {
				writeDomainError(writer, err)
				return true
			}
			s.handleEvents(writer, request, operationID.String())
			return true
		}
		if len(parts) == 5 && parts[4] == "destroy" {
			s.handleM2Destroy(writer, request, deploymentID)
			return true
		}
	}
	if len(parts) == 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "rollouts" {
		s.handleM2Rollout(writer, request, domain.ID(parts[3]))
		return true
	}
	return false
}

func (s *Server) handleM2AgentCapabilities(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	values := s.agentGateway.NodeCapabilities(s.m2AgentInstance, s.m2AgentNode)
	if values == nil {
		values = []string{}
	}
	sort.Strings(values)
	writeJSON(writer, http.StatusOK, map[string]any{
		"instance_id":  s.m2AgentInstance,
		"node_id":      s.m2AgentNode,
		"capabilities": values,
	})
}

func (s *Server) handleM2LegacyAgentNegative(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		ServiceGroupID       domain.ID                  `json:"service_group_id"`
		RequiredCapabilities []contracts.Capability     `json:"required_capabilities"`
		Operation            contracts.OperationContext `json:"operation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_capability_probe", err.Error())
		return
	}
	// This endpoint is an explicit compatibility probe.  It models an N-1
	// Agent that can only deploy one container.  A group request must be
	// rejected before an Operation, task, Release, or runtime side effect is
	// created; it is never translated to runtime.deploy.
	if input.ServiceGroupID.Empty() || strings.TrimSpace(input.Operation.IdempotencyKey) == "" {
		writeJSONError(writer, http.StatusBadRequest, "invalid_capability_probe", "service_group_id and operation idempotency key are required")
		return
	}
	writeJSONError(writer, http.StatusConflict, "agent_capability_unavailable", "legacy Agent does not support runtime.deploy_group; aggregate deployment was rejected without downgrade")
}

func (s *Server) handleM2Source(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if strings.TrimSpace(s.m2UploadRoot) == "" {
		writeJSONError(writer, http.StatusServiceUnavailable, "source_unavailable", "M2 upload root is unavailable")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxM2UploadBytes+1<<20)
	if err := request.ParseMultipartForm(1 << 20); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_source", "multipart source is invalid")
		return
	}
	applicationID := domain.ID(strings.TrimSpace(request.FormValue("application_id")))
	if request.FormValue("kind") != "upload" || applicationID.Empty() {
		writeJSONError(writer, http.StatusBadRequest, "invalid_source", "M2 source requires upload kind and application_id")
		return
	}
	input, _, err := request.FormFile("archive")
	if err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_source", "source archive is required")
		return
	}
	defer input.Close()
	temporary, err := os.CreateTemp(s.m2UploadRoot, ".m2-upload-*.tar")
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "source_unavailable", "source staging is unavailable")
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, copyErr := io.Copy(temporary, io.LimitReader(input, maxM2UploadBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written <= 0 || written > maxM2UploadBytes {
		writeJSONError(writer, http.StatusBadRequest, "invalid_source", "source archive exceeds the accepted boundary")
		return
	}
	_ = os.Chmod(temporaryPath, 0o600)
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	revision, err := s.m2Controller.PrepareSource(request.Context(), contracts.PrepareSourceRequest{ApplicationID: applicationID, Kind: domain.SourceUpload, Locator: temporaryPath, Operation: contracts.OperationContext{IdempotencyKey: idempotencyKey, Actor: "m2-api"}})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"source_revision": revision})
}

func (s *Server) handleM2Import(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		ApplicationID    domain.ID       `json:"application_id"`
		EnvironmentID    domain.ID       `json:"environment_id"`
		SourceRevisionID domain.ID       `json:"source_revision_id"`
		Name             string          `json:"name"`
		Version          int64           `json:"version,omitempty"`
		Compose          json.RawMessage `json:"compose"`
		OptionalServices []string        `json:"optional_services,omitempty"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_compose", err.Error())
		return
	}
	if input.Version == 0 {
		input.Version = 1
	}
	revision, err := s.m2Store.GetSourceRevision(request.Context(), input.SourceRevisionID)
	if err != nil || revision.ApplicationID != input.ApplicationID {
		writeJSONError(writer, http.StatusBadRequest, "invalid_source", "source revision does not belong to application")
		return
	}
	result, err := composeimport.ImportJSON(input.Compose, composeimport.Options{ApplicationID: input.ApplicationID, Name: input.Name, Now: time.Now().UTC()})
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"code": "compose_rejected", "message": err.Error(), "report": result.Report})
		return
	}
	optional := make(map[string]struct{}, len(input.OptionalServices))
	for _, name := range input.OptionalServices {
		optional[strings.TrimSpace(name)] = struct{}{}
	}
	for index := range result.ServiceGroup.Services {
		if _, ok := optional[result.ServiceGroup.Services[index].Name]; ok {
			result.ServiceGroup.Services[index].Required = false
			delete(optional, result.ServiceGroup.Services[index].Name)
		}
	}
	if len(optional) != 0 {
		writeJSONError(writer, http.StatusBadRequest, "invalid_compose", "optional service override references an unknown service")
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	definitionID := m2ServerID("def", key, input.ApplicationID.String(), input.SourceRevisionID.String(), fmt.Sprint(input.Version), result.Report.CanonicalDigest)
	evidence := domain.EvidenceRef{ID: m2ServerID("ev", key, "compose"), Kind: "compose.import", Digest: result.Report.CanonicalDigest, Locator: "compose://canonical"}
	definition, err := domain.NewApplicationDeliveryDefinition(input.ApplicationID, input.SourceRevisionID, int(input.Version), map[string]domain.FieldFact{"service_group": {Value: map[string]any{"name": input.Name, "service_count": len(result.ServiceGroup.Services), "canonical_digest": result.Report.CanonicalDigest}, Source: domain.FactSourceRepository, Confidence: 1, Evidence: []domain.EvidenceRef{evidence}, Status: domain.FactConfirmed}}, time.Now().UTC())
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	definition.ID = definitionID
	if _, err := s.m2Store.CreateDeliveryDefinition(request.Context(), *definition); err != nil {
		existing, getErr := s.m2Store.GetDeliveryDefinition(request.Context(), definitionID)
		if getErr != nil || existing.ApplicationID != definition.ApplicationID || existing.SourceRevisionID != definition.SourceRevisionID || existing.Version != definition.Version {
			writeDomainError(writer, err)
			return
		}
	}
	volumeNames := make([]string, 0, len(result.Document.Volumes))
	for name := range result.Document.Volumes {
		volumeNames = append(volumeNames, name)
	}
	sort.Strings(volumeNames)
	claims := make([]postgres.M2ServiceGroupVolumeClaim, 0, len(volumeNames))
	for _, name := range volumeNames {
		claims = append(claims, postgres.M2ServiceGroupVolumeClaim{ID: m2ServerID("volume", input.ApplicationID.String(), name), Name: name, SizeBytes: 1 << 30, Retain: true})
	}
	group, err := s.m2Controller.PersistImportedGroup(request.Context(), controllers.PersistImportedGroupRequest{Result: result, DefinitionID: definitionID, Version: input.Version, VolumeClaims: claims, IdempotencyKey: key})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	identity, err := s.m2Store.GetServiceGroupIdentity(request.Context(), group.ID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	projection := map[string]any{"id": group.ID, "application_id": group.ApplicationID, "name": group.Name, "services": group.Services, "definition_id": identity.DefinitionID, "version": identity.Version, "config_digest": identity.ConfigDigest, "canonical_digest": identity.CanonicalDigest, "created_at": group.CreatedAt}
	writeJSON(writer, http.StatusCreated, map[string]any{"service_group": projection, "report": result.Report, "environment_id": input.EnvironmentID})
}

type m2RegistryInput struct {
	Endpoint  string                  `json:"endpoint"`
	SecretRef *domain.SecretReference `json:"secret_ref,omitempty"`
}

func (s *Server) handleM2Release(writer http.ResponseWriter, request *http.Request, groupID domain.ID) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		SourceRevisionID domain.ID         `json:"source_revision_id"`
		Version          int               `json:"version"`
		Registries       []m2RegistryInput `json:"registries,omitempty"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_release", err.Error())
		return
	}
	record, err := s.m2Store.GetServiceGroupRecord(request.Context(), groupID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	identity, err := s.m2Store.GetServiceGroupIdentity(request.Context(), groupID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	sourceRevision, err := s.m2Store.GetSourceRevision(request.Context(), input.SourceRevisionID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	environmentID, err := s.m2Store.GetDefaultEnvironmentID(request.Context(), record.Group.ApplicationID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	builds := make(map[string]controllers.M2BuildService)
	registryRequests := make(map[string]contracts.ImageResolveRequest)
	runtimeResources := make(map[string]contracts.ResourceLimits)
	for _, service := range record.Group.Services {
		cpu, memory := service.Resources.CPUMillis, service.Resources.MemoryBytes
		if cpu <= 0 {
			cpu = 250
		}
		if memory <= 0 {
			memory = 64 << 20
		}
		runtimeResources[service.Name] = contracts.ResourceLimits{CPUMillis: cpu, MemoryBytes: memory, DiskBytes: 128 << 20, PIDs: 64}
		if service.Source.Kind == domain.ServiceStatic || service.Source.Kind == domain.ServiceDockerfile {
			builds[service.Name] = controllers.M2BuildService{Resources: contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 512 << 20, DiskBytes: 256 << 20, TimeoutSeconds: 300, ConcurrencySlot: 1}, Network: contracts.NetworkPolicy{Mode: "none"}, TargetRepository: "open-card.local/" + strings.ToLower(record.Group.ApplicationID.String()) + "/" + strings.ToLower(record.Group.ID.String()) + "/" + service.Name, OutputStorageKey: record.Group.ID.String() + "/" + service.Name}
			continue
		}
		if service.Source.Prebuilt != nil && service.Source.Prebuilt.Reference != "" {
			repository, tag, splitErr := splitM2ServerImage(service.Source.Prebuilt.Reference)
			if splitErr != nil || len(input.Registries) == 0 {
				writeJSONError(writer, http.StatusBadRequest, "invalid_registry", "prebuilt service requires an explicit registry")
				return
			}
			host, hostErr := m2RegistryHost(input.Registries[0].Endpoint)
			if hostErr != nil {
				writeJSONError(writer, http.StatusBadRequest, "invalid_registry", hostErr.Error())
				return
			}
			if imageHost := m2ExplicitRegistryHost(repository); imageHost != "" && !strings.EqualFold(imageHost, host) {
				// The request registry is an authority boundary, not a rewrite
				// hint.  Prefixing an already-qualified image with a different
				// host turns a valid image reference into an invalid one and can
				// accidentally direct a credential-bearing pull at the wrong
				// registry. Reject before capacity, registry, build, or release
				// side effects instead.
				writeJSONError(writer, http.StatusBadRequest, "invalid_registry", "prebuilt image registry does not match explicit registry")
				return
			}
			if m2ExplicitRegistryHost(repository) == "" {
				repository = host + "/" + repository
			}
			registryRequests[service.Name] = contracts.ImageResolveRequest{Repository: repository, Tag: tag, Secret: input.Registries[0].SecretRef}
		}
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	result, err := s.m2Controller.CreateCompleteRelease(request.Context(), controllers.M2CompleteReleaseRequest{Group: record.Group, Identity: identity, DefinitionID: identity.DefinitionID, Version: input.Version, Source: sourceRevision, IdempotencyKey: key, Actor: "m2-api", EnvironmentID: environmentID, BuildServices: builds, Registry: registryRequests, Runtime: runtimeResources, VolumeClaims: record.VolumeClaims, Rollout: postgres.M2ReleaseRollout{Mode: "initial"}})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"release": result.Release, "canonical_digest": result.CanonicalDigest})
}

func (s *Server) handleM2Deploy(writer http.ResponseWriter, request *http.Request, groupID domain.ID) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		ReleaseID            domain.ID                      `json:"release_id"`
		PreviousDeploymentID domain.ID                      `json:"previous_deployment_id,omitempty"`
		Rollout              contracts.RuntimeRolloutPolicy `json:"rollout,omitempty"`
		RuntimeResources     *contracts.ResourceLimits      `json:"runtime_resources,omitempty"`
		Operation            contracts.OperationContext     `json:"operation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_deployment", err.Error())
		return
	}
	release, err := s.m2Store.GetCompleteRelease(request.Context(), input.ReleaseID)
	if err != nil || release.ServiceGroupID != groupID {
		writeJSONError(writer, http.StatusBadRequest, "invalid_release", "release does not belong to service group")
		return
	}
	spec, _, err := s.m2Store.GetM2ReleaseRuntimeSpec(request.Context(), input.ReleaseID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	spec.EnvironmentID, err = s.m2Store.GetDefaultEnvironmentID(request.Context(), release.ApplicationID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if input.Rollout.Mode == "" {
		input.Rollout = contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial}
	}
	if !input.PreviousDeploymentID.Empty() {
		input.Rollout.PreviousDeploymentID = input.PreviousDeploymentID
	}
	spec.Rollout = input.Rollout
	if input.RuntimeResources != nil {
		_, _, err = s.m2Controller.Capacity.Preflight(request.Context(), contracts.CapacityRequest{Scope: contracts.CapacityRuntime, Resources: *input.RuntimeResources, HostPorts: 1, Operation: contracts.OperationContext{IdempotencyKey: input.Operation.IdempotencyKey + ":capacity-override"}})
		if err != nil {
			writeDomainError(writer, err)
			return
		}
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		key = input.Operation.IdempotencyKey
	}
	result, err := s.m2Controller.EnqueueGroupDeployment(request.Context(), controllers.M2GroupDeploymentRequest{ApplicationID: release.ApplicationID, EnvironmentID: spec.EnvironmentID, Release: release, Spec: spec, AgentCapabilities: s.m2AgentCapabilities(), IdempotencyKey: key, Actor: "m2-api", Deadline: time.Now().Add(5 * time.Minute)})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"deployment": result.Deployment, "operation": result.Operation, "task_id": result.TaskID})
}

func (s *Server) handleM2Deployment(writer http.ResponseWriter, request *http.Request, deploymentID domain.ID) {
	if request.Method != http.MethodGet {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	deployment, err := s.m2Store.GetDeployment(request.Context(), deploymentID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	endpoint, _ := s.m2Store.GetDeploymentEndpoint(request.Context(), deploymentID)
	claims, _ := s.m2Store.ListM2ReleaseVolumeClaims(request.Context(), deployment.ReleaseID)
	claimFacts := make([]map[string]any, 0, len(claims))
	for _, claim := range claims {
		claimFacts = append(claimFacts, map[string]any{"id": claim.ID, "logical_name": claim.Name, "name": s.m2TaskPrefix + "-volume-" + claim.Name, "size_bytes": claim.SizeBytes, "retain": claim.Retain})
	}
	projection := map[string]any{"id": deployment.ID, "application_id": deployment.ApplicationID, "environment_id": deployment.EnvironmentID, "release_id": deployment.ReleaseID, "state": deployment.Status, "failure_reason": deployment.FailureReason, "runtime_healthy": endpoint.Healthy, "host_port": endpoint.HostPort, "url": "", "volume_claims": claimFacts}
	if endpoint.HostPort > 0 {
		projection["url"] = fmt.Sprintf("http://127.0.0.1:%d/", endpoint.HostPort)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"state": deployment.Status, "deployment": projection})
}

func (s *Server) handleM2Rollout(writer http.ResponseWriter, request *http.Request, currentDeploymentID domain.ID) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		ReleaseID               domain.ID                    `json:"release_id"`
		PreviousDeploymentID    domain.ID                    `json:"previous_deployment_id"`
		Mode                    contracts.RuntimeRolloutMode `json:"mode"`
		PreserveOldUntilHealthy bool                         `json:"preserve_old_until_healthy"`
		DowntimeApproved        bool                         `json:"downtime_approved,omitempty"`
		Operation               contracts.OperationContext   `json:"operation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_rollout", err.Error())
		return
	}
	currentDeployment, err := s.m2Store.GetDeployment(request.Context(), currentDeploymentID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	currentSpec, _, err := s.m2Store.GetM2ReleaseRuntimeSpec(request.Context(), currentDeployment.ReleaseID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	targetRelease, err := s.m2Store.GetCompleteRelease(request.Context(), input.ReleaseID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	targetSpec, _, err := s.m2Store.GetM2ReleaseRuntimeSpec(request.Context(), input.ReleaseID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	targetSpec.EnvironmentID = currentDeployment.EnvironmentID
	targetSpec.Rollout = contracts.RuntimeRolloutPolicy{Mode: input.Mode, PreviousDeploymentID: currentDeploymentID, PreserveOldUntilHealthy: input.PreserveOldUntilHealthy, DowntimeApproved: input.DowntimeApproved}
	currentSpec.EnvironmentID = currentDeployment.EnvironmentID
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		key = input.Operation.IdempotencyKey
	}
	result, err := s.m2Controller.Rollout(request.Context(), controllers.M2RolloutRequest{Current: &currentSpec, Target: targetSpec, Release: targetRelease, AgentCapabilities: s.m2AgentCapabilities(), IdempotencyKey: key, Actor: "m2-api", Deadline: time.Now().Add(5 * time.Minute)})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"plan": result.Plan, "deployment": result.Deployment.Deployment, "operation": result.Deployment.Operation, "task_id": result.Deployment.TaskID})
}

func (s *Server) handleM2Destroy(writer http.ResponseWriter, request *http.Request, deploymentID domain.ID) {
	if request.Method != http.MethodPost {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		PreserveVolumes   bool                       `json:"preserve_volumes"`
		ConfirmationToken string                     `json:"confirmation_token,omitempty"`
		Operation         contracts.OperationContext `json:"operation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_destroy", err.Error())
		return
	}
	deployment, err := s.m2Store.GetDeployment(request.Context(), deploymentID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		key = input.Operation.IdempotencyKey
	}
	result, err := s.m2Controller.Destroy(request.Context(), controllers.M2GroupDestroyRequest{ApplicationID: deployment.ApplicationID, EnvironmentID: deployment.EnvironmentID, DeploymentID: deployment.ID, ReleaseID: deployment.ReleaseID, AgentCapabilities: s.m2AgentCapabilities(), PreserveVolumes: input.PreserveVolumes, ConfirmationToken: input.ConfirmationToken, IdempotencyKey: key, Actor: "m2-api", Deadline: time.Now().Add(2 * time.Minute)})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, result)
}

func (s *Server) handleM2ImageResolve(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || s.m2Registry == nil {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input struct {
		Repository string                     `json:"repository"`
		Tag        string                     `json:"tag"`
		Registry   string                     `json:"registry"`
		Platform   map[string]string          `json:"platform,omitempty"`
		SecretRef  *domain.SecretReference    `json:"secret_ref,omitempty"`
		Operation  contracts.OperationContext `json:"operation"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_registry", err.Error())
		return
	}
	host, err := m2RegistryHost(input.Registry)
	if err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_registry", err.Error())
		return
	}
	result, err := s.m2Registry.ResolveAndPull(request.Context(), contracts.ImageResolveRequest{Repository: host + "/" + strings.TrimPrefix(input.Repository, "/"), Tag: input.Tag, Secret: input.SecretRef, Operation: input.Operation})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) m2AgentCapabilities() contracts.CapabilitySet {
	values := s.agentGateway.NodeCapabilities(s.m2AgentInstance, s.m2AgentNode)
	set := make(contracts.CapabilitySet, len(values))
	for _, value := range values {
		set[contracts.Capability(value)] = struct{}{}
	}
	return set
}

func m2RegistryHost(endpoint string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("registry endpoint is invalid")
	}
	if parsed.Scheme == "http" {
		host, _, splitErr := net.SplitHostPort(parsed.Host)
		if splitErr != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			return "", errors.New("plain HTTP registry is allowed only on loopback")
		}
	} else if parsed.Scheme != "https" {
		return "", errors.New("registry endpoint must use HTTPS")
	}
	return parsed.Host, nil
}

// m2ExplicitRegistryHost returns a registry authority only when the first
// repository segment uses the OCI explicit-host form. Plain image names such
// as "library/nginx" remain repository paths and are eligible to inherit the
// request's explicitly declared registry endpoint.
func m2ExplicitRegistryHost(repository string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(repository), "/")
	if first == "localhost" || strings.ContainsAny(first, ".:") || net.ParseIP(first) != nil {
		return first
	}
	return ""
}

func splitM2ServerImage(reference string) (string, string, error) {
	index := strings.LastIndex(reference, ":")
	if index <= strings.LastIndex(reference, "/") || index == len(reference)-1 || strings.Contains(reference, "@") {
		return "", "", errors.New("prebuilt image must use repository:tag before resolution")
	}
	return reference[:index], reference[index+1:], nil
}

func m2ServerID(prefix string, values ...string) domain.ID {
	digest := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(digest, value)
		_, _ = digest.Write([]byte{0})
	}
	return domain.ID(prefix + "_" + hex.EncodeToString(digest.Sum(nil))[:32])
}
