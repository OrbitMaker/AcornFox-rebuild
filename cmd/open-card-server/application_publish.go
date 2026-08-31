package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

var publishServiceNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62})$`)

type publishInputStore interface {
	LatestApplicationPublishInput(context.Context, domain.ID) (postgres.ApplicationPublishInput, error)
}

func writeApplicationPublishError(w http.ResponseWriter, err error) {
	if domain.IsCode(err, domain.ErrValidation) {
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "publish request is invalid")
		return
	}
	if errors.Is(err, application.ErrNotFound) || errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "application publish input not found")
		return
	}
	if errors.Is(err, application.ErrIdempotencyConflict) || errors.Is(err, postgres.ErrIdempotencyConflict) || errors.Is(err, postgres.ErrIdempotencyInProgress) || errors.Is(err, postgres.ErrPublishPreviouslyFailed) {
		writeJSONError(w, http.StatusConflict, "publish_conflict", "publish conflict")
		return
	}
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		if providerErr.Code == contracts.ErrValidation {
			writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "publish request is invalid")
			return
		}
		if providerErr.Code == contracts.ErrConflict {
			writeJSONError(w, http.StatusConflict, "publish_conflict", "publish conflict")
			return
		}
		if providerErr.Code == contracts.ErrCapacity {
			writeJSONError(w, http.StatusConflict, "publish_conflict", "publish conflict")
			return
		}
		if providerErr.Code == contracts.ErrUnauthorized || providerErr.Code == contracts.ErrForbidden {
			writeJSONError(w, http.StatusForbidden, "forbidden", "publish is forbidden")
			return
		}
		if providerErr.Code == contracts.ErrUnavailable || providerErr.Code == contracts.ErrTimeout {
			writeJSONError(w, http.StatusServiceUnavailable, "publish_unavailable", "publish is unavailable")
			return
		}
	}
	writeJSONError(w, http.StatusInternalServerError, "publish_failed", "publish failed")
}

type applicationPublisher interface {
	Publish(context.Context, controllers.PublishRequest) (controllers.PublishResult, error)
}
type applicationPublishRequest struct {
	BuildKind      string `json:"build_kind"`
	ContextPath    string `json:"context_path"`
	DockerfilePath string `json:"dockerfile_path,omitempty"`
	ServiceName    string `json:"service_name"`
	ContainerPort  int    `json:"container_port"`
}
type applicationPublishResponse struct {
	Status           string    `json:"status"`
	OperationID      domain.ID `json:"operation_id"`
	ReleaseID        domain.ID `json:"release_id"`
	DeploymentID     domain.ID `json:"deployment_id"`
	TaskID           domain.ID `json:"task_id"`
	SourceRevisionID domain.ID `json:"source_revision_id"`
}

func deriveApplicationPublishRequest(input applicationPublishRequest, applicationID domain.ID, publishInput postgres.ApplicationPublishInput, key, actor string, now time.Time) (controllers.PublishRequest, error) {
	kind := domain.BuildKind(input.BuildKind)
	contextPath := strings.TrimSpace(input.ContextPath)
	dockerfilePath := strings.TrimSpace(input.DockerfilePath)
	if kind != domain.BuildStatic && kind != domain.BuildDockerfile {
		return controllers.PublishRequest{}, domain.ValidationError("build_kind is invalid")
	}
	if applicationID.Empty() || strings.TrimSpace(key) == "" || strings.TrimSpace(actor) == "" || publishInput.SourceRevisionID.Empty() || publishInput.EnvironmentID.Empty() || publishInput.NextVersion < 1 || !publishServiceNamePattern.MatchString(strings.TrimSpace(input.ServiceName)) || contextPath == "" || input.ContainerPort < 1 || input.ContainerPort > 65535 {
		return controllers.PublishRequest{}, domain.ValidationError("publish request is invalid")
	}
	if (kind == domain.BuildStatic && dockerfilePath != "") || (kind == domain.BuildDockerfile && dockerfilePath == "") || unsafeApplicationPublishContextPath(contextPath) || unsafeApplicationPublishPath(dockerfilePath) {
		return controllers.PublishRequest{}, domain.ValidationError("publish paths are invalid")
	}
	service := strings.TrimSpace(input.ServiceName)
	version := publishInput.NextVersion
	return controllers.PublishRequest{ApplicationID: applicationID, EnvironmentID: publishInput.EnvironmentID, ServiceGroupID: domain.ID("group_" + applicationID.String()), ServiceName: service, Source: contracts.PrepareSourceRequest{ApplicationID: applicationID, Kind: domain.SourceKind(publishInput.SourceKind), Locator: publishInput.Locator, Ref: publishInput.Ref, ContentDigest: publishInput.ContentDigest, Operation: contracts.OperationContext{IdempotencyKey: key + ":source", Actor: actor}}, BuildKind: kind, ContextPath: contextPath, DockerfilePath: dockerfilePath, TargetRepository: "open-card.local/" + applicationID.String() + "/" + service, OutputStorageKey: "publish/" + applicationID.String() + "/v" + strconv.Itoa(version) + "/" + service, BuildResources: contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 512 << 20, DiskBytes: 1 << 30}, BuildNetwork: contracts.NetworkPolicy{Mode: "none"}, RuntimeResources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 256 << 20, DiskBytes: 512 << 20, PIDs: 64}, ContainerPort: input.ContainerPort, Version: version, IdempotencyKey: key, Deadline: now.Add(10 * time.Minute), Actor: actor}, nil
}
func unsafeApplicationPublishContextPath(value string) bool {
	if strings.TrimSpace(value) == "." {
		return false
	}
	return unsafeApplicationPublishPath(value)
}
func unsafeApplicationPublishPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\r\n\x00") {
		return true
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return true
		}
	}
	return false
}

func writeApplicationPublishResult(w http.ResponseWriter, result controllers.PublishResult) {
	if result.Operation.ID.Empty() || result.Release.ID.Empty() || result.Deployment.ID.Empty() || result.TaskID.Empty() || result.SourceRevision.ID.Empty() {
		writeJSONError(w, http.StatusInternalServerError, "publish_failed", "publish failed")
		return
	}
	writeJSON(w, http.StatusAccepted, applicationPublishResponse{Status: "deploying", OperationID: result.Operation.ID, ReleaseID: result.Release.ID, DeploymentID: result.Deployment.ID, TaskID: result.TaskID, SourceRevisionID: result.SourceRevision.ID})
}

func handleApplicationPublish(w http.ResponseWriter, r *http.Request, applicationID domain.ID, store publishInputStore, publisher applicationPublisher, actor string, now func() time.Time) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if store == nil || publisher == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "publish_unavailable", "publish is unavailable")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if applicationID.Empty() || key == "" || strings.TrimSpace(actor) == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "application id, idempotency key, and actor are required")
		return
	}
	if now == nil {
		now = time.Now
	}
	var input applicationPublishRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	publishInput, err := store.LatestApplicationPublishInput(r.Context(), applicationID)
	if err != nil {
		writeApplicationPublishError(w, err)
		return
	}
	request, err := deriveApplicationPublishRequest(input, applicationID, publishInput, key, actor, now().UTC())
	if err != nil {
		writeApplicationPublishError(w, err)
		return
	}
	result, err := publisher.Publish(r.Context(), request)
	if err != nil {
		writeApplicationPublishError(w, err)
		return
	}
	writeApplicationPublishResult(w, result)
}
