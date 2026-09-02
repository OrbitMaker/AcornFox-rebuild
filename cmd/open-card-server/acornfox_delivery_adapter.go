package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// acornFoxPostgresAdapter is deliberately a thin typed bridge. It has no
// routing policy and never returns raw task/source payloads to HTTP callers.
type acornFoxPostgresAdapter struct{ store *postgres.Store }

const acornFoxDeliveryRecoveryLease = 6 * time.Minute

func (a acornFoxPostgresAdapter) BeginAcornFoxDelivery(ctx context.Context, key, digest string, now time.Time) (application.AcornFoxDeliveryResult, bool, error) {
	raw, replay, err := a.store.ReservePublish(ctx, strings.TrimSpace(key), "sha256:"+strings.TrimPrefix(digest, "sha256:"), now)
	if errors.Is(err, postgres.ErrIdempotencyInProgress) {
		err = a.store.AbandonExpiredAcornFoxPublish(ctx, strings.TrimSpace(key), "sha256:"+strings.TrimPrefix(digest, "sha256:"), now, acornFoxDeliveryRecoveryLease)
	}
	if err != nil || !replay {
		return application.AcornFoxDeliveryResult{}, replay, acornFoxDeliveryBeginError(err)
	}
	var result application.AcornFoxDeliveryResult
	if err := json.Unmarshal(raw, &result); err != nil || result.DeploymentID.Empty() || result.OperationID.Empty() || result.TaskID.Empty() {
		return application.AcornFoxDeliveryResult{}, false, errors.New("AcornFox durable replay is invalid")
	}
	return result, true, nil
}

func acornFoxDeliveryBeginError(err error) error {
	if errors.Is(err, postgres.ErrAcornFoxPublishAbandoned) {
		return domain.WrapError(domain.ErrUnknownState, "AcornFox delivery command was abandoned; retry with a new idempotency key after inspection", err)
	}
	if errors.Is(err, postgres.ErrIdempotencyInProgress) {
		return domain.WrapError(domain.ErrConflict, "AcornFox delivery command is still in progress", err)
	}
	return err
}
func (a acornFoxPostgresAdapter) CommitAcornFoxDeliveryTask(ctx context.Context, task application.AcornFoxQueuedTask, key, digest string, result application.AcornFoxDeliveryResult, now time.Time) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if a.store == nil || task.Operation.Validate() != nil || task.TaskID.Empty() || len(task.Payload) == 0 || task.MaxAttempts < 1 || task.MaxAttempts > 3 || !validAcornFoxTaskPayload(task.Payload) {
		return domain.ValidationError("AcornFox queued task is invalid")
	}
	_, err = a.store.EnqueueControllerTaskAndCompletePublish(ctx, postgres.EnqueueControllerTaskRequest{Operation: task.Operation, Deployment: task.Deployment, ExistingDeploymentID: task.ExistingDeploymentID, TaskID: task.TaskID, Payload: task.Payload, MaxAttempts: task.MaxAttempts, InitialPublishStatus: domain.PublishDeploying}, strings.TrimSpace(key), "sha256:"+strings.TrimPrefix(digest, "sha256:"), raw, now)
	return err
}
func (a acornFoxPostgresAdapter) FailAcornFoxDelivery(ctx context.Context, key, digest, reason string, now time.Time) error {
	return a.store.FailPublish(ctx, strings.TrimSpace(key), "sha256:"+strings.TrimPrefix(digest, "sha256:"), reason, now)
}
func (a acornFoxPostgresAdapter) GetSourceRevision(ctx context.Context, id domain.ID) (domain.SourceRevision, error) {
	return a.store.GetSourceRevision(ctx, id)
}
func (a acornFoxPostgresAdapter) GetAcornFoxEnvironment(ctx context.Context, app domain.ID) (domain.ID, error) {
	return a.store.GetDefaultEnvironmentID(ctx, app)
}
func (a acornFoxPostgresAdapter) NextAcornFoxDefinitionVersion(ctx context.Context, app domain.ID) (int, error) {
	return a.store.NextAcornFoxDefinitionVersion(ctx, app)
}
func (a acornFoxPostgresAdapter) NextAcornFoxReleaseVersion(ctx context.Context, app domain.ID) (int, error) {
	return a.store.NextAcornFoxReleaseVersion(ctx, app)
}
func (a acornFoxPostgresAdapter) CreateAcornFoxDefinition(ctx context.Context, definition domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error) {
	return a.store.CreateDeliveryDefinition(ctx, definition)
}
func (a acornFoxPostgresAdapter) CreateBuildPlan(ctx context.Context, plan domain.BuildPlan) (domain.BuildPlan, error) {
	return a.store.CreateBuildPlan(ctx, plan)
}
func (a acornFoxPostgresAdapter) CreateBuild(ctx context.Context, build domain.Build) (domain.Build, error) {
	return a.store.CreateBuild(ctx, build)
}
func (a acornFoxPostgresAdapter) StartBuild(ctx context.Context, id domain.ID, now time.Time) (domain.Build, error) {
	return a.store.StartBuild(ctx, id, now)
}
func (a acornFoxPostgresAdapter) CompleteAcornFoxBuild(ctx context.Context, artifact domain.Artifact, release domain.Release, definitionID domain.ID, now time.Time) (domain.Build, error) {
	return a.store.CompleteBuild(ctx, artifact, &postgres.ReleaseCreation{Release: release, DefinitionID: definitionID}, now)
}
func (a acornFoxPostgresAdapter) FailBuild(ctx context.Context, id domain.ID, reason string, now time.Time) (domain.Build, error) {
	return a.store.FailBuild(ctx, id, reason, now)
}
func (a acornFoxPostgresAdapter) GetAcornFoxRuntimeRequest(ctx context.Context, app, deployment domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error) {
	return a.store.GetAcornFoxRuntimeRequest(ctx, app, deployment)
}
func (a acornFoxPostgresAdapter) GetAcornFoxRuntimeObservation(ctx context.Context, app, deployment domain.ID) (contracts.AcornFoxRuntimeObservation, error) {
	return a.store.GetAcornFoxRuntimeObservation(ctx, app, deployment)
}

func validAcornFoxTaskPayload(payload json.RawMessage) bool {
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if json.Unmarshal(payload, &task) != nil || len(task.Parameters) == 0 {
		return false
	}
	var marker map[string]json.RawMessage
	if json.Unmarshal(task.Parameters, &marker) != nil {
		return false
	}
	if raw, ok := marker["acornfox_payload_type"]; ok {
		var kind string
		if json.Unmarshal(raw, &kind) != nil {
			return false
		}
		switch kind {
		case "deploy", "redeploy":
			var request contracts.AcornFoxRuntimeDeployRequest
			return task.Kind == v1.TaskDeploy && json.Unmarshal(marker["request"], &request) == nil && request.Recreate == (kind == "redeploy") && request.Validate() == nil
		case "restart":
			var request contracts.AcornFoxRuntimeActionRequest
			return task.Kind == v1.TaskRestart && json.Unmarshal(marker["request"], &request) == nil && request.Validate() == nil
		default:
			return false
		}
	}
	if raw, ok := marker["acornfox_probe_payload_type"]; ok {
		var kind string
		var request contracts.AcornFoxProbeRequest
		return json.Unmarshal(raw, &kind) == nil && kind == "probe" && task.Kind == v1.TaskObserve && json.Unmarshal(marker["request"], &request) == nil && request.Validate() == nil
	}
	return false
}

type acornFoxHTTPCommand struct {
	service *application.AcornFoxDeliveryService
}

func (h acornFoxHTTPCommand) Create(ctx context.Context, app domain.ID, input acornFoxDeliveryInput, key, actor string) (acornFoxDeliveryResult, error) {
	result, err := h.service.Create(ctx, application.AcornFoxDeliveryCreateRequest{ApplicationID: app, SourceRevisionID: input.SourceRevisionID, ContainerPort: input.ContainerPort, IdempotencyKey: acornFoxHTTPKey("create", app, input.SourceRevisionID, key), Actor: actor})
	return acornFoxHTTPResult(result), err
}
func (h acornFoxHTTPCommand) Restart(ctx context.Context, app, deployment domain.ID, key, actor string) (acornFoxDeliveryResult, error) {
	result, err := h.service.Restart(ctx, application.AcornFoxDeliveryActionRequest{ApplicationID: app, DeploymentID: deployment, IdempotencyKey: acornFoxHTTPKey("restart", app, deployment, key), Actor: actor})
	return acornFoxHTTPResult(result), err
}
func (h acornFoxHTTPCommand) Redeploy(ctx context.Context, app, deployment domain.ID, key, actor string) (acornFoxDeliveryResult, error) {
	result, err := h.service.Redeploy(ctx, application.AcornFoxDeliveryActionRequest{ApplicationID: app, DeploymentID: deployment, IdempotencyKey: acornFoxHTTPKey("redeploy", app, deployment, key), Actor: actor})
	return acornFoxHTTPResult(result), err
}
func (h acornFoxHTTPCommand) Probe(ctx context.Context, app, deployment domain.ID, input acornFoxProbeInput, key, actor string) (acornFoxDeliveryResult, error) {
	result, err := h.service.Probe(ctx, application.AcornFoxDeliveryProbeRequest{AcornFoxDeliveryActionRequest: application.AcornFoxDeliveryActionRequest{ApplicationID: app, DeploymentID: deployment, IdempotencyKey: acornFoxHTTPKey("probe", app, deployment, key), Actor: actor}, Protocol: input.Protocol, HTTPPath: input.Path})
	return acornFoxHTTPResult(result), err
}
func acornFoxHTTPResult(result application.AcornFoxDeliveryResult) acornFoxDeliveryResult {
	return acornFoxDeliveryResult{DeploymentID: result.DeploymentID, OperationID: result.OperationID, TaskID: result.TaskID, Status: result.Status}
}
func acornFoxHTTPKey(action string, app, resource domain.ID, callerKey string) string {
	return "acornfox:" + action + ":" + app.String() + ":" + resource.String() + ":" + strings.TrimSpace(callerKey)
}
