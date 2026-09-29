package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var (
	ErrManagementCommandConflict   = errors.New("management command conflict")
	ErrManagementCommandInProgress = errors.New("management command in progress")
	ErrManagementRouteConflict     = errors.New("management route restore conflict")
	ErrManagementAppArchived       = errors.New("application is archived")
	ErrManagementLeaseLost         = errors.New("management lease lost or expired")
	ErrManagementTargetConflict    = errors.New("management target conflict or revision mismatch")
)

type AcornFoxManagementRequest struct {
	ApplicationID  domain.ID `json:"application_id"`
	DeploymentID   domain.ID `json:"deployment_id,omitempty"` // Required for stop/start, must be empty for archive
	Action         string    `json:"action"`                  // "stop", "start", "archive"
	IdempotencyKey string    `json:"idempotency_key"`
	Actor          string    `json:"actor"`
}

func (r AcornFoxManagementRequest) Validate() error {
	if r.ApplicationID.Empty() {
		return domain.ValidationError("application id is required")
	}
	switch r.Action {
	case "stop", "start":
		if r.DeploymentID.Empty() {
			return domain.ValidationError("deployment id is required for stop/start")
		}
	case "archive":
		if !r.DeploymentID.Empty() {
			return domain.ValidationError("deployment id must be empty for archive")
		}
	default:
		return domain.ValidationError("management action is unsupported")
	}
	if strings.TrimSpace(r.IdempotencyKey) == "" || len(r.IdempotencyKey) > 512 {
		return domain.ValidationError("management idempotency key is invalid")
	}
	if strings.TrimSpace(r.Actor) == "" {
		return domain.ValidationError("management actor is required")
	}
	return nil
}

type AcornFoxManagementTarget struct {
	ID                        domain.ID `json:"id"`
	CommandID                 domain.ID `json:"command_id"`
	DeploymentID              domain.ID `json:"deployment_id"`
	ReleaseID                 domain.ID `json:"release_id"`
	SnapshotDeploymentVersion int64     `json:"snapshot_deployment_version"`
	Revision                  int64     `json:"revision"`
	RoutePhase                string    `json:"route_phase"` // "initial", "closed", "restored", "conflict", "skipped"
	RuntimeTaskID             domain.ID `json:"runtime_task_id,omitempty"`
	ProbeTaskID               domain.ID `json:"probe_task_id,omitempty"`
	OriginalDesiredPublic     bool      `json:"original_desired_public"`
	OriginalRouteIntent       string    `json:"original_route_intent,omitempty"`
	ConfigIdentity            string    `json:"config_identity,omitempty"`
	Status                    string    `json:"status"` // "pending", "running", "completed", "failed", "conflict"
	FailureReason             string    `json:"failure_reason,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type AcornFoxManagementResult struct {
	CommandID       domain.ID                                 `json:"command_id"`
	ApplicationID   domain.ID                                 `json:"application_id"`
	Action          string                                    `json:"action"`
	Phase           string                                    `json:"phase"`
	TargetSetDigest string                                    `json:"target_set_digest,omitempty"`
	Targets         []AcornFoxManagementTarget               `json:"targets"`
	RetainedVolumes []contracts.AcornFoxRetainedVolumeReceipt `json:"retained_volumes,omitempty"`
	FailureReason   string                                    `json:"failure_reason,omitempty"`
	CreatedAt       time.Time                                 `json:"created_at"`
	UpdatedAt       time.Time                                 `json:"updated_at"`
}

type AcornFoxManagementCommandLease struct {
	CommandID     domain.ID
	ApplicationID domain.ID
	Action        string
	Phase         string
	PhaseVersion  int64
	Owner         string
	Token         string
	ExpiresAt     time.Time
	Targets       []AcornFoxManagementTarget
}

type AcornFoxPauseReceipt struct {
	DeploymentID          domain.ID                            `json:"deployment_id"`
	ApplicationID         domain.ID                            `json:"application_id"`
	StopCommandID         domain.ID                            `json:"stop_command_id"`
	ReleaseID             domain.ID                            `json:"release_id"`
	ConfigIdentity        string                               `json:"config_identity"`
	OriginalDesiredPublic bool                                 `json:"original_desired_public"`
	CanonicalIntent       *contracts.AcornFoxPublicRouteIntent `json:"canonical_intent,omitempty"`
	IntentDigest          string                               `json:"intent_digest,omitempty"`
	PauseEpoch            int64                                `json:"pause_epoch"`
	Consumed              bool                                 `json:"consumed"`
	CreatedAt             time.Time                            `json:"created_at"`
	UpdatedAt             time.Time                            `json:"updated_at"`
}

type AcornFoxManagementStore interface {
	BeginManagementCommand(ctx context.Context, request AcornFoxManagementRequest, digest string, now time.Time) (AcornFoxManagementResult, bool, error)
	ClaimManagementCommandLeases(ctx context.Context, owner string, lease time.Duration, limit int, now time.Time) ([]AcornFoxManagementCommandLease, error)
	GetManagementCommand(ctx context.Context, appID, commandID domain.ID) (AcornFoxManagementResult, error)
	UpdateManagementCommandPhase(ctx context.Context, lease AcornFoxManagementCommandLease, expectedPhase, newPhase, failureReason string) error
	UpdateManagementTarget(ctx context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget, expectedRevision int64) error
	EnqueueTargetTask(ctx context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget, task AcornFoxQueuedTask) error
	GetValidatedManagementDestroyEvidence(ctx context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget) ([]contracts.AcornFoxRetainedVolumeReceipt, error)
	GetTaskState(ctx context.Context, taskID domain.ID) (string, string, json.RawMessage, error)
	SavePauseReceipt(ctx context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget, receipt AcornFoxPauseReceipt) error
	GetPauseReceipt(ctx context.Context, appID, deploymentID domain.ID) (AcornFoxPauseReceipt, bool, error)
	ConsumePauseReceipt(ctx context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget, expectedEpoch int64) error
	FinalizeArchive(ctx context.Context, lease AcornFoxManagementCommandLease) error
	GetRetainedVolumes(ctx context.Context, appID domain.ID) ([]contracts.AcornFoxRetainedVolumeReceipt, error)
}

type AcornFoxManagementService struct {
	Store        AcornFoxManagementStore
	Delivery     *AcornFoxDeliveryService
	PublicAccess *AcornFoxPublicAccessService
	Clock        func() time.Time
}

func (s *AcornFoxManagementService) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock().UTC()
}

func AcornFoxManagementRequestDigest(action string, appID, depID domain.ID) string {
	sum := sha256.Sum256([]byte(action + "\x00" + appID.String() + "\x00" + depID.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func AcornFoxManagementSemanticDigest(action string, appID, depID domain.ID, configOrSetDigest string) string {
	sum := sha256.Sum256([]byte(action + "\x00" + appID.String() + "\x00" + depID.String() + "\x00" + configOrSetDigest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *AcornFoxManagementService) Stop(ctx context.Context, request AcornFoxManagementRequest) (AcornFoxManagementResult, error) {
	request.Action = "stop"
	return s.submit(ctx, request)
}

func (s *AcornFoxManagementService) Start(ctx context.Context, request AcornFoxManagementRequest) (AcornFoxManagementResult, error) {
	request.Action = "start"
	return s.submit(ctx, request)
}

func (s *AcornFoxManagementService) Archive(ctx context.Context, request AcornFoxManagementRequest) (AcornFoxManagementResult, error) {
	request.Action = "archive"
	return s.submit(ctx, request)
}

func (s *AcornFoxManagementService) submit(ctx context.Context, request AcornFoxManagementRequest) (AcornFoxManagementResult, error) {
	if s == nil || s.Store == nil {
		return AcornFoxManagementResult{}, errors.New("management service is unavailable")
	}
	if err := request.Validate(); err != nil {
		return AcornFoxManagementResult{}, err
	}
	now := s.now()
	digest := AcornFoxManagementRequestDigest(request.Action, request.ApplicationID, request.DeploymentID)
	res, replay, err := s.Store.BeginManagementCommand(ctx, request, digest, now)
	if err != nil {
		return AcornFoxManagementResult{}, err
	}
	if replay {
		return res, nil
	}
	_, _ = s.ProcessOnce(ctx, 1)
	return s.Store.GetManagementCommand(ctx, request.ApplicationID, res.CommandID)
}

func (s *AcornFoxManagementService) Get(ctx context.Context, applicationID, commandID domain.ID) (AcornFoxManagementResult, error) {
	if s == nil || s.Store == nil {
		return AcornFoxManagementResult{}, errors.New("management service is unavailable")
	}
	if applicationID.Empty() || commandID.Empty() {
		return AcornFoxManagementResult{}, domain.ValidationError("management query identity is invalid")
	}
	return s.Store.GetManagementCommand(ctx, applicationID, commandID)
}

func (s *AcornFoxManagementService) ProcessOnce(ctx context.Context, limit int) (int, error) {
	if s == nil || s.Store == nil {
		return 0, errors.New("management service is unavailable")
	}
	if limit <= 0 {
		limit = 10
	}
	now := s.now()
	workerID := "mgmt-worker-" + domain.MustNewID("w").String()
	leases, err := s.Store.ClaimManagementCommandLeases(ctx, workerID, 2*time.Minute, limit, now)
	if err != nil || len(leases) == 0 {
		return 0, err
	}
	processed := 0
	for _, lease := range leases {
		if err := s.reconcileCommand(ctx, lease); err == nil {
			processed++
		}
	}
	return processed, nil
}

func (s *AcornFoxManagementService) reconcileCommand(ctx context.Context, lease AcornFoxManagementCommandLease) error {
	switch lease.Action {
	case "stop":
		return s.reconcileStop(ctx, lease)
	case "start":
		return s.reconcileStart(ctx, lease)
	case "archive":
		return s.reconcileArchive(ctx, lease)
	default:
		return fmt.Errorf("unknown management command action %s", lease.Action)
	}
}

func (s *AcornFoxManagementService) reconcileStop(ctx context.Context, lease AcornFoxManagementCommandLease) error {
	if len(lease.Targets) == 0 {
		return s.Store.UpdateManagementCommandPhase(ctx, lease, lease.Phase, "completed", "")
	}
	target := lease.Targets[0]

	switch lease.Phase {
	case "accepted":
		// P1-3: Atomically capture and save pause receipt before route disable
		receipt := AcornFoxPauseReceipt{
			DeploymentID:          target.DeploymentID,
			ApplicationID:         lease.ApplicationID,
			StopCommandID:         lease.CommandID,
			ReleaseID:             target.ReleaseID,
			ConfigIdentity:        target.ConfigIdentity,
			OriginalDesiredPublic: target.OriginalDesiredPublic,
			PauseEpoch:            1,
		}
		if target.OriginalDesiredPublic && s.PublicAccess != nil {
			intent, found, err := s.PublicAccess.Store.GetAcornFoxPublicRouteIntent(ctx, lease.ApplicationID, target.DeploymentID)
			if err == nil && found {
				receipt.CanonicalIntent = &intent
				raw, _ := json.Marshal(intent)
				h := sha256.Sum256(raw)
				receipt.IntentDigest = "sha256:" + hex.EncodeToString(h[:])
			}
		}
		if err := s.Store.SavePauseReceipt(ctx, lease, target, receipt); err != nil {
			return err
		}

		// Step 1: Close route before runtime stop
		expectedRev := target.Revision
		if target.OriginalDesiredPublic && s.PublicAccess != nil {
			routeKey := fmt.Sprintf("mgmt:stop:route:%s:%s", lease.CommandID, target.DeploymentID)
			_, err := s.PublicAccess.Set(ctx, AcornFoxPublicAccessRequest{
				ApplicationID:       lease.ApplicationID,
				DeploymentID:        target.DeploymentID,
				Enabled:             false,
				IdempotencyKey:      routeKey,
				ManagementCommandID: lease.CommandID,
			})
			if err != nil {
				return err
			}
			target.RoutePhase = "closed"
		} else {
			target.RoutePhase = "skipped"
		}
		if err := s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev); err != nil {
			return err
		}
		return s.Store.UpdateManagementCommandPhase(ctx, lease, "accepted", "runtime_stopping", "")

	case "route_closing":
		return s.Store.UpdateManagementCommandPhase(ctx, lease, "route_closing", "runtime_stopping", "")

	case "runtime_stopping":
		if target.RuntimeTaskID.Empty() {
			req, err := s.Delivery.Runtime.GetAcornFoxRuntimeRequest(ctx, lease.ApplicationID, target.DeploymentID)
			if err != nil {
				return err
			}
			childKey := fmt.Sprintf("mgmt:stop:task:%s:%s", lease.CommandID, target.DeploymentID)
			task, err := prepareManagementRuntimeTask(req.Fact, childKey, "system:management", domain.OperationStop, "stop", target.DeploymentID, s.now())
			if err != nil {
				return err
			}
			return s.Store.EnqueueTargetTask(ctx, lease, target, task)
		}

		state, failureReason, _, err := s.Store.GetTaskState(ctx, target.RuntimeTaskID)
		if err != nil {
			return err
		}
		switch state {
		case "completed":
			expectedRev := target.Revision
			target.Status = "completed"
			if err := s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev); err != nil {
				return err
			}
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "runtime_stopping", "completed", "")
		case "failed":
			expectedRev := target.Revision
			target.Status = "failed"
			target.FailureReason = failureReason
			_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "runtime_stopping", "failed", failureReason)
		default:
			return nil
		}
	}
	return nil
}

func (s *AcornFoxManagementService) reconcileStart(ctx context.Context, lease AcornFoxManagementCommandLease) error {
	if len(lease.Targets) == 0 {
		return s.Store.UpdateManagementCommandPhase(ctx, lease, lease.Phase, "completed", "")
	}
	target := lease.Targets[0]

	switch lease.Phase {
	case "accepted":
		// P1-3: Verify pause receipt exists and matches identity
		receipt, found, err := s.Store.GetPauseReceipt(ctx, lease.ApplicationID, target.DeploymentID)
		if err != nil || !found || receipt.Consumed {
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "accepted", "failed", "pause receipt missing or consumed")
		}
		if receipt.ConfigIdentity != target.ConfigIdentity {
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "accepted", "failed", "pause receipt configuration identity mismatch")
		}
		return s.Store.UpdateManagementCommandPhase(ctx, lease, "accepted", "runtime_starting", "")

	case "runtime_starting":
		if target.RuntimeTaskID.Empty() {
			req, err := s.Delivery.Runtime.GetAcornFoxRuntimeRequest(ctx, lease.ApplicationID, target.DeploymentID)
			if err != nil {
				return err
			}
			childKey := fmt.Sprintf("mgmt:start:task:%s:%s", lease.CommandID, target.DeploymentID)
			task, err := prepareManagementRuntimeTask(req.Fact, childKey, "system:management", domain.OperationStart, "start", target.DeploymentID, s.now())
			if err != nil {
				return err
			}
			return s.Store.EnqueueTargetTask(ctx, lease, target, task)
		}

		state, failureReason, _, err := s.Store.GetTaskState(ctx, target.RuntimeTaskID)
		if err != nil {
			return err
		}
		switch state {
		case "completed":
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "runtime_starting", "probing", "")
		case "failed":
			expectedRev := target.Revision
			target.Status = "failed"
			target.FailureReason = failureReason
			_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "runtime_starting", "failed", failureReason)
		default:
			return nil
		}

	case "probing":
		if target.ProbeTaskID.Empty() {
			probeKey := fmt.Sprintf("mgmt:start:probe:%s:%s", lease.CommandID, target.DeploymentID)
			probeResult, err := s.Delivery.Probe(ctx, AcornFoxDeliveryProbeRequest{
				AcornFoxDeliveryActionRequest: AcornFoxDeliveryActionRequest{
					ApplicationID:  lease.ApplicationID,
					DeploymentID:   target.DeploymentID,
					IdempotencyKey: probeKey,
					Actor:          "system:management",
				},
				Protocol: contracts.AcornFoxProbeProtocolHTTP,
				HTTPPath: "/",
			})
			if err != nil {
				return err
			}
			expectedRev := target.Revision
			target.ProbeTaskID = probeResult.TaskID
			return s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
		}

		state, failureReason, _, err := s.Store.GetTaskState(ctx, target.ProbeTaskID)
		if err != nil {
			return err
		}
		switch state {
		case "completed":
			receipt, found, _ := s.Store.GetPauseReceipt(ctx, lease.ApplicationID, target.DeploymentID)
			if found && receipt.OriginalDesiredPublic {
				return s.Store.UpdateManagementCommandPhase(ctx, lease, "probing", "route_restoring", "")
			}
			expectedRev := target.Revision
			target.RoutePhase = "skipped"
			target.Status = "completed"
			if err := s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev); err != nil {
				return err
			}
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "probing", "completed", "")
		case "failed":
			expectedRev := target.Revision
			target.Status = "failed"
			target.FailureReason = "health probe failed: " + failureReason
			_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "probing", "failed", target.FailureReason)
		default:
			return nil
		}

	case "route_restoring":
		receipt, found, err := s.Store.GetPauseReceipt(ctx, lease.ApplicationID, target.DeploymentID)
		if err != nil || !found || !receipt.OriginalDesiredPublic || receipt.CanonicalIntent == nil {
			expectedRev := target.Revision
			target.RoutePhase = "skipped"
			target.Status = "completed"
			_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "route_restoring", "completed", "")
		}

		// P1-3: Verify stored intent matches canonical pause receipt exactly
		currentIntent, found, err := s.PublicAccess.Store.GetAcornFoxPublicRouteIntent(ctx, lease.ApplicationID, target.DeploymentID)
		if err != nil || !found {
			expectedRev := target.Revision
			target.RoutePhase = "conflict"
			target.Status = "conflict"
			target.FailureReason = "route_restore_conflict: stored intent missing"
			_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "route_restoring", "completed", "")
		}
		currentRaw, _ := json.Marshal(currentIntent)
		h := sha256.Sum256(currentRaw)
		currentDigest := "sha256:" + hex.EncodeToString(h[:])
		if currentDigest != receipt.IntentDigest {
			expectedRev := target.Revision
			target.RoutePhase = "conflict"
			target.Status = "conflict"
			target.FailureReason = "route_restore_conflict: intent drifted"
			_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "route_restoring", "completed", "")
		}

		routeKey := fmt.Sprintf("mgmt:start:route:%s:%s", lease.CommandID, target.DeploymentID)
		_, err = s.PublicAccess.Set(ctx, AcornFoxPublicAccessRequest{
			ApplicationID:       lease.ApplicationID,
			DeploymentID:        target.DeploymentID,
			Enabled:             true,
			IdempotencyKey:      routeKey,
			ManagementCommandID: lease.CommandID,
		})
		if err != nil {
			return err
		}
		_ = s.Store.ConsumePauseReceipt(ctx, lease, target, receipt.PauseEpoch)
		expectedRev := target.Revision
		target.RoutePhase = "restored"
		target.Status = "completed"
		if err := s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev); err != nil {
			return err
		}
		return s.Store.UpdateManagementCommandPhase(ctx, lease, "route_restoring", "completed", "")
	}
	return nil
}

func (s *AcornFoxManagementService) reconcileArchive(ctx context.Context, lease AcornFoxManagementCommandLease) error {
	switch lease.Phase {
	case "accepted":
		for _, target := range lease.Targets {
			if target.OriginalDesiredPublic && target.RoutePhase != "closed" && s.PublicAccess != nil {
				routeKey := fmt.Sprintf("mgmt:archive:route:%s:%s", lease.CommandID, target.DeploymentID)
				_, err := s.PublicAccess.Set(ctx, AcornFoxPublicAccessRequest{
					ApplicationID:       lease.ApplicationID,
					DeploymentID:        target.DeploymentID,
					Enabled:             false,
					IdempotencyKey:      routeKey,
					ManagementCommandID: lease.CommandID,
				})
				if err != nil {
					return err
				}
				expectedRev := target.Revision
				target.RoutePhase = "closed"
				_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
			}
		}
		return s.Store.UpdateManagementCommandPhase(ctx, lease, "accepted", "runtime_destroying", "")

	case "runtime_destroying":
		allDestroyed := true
		for _, target := range lease.Targets {
			if target.Status == "completed" {
				continue
			}
			if target.RuntimeTaskID.Empty() {
				req, err := s.Delivery.Runtime.GetAcornFoxRuntimeRequest(ctx, lease.ApplicationID, target.DeploymentID)
				if err != nil {
					expectedRev := target.Revision
					target.Status = "completed"
					_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
					continue
				}
				childKey := fmt.Sprintf("mgmt:archive:destroy:%s:%s", lease.CommandID, target.DeploymentID)
				task, err := prepareManagementRuntimeTask(req.Fact, childKey, "system:management", domain.OperationDestroy, "destroy", target.DeploymentID, s.now())
				if err != nil {
					return err
				}
				if err := s.Store.EnqueueTargetTask(ctx, lease, target, task); err != nil {
					return err
				}
				allDestroyed = false
				continue
			}

			state, failureReason, _, err := s.Store.GetTaskState(ctx, target.RuntimeTaskID)
			if err != nil {
				return err
			}
			switch state {
			case "completed":
				// Task completed, ready for retention verification
			case "failed":
				expectedRev := target.Revision
				target.Status = "failed"
				target.FailureReason = failureReason
				_ = s.Store.UpdateManagementTarget(ctx, lease, target, expectedRev)
				return s.Store.UpdateManagementCommandPhase(ctx, lease, "runtime_destroying", "failed", failureReason)
			default:
				allDestroyed = false
			}
		}
		if allDestroyed {
			return s.Store.UpdateManagementCommandPhase(ctx, lease, "runtime_destroying", "verifying_retention", "")
		}
		return nil

	case "verifying_retention":
		// P1-4: Strongly-typed Observation projection and spec matching
		for _, target := range lease.Targets {
			if target.Status == "completed" && target.RuntimeTaskID.Empty() {
				continue
			}
			_, err := s.Store.GetValidatedManagementDestroyEvidence(ctx, lease, target)
			if err != nil {
				return s.Store.UpdateManagementCommandPhase(ctx, lease, "verifying_retention", "failed", "retention validation failed: "+err.Error())
			}
		}
		return s.Store.UpdateManagementCommandPhase(ctx, lease, "verifying_retention", "archived", "")

	case "archived":
		// P1-5: Atomic finalize archive
		return s.Store.FinalizeArchive(ctx, lease)
	}
	return nil
}

func prepareManagementRuntimeTask(fact contracts.AcornFoxRuntimeReleaseFact, idempotencyKey, actor string, opType domain.OperationType, action string, deploymentID domain.ID, now time.Time) (AcornFoxQueuedTask, error) {
	if err := fact.Validate(); err != nil {
		return AcornFoxQueuedTask{}, err
	}
	op, err := domain.NewOperation(fact.ApplicationID, fact.EnvironmentID, opType, "deployment/"+deploymentID.String(), idempotencyKey, now)
	if err != nil {
		return AcornFoxQueuedTask{}, err
	}
	taskID, err := domain.NewID("task")
	if err != nil {
		return AcornFoxQueuedTask{}, err
	}
	wireKind := v1.TaskKind(action)
	payloadRaw, err := json.Marshal(map[string]any{
		"kind": wireKind,
		"parameters": map[string]any{
			"acornfox_payload_type": action,
			"request": contracts.AcornFoxRuntimeActionRequest{
				Fact:           fact,
				IdempotencyKey: idempotencyKey,
			},
		},
	})
	if err != nil {
		return AcornFoxQueuedTask{}, err
	}
	redacted, err := foundation.RedactJSON(payloadRaw, nil)
	if err != nil {
		return AcornFoxQueuedTask{}, err
	}
	return AcornFoxQueuedTask{
		Operation:            op,
		ExistingDeploymentID: deploymentID,
		TaskID:               taskID,
		Payload:              redacted,
		MaxAttempts:          3,
	}, nil
}

func TargetSetDigest(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
