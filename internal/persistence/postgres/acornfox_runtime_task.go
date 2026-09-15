package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// GetAcornFoxRuntimeRequest recovers only the originally validated runtime
// fact from a durable AcornFox deploy/redeploy task. It deliberately does not
// return generic task payloads, endpoints, Agent observations, or legacy M1/M2
// requests: restart, recreate and probe must reuse the accepted fact exactly.
func (s *Store) GetAcornFoxRuntimeRequest(ctx context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxRuntimeDeployRequest, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, err
	}
	if err := domain.RequireID(deploymentID, "deployment id"); err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.payload,d.environment_id,d.release_id
		  FROM task_leases t
		  JOIN operations o ON o.id=t.operation_id
		  JOIN deployments d ON d.id=o.deployment_id
		 WHERE d.id=$1 AND o.application_id=$2
		 ORDER BY t.created_at,t.task_id`, deploymentID.String(), applicationID.String())
	if err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, fmt.Errorf("query AcornFox runtime task: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload json.RawMessage
		var environmentID, releaseID domain.ID
		if err := rows.Scan(&payload, &environmentID, &releaseID); err != nil {
			return contracts.AcornFoxRuntimeDeployRequest{}, err
		}
		request, ok, err := decodeAcornFoxRuntimeTask(payload)
		if err != nil {
			return contracts.AcornFoxRuntimeDeployRequest{}, err
		}
		if !ok {
			continue
		}
		expected, err := contracts.AcornFoxRuntimeDeploymentID(request.Fact)
		if err != nil || expected != deploymentID || request.Fact.ApplicationID != applicationID || request.Fact.EnvironmentID != environmentID || request.Fact.ReleaseID != releaseID {
			return contracts.AcornFoxRuntimeDeployRequest{}, domain.ValidationError("AcornFox runtime task identity is invalid")
		}
		if request.Fact.SchemaVersion == 2 {
			if err := rows.Close(); err != nil {
				return contracts.AcornFoxRuntimeDeployRequest{}, err
			}
			release, err := s.GetRelease(ctx, releaseID)
			image := release.ServiceDigests()[request.Fact.ServiceName]
			if err != nil || release.ApplicationID != applicationID || release.ConfigDigest != request.Fact.ConfigDigest || len(release.ServiceDigests()) != 1 || image.Repository != request.Fact.Image.Repository || image.Digest != request.Fact.Image.Digest {
				return contracts.AcornFoxRuntimeDeployRequest{}, domain.ValidationError("runtime fact does not match accepted release")
			}
		}
		return request, nil
	}
	if err := rows.Err(); err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, err
	}
	return contracts.AcornFoxRuntimeDeployRequest{}, ErrNotFound
}

// GetAcornFoxRuntimeObservation returns the latest strict runtime observation
// emitted by the Agent for the immutable AcornFox deployment. Probe results
// are deliberately skipped: a response fact cannot be reinterpreted as a
// runtime observation, and no endpoint/readiness field is invented locally.
func (s *Store) GetAcornFoxRuntimeObservation(ctx context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxRuntimeObservation, error) {
	request, err := s.GetAcornFoxRuntimeRequest(ctx, applicationID, deploymentID)
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.payload
		  FROM task_agent_events e
		  JOIN task_leases t ON t.task_id=e.task_id
		  JOIN operations o ON o.id=t.operation_id
		 WHERE o.deployment_id=$1 AND e.event_type='observation'
		 ORDER BY e.created_at DESC,e.sequence DESC`, deploymentID.String())
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, fmt.Errorf("query AcornFox runtime observation: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload json.RawMessage
		if err := rows.Scan(&payload); err != nil {
			return contracts.AcornFoxRuntimeObservation{}, err
		}
		var event v1.Observation
		if err := decodeControllerTaskJSON(payload, &event); err != nil || len(event.Details) == 0 {
			continue
		}
		var observed contracts.AcornFoxRuntimeObservation
		if err := decodeControllerTaskJSON(event.Details, &observed); err != nil {
			continue
		}
		if observed.DeploymentID != deploymentID || observed.ServiceName != request.Fact.ServiceName || observed.ObservedAt.IsZero() || observed.RequestedResources != request.Fact.Resources || observed.AppliedLimits.CPUMillis != request.Fact.Resources.CPUMillis || observed.AppliedLimits.MemoryBytes != request.Fact.Resources.MemoryBytes || observed.AppliedLimits.PIDs != request.Fact.Resources.PIDs {
			continue
		}
		if request.Fact.ContainerPort == 0 && observed.InternalAddress != "" {
			continue
		}
		if request.Fact.ContainerPort > 0 && observed.InternalAddress == "" {
			continue
		}
		return observed, nil
	}
	if err := rows.Err(); err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	return contracts.AcornFoxRuntimeObservation{}, ErrNotFound
}

func (s *Store) NextAcornFoxDefinitionVersion(ctx context.Context, applicationID domain.ID) (int, error) {
	return s.nextAcornFoxVersion(ctx, applicationID, "delivery_definitions")
}
func (s *Store) NextAcornFoxReleaseVersion(ctx context.Context, applicationID domain.ID) (int, error) {
	return s.nextAcornFoxVersion(ctx, applicationID, "releases")
}
func (s *Store) nextAcornFoxVersion(ctx context.Context, applicationID domain.ID, table string) (int, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return 0, err
	}
	var next int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM `+table+` WHERE application_id=$1`, applicationID.String()).Scan(&next); err != nil {
		return 0, err
	}
	if next < 1 {
		return 0, errors.New("AcornFox version allocation is invalid")
	}
	return next, nil
}

func decodeAcornFoxRuntimeTask(payload json.RawMessage) (contracts.AcornFoxRuntimeDeployRequest, bool, error) {
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := decodeControllerTaskJSON(payload, &task); err != nil || task.Kind != v1.TaskDeploy {
		return contracts.AcornFoxRuntimeDeployRequest{}, false, nil
	}
	var wrapper struct {
		PayloadType string                                 `json:"acornfox_payload_type"`
		Request     contracts.AcornFoxRuntimeDeployRequest `json:"request"`
	}
	if err := decodeControllerTaskJSON(task.Parameters, &wrapper); err != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, false, nil
	}
	if wrapper.PayloadType != "deploy" && wrapper.PayloadType != "redeploy" {
		return contracts.AcornFoxRuntimeDeployRequest{}, false, nil
	}
	if wrapper.Request.Recreate != (wrapper.PayloadType == "redeploy") || wrapper.Request.Validate() != nil {
		return contracts.AcornFoxRuntimeDeployRequest{}, true, domain.ValidationError("AcornFox runtime task is invalid")
	}
	return wrapper.Request, true, nil
}
