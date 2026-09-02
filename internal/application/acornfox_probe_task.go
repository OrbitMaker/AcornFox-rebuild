package application

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxProbeTaskPlan is the complete, durable intent for exactly one
// manually requested loopback probe. It is deliberately a value object: the
// caller decides when to enqueue it, and this package never schedules probes
// on its own.
type AcornFoxProbeTaskPlan struct {
	Operation domain.Operation
	TaskID    domain.ID
	Payload   json.RawMessage
}

// BuildAcornFoxProbeTaskPlan binds one validated probe request to the current
// objective runtime observation. The observation is used only to prove that a
// loopback publication exists now; it is never serialized as a caller-chosen
// network target.
func BuildAcornFoxProbeTaskPlan(request contracts.AcornFoxProbeRequest, current contracts.AcornFoxRuntimeObservation, now time.Time) (AcornFoxProbeTaskPlan, error) {
	if err := request.Validate(); err != nil {
		return AcornFoxProbeTaskPlan{}, fmt.Errorf("probe request is invalid: %w", err)
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil {
		return AcornFoxProbeTaskPlan{}, fmt.Errorf("probe deployment identity is invalid: %w", err)
	}
	if current.DeploymentID != deploymentID || current.ServiceName != request.Reference.Fact.ServiceName || current.ObservedAt.IsZero() {
		return AcornFoxProbeTaskPlan{}, fmt.Errorf("current runtime observation does not match probe request")
	}
	if err := validateAcornFoxProbeLoopbackFact(request.Reference.Fact.ContainerPort, current.InternalAddress); err != nil {
		return AcornFoxProbeTaskPlan{}, err
	}
	if now.IsZero() {
		return AcornFoxProbeTaskPlan{}, fmt.Errorf("probe task time is required")
	}
	operationID, err := contracts.AcornFoxRuntimeOperationID(request.Reference.Fact, "probe", request.IdempotencyKey)
	if err != nil {
		return AcornFoxProbeTaskPlan{}, fmt.Errorf("probe operation identity is invalid: %w", err)
	}
	operation := domain.Operation{
		ID:             domain.ID(operationID),
		ApplicationID:  request.Reference.Fact.ApplicationID,
		EnvironmentID:  request.Reference.Fact.EnvironmentID,
		TargetRef:      "deployment/" + deploymentID.String() + "/probe/" + request.Reference.Fact.ServiceName,
		Type:           domain.OperationObserve,
		IdempotencyKey: request.IdempotencyKey,
		Status:         domain.OperationPending,
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
	if err := operation.Validate(); err != nil {
		return AcornFoxProbeTaskPlan{}, err
	}
	parameters, err := json.Marshal(struct {
		PayloadType string                         `json:"acornfox_probe_payload_type"`
		Request     contracts.AcornFoxProbeRequest `json:"request"`
	}{PayloadType: "probe", Request: request})
	if err != nil {
		return AcornFoxProbeTaskPlan{}, err
	}
	payload, err := json.Marshal(struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}{Kind: v1.TaskObserve, Parameters: parameters})
	if err != nil {
		return AcornFoxProbeTaskPlan{}, err
	}
	// The operation identity is already a collision-resistant digest of the
	// immutable fact and caller key. Reusing it makes a restart/retry create
	// the same durable task rather than a second probe request.
	taskID := domain.ID("task_" + strings.TrimPrefix(operationID, "acornfox-runtime-probe-"))
	return AcornFoxProbeTaskPlan{Operation: operation, TaskID: taskID, Payload: payload}, nil
}

func validateAcornFoxProbeLoopbackFact(containerPort int, address string) error {
	if containerPort == 0 {
		if address != "" {
			return fmt.Errorf("runtime observation has an unexpected loopback address")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("runtime observation has no accepted loopback address")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("runtime observation has no accepted loopback address")
	}
	return nil
}
