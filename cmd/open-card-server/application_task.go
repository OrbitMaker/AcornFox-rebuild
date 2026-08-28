package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const applicationCreateTaskKind = "application.create"

// applicationTaskHandler owns the control-plane-only application creation
// acknowledgement. Creating the application/environment is already atomic in
// PostgreSQL; this durable task closes that operation without ever crossing
// the Agent trust boundary.
type applicationTaskHandler struct{}

func (applicationTaskHandler) Execute(_ context.Context, task postgres.ControllerTask, _ *controllers.TaskReporter) controllers.HandlerResult {
	var payload struct {
		Kind          string `json:"kind"`
		ApplicationID string `json:"application_id"`
		OperationID   string `json:"operation_id"`
	}
	if err := json.Unmarshal(task.Task.Payload, &payload); err != nil {
		return controllers.HandlerResult{Err: errors.New("application task payload is invalid"), FailureReason: "application task payload is invalid"}
	}
	if payload.Kind != applicationCreateTaskKind || payload.ApplicationID != task.Operation.ApplicationID.String() || payload.OperationID != task.Operation.ID.String() {
		return controllers.HandlerResult{Err: errors.New("application task identity mismatch"), FailureReason: "application task identity mismatch"}
	}
	return controllers.HandlerResult{EvidenceIDs: []string{"application.persisted"}}
}
