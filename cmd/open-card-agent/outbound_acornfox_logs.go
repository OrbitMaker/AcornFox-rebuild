package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	acornFoxLogsMaxChunks = contracts.AcornFoxLogsMaxRecords
	acornFoxLogsMaxBytes  = contracts.AcornFoxLogsMaxBytes
)

// acornFoxRuntimeLogger is intentionally narrower than RuntimeDriver. The
// executor can collect trusted runtime logs but cannot deploy, restart, scale,
// roll back, destroy, choose a container, or invoke an arbitrary command.
type acornFoxRuntimeLogger interface {
	contracts.AcornFoxBoundedLogReader
}

type AcornFoxLogsOutboundExecutor struct {
	instanceID string
	nodeID     string
	runtime    acornFoxRuntimeLogger
	clock      func() time.Time
}

type acornFoxLogsTaskPayload struct {
	PayloadType string          `json:"acornfox_log_payload_type"`
	Request     json.RawMessage `json:"request"`
}

type acornFoxLogsOutboundResult struct {
	Logs   []v1.LogChunk
	Result v1.TaskResult
}

func NewAcornFoxLogsOutboundExecutor(instanceID, nodeID string, runtime acornFoxRuntimeLogger) *AcornFoxLogsOutboundExecutor {
	return &AcornFoxLogsOutboundExecutor{instanceID: strings.TrimSpace(instanceID), nodeID: strings.TrimSpace(nodeID), runtime: runtime, clock: time.Now}
}

func acornFoxLogsPayloadMarked(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	if json.NewDecoder(bytes.NewReader(data)).Decode(&object) != nil {
		return false
	}
	_, present := object["acornfox_log_payload_type"]
	return present
}

func (e *AcornFoxLogsOutboundExecutor) Execute(ctx context.Context, task v1.TaskRequest) acornFoxLogsOutboundResult {
	if e == nil || e.runtime == nil {
		return rejectedAcornFoxLogs(task, "unsupported_capability", "AcornFox logs capability is unavailable")
	}
	if err := task.Validate(); err != nil || task.InstanceID != e.instanceID || task.NodeID != e.nodeID || !task.Deadline.After(e.now()) {
		return rejectedAcornFoxLogs(task, "invalid_argument", "AcornFox logs task is invalid")
	}
	if task.Kind != v1.TaskLogs {
		return rejectedAcornFoxLogs(task, "invalid_argument", "AcornFox logs payload type does not match task kind")
	}
	payload, err := decodeAcornFoxLogsPayload(task.Parameters)
	if err != nil || payload.PayloadType != "logs" {
		return rejectedAcornFoxLogs(task, "invalid_argument", "AcornFox logs task wrapper is invalid")
	}
	var request contracts.AcornFoxLogsRequest
	if err := decodeStrictJSON(payload.Request, &request); err != nil || request.IdempotencyKey != task.IdempotencyKey || request.Validate() != nil {
		return rejectedAcornFoxLogs(task, "invalid_argument", "AcornFox logs request is invalid")
	}
	taskContext, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()
	logs, err := e.runtime.ReadAcornFoxLogs(taskContext, contracts.LogsRequest{
		DeploymentID: request.DeploymentID,
		ServiceName:  request.ServiceName,
		Since:        request.Since,
		Tail:         request.Tail,
		Operation:    contracts.OperationContext{IdempotencyKey: task.IdempotencyKey, Deadline: task.Deadline},
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || taskContext.Err() != nil {
			return failedAcornFoxLogs(task, "runtime_logs_cancelled")
		}
		return failedAcornFoxLogs(task, "runtime_logs_failed")
	}
	if err := logs.Validate(); err != nil {
		return failedAcornFoxLogs(task, "runtime_logs_failed")
	}
	return collectAcornFoxLogs(taskContext, task, logs)
}

func (e *AcornFoxLogsOutboundExecutor) now() time.Time {
	if e.clock == nil {
		return time.Now()
	}
	return e.clock()
}

func decodeAcornFoxLogsPayload(data json.RawMessage) (acornFoxLogsTaskPayload, error) {
	var payload acornFoxLogsTaskPayload
	if err := decodeStrictJSON(data, &payload); err != nil || strings.TrimSpace(payload.PayloadType) == "" || len(payload.Request) == 0 {
		return acornFoxLogsTaskPayload{}, errors.New("AcornFox logs task wrapper is invalid")
	}
	return payload, nil
}

func collectAcornFoxLogs(ctx context.Context, task v1.TaskRequest, logs contracts.AcornFoxBoundedLogs) acornFoxLogsOutboundResult {
	result := acornFoxLogsOutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded}}
	remaining := acornFoxLogsMaxBytes
	select {
	case <-ctx.Done():
		return failedAcornFoxLogs(task, "runtime_logs_cancelled")
	default:
	}
	limited := logs.SourceLimited
	for _, record := range logs.Records {
		if len(result.Logs) == acornFoxLogsMaxChunks || remaining == 0 {
			limited = true
			break
		}
		if record.Stream != contracts.AcornFoxLogStreamStdout && record.Stream != contracts.AcornFoxLogStreamStderr {
			return failedAcornFoxLogs(task, "runtime_logs_failed")
		}
		data := record.Data
		if len(data) > remaining {
			data = data[:remaining]
			limited = true
		}
		// Redaction is performed immediately before the Agent envelope. The
		// provider's raw boundary is still authoritative for source limits.
		data = foundation.RedactText(data)
		if len(data) > remaining {
			data = data[:remaining]
			limited = true
		}
		if data == "" {
			continue
		}
		result.Logs = append(result.Logs, v1.LogChunk{TaskID: task.TaskID, Sequence: uint64(len(result.Logs) + 1), Stream: record.Stream, Data: data})
		remaining -= len(data)
	}
	if err := ctx.Err(); err != nil {
		return failedAcornFoxLogs(task, "runtime_logs_cancelled")
	}
	return finalizeAcornFoxLogs(result, limited)
}

func finalizeAcornFoxLogs(result acornFoxLogsOutboundResult, sourceLimited bool) acornFoxLogsOutboundResult {
	if len(result.Logs) > 0 {
		result.Logs[len(result.Logs)-1].Final = true
		result.Logs[len(result.Logs)-1].SourceLimited = sourceLimited
	}
	return result
}

func rejectedAcornFoxLogs(task v1.TaskRequest, code, message string) acornFoxLogsOutboundResult {
	return acornFoxLogsOutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: message}}
}

// Runtime errors are deliberately not emitted as log data. The server can
// safely classify by stable error code without serializing daemon details.
func failedAcornFoxLogs(task v1.TaskRequest, code string) acornFoxLogsOutboundResult {
	return acornFoxLogsOutboundResult{Result: v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Status: v1.TaskResultFailed, ErrorCode: code, ErrorMessage: "AcornFox logs collection failed"}}
}
