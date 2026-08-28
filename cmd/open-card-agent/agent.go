package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
)

type Agent struct {
	InstanceID string
	NodeID     string
	Version    string
	ready      atomic.Bool
	mu         sync.Mutex
	seenTasks  map[string]struct{}
	tasksByKey map[string]*agentTask
	tasksByID  map[string]*agentTask
	executor   TaskExecutor
}

func NewAgent(instanceID, nodeID, version string) *Agent {
	return NewAgentWithExecutor(instanceID, nodeID, version, RejectingTaskExecutor{})
}

func NewAgentWithExecutor(instanceID, nodeID, version string, executor TaskExecutor) *Agent {
	if executor == nil {
		executor = RejectingTaskExecutor{}
	}
	agent := &Agent{
		InstanceID: strings.TrimSpace(instanceID),
		NodeID:     strings.TrimSpace(nodeID),
		Version:    strings.TrimSpace(version),
		seenTasks:  make(map[string]struct{}),
		tasksByKey: make(map[string]*agentTask),
		tasksByID:  make(map[string]*agentTask),
		executor:   executor,
	}
	agent.ready.Store(true)
	return agent
}

func (a *Agent) SetReady(ready bool)   { a.ready.Store(ready) }
func (a *Agent) Handler() http.Handler { return http.HandlerFunc(a.serveHTTP) }
func (a *Agent) HTTPServer(address string) *http.Server {
	return &http.Server{Addr: address, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
}

func (a *Agent) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/v1/agent/tasks/") {
		a.handleTaskResource(writer, request)
		return
	}
	switch request.URL.Path {
	case "/healthz":
		writeAgentJSON(writer, http.StatusOK, map[string]any{"status": "ok"})
	case "/readyz":
		if !a.ready.Load() {
			writeAgentJSON(writer, http.StatusServiceUnavailable, v1.ErrorResponse{Code: "not_ready", Message: "agent is not ready"})
			return
		}
		writeAgentJSON(writer, http.StatusOK, map[string]any{"status": "ok", "instance_id": a.InstanceID, "node_id": a.NodeID})
	case "/v1/agent/heartbeat":
		a.handleHeartbeat(writer, request)
	case "/v1/agent/tasks":
		a.handleTask(writer, request)
	default:
		writeAgentJSON(writer, http.StatusNotFound, v1.ErrorResponse{Code: "not_found", Message: "route not found"})
	}
}

func (a *Agent) handleHeartbeat(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeAgentJSON(writer, http.StatusMethodNotAllowed, v1.ErrorResponse{Code: "method_not_allowed", Message: "method not allowed"})
		return
	}
	var heartbeat v1.Heartbeat
	if err := decodeAgentJSON(writer, request, &heartbeat); err != nil {
		writeAgentJSON(writer, http.StatusBadRequest, v1.ErrorResponse{Code: "invalid_argument", Message: err.Error()})
		return
	}
	if err := heartbeat.Validate(); err != nil {
		writeAgentJSON(writer, http.StatusBadRequest, v1.ErrorResponse{Code: "invalid_heartbeat", Message: err.Error()})
		return
	}
	if heartbeat.InstanceID != a.InstanceID || heartbeat.NodeID != a.NodeID {
		writeAgentJSON(writer, http.StatusForbidden, v1.ErrorResponse{Code: "identity_mismatch", Message: "agent identity does not match registered node"})
		return
	}
	writeAgentJSON(writer, http.StatusOK, map[string]any{"accepted": true, "sequence": heartbeat.Sequence})
}

func (a *Agent) handleTask(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeAgentJSON(writer, http.StatusMethodNotAllowed, v1.ErrorResponse{Code: "method_not_allowed", Message: "method not allowed"})
		return
	}
	var task v1.TaskRequest
	if err := decodeAgentJSON(writer, request, &task); err != nil {
		writeAgentJSON(writer, http.StatusBadRequest, v1.ErrorResponse{Code: "invalid_argument", Message: err.Error()})
		return
	}
	if err := task.Validate(); err != nil {
		writeAgentJSON(writer, http.StatusBadRequest, v1.ErrorResponse{Code: "invalid_task", Message: err.Error()})
		return
	}
	if task.InstanceID != a.InstanceID || task.NodeID != a.NodeID {
		writeAgentJSON(writer, http.StatusForbidden, v1.ErrorResponse{Code: "identity_mismatch", Message: "agent identity does not match registered node"})
		return
	}
	if !task.Deadline.After(time.Now()) {
		writeAgentJSON(writer, http.StatusRequestTimeout, v1.ErrorResponse{Code: "task_deadline_elapsed", Message: "task deadline has elapsed"})
		return
	}
	fingerprint := taskFingerprint(task)
	a.mu.Lock()
	previous, duplicate := a.tasksByKey[task.IdempotencyKey]
	if duplicate && previous.fingerprint != fingerprint {
		a.mu.Unlock()
		writeAgentJSON(writer, http.StatusConflict, v1.ErrorResponse{Code: "idempotency_conflict", Message: "idempotency key was reused with different task input"})
		return
	}
	if duplicate {
		a.mu.Unlock()
		writeAgentJSON(writer, http.StatusOK, v1.TaskAck{TaskID: previous.request.TaskID, Status: v1.AckDuplicate})
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), task.Deadline)
	record := newAgentTask(task, fingerprint, cancel)
	a.seenTasks[task.IdempotencyKey] = struct{}{}
	a.tasksByKey[task.IdempotencyKey] = record
	a.tasksByID[task.TaskID] = record
	a.mu.Unlock()
	go a.executeTask(ctx, record)
	writeAgentJSON(writer, http.StatusAccepted, v1.TaskAck{TaskID: task.TaskID, Status: v1.AckAccepted})
}

func (a *Agent) executeTask(ctx context.Context, task *agentTask) {
	task.markRunning()
	reporter := taskReporter{task: task}
	result := a.executor.Execute(ctx, task.request, reporter)
	if result.TaskID == "" {
		result.TaskID = task.request.TaskID
	}
	if result.IdempotencyKey == "" {
		result.IdempotencyKey = task.request.IdempotencyKey
	}
	if ctx.Err() != nil && result.ErrorCode == "" {
		result.Succeeded = false
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = v1.TaskResultFailed
			result.ErrorCode = "timeout"
			result.ErrorMessage = "task deadline elapsed"
		} else {
			result.Status = v1.TaskResultCancelled
			result.ErrorCode = "cancelled"
			result.ErrorMessage = "task was cancelled"
		}
	}
	if err := result.Validate(); err != nil {
		result = v1.TaskResult{
			TaskID:         task.request.TaskID,
			IdempotencyKey: task.request.IdempotencyKey,
			Succeeded:      false,
			Status:         v1.TaskResultFailed,
			ErrorCode:      "invalid_executor_result",
			ErrorMessage:   err.Error(),
		}
	}
	task.finish(result)
}

func (a *Agent) handleTaskResource(writer http.ResponseWriter, request *http.Request) {
	remainder := strings.Trim(strings.TrimPrefix(request.URL.Path, "/v1/agent/tasks/"), "/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeAgentJSON(writer, http.StatusNotFound, v1.ErrorResponse{Code: "not_found", Message: "task not found"})
		return
	}
	a.mu.Lock()
	task := a.tasksByID[parts[0]]
	a.mu.Unlock()
	if task == nil {
		writeAgentJSON(writer, http.StatusNotFound, v1.ErrorResponse{Code: "not_found", Message: "task not found"})
		return
	}
	if len(parts) == 1 && request.Method == http.MethodGet {
		writeAgentJSON(writer, http.StatusOK, task.snapshot())
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && request.Method == http.MethodPost {
		a.handleCancelTask(writer, request, task)
		return
	}
	if len(parts) == 2 && parts[1] == "logs" && request.Method == http.MethodGet {
		streamTaskLogs(writer, request, task)
		return
	}
	if len(parts) == 2 && parts[1] == "observations" && request.Method == http.MethodGet {
		streamTaskObservations(writer, request, task)
		return
	}
	writeAgentJSON(writer, http.StatusMethodNotAllowed, v1.ErrorResponse{Code: "method_not_allowed", Message: "method not allowed"})
}

func (a *Agent) handleCancelTask(writer http.ResponseWriter, request *http.Request, task *agentTask) {
	var cancelRequest v1.CancelTask
	if err := decodeAgentJSON(writer, request, &cancelRequest); err != nil {
		writeAgentJSON(writer, http.StatusBadRequest, v1.ErrorResponse{Code: "invalid_argument", Message: err.Error()})
		return
	}
	if err := cancelRequest.Validate(); err != nil {
		writeAgentJSON(writer, http.StatusBadRequest, v1.ErrorResponse{Code: "invalid_cancel", Message: err.Error()})
		return
	}
	if cancelRequest.TaskID != task.request.TaskID || cancelRequest.IdempotencyKey != task.request.IdempotencyKey {
		writeAgentJSON(writer, http.StatusConflict, v1.ErrorResponse{Code: "task_identity_mismatch", Message: "cancel request does not match task"})
		return
	}
	if !task.cancelTask() {
		writeAgentJSON(writer, http.StatusConflict, v1.ErrorResponse{Code: "task_terminal", Message: "task is already terminal"})
		return
	}
	writeAgentJSON(writer, http.StatusAccepted, map[string]any{"accepted": true, "task_id": task.request.TaskID})
}

func streamTaskLogs(writer http.ResponseWriter, request *http.Request, task *agentTask) {
	streamTaskValues(writer, request, func(position int) ([]any, int, bool, <-chan struct{}) {
		logs, done, changed := task.logsAfter(position)
		values := make([]any, len(logs))
		for index := range logs {
			values[index] = logs[index]
		}
		return values, position + len(logs), done, changed
	})
}

func streamTaskObservations(writer http.ResponseWriter, request *http.Request, task *agentTask) {
	streamTaskValues(writer, request, func(position int) ([]any, int, bool, <-chan struct{}) {
		observations, done, changed := task.observationsAfter(position)
		values := make([]any, len(observations))
		for index := range observations {
			values[index] = observations[index]
		}
		return values, position + len(observations), done, changed
	})
}

func streamTaskValues(writer http.ResponseWriter, request *http.Request, next func(int) ([]any, int, bool, <-chan struct{})) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeAgentJSON(writer, http.StatusInternalServerError, v1.ErrorResponse{Code: "stream_unsupported", Message: "streaming is unavailable"})
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)
	position := 0
	for {
		values, newPosition, done, changed := next(position)
		for _, value := range values {
			encoded, err := json.Marshal(value)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(writer, "data: %s\n\n", encoded); err != nil {
				return
			}
		}
		position = newPosition
		flusher.Flush()
		if done {
			return
		}
		select {
		case <-request.Context().Done():
			return
		case <-changed:
		}
	}
}

func decodeAgentJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	if request.Body == nil {
		return fmt.Errorf("request body is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request body must contain one JSON value")
	}
	return nil
}

func taskFingerprint(task v1.TaskRequest) string {
	encoded, _ := json.Marshal(task)
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", digest[:])
}

func writeAgentJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
