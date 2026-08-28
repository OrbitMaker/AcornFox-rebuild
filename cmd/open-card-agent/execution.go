package main

import (
	"context"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/foundation"
)

type TaskReporter interface {
	Log(v1.LogChunk)
	Observe(v1.Observation)
}

type TaskExecutor interface {
	Execute(context.Context, v1.TaskRequest, TaskReporter) v1.TaskResult
}

// RejectingTaskExecutor keeps the M0 Agent fail-closed until a real,
// allowlisted Docker executor is installed. Accepting a wire task must never
// be confused with successfully applying a runtime side effect.
type RejectingTaskExecutor struct{}

func (RejectingTaskExecutor) Execute(_ context.Context, request v1.TaskRequest, _ TaskReporter) v1.TaskResult {
	return v1.TaskResult{
		TaskID:         request.TaskID,
		IdempotencyKey: request.IdempotencyKey,
		Succeeded:      false,
		Status:         "failed",
		ErrorCode:      "unsupported_capability",
		ErrorMessage:   "no runtime executor is configured",
	}
}

type taskReporter struct{ task *agentTask }

func (r taskReporter) Log(value v1.LogChunk) {
	if value.TaskID == "" {
		value.TaskID = r.task.request.TaskID
	}
	r.task.appendLog(value)
}

func (r taskReporter) Observe(value v1.Observation) {
	if value.TaskID == "" {
		value.TaskID = r.task.request.TaskID
	}
	r.task.appendObservation(value)
}

type agentTask struct {
	mu           sync.Mutex
	request      v1.TaskRequest
	fingerprint  string
	state        string
	acceptedAt   time.Time
	startedAt    time.Time
	finishedAt   time.Time
	result       *v1.TaskResult
	logs         []v1.LogChunk
	observations []v1.Observation
	cancel       context.CancelFunc
	changed      chan struct{}
}

func newAgentTask(request v1.TaskRequest, fingerprint string, cancel context.CancelFunc) *agentTask {
	return &agentTask{
		request:     request,
		fingerprint: fingerprint,
		state:       "accepted",
		acceptedAt:  time.Now().UTC(),
		cancel:      cancel,
		changed:     make(chan struct{}),
	}
}

func (t *agentTask) markRunning() {
	t.mu.Lock()
	if t.state == "accepted" {
		t.state = "running"
		t.startedAt = time.Now().UTC()
		t.signalLocked()
	}
	t.mu.Unlock()
}

func (t *agentTask) finish(result v1.TaskResult) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.result != nil {
		return
	}
	copyResult := result
	copyResult.ErrorMessage = foundation.RedactText(copyResult.ErrorMessage)
	copyResult.EvidenceRefs = append([]string(nil), result.EvidenceRefs...)
	t.result = &copyResult
	t.finishedAt = time.Now().UTC()
	switch {
	case result.Status == "cancelled" || result.ErrorCode == "cancelled":
		t.state = "cancelled"
	case result.Succeeded:
		t.state = "succeeded"
	default:
		t.state = "failed"
	}
	t.signalLocked()
}

func (t *agentTask) cancelTask() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.result != nil {
		return false
	}
	t.state = "cancelling"
	t.cancel()
	t.signalLocked()
	return true
}

func (t *agentTask) appendLog(value v1.LogChunk) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.result != nil {
		return
	}
	value.Sequence = uint64(len(t.logs) + 1)
	value.Data = foundation.RedactText(value.Data)
	if err := value.Validate(); err != nil {
		return
	}
	t.logs = append(t.logs, value)
	t.signalLocked()
}

func (t *agentTask) appendObservation(value v1.Observation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.result != nil {
		return
	}
	value.Sequence = uint64(len(t.observations) + 1)
	if value.At.IsZero() {
		value.At = time.Now().UTC()
	}
	value.EvidenceRefs = append([]string(nil), value.EvidenceRefs...)
	if err := value.Validate(); err != nil {
		return
	}
	t.observations = append(t.observations, value)
	t.signalLocked()
}

func (t *agentTask) signalLocked() {
	close(t.changed)
	t.changed = make(chan struct{})
}

func (t *agentTask) snapshot() v1.TaskSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	snapshot := v1.TaskSnapshot{
		TaskID:         t.request.TaskID,
		IdempotencyKey: t.request.IdempotencyKey,
		Kind:           t.request.Kind,
		State:          t.state,
		AcceptedAt:     t.acceptedAt,
		StartedAt:      t.startedAt,
		FinishedAt:     t.finishedAt,
	}
	if t.result != nil {
		result := *t.result
		result.EvidenceRefs = append([]string(nil), t.result.EvidenceRefs...)
		snapshot.Result = &result
	}
	return snapshot
}

func (t *agentTask) logsAfter(position int) ([]v1.LogChunk, bool, <-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if position < 0 || position > len(t.logs) {
		position = len(t.logs)
	}
	values := append([]v1.LogChunk(nil), t.logs[position:]...)
	return values, t.result != nil, t.changed
}

func (t *agentTask) observationsAfter(position int) ([]v1.Observation, bool, <-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if position < 0 || position > len(t.observations) {
		position = len(t.observations)
	}
	values := append([]v1.Observation(nil), t.observations[position:]...)
	for index := range values {
		values[index].EvidenceRefs = append([]string(nil), values[index].EvidenceRefs...)
	}
	return values, t.result != nil, t.changed
}
