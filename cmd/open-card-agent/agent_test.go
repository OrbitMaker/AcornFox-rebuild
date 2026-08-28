package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
)

func TestAGENT_CT_002_RejectUnknownTask(t *testing.T) {
	agent := NewAgent("instance-1", "node-1", "test")
	server := httptest.NewServer(agent.Handler())
	defer server.Close()

	request := v1.TaskRequest{TaskID: "task-1", InstanceID: "instance-1", NodeID: "node-1", Kind: "shell", IdempotencyKey: "idem-1", LeaseID: "lease-1", Parameters: json.RawMessage(`{"command":"id"}`), Deadline: time.Now().Add(time.Minute)}
	response, err := postTask(server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected unknown task rejection, got %s", response.Status)
	}
	response.Body.Close()
}

func TestAGENT_CT_003_DeduplicateAllowedTask100Times(t *testing.T) {
	agent := NewAgent("instance-1", "node-1", "test")
	server := httptest.NewServer(agent.Handler())
	defer server.Close()
	request := v1.TaskRequest{TaskID: "task-1", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskObserve, IdempotencyKey: "idem-1", LeaseID: "lease-1", Parameters: json.RawMessage(`{"deployment_id":"dep-1"}`), Deadline: time.Now().Add(time.Minute)}
	response, err := postTask(server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected task acceptance, got %s", response.Status)
	}
	response.Body.Close()
	for attempt := 1; attempt < 100; attempt++ {
		response, err = postTask(server.URL, request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("expected duplicate task acknowledgement on attempt %d, got %s", attempt, response.Status)
		}
		var ack v1.TaskAck
		if err := json.NewDecoder(response.Body).Decode(&ack); err != nil {
			response.Body.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		if ack.Status != v1.AckDuplicate {
			t.Fatalf("unexpected duplicate acknowledgement: %#v", ack)
		}
	}
	agent.mu.Lock()
	seen := len(agent.seenTasks)
	agent.mu.Unlock()
	if seen != 1 {
		t.Fatalf("expected one idempotent side-effect record after 100 requests, got %d", seen)
	}
}

func TestAgentHeartbeatBindsNodeIdentity(t *testing.T) {
	agent := NewAgent("instance-1", "node-1", "test")
	server := httptest.NewServer(agent.Handler())
	defer server.Close()
	body, _ := json.Marshal(v1.Heartbeat{InstanceID: "instance-2", NodeID: "node-1", Sequence: 1, At: time.Now().UTC()})
	response, err := http.Post(server.URL+"/v1/agent/heartbeat", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected identity mismatch, got %s", response.Status)
	}
}

type cancellableExecutor struct{ started chan struct{} }

func (e *cancellableExecutor) Execute(ctx context.Context, request v1.TaskRequest, reporter TaskReporter) v1.TaskResult {
	reporter.Log(v1.LogChunk{TaskID: request.TaskID, Stream: "stdout", Data: "token=agent-canary"})
	reporter.Observe(v1.Observation{TaskID: request.TaskID, TargetRef: "deployment/dep-1", Status: "unknown", Healthy: false, EvidenceRefs: []string{"evidence/observation-1"}})
	close(e.started)
	<-ctx.Done()
	return v1.TaskResult{TaskID: request.TaskID, IdempotencyKey: request.IdempotencyKey, Succeeded: false, Status: "cancelled", ErrorCode: "cancelled", ErrorMessage: "cancelled by test", EvidenceRefs: []string{"evidence/cancel-1"}}
}

func TestAgentTaskCancellationAndReplayableStreams(t *testing.T) {
	executor := &cancellableExecutor{started: make(chan struct{})}
	agent := NewAgentWithExecutor("instance-1", "node-1", "test", executor)
	server := httptest.NewServer(agent.Handler())
	defer server.Close()
	task := v1.TaskRequest{TaskID: "task-cancel", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskObserve, IdempotencyKey: "idem-cancel", LeaseID: "lease-cancel", Parameters: json.RawMessage(`{"deployment_id":"dep-1"}`), Deadline: time.Now().Add(time.Minute)}
	response, err := postTask(server.URL, task)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("task status: %s", response.Status)
	}
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start")
	}
	cancelBody, _ := json.Marshal(v1.CancelTask{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Reason: "test cancellation"})
	cancelResponse, err := http.Post(server.URL+"/v1/agent/tasks/"+task.TaskID+"/cancel", "application/json", strings.NewReader(string(cancelBody)))
	if err != nil {
		t.Fatal(err)
	}
	cancelResponse.Body.Close()
	if cancelResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel status: %s", cancelResponse.Status)
	}

	waitForTaskState(t, server.URL, task.TaskID, "cancelled")
	assertSSEContains(t, server.URL+"/v1/agent/tasks/"+task.TaskID+"/logs", `"data":"token=[REDACTED]"`)
	assertSSEContains(t, server.URL+"/v1/agent/tasks/"+task.TaskID+"/observations", `"target_ref":"deployment/dep-1"`)
}

func TestAgentRejectsIdempotencyReuseWithDifferentTask(t *testing.T) {
	agent := NewAgent("instance-1", "node-1", "test")
	server := httptest.NewServer(agent.Handler())
	defer server.Close()
	task := v1.TaskRequest{TaskID: "task-one", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskObserve, IdempotencyKey: "same-key", LeaseID: "lease-one", Parameters: json.RawMessage(`{"deployment_id":"dep-1"}`), Deadline: time.Now().Add(time.Minute)}
	response, err := postTask(server.URL, task)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	task.TaskID = "task-two"
	task.Parameters = json.RawMessage(`{"deployment_id":"dep-2"}`)
	response, err = postTask(server.URL, task)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("expected idempotency conflict, got %s body=%s", response.Status, body)
	}
}

func waitForTaskState(t *testing.T, baseURL, taskID, wanted string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/v1/agent/tasks/" + taskID)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot map[string]any
		err = json.NewDecoder(response.Body).Decode(&snapshot)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if snapshot["state"] == wanted {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s", taskID, wanted)
}

func assertSSEContains(t *testing.T, url, wanted string) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), wanted) {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("SSE stream did not contain %q", wanted)
}

func postTask(url string, task v1.TaskRequest) (*http.Response, error) {
	body, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	return http.Post(url+"/v1/agent/tasks", "application/json", strings.NewReader(string(body)))
}
