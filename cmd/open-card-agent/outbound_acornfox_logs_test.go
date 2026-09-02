package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/foundation"
)

func TestAcornFoxLogsOutboundExecutorPreservesStreamsAndRedactsAtEnvelope(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := &acornFoxLogsRuntime{logs: contracts.AcornFoxBoundedLogs{Records: []contracts.AcornFoxLogRecord{
		{Stream: contracts.AcornFoxLogStreamStdout, Data: "service started\n"},
		{Stream: contracts.AcornFoxLogStreamStdout, Data: "token=must-not-leak\n"},
		{Stream: contracts.AcornFoxLogStreamStderr, Data: "Authorization: Bearer another-secret\n"},
	}}}
	handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, runtime, nil, nil, nil, nil)
	task := acornFoxLogsTask(t, "logs-happy", fact, time.Unix(10, 0).UTC(), 3)
	events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 || events[0].Kind != v1.KindTaskAck || events[4].Kind != v1.KindTaskResult || len(runtime.requests) != 1 {
		t.Fatalf("unexpected logs events=%#v requests=%#v", events, runtime.requests)
	}
	var first, second, third v1.LogChunk
	for index, target := range []*v1.LogChunk{&first, &second, &third} {
		if err := json.Unmarshal(events[index+1].Payload, target); err != nil {
			t.Fatal(err)
		}
		if target.Stream != []string{v1.LogStreamStdout, v1.LogStreamStdout, v1.LogStreamStderr}[index] || target.Sequence != uint64(index+1) || target.Final != (index == 2) {
			t.Fatalf("stream metadata=%#v", target)
		}
		if !strings.HasSuffix(target.Data, "\n") {
			t.Fatalf("logical log line %d has no delimiter: %q", index, target.Data)
		}
	}
	joined := first.Data + second.Data + third.Data
	if strings.Contains(joined, "must-not-leak") || strings.Contains(joined, "another-secret") || !strings.Contains(joined, foundation.RedactedValue) {
		t.Fatalf("runtime logs were not generically redacted: %q", joined)
	}
	got := runtime.requests[0]
	if got.DeploymentID == "" || got.ServiceName != fact.ServiceName || got.Tail != 3 || !got.Since.Equal(time.Unix(10, 0).UTC()) || got.Operation.IdempotencyKey != task.IdempotencyKey || !got.Operation.Deadline.Equal(task.Deadline) {
		t.Fatalf("legacy logs request was not derived from trusted facts: %#v", got)
	}
}

func TestCollectAcornFoxLogsPreservesLogicalLineBoundaries(t *testing.T) {
	task := acornFoxLogsTask(t, "logs-lines", testAcornFoxFact(), time.Time{}, 3)
	result := collectAcornFoxLogs(context.Background(), task, contracts.AcornFoxBoundedLogs{Records: []contracts.AcornFoxLogRecord{
		{Stream: contracts.AcornFoxLogStreamStdout, Data: "first"},
		{Stream: contracts.AcornFoxLogStreamStdout, Data: "second\n"},
		{Stream: contracts.AcornFoxLogStreamStderr, Data: "\n"},
	}})
	if !result.Result.Succeeded || len(result.Logs) != 3 {
		t.Fatalf("collection result=%#v", result)
	}
	for index, want := range []string{"first", "second\n", "\n"} {
		if got := result.Logs[index].Data; got != want {
			t.Fatalf("line %d got %q, want %q", index, got, want)
		}
	}
	if !result.Logs[2].Final || result.Logs[2].SourceLimited {
		t.Fatalf("final logical line metadata=%#v", result.Logs[2])
	}
}

func TestAcornFoxLogsOutboundExecutorEmptyTruncatedAndCancelled(t *testing.T) {
	fact := testAcornFoxFact()
	t.Run("empty", func(t *testing.T) {
		runtime := &acornFoxLogsRuntime{}
		executor := NewAcornFoxLogsOutboundExecutor("instance-acorn", "node-acorn", runtime)
		result := executor.Execute(context.Background(), acornFoxLogsTask(t, "logs-empty", fact, time.Time{}, 1))
		if !result.Result.Succeeded || len(result.Logs) != 0 {
			t.Fatalf("empty result=%#v", result)
		}
	})
	t.Run("source limited", func(t *testing.T) {
		records := make([]contracts.AcornFoxLogRecord, acornFoxLogsMaxChunks)
		for index := range records {
			records[index] = contracts.AcornFoxLogRecord{Stream: contracts.AcornFoxLogStreamStdout, Data: "line\n"}
		}
		runtime := &acornFoxLogsRuntime{logs: contracts.AcornFoxBoundedLogs{Records: records, SourceLimited: true}}
		result := NewAcornFoxLogsOutboundExecutor("instance-acorn", "node-acorn", runtime).Execute(context.Background(), acornFoxLogsTask(t, "logs-limited", fact, time.Time{}, contracts.AcornFoxLogsMaxTail))
		if !result.Result.Succeeded || len(result.Logs) != acornFoxLogsMaxChunks || !result.Logs[len(result.Logs)-1].Final || !result.Logs[len(result.Logs)-1].SourceLimited {
			t.Fatalf("truncation metadata=%#v", result)
		}
	})
	t.Run("oversize source limited", func(t *testing.T) {
		runtime := &acornFoxLogsRuntime{logs: contracts.AcornFoxBoundedLogs{Records: []contracts.AcornFoxLogRecord{{Stream: contracts.AcornFoxLogStreamStdout, Data: strings.Repeat("x", acornFoxLogsMaxBytes+1)}}}}
		result := NewAcornFoxLogsOutboundExecutor("instance-acorn", "node-acorn", runtime).Execute(context.Background(), acornFoxLogsTask(t, "logs-oversize", fact, time.Time{}, 1))
		if result.Result.Succeeded || result.Result.ErrorCode != "runtime_logs_failed" || len(result.Logs) != 0 {
			t.Fatalf("oversize provider result was not rejected without chunks: %#v", result)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		runtime := &acornFoxLogsRuntime{respectContext: true}
		executor := NewAcornFoxLogsOutboundExecutor("instance-acorn", "node-acorn", runtime)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := executor.Execute(ctx, acornFoxLogsTask(t, "logs-cancelled", fact, time.Time{}, 1))
		if result.Result.ErrorCode != "runtime_logs_cancelled" || result.Result.Succeeded || len(result.Logs) != 0 {
			t.Fatalf("cancel result=%#v", result)
		}
	})
}

func TestAcornFoxLogsStrictMarkerRoutingRejectsWithoutLegacyFallback(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := &acornFoxLogsRuntime{}
	handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, runtime, nil, nil, nil, nil)
	valid := acornFoxLogsTask(t, "logs-strict", fact, time.Time{}, 1)
	cases := []struct {
		name string
		task v1.TaskRequest
	}{
		{name: "unknown marker", task: acornFoxLogsWithParameters(valid, `{"acornfox_log_payload_type":"shell","request":{}}`)},
		{name: "kind mismatch", task: acornFoxLogsWithKind(valid, v1.TaskObserve)},
		{name: "marker collision", task: acornFoxLogsWithParameters(valid, `{"acornfox_log_payload_type":"logs","acornfox_probe_payload_type":"probe","request":{}}`)},
		{name: "command rejected", task: acornFoxLogsWithParameters(valid, `{"acornfox_log_payload_type":"logs","request":{},"command":"docker ps"}`)},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			task := test.task
			task.TaskID = "task-logs-strict-" + string(rune('a'+index))
			task.IdempotencyKey = "logs-strict-" + string(rune('a'+index))
			task.LeaseID = "lease-" + task.IdempotencyKey
			events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
			if err != nil || len(events) != 2 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindTaskResult {
				t.Fatalf("events=%#v err=%v", events, err)
			}
			var result v1.TaskResult
			if err := json.Unmarshal(events[1].Payload, &result); err != nil || result.ErrorCode != "invalid_argument" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
	trailing := acornFoxLogsWithParameters(valid, `{"acornfox_log_payload_type":"logs","request":{}} {"ignored":true}`)
	trailing.TaskID = "task-logs-trailing"
	trailing.IdempotencyKey = "logs-trailing"
	trailing.LeaseID = "lease-logs-trailing"
	events, err := handler.executeTask(context.Background(), trailing)
	if err != nil || len(events) != 2 {
		t.Fatalf("trailing task events=%#v err=%v", events, err)
	}
	var trailingResult v1.TaskResult
	if err := json.Unmarshal(events[1].Payload, &trailingResult); err != nil || trailingResult.ErrorCode != "invalid_argument" {
		t.Fatalf("trailing task result=%#v err=%v", trailingResult, err)
	}
	if len(runtime.requests) != 0 {
		t.Fatalf("invalid marked task fell through to legacy runtime: %#v", runtime.requests)
	}
}

func TestAcornFoxLogsRequireBoundedReaderWithoutLegacyFallback(t *testing.T) {
	fact := testAcornFoxFact()
	// The legacy fake implements RuntimeDriver.Logs, but it deliberately does
	// not implement the AcornFox bounded reader contract.
	handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, contracts.NewFakeRuntimeDriver(true), nil, nil, nil, nil)
	events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, acornFoxLogsTask(t, "logs-no-bounded-reader", fact, time.Time{}, 1)))
	if err != nil || len(events) != 2 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindTaskResult {
		t.Fatalf("legacy runtime received marked AcornFox logs task: events=%#v err=%v", events, err)
	}
	var ack v1.TaskAck
	var result v1.TaskResult
	if err := json.Unmarshal(events[0].Payload, &ack); err != nil || ack.Status != v1.AckRejected {
		t.Fatalf("missing bounded reader did not reject task: %#v err=%v", ack, err)
	}
	if err := json.Unmarshal(events[1].Payload, &result); err != nil || result.ErrorCode != "unsupported_capability" || len(events) != 2 {
		t.Fatalf("missing bounded reader emitted unsafe fallback: %#v err=%v", result, err)
	}
}

func acornFoxLogsTask(t *testing.T, key string, fact contracts.AcornFoxRuntimeReleaseFact, since time.Time, tail int) v1.TaskRequest {
	t.Helper()
	request, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, since, tail, key)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := json.Marshal(struct {
		PayloadType string                        `json:"acornfox_log_payload_type"`
		Request     contracts.AcornFoxLogsRequest `json:"request"`
	}{PayloadType: "logs", Request: request})
	if err != nil {
		t.Fatal(err)
	}
	return v1.TaskRequest{TaskID: "task-" + key, InstanceID: "instance-acorn", NodeID: "node-acorn", Kind: v1.TaskLogs, IdempotencyKey: key, LeaseID: "lease-" + key, Parameters: parameters, Deadline: time.Now().Add(time.Minute).UTC()}
}

func acornFoxLogsWithParameters(task v1.TaskRequest, parameters string) v1.TaskRequest {
	task.Parameters = json.RawMessage(parameters)
	return task
}

func acornFoxLogsWithKind(task v1.TaskRequest, kind v1.TaskKind) v1.TaskRequest {
	task.Kind = kind
	return task
}

type acornFoxLogsRuntime struct {
	contracts.RuntimeDriver
	logs           contracts.AcornFoxBoundedLogs
	err            error
	respectContext bool
	requests       []contracts.LogsRequest
}

func (r *acornFoxLogsRuntime) ReadAcornFoxLogs(ctx context.Context, request contracts.LogsRequest) (contracts.AcornFoxBoundedLogs, error) {
	r.requests = append(r.requests, request)
	if r.respectContext && ctx.Err() != nil {
		return contracts.AcornFoxBoundedLogs{}, ctx.Err()
	}
	if r.err != nil {
		return contracts.AcornFoxBoundedLogs{}, r.err
	}
	return r.logs, nil
}

func TestAcornFoxLogsRuntimeFailureUsesStableCode(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := &acornFoxLogsRuntime{err: errors.New("token=must-not-leak")}
	result := NewAcornFoxLogsOutboundExecutor("instance-acorn", "node-acorn", runtime).Execute(context.Background(), acornFoxLogsTask(t, "logs-failure", fact, time.Time{}, 1))
	if result.Result.Succeeded || result.Result.ErrorCode != "runtime_logs_failed" || len(result.Logs) != 0 || strings.Contains(result.Result.ErrorMessage, "must-not-leak") {
		t.Fatalf("runtime failure escaped stable boundary: %#v", result)
	}
}
