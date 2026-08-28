package v1

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAGENT_SCHEMA_001_EnvelopeRoundTripAndVersionGate(t *testing.T) {
	now := time.Now().UTC()
	payload, err := json.Marshal(Heartbeat{InstanceID: "instance-1", NodeID: "node-1", Sequence: 7, At: now})
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{Protocol: ProtocolName, Version: ProtocolVersion, MessageID: "msg-1", InstanceID: "instance-1", NodeID: "node-1", Kind: KindHeartbeat, SentAt: now, Payload: payload}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Protocol != ProtocolName || decoded.Version != ProtocolVersion || decoded.Kind != KindHeartbeat {
		t.Fatalf("unexpected decoded envelope: %#v", decoded)
	}
	decoded.Version = "v2"
	if _, err := EncodeEnvelope(decoded); err == nil {
		t.Fatal("expected incompatible protocol version to be rejected")
	}
}

func TestEnvelopePayloadValidationRejectsKindPayloadMismatch(t *testing.T) {
	envelope := Envelope{Protocol: ProtocolName, Version: ProtocolVersion, MessageID: "message-1", InstanceID: "instance-1", NodeID: "node-1", Kind: KindHeartbeat, SentAt: time.Now().UTC(), Payload: json.RawMessage(`{"task_id":"task-1"}`)}
	if err := ValidateEnvelopePayload(envelope); err == nil {
		t.Fatal("heartbeat envelope accepted a task-shaped payload")
	}
}

func TestAGENT_CT_002_TaskAllowlistAndIdempotencyFields(t *testing.T) {
	valid := TaskRequest{TaskID: "task-1", InstanceID: "instance-1", NodeID: "node-1", Kind: TaskObserve, IdempotencyKey: "idem-1", LeaseID: "lease-1", Parameters: json.RawMessage(`{"deployment_id":"dep-1"}`), Deadline: time.Unix(1700000000, 0)}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.Kind = TaskKind("shell")
	if err := valid.Validate(); err == nil {
		t.Fatal("expected arbitrary shell task to be rejected")
	}
	valid.Kind = TaskObserve
	valid.IdempotencyKey = ""
	if err := valid.Validate(); err == nil {
		t.Fatal("expected task without idempotency key to be rejected")
	}
}

func TestAGENT_CT_003_TaskRequestRejectsInvalidIdentityKindJSONAndDeadline(t *testing.T) {
	base := TaskRequest{
		TaskID:         "task-1",
		InstanceID:     "instance-1",
		NodeID:         "node-1",
		Kind:           TaskObserve,
		IdempotencyKey: "idem-1",
		LeaseID:        "lease-1",
		Parameters:     json.RawMessage(`{"deployment_id":"dep-1"}`),
		Deadline:       time.Unix(1700000000, 0),
	}
	cases := []struct {
		name   string
		mutate func(*TaskRequest)
	}{
		{name: "missing task id", mutate: func(request *TaskRequest) { request.TaskID = " " }},
		{name: "missing instance id", mutate: func(request *TaskRequest) { request.InstanceID = "" }},
		{name: "missing node id", mutate: func(request *TaskRequest) { request.NodeID = "" }},
		{name: "unallowlisted kind", mutate: func(request *TaskRequest) { request.Kind = TaskKind("shell") }},
		{name: "missing parameters", mutate: func(request *TaskRequest) { request.Parameters = nil }},
		{name: "malformed JSON", mutate: func(request *TaskRequest) { request.Parameters = json.RawMessage(`{"deployment_id":`) }},
		{name: "array JSON", mutate: func(request *TaskRequest) { request.Parameters = json.RawMessage(`[]`) }},
		{name: "null JSON", mutate: func(request *TaskRequest) { request.Parameters = json.RawMessage(`null`) }},
		{name: "scalar JSON", mutate: func(request *TaskRequest) { request.Parameters = json.RawMessage(`"deploy"`) }},
		{name: "zero deadline", mutate: func(request *TaskRequest) { request.Deadline = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := base
			tc.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", request)
			}
		})
	}

	for _, parameters := range []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"nested":{"enabled":true}}`)} {
		request := base
		request.Parameters = parameters
		if err := request.Validate(); err != nil {
			t.Fatalf("expected JSON object parameters %s to be accepted: %v", parameters, err)
		}
	}
}

func TestAGENT_CT_004_WireMessageValidation(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	t.Run("heartbeat", func(t *testing.T) {
		base := Heartbeat{InstanceID: "instance-1", NodeID: "node-1", Sequence: 1, At: now}
		cases := []struct {
			name   string
			mutate func(*Heartbeat)
		}{
			{name: "missing instance", mutate: func(value *Heartbeat) { value.InstanceID = "" }},
			{name: "missing node", mutate: func(value *Heartbeat) { value.NodeID = "" }},
			{name: "zero sequence", mutate: func(value *Heartbeat) { value.Sequence = 0 }},
			{name: "zero timestamp", mutate: func(value *Heartbeat) { value.At = time.Time{} }},
			{name: "negative CPU", mutate: func(value *Heartbeat) { value.Load.CPUMillis = -1 }},
		}
		assertInvalidCases(t, base, cases)
		if err := base.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("task ack", func(t *testing.T) {
		base := TaskAck{TaskID: "task-1", Status: AckAccepted}
		cases := []struct {
			name   string
			mutate func(*TaskAck)
		}{
			{name: "missing task", mutate: func(value *TaskAck) { value.TaskID = " " }},
			{name: "unsupported status", mutate: func(value *TaskAck) { value.Status = TaskAckStatus("queued") }},
			{name: "rejected without reason", mutate: func(value *TaskAck) { value.Status = AckRejected; value.Reason = "" }},
		}
		assertInvalidCases(t, base, cases)
		for _, status := range []TaskAckStatus{AckAccepted, AckDuplicate, AckRejected} {
			ack := base
			ack.Status = status
			if status == AckRejected {
				ack.Reason = "policy denied"
			}
			if err := ack.Validate(); err != nil {
				t.Fatalf("expected ack status %q to be accepted: %v", status, err)
			}
		}
	})

	t.Run("task result", func(t *testing.T) {
		base := TaskResult{TaskID: "task-1", IdempotencyKey: "idem-1", Succeeded: true, Status: TaskResultSucceeded, EvidenceRefs: []string{"result.json"}}
		cases := []struct {
			name   string
			mutate func(*TaskResult)
		}{
			{name: "missing task", mutate: func(value *TaskResult) { value.TaskID = "" }},
			{name: "missing idempotency key", mutate: func(value *TaskResult) { value.IdempotencyKey = "" }},
			{name: "unsupported status", mutate: func(value *TaskResult) { value.Status = "complete" }},
			{name: "success status mismatch", mutate: func(value *TaskResult) { value.Status = TaskResultFailed }},
			{name: "failure status mismatch", mutate: func(value *TaskResult) { value.Succeeded = false }},
			{name: "blank evidence ref", mutate: func(value *TaskResult) { value.EvidenceRefs = []string{" "} }},
		}
		assertInvalidCases(t, base, cases)
		failed := TaskResult{TaskID: "task-1", IdempotencyKey: "idem-1", Status: TaskResultFailed}
		if err := failed.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cancel task", func(t *testing.T) {
		base := CancelTask{TaskID: "task-1", IdempotencyKey: "idem-1", Reason: "operator requested"}
		cases := []struct {
			name   string
			mutate func(*CancelTask)
		}{
			{name: "missing task", mutate: func(value *CancelTask) { value.TaskID = "" }},
			{name: "missing idempotency key", mutate: func(value *CancelTask) { value.IdempotencyKey = "" }},
			{name: "missing reason", mutate: func(value *CancelTask) { value.Reason = "\t" }},
		}
		assertInvalidCases(t, base, cases)
	})

	t.Run("log chunk", func(t *testing.T) {
		base := LogChunk{TaskID: "task-1", Sequence: 1, Stream: LogStreamStdout, Data: "ready\n"}
		cases := []struct {
			name   string
			mutate func(*LogChunk)
		}{
			{name: "missing task", mutate: func(value *LogChunk) { value.TaskID = "" }},
			{name: "zero sequence", mutate: func(value *LogChunk) { value.Sequence = 0 }},
			{name: "unsupported stream", mutate: func(value *LogChunk) { value.Stream = "combined" }},
			{name: "blank stream", mutate: func(value *LogChunk) { value.Stream = " " }},
		}
		assertInvalidCases(t, base, cases)
		for _, stream := range []string{LogStreamStdout, LogStreamStderr} {
			chunk := base
			chunk.Stream = stream
			if err := chunk.Validate(); err != nil {
				t.Fatalf("expected log stream %q to be accepted: %v", stream, err)
			}
		}
	})

	t.Run("observation", func(t *testing.T) {
		base := Observation{TaskID: "task-1", Sequence: 1, TargetRef: "deployment/dep-1", Status: "healthy", Healthy: true, At: now, EvidenceRefs: []string{"observation.json"}}
		cases := []struct {
			name   string
			mutate func(*Observation)
		}{
			{name: "missing task", mutate: func(value *Observation) { value.TaskID = "" }},
			{name: "zero sequence", mutate: func(value *Observation) { value.Sequence = 0 }},
			{name: "missing target", mutate: func(value *Observation) { value.TargetRef = " " }},
			{name: "unsupported status", mutate: func(value *Observation) { value.Status = "not-a-status" }},
			{name: "zero timestamp", mutate: func(value *Observation) { value.At = time.Time{} }},
			{name: "blank evidence ref", mutate: func(value *Observation) { value.EvidenceRefs = []string{""} }},
			{name: "details are not an object", mutate: func(value *Observation) { value.Details = json.RawMessage(`[]`) }},
		}
		assertInvalidCases(t, base, cases)
		if err := base.Validate(); err != nil {
			t.Fatal(err)
		}
		degraded := base
		degraded.Status = "degraded"
		if err := degraded.Validate(); err != nil {
			t.Fatalf("aggregate optional-service degradation was rejected: %v", err)
		}
	})

	t.Run("task snapshot", func(t *testing.T) {
		base := TaskSnapshot{TaskID: "task-1", IdempotencyKey: "idem-1", Kind: TaskDeploy, State: TaskStateRunning, AcceptedAt: now, StartedAt: now.Add(time.Second)}
		cases := []struct {
			name   string
			mutate func(*TaskSnapshot)
		}{
			{name: "missing task", mutate: func(value *TaskSnapshot) { value.TaskID = "" }},
			{name: "missing idempotency key", mutate: func(value *TaskSnapshot) { value.IdempotencyKey = "" }},
			{name: "unsupported kind", mutate: func(value *TaskSnapshot) { value.Kind = TaskKind("shell") }},
			{name: "unsupported state", mutate: func(value *TaskSnapshot) { value.State = "not-a-state" }},
			{name: "missing accepted timestamp", mutate: func(value *TaskSnapshot) { value.AcceptedAt = time.Time{} }},
			{name: "started before acceptance", mutate: func(value *TaskSnapshot) { value.StartedAt = now.Add(-time.Second) }},
			{name: "finished before start", mutate: func(value *TaskSnapshot) { value.FinishedAt = now }},
			{name: "result identity mismatch", mutate: func(value *TaskSnapshot) {
				value.Result = &TaskResult{TaskID: "other-task", IdempotencyKey: "idem-1", Succeeded: true, Status: TaskResultSucceeded}
			}},
			{name: "invalid result evidence", mutate: func(value *TaskSnapshot) {
				value.Result = &TaskResult{TaskID: "task-1", IdempotencyKey: "idem-1", Succeeded: false, Status: TaskResultFailed, EvidenceRefs: []string{" "}}
			}},
		}
		assertInvalidCases(t, base, cases)
		if err := base.Validate(); err != nil {
			t.Fatal(err)
		}
		finished := base
		finished.State = TaskStateSucceeded
		finished.FinishedAt = now.Add(2 * time.Second)
		finished.Result = &TaskResult{TaskID: "task-1", IdempotencyKey: "idem-1", Succeeded: true, Status: TaskResultSucceeded, EvidenceRefs: []string{"result.json"}}
		if err := finished.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func assertInvalidCases[T any](t *testing.T, base T, cases []struct {
	name   string
	mutate func(*T)
}) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := base
			tc.mutate(&value)
			validator, ok := any(value).(interface{ Validate() error })
			if !ok {
				t.Fatal("test value does not implement Validate")
			}
			if err := validator.Validate(); err == nil {
				t.Fatalf("expected validation error for %#v", value)
			}
		})
	}
}
