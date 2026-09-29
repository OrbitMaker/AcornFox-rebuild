package packprotocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseHealthResponse(t *testing.T) {
	valid := HealthResponse{
		Schema:          ProtocolSchemaV1,
		ProtocolVersion: ProtocolVersion1,
		PackID:          "pack-test",
		Version:         "1.0.0",
		InstanceID:      "inst-1",
		Status:          "ok",
		Capabilities:    []string{"diagnostic.observe"},
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal valid: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr bool
	}{
		{
			name:    "valid",
			mutate:  func(b []byte) []byte { return b },
			wantErr: false,
		},
		{
			name: "wrong schema",
			mutate: func(b []byte) []byte {
				return []byte(strings.Replace(string(b), ProtocolSchemaV1, "wrong-schema", 1))
			},
			wantErr: true,
		},
		{
			name: "wrong protocol version",
			mutate: func(b []byte) []byte {
				return []byte(strings.Replace(string(b), ProtocolVersion1, "2.0", 1))
			},
			wantErr: true,
		},
		{
			name: "duplicate keys rejected",
			mutate: func(b []byte) []byte {
				return []byte(`{"schema":"` + ProtocolSchemaV1 + `","schema":"` + ProtocolSchemaV1 + `"}`)
			},
			wantErr: true,
		},
		{
			name: "uppercase key rejected",
			mutate: func(b []byte) []byte {
				return []byte(`{"Schema":"` + ProtocolSchemaV1 + `"}`)
			},
			wantErr: true,
		},
		{
			name: "trailing json rejected",
			mutate: func(b []byte) []byte {
				return append(b, []byte(` {"extra":"json"}`)...)
			},
			wantErr: true,
		},
		{
			name: "oversized payload",
			mutate: func(b []byte) []byte {
				return []byte(`{"schema":"` + ProtocolSchemaV1 + `","padding":"` + strings.Repeat("x", MaxProtocolMessageBytes) + `"}`)
			},
			wantErr: true,
		},
		{
			name: "invalid pack id",
			mutate: func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `"pack_id":"pack-test"`, `"pack_id":"INVALID_ID"`, 1))
			},
			wantErr: true,
		},
		{
			name: "empty capabilities",
			mutate: func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `["diagnostic.observe"]`, `[]`, 1))
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseHealthResponse(tc.mutate(raw))
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseHealthResponse error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestObserveTaskProtocolWithWhitespaceAndSpecialChars(t *testing.T) {
	// 1. Diagnostic input with whitespace and special characters
	input := DiagnosticInputContext{
		Action: "observe.query",
		Target: "service:web & database <pg>",
		Param:  "{\n  \"flag\": true,\n  \"query\": \"select * from <tbl>\"\n}",
	}
	inputDigest, _, err := DigestDiagnosticInput(input)
	if err != nil {
		t.Fatalf("DigestDiagnosticInput: %v", err)
	}

	deadline := FormatCanonicalTime(time.Now().Add(time.Minute))
	req := ObserveTaskRequest{
		Schema:             ProtocolSchemaV1,
		ProtocolVersion:    ProtocolVersion1,
		TaskID:             "task_special_01",
		OperationID:        "op_special_01",
		PackID:             "pack-test",
		InstanceID:         "inst_special_01",
		InstanceGeneration: 1,
		CoreGeneration:     2,
		LeaseGeneration:    3,
		Kind:               KindDiagnosticObserve,
		Capability:         CapabilityDiagnosticObserve,
		InputDigest:        inputDigest,
		InputContext:       input,
		Deadline:           deadline,
	}

	rawReq, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}

	parsedReq, err := ParseObserveTaskRequest(rawReq)
	if err != nil {
		t.Fatalf("ParseObserveTaskRequest failed: %v", err)
	}
	if parsedReq.InputDigest != inputDigest || parsedReq.InputContext.Target != input.Target {
		t.Fatalf("parsed request mismatch: %+v", parsedReq)
	}

	// 2. Observation with special characters and timestamp
	occurredAt := FormatCanonicalTime(time.Now())
	observation := DiagnosticObservation{
		CheckedAt:   occurredAt,
		InputDigest: inputDigest,
		Status:      "healthy",
		Summary:     "diagnostic check observed <status=ok & healthy>",
	}
	obsDigest, _, err := DigestDiagnosticObservation(observation)
	if err != nil {
		t.Fatalf("DigestDiagnosticObservation: %v", err)
	}

	eventDigest := ComputeEventDigest(
		req.TaskID, req.InstanceID,
		req.CoreGeneration, req.LeaseGeneration, req.InstanceGeneration,
		1, KindDiagnosticObserve, inputDigest,
		true, "succeeded", occurredAt, obsDigest,
	)

	event := ObserveTaskEvent{
		Schema:             ProtocolSchemaV1,
		TaskID:             req.TaskID,
		InstanceID:         req.InstanceID,
		CoreGeneration:     req.CoreGeneration,
		LeaseGeneration:    req.LeaseGeneration,
		InstanceGeneration: req.InstanceGeneration,
		Sequence:           1,
		InputDigest:        inputDigest,
		EventDigest:        eventDigest,
		Kind:               KindDiagnosticObserve,
		Terminal:           true,
		TerminalStatus:     "succeeded",
		Observation:        observation,
		OccurredAt:         occurredAt,
	}

	rawEv, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	parsedEv, err := ParseObserveTaskEvent(rawEv)
	if err != nil {
		t.Fatalf("ParseObserveTaskEvent failed: %v", err)
	}
	if parsedEv.EventDigest != eventDigest {
		t.Fatalf("parsed event digest mismatch: %+v", parsedEv)
	}

	// 3. Semantic tamper cases: changing fields without updating digest must be rejected
	// Case 3a: tamper terminal from true to false
	tamperedTerminal := event
	tamperedTerminal.Terminal = false
	tamperedTerminal.TerminalStatus = ""
	rawTampered, _ := json.Marshal(tamperedTerminal)
	if _, err := ParseObserveTaskEvent(rawTampered); err == nil {
		t.Fatalf("expected error on tampered terminal field")
	}

	// Case 3b: tamper status from succeeded to failed
	tamperedStatus := event
	tamperedStatus.TerminalStatus = "failed"
	rawTamperedStatus, _ := json.Marshal(tamperedStatus)
	if _, err := ParseObserveTaskEvent(rawTamperedStatus); err == nil {
		t.Fatalf("expected error on tampered terminal status")
	}

	// Case 3c: tamper task ID
	tamperedTaskID := event
	tamperedTaskID.TaskID = "task_tampered"
	rawTamperedTask, _ := json.Marshal(tamperedTaskID)
	if _, err := ParseObserveTaskEvent(rawTamperedTask); err == nil {
		t.Fatalf("expected error on tampered task id")
	}

	// Case 3d: tamper generation fencing
	tamperedGen := event
	tamperedGen.CoreGeneration = 999
	rawTamperedGen, _ := json.Marshal(tamperedGen)
	if _, err := ParseObserveTaskEvent(rawTamperedGen); err == nil {
		t.Fatalf("expected error on tampered core generation")
	}

	// 4. Ack parsing with committed_at
	committedAt := FormatCanonicalTime(time.Now())
	ack := ObserveTaskAck{
		Schema:      ProtocolSchemaV1,
		ReceiptID:   "rcpt_test_01",
		TaskID:      req.TaskID,
		InstanceID:  req.InstanceID,
		Sequence:    1,
		EventDigest: eventDigest,
		Status:      "persisted",
		CommittedAt: committedAt,
	}
	rawAck, err := json.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	parsedAck, err := ParseObserveTaskAck(rawAck)
	if err != nil {
		t.Fatalf("ParseObserveTaskAck failed: %v", err)
	}
	if parsedAck.ReceiptID != "rcpt_test_01" || parsedAck.CommittedAt != committedAt {
		t.Fatalf("parsed ack mismatch: %+v", parsedAck)
	}
}
