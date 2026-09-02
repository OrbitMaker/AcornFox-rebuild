package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxRedactionEvidenceStore struct {
	task       postgres.ControllerTask
	redactions []string
	recorded   []postgres.AgentEventRequest
}

func (s *acornFoxRedactionEvidenceStore) GetControllerTask(_ context.Context, id domain.ID) (postgres.ControllerTask, error) {
	if id != s.task.Task.ID {
		return postgres.ControllerTask{}, postgres.ErrNotFound
	}
	return s.task, nil
}
func (s *acornFoxRedactionEvidenceStore) StartControllerTask(context.Context, domain.ID, string, time.Time) (application.Event, error) {
	return application.Event{}, nil
}
func (s *acornFoxRedactionEvidenceStore) RecordAgentEvent(_ context.Context, event postgres.AgentEventRequest) (postgres.AgentEventResult, error) {
	s.recorded = append(s.recorded, event)
	return postgres.AgentEventResult{}, nil
}
func (s *acornFoxRedactionEvidenceStore) FinishControllerTask(context.Context, postgres.FinishControllerTaskRequest) (postgres.FinishControllerTaskResult, error) {
	return postgres.FinishControllerTaskResult{}, nil
}
func (s *acornFoxRedactionEvidenceStore) FailControllerTask(context.Context, postgres.FailControllerTaskRequest) (postgres.FinishControllerTaskResult, error) {
	return postgres.FinishControllerTaskResult{}, nil
}
func (s *acornFoxRedactionEvidenceStore) GetAcornFoxDeliveryLogRedactionValues(context.Context, domain.ID, domain.ID) ([]string, error) {
	return append([]string(nil), s.redactions...), nil
}
func (s *acornFoxRedactionEvidenceStore) ListAcornFoxDeliveryLogIndexes(context.Context, domain.ID, domain.ID, postgres.LogIndexCategory, *postgres.AcornFoxLogIndexCursor, int) (postgres.AcornFoxDeliveryLogIndexes, error) {
	return postgres.AcornFoxDeliveryLogIndexes{}, nil
}

type acornFoxRedactionEvidenceProjector struct {
	logs *observability.LogStore
	seen v1.Envelope
}

func (p *acornFoxRedactionEvidenceProjector) ProjectAgentEvidence(_ context.Context, _ postgres.ControllerTask, envelope v1.Envelope) error {
	p.seen = envelope
	var chunk v1.LogChunk
	if err := json.Unmarshal(envelope.Payload, &chunk); err != nil {
		return err
	}
	return p.logs.Append(observability.LogCategoryRuntime, "redaction-evidence", []byte(chunk.Data))
}

func TestAcornFoxLogRedactionPrecedesEventPersistenceAndDiskProjection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_redaction", EnvironmentID: "env_redaction", ReleaseID: "release_redaction", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	request, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, time.Time{}, 1, "logs-redaction-proof")
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
	taskPayload, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskLogs, Parameters: parameters})
	if err != nil {
		t.Fatal(err)
	}
	locator, workspace, staticRoot := "https://private.example/repo.git", "/private/acornfox/workspace", "/private/acornfox/build"
	deploymentID := request.DeploymentID
	store := &acornFoxRedactionEvidenceStore{
		task:       postgres.ControllerTask{Task: postgres.Task{ID: "task_redaction", LeaseOwner: "node_redaction", Payload: taskPayload}, Operation: domain.Operation{ID: "operation_redaction", ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, IdempotencyKey: request.IdempotencyKey, Status: domain.OperationRunning}, DeploymentID: deploymentID},
		redactions: []string{locator, workspace},
	}
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	projector := &acornFoxRedactionEvidenceProjector{logs: logs}
	canaries := []string{"generic-token-should-redact", locator, workspace, staticRoot}
	data := "token=" + canaries[0]
	for _, canary := range canaries[1:] {
		data += " plain=" + canary + " url=" + base64.RawURLEncoding.EncodeToString([]byte(canary)) + " hex=" + hex.EncodeToString([]byte(canary))
	}
	payload, err := json.Marshal(v1.LogChunk{TaskID: "task_redaction", Sequence: 1, Stream: v1.LogStreamStdout, Data: data, Final: true})
	if err != nil {
		t.Fatal(err)
	}
	envelope := v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: "message_redaction", InstanceID: "instance_redaction", NodeID: "node_redaction", Kind: v1.KindLogChunk, SentAt: now, AgentSequence: 1, IdempotencyKey: request.IdempotencyKey, Payload: payload}
	sink := &controllers.DurableAgentSink{Store: store, Projector: projector, RedactEnvelope: newAcornFoxAgentLogEnvelopeRedactor(store, staticRoot), Clock: func() time.Time { return now }}
	if err := sink.RecordAgentEnvelope(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(store.recorded) != 1 || !reflect.DeepEqual(store.recorded[0].Payload, projector.seen.Payload) || v1.ValidateEnvelopePayload(projector.seen) != nil {
		t.Fatalf("persisted/projected envelope diverged: events=%#v projector=%#v", store.recorded, projector.seen)
	}
	raw, err := logs.Read(observability.LogCategoryRuntime, "redaction-evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range canaries {
		for _, representation := range []string{canary, base64.RawURLEncoding.EncodeToString([]byte(canary)), hex.EncodeToString([]byte(canary))} {
			if strings.Contains(string(store.recorded[0].Payload), representation) || strings.Contains(string(projector.seen.Payload), representation) || strings.Contains(string(raw), representation) {
				t.Fatalf("redaction canary leaked %q", representation)
			}
		}
	}

	nonLogPayload := json.RawMessage(`{"task_id":"task_redaction","sequence":1,"target_ref":"runtime/test","status":"observed","at":"2023-11-14T22:13:20Z"}`)
	nonLog := v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: "message_observation", InstanceID: "instance_redaction", NodeID: "node_redaction", Kind: v1.KindObservation, SentAt: now, AgentSequence: 1, IdempotencyKey: request.IdempotencyKey, Payload: nonLogPayload}
	redactedNonLog, err := newAcornFoxAgentLogEnvelopeRedactor(store, staticRoot)(context.Background(), store.task, nonLog)
	if err != nil || !reflect.DeepEqual(nonLog, redactedNonLog) {
		t.Fatalf("non-log event changed: err=%v before=%#v after=%#v", err, nonLog, redactedNonLog)
	}
}
