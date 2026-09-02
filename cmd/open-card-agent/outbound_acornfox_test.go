package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxOutboundHandlerExecutesOnlyNarrowTypedLifecycle(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := &fakeAcornFoxRuntime{}
	handler := NewOutboundHandlerWithProvidersAndAcornFoxRuntime("instance-acorn", "node-acorn", staticDockerFacts{}, contracts.NewFakeRuntimeDriver(true), nil, nil, runtime)
	handler.healthProbe = func(context.Context, int, time.Time) error {
		t.Fatal("AcornFox task called legacy health probe")
		return nil
	}
	fixedNow := time.Unix(1700000000, 0).UTC()
	handler.clock = func() time.Time { return fixedNow }
	handler.acornFoxRuntime.clock = func() time.Time { return fixedNow }

	operations := []struct {
		name        string
		kind        v1.TaskKind
		payloadType string
		key         string
	}{
		{name: "deploy", kind: v1.TaskDeploy, payloadType: "deploy", key: "acorn-deploy"},
		{name: "redeploy", kind: v1.TaskDeploy, payloadType: "redeploy", key: "acorn-redeploy"},
		{name: "observe", kind: v1.TaskObserve, payloadType: "observe", key: "acorn-observe"},
		{name: "restart", kind: v1.TaskRestart, payloadType: "restart", key: "acorn-restart"},
		{name: "destroy", kind: v1.TaskDestroy, payloadType: "destroy", key: "acorn-destroy"},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			task := acornFoxTask(t, operation.kind, operation.payloadType, operation.key, fact)
			events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
			if err != nil {
				t.Fatal(err)
			}
			assertAcornFoxSuccessEvents(t, events)
			for _, event := range events {
				if event.Kind != v1.KindObservation {
					continue
				}
				var observation v1.Observation
				if err := json.Unmarshal(event.Payload, &observation); err != nil {
					t.Fatal(err)
				}
				if observation.Healthy {
					t.Fatalf("AcornFox %s claimed application health: %#v", operation.name, observation)
				}
				if operation.name != "destroy" && observation.Status != "running" {
					t.Fatalf("AcornFox %s did not preserve objective running state: %#v", operation.name, observation)
				}
			}
		})
	}
	if runtime.deploys != 1 || runtime.redeploys != 1 || runtime.observes != 4 || runtime.restarts != 1 || runtime.destroys != 1 {
		t.Fatalf("unexpected narrow runtime calls: %#v", runtime)
	}

	// The handler-level semantic replay cache preserves the exact event stream
	// and avoids a second provider effect even before the durable provider is
	// consulted again.
	replayTask := acornFoxTask(t, v1.TaskDeploy, "deploy", "acorn-replay", fact)
	first, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, replayTask))
	if err != nil {
		t.Fatal(err)
	}
	second, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, replayTask))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.deploys != 2 || len(first) != len(second) {
		t.Fatalf("idempotent replay repeated provider effect: calls=%#v", runtime)
	}
	for index := range first {
		if first[index].MessageID != second[index].MessageID {
			t.Fatalf("replay changed event %d identity", index)
		}
	}
}

func TestAcornFoxWireObservationUsesOnlyObjectiveContainerStates(t *testing.T) {
	fact := testAcornFoxFact()
	for _, state := range []string{"running", "exited"} {
		t.Run("preserves "+state, func(t *testing.T) {
			runtime := &fakeAcornFoxRuntime{state: state}
			handler := NewOutboundHandlerWithProvidersAndAcornFoxRuntime("instance-acorn", "node-acorn", staticDockerFacts{}, nil, nil, nil, runtime)
			task := acornFoxTask(t, v1.TaskDeploy, "deploy", "objective-"+state, fact)
			events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
			if err != nil {
				t.Fatal(err)
			}
			assertAcornFoxWireState(t, events, state)
		})
	}
	for _, forbidden := range acornFoxForbiddenRuntimeStates() {
		t.Run("normalizes "+forbidden, func(t *testing.T) {
			runtime := &fakeAcornFoxRuntime{state: forbidden}
			handler := NewOutboundHandlerWithProvidersAndAcornFoxRuntime("instance-acorn", "node-acorn", staticDockerFacts{}, nil, nil, nil, runtime)
			task := acornFoxTask(t, v1.TaskDeploy, "deploy", "forbidden-"+forbidden, fact)
			events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
			if err != nil {
				t.Fatal(err)
			}
			assertAcornFoxWireState(t, events, "unknown")
			for _, event := range events {
				if event.Kind != v1.KindObservation {
					continue
				}
				var observation v1.Observation
				if err := json.Unmarshal(event.Payload, &observation); err != nil {
					t.Fatal(err)
				}
				var details contracts.AcornFoxRuntimeObservation
				if err := json.Unmarshal(observation.Details, &details); err != nil {
					t.Fatal(err)
				}
				if details.RuntimeState == forbidden || strings.Contains(string(observation.Details), `"`+forbidden+`"`) {
					t.Fatalf("forbidden state leaked through AcornFox details: state=%q details=%s", forbidden, observation.Details)
				}
			}
		})
	}
}

func TestAcornFoxWireSourceDoesNotDeclareLegacyBusinessStates(t *testing.T) {
	source, err := os.ReadFile("outbound_acornfox.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range acornFoxForbiddenRuntimeStates() {
		if strings.Contains(string(source), `"`+forbidden+`"`) {
			t.Fatalf("AcornFox wire source declares forbidden runtime state %q", forbidden)
		}
	}
}

func acornFoxForbiddenRuntimeStates() []string {
	return []string{"healthy", "unhealthy", "pending", "preparing", "deploying", "runtime_ready", "degraded", "serving", "failed", "rolling_back", "rolled_back"}
}

func assertAcornFoxWireState(t *testing.T, events []v1.Envelope, want string) {
	t.Helper()
	for _, event := range events {
		if event.Kind != v1.KindObservation {
			continue
		}
		var observation v1.Observation
		if err := json.Unmarshal(event.Payload, &observation); err != nil {
			t.Fatal(err)
		}
		if observation.Status != want || observation.Healthy {
			t.Fatalf("AcornFox wire state = %#v, want status=%q healthy=false", observation, want)
		}
		var details contracts.AcornFoxRuntimeObservation
		if err := json.Unmarshal(observation.Details, &details); err != nil {
			t.Fatal(err)
		}
		if details.RuntimeState != want {
			t.Fatalf("AcornFox detail state = %q, want %q", details.RuntimeState, want)
		}
		return
	}
	t.Fatal("AcornFox task omitted objective observation")
}

func TestAcornFoxOutboundHandlerRejectsMalformedMismatchedAndNeverFallsThrough(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := &fakeAcornFoxRuntime{}
	handler := NewOutboundHandlerWithProvidersAndAcornFoxRuntime("instance-acorn", "node-acorn", staticDockerFacts{}, contracts.NewFakeRuntimeDriver(true), nil, nil, runtime)
	handler.healthProbe = func(context.Context, int, time.Time) error {
		t.Fatal("rejected AcornFox task called health probe")
		return nil
	}

	validDeploy := acornFoxTask(t, v1.TaskDeploy, "deploy", "valid-deploy", fact)
	cases := []struct {
		name string
		task v1.TaskRequest
	}{
		{name: "unknown marker", task: acornFoxTask(t, v1.TaskRestart, "shell", "unknown-marker", fact)},
		{name: "kind mismatch restart", task: acornFoxTask(t, v1.TaskRestart, "deploy", "mismatch-restart", fact)},
		{name: "kind mismatch rollback", task: acornFoxTask(t, v1.TaskRollback, "observe", "mismatch-rollback", fact)},
		{name: "kind mismatch scale", task: acornFoxTask(t, v1.TaskScale, "observe", "mismatch-scale", fact)},
		{name: "kind mismatch logs", task: acornFoxTask(t, v1.TaskLogs, "observe", "mismatch-logs", fact)},
		{name: "kind mismatch group", task: acornFoxTask(t, v1.TaskDeployGroup, "observe", "mismatch-group", fact)},
		{name: "wrapper unknown field", task: withAcornFoxParameters(t, validDeploy, `{"acornfox_payload_type":"deploy","request":{},"command":"docker ps"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, tc.task))
			if err != nil {
				t.Fatalf("marked task escaped typed rejection: %v", err)
			}
			if len(events) != 2 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindTaskResult {
				t.Fatalf("marked task fell through to a legacy executor: %#v", events)
			}
			var ack v1.TaskAck
			var result v1.TaskResult
			if err := json.Unmarshal(events[0].Payload, &ack); err != nil || ack.Status != v1.AckRejected {
				t.Fatalf("AcornFox rejection did not produce rejected ack: %#v err=%v", ack, err)
			}
			if err := json.Unmarshal(events[1].Payload, &result); err != nil || result.Succeeded || result.ErrorCode == "" {
				t.Fatalf("AcornFox rejection did not produce failed result: %#v err=%v", result, err)
			}
		})
	}
	// TaskRequest arrives from a JSON envelope in production, so a RawMessage
	// with a second value cannot be marshalled into that envelope. Exercise the
	// dispatcher boundary directly to prove the strict wrapper still rejects it
	// before any runtime effect if an in-process caller provides malformed data.
	trailing := withAcornFoxParameters(t, validDeploy, `{"acornfox_payload_type":"deploy","request":{}} {"scope":"node_docker_facts"}`)
	events, err := handler.executeTask(context.Background(), trailing)
	if err != nil || len(events) != 2 {
		t.Fatalf("trailing AcornFox wrapper escaped strict rejection: events=%#v err=%v", events, err)
	}
	var trailingAck v1.TaskAck
	if err := json.Unmarshal(events[0].Payload, &trailingAck); err != nil || trailingAck.Status != v1.AckRejected {
		t.Fatalf("trailing AcornFox wrapper was not rejected: %#v err=%v", trailingAck, err)
	}
	if runtime.deploys != 0 || runtime.redeploys != 0 || runtime.observes != 0 || runtime.restarts != 0 || runtime.destroys != 0 {
		t.Fatalf("rejected task reached AcornFox runtime: %#v", runtime)
	}
}

func TestComposeAcornFoxRuntimeReconcilesBeforeReturningCapabilities(t *testing.T) {
	provider := &reconcileOrderingRuntime{RuntimeDriver: contracts.NewFakeRuntimeDriver(true)}
	legacy, runtime, capabilities, err := composeAcornFoxRuntime(context.Background(), provider)
	if err != nil || provider.reconcileCalls != 1 || legacy != provider || runtime == nil {
		t.Fatalf("runtime composition did not reconcile before construction: legacy=%#v runtime=%#v calls=%d err=%v", legacy, runtime, provider.reconcileCalls, err)
	}
	seen := false
	for _, capability := range capabilities {
		if capability == v1.AgentCapabilityAcornFoxRuntime {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("reconciled runtime did not return AcornFox capability: %v", capabilities)
	}

	failed := &reconcileOrderingRuntime{RuntimeDriver: contracts.NewFakeRuntimeDriver(true), reconcileErr: errors.New("unsafe durable state")}
	legacy, runtime, capabilities, err = composeAcornFoxRuntime(context.Background(), failed)
	if err == nil || failed.reconcileCalls != 1 || legacy != nil || runtime != nil || len(capabilities) != 0 {
		t.Fatalf("failed reconcile advertised runtime: legacy=%#v runtime=%#v capabilities=%v calls=%d err=%v", legacy, runtime, capabilities, failed.reconcileCalls, err)
	}
}

func assertAcornFoxSuccessEvents(t *testing.T, events []v1.Envelope) {
	t.Helper()
	if len(events) != 4 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindLogChunk || events[2].Kind != v1.KindObservation || events[3].Kind != v1.KindTaskResult {
		t.Fatalf("unexpected AcornFox events: %#v", events)
	}
	var ack v1.TaskAck
	var result v1.TaskResult
	if err := json.Unmarshal(events[0].Payload, &ack); err != nil || ack.Status != v1.AckAccepted {
		t.Fatalf("unexpected AcornFox acknowledgement: %#v err=%v", ack, err)
	}
	if err := json.Unmarshal(events[3].Payload, &result); err != nil || !result.Succeeded || result.Status != v1.TaskResultSucceeded {
		t.Fatalf("unexpected AcornFox result: %#v err=%v", result, err)
	}
}

func acornFoxTask(t *testing.T, kind v1.TaskKind, payloadType, key string, fact contracts.AcornFoxRuntimeReleaseFact) v1.TaskRequest {
	t.Helper()
	var request any
	switch payloadType {
	case "deploy", "redeploy":
		request = contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: key, Recreate: payloadType == "redeploy"}
	case "observe":
		request = contracts.AcornFoxRuntimeReference{Fact: fact}
	default:
		request = contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: key}
	}
	encoded, err := json.Marshal(struct {
		PayloadType string `json:"acornfox_payload_type"`
		Request     any    `json:"request"`
	}{PayloadType: payloadType, Request: request})
	if err != nil {
		t.Fatal(err)
	}
	return v1.TaskRequest{TaskID: "task-" + key, InstanceID: "instance-acorn", NodeID: "node-acorn", Kind: kind, IdempotencyKey: key, LeaseID: "lease-" + key, Parameters: encoded, Deadline: time.Now().Add(time.Minute).UTC()}
}

func withAcornFoxParameters(t *testing.T, task v1.TaskRequest, parameters string) v1.TaskRequest {
	t.Helper()
	task.Parameters = json.RawMessage(parameters)
	return task
}

func testAcornFoxFact() contracts.AcornFoxRuntimeReleaseFact {
	return contracts.AcornFoxRuntimeReleaseFact{
		ApplicationID: "app_acorn", EnvironmentID: "env_acorn", ReleaseID: "rel_acorn", ServiceName: "web",
		Image:     domain.ImageDigest{Repository: "registry.open-card.test/acorn/web", Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 128 << 20, PIDs: 64, DiskReservationBytes: 256 << 20}, ContainerPort: 8080, AcceptedAt: time.Unix(1, 0).UTC(), Immutable: true,
	}
}

type fakeAcornFoxRuntime struct {
	deploys, redeploys, observes, restarts, destroys int
	destroyed                                        bool
	state                                            string
}

type reconcileOrderingRuntime struct {
	contracts.RuntimeDriver
	reconcileCalls int
	reconcileErr   error
}

func (r *reconcileOrderingRuntime) Reconcile(context.Context) error {
	r.reconcileCalls++
	return r.reconcileErr
}

func (r *reconcileOrderingRuntime) Recreate(_ context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	return domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentRuntimeReady, CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC()}, nil
}

func (f *fakeAcornFoxRuntime) Deploy(_ context.Context, request contracts.AcornFoxRuntimeDeployRequest) (contracts.AcornFoxRuntimeDeployment, error) {
	if err := request.Validate(); err != nil {
		return contracts.AcornFoxRuntimeDeployment{}, err
	}
	id, err := contracts.AcornFoxRuntimeDeploymentID(request.Fact)
	if err != nil {
		return contracts.AcornFoxRuntimeDeployment{}, err
	}
	if request.Recreate {
		f.redeploys++
	} else {
		f.deploys++
	}
	f.destroyed = false
	return contracts.AcornFoxRuntimeDeployment{DeploymentID: id, ApplicationID: request.Fact.ApplicationID, EnvironmentID: request.Fact.EnvironmentID, ReleaseID: request.Fact.ReleaseID, ServiceName: request.Fact.ServiceName, Image: request.Fact.Image, RuntimeState: "runtime_ready", OperationID: request.IdempotencyKey, RequestedResources: request.Fact.Resources}, nil
}

func (f *fakeAcornFoxRuntime) Observe(_ context.Context, reference contracts.AcornFoxRuntimeReference) (contracts.AcornFoxRuntimeObservation, error) {
	if err := reference.Fact.Validate(); err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	if f.destroyed {
		return contracts.AcornFoxRuntimeObservation{}, errors.New("deployment is stopped")
	}
	id, err := contracts.AcornFoxRuntimeDeploymentID(reference.Fact)
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	f.observes++
	state := f.state
	if state == "" {
		state = "running"
	}
	return contracts.AcornFoxRuntimeObservation{DeploymentID: id, ServiceName: reference.Fact.ServiceName, ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", RuntimeState: state, RestartCount: uint64(f.restarts), InternalAddress: "127.0.0.1:32001", RequestedResources: reference.Fact.Resources, AppliedLimits: contracts.AcornFoxRuntimeAppliedLimits{CPUMillis: reference.Fact.Resources.CPUMillis, MemoryBytes: reference.Fact.Resources.MemoryBytes, PIDs: reference.Fact.Resources.PIDs}, Disk: contracts.AcornFoxRuntimeDiskFact{ReservationBytes: reference.Fact.Resources.DiskReservationBytes}, ObservedAt: time.Unix(2, 0).UTC()}, nil
}

func (f *fakeAcornFoxRuntime) Restart(_ context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	f.restarts++
	return nil
}

func (f *fakeAcornFoxRuntime) Destroy(_ context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	f.destroys++
	f.destroyed = true
	return nil
}
