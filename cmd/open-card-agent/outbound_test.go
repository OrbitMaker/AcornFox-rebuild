package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type staticDockerFacts struct{ facts DockerFacts }

func (s staticDockerFacts) ReadFacts(context.Context) (DockerFacts, error) { return s.facts, nil }

type fakeGroupRuntime struct {
	observation contracts.ServiceGroupRuntimeObservation
	destroyed   int
}

func (f *fakeGroupRuntime) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "fake-group-runtime", Version: "m2", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityRuntimeDeployGroup, contracts.CapabilityRuntimeObserveGroup, contracts.CapabilityRuntimeDestroyGroup)}
}

func (f *fakeGroupRuntime) DeployGroup(_ context.Context, request contracts.DeployGroupRequest) (domain.Deployment, error) {
	now := time.Now().UTC()
	return domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentRuntimeReady, CreatedAt: now, UpdatedAt: now}, nil
}

func (f *fakeGroupRuntime) ObserveGroup(context.Context, contracts.ObserveGroupRequest) (contracts.ServiceGroupRuntimeObservation, error) {
	return f.observation, nil
}

func (f *fakeGroupRuntime) RollbackGroup(_ context.Context, request contracts.RollbackGroupRequest) (domain.Deployment, error) {
	now := time.Now().UTC()
	return domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Target.ApplicationID, EnvironmentID: request.Target.EnvironmentID, ReleaseID: request.Target.ReleaseID, Status: domain.DeploymentRuntimeReady, CreatedAt: now, UpdatedAt: now}, nil
}

func (f *fakeGroupRuntime) DestroyGroup(context.Context, contracts.DestroyRequest) error {
	f.destroyed++
	return nil
}

func TestOutboundHandlerAllowsOnlyReadOnlyDockerObservation(t *testing.T) {
	handler := NewOutboundHandler("instance-1", "node-1", staticDockerFacts{facts: DockerFacts{ServerVersion: "29.1.3", APIVersion: "1.52", OperatingSystem: "Ubuntu", Architecture: "x86_64", CPUs: 8, MemoryBytes: 16 << 30, Containers: 4, ContainersRunning: 2, ContainersStopped: 2}})
	handler.clock = func() time.Time { return time.Unix(100, 0).UTC() }
	task := v1.TaskRequest{TaskID: "task-facts", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskObserve, IdempotencyKey: "facts-1", LeaseID: "lease-1", Parameters: json.RawMessage(`{"scope":"node_docker_facts"}`), Deadline: time.Now().Add(time.Minute)}
	envelope := controlTaskEnvelope(t, task)
	events, err := handler.HandleControlEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindLogChunk || events[2].Kind != v1.KindObservation || events[3].Kind != v1.KindTaskResult {
		t.Fatalf("unexpected outbound event sequence: %#v", events)
	}
	var observation v1.Observation
	if err := json.Unmarshal(events[2].Payload, &observation); err != nil {
		t.Fatal(err)
	}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	var facts DockerFacts
	if err := json.Unmarshal(observation.Details, &facts); err != nil {
		t.Fatal(err)
	}
	if facts.ServerVersion != "29.1.3" || facts.CPUs != 8 {
		t.Fatalf("observation omitted Docker facts: %#v", facts)
	}

	replayed, err := handler.HandleControlEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	for index := range events {
		if replayed[index].MessageID != events[index].MessageID {
			t.Fatalf("idempotent replay changed message %d identity", index)
		}
	}
	takeover := task
	takeover.LeaseID = "lease-2"
	takeover.Deadline = task.Deadline.Add(time.Minute)
	takenOver, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, takeover))
	if err != nil {
		t.Fatalf("durable lease takeover rejected semantic replay: %v", err)
	}
	for index := range events {
		if takenOver[index].MessageID != events[index].MessageID {
			t.Fatalf("lease takeover changed replayed message %d identity", index)
		}
	}
	conflict := task
	conflict.Parameters = json.RawMessage(`{"scope":"node_docker_facts","extra":true}`)
	if _, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, conflict)); err == nil {
		t.Fatal("outbound task idempotency key accepted different input")
	}
}

func TestOutboundHandlerDeploysDigestAndRequiresHealthyObservation(t *testing.T) {
	runtime := contracts.NewFakeRuntimeDriver(true)
	handler := NewOutboundHandlerWithRuntime("instance-1", "node-1", staticDockerFacts{}, runtime)
	handler.healthProbe = func(context.Context, int, time.Time) error { return nil }
	deadline := time.Now().Add(time.Minute).UTC()
	request := contracts.DeployRequest{
		DeploymentID: domain.ID("dep_1234567890abcdef"),
		Spec: contracts.RuntimeSpec{
			ApplicationID: domain.ID("app_1234567890abcdef"), EnvironmentID: domain.ID("env_1234567890abcdef"), ReleaseID: domain.ID("rel_1234567890abcdef"),
			ServiceName: "web", Image: domain.ImageDigest{Repository: "opencard/web", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Resources: contracts.ResourceLimits{CPUMillis: 500, MemoryBytes: 256 << 20, DiskBytes: 512 << 20, PIDs: 64}, Port: 8080,
		},
		Operation: contracts.OperationContext{IdempotencyKey: "deploy-runtime-1", Deadline: deadline},
	}
	parameters, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	task := v1.TaskRequest{TaskID: "task-deploy-runtime", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskDeploy, IdempotencyKey: request.Operation.IdempotencyKey, LeaseID: "lease-1", Parameters: parameters, Deadline: deadline}
	events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[2].Kind != v1.KindObservation || events[3].Kind != v1.KindTaskResult {
		t.Fatalf("unexpected deploy event sequence: %#v", events)
	}
	var observation v1.Observation
	if err := json.Unmarshal(events[2].Payload, &observation); err != nil || !observation.Healthy || observation.TargetRef != "deployment/"+request.DeploymentID.String() {
		t.Fatalf("deploy did not return a healthy bound observation: %#v err=%v", observation, err)
	}
	var runtimeObservation contracts.RuntimeObservation
	if err := json.Unmarshal(observation.Details, &runtimeObservation); err != nil || runtimeObservation.Limits != request.Spec.Resources {
		t.Fatalf("runtime observation omitted applied limits: %#v err=%v", runtimeObservation, err)
	}
	var result v1.TaskResult
	if err := json.Unmarshal(events[3].Payload, &result); err != nil || !result.Succeeded {
		t.Fatalf("deploy did not succeed: %#v err=%v", result, err)
	}

	request.Operation.IdempotencyKey = "deploy-runtime-unknown"
	badParameters := append(parameters[:len(parameters)-1], []byte(`,"command":"id"}`)...)
	task.TaskID, task.IdempotencyKey, task.Parameters = "task-deploy-unknown", request.Operation.IdempotencyKey, badParameters
	if _, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task)); err == nil {
		t.Fatal("deploy accepted an unknown command field")
	}
}

func TestOutboundHandlerDeployGroupRequiresCapabilityImplementationAndCompleteObservation(t *testing.T) {
	deadline := time.Now().Add(time.Minute).UTC()
	image := domain.ImageDigest{Repository: "opencard/web", Digest: "sha256:" + strings.Repeat("a", 64)}
	spec := contracts.ServiceGroupRuntimeSpec{
		SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: domain.ID("app_group"), EnvironmentID: domain.ID("env_group"), ReleaseID: domain.ID("rel_group"), ServiceGroupID: domain.ID("group_group"), ConfigDigest: "sha256:" + strings.Repeat("b", 64), EntryService: "web",
		Services: []contracts.ServiceRuntimeSpec{{Name: "web", Role: domain.RoleIngress, Required: true, Image: image, Resources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, ContainerPorts: []int{8080}}}, Rollout: contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial},
	}
	request := contracts.DeployGroupRequest{DeploymentID: domain.ID("dep_group"), Spec: spec, Operation: contracts.OperationContext{IdempotencyKey: "deploy-group-1", Deadline: deadline}}
	parameters, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	task := v1.TaskRequest{TaskID: "task-deploy-group", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskDeployGroup, IdempotencyKey: request.Operation.IdempotencyKey, LeaseID: "lease-group", Parameters: parameters, Deadline: deadline}

	unsupported := NewOutboundHandler("instance-1", "node-1", staticDockerFacts{})
	events, err := unsupported.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil || len(events) != 2 {
		t.Fatalf("missing group runtime did not fail closed: events=%#v err=%v", events, err)
	}
	var ack v1.TaskAck
	_ = json.Unmarshal(events[0].Payload, &ack)
	if ack.Status != v1.AckRejected {
		t.Fatalf("missing group capability was not rejected: %#v", ack)
	}

	runtime := &fakeGroupRuntime{observation: contracts.ServiceGroupRuntimeObservation{
		DeploymentID: request.DeploymentID, ReleaseID: spec.ReleaseID, Status: "runtime_ready", Effect: contracts.RuntimeEffectKnown,
		Services: []contracts.RuntimeObservation{{DeploymentID: request.DeploymentID, ServiceName: "web", Status: "healthy", Healthy: true, HostPort: 39180, Limits: spec.Services[0].Resources, ObservedAt: time.Now().UTC()}},
		Evidence: contracts.Evidence{Summary: "group observed", Redacted: true},
	}}
	handler := NewOutboundHandlerWithRuntimes("instance-1", "node-1", staticDockerFacts{}, nil, runtime)
	handler.healthProbe = func(_ context.Context, port int, _ time.Time) error {
		if port != 39180 {
			t.Fatalf("health probe port=%d", port)
		}
		return nil
	}
	events, err = handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil || len(events) != 4 {
		t.Fatalf("group deploy failed: events=%#v err=%v", events, err)
	}
	var observation v1.Observation
	if err := json.Unmarshal(events[2].Payload, &observation); err != nil || !observation.Healthy || observation.Status != "runtime_ready" {
		t.Fatalf("group observation invalid: %#v err=%v", observation, err)
	}
	var result v1.TaskResult
	if err := json.Unmarshal(events[3].Payload, &result); err != nil || !result.Succeeded {
		t.Fatalf("group result invalid: %#v err=%v", result, err)
	}

	unknownRuntime := &fakeGroupRuntime{observation: runtime.observation}
	unknownRuntime.observation.Effect = contracts.RuntimeEffectUnknown
	unknownHandler := NewOutboundHandlerWithRuntimes("instance-1", "node-1", staticDockerFacts{}, nil, unknownRuntime)
	unknownTask := task
	unknownTask.TaskID, unknownTask.IdempotencyKey = "task-deploy-group-unknown", "deploy-group-unknown"
	unknownRequest := request
	unknownRequest.Operation.IdempotencyKey = unknownTask.IdempotencyKey
	unknownTask.Parameters, _ = json.Marshal(unknownRequest)
	events, err = unknownHandler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, unknownTask))
	if err != nil || len(events) != 2 || unknownRuntime.destroyed != 0 {
		t.Fatalf("unknown group effect triggered destructive cleanup: events=%#v destroyed=%d err=%v", events, unknownRuntime.destroyed, err)
	}
	if err := json.Unmarshal(events[1].Payload, &result); err != nil || result.ErrorCode != "runtime_effect_unknown" {
		t.Fatalf("unknown effect result invalid: %#v err=%v", result, err)
	}
}

func TestOutboundHandlerDestroysOnlyExplicitConfirmedVolume(t *testing.T) {
	volumes := contracts.NewFakeVolumeProvider(true)
	volume := contracts.VolumeSpec{Name: "opencard-task-volume-data", MountPath: "/", SizeBytes: 4096}
	if _, _, err := volumes.Create(context.Background(), contracts.VolumeRequest{Volume: volume, Operation: contracts.OperationContext{IdempotencyKey: "create-volume"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute).UTC()
	request := struct {
		Volume             contracts.VolumeSpec       `json:"volume"`
		ConfirmationPhrase string                     `json:"confirmation_phrase"`
		Operation          contracts.OperationContext `json:"operation"`
	}{Volume: volume, ConfirmationPhrase: "confirm-volume-destroy:opencard-task-volume-data", Operation: contracts.OperationContext{IdempotencyKey: "destroy-volume", Deadline: deadline}}
	parameters, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	task := v1.TaskRequest{TaskID: "task-destroy-volume", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskDestroyVolume, IdempotencyKey: request.Operation.IdempotencyKey, LeaseID: "lease-volume", Parameters: parameters, Deadline: deadline}
	handler := NewOutboundHandlerWithProviders("instance-1", "node-1", staticDockerFacts{}, nil, nil, volumes)
	events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil || len(events) != 3 {
		t.Fatalf("confirmed volume destroy failed: events=%#v err=%v", events, err)
	}
	var result v1.TaskResult
	if err := json.Unmarshal(events[2].Payload, &result); err != nil || !result.Succeeded {
		t.Fatalf("confirmed volume destroy result invalid: %#v err=%v", result, err)
	}

	request.Operation.IdempotencyKey = "destroy-volume-unconfirmed"
	request.ConfirmationPhrase = ""
	task.TaskID, task.IdempotencyKey = "task-destroy-volume-unconfirmed", request.Operation.IdempotencyKey
	task.Parameters, _ = json.Marshal(request)
	if _, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task)); err == nil {
		t.Fatal("volume destroy accepted a missing exact confirmation")
	}
}

func TestOutboundHandlerFailsClosedForOtherTasksAndParameters(t *testing.T) {
	handler := NewOutboundHandler("instance-1", "node-1", staticDockerFacts{})
	deploy := v1.TaskRequest{TaskID: "task-deploy", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskDeploy, IdempotencyKey: "deploy-1", LeaseID: "lease-1", Parameters: json.RawMessage(`{"scope":"node_docker_facts"}`), Deadline: time.Now().Add(time.Minute)}
	events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, deploy))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("unsupported task returned unexpected events: %#v", events)
	}
	var ack v1.TaskAck
	if err := json.Unmarshal(events[0].Payload, &ack); err != nil || ack.Status != v1.AckRejected {
		t.Fatalf("unsupported task was not rejected: %#v err=%v", ack, err)
	}

	observe := deploy
	observe.TaskID = "task-observe"
	observe.IdempotencyKey = "observe-extra"
	observe.Kind = v1.TaskObserve
	observe.Parameters = json.RawMessage(`{"scope":"node_docker_facts","command":"id"}`)
	if _, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, observe)); err == nil {
		t.Fatal("observe task accepted a non-allowlisted parameter")
	}
}

func controlTaskEnvelope(t *testing.T, task v1.TaskRequest) v1.Envelope {
	t.Helper()
	payload, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	return v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: "control-" + task.TaskID, InstanceID: task.InstanceID, NodeID: task.NodeID, Kind: v1.KindTaskRequest, SentAt: time.Now().UTC(), IdempotencyKey: task.IdempotencyKey, Payload: payload}
}
