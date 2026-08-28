package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type m4RuntimeFake struct {
	mu       sync.Mutex
	caps     contracts.CapabilitySet
	restarts []contracts.RestartRequest
	deploys  []contracts.DeployRequest
	rolls    []contracts.RollbackRequest
	observes []contracts.ObserveRequest
	logs     []contracts.LogsRequest
	lines    []string
	fail     error
}

func newM4RuntimeFake() *m4RuntimeFake {
	return &m4RuntimeFake{caps: contracts.NewCapabilitySet(contracts.CapabilityRuntimeRestart, contracts.CapabilityRuntimeDeploy, contracts.CapabilityRuntimeRollback, contracts.CapabilityRuntimeObserve, contracts.CapabilityRuntimeLogs)}
}

func (f *m4RuntimeFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m4-runtime", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: f.caps}
}
func (f *m4RuntimeFake) Deploy(_ context.Context, request contracts.DeployRequest) (domain.Deployment, error) {
	f.mu.Lock()
	f.deploys = append(f.deploys, request)
	failure := f.fail
	f.mu.Unlock()
	if failure != nil {
		return domain.Deployment{}, failure
	}
	return domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentServing}, nil
}
func (f *m4RuntimeFake) Observe(_ context.Context, request contracts.ObserveRequest) (contracts.RuntimeObservation, error) {
	f.mu.Lock()
	f.observes = append(f.observes, request)
	failure := f.fail
	f.mu.Unlock()
	if failure != nil {
		return contracts.RuntimeObservation{}, failure
	}
	return contracts.RuntimeObservation{DeploymentID: request.DeploymentID, ServiceName: "frontend", Status: "runtime_ready", Healthy: true, HostPort: 39001, Evidence: contracts.Evidence{Refs: []domain.EvidenceRef{{ID: "evidence_m4", Kind: "runtime.observe"}}, Redacted: true}, ObservedAt: time.Unix(1, 0).UTC()}, nil
}
func (f *m4RuntimeFake) Logs(_ context.Context, request contracts.LogsRequest) (<-chan string, error) {
	f.mu.Lock()
	f.logs = append(f.logs, request)
	lines, failure := append([]string(nil), f.lines...), f.fail
	f.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	channel := make(chan string, len(lines))
	for _, line := range lines {
		channel <- line
	}
	close(channel)
	return channel, nil
}
func (f *m4RuntimeFake) Restart(_ context.Context, request contracts.RestartRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restarts = append(f.restarts, request)
	return f.fail
}
func (f *m4RuntimeFake) Scale(context.Context, contracts.ScaleRequest) error {
	return errors.New("not used")
}
func (f *m4RuntimeFake) Rollback(_ context.Context, request contracts.RollbackRequest) (domain.Deployment, error) {
	f.mu.Lock()
	f.rolls = append(f.rolls, request)
	failure := f.fail
	f.mu.Unlock()
	if failure != nil {
		return domain.Deployment{}, failure
	}
	return domain.Deployment{ID: request.DeploymentID, ApplicationID: "app_m4", EnvironmentID: "env_m4", ReleaseID: request.ReleaseID, Status: domain.DeploymentServing}, nil
}
func (f *m4RuntimeFake) Destroy(context.Context, contracts.DestroyRequest) error {
	return errors.New("not used")
}

func m4Task(t *testing.T, kind v1.TaskKind, key string, parameters any) v1.TaskRequest {
	t.Helper()
	encoded, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	return v1.TaskRequest{TaskID: "task-" + key, InstanceID: "instance_m4", NodeID: "node_m4", Kind: kind, IdempotencyKey: key, LeaseID: "lease-" + key, Parameters: encoded, Deadline: time.Now().Add(time.Minute)}
}

func m4Operation(key string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key}
}

func TestM4OutboundTypedRestartAndObservation(t *testing.T) {
	runtime := newM4RuntimeFake()
	executor := NewM4OutboundExecutor("instance_m4", "node_m4", runtime)
	task := m4Task(t, v1.TaskRestart, "restart", contracts.RestartRequest{DeploymentID: "dep_m4", ServiceName: "worker", Operation: m4Operation("restart")})
	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Result.Succeeded || len(runtime.restarts) != 1 || runtime.restarts[0].ServiceName != "worker" || len(runtime.observes) != 1 || len(result.Observations) != 1 || result.Observations[0].TargetRef != "deployment/dep_m4" || len(result.Logs) != 1 {
		t.Fatalf("restart was not constrained and observed: result=%#v runtime=%#v", result, runtime)
	}
	if runtime.observes[0].Operation.IdempotencyKey != "restart:observe" || runtime.restarts[0].Operation.Deadline.IsZero() {
		t.Fatalf("operation deadline/idempotency drifted: %#v %#v", runtime.restarts[0], runtime.observes[0])
	}
}

func TestM4OutboundRedeployRollbackAndReplayAreTyped(t *testing.T) {
	runtime := newM4RuntimeFake()
	executor := NewM4OutboundExecutor("instance_m4", "node_m4", runtime)
	image := domain.ImageDigest{Repository: "registry.example/app", Digest: "sha256:" + strings.Repeat("a", 64)}
	deploy := m4Task(t, v1.TaskDeploy, "redeploy", contracts.DeployRequest{DeploymentID: "dep_m4", Spec: contracts.RuntimeSpec{ApplicationID: "app_m4", EnvironmentID: "env_m4", ReleaseID: "rel_current", ServiceName: "frontend", Image: image}, Operation: m4Operation("redeploy")})
	first, err := executor.Execute(context.Background(), deploy)
	if err != nil || !first.Result.Succeeded {
		t.Fatalf("typed redeploy failed: %#v %v", first, err)
	}
	second, err := executor.Execute(context.Background(), deploy)
	if err != nil || !second.Result.Succeeded || len(runtime.deploys) != 1 {
		t.Fatalf("disconnect/replay repeated redeploy side effect: %#v %v calls=%d", second, err, len(runtime.deploys))
	}
	rollback := m4Task(t, v1.TaskRollback, "rollback", contracts.RollbackRequest{DeploymentID: "dep_m4", ReleaseID: "rel_previous", Operation: m4Operation("rollback")})
	if result, err := executor.Execute(context.Background(), rollback); err != nil || !result.Result.Succeeded || len(runtime.rolls) != 1 || runtime.rolls[0].ReleaseID != "rel_previous" {
		t.Fatalf("typed rollback did not call RuntimeDriver exactly: %#v %v %#v", result, err, runtime.rolls)
	}
}

func TestM4OutboundRejectsShellUnknownFieldsAndWrongIdentity(t *testing.T) {
	runtime := newM4RuntimeFake()
	executor := NewM4OutboundExecutor("instance_m4", "node_m4", runtime)
	destroy := m4Task(t, v1.TaskDestroy, "destroy", map[string]any{"command": "rm -rf /"})
	if result, err := executor.Execute(context.Background(), destroy); err != nil || result.Result.ErrorCode != "unsupported_capability" || len(runtime.restarts) != 0 {
		t.Fatalf("non-M4 destructive task was accepted: %#v %v", result, err)
	}
	unknown := m4Task(t, v1.TaskRestart, "unknown", map[string]any{"deployment_id": "dep_m4", "service_name": "worker", "operation": map[string]any{"idempotency_key": "unknown"}, "command": "id"})
	if result, err := executor.Execute(context.Background(), unknown); err != nil || result.Result.ErrorCode != "invalid_argument" || len(runtime.restarts) != 0 {
		t.Fatalf("unknown/shell parameter reached runtime: %#v %v", result, err)
	}
	wrong := m4Task(t, v1.TaskObserve, "identity", contracts.ObserveRequest{DeploymentID: "dep_m4", Operation: m4Operation("identity")})
	wrong.NodeID = "other-node"
	if _, err := executor.Execute(context.Background(), wrong); err == nil {
		t.Fatal("wrong Agent identity was accepted")
	}
}

func TestM4OutboundLogsAreBoundedAndRedacted(t *testing.T) {
	runtime := newM4RuntimeFake()
	runtime.lines = []string{"service started", "token=super-secret runtime detail"}
	executor := NewM4OutboundExecutor("instance_m4", "node_m4", runtime)
	task := m4Task(t, v1.TaskLogs, "logs", contracts.LogsRequest{DeploymentID: "dep_m4", ServiceName: "worker", Tail: 2, Operation: m4Operation("logs")})
	result, err := executor.Execute(context.Background(), task)
	if err != nil || !result.Result.Succeeded || len(runtime.logs) != 1 || len(result.Logs) != 1 || !result.Logs[0].Final || strings.Contains(result.Logs[0].Data, "super-secret") || !strings.Contains(result.Logs[0].Data, foundation.RedactedValue) || !strings.Contains(result.Logs[0].Data, "service started") {
		t.Fatalf("logs escaped bounds/redaction: %#v %v", result, err)
	}
}

func TestM4OutboundRuntimeFailureIsRedactedAndReplaySafe(t *testing.T) {
	runtime := newM4RuntimeFake()
	runtime.fail = errors.New("password=do-not-leak restart failure")
	executor := NewM4OutboundExecutor("instance_m4", "node_m4", runtime)
	task := m4Task(t, v1.TaskRestart, "failure", contracts.RestartRequest{DeploymentID: "dep_m4", ServiceName: "worker", Operation: m4Operation("failure")})
	first, err := executor.Execute(context.Background(), task)
	if err != nil || first.Result.Succeeded || strings.Contains(first.Result.ErrorMessage, "do-not-leak") || !strings.Contains(first.Result.ErrorMessage, foundation.RedactedValue) {
		t.Fatalf("failure was not redacted: %#v %v", first, err)
	}
	second, err := executor.Execute(context.Background(), task)
	if err != nil || second.Result.ErrorMessage != first.Result.ErrorMessage || len(runtime.restarts) != 1 {
		t.Fatalf("failed task replay repeated side effect: %#v %v restarts=%d", second, err, len(runtime.restarts))
	}
}

type m4GroupRuntimeFake struct {
	mu       sync.Mutex
	caps     contracts.CapabilitySet
	deploys  []contracts.DeployGroupRequest
	observes []contracts.ObserveGroupRequest
	rolls    []contracts.RollbackGroupRequest
	restarts []M4GroupServiceRestartRequest
	logs     []contracts.LogsRequest
	lines    []string
}

func newM4GroupRuntimeFake() *m4GroupRuntimeFake {
	return &m4GroupRuntimeFake{caps: contracts.NewCapabilitySet(contracts.CapabilityRuntimeDeployGroup, contracts.CapabilityRuntimeObserveGroup, contracts.CapabilityRuntimeLogsGroup, contracts.CapabilityRuntimeRollbackGroup)}
}

func (f *m4GroupRuntimeFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "m4-group-runtime", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: f.caps}
}
func (f *m4GroupRuntimeFake) DeployGroup(_ context.Context, request contracts.DeployGroupRequest) (domain.Deployment, error) {
	f.mu.Lock()
	f.deploys = append(f.deploys, request)
	f.mu.Unlock()
	return domain.Deployment{ID: request.DeploymentID, ApplicationID: request.Spec.ApplicationID, EnvironmentID: request.Spec.EnvironmentID, ReleaseID: request.Spec.ReleaseID, Status: domain.DeploymentServing}, nil
}
func (f *m4GroupRuntimeFake) ObserveGroup(_ context.Context, request contracts.ObserveGroupRequest) (contracts.ServiceGroupRuntimeObservation, error) {
	f.mu.Lock()
	f.observes = append(f.observes, request)
	f.mu.Unlock()
	return contracts.ServiceGroupRuntimeObservation{DeploymentID: request.DeploymentID, ReleaseID: "rel_group", Status: "runtime_ready", Effect: contracts.RuntimeEffectKnown, Services: []contracts.RuntimeObservation{{DeploymentID: request.DeploymentID, ServiceName: "frontend", ContainerID: strings.Repeat("a", 64), Status: "running", Healthy: true, MetricsKnown: true, CgroupVerified: true, Limits: m4GroupSpec().Services[0].Resources, MemoryBytes: 64 << 20, DiskBytes: 1, NetworkRxBytes: 1, NetworkTxBytes: 1}}, Evidence: contracts.Evidence{Refs: []domain.EvidenceRef{{ID: "evidence_group", Kind: "runtime.group.observe"}}, Redacted: true}}, nil
}
func (f *m4GroupRuntimeFake) RollbackGroup(_ context.Context, request contracts.RollbackGroupRequest) (domain.Deployment, error) {
	f.mu.Lock()
	f.rolls = append(f.rolls, request)
	f.mu.Unlock()
	return domain.Deployment{ID: request.TargetDeploymentID, ApplicationID: request.Target.ApplicationID, EnvironmentID: request.Target.EnvironmentID, ReleaseID: request.Target.ReleaseID, Status: domain.DeploymentServing}, nil
}
func (f *m4GroupRuntimeFake) DestroyGroup(context.Context, contracts.DestroyRequest) error {
	return errors.New("not used")
}
func (f *m4GroupRuntimeFake) RestartGroupService(_ context.Context, request M4GroupServiceRestartRequest) error {
	f.mu.Lock()
	f.restarts = append(f.restarts, request)
	f.mu.Unlock()
	return nil
}
func (f *m4GroupRuntimeFake) Logs(_ context.Context, request contracts.LogsRequest) (<-chan string, error) {
	f.mu.Lock()
	f.logs = append(f.logs, request)
	lines := append([]string(nil), f.lines...)
	f.mu.Unlock()
	result := make(chan string, len(lines))
	for _, line := range lines {
		result <- line
	}
	close(result)
	return result, nil
}

func m4GroupSpec() contracts.ServiceGroupRuntimeSpec {
	image := domain.ImageDigest{Repository: "registry.example/group", Digest: "sha256:" + strings.Repeat("b", 64)}
	return contracts.ServiceGroupRuntimeSpec{SchemaVersion: contracts.ServiceGroupRuntimeSchema, ApplicationID: "app_group", EnvironmentID: "env_group", ReleaseID: "rel_group", ServiceGroupID: "group_m4", ConfigDigest: "sha256:" + strings.Repeat("c", 64), EntryService: "frontend", Services: []contracts.ServiceRuntimeSpec{{Name: "frontend", Role: domain.RoleIngress, Required: true, Image: image, Resources: contracts.ResourceLimits{CPUMillis: 100, MemoryBytes: 64 << 20, DiskBytes: 64 << 20, PIDs: 16}, ContainerPorts: []int{8080}}}, Rollout: contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial}}
}

func m4GroupTask(t *testing.T, kind v1.TaskKind, key, marker string, request any) v1.TaskRequest {
	t.Helper()
	inner, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return m4Task(t, kind, key, M4GroupTaskPayload{M4PayloadType: marker, Request: inner})
}

func TestM4OutboundServiceGroupTypedObserveRedeployRollbackAndRestart(t *testing.T) {
	group := newM4GroupRuntimeFake()
	group.lines = []string{"worker token=group-secret"}
	executor := NewM4OutboundExecutorWithGroupRuntime("instance_m4", "node_m4", nil, group)
	observe := m4GroupTask(t, v1.TaskObserve, "group-observe", "service_group.observe", contracts.ObserveGroupRequest{DeploymentID: "dep_group", Operation: m4Operation("group-observe")})
	if result, err := executor.Execute(context.Background(), observe); err != nil || !result.Result.Succeeded || len(group.observes) != 1 || len(result.Observations) != 1 {
		t.Fatalf("group observe was not typed: %#v %v %#v", result, err, group)
	}
	spec := m4GroupSpec()
	redeploy := m4GroupTask(t, v1.TaskDeploy, "group-redeploy", "service_group.redeploy", contracts.DeployGroupRequest{DeploymentID: "dep_group", Spec: spec, Operation: m4Operation("group-redeploy"), ForceRecreate: true})
	if result, err := executor.Execute(context.Background(), redeploy); err != nil || !result.Result.Succeeded || len(group.deploys) != 1 || group.deploys[0].Spec.ReleaseID != "rel_group" {
		t.Fatalf("group redeploy was not typed: %#v %v %#v", result, err, group.deploys)
	}
	rollbackSpec := spec
	rollbackSpec.ReleaseID = "rel_previous"
	rollbackSpec.ConfigDigest = "sha256:" + strings.Repeat("d", 64)
	rollback := m4GroupTask(t, v1.TaskRollback, "group-rollback", "service_group.rollback", contracts.RollbackGroupRequest{DeploymentID: "dep_group", TargetDeploymentID: "dep_group_rollback", Target: rollbackSpec, Operation: m4Operation("group-rollback")})
	if result, err := executor.Execute(context.Background(), rollback); err != nil || !result.Result.Succeeded || len(group.rolls) != 1 || group.rolls[0].Target.ReleaseID != "rel_previous" {
		t.Fatalf("group rollback was not typed: %#v %v %#v", result, err, group.rolls)
	}
	restart := m4GroupTask(t, v1.TaskRestart, "group-restart", "service_group.restart_service", M4GroupServiceRestartRequest{DeploymentID: "dep_group", ServiceGroupID: "group_m4", ReleaseID: "rel_group", ServiceName: "worker", Operation: m4Operation("group-restart")})
	if result, err := executor.Execute(context.Background(), restart); err != nil || !result.Result.Succeeded || len(group.restarts) != 1 || group.restarts[0].ServiceName != "worker" {
		t.Fatalf("optional typed group service restart was not called: %#v %v %#v", result, err, group.restarts)
	}
	logs := m4GroupTask(t, v1.TaskLogs, "group-logs", "service_group.logs", contracts.LogsRequest{DeploymentID: "dep_group", ServiceName: "worker", Tail: 64, Operation: m4Operation("group-logs")})
	if result, err := executor.Execute(context.Background(), logs); err != nil || !result.Result.Succeeded || len(group.logs) != 1 || len(result.Logs) != 1 || strings.Contains(result.Logs[0].Data, "group-secret") || !strings.Contains(result.Logs[0].Data, foundation.RedactedValue) {
		t.Fatalf("group logs were not typed and redacted: %#v %v %#v", result, err, group.logs)
	}
}

func TestM4OutboundServiceGroupMarkerCannotFallBackToSingleRuntimeOrShell(t *testing.T) {
	single := newM4RuntimeFake()
	executor := NewM4OutboundExecutor("instance_m4", "node_m4", single)
	payload := m4GroupTask(t, v1.TaskRestart, "group-no-provider", "service_group.restart_service", M4GroupServiceRestartRequest{DeploymentID: "dep_group", ServiceGroupID: "group_m4", ReleaseID: "rel_group", ServiceName: "worker", Operation: m4Operation("group-no-provider")})
	if result, err := executor.Execute(context.Background(), payload); err != nil || result.Result.ErrorCode != "unsupported_capability" || len(single.restarts) != 0 {
		t.Fatalf("group marker fell back to single runtime: %#v %v", result, err)
	}
	bad := m4Task(t, v1.TaskObserve, "group-shell", map[string]any{"m4_payload_type": "service_group.observe", "request": map[string]any{"deployment_id": "dep_group", "operation": map[string]any{"idempotency_key": "group-shell"}, "command": "docker ps"}})
	if result, err := executor.Execute(context.Background(), bad); err != nil || result.Result.ErrorCode != "invalid_argument" || len(single.observes) != 0 {
		t.Fatalf("group payload shell field reached runtime: %#v %v", result, err)
	}
}
