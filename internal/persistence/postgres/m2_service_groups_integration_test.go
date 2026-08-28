//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// TestM2ServiceGroupRevisionPersistsIdentityAndRetainedClaims exercises the
// real PostgreSQL constraints and immutable triggers. The test is skipped
// without the task-scoped integration DSN; the devbox gate supplies it after
// applying the complete migration set.
func TestM2ServiceGroupRevisionPersistsIdentityAndRetainedClaims(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	store := NewStore(db)
	suffix := strings.ToLower(domain.MustNewID("m2pg").String())
	appID := domain.ID("app_" + suffix)
	sourceID := domain.ID("src_" + suffix)
	definitionID := domain.ID("def_" + suffix)
	groupID := domain.ID("group_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,$2)`, appID.String(), "m2-persistence-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable)
		VALUES($1,$2,'upload','upload','upload://m2',$3,$4,$5,'prepared',true)
	`, sourceID.String(), appID.String(), "upload-"+suffix, "sha256:"+strings.Repeat("a", 64), "/var/lib/open-card/workspaces/"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration)
		VALUES($1,$2,$3,1,'{}'::jsonb)
	`, definitionID.String(), appID.String(), sourceID.String()); err != nil {
		t.Fatal(err)
	}
	group := m2TestServiceGroup()
	group.ID, group.ApplicationID, group.Name = groupID, appID, "same-logical-name"
	group.Services[0].Source = domain.ServiceSource{Kind: domain.ServicePrebuilt, Prebuilt: &domain.PrebuiltSource{Reference: "registry.example.test/open-card/web:stable"}}
	created, err := store.CreateServiceGroupRevision(ctx, ServiceGroupCreateRequest{
		Group:          group,
		ImportReport:   domain.ComposeImportReport{MappedFields: []string{"services.web"}},
		IdempotencyKey: "m2-integration-" + suffix,
		Identity:       M2ServiceGroupIdentity{DefinitionID: definitionID, Version: 1, ConfigDigest: "sha256:" + strings.Repeat("b", 64)},
		VolumeClaims:   []M2ServiceGroupVolumeClaim{{ID: domain.ID("claim_" + suffix), Name: "data", SizeBytes: 4096, Retain: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != groupID {
		t.Fatalf("created group id changed: %s", created.ID)
	}
	identity, err := store.GetServiceGroupIdentity(ctx, groupID)
	if err != nil || identity.DefinitionID != definitionID || identity.Version != 1 || identity.CanonicalDigest == "" {
		t.Fatalf("persisted identity mismatch: %+v err=%v", identity, err)
	}
	claims, err := store.ListServiceGroupVolumeClaims(ctx, groupID)
	if err != nil || len(claims) != 1 || claims[0].Name != "data" || !claims[0].Retain {
		t.Fatalf("persisted claims mismatch: %+v err=%v", claims, err)
	}
	image := domain.ImageDigest{Repository: "registry.example.test/open-card/web", Digest: "sha256:" + strings.Repeat("d", 64), ResolvedTag: "stable"}
	release, err := domain.NewRelease(appID, groupID, 1, identity.ConfigDigest, map[string]domain.ImageDigest{"web": image}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	release.ID = domain.ID("release_" + suffix)
	runtimeSpec := contracts.ServiceGroupRuntimeSpec{
		SchemaVersion: contracts.ServiceGroupRuntimeSchema,
		ApplicationID: appID, EnvironmentID: domain.ID("env_runtime_placeholder"), ReleaseID: release.ID, ServiceGroupID: groupID,
		ConfigDigest: identity.ConfigDigest, EntryService: "web",
		Services:     []contracts.ServiceRuntimeSpec{{Name: "web", Role: domain.RoleIngress, Required: true, Image: image, Resources: contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64}, Volumes: []domain.VolumeMount{{Name: "data", MountPath: "/var/lib/opencard/data"}}, ContainerPorts: []int{8080}}},
		VolumeClaims: []contracts.RuntimeVolumeClaim{{ID: claims[0].ID, Name: claims[0].Name, SizeBytes: claims[0].SizeBytes, Retain: true}},
		Rollout:      contracts.RuntimeRolloutPolicy{Mode: contracts.RuntimeRolloutInitial},
	}
	canonical, err := contracts.CanonicalServiceGroupReleaseDigest(definitionID, identity.Version, runtimeSpec)
	if err != nil {
		t.Fatal(err)
	}
	createdRelease, err := store.CreateM2Release(ctx, M2ReleaseCreation{Release: *release, DefinitionID: definitionID, Bindings: []M2ReleaseServiceBinding{{ServiceName: "web", Kind: M2ReleaseBindingResolvedImage, Image: image, ResolvedFrom: image.Repository + ":stable"}}, CanonicalDigest: canonical, RuntimeSpec: runtimeSpec, Rollout: M2ReleaseRollout{Mode: "initial"}}, time.Now().UTC())
	if err != nil || createdRelease.ID != release.ID {
		t.Fatalf("complete M2 release persistence failed: release=%+v err=%v", createdRelease, err)
	}
	loadedRuntime, loadedCanonical, err := store.GetM2ReleaseRuntimeSpec(ctx, release.ID)
	if err != nil || loadedCanonical != canonical || loadedRuntime.ReleaseID != release.ID || len(loadedRuntime.Services) != 1 || loadedRuntime.Services[0].Image.Digest != image.Digest {
		t.Fatalf("M2 runtime identity readback mismatch: spec=%+v canonical=%s err=%v", loadedRuntime, loadedCanonical, err)
	}
	environmentID := runtimeSpec.EnvironmentID
	deploymentID := domain.ID("deployment_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO environments(id,application_id,name) VALUES($1,$2,'runtime')`, environmentID.String(), appID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'serving',true)`, deploymentID.String(), environmentID.String(), release.ID.String()); err != nil {
		t.Fatal(err)
	}
	routeID, leaseID := domain.ID("route_"+suffix), domain.ID("lease_"+suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port) VALUES($1,$2,$3,'web','127.0.0.1',39001)`, leaseID.String(), appID.String(), deploymentID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving) VALUES($1,$2,$3,'web','m4.integration.test','/','active',true,true)`, routeID.String(), appID.String(), deploymentID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision) VALUES($1,$2,$3,1)`, routeID.String(), deploymentID.String(), leaseID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE deployments SET state='unknown',runtime_healthy=false WHERE id=$1`, deploymentID.String()); err != nil {
		t.Fatal(err)
	}
	observeKey := "m4-group-observe-recovery-" + suffix
	groupObserveOperation := domain.Operation{ID: domain.ID("op_group_observe_" + suffix), ApplicationID: appID, EnvironmentID: environmentID, TargetRef: "deployment/" + deploymentID.String(), Type: domain.OperationObserve, IdempotencyKey: observeKey, Status: domain.OperationPending, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	observeRequest, _ := json.Marshal(contracts.ObserveGroupRequest{DeploymentID: deploymentID, Operation: contracts.OperationContext{IdempotencyKey: observeKey, Deadline: time.Now().UTC().Add(time.Minute), Actor: "integration"}})
	observeParameters, _ := json.Marshal(map[string]any{"m4_payload_type": "service_group.observe", "request": json.RawMessage(observeRequest)})
	observePayload, _ := json.Marshal(map[string]any{"kind": string(v1.TaskObserve), "parameters": json.RawMessage(observeParameters)})
	groupObserveTaskID := domain.ID("task_group_observe_" + suffix)
	if _, err := store.EnqueueControllerTask(ctx, EnqueueControllerTaskRequest{Operation: groupObserveOperation, ExistingDeploymentID: deploymentID, TaskID: groupObserveTaskID, Payload: observePayload, MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := store.ClaimControllerTask(ctx, ClaimTaskRequest{Owner: "agent-group-observe", Now: time.Now().UTC(), LeasePolicy: LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
	if err != nil || !found || claimed.Task.ID != groupObserveTaskID {
		t.Fatalf("claim group observation: task=%+v found=%v err=%v", claimed, found, err)
	}
	if _, err := store.StartControllerTask(ctx, groupObserveTaskID, "agent-group-observe", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	groupObservation := contracts.ServiceGroupRuntimeObservation{DeploymentID: deploymentID, ReleaseID: release.ID, Status: "runtime_ready", Effect: contracts.RuntimeEffectKnown, Services: []contracts.RuntimeObservation{{DeploymentID: deploymentID, ServiceName: "web", ContainerID: strings.Repeat("e", 64), Status: "running", Healthy: true, HostPort: 39001, Limits: runtimeSpec.Services[0].Resources, MemoryBytes: 1024, DiskBytes: 1, NetworkRxBytes: 1, NetworkTxBytes: 1, PIDsCurrent: 2, CgroupVerified: true, MetricsKnown: true}}, Evidence: contracts.Evidence{Redacted: true}}
	details, _ := json.Marshal(groupObservation)
	wire, _ := json.Marshal(v1.Observation{TaskID: groupObserveTaskID.String(), Sequence: 1, TargetRef: "deployment/" + deploymentID.String(), Status: "runtime_ready", Healthy: true, At: time.Now().UTC(), Details: details})
	if _, err := store.RecordAgentEvent(ctx, AgentEventRequest{TaskID: groupObserveTaskID, Owner: "agent-group-observe", Now: time.Now().UTC(), Sequence: 1, Kind: "observation", Payload: wire, WireVersion: v1.ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	var recoveredState string
	if err := db.QueryRowContext(ctx, `SELECT state FROM deployments WHERE id=$1`, deploymentID.String()).Scan(&recoveredState); err != nil || recoveredState != "serving" {
		t.Fatalf("aggregate observation did not recover unknown deployment: state=%s err=%v", recoveredState, err)
	}
	failedObservation := groupObservation
	failedObservation.Status = "failed"
	failedObservation.Services[0].Status = "exited"
	failedObservation.Services[0].Healthy = false
	failedObservation.Services[0].HostPort = 0
	failedObservation.Services[0].CgroupVerified = false
	failedDetails, _ := json.Marshal(failedObservation)
	failedWire, _ := json.Marshal(v1.Observation{TaskID: groupObserveTaskID.String(), Sequence: 2, TargetRef: "deployment/" + deploymentID.String(), Status: "failed", Healthy: false, At: time.Now().UTC(), Details: failedDetails})
	if _, err := store.RecordAgentEvent(ctx, AgentEventRequest{TaskID: groupObserveTaskID, Owner: "agent-group-observe", Now: time.Now().UTC(), Sequence: 2, Kind: "observation", Payload: failedWire, WireVersion: v1.ProtocolVersion}); err != nil {
		t.Fatalf("failed aggregate observation was rejected: %v", err)
	}
	refreshWire, _ := json.Marshal(v1.Observation{TaskID: groupObserveTaskID.String(), Sequence: 3, TargetRef: "deployment/" + deploymentID.String(), Status: "runtime_ready", Healthy: true, At: time.Now().UTC(), Details: details})
	if _, err := store.RecordAgentEvent(ctx, AgentEventRequest{TaskID: groupObserveTaskID, Owner: "agent-group-observe", Now: time.Now().UTC(), Sequence: 3, Kind: "observation", Payload: refreshWire, WireVersion: v1.ProtocolVersion}); err != nil {
		t.Fatalf("idempotent aggregate runtime refresh was rejected: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT state FROM deployments WHERE id=$1`, deploymentID.String()).Scan(&recoveredState); err != nil || recoveredState != "serving" {
		t.Fatalf("routed aggregate refresh lost serving state: state=%s err=%v", recoveredState, err)
	}
	if _, err := store.FinishControllerTask(ctx, FinishControllerTaskRequest{TaskID: groupObserveTaskID, Owner: "agent-group-observe", Now: time.Now().UTC(), Outcome: ControllerTaskSucceeded}); err != nil {
		t.Fatal(err)
	}
	logCandidates, err := store.ListM4LogCollectionCandidates(ctx, time.Now().UTC().Add(-time.Minute), 10)
	if err != nil || len(logCandidates) != 1 || logCandidates[0].Deployment.ID != deploymentID || logCandidates[0].ServiceName != "web" {
		t.Fatalf("M4 log collection candidates=%+v err=%v", logCandidates, err)
	}
	if err := store.AppendLogIndex(ctx, LogIndex{ID: domain.ID("log_" + suffix), ApplicationID: appID, ServiceName: "web", ReleaseID: release.ID, DeploymentID: deploymentID, Category: LogIndexRuntime, Path: "/var/lib/open-card/build-work/m4-logs/runtime/task-fixture/segment-000001.log", Segment: 1, ByteSize: 12}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if logCandidates, err := store.ListM4LogCollectionCandidates(ctx, time.Now().UTC().Add(-time.Minute), 10); err != nil || len(logCandidates) != 0 {
		t.Fatalf("recent runtime log did not suppress recollection: candidates=%+v err=%v", logCandidates, err)
	}
	observeOperation := domain.Operation{ID: domain.ID("op_observe_" + suffix), ApplicationID: appID, EnvironmentID: environmentID, TargetRef: "deployment/" + deploymentID.String() + "/service/web/logs", Type: domain.OperationObserve, IdempotencyKey: "observe-before-destroy-" + suffix, Status: domain.OperationPending, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	observeTaskID := domain.ID("task_observe_" + suffix)
	if _, err := store.EnqueueControllerTask(ctx, EnqueueControllerTaskRequest{Operation: observeOperation, ExistingDeploymentID: deploymentID, TaskID: observeTaskID, Payload: json.RawMessage(`{"kind":"logs"}`), MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	destroyOperation := domain.Operation{ID: domain.ID("op_destroy_" + suffix), ApplicationID: appID, EnvironmentID: environmentID, TargetRef: "destroy/" + deploymentID.String(), Type: domain.OperationDestroy, IdempotencyKey: "destroy-after-observe-" + suffix, Status: domain.OperationPending, CreatedAt: time.Now().UTC().Add(time.Second), UpdatedAt: time.Now().UTC().Add(time.Second)}
	if _, err := store.EnqueueControllerTask(ctx, EnqueueControllerTaskRequest{Operation: destroyOperation, ExistingDeploymentID: deploymentID, TaskID: domain.ID("task_destroy_" + suffix), Payload: json.RawMessage(`{"kind":"destroy_group"}`), MaxAttempts: 3}); err != nil {
		t.Fatalf("foreground destroy did not preempt background logs task: %v", err)
	}
	var observeState, observeTaskState, destroyState string
	if err := db.QueryRowContext(ctx, `SELECT o.state,t.state,next.state FROM operations o JOIN task_leases t ON t.operation_id=o.id JOIN operations next ON next.id=$2 WHERE o.id=$1`, observeOperation.ID.String(), destroyOperation.ID.String()).Scan(&observeState, &observeTaskState, &destroyState); err != nil {
		t.Fatal(err)
	}
	if observeState != "cancelled" || observeTaskState != "cancelled" || destroyState != "pending" {
		t.Fatalf("read-only preemption states=%s/%s foreground=%s", observeState, observeTaskState, destroyState)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m2_release_runtime_specs SET spec=jsonb_set(spec,'{entry_service}','\"changed\"'::jsonb) WHERE release_id=$1`, release.ID.String()); err == nil {
		t.Fatal("immutable M2 runtime specification update was accepted")
	}
	definitionID2 := domain.ID("def2_" + suffix)
	groupID2 := domain.ID("group2_" + suffix)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration)
		VALUES($1,$2,$3,2,'{}'::jsonb)
	`, definitionID2.String(), appID.String(), sourceID.String()); err != nil {
		t.Fatal(err)
	}
	group2 := group
	group2.ID = groupID2
	if _, err := store.CreateServiceGroupRevision(ctx, ServiceGroupCreateRequest{
		Group:          group2,
		ImportReport:   domain.ComposeImportReport{},
		IdempotencyKey: "m2-integration-v2-" + suffix,
		Identity:       M2ServiceGroupIdentity{DefinitionID: definitionID2, Version: 2, ConfigDigest: "sha256:" + strings.Repeat("c", 64)},
	}); err != nil {
		t.Fatalf("same logical name at a later definition version was rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE service_groups SET name='mutated' WHERE id=$1`, groupID.String()); err == nil {
		t.Fatal("immutable service group update was accepted")
	}
}
