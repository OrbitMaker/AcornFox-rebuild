//go:build integration

package persistence_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type controllerFixture struct {
	applicationID domain.ID
	environmentID domain.ID
	releaseID     domain.ID
}

func TestControllerWorkerTransactionOrderingRecoveryAndRollback(t *testing.T) {
	databaseURL := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	store, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	drainControllerTasks(t, ctx, store)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fixture := seedControllerFixture(t, ctx, store, suffix)
	base := time.Now().UTC()

	deployOperation := domain.Operation{
		ID: domain.ID("op_g9_deploy_" + suffix), ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, TargetRef: "deployment/dep_g9_deploy_" + suffix,
		Type: domain.OperationDeploy, IdempotencyKey: "g9-deploy-" + suffix,
		Status: domain.OperationPending, CreatedAt: base, UpdatedAt: base,
	}
	deployment := domain.Deployment{
		ID: domain.ID("dep_g9_deploy_" + suffix), ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, ReleaseID: fixture.releaseID,
		Status: domain.DeploymentPending, CreatedAt: base, UpdatedAt: base,
	}
	taskID := domain.ID("task_g9_deploy_" + suffix)
	if _, err := store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{
		Operation: deployOperation, Deployment: &deployment, TaskID: taskID,
		Payload: json.RawMessage(`{"kind":"deploy","target":"fixture"}`), MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}

	first, ok, err := store.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: "worker-one", Now: base, LeasePolicy: postgres.LeasePolicy{Duration: 100 * time.Millisecond, MaxAttempts: 3}})
	if err != nil || !ok {
		t.Fatalf("first claim ok=%v err=%v", ok, err)
	}
	if first.Task.ID != taskID || first.Operation.Status != domain.OperationLeased || first.Task.Attempt != 1 {
		t.Fatalf("unexpected first claim: %#v", first)
	}
	if _, err := store.StartControllerTask(ctx, taskID, "worker-one", base.Add(10*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	accepted, err := store.RecordAgentEvent(ctx, postgres.AgentEventRequest{
		TaskID: taskID, Owner: "worker-one", Now: base.Add(20 * time.Millisecond), Sequence: 1,
		Kind: "observation", Payload: json.RawMessage(`{"status":"healthy","token":"controller-secret-canary"}`),
	})
	if err != nil || accepted.Replayed {
		t.Fatalf("first agent event: %#v err=%v", accepted, err)
	}
	replayed, err := store.RecordAgentEvent(ctx, postgres.AgentEventRequest{
		TaskID: taskID, Owner: "worker-one", Now: base.Add(21 * time.Millisecond), Sequence: 1,
		Kind: "observation", Payload: json.RawMessage(`{"status":"healthy","token":"controller-secret-canary"}`),
	})
	if err != nil || !replayed.Replayed {
		t.Fatalf("exact agent replay was not idempotent: %#v err=%v", replayed, err)
	}
	if _, err := store.RecordAgentEvent(ctx, postgres.AgentEventRequest{TaskID: taskID, Owner: "worker-one", Now: base.Add(22 * time.Millisecond), Sequence: 3, Kind: "log", Payload: json.RawMessage(`{"data":"gap"}`)}); !errors.Is(err, postgres.ErrOutOfOrderAgentEvent) {
		t.Fatalf("sequence gap was accepted: %v", err)
	}
	if _, err := store.RecordAgentEvent(ctx, postgres.AgentEventRequest{TaskID: taskID, Owner: "worker-one", Now: base.Add(23 * time.Millisecond), Sequence: 1, Kind: "observation", Payload: json.RawMessage(`{"status":"different"}`)}); !errors.Is(err, postgres.ErrOutOfOrderAgentEvent) {
		t.Fatalf("conflicting replay was accepted: %v", err)
	}
	var storedAgentPayload string
	if err := store.DB().QueryRowContext(ctx, `SELECT payload::text FROM task_agent_events WHERE task_id=$1 AND sequence=1`, taskID.String()).Scan(&storedAgentPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedAgentPayload, "controller-secret-canary") || !strings.Contains(storedAgentPayload, "[REDACTED]") {
		t.Fatalf("agent event was not redacted before persistence: %s", storedAgentPayload)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate controller process loss after an Agent event but before the task
	// result transaction. A new Store must take over the expired lease and
	// resume at sequence 2 without regressing the running Operation.
	restarted, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	takenOver, ok, err := restarted.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: "worker-two", Now: base.Add(200 * time.Millisecond), LeasePolicy: postgres.LeasePolicy{Duration: time.Second, MaxAttempts: 3}})
	if err != nil || !ok {
		t.Fatalf("takeover ok=%v err=%v", ok, err)
	}
	if takenOver.Task.ID != taskID || takenOver.Task.Attempt != 2 || takenOver.Task.LastAgentSequence != 1 || takenOver.Operation.Status != domain.OperationRunning {
		t.Fatalf("takeover lost durable state: %#v", takenOver)
	}
	if _, err := restarted.StartControllerTask(ctx, taskID, "worker-two", base.Add(210*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.RecordAgentEvent(ctx, postgres.AgentEventRequest{TaskID: taskID, Owner: "worker-two", Now: base.Add(220 * time.Millisecond), Sequence: 2, Kind: "log", Payload: json.RawMessage(`{"stream":"stdout","data":"resumed"}`)}); err != nil {
		t.Fatal(err)
	}
	finishRequest := postgres.FinishControllerTaskRequest{TaskID: taskID, Owner: "worker-two", Now: base.Add(230 * time.Millisecond), Outcome: postgres.ControllerTaskSucceeded, EvidenceIDs: []string{"evidence/runtime-ready"}}
	finished, err := restarted.FinishControllerTask(ctx, finishRequest)
	if err != nil {
		t.Fatal(err)
	}
	if finished.Operation.Status != domain.OperationSucceeded || finished.Deployment == nil || finished.Deployment.Status != domain.DeploymentRuntimeReady {
		t.Fatalf("success transaction did not converge state: %#v", finished)
	}
	replayFinish, err := restarted.FinishControllerTask(ctx, finishRequest)
	if err != nil || !replayFinish.Replayed {
		t.Fatalf("identical result replay was not idempotent: %#v err=%v", replayFinish, err)
	}
	conflictingFinish := finishRequest
	conflictingFinish.Outcome = postgres.ControllerTaskFailed
	if _, err := restarted.FinishControllerTask(ctx, conflictingFinish); !errors.Is(err, postgres.ErrTaskResultConflict) {
		t.Fatalf("conflicting terminal result was accepted: %v", err)
	}

	failedDeploymentID := runControllerRetriesToTerminalFailure(t, ctx, restarted, fixture, suffix, base.Add(time.Second))
	rollbackOperation := domain.Operation{
		ID: domain.ID("op_g9_rollback_" + suffix), ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, TargetRef: failedDeploymentID.String(),
		Type: domain.OperationRollback, IdempotencyKey: "g9-rollback-" + suffix,
		Status: domain.OperationPending, CreatedAt: base.Add(2 * time.Second), UpdatedAt: base.Add(2 * time.Second),
	}
	rollbackTaskID := domain.ID("task_g9_rollback_" + suffix)
	if _, err := restarted.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: rollbackOperation, ExistingDeploymentID: failedDeploymentID, TaskID: rollbackTaskID, Payload: json.RawMessage(`{"kind":"rollback"}`), MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	rollbackClaim, ok, err := restarted.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: "rollback-worker", Now: base.Add(2 * time.Second), LeasePolicy: postgres.LeasePolicy{Duration: time.Second, MaxAttempts: 3}})
	if err != nil || !ok || rollbackClaim.Task.ID != rollbackTaskID {
		t.Fatalf("rollback claim: %#v ok=%v err=%v", rollbackClaim, ok, err)
	}
	if _, err := restarted.StartControllerTask(ctx, rollbackTaskID, "rollback-worker", base.Add(2010*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := restarted.FinishControllerTask(ctx, postgres.FinishControllerTaskRequest{TaskID: rollbackTaskID, Owner: "rollback-worker", Now: base.Add(2020 * time.Millisecond), Outcome: postgres.ControllerTaskRolledBack, EvidenceIDs: []string{"evidence/rollback"}})
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Operation.Status != domain.OperationRolledBack || rolledBack.Deployment == nil || rolledBack.Deployment.Status != domain.DeploymentRolledBack {
		t.Fatalf("rollback transaction did not converge: %#v", rolledBack)
	}
	verifyDurableAgentBridge(t, ctx, restarted, fixture, suffix, base.Add(3*time.Second))
}

type captureAgentQueue struct{ envelope v1.Envelope }

func (q *captureAgentQueue) Enqueue(_, _ string, envelope v1.Envelope) (uint64, error) {
	q.envelope = envelope
	return 1, nil
}

func verifyDurableAgentBridge(t *testing.T, ctx context.Context, store *postgres.Store, fixture controllerFixture, suffix string, now time.Time) {
	t.Helper()
	operation := domain.Operation{ID: domain.ID("op_g9_bridge_" + suffix), ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID, TargetRef: "node/node-bridge/docker", Type: domain.OperationRestart, IdempotencyKey: "g9-bridge-" + suffix, Status: domain.OperationPending, CreatedAt: now, UpdatedAt: now}
	taskID := domain.ID("task_g9_bridge_" + suffix)
	spec, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskObserve, Parameters: json.RawMessage(`{"scope":"node_docker_facts"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: operation, TaskID: taskID, Payload: spec, MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	queue := &captureAgentQueue{}
	dispatcher := &controllers.AgentDispatcher{Store: store, Queue: queue, InstanceID: "instance-bridge", NodeID: "node-bridge", LeaseDuration: time.Second, MaxAttempts: 3, Clock: func() time.Time { return now }}
	worked, err := dispatcher.DispatchOne(ctx)
	if err != nil || !worked {
		t.Fatalf("durable Agent dispatch worked=%v err=%v", worked, err)
	}
	if err := v1.ValidateEnvelopePayload(queue.envelope); err != nil {
		t.Fatal(err)
	}
	var task v1.TaskRequest
	if err := json.Unmarshal(queue.envelope.Payload, &task); err != nil {
		t.Fatal(err)
	}
	if task.TaskID != taskID.String() || task.NodeID != "node-bridge" || task.Kind != v1.TaskObserve {
		t.Fatalf("unexpected dispatched Agent task: %#v", task)
	}
	sink := &controllers.DurableAgentSink{Store: store, Clock: func() time.Time { return now.Add(10 * time.Millisecond) }}
	envelopes := []v1.Envelope{
		makeDurableAgentEnvelope(t, task, v1.KindTaskAck, 1, v1.TaskAck{TaskID: task.TaskID, Status: v1.AckAccepted}),
		makeDurableAgentEnvelope(t, task, v1.KindLogChunk, 2, v1.LogChunk{TaskID: task.TaskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "facts collected", Final: true}),
		makeDurableAgentEnvelope(t, task, v1.KindObservation, 3, v1.Observation{TaskID: task.TaskID, Sequence: 1, TargetRef: "node/node-bridge/docker", Status: "healthy", Healthy: true, At: now, EvidenceRefs: []string{"docker-api:/version", "docker-api:/info"}, Details: json.RawMessage(`{"server_version":"29.1.3"}`)}),
		makeDurableAgentEnvelope(t, task, v1.KindTaskResult, 4, v1.TaskResult{TaskID: task.TaskID, IdempotencyKey: task.IdempotencyKey, Succeeded: true, Status: v1.TaskResultSucceeded, EvidenceRefs: []string{"docker-api:/version", "docker-api:/info"}}),
	}
	for _, envelope := range envelopes {
		if err := sink.RecordAgentEnvelope(ctx, envelope); err != nil {
			t.Fatalf("persist Agent envelope %s: %v", envelope.Kind, err)
		}
	}
	if err := sink.RecordAgentEnvelope(ctx, envelopes[len(envelopes)-1]); err != nil {
		t.Fatalf("terminal Agent result replay was not idempotent: %v", err)
	}
	durable, err := store.GetControllerTask(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if durable.Task.State != postgres.TaskCompleted || durable.Task.LastAgentSequence != 4 || durable.Operation.Status != domain.OperationSucceeded {
		t.Fatalf("Agent bridge did not converge durable state: %#v", durable)
	}
	var taskWireVersion, minimumEventVersion, maximumEventVersion string
	if err := store.DB().QueryRowContext(ctx, `
		SELECT t.wire_version,MIN(e.wire_version),MAX(e.wire_version)
		  FROM task_leases t JOIN task_agent_events e ON e.task_id=t.task_id
		 WHERE t.task_id=$1 GROUP BY t.wire_version
	`, taskID.String()).Scan(&taskWireVersion, &minimumEventVersion, &maximumEventVersion); err != nil {
		t.Fatal(err)
	}
	if taskWireVersion != v1.ProtocolVersion || minimumEventVersion != v1.ProtocolVersion || maximumEventVersion != v1.ProtocolVersion {
		t.Fatalf("durable Agent wire versions task=%s min=%s max=%s", taskWireVersion, minimumEventVersion, maximumEventVersion)
	}
}

func makeDurableAgentEnvelope(t *testing.T, task v1.TaskRequest, kind v1.MessageKind, sequence uint64, value any) v1.Envelope {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: fmt.Sprintf("bridge-%d", sequence), InstanceID: task.InstanceID, NodeID: task.NodeID, Kind: kind, SentAt: time.Now().UTC(), IdempotencyKey: task.IdempotencyKey, AgentSequence: sequence, Payload: payload}
}

func drainControllerTasks(t *testing.T, ctx context.Context, store *postgres.Store) {
	t.Helper()
	now := time.Now().UTC().Add(24 * time.Hour)
	for index := 0; index < 100; index++ {
		owner := fmt.Sprintf("g9-drain-%d", index)
		claim, ok, err := store.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: owner, Now: now, LeasePolicy: postgres.LeasePolicy{Duration: time.Minute, MaxAttempts: 3}})
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return
		}
		if _, err := store.StartControllerTask(ctx, claim.Task.ID, owner, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		outcome := postgres.ControllerTaskSucceeded
		if claim.Operation.Type == domain.OperationRollback {
			outcome = postgres.ControllerTaskRolledBack
		}
		if _, err := store.FinishControllerTask(ctx, postgres.FinishControllerTaskRequest{TaskID: claim.Task.ID, Owner: owner, Now: now.Add(2 * time.Second), Outcome: outcome, EvidenceIDs: []string{"evidence/test-drain"}}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(3 * time.Second)
	}
	t.Fatal("controller task drain exceeded safety limit")
}

func seedControllerFixture(t *testing.T, ctx context.Context, store *postgres.Store, suffix string) controllerFixture {
	t.Helper()
	fixture := controllerFixture{applicationID: domain.ID("app_g9_" + suffix), environmentID: domain.ID("env_g9_" + suffix), releaseID: domain.ID("rel_g9_" + suffix)}
	sourceID := "src_g9_" + suffix
	definitionID := "def_g9_" + suffix
	digest := "sha256:" + strings.Repeat("a", 64)
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,'g9 fixture')`, []any{fixture.applicationID.String()}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'g9')`, []any{fixture.environmentID.String(), fixture.applicationID.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,content_digest) VALUES($1,$2,'upload',$3)`, []any{sourceID, fixture.applicationID.String(), digest}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definitionID, fixture.applicationID.String(), sourceID}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,jsonb_build_object('web',$4::text))`, []any{fixture.releaseID.String(), fixture.applicationID.String(), definitionID, digest}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func runControllerRetriesToTerminalFailure(t *testing.T, ctx context.Context, store *postgres.Store, fixture controllerFixture, suffix string, base time.Time) domain.ID {
	t.Helper()
	deploymentID := domain.ID("dep_g9_fail_" + suffix)
	operation := domain.Operation{ID: domain.ID("op_g9_fail_" + suffix), ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID, TargetRef: deploymentID.String(), Type: domain.OperationDeploy, IdempotencyKey: "g9-fail-" + suffix, Status: domain.OperationPending, CreatedAt: base, UpdatedAt: base}
	deployment := domain.Deployment{ID: deploymentID, ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID, ReleaseID: fixture.releaseID, Status: domain.DeploymentPending, CreatedAt: base, UpdatedAt: base}
	taskID := domain.ID("task_g9_fail_" + suffix)
	if _, err := store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{Operation: operation, Deployment: &deployment, TaskID: taskID, Payload: json.RawMessage(`{"kind":"deploy-fail"}`), MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		now := base.Add(time.Duration(attempt) * time.Second)
		owner := fmt.Sprintf("retry-worker-%d", attempt)
		claim, ok, err := store.ClaimControllerTask(ctx, postgres.ClaimTaskRequest{Owner: owner, Now: now, LeasePolicy: postgres.LeasePolicy{Duration: 500 * time.Millisecond, MaxAttempts: 3}})
		if err != nil || !ok || claim.Task.ID != taskID {
			t.Fatalf("retry claim %d: %#v ok=%v err=%v", attempt, claim, ok, err)
		}
		if _, err := store.StartControllerTask(ctx, taskID, owner, now.Add(10*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		result, err := store.FailControllerTask(ctx, postgres.FailControllerTaskRequest{TaskID: taskID, Owner: owner, Now: now.Add(20 * time.Millisecond), Retryable: true, FailureReason: "token=retry-secret", EvidenceIDs: []string{fmt.Sprintf("evidence/retry-%d", attempt)}})
		if err != nil {
			t.Fatal(err)
		}
		if attempt < 3 && result.Operation.Status != domain.OperationWaiting {
			t.Fatalf("attempt %d did not schedule retry: %#v", attempt, result)
		}
		if attempt == 3 && (result.Operation.Status != domain.OperationFailed || result.Deployment == nil || result.Deployment.Status != domain.DeploymentFailed) {
			t.Fatalf("attempt limit did not fail operation/deployment: %#v", result)
		}
	}
	var operationFailure, taskFailure string
	if err := store.DB().QueryRowContext(ctx, `
		SELECT o.failure_reason,t.last_error
		  FROM operations o JOIN task_leases t ON t.operation_id=o.id
		 WHERE o.id=$1
	`, operation.ID.String()).Scan(&operationFailure, &taskFailure); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{operationFailure, taskFailure} {
		if strings.Contains(value, "retry-secret") || !strings.Contains(value, "[REDACTED]") {
			t.Fatalf("controller failure reason was not redacted: %q", value)
		}
	}
	return deploymentID
}
