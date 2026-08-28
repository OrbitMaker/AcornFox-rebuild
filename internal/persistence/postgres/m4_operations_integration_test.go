//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

func TestM4WebhookLogAndOperationFactsPersist(t *testing.T) {
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
	suffix := strings.ToLower(domain.MustNewID("m4pg").String())
	appID, envID := domain.ID("app_"+suffix), domain.ID("env_"+suffix)
	sourceID, definitionID := domain.ID("src_"+suffix), domain.ID("def_"+suffix)
	previousRelease, currentRelease := domain.ID("release1_"+suffix), domain.ID("release2_"+suffix)
	previousDeployment, currentDeployment := domain.ID("dep1_"+suffix), domain.ID("dep2_"+suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{appID.String(), "m4-persistence-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m4')`, []any{envID.String(), appID.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://m4',$3,$4,$5,'prepared',true)`, []any{sourceID.String(), appID.String(), "upload-" + suffix, "sha256:" + strings.Repeat("a", 64), "/var/lib/open-card/workspaces/" + suffix}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definitionID.String(), appID.String(), sourceID.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES($1,$2,$3,1,jsonb_build_object('frontend',$4::text),$5)`, []any{previousRelease.String(), appID.String(), definitionID.String(), "sha256:" + strings.Repeat("b", 64), now.Add(-time.Minute)}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES($1,$2,$3,2,jsonb_build_object('frontend',$4::text),$5)`, []any{currentRelease.String(), appID.String(), definitionID.String(), "sha256:" + strings.Repeat("c", 64), now}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,last_observed_at) VALUES($1,$2,$3,'serving',true,$4)`, []any{previousDeployment.String(), envID.String(), previousRelease.String(), now.Add(-time.Minute)}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,last_observed_at) VALUES($1,$2,$3,'runtime_ready',true,$4)`, []any{currentDeployment.String(), envID.String(), currentRelease.String(), now}},
		{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'deploy',$5,'succeeded',$6,$7,$7)`, []any{"op_previous_" + suffix, appID.String(), envID.String(), previousDeployment.String(), "previous-deploy-" + suffix, "deployment/" + previousDeployment.String(), now.Add(-time.Minute)}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	containerID := strings.Repeat("d", 64)
	sampleID := "agent:task-obs:1:frontend"
	observationID := domain.ID("obs_" + suffix)
	insertObservation := `INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,observed_at,created_at,container_id,host_port,pids_current,applied_cpu_millicores,applied_memory_bytes,applied_pids,changed_path_count,cgroup_verified,metrics_known) VALUES($1,$2,$3,$4,$5,$6,'frontend','ingress','running',true,true,125,1024,9,10,11,2,$7,$7,$8,39001,3,250,67108864,32,4,true,true) ON CONFLICT(sample_id) DO NOTHING`
	for range 2 {
		if _, err := db.ExecContext(ctx, insertObservation, observationID.String(), sampleID, appID.String(), envID.String(), currentDeployment.String(), currentRelease.String(), now, containerID); err != nil {
			t.Fatal(err)
		}
	}
	var observationCount int
	var storedContainer string
	var cgroupVerified, metricsKnown bool
	if err := db.QueryRowContext(ctx, `SELECT count(*),max(container_id),bool_and(cgroup_verified),bool_and(metrics_known) FROM m4_service_observations WHERE sample_id=$1`, sampleID).Scan(&observationCount, &storedContainer, &cgroupVerified, &metricsKnown); err != nil || observationCount != 1 || storedContainer != containerID || !cgroupVerified || !metricsKnown {
		t.Fatalf("independent observation dedupe/restart projection mismatch: count=%d container=%q cgroup=%v metrics=%v err=%v", observationCount, storedContainer, cgroupVerified, metricsKnown, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m4_service_observations SET restart_count=3 WHERE id=$1`, observationID.String()); err == nil {
		t.Fatal("immutable independent observation accepted an in-place update")
	}
	// A read-only observation can exhaust its lease while the Agent or control
	// plane is deliberately restarted. That closes the observation operation,
	// but it must never erase the independently serving/runtime-ready
	// deployment fact used by the operator view.
	exhaustedOperation := domain.Operation{ID: domain.ID("op_exhausted_observe_" + suffix), ApplicationID: appID, EnvironmentID: envID, TargetRef: "deployment/" + currentDeployment.String(), Type: domain.OperationObserve, IdempotencyKey: "exhausted-observe-" + suffix, Status: domain.OperationPending, CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second)}
	exhaustedTask := domain.ID("task_exhausted_observe_" + suffix)
	if _, err := store.EnqueueControllerTask(ctx, EnqueueControllerTaskRequest{Operation: exhaustedOperation, ExistingDeploymentID: currentDeployment, TaskID: exhaustedTask, Payload: json.RawMessage(`{"kind":"observe_group"}`), MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	if claimed, found, err := store.ClaimControllerTask(ctx, ClaimTaskRequest{Owner: "agent-observe", Now: now.Add(2 * time.Second), LeasePolicy: LeasePolicy{Duration: time.Second, MaxAttempts: 1}}); err != nil || !found || claimed.Task.ID != exhaustedTask {
		t.Fatalf("claim exhausted observation: task=%+v found=%v err=%v", claimed, found, err)
	}
	if expired, err := store.ExpireExhaustedControllerTask(ctx, now.Add(4*time.Second), 1); err != nil || !expired {
		t.Fatalf("expire observation lease: expired=%v err=%v", expired, err)
	}
	var exhaustedState, deploymentState string
	if err := db.QueryRowContext(ctx, `SELECT o.state,d.state FROM operations o JOIN deployments d ON d.id=o.deployment_id WHERE o.id=$1`, exhaustedOperation.ID.String()).Scan(&exhaustedState, &deploymentState); err != nil {
		t.Fatal(err)
	}
	if exhaustedState != "failed" || deploymentState != string(domain.DeploymentRuntimeReady) {
		t.Fatalf("read-only exhaustion rewrote deployment: operation=%s deployment=%s", exhaustedState, deploymentState)
	}
	endpointID := domain.ID("hook_" + suffix)
	if err := store.UpsertWebhookEndpoint(ctx, WebhookEndpoint{ID: endpointID, ApplicationID: appID, URL: "https://receiver.fixture.test/events", SecretReferenceID: domain.ID("opaque-secret-" + suffix), SecretName: "webhook", SecretProvider: "fixture-secret", SecretVersion: "v1", EventTypes: []string{"notification.occurrence", "notification.escalation", "notification.recovery"}, Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	eventID := domain.ID("evt_" + suffix)
	payload := m4TestWebhookPayload(t, appID, envID, now)
	payloadDigest := m1Digest(payload)
	request := WebhookDeliveryRequest{DeliveryID: "delivery_" + suffix, EndpointID: endpointID, EventID: eventID, EventType: "notification.occurrence", PayloadDigest: payloadDigest, Payload: payload, IdempotencyKey: "notify-" + suffix, RequestDigest: m1Digest([]byte("notify-" + suffix)), OccurredAt: now}
	ledger, duplicate, err := store.ReserveWebhookDelivery(ctx, request, now)
	if err != nil || duplicate || ledger.ReceivedCount != 1 {
		t.Fatalf("initial webhook reservation: ledger=%+v duplicate=%v err=%v", ledger, duplicate, err)
	}
	repeated := request
	repeated.IdempotencyKey += ":repeated-event"
	repeated.RequestDigest = m1Digest([]byte(repeated.IdempotencyKey))
	ledger, duplicate, err = store.ReserveWebhookDelivery(ctx, repeated, now.Add(time.Second))
	if err != nil || !duplicate || ledger.ReceivedCount != 2 {
		t.Fatalf("webhook dedupe count: ledger=%+v duplicate=%v err=%v", ledger, duplicate, err)
	}
	conflictingPayload := m4TestWebhookPayload(t, appID, envID, now.Add(time.Second))
	if _, _, err := store.ReserveWebhookDelivery(ctx, WebhookDeliveryRequest{DeliveryID: "delivery_conflict_" + suffix, EndpointID: endpointID, EventID: eventID, EventType: "notification.occurrence", PayloadDigest: m1Digest(conflictingPayload), Payload: conflictingPayload, IdempotencyKey: "notify-conflict-" + suffix, RequestDigest: m1Digest([]byte("notify-conflict-" + suffix)), OccurredAt: now}, now); !errors.Is(err, ErrWebhookPayloadConflict) {
		t.Fatalf("changed duplicate payload was accepted: %v", err)
	}
	claimed, err := store.ClaimDueWebhookDeliveries(ctx, "worker-first", now, time.Minute, 5)
	if err != nil || len(claimed) != 1 || claimed[0].LeaseOwner != "worker-first" {
		t.Fatalf("initial durable claim mismatch: claimed=%+v err=%v", claimed, err)
	}
	ledger, err = store.AppendWebhookDeliveryAttempt(ctx, WebhookDeliveryAttempt{DeliveryID: claimed[0].DeliveryID, EventID: eventID, Attempt: 1, LeaseOwner: "worker-first", At: now.Add(time.Second), Status: WebhookDeliveryPending, NextAttemptAt: now.Add(time.Minute), Failure: "receiver timeout", FailureCode: "timeout"})
	if err != nil || ledger.Status != WebhookDeliveryRetryWait || ledger.AttemptCount != 1 || ledger.NextAttemptAt == nil || !ledger.NextAttemptAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("persisted retry mismatch: ledger=%+v err=%v", ledger, err)
	}
	claimed, err = store.ClaimDueWebhookDeliveries(ctx, "worker-crashed", now.Add(time.Minute), 10*time.Second, 5)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("due retry was not claimed: claimed=%+v err=%v", claimed, err)
	}
	if claimedAgain, err := store.ClaimDueWebhookDeliveries(ctx, "worker-other", now.Add(time.Minute+time.Second), 10*time.Second, 5); err != nil || len(claimedAgain) != 0 {
		t.Fatalf("leased delivery was double claimed: claimed=%+v err=%v", claimedAgain, err)
	}
	claimed, err = store.ClaimDueWebhookDeliveries(ctx, "worker-recovered", now.Add(time.Minute+11*time.Second), time.Minute, 5)
	if err != nil || len(claimed) != 1 || claimed[0].LeaseOwner != "worker-recovered" {
		t.Fatalf("expired lease was not recovered: claimed=%+v err=%v", claimed, err)
	}
	finalAttempt := WebhookDeliveryAttempt{DeliveryID: claimed[0].DeliveryID, EventID: eventID, Attempt: 2, LeaseOwner: "worker-recovered", At: now.Add(time.Minute + 12*time.Second), Succeeded: true, Status: WebhookDeliveryDelivered}
	ledger, err = store.AppendWebhookDeliveryAttempt(ctx, finalAttempt)
	if err != nil || ledger.Status != WebhookDeliveryDelivered || ledger.DeliveredAt == nil || ledger.LeaseOwner != "" {
		t.Fatalf("delivered retry mismatch: ledger=%+v err=%v", ledger, err)
	}
	replayed, err := store.AppendWebhookDeliveryAttempt(ctx, finalAttempt)
	if err != nil || replayed.Status != WebhookDeliveryDelivered || replayed.AttemptCount != 2 {
		t.Fatalf("committed webhook attempt did not replay: ledger=%+v err=%v", replayed, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m4_webhook_attempts SET error_code='mutated' WHERE endpoint_id=$1 AND event_id=$2 AND attempt_number=2`, endpointID.String(), eventID.String()); err == nil {
		t.Fatal("webhook attempt mutation was accepted")
	}
	operationID := domain.ID("op_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'restart',$5,'succeeded',$6,$7,$7)`, operationID.String(), appID.String(), envID.String(), currentDeployment.String(), "m4-restart-"+suffix, currentDeployment.String(), now); err != nil {
		t.Fatal(err)
	}
	operationEventPayload, err := json.Marshal(map[string]any{"id": "evt_operation_" + suffix, "operation_id": operationID.String(), "application_id": appID.String(), "kind": "operations.service_restart.failed", "status": "failed", "message": "service restart failed", "occurred_at": now.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	outboxID := "evt_m4_operation_" + suffix
	if _, err := db.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,1,1,999,$3,$4::jsonb,$5,'1.1')`, outboxID, operationID.String(), "operations.service_restart.failed", operationEventPayload, now); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := store.ListPendingWebhookLifecycleEvents(ctx, 10)
	if err != nil || len(lifecycle) != 1 || lifecycle[0].OutboxEventID != outboxID || lifecycle[0].Endpoint.ID != endpointID || lifecycle[0].EnvironmentID != envID || lifecycle[0].Status != "failed" {
		t.Fatalf("M4 webhook lifecycle projection mismatch: values=%+v err=%v", lifecycle, err)
	}
	if marked, err := store.MarkWebhookLifecycleDispatched(ctx, outboxID, endpointID, now); err != nil || !marked {
		t.Fatalf("M4 webhook lifecycle receipt was not recorded: marked=%v err=%v", marked, err)
	}
	if lifecycle, err := store.ListPendingWebhookLifecycleEvents(ctx, 10); err != nil || len(lifecycle) != 0 {
		t.Fatalf("M4 webhook lifecycle receipt did not suppress replay: values=%+v err=%v", lifecycle, err)
	}
	// A non-lifecycle operation event must not block the endpoint-local
	// dispatcher cursor. The dispatcher correctly rejects unknown kinds, so
	// selection must keep it out rather than repeatedly failing a worker.
	startedPayload, err := json.Marshal(map[string]any{"id": "evt_operation_started_" + suffix, "operation_id": operationID.String(), "application_id": appID.String(), "kind": "operations.service_restart.started", "status": "running", "message": "service restart started", "occurred_at": now.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,2,2,1000,$3,$4::jsonb,$5,'1.1')`, "evt_m4_operation_started_"+suffix, operationID.String(), "operations.service_restart.started", startedPayload, now); err != nil {
		t.Fatal(err)
	}
	if lifecycle, err := store.ListPendingWebhookLifecycleEvents(ctx, 10); err != nil || len(lifecycle) != 0 {
		t.Fatalf("non-lifecycle operation event entered M4 webhook cursor: values=%+v err=%v", lifecycle, err)
	}
	// Reconfiguration is an activation cursor, not a request to backfill old
	// unmatched events. Disable/re-enable and event-type expansion must consume
	// pre-activation lifecycle facts without reserving a delivery.
	pendingFailureID := "evt_m4_pending_reenable_" + suffix
	pendingFailurePayload, _ := json.Marshal(map[string]any{"id": pendingFailureID, "operation_id": operationID.String(), "application_id": appID.String(), "kind": "operations.service_restart.failed", "status": "failed", "message": "historic failure", "occurred_at": now.Add(time.Second).Format(time.RFC3339Nano)})
	if _, err := db.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,3,3,1001,'operations.service_restart.failed',$3::jsonb,$4,'1.1')`, pendingFailureID, operationID.String(), pendingFailurePayload, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	configured := WebhookEndpoint{ID: endpointID, ApplicationID: appID, URL: "https://receiver.fixture.test/events", SecretReferenceID: domain.ID("opaque-secret-" + suffix), SecretName: "webhook", SecretProvider: "fixture-secret", SecretVersion: "v1", EventTypes: []string{"notification.occurrence", "notification.escalation", "notification.recovery"}, Enabled: false}
	if err := store.UpsertWebhookEndpoint(ctx, configured, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	configured.Enabled = true
	if err := store.UpsertWebhookEndpoint(ctx, configured, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if lifecycle, err := store.ListPendingWebhookLifecycleEvents(ctx, 10); err != nil || len(lifecycle) != 0 {
		t.Fatalf("disable/re-enable backfilled historic lifecycle: values=%+v err=%v", lifecycle, err)
	}
	configured.EventTypes = []string{"notification.occurrence"}
	if err := store.UpsertWebhookEndpoint(ctx, configured, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	pendingEscalationID := "evt_m4_pending_expansion_" + suffix
	pendingEscalationPayload, _ := json.Marshal(map[string]any{"id": pendingEscalationID, "operation_id": operationID.String(), "application_id": appID.String(), "kind": "operations.service_restart.retry", "status": "retry", "message": "historic escalation", "occurred_at": now.Add(5 * time.Second).Format(time.RFC3339Nano)})
	if _, err := db.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,4,4,1002,'operations.service_restart.retry',$3::jsonb,$4,'1.1')`, pendingEscalationID, operationID.String(), pendingEscalationPayload, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	configured.EventTypes = []string{"notification.occurrence", "notification.escalation", "notification.recovery"}
	if err := store.UpsertWebhookEndpoint(ctx, configured, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if lifecycle, err := store.ListPendingWebhookLifecycleEvents(ctx, 10); err != nil || len(lifecycle) != 0 {
		t.Fatalf("event-type expansion backfilled historic lifecycle: values=%+v err=%v", lifecycle, err)
	}
	if err := store.AppendLogIndex(ctx, LogIndex{ID: domain.ID("log_runtime_" + suffix), ApplicationID: appID, ServiceName: "frontend", ReleaseID: currentRelease, DeploymentID: currentDeployment, OperationID: operationID, Category: LogIndexRuntime, Path: "/var/lib/open-card/logs/runtime/segment.log", Segment: 1, ByteSize: 12}, now); err != nil {
		t.Fatal(err)
	}
	auditID := domain.ID("log_audit_" + suffix)
	if err := store.AppendLogIndex(ctx, LogIndex{ID: auditID, ApplicationID: appID, ServiceName: "audit", OperationID: operationID, Category: LogIndexAudit, Path: "/var/lib/open-card/logs/audit/segment.log", Segment: 1, ByteSize: 12}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireOrdinaryLogIndex(ctx, auditID, now.Add(time.Second)); !errors.Is(err, ErrAuditLogImmutable) {
		t.Fatalf("audit log index retirement was accepted: %v", err)
	}
	indexes, err := store.ListLogIndexes(ctx, appID, false, 20)
	if err != nil || len(indexes) != 2 {
		t.Fatalf("log index query mismatch: indexes=%+v err=%v", indexes, err)
	}
	fact, err := store.GetOperationFact(ctx, operationID)
	if err != nil || fact.DeploymentID != currentDeployment || fact.ReleaseID != currentRelease || !fact.RuntimeHealthy {
		t.Fatalf("operation fact mismatch: fact=%+v err=%v", fact, err)
	}
	previous, err := store.PreviousSuccessfulReleaseID(ctx, appID, currentRelease)
	if err != nil || previous != previousRelease {
		t.Fatalf("previous successful release mismatch: release=%s err=%v", previous, err)
	}
}

func m4TestWebhookPayload(t *testing.T, applicationID, environmentID domain.ID, now time.Time) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"schema_version": "m4.notification.v1", "application_id": applicationID.String(), "environment_id": environmentID.String(), "incident_id": "incident-1", "kind": "occurrence", "severity": "warning", "message": "runtime unavailable", "occurred_at": now.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
