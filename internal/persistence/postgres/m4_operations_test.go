package postgres

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestM4MigrationHasOpaqueWebhookLedgerAndProtectedAuditIndexes(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0014_m4_operations_notifications.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS m4_webhook_endpoints",
		"CREATE TABLE IF NOT EXISTS m4_webhook_events",
		"CREATE TABLE IF NOT EXISTS m4_webhook_attempts",
		"CREATE TABLE IF NOT EXISTS m4_log_indexes",
		"secret_reference_id text NOT NULL",
		"payload jsonb NOT NULL",
		"m4_webhook_events_payload_shape",
		"next_attempt_at timestamptz DEFAULT now()",
		"lease_owner text",
		"UNIQUE(endpoint_id, event_id, attempt_number)",
		"m4_webhook_attempts_are_immutable",
		"m4_log_indexes_audit_not_retired",
		"m4_protect_log_index",
		"operations_m4_application_state_updated_idx",
		"CREATE TABLE IF NOT EXISTS m4_operation_requests",
		"expected_fact_version text NOT NULL",
		"CREATE TABLE IF NOT EXISTS m4_service_observations",
		"m4_service_observations_are_immutable",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("M4 migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"secret_value", "webhook_payload", "response_body", "private_key"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("M4 migration must not persist %q", forbidden)
		}
	}
}

func TestM4IndependentRuntimeFactsMigrationIsAdditiveAndBounded(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0017_m4_independent_runtime_facts.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, fragment := range []string{"ADD COLUMN IF NOT EXISTS container_id", "pids_current", "applied_cpu_millicores", "applied_memory_bytes", "applied_pids", "changed_path_count", "cgroup_verified", "metrics_known", "m4_service_observations_runtime_fact_shape"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("0017 missing independent runtime fact contract %q", fragment)
		}
	}
	for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "docker_socket", "environment_json", "mounts_json"} {
		if strings.Contains(strings.ToUpper(text), strings.ToUpper(forbidden)) {
			t.Fatalf("0017 contains unsafe or destructive field %q", forbidden)
		}
	}
}

func TestM4WebhookEndpointRejectsPrivateOrCredentialURL(t *testing.T) {
	valid := WebhookEndpoint{ID: "hook_1", ApplicationID: "app_1", URL: "https://receiver.fixture.test/events", SecretReferenceID: "secret_opaque", SecretName: "webhook", SecretProvider: "fixture-secret", SecretVersion: "v1", EventTypes: []string{"deployment.failed", "deployment.succeeded"}, Enabled: true}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid opaque endpoint rejected: %v", err)
	}
	for _, endpoint := range []WebhookEndpoint{
		{ID: "hook_2", ApplicationID: "app_1", URL: "http://receiver.fixture.test", SecretReferenceID: "secret_opaque", SecretName: "webhook", SecretProvider: "fixture-secret", EventTypes: []string{"deployment.failed"}},
		{ID: "hook_3", ApplicationID: "app_1", URL: "https://localhost/events", SecretReferenceID: "secret_opaque", SecretName: "webhook", SecretProvider: "fixture-secret", EventTypes: []string{"deployment.failed"}},
		{ID: "hook_4", ApplicationID: "app_1", URL: "https://user:pass@receiver.fixture.test/events", SecretReferenceID: "secret_opaque", SecretName: "webhook", SecretProvider: "fixture-secret", EventTypes: []string{"deployment.failed"}},
		{ID: "hook_5", ApplicationID: "app_1", URL: "https://receiver.fixture.test/events?token=no", SecretReferenceID: "secret_opaque", SecretName: "webhook", SecretProvider: "fixture-secret", EventTypes: []string{"deployment.failed"}},
		{ID: "hook_6", ApplicationID: "app_1", URL: "https://receiver.fixture.test/events", SecretReferenceID: "secret_opaque", SecretName: "webhook", SecretProvider: "fixture-secret", EventTypes: []string{"deployment.failed", "deployment.failed"}},
	} {
		if err := endpoint.Validate(); err == nil {
			t.Errorf("unsafe webhook endpoint accepted: %#v", endpoint)
		}
	}
}

func TestM4WebhookLedgerAndAttemptStatesFailClosed(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	event := WebhookEventLedger{EndpointID: "hook_1", EventID: "evt_1", EventType: "deployment.failed", PayloadDigest: "sha256:" + strings.Repeat("a", 64), OccurredAt: now, Status: WebhookDeliveryPending, ReceivedCount: 1}
	if err := event.Validate(); err != nil {
		t.Fatalf("valid pending event rejected: %v", err)
	}
	status := 204
	attempt := WebhookAttempt{ID: "attempt_1", EndpointID: event.EndpointID, EventID: event.EventID, AttemptNumber: 1, RequestDigest: "sha256:" + strings.Repeat("b", 64), Status: WebhookAttemptDelivered, HTTPStatus: &status, CreatedAt: now}
	if err := attempt.Validate(); err != nil {
		t.Fatalf("valid delivered attempt rejected: %v", err)
	}
	for _, invalid := range []WebhookAttempt{
		{ID: "attempt_2", EndpointID: event.EndpointID, EventID: event.EventID, AttemptNumber: 0, RequestDigest: attempt.RequestDigest, Status: WebhookAttemptRetryable},
		{ID: "attempt_3", EndpointID: event.EndpointID, EventID: event.EventID, AttemptNumber: 1, RequestDigest: attempt.RequestDigest, Status: WebhookAttemptDelivered},
		{ID: "attempt_4", EndpointID: event.EndpointID, EventID: event.EventID, AttemptNumber: 1, RequestDigest: attempt.RequestDigest, Status: WebhookAttemptRetryable, HTTPStatus: &status},
	} {
		if err := invalid.Validate(); err == nil {
			t.Errorf("invalid webhook attempt accepted: %#v", invalid)
		}
	}
}

func TestM4WebhookPayloadIsCanonicalRedactedLifecycleOnly(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	payload, err := json.Marshal(map[string]string{"schema_version": "m4.notification.v1", "application_id": "app_1", "environment_id": "env_1", "incident_id": "incident_1", "kind": "occurrence", "severity": "warning", "message": "runtime unavailable", "occurred_at": now.Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := canonicalM4WebhookPayload(payload)
	if err != nil || digest != m1Digest(canonical) {
		t.Fatalf("canonical payload failed: digest=%s err=%v", digest, err)
	}
	request := WebhookDeliveryRequest{DeliveryID: "delivery_1", EndpointID: "hook_1", EventID: "event_1", EventType: "notification.occurrence", PayloadDigest: digest, Payload: canonical, IdempotencyKey: "notify-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), OccurredAt: now}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid delivery request rejected: %v", err)
	}
	unsafe := append(json.RawMessage(nil), canonical...)
	unsafe = json.RawMessage(strings.ReplaceAll(string(unsafe), "runtime unavailable", "token=canary"))
	if _, _, err := canonicalM4WebhookPayload(unsafe); err == nil {
		t.Fatal("unredacted token payload accepted")
	}
	unknown, _ := json.Marshal(map[string]string{"schema_version": "m4.notification.v1", "application_id": "app_1", "environment_id": "env_1", "incident_id": "incident_1", "kind": "occurrence", "severity": "warning", "message": "runtime unavailable", "occurred_at": now.Format(time.RFC3339Nano), "raw_log": "never"})
	if _, _, err := canonicalM4WebhookPayload(unknown); err == nil {
		t.Fatal("raw-log field accepted")
	}
}

func TestM4WebhookDeliveryAttemptRequiresClaimOwnerAndExactRetryTime(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	valid := WebhookDeliveryAttempt{DeliveryID: "delivery_1", EventID: "event_1", Attempt: 1, LeaseOwner: "worker_1", At: now, Status: WebhookDeliveryPending, NextAttemptAt: now.Add(time.Minute), Failure: "timeout", FailureCode: "timeout"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid retry attempt rejected: %v", err)
	}
	valid.LeaseOwner = ""
	if err := valid.Validate(); err == nil {
		t.Fatal("unowned delivery attempt accepted")
	}
}

func TestM4LogIndexProtectsAuditAndOperationFactsAreTyped(t *testing.T) {
	audit := LogIndex{ID: "log_1", ApplicationID: "app_1", ServiceName: "audit", Category: LogIndexAudit, Path: "/safe/audit/0001.log", Segment: 1, ByteSize: 1}
	if err := audit.Validate(); err != nil {
		t.Fatalf("valid audit log index rejected: %v", err)
	}
	now := time.Now().UTC()
	audit.RetiredAt = &now
	if err := audit.Validate(); err == nil {
		t.Fatal("retired audit index accepted")
	}
	if err := (LogIndex{ID: "log_2", ApplicationID: "app_1", ServiceName: "runtime", Category: LogIndexRuntime, Path: "", Segment: 0}).Validate(); err == nil {
		t.Fatal("blank log path accepted")
	}
	if !m4SHA256("sha256:"+strings.Repeat("a", 64)) || m4SHA256("sha256:UPPER") {
		t.Fatal("digest shape validation mismatch")
	}
}

func TestAcornFoxLogIndexMetadataRejectsInventedOrInvalidIdentity(t *testing.T) {
	valid := LogIndex{
		ID:            "log_build_1",
		ApplicationID: "app_1",
		ServiceName:   "web",
		BuildID:       "build_1",
		Category:      LogIndexBuild,
		LogStream:     LogStreamStderr,
		Truncation:    LogTruncationSourceLimited,
		Path:          "/safe/build/0001.log",
		Segment:       1,
		ByteSize:      1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid AcornFox build log metadata rejected: %v", err)
	}
	for _, invalid := range []LogIndex{
		func() LogIndex { item := valid; item.Category, item.BuildID = LogIndexRuntime, "build_1"; return item }(),
		func() LogIndex { item := valid; item.LogTaskID = "task_1"; return item }(),
		func() LogIndex { item := valid; item.LogStream = "file"; return item }(),
		func() LogIndex { item := valid; item.Truncation = "partial"; return item }(),
	} {
		if err := invalid.Validate(); err == nil {
			t.Errorf("invalid AcornFox log metadata accepted: %#v", invalid)
		}
	}
	legacy := valid
	legacy.LogStream, legacy.Truncation, legacy.BuildID = "", "", ""
	if normalized := legacy.normalizedLogMetadata(); normalized.LogStream != LogStreamUnknown || normalized.Truncation != LogTruncationUnknown {
		t.Fatalf("legacy metadata normalization=%+v, want explicit unknown values", normalized)
	}
	if err := (AcornFoxLogIndexCursor{RecordedAt: time.Unix(1, 0).UTC(), RecordKey: "record_1"}).Validate(); err != nil {
		t.Fatalf("valid AcornFox log cursor rejected: %v", err)
	}
	if err := (AcornFoxLogIndexCursor{}).Validate(); err == nil {
		t.Fatal("empty AcornFox log cursor accepted")
	}
}

func TestAcornFoxLogMetadataMigrationIsAdditiveAndBounded(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0028_acornfox_log_metadata.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, fragment := range []string{
		"add column if not exists build_id text references builds(id)",
		"add column if not exists log_stream text",
		"add column if not exists truncation text",
		"add column if not exists content_digest text",
		"build_id is null or category = 'build'",
		"log_stream in ('stdout', 'stderr', 'combined', 'unknown')",
		"truncation in ('complete', 'source_limited', 'unknown')",
		"m4_log_indexes_content_digest_sha256",
		"content_digest ~ '^sha256:[0-9a-f]{64}$'",
		"m4_log_indexes_active_build_delivery_idx",
		"m4_log_indexes_active_runtime_delivery_idx",
		"retired_at is null",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("AcornFox log metadata migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"log_content", "log_bytes", "delete from", "drop table"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("AcornFox log metadata migration must not contain %q", forbidden)
		}
	}
}

func TestAcornFoxLogProvenanceMigrationDoesNotStoreLogBytes(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0029_acornfox_log_provenance.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, fragment := range []string{
		"add column if not exists log_task_id text references task_leases(task_id)",
		"log_task_id is null or category = 'runtime'",
		"m4_log_indexes_active_runtime_task_idx",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("AcornFox log provenance migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"log_content", "log_bytes", "delete from", "drop table"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("AcornFox log provenance migration must not contain %q", forbidden)
		}
	}
}
