package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
)

func TestValidateCreateRecordRejectsMissingIdentityAndEvent(t *testing.T) {
	record := application.CreateApplicationRecord{}
	if err := validateCreateRecord(record); err == nil {
		t.Fatal("expected incomplete create record to fail closed")
	}

	record = validCreateRecord()
	record.Event.OperationID = "different-operation"
	if err := validateCreateRecord(record); err == nil {
		t.Fatal("expected mismatched event operation to be rejected")
	}

	record = validCreateRecord()
	record.IdempotencyKey = ""
	if err := validateCreateRecord(record); err == nil {
		t.Fatal("expected missing idempotency key to be rejected")
	}
}

func TestRepositorySequenceAndQueryBounds(t *testing.T) {
	for _, test := range []struct {
		input    uint64
		expected string
	}{
		{input: 0, expected: "0"},
		{input: 1, expected: "1"},
		{input: 3000000000, expected: "3000000000"},
	} {
		if got := formatSequence(test.input); got != test.expected {
			t.Errorf("formatSequence(%d) = %q, want %q", test.input, got, test.expected)
		}
	}
	if got, err := normalizeLimit(0); err != nil || got != defaultQueryLimit {
		t.Fatalf("default query limit = %d, %v", got, err)
	}
	if _, err := normalizeLimit(maxQueryLimit + 1); err == nil {
		t.Fatal("expected oversized query limit to fail")
	}
}

func TestOutboxValidationIsFailClosed(t *testing.T) {
	valid := OutboxEvent{
		AggregateType:    "operation",
		AggregateID:      "op_1",
		AggregateVersion: 1,
		EventType:        "operation.created",
	}
	if err := validateOutboxEvent(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []OutboxEvent{
		{AggregateID: "op_1", AggregateVersion: 1, EventType: "operation.created"},
		{AggregateType: "operation", AggregateID: "op_1", AggregateVersion: 0, EventType: "operation.created"},
		{AggregateType: "operation", AggregateID: "op_1", AggregateVersion: 1},
	} {
		if err := validateOutboxEvent(invalid); err == nil {
			t.Errorf("expected invalid outbox event to fail: %#v", invalid)
		}
	}
}

func TestApplicationErrorsRemainCompatible(t *testing.T) {
	if !errors.Is(ErrNotFound, application.ErrNotFound) {
		t.Fatal("postgres ErrNotFound must preserve application error identity")
	}
	if !errors.Is(ErrNotFound, auth.ErrNotFound) {
		t.Fatal("postgres ErrNotFound must preserve auth error identity")
	}
	if !errors.Is(ErrCredentialVersionConflict, auth.ErrCredentialVersionConflict) {
		t.Fatal("postgres ErrCredentialVersionConflict must preserve auth error identity")
	}
	if !errors.Is(ErrIdempotencyConflict, application.ErrIdempotencyConflict) {
		t.Fatal("postgres idempotency conflict must preserve application error identity")
	}
}

func TestNormalizedClaimKindsRejectsEmptyAndDeduplicates(t *testing.T) {
	kinds, err := normalizedClaimKinds([]string{"deploy_group", " deploy_group ", "application.create"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 2 || kinds[0] != "deploy_group" || kinds[1] != "application.create" {
		t.Fatalf("unexpected normalized kinds: %#v", kinds)
	}
	if _, err := normalizedClaimKinds([]string{"deploy_group", " "}); err == nil {
		t.Fatal("empty claim kind was accepted")
	}
}

func validCreateRecord() application.CreateApplicationRecord {
	now := time.Unix(1700000000, 0).UTC()
	app := domain.Application{ID: "app_1", Name: "demo", CreatedAt: now, UpdatedAt: now}
	return application.CreateApplicationRecord{
		Application:    app,
		EnvironmentID:  "env_1",
		OperationID:    "op_1",
		TaskID:         "task_1",
		IdempotencyKey: "create-demo",
		RequestDigest:  "sha256:demo",
		Event: application.Event{
			OperationID:   "op_1",
			ApplicationID: "app_1",
			Kind:          "operation.created",
			Status:        "preparing",
			OccurredAt:    now,
		},
	}
}
