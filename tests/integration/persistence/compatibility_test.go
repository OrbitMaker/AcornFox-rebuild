//go:build integration

package persistence_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestProtocolCompatibilityDatabaseDefaultsAndCurrentWrites(t *testing.T) {
	databaseURL := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var contractCount int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM protocol_contracts WHERE (component='agent' OR component='rest-sse') AND version IN ('1.0','1.1')`).Scan(&contractCount); err != nil || contractCount != 4 {
		t.Fatalf("protocol contracts count=%d err=%v", contractCount, err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	applicationID := "app_compat_" + suffix
	environmentID := "env_compat_" + suffix
	operationID := "op_compat_" + suffix
	taskID := "task_compat_" + suffix
	eventID := "evt_compat_" + suffix
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,'compatibility fixture')`, applicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO environments(id,application_id,name) VALUES($1,$2,'compatibility')`, environmentID, applicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,target_ref) VALUES($1,$2,$3,'deploy',$4,'pending',$2)`, operationID, applicationID, environmentID, "compat-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,state,payload) VALUES($1,$2,'ready','{"kind":"observe"}'::jsonb)`, taskID, operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,event_type,payload) VALUES($1,'operation',$2,1,1,'operation.created','{"status":"preparing"}'::jsonb)`, eventID, operationID); err != nil {
		t.Fatal(err)
	}
	var wireVersion, payloadVersion string
	if err := store.DB().QueryRowContext(ctx, `SELECT t.wire_version,e.payload_version FROM task_leases t CROSS JOIN outbox_events e WHERE t.task_id=$1 AND e.id=$2`, taskID, eventID).Scan(&wireVersion, &payloadVersion); err != nil {
		t.Fatal(err)
	}
	if wireVersion != "1.0" || payloadVersion != "1.0" {
		t.Fatalf("legacy defaults wire=%s payload=%s", wireVersion, payloadVersion)
	}
	events, err := store.ListEvents(ctx, application.EventFilter{OperationID: operationID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].SchemaVersion != "1.0" {
		t.Fatalf("new reader did not normalize old event: %#v", events)
	}
	controller := application.NewController(store)
	created, err := controller.CreateApplication(ctx, "compat-current", "compat-current-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT payload_version FROM outbox_events WHERE id=$1`, created.Event.ID).Scan(&payloadVersion); err != nil {
		t.Fatal(err)
	}
	if payloadVersion != "1.1" || created.Event.SchemaVersion != "1.1" {
		t.Fatalf("current write versions payload=%s event=%s", payloadVersion, created.Event.SchemaVersion)
	}
	var oldReaderState string
	var oldReaderPayload []byte
	if err := store.DB().QueryRowContext(ctx, `SELECT state,payload FROM task_leases WHERE task_id=$1`, taskID).Scan(&oldReaderState, &oldReaderPayload); err != nil || oldReaderState != "ready" {
		t.Fatalf("old task reader state=%s err=%v", oldReaderState, err)
	}
}
