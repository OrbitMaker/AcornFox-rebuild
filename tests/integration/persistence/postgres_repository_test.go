//go:build integration

package persistence_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestPostgresRepositoryConcurrencyReplayAndLeaseTakeover(t *testing.T) {
	databaseURL := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("OPEN_CARD_TEST_DATABASE_URL is required for the integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	// Previous interrupted test runs may leave only task-prefixed fixture work
	// ready. Drain it inside the dedicated task database so this run proves it
	// leases the operation it just created rather than an unrelated old row.
	drainNow := time.Now().UTC().Add(24 * time.Hour)
	for {
		stale, ok, err := store.ClaimNextTask(ctx, "integration-drain", drainNow, time.Second, 3)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if err := store.CompleteTaskLease(ctx, stale.ID, "integration-drain", drainNow.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	controller := application.NewController(store)
	key := fmt.Sprintf("repository-integration-%d", time.Now().UnixNano())

	const clients = 20
	results := make([]application.CreateApplicationResult, clients)
	errorsByClient := make([]error, clients)
	var wait sync.WaitGroup
	wait.Add(clients)
	for index := 0; index < clients; index++ {
		go func(index int) {
			defer wait.Done()
			results[index], errorsByClient[index] = controller.CreateApplication(ctx, "repository-integration", key)
		}(index)
	}
	wait.Wait()
	for index, clientErr := range errorsByClient {
		if clientErr != nil {
			t.Fatalf("client %d create failed: %v", index, clientErr)
		}
		if results[index].Application.ID != results[0].Application.ID || results[index].OperationID != results[0].OperationID || results[index].Event.Sequence != results[0].Event.Sequence {
			t.Fatalf("client %d observed a different idempotent result: %#v vs %#v", index, results[index], results[0])
		}
	}
	if _, err := controller.CreateApplication(ctx, "different-input", key); !errors.Is(err, application.ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	replayed, err := controller.ListEvents(ctx, results[0].OperationID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 1 || replayed[0].ID != results[0].Event.ID || replayed[0].Sequence != results[0].Event.Sequence {
		t.Fatalf("persistent replay mismatch: %#v", replayed)
	}

	baseTime := time.Now().UTC()
	firstLease, ok, err := store.ClaimNextTask(ctx, "worker-one", baseTime, 100*time.Millisecond, 3)
	if err != nil || !ok {
		t.Fatalf("first task claim: ok=%v err=%v", ok, err)
	}
	if firstLease.Attempt != 1 || firstLease.LeaseOwner != "worker-one" || firstLease.LeaseUntil == nil {
		t.Fatalf("unexpected first lease: %#v", firstLease)
	}
	if firstLease.OperationID != results[0].OperationID {
		t.Fatalf("claimed task belongs to %s, want current operation %s", firstLease.OperationID, results[0].OperationID)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// A new Store models a worker/control-plane process restart. The second
	// worker may take over only after the durable first lease has expired.
	restarted, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	secondLease, ok, err := restarted.ClaimNextTask(ctx, "worker-two", baseTime.Add(200*time.Millisecond), 250*time.Millisecond, 3)
	if err != nil || !ok {
		t.Fatalf("takeover claim: ok=%v err=%v", ok, err)
	}
	if secondLease.ID != firstLease.ID || secondLease.Attempt != 2 || secondLease.LeaseOwner != "worker-two" {
		t.Fatalf("expired lease was not taken over deterministically: first=%#v second=%#v", firstLease, secondLease)
	}
	if err := restarted.CompleteTaskLease(ctx, secondLease.ID, "worker-one", baseTime.Add(210*time.Millisecond)); !errors.Is(err, postgres.ErrLeaseLost) {
		t.Fatalf("stale owner completed taken-over task: %v", err)
	}
	if err := restarted.RenewTaskLease(ctx, secondLease.ID, "worker-two", baseTime.Add(210*time.Millisecond), 250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := restarted.CompleteTaskLease(ctx, secondLease.ID, "worker-two", baseTime.Add(220*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	completed, err := restarted.GetTask(ctx, secondLease.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != postgres.TaskCompleted || completed.LeaseOwner != "" || completed.LeaseUntil != nil {
		t.Fatalf("task did not reach durable completed state: %#v", completed)
	}

	pending, err := restarted.FetchOutboxAfter(ctx, int64(results[0].Event.Sequence-1), 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range pending {
		if event.ID != results[0].Event.ID {
			continue
		}
		found = true
		marked, err := restarted.MarkOutboxPublished(ctx, event.ID, time.Now().UTC())
		if err != nil || !marked {
			t.Fatalf("first outbox publish mark: marked=%v err=%v", marked, err)
		}
		marked, err = restarted.MarkOutboxPublished(ctx, event.ID, time.Now().UTC())
		if err != nil || marked {
			t.Fatalf("repeated outbox publish mark was not idempotent: marked=%v err=%v", marked, err)
		}
	}
	if !found {
		t.Fatalf("created event %s was absent from pending outbox", results[0].Event.ID)
	}
}

func TestPostgresRepositoryQueriesOneHundredThousandEventsUnderGate(t *testing.T) {
	databaseURL := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("OPEN_CARD_TEST_DATABASE_URL is required for the integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const aggregateID = "m0-load-100k-v1"
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO outbox_events
			(id, aggregate_type, aggregate_id, aggregate_version, sequence, event_type, payload)
		SELECT 'evt-m0-load-' || lpad(value::text, 6, '0'),
		       'load_fixture', $1, value, value, 'load.sample',
		       jsonb_build_object('sequence', value, 'evidence_type', 'database_query')
		  FROM generate_series(1, 100000) AS value
		ON CONFLICT DO NOTHING
	`, aggregateID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_type='load_fixture' AND aggregate_id=$1`, aggregateID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 100000 {
		t.Fatalf("expected 100000 load events, got %d", count)
	}
	if _, err := store.DB().ExecContext(ctx, `ANALYZE outbox_events`); err != nil {
		t.Fatal(err)
	}
	durations := make([]time.Duration, 0, 30)
	for iteration := 0; iteration < 30; iteration++ {
		started := time.Now()
		rows, err := store.DB().QueryContext(ctx, `
			SELECT id, sequence, payload
			  FROM outbox_events
			 WHERE aggregate_type='load_fixture' AND aggregate_id=$1
			 ORDER BY sequence DESC
			 LIMIT 100
		`, aggregateID)
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for rows.Next() {
			var id string
			var sequence int64
			var payload []byte
			if err := rows.Scan(&id, &sequence, &payload); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			seen++
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if seen != 100 {
			t.Fatalf("query %d returned %d events", iteration, seen)
		}
		durations = append(durations, time.Since(started))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95+99)/100-1]
	t.Logf("event_count=%d query_samples=%d query_p95=%s", count, len(durations), p95)
	if p95 > 500*time.Millisecond {
		t.Fatalf("100000-event query p95 exceeded 500ms gate: %s", p95)
	}
}
