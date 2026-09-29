package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

const accepted0002Checksum = "115e0a87ff39cba74d0281cb15d30b54c375e4e8b9cae3b0606084d7981ef400"

func taskFixture(t *testing.T, s *Store, name string, now time.Time) contracts.CreateApplicationResult {
	t.Helper()
	app, err := domain.NewApplication(name, now)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := domain.NewID("env")
	op, _ := domain.NewID("op")
	task, _ := domain.NewID("task")
	result, err := s.CreateApplication(context.Background(), contracts.CreateApplicationRecord{Audit: contracts.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "trusted fixture creation"}, Application: app, EnvironmentID: env, OperationID: op, TaskID: task, IdempotencyKey: name, Event: contracts.Event{SchemaVersion: "1.1", OccurredAt: now, Kind: "operation.created", Status: "preparing"}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func claimRequest(now time.Time, max int) contracts.ClaimTaskRequest {
	return contracts.ClaimTaskRequest{Owner: "worker", Now: now, Kinds: []string{" application.create ", "application.create"}, LeasePolicy: contracts.LeasePolicy{Duration: time.Minute, MaxAttempts: max}}
}
func mutation(t contracts.Task, now time.Time) contracts.TaskMutationRequest {
	return contracts.TaskMutationRequest{TaskID: t.ID, Owner: t.LeaseOwner, Now: now, CoreGeneration: t.CoreGeneration, LeaseGeneration: t.LeaseGeneration, LeasePolicy: contracts.LeasePolicy{Duration: time.Minute}}
}
func mustClaim(t *testing.T, s *Store, r contracts.ClaimTaskRequest) contracts.Task {
	t.Helper()
	task, found, err := s.ClaimTask(context.Background(), r)
	if err != nil || !found {
		t.Fatalf("claim found=%v err=%v", found, err)
	}
	return task
}

func TestSQLiteTasksLifecycleKindsBudget(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestSQLiteStore(t)
	now := time.Now().UTC()
	first := taskFixture(t, s, "task-first", now)
	second := taskFixture(t, s, "task-second", now.Add(time.Second))
	third := taskFixture(t, s, "task-third", now.Add(2*time.Second))
	clock := now.Add(time.Minute)
	empty := claimRequest(clock, 2)
	empty.Kinds = []string{" "}
	if _, _, err := s.ClaimTask(ctx, empty); err == nil {
		t.Fatal("empty kinds accepted")
	}
	mixed := claimRequest(clock, 2)
	mixed.Kinds = []string{"application.create", " "}
	if _, _, err := s.ClaimTask(ctx, mixed); err == nil {
		t.Fatal("mixed empty kind accepted")
	}
	wrong := claimRequest(clock, 2)
	wrong.Kinds = []string{"other"}
	if _, found, err := s.ClaimTask(ctx, wrong); err != nil || found {
		t.Fatalf("wrong kind found=%v err=%v", found, err)
	}
	generic := claimRequest(clock, 2)
	generic.Kinds = nil
	task := mustClaim(t, s, generic)
	if task.OperationID != first.OperationID || task.Attempt != 1 || task.MaxAttempts != 2 {
		t.Fatalf("first task %+v", task)
	}
	if err := s.RenewTask(ctx, mutation(task, clock.Add(10*time.Second))); err != nil {
		t.Fatal(err)
	}
	state, err := s.FailTask(ctx, contracts.FailTaskRequest{TaskMutationRequest: mutation(task, clock.Add(20*time.Second)), Reason: "Authorization: Bearer supersecret\npassword=verysecret " + strings.Repeat("x", 2000)})
	if err != nil || state != contracts.TaskReady {
		t.Fatalf("retry state=%s err=%v", state, err)
	}
	stored, err := s.GetTask(ctx, task.ID)
	if err != nil || stored.LeaseOwner != "" || stored.LeaseUntil != nil || len(stored.LastError) > 1024 || strings.Contains(stored.LastError, "supersecret") || strings.Contains(stored.LastError, "verysecret") {
		t.Fatalf("failure projection %+v %v", stored, err)
	}
	task = mustClaim(t, s, claimRequest(clock.Add(30*time.Second), 9))
	if task.Attempt != 2 || task.MaxAttempts != 2 {
		t.Fatalf("attempt budget reset %+v", task)
	}
	state, err = s.FailTask(ctx, contracts.FailTaskRequest{TaskMutationRequest: mutation(task, clock.Add(31*time.Second)), Reason: "exhausted"})
	if err != nil || state != contracts.TaskFailed {
		t.Fatalf("exhausted state=%s err=%v", state, err)
	}
	task = mustClaim(t, s, claimRequest(clock.Add(40*time.Second), 3))
	if task.OperationID != second.OperationID {
		t.Fatal("unstable task order")
	}
	if err := s.CompleteTask(ctx, mutation(task, clock.Add(41*time.Second))); err != nil {
		t.Fatal(err)
	}
	task = mustClaim(t, s, claimRequest(clock.Add(42*time.Second), 3))
	if task.OperationID != third.OperationID {
		t.Fatal("third task order")
	}
	if err := s.CancelTask(ctx, mutation(task, clock.Add(43*time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.ClaimTask(ctx, claimRequest(clock.Add(24*time.Hour), 3)); err != nil || found {
		t.Fatalf("terminal task reclaimed: %v %v", found, err)
	}
}

func TestSQLiteTaskFencingExpiryRestartAndCompetition(t *testing.T) {
	ctx := context.Background()
	s, dir := newTestSQLiteStore(t)
	now := time.Now().UTC()
	taskFixture(t, s, "fenced", now)
	req := claimRequest(now.Add(time.Minute), 3)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winner contracts.Task
	claims := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, found, err := s.ClaimTask(ctx, req)
			if err != nil {
				t.Error(err)
				return
			}
			if found {
				mu.Lock()
				winner = got
				claims++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claims != 1 {
		t.Fatalf("competitive claims=%d", claims)
	}
	expired := mutation(winner, *winner.LeaseUntil)
	if err := s.CompleteTask(ctx, expired); !errors.Is(err, contracts.ErrLeaseLost) {
		t.Fatalf("exact expiry accepted %v", err)
	}
	newer := mustClaim(t, s, claimRequest(*winner.LeaseUntil, 3))
	if newer.LeaseGeneration <= winner.LeaseGeneration || newer.Attempt != 2 {
		t.Fatalf("same owner reclaimed without fencing %+v", newer)
	}
	assertStale := func(store *Store, stale contracts.TaskMutationRequest) {
		t.Helper()
		cases := []struct {
			name string
			call func() error
		}{{"renew", func() error { return store.RenewTask(ctx, stale) }}, {"complete", func() error { return store.CompleteTask(ctx, stale) }}, {"fail", func() error {
			_, err := store.FailTask(ctx, contracts.FailTaskRequest{TaskMutationRequest: stale, Reason: "stale"})
			return err
		}}, {"cancel", func() error { return store.CancelTask(ctx, stale) }}}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if err := c.call(); !errors.Is(err, contracts.ErrLeaseLost) {
					t.Fatalf("stale token accepted: %v", err)
				}
			})
		}
	}
	assertStale(s, mutation(winner, newer.LeaseUntil.Add(-time.Second)))
	wrong := mutation(newer, newer.LeaseUntil.Add(-time.Second))
	wrong.Owner = "other"
	if err := s.CompleteTask(ctx, wrong); !errors.Is(err, contracts.ErrLeaseLost) {
		t.Fatalf("foreign owner mutated %v", err)
	}
	missing := mutation(newer, newer.LeaseUntil.Add(-time.Second))
	missing.LeaseGeneration = 0
	if err := s.CompleteTask(ctx, missing); err == nil {
		t.Fatal("missing fencing accepted")
	}

	oldGeneration := s.coreGeneration
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.coreGeneration != oldGeneration+1 {
		t.Fatalf("core generation not persistent %d -> %d", oldGeneration, reopened.coreGeneration)
	}
	restarted := mustClaim(t, reopened, claimRequest(*winner.LeaseUntil, 3))
	if restarted.Attempt != 3 || restarted.CoreGeneration <= newer.CoreGeneration || restarted.LeaseGeneration <= newer.LeaseGeneration {
		t.Fatalf("restart token %+v", restarted)
	}
	assertStale(reopened, mutation(newer, *winner.LeaseUntil))
	if err := reopened.CompleteTask(ctx, mutation(restarted, *winner.LeaseUntil)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := reopened.ClaimTask(ctx, claimRequest(now.Add(48*time.Hour), 3)); err != nil || found {
		t.Fatalf("budget/terminal invalid %v %v", found, err)
	}
	// Exhausted leases retain queryable facts for explicit controller recovery.
	taskFixture(t, reopened, "old-exhausted", now)
	exhausted := mustClaim(t, reopened, claimRequest(now.Add(48*time.Hour), 1))
	before := reopened.coreGeneration
	reopened.Close()
	reopened, err = Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.coreGeneration != before+1 {
		t.Fatal("second restart generation")
	}
	if _, found, err := reopened.ClaimTask(ctx, claimRequest(now.Add(48*time.Hour), 3)); err != nil || found {
		t.Fatalf("exhausted restart reclaims %v %v", found, err)
	}
	terminal, err := reopened.GetTask(ctx, exhausted.ID)
	if err != nil || terminal.State != contracts.TaskLeased || terminal.LeaseOwner != exhausted.LeaseOwner || terminal.Attempt != 1 || terminal.CoreGeneration != exhausted.CoreGeneration || terminal.LeaseGeneration != exhausted.LeaseGeneration {
		t.Fatalf("exhausted facts altered %+v %v", terminal, err)
	}
	// Exhaustion refuses opening rather than wrapping the persistent generation.
	if _, err := reopened.db.Exec(`UPDATE core_generation SET generation=? WHERE singleton=1`, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if bad, err := Open(Config{DataDirectory: dir}); err == nil {
		bad.Close()
		t.Fatal("core generation wrapped")
	}
}

func TestSQLiteOutboxCursorPublicationReplayAndRestart(t *testing.T) {
	ctx := context.Background()
	s, dir := newTestSQLiteStore(t)
	now := time.Now().UTC()
	created := taskFixture(t, s, "outbox", now)
	appendNext := func(store *Store, id string) contracts.OutboxEvent {
		t.Helper()
		payload, _ := json.Marshal(contracts.Event{SchemaVersion: "1.1", ID: id, ApplicationID: created.Application.ID.String(), OperationID: created.OperationID.String(), Sequence: 2, OccurredAt: now, Kind: "operation.updated", Status: "preparing"})
		event, err := store.AppendOutboxEvent(ctx, contracts.OutboxEvent{ID: id, AggregateType: "operation", AggregateID: created.OperationID.String(), AggregateVersion: 1, EventType: "operation.updated", Payload: payload, CreatedAt: now, PayloadVersion: "1.1"})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	second := appendNext(s, "outbox-second")
	if second.Sequence != 2 || second.StreamSequence != 2 {
		t.Fatalf("cursor %+v", second)
	}
	pending, err := s.FetchOutboxAfter(ctx, 0, 10)
	if err != nil || len(pending) != 2 || pending[0].StreamSequence != 1 || pending[1].StreamSequence != 2 {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if marked, err := s.MarkOutboxPublished(ctx, pending[0].ID, now); err != nil || !marked {
		t.Fatalf("first publication %v %v", marked, err)
	}
	if marked, err := s.MarkOutboxPublished(ctx, pending[0].ID, now.Add(time.Hour)); err != nil || marked {
		t.Fatalf("repeat publication %v %v", marked, err)
	}
	var published string
	if err := s.db.QueryRow(`SELECT published_at FROM outbox_events WHERE id=?`, pending[0].ID).Scan(&published); err != nil || published != FormatTime(now) {
		t.Fatalf("marker overwritten %s %v", published, err)
	}
	if _, err := s.db.Exec(`UPDATE outbox_events SET payload='{}' WHERE id=?`, pending[0].ID); err == nil {
		t.Fatal("history mutable")
	}
	if _, err := s.db.Exec(`DELETE FROM outbox_events WHERE id=?`, pending[0].ID); err == nil {
		t.Fatal("history deleted")
	}
	s.Close()
	reopened, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	third := appendNext(reopened, "outbox-third")
	if third.Sequence != 3 || third.StreamSequence != 3 {
		t.Fatalf("reopen reset cursor %+v", third)
	}
	pending, err = reopened.FetchOutboxAfter(ctx, 1, 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending cursor %+v %v", pending, err)
	}
	fourth := taskFixture(t, reopened, "outbox-other-aggregate", now)
	var local, cursor int64
	if err := reopened.db.QueryRow(`SELECT sequence,stream_sequence FROM outbox_events WHERE id=?`, fourth.Event.ID).Scan(&local, &cursor); err != nil || local != 1 || cursor != 4 {
		t.Fatalf("aggregate/global distinction %d %d %v", local, cursor, err)
	}
	events, err := reopened.ListEvents(ctx, contracts.EventFilter{OperationID: created.OperationID.String()})
	if err != nil || len(events) != 3 {
		t.Fatalf("full replay includes published %+v %v", events, err)
	}
}
