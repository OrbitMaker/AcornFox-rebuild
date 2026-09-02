//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/dnschange"
)

type dnsExecutionFixtureProvider struct {
	mu            sync.Mutex
	records       []dnschange.Record
	listResponses [][]dnschange.Record
	creates       int
	updates       int
	deletes       int
	indeterminate bool
	entered       chan struct{}
	release       chan struct{}
}

func (p *dnsExecutionFixtureProvider) ListRecords(_ context.Context, _ dnschange.ManagedZone) ([]dnschange.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.listResponses) > 0 {
		value := p.listResponses[0]
		p.listResponses = p.listResponses[1:]
		return append([]dnschange.Record(nil), value...), nil
	}
	return append([]dnschange.Record(nil), p.records...), nil
}
func (p *dnsExecutionFixtureProvider) CreateRecord(_ context.Context, desired dnschange.DesiredRecord) (dnschange.WriteReceipt, error) {
	p.mu.Lock()
	p.creates++
	p.mu.Unlock()
	p.pause()
	p.mu.Lock()
	defer p.mu.Unlock()
	record := desired.Record
	record.RecordID, record.RequestID, record.CreatedAt = "opaque-create", "request-create", time.Unix(1, 0).UTC()
	p.records = append(p.records, record)
	if p.indeterminate {
		return dnschange.WriteReceipt{}, dnsExecutionIndeterminate{}
	}
	return dnschange.WriteReceipt{RecordID: record.RecordID, RequestID: record.RequestID}, nil
}
func (p *dnsExecutionFixtureProvider) UpdateRecord(_ context.Context, update dnschange.Record) (dnschange.WriteReceipt, error) {
	p.mu.Lock()
	p.updates++
	p.mu.Unlock()
	p.pause()
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := range p.records {
		if p.records[index].RecordID == update.RecordID {
			p.records[index].Name, p.records[index].Type, p.records[index].Value, p.records[index].TTL = update.Name, update.Type, update.Value, update.TTL
			if p.indeterminate {
				return dnschange.WriteReceipt{}, dnsExecutionIndeterminate{}
			}
			return dnschange.WriteReceipt{RecordID: update.RecordID, RequestID: "request-update"}, nil
		}
	}
	return dnschange.WriteReceipt{}, errors.New("fixture record missing")
}
func (p *dnsExecutionFixtureProvider) DeleteRecord(_ context.Context, record dnschange.Record) (dnschange.WriteReceipt, error) {
	p.mu.Lock()
	p.deletes++
	p.mu.Unlock()
	p.pause()
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := range p.records {
		if p.records[index].RecordID == record.RecordID {
			p.records = append(p.records[:index], p.records[index+1:]...)
			if p.indeterminate {
				return dnschange.WriteReceipt{}, dnsExecutionIndeterminate{}
			}
			return dnschange.WriteReceipt{RecordID: record.RecordID, RequestID: "request-delete"}, nil
		}
	}
	return dnschange.WriteReceipt{}, errors.New("fixture record missing")
}

func (p *dnsExecutionFixtureProvider) pause() {
	if p.entered != nil {
		p.entered <- struct{}{}
	}
	if p.release != nil {
		<-p.release
	}
}

type dnsExecutionIndeterminate struct{}

func (dnsExecutionIndeterminate) Error() string           { return "fixture outcome unknown" }
func (dnsExecutionIndeterminate) RequiresReconcile() bool { return true }

func TestAFBDNSExecutionDurablyPreventsBlindRetryAfterRestart(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAFBDNSExecutionDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, test := range []struct {
		name    string
		cleanup bool
		writes  func(*dnsExecutionFixtureProvider) int
	}{
		{"create", false, func(p *dnsExecutionFixtureProvider) int { return p.creates }},
		{"update", false, func(p *dnsExecutionFixtureProvider) int { return p.updates }},
		{"delete", true, func(p *dnsExecutionFixtureProvider) int { return p.deletes }},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.PingContext(ctx); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			resetAuthTestSchema(t, ctx, db)
			applyControlPlaneMigrations(t, ctx, db)

			desired, zone := dnsExecutionFixture(test.cleanup)
			provider := &dnsExecutionFixtureProvider{indeterminate: true}
			if test.name != "create" {
				current := desired[0].Record
				current.Value = "8.8.8.8"
				current.RecordID, current.RequestID, current.CreatedAt = "opaque-existing", "request-existing", time.Unix(1, 0).UTC()
				provider.records = []dnschange.Record{current}
				store := dnschange.NewStore(db)
				if err := store.UpsertOwned(ctx, dnschange.OwnedRecord{OwnerKey: desired[0].OwnerKey, Record: current, UpdatedAt: time.Unix(1, 0).UTC()}); err != nil {
					_ = db.Close()
					t.Fatal(err)
				}
			}
			requestDesired := desired
			if test.cleanup {
				requestDesired = nil
			}
			executor := &dnschange.Executor{Store: dnschange.NewStore(db), Provider: provider}
			key := "restart-" + test.name
			if _, err := executor.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: key, Desired: requestDesired, ManagedZone: zone}); !errors.Is(err, dnschange.ErrReconcileRequired) || test.writes(provider) != 1 {
				_ = db.Close()
				t.Fatalf("initial err=%v writes=%d", err, test.writes(provider))
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			// A fresh Store/Executor simulates process restart. The first post-
			// restart read is stale, so it must return reconciliation-required
			// without repeating the provider write.
			db, err = sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			stale := []dnschange.Record{}
			if test.name != "create" {
				current := desired[0].Record
				current.Value = "8.8.8.8"
				current.RecordID, current.RequestID, current.CreatedAt = "opaque-existing", "request-existing", time.Unix(1, 0).UTC()
				stale = []dnschange.Record{current}
			}
			provider.listResponses = [][]dnschange.Record{stale, append([]dnschange.Record(nil), provider.records...)}
			executor = &dnschange.Executor{Store: dnschange.NewStore(db), Provider: provider}
			if _, err := executor.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: key, Desired: requestDesired, ManagedZone: zone}); !errors.Is(err, dnschange.ErrReconcileRequired) || test.writes(provider) != 1 {
				t.Fatalf("stale restart replay err=%v writes=%d", err, test.writes(provider))
			}
			if test.name == "create" {
				if _, err := executor.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: key, Desired: requestDesired, ManagedZone: zone}); !errors.Is(err, dnschange.ErrReconcileRequired) || test.writes(provider) != 1 {
					t.Fatalf("create conclusive replay must not adopt unknown record err=%v writes=%d", err, test.writes(provider))
				}
				return
			}
			if result, err := executor.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: key, Desired: requestDesired, ManagedZone: zone}); err != nil || !result.Replayed || test.writes(provider) != 1 {
				t.Fatalf("conclusive replay result=%+v err=%v writes=%d", result, err, test.writes(provider))
			}
			var phase string
			if err := db.QueryRowContext(ctx, `SELECT phase FROM dns_change_execution_steps ORDER BY change_index LIMIT 1`).Scan(&phase); err != nil || phase != string(dnschange.ExecutionApplied) {
				t.Fatalf("durable phase=%q err=%v", phase, err)
			}
		})
	}
}

func TestAFBDNSExecutionClaimCASAllowsOnlyOneExecutorWrite(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAFBDNSExecutionDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, test := range []struct {
		name    string
		cleanup bool
		writes  func(*dnsExecutionFixtureProvider) int
	}{
		{"create", false, func(p *dnsExecutionFixtureProvider) int { return p.creates }},
		{"update", false, func(p *dnsExecutionFixtureProvider) int { return p.updates }},
		{"delete", true, func(p *dnsExecutionFixtureProvider) int { return p.deletes }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dbOne, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer dbOne.Close()
			if err := dbOne.PingContext(ctx); err != nil {
				t.Fatal(err)
			}
			resetAuthTestSchema(t, ctx, dbOne)
			applyControlPlaneMigrations(t, ctx, dbOne)
			desired, zone := dnsExecutionFixture(test.cleanup)
			provider := &dnsExecutionFixtureProvider{entered: make(chan struct{}, 1), release: make(chan struct{})}
			requestDesired := desired
			if test.name != "create" {
				current := desired[0].Record
				current.Value = "8.8.8.8"
				current.RecordID, current.RequestID, current.CreatedAt = "opaque-cas", "request-cas", time.Unix(1, 0).UTC()
				provider.records = []dnschange.Record{current}
				if err := dnschange.NewStore(dbOne).UpsertOwned(ctx, dnschange.OwnedRecord{OwnerKey: desired[0].OwnerKey, Record: current, UpdatedAt: time.Unix(1, 0).UTC()}); err != nil {
					t.Fatal(err)
				}
			}
			if test.cleanup {
				requestDesired = nil
			}
			dbTwo, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer dbTwo.Close()
			first := &dnschange.Executor{Store: dnschange.NewStore(dbOne), Provider: provider}
			second := &dnschange.Executor{Store: dnschange.NewStore(dbTwo), Provider: provider}
			key := "cas-" + test.name
			firstResult := make(chan error, 1)
			go func() {
				_, executeErr := first.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: key, Desired: requestDesired, ManagedZone: zone})
				firstResult <- executeErr
			}()
			select {
			case <-provider.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			secondResult := make(chan error, 1)
			go func() {
				_, executeErr := second.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: key, Desired: requestDesired, ManagedZone: zone})
				secondResult <- executeErr
			}()
			select {
			case executeErr := <-secondResult:
				if !errors.Is(executeErr, dnschange.ErrReconcileRequired) || test.writes(provider) != 1 {
					t.Fatalf("loser err=%v writes=%d", executeErr, test.writes(provider))
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			provider.release <- struct{}{}
			if executeErr := <-firstResult; executeErr != nil || test.writes(provider) != 1 {
				t.Fatalf("winner err=%v writes=%d", executeErr, test.writes(provider))
			}
		})
	}
}

func TestAFBDNSExecutionScopeBlocksDifferentPlansInSameZone(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_DNS10_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateAFBDNSExecutionDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, test := range []struct {
		name          string
		secondDesired func(dnschange.DesiredRecord) dnschange.DesiredRecord
		wantSecondNil bool
	}{
		{"same-record", func(first dnschange.DesiredRecord) dnschange.DesiredRecord { return first }, true},
		{"different-record", func(first dnschange.DesiredRecord) dnschange.DesiredRecord {
			return dnschange.DesiredRecord{OwnerKey: "acornfox:wildcard-dns01", Record: dnschange.Record{InstallationID: first.InstallationID, Provider: first.Provider, ZoneID: first.ZoneID, Domain: first.Domain, Name: "_acme-challenge.apps", Type: "TXT", Value: "challenge-different-plan", TTL: first.TTL}}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dbOne, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer dbOne.Close()
			if err := dbOne.PingContext(ctx); err != nil {
				t.Fatal(err)
			}
			resetAuthTestSchema(t, ctx, dbOne)
			applyControlPlaneMigrations(t, ctx, dbOne)
			firstDesired, zone := dnsExecutionFixture(false)
			secondDesired := test.secondDesired(firstDesired[0])
			provider := &dnsExecutionFixtureProvider{entered: make(chan struct{}, 1), release: make(chan struct{})}
			dbTwo, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer dbTwo.Close()
			first := &dnschange.Executor{Store: dnschange.NewStore(dbOne), Provider: provider}
			second := &dnschange.Executor{Store: dnschange.NewStore(dbTwo), Provider: provider}
			firstDone := make(chan error, 1)
			go func() {
				_, executeErr := first.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: "scope-first-" + test.name, Desired: firstDesired, ManagedZone: zone})
				firstDone <- executeErr
			}()
			select {
			case <-provider.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if _, err := second.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: "scope-second-" + test.name, Desired: []dnschange.DesiredRecord{secondDesired}, ManagedZone: zone}); !errors.Is(err, dnschange.ErrReconcileRequired) || provider.creates != 1 {
				t.Fatalf("different-plan loser err=%v creates=%d", err, provider.creates)
			}
			provider.release <- struct{}{}
			if err := <-firstDone; err != nil || provider.creates != 1 {
				t.Fatalf("first plan err=%v creates=%d", err, provider.creates)
			}
			var activeScopes int
			if err := dbOne.QueryRowContext(ctx, `SELECT count(*) FROM dns_change_execution_scopes`).Scan(&activeScopes); err != nil || activeScopes != 0 {
				t.Fatalf("scope should release after applied count=%d err=%v", activeScopes, err)
			}
			_, err = second.Execute(ctx, dnschange.ExecuteRequest{IdempotencyKey: "scope-second-" + test.name, Desired: []dnschange.DesiredRecord{secondDesired}, ManagedZone: zone})
			if test.wantSecondNil && err != nil {
				t.Fatalf("same record should reconcile without write err=%v", err)
			}
			if !test.wantSecondNil && !errors.Is(err, dnschange.ErrReconcileRequired) {
				t.Fatalf("different record stale plan err=%v", err)
			}
			if provider.creates != 1 {
				t.Fatalf("released scope must not revive stale plan write creates=%d", provider.creates)
			}
		})
	}
}

func dnsExecutionFixture(_ bool) ([]dnschange.DesiredRecord, dnschange.ManagedZone) {
	record := dnschange.DesiredRecord{OwnerKey: "acornfox:wildcard-a", Record: dnschange.Record{InstallationID: "install-dns10", Provider: dnschange.ProviderAlibabaCloudDNS, ZoneID: "zone/opaque:10", Domain: "example.com", Name: "*.apps", Type: "A", Value: "1.1.1.1", TTL: 600}}
	return []dnschange.DesiredRecord{record}, dnschange.ManagedZone{InstallationID: record.InstallationID, Provider: record.Provider, ZoneID: record.ZoneID, Domain: record.Domain}
}

func validateAFBDNSExecutionDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("AFB DNS execution database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "localhost" && host != "::1" {
		t.Fatal("AFB DNS execution database must be loopback")
	}
	if name := strings.TrimPrefix(parsed.Path, "/"); !strings.HasPrefix(name, "open_card_afbdns10_") {
		t.Fatal("AFB DNS execution database must be task-scoped")
	}
}
