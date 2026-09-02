//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/dnschange"
)

type g4FixtureReader struct {
	records []dnschange.Record
	calls   int
}

func (r *g4FixtureReader) ListRecords(context.Context, string, string, string) ([]dnschange.Record, error) {
	r.calls++
	return append([]dnschange.Record(nil), r.records...), nil
}

func TestG4DNSChangeLedgerIsIdempotentAndProtectsOwnership(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4_DNS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4_DNS_TEST_DATABASE_URL is required")
	}
	validateG4DNSDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := dnschange.NewStore(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	owned := dnschange.OwnedRecord{OwnerKey: "platform:console", Record: dnschange.Record{InstallationID: "legacy-dnspod", Provider: dnschange.ProviderDNSPod, ZoneID: "7", Domain: "example.com", RecordID: "42", Name: "console", Type: "A", Value: "1.1.1.1", TTL: 600, RequestID: "req-42", CreatedAt: now}, UpdatedAt: now, LastPlanID: "seed"}
	if err := store.UpsertOwned(ctx, owned); err != nil {
		t.Fatal(err)
	}
	rewrite := owned
	rewrite.Record.ZoneID, rewrite.Record.Domain, rewrite.Record.RecordID = "8", "other.example", "99"
	if err := store.UpsertOwned(ctx, rewrite); !errors.Is(err, dnschange.ErrOwnershipConflict) {
		t.Fatalf("ownership rewrite error=%v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO dns_change_owned_records(installation_id,owner_key,provider,zone_id,domain,record_id,name,record_type,value,ttl,last_request_id,created_at,updated_at) VALUES('legacy-dnspod','x','dnspod','7','example.com','77','ingress','A','8.8.8.8',600,'req',now(),now())`); err == nil {
		t.Fatal("migration accepted invalid owner key")
	}
	desired, err := dnschange.PlatformARecords("7", "example.com", "8.8.8.8", 600)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := dnschange.BuildDryRun("g4-dry", desired, []dnschange.Record{owned.Record}, []dnschange.OwnedRecord{owned}, now)
	if err != nil {
		t.Fatal(err)
	}
	stored, replay, err := store.SavePlan(ctx, plan)
	if err != nil || replay || stored.ID != plan.ID {
		t.Fatalf("store=%+v replay=%v err=%v", stored, replay, err)
	}
	if _, replay, err := store.SavePlan(ctx, plan); err != nil || !replay {
		t.Fatalf("replay=%v err=%v", replay, err)
	}
	changed := plan
	changed.InputDigest = "sha256:" + strings.Repeat("f", 64)
	if _, _, err := store.SavePlan(ctx, changed); !errors.Is(err, dnschange.ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
	ownedRows, err := store.ListOwned(ctx, "legacy-dnspod", dnschange.ProviderDNSPod, "7")
	if err != nil || len(ownedRows) != 1 || ownedRows[0].Record.RecordID != "42" {
		t.Fatalf("owned=%+v err=%v", ownedRows, err)
	}
	if err := store.SetLastReconcile(ctx, "g4", now); err != nil {
		t.Fatal(err)
	}
	if got, err := store.LastReconcile(ctx, "g4"); err != nil || !got.Equal(now) {
		t.Fatalf("last=%v err=%v", got, err)
	}
	reconcileNow := now
	reader := &g4FixtureReader{records: []dnschange.Record{owned.Record}}
	reconciler := &dnschange.Reconciler{Store: store, Reader: reader, Desired: desired, Scope: "g4-60", Clock: func() time.Time { return reconcileNow }, Interval: time.Minute}
	first, err := reconciler.ReconcileOnce(ctx)
	if err != nil || !first.Due {
		t.Fatalf("first reconcile=%+v err=%v", first, err)
	}
	reconcileNow = reconcileNow.Add(time.Minute)
	second, err := reconciler.ReconcileOnce(ctx)
	if err != nil || !second.Due || second.Plan.ID == first.Plan.ID || reader.calls != 2 {
		t.Fatalf("second reconcile=%+v err=%v calls=%d", second, err, reader.calls)
	}
	var planCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM dns_change_plans WHERE idempotency_key LIKE 'g4-60:%'`).Scan(&planCount); err != nil || planCount != 2 {
		t.Fatalf("reconcile plans=%d err=%v", planCount, err)
	}
}

func TestG4DNSChangeProviderNeutralMigrationPreservesLegacyDNSPodRow(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4_DNS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4_DNS_TEST_DATABASE_URL is required")
	}
	validateG4DNSDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrationsBefore(t, ctx, db, "0030")
	now := time.Unix(1_700_000_000, 0).UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO dns_change_owned_records(owner_key,provider,domain_id,domain,record_id,host,record_type,value,ttl,last_request_id,created_at,updated_at,last_plan_id) VALUES('platform:console','dnspod',7,'example.com',42,'console','A','8.8.8.8',600,'legacy-request',$1,$1,'legacy-plan')`, now); err != nil {
		t.Fatalf("seed pre-0030 legacy DNSPod row: %v", err)
	}
	applyControlPlaneMigration(t, ctx, db, "0030_dns_change_provider_neutral.sql")
	store := dnschange.NewStore(db)
	rows, err := store.ListOwned(ctx, "legacy-dnspod", dnschange.ProviderDNSPod, "7")
	if err != nil || len(rows) != 1 {
		t.Fatalf("legacy owned rows=%+v err=%v", rows, err)
	}
	got := rows[0]
	if got.OwnerKey != "platform:console" || got.Record.ZoneID != "7" || got.Record.RecordID != "42" || got.Record.Name != "console" || got.Record.InstallationID != "legacy-dnspod" || got.Record.Validate(true) != nil {
		t.Fatalf("legacy ownership not preserved: %+v", got)
	}
}

func applyControlPlaneMigrationsBefore(t *testing.T, ctx context.Context, db *sql.DB, stopBefore string) {
	t.Helper()
	entries, err := os.ReadDir("../../../migrations/control-plane")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" && entry.Name()[:4] < stopBefore {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		applyControlPlaneMigration(t, ctx, db, name)
	}
}

func applyControlPlaneMigration(t *testing.T, ctx context.Context, db *sql.DB, name string) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("../../../migrations/control-plane", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(payload)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

func validateG4DNSDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("G4 DNS database URL is invalid")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("G4 DNS database must be loopback")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g4dns_") {
		t.Fatal("G4 DNS database must use open_card_g4dns_ prefix")
	}
}
