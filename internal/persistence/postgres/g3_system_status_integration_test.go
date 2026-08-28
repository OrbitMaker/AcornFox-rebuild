//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestG3SystemStatusWebhookAggregateUsesTaskPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G3D_STATUS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G3D_STATUS_TEST_DATABASE_URL is required")
	}
	validateG3DStatusDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := NewStore(db)
	count, err := store.CountEnabledWebhookEndpoints(ctx)
	if err != nil || count != 0 {
		t.Fatalf("empty count=%d err=%v", count, err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO applications(id,name,version,created_at,updated_at) VALUES('app_status','status fixture',1,now(),now())`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO m4_webhook_endpoints(id,application_id,endpoint_url,secret_reference_id,secret_name,secret_provider,secret_version,event_types,enabled,created_at,updated_at) VALUES('status_hook','app_status','https://receiver.example.test/hook','secret_status','webhook','fixture','v1','[]'::jsonb,true,now(),now()),('status_disabled','app_status','https://receiver.example.test/disabled','secret_disabled','webhook','fixture','v1','[]'::jsonb,false,now(),now())`)
	if err != nil {
		t.Fatal(err)
	}
	count, err = store.CountEnabledWebhookEndpoints(ctx)
	if err != nil || count != 1 {
		t.Fatalf("enabled count=%d err=%v", count, err)
	}
}

func validateG3DStatusDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("G3D status database URL is invalid")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("G3D status database must be loopback")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g3d_") {
		t.Fatal("G3D status database must use open_card_g3d_ prefix")
	}
}
