//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxAccessObservationReplayOwnerScopeAndExpiry(t *testing.T) {
	db, ctx, now, fixture := openAcornFoxAccessObservationTest(t)
	defer db.Close()
	store := NewStore(db)
	report := observedAcornFoxAccessReport(now)
	report.ObservedAt = now.Add(123456789 * time.Nanosecond)

	created, replayed, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, report, now)
	if err != nil || replayed {
		t.Fatalf("create observation=%+v replayed=%v err=%v", created, replayed, err)
	}
	if created.Observer != "administrator_client" || created.ApplicationID != fixture.applicationID.String() || created.DeploymentID != fixture.deploymentID.String() || created.Hostname != fixture.hostname || !created.ObservedAt.Equal(now.Add(123456*time.Microsecond)) || !created.ReceivedAt.Equal(now) || !created.ExpiresAt.Equal(now.Add(5*time.Minute)) || created.HTTPS.HTTPStatus == nil || *created.HTTPS.HTTPStatus != 500 {
		t.Fatalf("created observation=%+v", created)
	}
	var owner string
	if err := db.QueryRowContext(ctx, `SELECT owner_admin_id FROM acornfox_access_observations WHERE application_id=$1 AND deployment_id=$2 AND report_id=$3`, fixture.applicationID.String(), fixture.deploymentID.String(), report.ReportID).Scan(&owner); err != nil || owner != fixture.ownerAdminID.String() {
		t.Fatalf("stored owner=%q err=%v", owner, err)
	}

	reorderedReplay := report
	reorderedReplay.DNS.Addresses = []string{"1.1.1.1", "2001:db8::1"}
	replay, replayed, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, reorderedReplay, now.Add(30*time.Second))
	if err != nil || !replayed || !reflect.DeepEqual(replay, created) {
		t.Fatalf("replay observation=%+v replayed=%v err=%v want=%+v", replay, replayed, err, created)
	}
	lateReplay, replayed, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, reorderedReplay, now.Add(20*time.Minute))
	if err != nil || !replayed || !reflect.DeepEqual(lateReplay, created) {
		t.Fatalf("late replay observation=%+v replayed=%v err=%v want=%+v", lateReplay, replayed, err, created)
	}
	lateNew := reorderedReplay
	lateNew.ReportID = "access_report_late_new"
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, lateNew, now.Add(20*time.Minute)); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("new report with old observed_at err=%v", err)
	}
	changed := report
	changed.HTTPS.ResponseSampleSHA256 = "sha256:" + strings.Repeat("c", 64)
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, changed, now.Add(30*time.Second)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed payload err=%v", err)
	}
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.otherAdminID, report, now.Add(30*time.Second)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("owner mismatch err=%v", err)
	}

	current, found, err := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, now.Add(4*time.Minute))
	if err != nil || !found || !reflect.DeepEqual(current, created) {
		t.Fatalf("current observation=%+v found=%v err=%v", current, found, err)
	}
	expired, found, err := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, now.Add(6*time.Minute))
	if err != nil || !found || !reflect.DeepEqual(expired, created) {
		t.Fatalf("expired observation=%+v found=%v err=%v", expired, found, err)
	}
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, "app_other", fixture.deploymentID, fixture.ownerAdminID, report, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign application err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) SELECT 'deployment_without_public_route',environment_id,release_id,state,$2,$2 FROM deployments WHERE id=$1`, fixture.deploymentID.String(), now); err != nil {
		t.Fatal(err)
	}
	missing := report
	missing.ReportID = "missing_target"
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, "deployment_without_public_route", fixture.ownerAdminID, missing, now); !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("missing public target err=%v", err)
	}
	if _, found, err := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, "deployment_without_public_route", now); err != nil || found {
		t.Fatalf("never enabled target found=%v err=%v", found, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='disabled' WHERE id=$1`, fixture.routeID.String()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, now); err != nil || found {
		t.Fatalf("disabled target returned historical observation found=%v err=%v", found, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE acornfox_access_observations SET expires_at=expires_at + interval '1 minute' WHERE report_id=$1`, report.ReportID); err == nil {
		t.Fatal("immutable observation UPDATE was accepted")
	}
}

func TestAcornFoxAccessObservationRejectsBoundsAndObsoleteTarget(t *testing.T) {
	db, ctx, now, fixture := openAcornFoxAccessObservationTest(t)
	defer db.Close()
	store := NewStore(db)

	old := observedAcornFoxAccessReport(now.Add(-15*time.Minute - time.Microsecond))
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, old, now); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("old observed_at err=%v", err)
	}
	future := observedAcornFoxAccessReport(now.Add(time.Minute + time.Microsecond))
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, future, now); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("future observed_at err=%v", err)
	}
	invalidIP := observedAcornFoxAccessReport(now)
	invalidIP.ReportID = "invalid_ip"
	invalidIP.DNS.Addresses = []string{"2001:0db8::1"}
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, invalidIP, now); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("noncanonical IP err=%v", err)
	}
	oversized := observedAcornFoxAccessReport(now)
	oversized.ReportID = "oversized"
	oversizedBytes := 65537
	oversized.HTTPS.ResponseSampleBytes = &oversizedBytes
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, oversized, now); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("oversized sample err=%v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='disabled' WHERE id=$1`, fixture.routeID.String()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, observedAcornFoxAccessReport(now), now); !domain.IsCode(err, domain.ErrConflict) {
		t.Fatalf("obsolete target create err=%v", err)
	}
	if _, found, err := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, now); err != nil || found {
		t.Fatalf("disabled target found=%v err=%v", found, err)
	}
}

func TestAcornFoxAccessObservationSerializesAgainstTargetChange(t *testing.T) {
	db, ctx, now, fixture := openAcornFoxAccessObservationTest(t)
	defer db.Close()
	store := NewStore(db)

	blocker, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='disabled' WHERE id=$1`, fixture.routeID.String()); err != nil {
		blocker.Rollback()
		t.Fatal(err)
	}
	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		_, _, createErr := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, observedAcornFoxAccessReport(now), now)
		done <- result{err: createErr}
	}()
	select {
	case value := <-done:
		blocker.Rollback()
		t.Fatalf("create did not wait for route lock: err=%v", value.err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-done:
		if !domain.IsCode(value.err, domain.ErrConflict) {
			t.Fatalf("create after disable err=%v", value.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("create remained blocked after route transaction committed")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_access_observations`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("target race left observations=%d err=%v", count, err)
	}
}

func TestGetAcornFoxAccessObservationHoldsTargetThroughFactRead(t *testing.T) {
	db, ctx, now, fixture := openAcornFoxAccessObservationTest(t)
	defer db.Close()
	store := NewStore(db)
	created, _, err := store.CreateAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, fixture.ownerAdminID, observedAcornFoxAccessReport(now), now)
	if err != nil {
		t.Fatal(err)
	}

	// Hold only the observation table. GET can validate and lock the route
	// graph, then deterministically pauses on its fact SELECT while the disable
	// below tries to acquire the same route row.
	blocker, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(ctx, `LOCK TABLE acornfox_access_observations IN ACCESS EXCLUSIVE MODE`); err != nil {
		blocker.Rollback()
		t.Fatal(err)
	}
	type getResult struct {
		observation contracts.AcornFoxAccessObservation
		found       bool
		err         error
	}
	getDone := make(chan getResult, 1)
	go func() {
		observation, found, getErr := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, now)
		getDone <- getResult{observation: observation, found: found, err: getErr}
	}()
	waitForAcornFoxAccessObservationBlockedRead(t, ctx, db)

	disableDone := make(chan error, 1)
	go func() {
		_, disableErr := db.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='disabled' WHERE id=$1`, fixture.routeID.String())
		disableDone <- disableErr
	}()
	select {
	case disableErr := <-disableDone:
		blocker.Rollback()
		t.Fatalf("disable crossed GET target lock: err=%v", disableErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-getDone:
		if result.err != nil || !result.found || !reflect.DeepEqual(result.observation, created) {
			t.Fatalf("locked GET observation=%+v found=%v err=%v", result.observation, result.found, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GET remained blocked after observation table lock was released")
	}
	select {
	case err := <-disableDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disable remained blocked after GET committed")
	}
	if _, found, err := store.GetCurrentAcornFoxAccessObservation(ctx, fixture.applicationID, fixture.deploymentID, now); err != nil || found {
		t.Fatalf("disabled route returned observation found=%v err=%v", found, err)
	}
}

func waitForAcornFoxAccessObservationBlockedRead(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			 WHERE pid <> pg_backend_pid()
			   AND wait_event_type = 'Lock'
			   AND query LIKE 'SELECT report_id,hostname,observed_at,received_at,expires_at,dns,tls,https,report_digest,owner_admin_id FROM acornfox_access_observations%'
		)`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	blockerCount := 0
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock'`).Scan(&blockerCount)
	t.Fatalf("GET did not reach blocked observation read; blocked sessions=%d", blockerCount)
}

type acornFoxAccessObservationFixture struct {
	applicationID, deploymentID, ownerAdminID, otherAdminID, routeID domain.ID
	hostname                                                         string
}

func openAcornFoxAccessObservationTest(t *testing.T) (*sql.DB, context.Context, time.Time, acornFoxAccessObservationFixture) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_ACCESS_OBSERVATION_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_ACCESS_OBSERVATION_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expected := validateAcornFoxAccessObservationDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatal(err)
	}
	resetAcornFoxSourceMetadataSchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1_700_800_000, 0).UTC()
	probe := insertAcornFoxProbeFixture(t, ctx, db, now)
	fixture := acornFoxAccessObservationFixture{
		applicationID: domain.ID(probe.applicationID), deploymentID: domain.ID(probe.deploymentID),
		ownerAdminID: "admin_access_owner", otherAdminID: "admin_access_other",
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO admin_credentials(id,password_hash_scheme,password_hash,credential_version,disabled_at,created_at,updated_at) VALUES($1,'argon2id-v1',$2,1,NULL,$3,$3),($4,'argon2id-v1',$2,1,$3,$3,$3)`, fixture.ownerAdminID.String(), "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZGlnaWVzdA", now, fixture.otherAdminID.String()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	fixture.routeID = afpaID("route", fixture.applicationID.String(), fixture.deploymentID.String())
	fixture.hostname, err = contracts.AcornFoxPublicHostname("example.test", fixture.applicationID, fixture.deploymentID)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	intent := contracts.AcornFoxPublicRouteIntent{ApplicationID: fixture.applicationID, DeploymentID: fixture.deploymentID, Hostname: fixture.hostname, ServiceName: "web", Port: 18080}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := afpaPersistEnabled(ctx, tx, intent, fixture.routeID, now); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO acornfox_public_access_commands(application_id,deployment_id,idempotency_key,request_digest,requested_enabled,route_id,phase,result_status,result_hostname,created_at,updated_at) VALUES($1,$2,'access-enabled',$3,true,$4,'completed','PENDING_EXTERNAL_VALIDATION',$5,$6,$6)`, fixture.applicationID.String(), fixture.deploymentID.String(), "sha256:"+strings.Repeat("a", 64), fixture.routeID.String(), fixture.hostname, now); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, ctx, now, fixture
}

func validateAcornFoxAccessObservationDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" && parsed.Hostname() != "localhost") {
		t.Fatal("task-scoped AcornFox access observation database URL is invalid")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afbsourcemeta_accessobs_") {
		t.Fatal("task-scoped AcornFox access observation database name is invalid")
	}
	return database
}

func observedAcornFoxAccessReport(now time.Time) contracts.AcornFoxAccessObservationReport {
	status := 500
	sampleBytes := 65536
	truncated := true
	return contracts.AcornFoxAccessObservationReport{
		ReportID: "access_report_0123456789abcdef0123456789abcdef", ObservedAt: now,
		DNS:   contracts.AcornFoxAccessDNSReport{State: contracts.AcornFoxAccessObserved, Addresses: []string{"2001:db8::1", "1.1.1.1"}},
		TLS:   contracts.AcornFoxAccessTLSReport{State: contracts.AcornFoxAccessObserved, CertificateSHA256: "sha256:" + strings.Repeat("b", 64)},
		HTTPS: contracts.AcornFoxAccessHTTPSReport{State: contracts.AcornFoxAccessObserved, HTTPStatus: &status, ResponseSampleSHA256: "sha256:" + strings.Repeat("a", 64), ResponseSampleBytes: &sampleBytes, ResponseTruncated: &truncated},
	}
}
