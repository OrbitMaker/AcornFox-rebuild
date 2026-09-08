//go:build integration

package main

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestCandidateBuildLogSinkAvoidsNormalBuildLedgerDependency(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_CANDIDATE_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_CANDIDATE_TEST_DATABASE_URL is required")
	}
	validateCandidateBuildLogDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	acornFoxLogsIntegrationMigrations(t, ctx, db)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_candidate','candidate',now(),now())`); err != nil {
		t.Fatal(err)
	}
	request := candidateBuildLogRequestFixture()
	productionLogs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: t.TempDir(), MaxFileBytes: 1024, MaxTotalBytes: 8192, MaxBuildFiles: 4})
	if err != nil {
		t.Fatal(err)
	}
	production := &m4BuildLogSink{store: postgres.NewStore(db), logs: productionLogs}
	if _, err := production.StoreBuildLog(ctx, request, "candidate build passed\n"); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("production sink accepted build without ledger fact: %v", err)
	}
	candidateLogs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: t.TempDir(), MaxFileBytes: 1024, MaxTotalBytes: 8192, MaxBuildFiles: 4})
	if err != nil {
		t.Fatal(err)
	}
	candidate := &acornFoxCandidateBuildLogSink{logs: candidateLogs}
	ref, err := candidate.StoreBuildLog(ctx, request, "candidate build passed\n")
	if err != nil || !strings.HasPrefix(ref, "candidate-log://"+request.Source.ID.String()+"/sha256:") {
		t.Fatalf("candidate ref=%q err=%v", ref, err)
	}
	stored, err := candidateLogs.Read(observability.LogCategoryBuild, "candidate-"+request.Source.ID.String())
	if err != nil || string(stored) != "candidate build passed\n" {
		t.Fatalf("stored=%q err=%v", stored, err)
	}
	for _, table := range []string{"build_plans", "builds", "m4_log_indexes"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("table=%s count=%d err=%v", table, count, err)
		}
	}

	delegate := contracts.NewFakeImageStore(true)
	firstGate := postgresAcornFoxImageMutationGate{db: db, delegate: delegate}
	secondGate := postgresAcornFoxImageMutationGate{db: db, delegate: delegate}
	firstEntered, releaseFirst, secondEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		firstDone <- firstGate.With(ctx, func(contracts.ImageStore) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered
	go func() {
		secondDone <- secondGate.With(ctx, func(contracts.ImageStore) error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second image mutation entered while the PostgreSQL gate was held")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second image mutation did not enter after gate release")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}

	sourceDigest := "sha256:" + strings.Repeat("b", 64)
	image, _ := domain.ParseImageDigest("acornfox.local/apps", "sha256:"+strings.Repeat("c", 64))
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,content_digest,source_kind,locator,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_normal_build','app_candidate','upload',$1,'upload','upload://normal','/immutable/normal','prepared',true,now())`, sourceDigest); err != nil {
		t.Fatal(err)
	}
	store := postgres.NewStore(db)
	plan := domain.BuildPlan{ID: "plan_normal_active", SourceRevisionID: "src_normal_build", SourceDigest: sourceDigest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: image.Repository, Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "normal-active"}, IdempotencyKey: "normal-active", CreatedAt: time.Now().UTC()}
	if _, err := store.CreateBuildPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateBuild(ctx, domain.Build{ID: "build_normal_active", PlanID: plan.ID, Status: domain.BuildPending, CreatedAt: plan.CreatedAt, UpdatedAt: plan.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	guard := postgresAcornFoxCandidateImageGuard{store: store}
	if disposition, err := guard.Disposition(ctx, request.Source.ID, image); err != nil || disposition != acornFoxCandidateImageWait {
		t.Fatalf("active normal build disposition=%q err=%v", disposition, err)
	}
}

func validateCandidateBuildLogDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1") || !strings.HasPrefix(strings.TrimPrefix(parsed.EscapedPath(), "/"), "open_card_afbcandidate_") {
		t.Fatal("candidate test database URL is invalid")
	}
}
