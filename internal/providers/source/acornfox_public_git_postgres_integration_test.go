//go:build integration

package source

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type fixtureFailingPostgresRepository struct {
	*postgres.Store
	err error
}

func (r fixtureFailingPostgresRepository) CreateApplication(context.Context, application.CreateApplicationRecord) (application.CreateApplicationResult, error) {
	return application.CreateApplicationResult{}, r.err
}

func TestAcornFoxPublicGitDurablePostgresComposition(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_SRC_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_SRC_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxSourceTaskDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAcornFoxSourceTaskSchema(t, ctx, db, expectedDatabase)
	applyAcornFoxSourceMigrations(t, ctx, dsn)
	store := postgres.NewStore(db)

	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	controller := application.NewController(store)
	controller.SetSourcePreparer(fixtureApplicationSourceProvider{inner: provider, fixture: fixture})
	callerURL := "https://git.fixture.test/repo.git"
	input := &application.CreateApplicationSource{Kind: application.CreateApplicationSourceGit, RepositoryURL: callerURL, Ref: "main"}
	first, err := controller.CreateApplicationWithSource(ctx, "git-postgres-first", input, "git-postgres-first")
	if err != nil || first.SourceRevisionID.Empty() {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	firstRevision := loadAcornFoxGitRevision(t, ctx, db, first.SourceRevisionID.String())
	if firstRevision.locator != callerURL || firstRevision.ref != "main" || len(firstRevision.commit) != 40 || !strings.HasPrefix(firstRevision.digest, "sha256:") || firstRevision.workspace == "" || firstRevision.lifecycle != "prepared" {
		t.Fatalf("persisted first Git revision=%+v", firstRevision)
	}
	if contents, err := os.ReadFile(filepath.Join(firstRevision.workspace, "README.md")); err != nil || string(contents) != "fixture\n" {
		t.Fatalf("first workspace content=%q err=%v", contents, err)
	}

	fixture.advanceMain(t, "fixture v2\n")
	requestsBeforeReplay := fixture.requests.Load()
	freshProvider := fixture.provider(t)
	recreated := application.NewController(store)
	recreated.SetSourcePreparer(fixtureApplicationSourceProvider{inner: freshProvider, fixture: fixture})
	replay, err := recreated.CreateApplicationWithSource(ctx, "git-postgres-first", input, "git-postgres-first")
	if err != nil || replay.Application.ID != first.Application.ID || replay.SourceRevisionID != first.SourceRevisionID || fixture.requests.Load() != requestsBeforeReplay {
		t.Fatalf("durable replay=%+v err=%v requests=%d before=%d", replay, err, fixture.requests.Load(), requestsBeforeReplay)
	}

	next, err := recreated.CreateApplicationWithSource(ctx, "git-postgres-next", input, "git-postgres-next")
	if err != nil || next.SourceRevisionID.Empty() {
		t.Fatalf("next=%+v err=%v", next, err)
	}
	nextRevision := loadAcornFoxGitRevision(t, ctx, db, next.SourceRevisionID.String())
	if nextRevision.commit == firstRevision.commit || nextRevision.digest == firstRevision.digest || nextRevision.workspace == firstRevision.workspace || nextRevision.locator != callerURL || nextRevision.ref != "main" {
		t.Fatalf("moved main was not persisted as a distinct source revision: first=%+v next=%+v", firstRevision, nextRevision)
	}
	if contents, err := os.ReadFile(filepath.Join(nextRevision.workspace, "README.md")); err != nil || string(contents) != "fixture v2\n" {
		t.Fatalf("next workspace content=%q err=%v", contents, err)
	}
	if contents, err := os.ReadFile(filepath.Join(firstRevision.workspace, "README.md")); err != nil || string(contents) != "fixture\n" {
		t.Fatalf("first immutable workspace changed=%q err=%v", contents, err)
	}

	failureFixture := newHTTPSGitFixture(t, false)
	failureProvider := failureFixture.provider(t)
	failingController := application.NewController(fixtureFailingPostgresRepository{Store: store, err: errors.New("forced persistent create failure")})
	failingController.SetSourcePreparer(fixtureApplicationSourceProvider{inner: failureProvider, fixture: failureFixture})
	failureInput := &application.CreateApplicationSource{Kind: application.CreateApplicationSourceGit, RepositoryURL: callerURL, Ref: "main"}
	if _, err := failingController.CreateApplicationWithSource(ctx, "git-postgres-failure", failureInput, "git-postgres-failure"); err == nil || !strings.Contains(err.Error(), "forced persistent create failure") {
		t.Fatalf("failed create=%v", err)
	}
	assertRetainedGitWorkspaceWithoutTransientEntries(t, failureFixture.workspace, "fixture\n")

	// Do not Release firstRevision/nextRevision: their PostgreSQL rows still
	// reference the workspaces. The fixture's TempDir cleanup makes test trees
	// writable and removes the task-owned fixture root after assertions finish.
}

type persistedGitRevision struct {
	id            string
	applicationID string
	locator       string
	ref           string
	commit        string
	digest        string
	workspace     string
	lifecycle     string
	createdAt     time.Time
}

func loadAcornFoxGitRevision(t *testing.T, ctx context.Context, db *sql.DB, id string) persistedGitRevision {
	t.Helper()
	var result persistedGitRevision
	if err := db.QueryRowContext(ctx, `SELECT id,application_id,locator,source_ref,git_commit,content_digest,workspace_ref,workspace_lifecycle,created_at FROM source_revisions WHERE id=$1`, id).Scan(&result.id, &result.applicationID, &result.locator, &result.ref, &result.commit, &result.digest, &result.workspace, &result.lifecycle, &result.createdAt); err != nil {
		t.Fatal(err)
	}
	result.createdAt = result.createdAt.UTC()
	return result
}

func validateAcornFoxSourceTaskDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped public Git database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped public Git database must be loopback-only")
	}
	database := strings.TrimPrefix(parsed.Path, "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afbsrc_") {
		t.Fatal("task-scoped public Git database name must use open_card_afbsrc_ prefix")
	}
	return database
}

func resetAcornFoxSourceTaskSchema(t *testing.T, ctx context.Context, db *sql.DB, expectedDatabase string) {
	t.Helper()
	var currentDatabase string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&currentDatabase); err != nil || currentDatabase != expectedDatabase {
		t.Fatal("connected database does not match validated dedicated source test database")
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset validated dedicated source test schema: %v", err)
	}
}

func applyAcornFoxSourceMigrations(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate source integration test")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	command := exec.CommandContext(ctx, filepath.Join(repositoryRoot, "scripts", "mvp", "control-plane-migrate.sh"), "migrations/control-plane")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "DATABASE_URL="+dsn, "OPEN_CARD_REQUIRED_MIGRATION_VERSION=0025")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("apply task migrations: %v (%s)", err, output)
	}
}
