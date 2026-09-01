//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/source"
)

type countingSourceProvider struct {
	contracts.SourceProvider
	mu       sync.Mutex
	prepares int
}

type postgresGitSourcePreparer struct {
	mu       sync.Mutex
	prepares int
}

func (*postgresGitSourcePreparer) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "postgres-git-source", Version: "test", ContractVersion: contracts.ContractAPIVersion}
}

func (p *postgresGitSourcePreparer) Prepare(_ context.Context, request contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	p.mu.Lock()
	p.prepares++
	p.mu.Unlock()
	revision, err := domain.NewSourceRevision(request.ApplicationID, request.Kind, request.Locator, request.Ref, strings.Repeat("d", 40), "sha256:"+strings.Repeat("e", 64), "memory://postgres-git-workspace", time.Now().UTC())
	if err != nil {
		return contracts.PrepareSourceResult{}, err
	}
	return contracts.PrepareSourceResult{Revision: revision}, nil
}

func (*postgresGitSourcePreparer) Release(context.Context, contracts.ReleaseSourceRequest) error {
	return nil
}

func (p *postgresGitSourcePreparer) prepareCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prepares
}

func (p *countingSourceProvider) Prepare(ctx context.Context, request contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	p.mu.Lock()
	p.prepares++
	p.mu.Unlock()
	return p.SourceProvider.Prepare(ctx, request)
}

func (p *countingSourceProvider) prepareCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prepares
}

func TestG3SourceUploadPersistsAndApplicationClaimIsAtomic(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G3_UPLOAD_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G3_UPLOAD_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG3UploadDSN(t, dsn)
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

	store := NewStore(db)
	now := time.Unix(1_700_000_000, 0).UTC()
	store.SetClock(func() time.Time { return now })
	upload := domain.SourceUploadRecord{ID: "upload_claim", Kind: domain.SourceUploadDirectory, Status: domain.SourceUploadReady, Digest: "sha256:" + strings.Repeat("a", 64), Bytes: 4, FileCount: 1, StorageRef: "upload://upload_claim", ExpiresAt: time.Now().UTC().Add(24 * time.Hour), IdempotencyKey: "upload-key", RequestDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: now, UpdatedAt: now, Files: []domain.SourceUploadFile{{Path: "src/main.go", Bytes: 4, Digest: "sha256:" + strings.Repeat("b", 64)}}}
	stored, replay, err := store.CreateSourceUpload(ctx, upload)
	if err != nil || replay || stored.ID != upload.ID {
		t.Fatalf("create upload=%+v replay=%v err=%v", stored, replay, err)
	}
	if replayed, replay, err := store.CreateSourceUpload(ctx, upload); err != nil || !replay || replayed.ID != upload.ID {
		t.Fatalf("replay upload=%+v replay=%v err=%v", replayed, replay, err)
	}
	conflict := upload
	conflict.Digest, conflict.RequestDigest = "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("c", 64)
	if _, _, err := store.CreateSourceUpload(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("upload idempotency conflict=%v", err)
	}
	var concurrent sync.WaitGroup
	concurrentErrors := make(chan error, 2)
	for _, id := range []domain.ID{"upload_concurrent_a", "upload_concurrent_b"} {
		concurrent.Add(1)
		go func(id domain.ID) {
			defer concurrent.Done()
			candidate := domain.SourceUploadRecord{ID: id, Kind: domain.SourceUploadArchive, Status: domain.SourceUploadReady, Digest: "sha256:" + strings.Repeat("9", 64), Bytes: 1, FileCount: 1, StorageRef: "upload://" + id.String(), ExpiresAt: time.Now().UTC().Add(time.Hour), IdempotencyKey: "upload-concurrent", RequestDigest: "sha256:" + strings.Repeat("9", 64), CreatedAt: now, UpdatedAt: now, Files: []domain.SourceUploadFile{{Path: "archive.zip", Bytes: 1, Digest: "sha256:" + strings.Repeat("8", 64)}}}
			_, _, err := store.CreateSourceUpload(context.Background(), candidate)
			concurrentErrors <- err
		}(id)
	}
	concurrent.Wait()
	close(concurrentErrors)
	for err := range concurrentErrors {
		if err != nil {
			t.Fatalf("concurrent upload error=%v", err)
		}
	}
	var concurrentCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM source_uploads WHERE idempotency_key='upload-concurrent'`).Scan(&concurrentCount); err != nil || concurrentCount != 1 {
		t.Fatalf("concurrent upload count=%d err=%v", concurrentCount, err)
	}
	expired := domain.SourceUploadRecord{ID: "upload_expired", Kind: domain.SourceUploadArchive, Status: domain.SourceUploadReady, Digest: "sha256:" + strings.Repeat("e", 64), Bytes: 1, FileCount: 1, StorageRef: "upload://upload_expired", ExpiresAt: now.Add(-time.Minute), IdempotencyKey: "upload-expired", RequestDigest: "sha256:" + strings.Repeat("e", 64), CreatedAt: now.Add(-2 * time.Minute), UpdatedAt: now.Add(-2 * time.Minute), Files: []domain.SourceUploadFile{{Path: "archive.zip", Bytes: 1, Digest: "sha256:" + strings.Repeat("f", 64)}}}
	if _, _, err := store.CreateSourceUpload(ctx, expired); err != nil {
		t.Fatal(err)
	}
	candidates, err := store.ListSourceUploadCleanupCandidates(ctx, now, 10)
	if err != nil || len(candidates) != 1 || candidates[0].ID != expired.ID {
		t.Fatalf("cleanup candidates=%+v err=%v", candidates, err)
	}
	if marked, err := store.MarkSourceUploadExpired(ctx, expired.ID, now); err != nil || !marked {
		t.Fatalf("mark expired=%v err=%v", marked, err)
	}
	if err := store.DeleteExpiredSourceUpload(ctx, expired.ID); err != nil {
		t.Fatal(err)
	}

	uploadRoot := t.TempDir()
	filesRoot := filepath.Join(uploadRoot, upload.ID.String(), "files", "src")
	if err := os.MkdirAll(filesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filesRoot, "main.go"), []byte("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceProvider, err := source.New(source.Config{UploadRoot: uploadRoot, WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces")})
	if err != nil {
		t.Fatal(err)
	}
	preparer := &countingSourceProvider{SourceProvider: sourceProvider}
	controller := application.NewController(store)
	controller.SetSourcePreparer(preparer)
	source := &application.CreateApplicationSource{Kind: application.CreateApplicationSourceUpload, UploadID: upload.ID}
	created, err := controller.CreateApplicationWithSource(ctx, "upload-backed", source, "create-upload")
	if err != nil || created.SourceRevisionID.Empty() {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	claimed, err := store.GetSourceUpload(ctx, upload.ID)
	if err != nil || claimed.Status != domain.SourceUploadClaimed || claimed.ClaimedApplicationID != created.Application.ID || claimed.ClaimedSourceID != created.SourceRevisionID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	var locator, workspace, contentDigest string
	if err := db.QueryRowContext(ctx, `SELECT locator,workspace_ref,content_digest FROM source_revisions WHERE id=$1`, created.SourceRevisionID.String()).Scan(&locator, &workspace, &contentDigest); err != nil || locator != "upload://upload_claim" || workspace == "" || !strings.HasPrefix(contentDigest, "sha256:") {
		t.Fatalf("source revision locator=%q workspace=%q err=%v", locator, workspace, err)
	}
	t.Cleanup(func() {
		revision := domain.SourceRevision{ID: created.SourceRevisionID, ApplicationID: created.Application.ID, Kind: domain.SourceUpload, Locator: locator, ContentDigest: contentDigest, WorkspaceRef: workspace, Immutable: true}
		if err := sourceProvider.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: revision, Operation: contracts.OperationContext{IdempotencyKey: "release-g3-upload-test", Actor: "test"}}); err != nil {
			t.Errorf("release temporary prepared source: %v", err)
		}
	})
	if lifecycle, err := store.GetSourceWorkspaceLifecycle(ctx, created.SourceRevisionID); err != nil || lifecycle != WorkspacePrepared {
		t.Fatalf("source workspace lifecycle=%q err=%v", lifecycle, err)
	}
	if replayed, err := controller.CreateApplicationWithSource(ctx, "upload-backed", source, "create-upload"); err != nil || replayed.Application.ID != created.Application.ID || replayed.SourceRevisionID != created.SourceRevisionID {
		t.Fatalf("create replay=%+v err=%v", replayed, err)
	}
	if prepares := preparer.prepareCount(); prepares != 1 {
		t.Fatalf("idempotent replay repeated source preparation %d times", prepares)
	}
	if _, err := controller.CreateApplicationWithSource(ctx, "second-consumer", source, "create-upload-second"); !errors.Is(err, domain.ErrSourceUploadClaimed) {
		t.Fatalf("second claim=%v", err)
	}
	var applicationCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM applications`).Scan(&applicationCount); err != nil || applicationCount != 1 {
		t.Fatalf("atomic claim application count=%d err=%v", applicationCount, err)
	}

	gitPreparer := &postgresGitSourcePreparer{}
	gitController := application.NewController(store)
	gitController.SetSourcePreparer(gitPreparer)
	gitSource := &application.CreateApplicationSource{Kind: application.CreateApplicationSourceGit, RepositoryURL: "https://git.public.org/project/repo.git", Ref: "main"}
	gitCreated, err := gitController.CreateApplicationWithSource(ctx, "git-backed", gitSource, "create-git")
	if err != nil || gitCreated.SourceRevisionID.Empty() {
		t.Fatalf("Git create=%+v err=%v", gitCreated, err)
	}
	var provider, commit, sourceRef, lifecycle string
	if err := db.QueryRowContext(ctx, `SELECT provider,git_commit,source_ref,workspace_lifecycle FROM source_revisions WHERE id=$1`, gitCreated.SourceRevisionID.String()).Scan(&provider, &commit, &sourceRef, &lifecycle); err != nil || provider != "git" || commit != strings.Repeat("d", 40) || sourceRef != "main" || lifecycle != string(WorkspacePrepared) {
		t.Fatalf("Git source persistence provider=%q commit=%q ref=%q lifecycle=%q err=%v", provider, commit, sourceRef, lifecycle, err)
	}
	freshGitPreparer := &postgresGitSourcePreparer{}
	recreatedGitController := application.NewController(store)
	recreatedGitController.SetSourcePreparer(freshGitPreparer)
	if replayed, err := recreatedGitController.CreateApplicationWithSource(ctx, "git-backed", gitSource, "create-git"); err != nil || replayed.Application.ID != gitCreated.Application.ID || replayed.SourceRevisionID != gitCreated.SourceRevisionID || gitPreparer.prepareCount() != 1 || freshGitPreparer.prepareCount() != 0 {
		t.Fatalf("durable Git replay=%+v err=%v original_prepares=%d fresh_prepares=%d", replayed, err, gitPreparer.prepareCount(), freshGitPreparer.prepareCount())
	}
	if _, err := gitController.CreateApplicationWithSource(ctx, "git-backed", &application.CreateApplicationSource{Kind: application.CreateApplicationSourceGit, RepositoryURL: gitSource.RepositoryURL, Ref: "release"}, "create-git"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Git idempotency conflict=%v", err)
	}
}

func validateG3UploadDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped G3 upload database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped G3 upload database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g3upload_") {
		t.Fatal("task-scoped G3 upload database name must use open_card_g3upload_ prefix")
	}
}
