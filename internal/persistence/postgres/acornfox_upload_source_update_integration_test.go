//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/source"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcornFoxUploadedSourceUpdateClaimReplayAndSharedWorkspace(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G3_UPLOAD_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("task PostgreSQL required")
	}
	validateG3UploadDSN(t, dsn)
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
	now := time.Now().UTC()
	store.SetClock(func() time.Time { return now })
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	workspaceRoot := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.WalkDir(workspaceRoot, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error("restore owned test-directory permissions", err)
		}
	})
	provider, err := source.New(source.Config{UploadRoot: root, WorkspaceRoot: workspaceRoot})
	if err != nil {
		t.Fatal(err)
	}
	upload := func(id, content string) domain.SourceUploadRecord {
		path := filepath.Join(root, id, "files")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "Dockerfile"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		digest := "sha256:" + hex.EncodeToString(sum[:])
		requestSum := sha256.Sum256([]byte(id))
		record := domain.SourceUploadRecord{ID: domain.ID(id), Kind: domain.SourceUploadDirectory, Status: domain.SourceUploadReady, Digest: digest, Bytes: int64(len(content)), FileCount: 1, StorageRef: "upload://" + id, ExpiresAt: now.Add(time.Hour), IdempotencyKey: id, RequestDigest: "sha256:" + hex.EncodeToString(requestSum[:]), CreatedAt: now, UpdatedAt: now, Files: []domain.SourceUploadFile{{Path: "Dockerfile", Bytes: int64(len(content)), Digest: digest}}}
		if _, _, err := store.CreateSourceUpload(ctx, record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	baseUpload := upload("upload_local_base", "FROM scratch\nEXPOSE 8080\n")
	controller := application.NewController(store)
	controller.SetSourcePreparer(provider)
	app, err := controller.CreateApplicationWithSource(ctx, "local-update", &application.CreateApplicationSource{Kind: application.CreateApplicationSourceUpload, UploadID: baseUpload.ID}, "local-base")
	if err != nil {
		t.Fatal(err)
	}
	base, err := store.GetAcornFoxSourceRevision(ctx, app.Application.ID, app.SourceRevisionID)
	if err != nil {
		t.Fatal(err)
	}
	service := &application.AcornFoxSourceUpdateService{Store: store, Preparer: provider, Clock: func() time.Time { return now }}
	updatedUpload := upload("upload_local_next", "FROM scratch\nEXPOSE 9090\n")
	request := application.AcornFoxSourceUpdateRequest{ApplicationID: app.Application.ID, BaseSourceRevisionID: base.ID, UploadID: updatedUpload.ID, IdempotencyKey: "update-local"}
	updated, err := service.Update(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.GetAcornFoxSourceRevision(ctx, app.Application.ID, updated.SourceRevisionID)
	if err != nil || revision.Kind != domain.SourceUpload || revision.Ref != updatedUpload.ID.String() || revision.Commit != "" {
		t.Fatal("uploaded update not discoverable", err)
	}
	record, err := store.GetSourceUpload(ctx, updatedUpload.ID)
	if err != nil || record.Status != domain.SourceUploadClaimed || record.ClaimedApplicationID != app.Application.ID || record.ClaimedSourceID != revision.ID {
		t.Fatal("upload was not claimed atomically", err)
	}
	replay, err := service.Update(ctx, request)
	if err != nil || replay != updated {
		t.Fatal("claimed upload replay failed", err)
	}
	changed := request
	changed.UploadID = baseUpload.ID
	if _, err := service.Update(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("same key changed upload", err)
	}
	foreign := request
	foreign.ApplicationID = "app_foreign"
	foreign.IdempotencyKey = "foreign"
	if _, err := service.Update(ctx, foreign); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-app base accepted", err)
	}
	// Duplicate content shares the immutable workspace. A failed insert must not
	// delete the directory that the earlier accepted revision still references.
	same := upload("upload_local_duplicate", "FROM scratch\nEXPOSE 8080\n")
	failed := application.AcornFoxSourceUpdateRequest{ApplicationID: app.Application.ID, BaseSourceRevisionID: revision.ID, UploadID: same.ID, IdempotencyKey: "same-tree-fails"}
	originalNow := now
	service.Preparer = uploadUpdateAfterPrepare{provider, func() { now = now.Add(2 * time.Hour) }}
	if _, err := service.Update(ctx, failed); err == nil {
		t.Fatal("expired update unexpectedly completed")
	}
	now = originalNow
	service.Preparer = provider
	content, err := os.ReadFile(filepath.Join(base.WorkspaceRef, "Dockerfile"))
	if err != nil || string(content) != "FROM scratch\nEXPOSE 8080\n" {
		t.Fatal("failed update deleted shared workspace", err)
	}
	if _, err := store.GetAcornFoxSourceRevision(ctx, app.Application.ID, base.ID); err != nil {
		t.Fatal("accepted base became unreadable", err)
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT state FROM acornfox_source_updates WHERE application_id=$1 AND idempotency_key='same-tree-fails'`, app.Application.ID.String()).Scan(&state); err != nil || state != "failed" {
		t.Fatal("failed update not recorded", err)
	}
	unclaimed, err := store.GetSourceUpload(ctx, same.ID)
	if err != nil || unclaimed.Status != domain.SourceUploadReady {
		t.Fatal("failed update partially claimed upload", err)
	}
	failed.IdempotencyKey = "same-tree-retry"
	reused, err := service.Update(ctx, failed)
	if err != nil || reused.SourceRevisionID != base.ID {
		t.Fatal("unchanged uploaded project did not reuse existing source", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM applications`).Scan(&count); err != nil || count != 1 {
		t.Fatal("source update created another application", err)
	}
	t.Log("LOCAL_UPLOAD_UPDATE_PASS application identity retained; update and claim atomic; replay stable; foreign base rejected; shared workspace preserved on failure")
}

type uploadUpdateAfterPrepare struct {
	contracts.SourceProvider
	after func()
}

func (p uploadUpdateAfterPrepare) Prepare(ctx context.Context, request contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	result, err := p.SourceProvider.Prepare(ctx, request)
	if err == nil {
		p.after()
	}
	return result, err
}
