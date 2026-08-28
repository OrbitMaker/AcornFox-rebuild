package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/source"
)

type testSourcePreparer struct {
	mu       sync.Mutex
	prepares int
	releases int
}

func (*testSourcePreparer) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "test-source", Version: "1", ContractVersion: contracts.ContractAPIVersion}
}

func (p *testSourcePreparer) Prepare(_ context.Context, request contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	p.mu.Lock()
	p.prepares++
	p.mu.Unlock()
	revision, err := domain.NewSourceRevision(request.ApplicationID, request.Kind, request.Locator, request.Ref, "", "sha256:"+strings.Repeat("c", 64), "memory://source-workspace", time.Now().UTC())
	if err != nil {
		return contracts.PrepareSourceResult{}, err
	}
	return contracts.PrepareSourceResult{Revision: revision}, nil
}

func (p *testSourcePreparer) Release(context.Context, contracts.ReleaseSourceRequest) error {
	p.mu.Lock()
	p.releases++
	p.mu.Unlock()
	return nil
}

func (p *testSourcePreparer) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prepares, p.releases
}

type failingCreateRepository struct {
	*MemoryRepository
	err error
}

func (r failingCreateRepository) CreateApplication(context.Context, CreateApplicationRecord) (CreateApplicationResult, error) {
	return CreateApplicationResult{}, r.err
}

func TestControllerCreateIsIdempotentAndReplayable(t *testing.T) {
	repository := NewMemoryRepository()
	controller := NewController(repository)
	controller.SetSourcePreparer(&testSourcePreparer{})
	first, err := controller.CreateApplication(context.Background(), "demo", "create-demo")
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.CreateApplication(context.Background(), "demo", "create-demo")
	if err != nil {
		t.Fatal(err)
	}
	if first.Application.ID != second.Application.ID || first.OperationID != second.OperationID || first.Event.Sequence != second.Event.Sequence {
		t.Fatalf("idempotent retry changed result: %#v %#v", first, second)
	}
	events, err := controller.ListEvents(context.Background(), first.OperationID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID == "" || events[0].OperationID != first.OperationID.String() {
		t.Fatalf("persistent replay did not return the operation event: %#v", events)
	}
	after, err := controller.ListEvents(context.Background(), first.OperationID.String(), events[0].Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("replay returned an already acknowledged event: %#v", after)
	}
}

func TestControllerRejectsIdempotencyKeyReuseWithDifferentInput(t *testing.T) {
	controller := NewController(NewMemoryRepository())
	if _, err := controller.CreateApplication(context.Background(), "one", "same-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.CreateApplication(context.Background(), "two", "same-key"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestControllerCreateWithUploadCarriesImmutableSourceRevision(t *testing.T) {
	repository := NewMemoryRepository()
	now := time.Now().UTC()
	if err := repository.RegisterSourceUpload(domain.SourceUploadRecord{ID: "upload_1", Kind: domain.SourceUploadDirectory, Status: domain.SourceUploadReady, Digest: "sha256:" + strings.Repeat("a", 64), Bytes: 1, FileCount: 1, StorageRef: "upload://upload_1", ExpiresAt: now.Add(time.Hour), IdempotencyKey: "upload_1", RequestDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: now, UpdatedAt: now, Files: []domain.SourceUploadFile{{Path: "src/main.go", Bytes: 1, Digest: "sha256:" + strings.Repeat("b", 64)}}}); err != nil {
		t.Fatal(err)
	}
	controller := NewController(repository)
	preparer := &testSourcePreparer{}
	controller.SetSourcePreparer(preparer)
	source := &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: "upload_1"}
	first, err := controller.CreateApplicationWithSource(context.Background(), "upload app", source, "upload-create")
	if err != nil || first.SourceRevisionID.Empty() {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replay, err := controller.CreateApplicationWithSource(context.Background(), "upload app", source, "upload-create")
	if err != nil || replay.Application.ID != first.Application.ID || replay.SourceRevisionID != first.SourceRevisionID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if prepares, releases := preparer.counts(); prepares != 1 || releases != 0 {
		t.Fatalf("idempotent upload repeated source preparation: prepares=%d releases=%d", prepares, releases)
	}
	changed := &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: "upload_2"}
	if _, err := controller.CreateApplicationWithSource(context.Background(), "upload app", changed, "upload-create"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed source idempotency error=%v", err)
	}
}

func TestControllerPreflightRejectsExpiredOrClaimedUploadBeforePreparation(t *testing.T) {
	now := time.Now().UTC()
	repository := NewMemoryRepository()
	expired := testReadyUpload("upload_expired", now.Add(-time.Hour))
	expired.CreatedAt = now.Add(-2 * time.Hour)
	expired.UpdatedAt = expired.CreatedAt
	if err := repository.RegisterSourceUpload(expired); err != nil {
		t.Fatal(err)
	}
	preparer := &testSourcePreparer{}
	controller := NewController(repository)
	controller.SetSourcePreparer(preparer)
	if _, err := controller.CreateApplicationWithSource(context.Background(), "expired", &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: expired.ID}, "expired-create"); err == nil {
		t.Fatal("expected expired upload rejection")
	}
	if prepares, _ := preparer.counts(); prepares != 0 {
		t.Fatalf("expired upload was materialized %d times", prepares)
	}

	ready := testReadyUpload("upload_claimed", now.Add(time.Hour))
	if err := repository.RegisterSourceUpload(ready); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.CreateApplicationWithSource(context.Background(), "first", &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: ready.ID}, "claimed-first"); err != nil {
		t.Fatal(err)
	}
	preparedBefore, _ := preparer.counts()
	if _, err := controller.CreateApplicationWithSource(context.Background(), "second", &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: ready.ID}, "claimed-second"); !errors.Is(err, domain.ErrSourceUploadClaimed) {
		t.Fatalf("claimed upload error=%v", err)
	}
	if prepares, _ := preparer.counts(); prepares != preparedBefore {
		t.Fatalf("claimed upload was materialized again: before=%d after=%d", preparedBefore, prepares)
	}
}

func TestControllerConcurrentUploadReplayPreparesOnlyOnce(t *testing.T) {
	now := time.Now().UTC()
	repository := NewMemoryRepository()
	upload := testReadyUpload("upload_concurrent", now.Add(time.Hour))
	if err := repository.RegisterSourceUpload(upload); err != nil {
		t.Fatal(err)
	}
	preparer := &testSourcePreparer{}
	controller := NewController(repository)
	controller.SetSourcePreparer(preparer)
	results := make(chan CreateApplicationResult, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := controller.CreateApplicationWithSource(context.Background(), "concurrent", &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: upload.ID}, "concurrent-upload")
			results <- result
			errors <- err
		}()
	}
	var first CreateApplicationResult
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		result := <-results
		if first.Application.ID.Empty() {
			first = result
		} else if result.Application.ID != first.Application.ID || result.SourceRevisionID != first.SourceRevisionID {
			t.Fatalf("concurrent replay diverged: first=%+v result=%+v", first, result)
		}
	}
	if prepares, releases := preparer.counts(); prepares != 1 || releases != 0 {
		t.Fatalf("concurrent upload source side effect: prepares=%d releases=%d", prepares, releases)
	}
}

func TestControllerCompensatesFailedSourceCreateWithoutWorkspaceOrphan(t *testing.T) {
	now := time.Now().UTC()
	base := NewMemoryRepository()
	upload := testReadyUpload("upload_cleanup", now.Add(time.Hour))
	if err := base.RegisterSourceUpload(upload); err != nil {
		t.Fatal(err)
	}
	uploadRoot := t.TempDir()
	filesRoot := filepath.Join(uploadRoot, upload.ID.String(), "files")
	if err := os.MkdirAll(filesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filesRoot, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspaceRoot := filepath.Join(t.TempDir(), "workspaces")
	provider, err := source.New(source.Config{UploadRoot: uploadRoot, WorkspaceRoot: workspaceRoot})
	if err != nil {
		t.Fatal(err)
	}
	createFailure := errors.New("forced application transaction failure")
	controller := NewController(failingCreateRepository{MemoryRepository: base, err: createFailure})
	controller.SetSourcePreparer(provider)
	if _, err := controller.CreateApplicationWithSource(context.Background(), "cleanup", &CreateApplicationSource{Kind: CreateApplicationSourceUpload, UploadID: upload.ID}, "cleanup-failure"); !errors.Is(err, createFailure) {
		t.Fatalf("create failure=%v", err)
	}
	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed source create left workspace entries: %#v", entries)
	}
}

func testReadyUpload(id domain.ID, expiresAt time.Time) domain.SourceUploadRecord {
	now := time.Now().UTC()
	return domain.SourceUploadRecord{ID: id, Kind: domain.SourceUploadDirectory, Status: domain.SourceUploadReady, Digest: "sha256:" + strings.Repeat("a", 64), Bytes: 1, FileCount: 1, StorageRef: "upload://" + id.String(), ExpiresAt: expiresAt, IdempotencyKey: id.String(), RequestDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: now, UpdatedAt: now, Files: []domain.SourceUploadFile{{Path: "src/main.go", Bytes: 1, Digest: "sha256:" + strings.Repeat("b", 64)}}}
}
