package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const readySourceUploadJSON = `{"kind":"upload","upload_id":"upload_test"}`

func newServerWithReadySourceUpload(t *testing.T) *Server {
	t.Helper()
	repository := application.NewMemoryRepository()
	registerReadySourceUpload(t, repository)
	server := NewServerWithRepository(repository)
	configureTestSourcePreparer(server)
	return server
}

// testSourcePreparer models only the prepared immutable fact that HTTP server
// tests need; real process wiring always uses providers/source with private
// upload and workspace roots.
type testSourcePreparer struct{}

func (testSourcePreparer) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "test-source", Version: "1", ContractVersion: contracts.ContractAPIVersion}
}

func (testSourcePreparer) Prepare(_ context.Context, request contracts.PrepareSourceRequest) (contracts.PrepareSourceResult, error) {
	revision, err := domain.NewSourceRevision(request.ApplicationID, request.Kind, request.Locator, request.Ref, "", "sha256:"+strings.Repeat("c", 64), "memory://source-workspace", time.Now().UTC())
	if err != nil {
		return contracts.PrepareSourceResult{}, err
	}
	return contracts.PrepareSourceResult{Revision: revision}, nil
}

func (testSourcePreparer) Release(context.Context, contracts.ReleaseSourceRequest) error { return nil }

func configureTestSourcePreparer(server *Server) {
	server.controller.SetSourcePreparer(testSourcePreparer{})
}

func registerReadySourceUpload(t *testing.T, repository *application.MemoryRepository) {
	t.Helper()
	now := time.Now().UTC()
	upload := domain.SourceUploadRecord{ID: "upload_test", Kind: domain.SourceUploadDirectory, Status: domain.SourceUploadReady, Digest: "sha256:" + strings.Repeat("a", 64), Bytes: 1, FileCount: 1, StorageRef: "upload://upload_test", ExpiresAt: now.Add(24 * time.Hour), IdempotencyKey: "upload-test", RequestDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: now, UpdatedAt: now, Files: []domain.SourceUploadFile{{Path: "src/main.go", Bytes: 1, Digest: "sha256:" + strings.Repeat("b", 64)}}}
	if err := repository.RegisterSourceUpload(upload); err != nil {
		t.Fatal(err)
	}
}
