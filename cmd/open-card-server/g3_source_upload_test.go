package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/sourceupload"
)

type sourceUploadMemoryStore struct {
	byID  map[domain.ID]domain.SourceUploadRecord
	byKey map[string]domain.SourceUploadRecord
}

func (s *sourceUploadMemoryStore) CreateSourceUpload(_ context.Context, upload domain.SourceUploadRecord) (domain.SourceUploadRecord, bool, error) {
	if existing, found := s.byKey[upload.IdempotencyKey]; found {
		if existing.RequestDigest != upload.RequestDigest || existing.Digest != upload.Digest {
			return domain.SourceUploadRecord{}, false, postgres.ErrIdempotencyConflict
		}
		return existing, true, nil
	}
	s.byKey[upload.IdempotencyKey], s.byID[upload.ID] = upload, upload
	return upload, false, nil
}
func (s *sourceUploadMemoryStore) GetSourceUpload(_ context.Context, id domain.ID) (domain.SourceUploadRecord, error) {
	upload, found := s.byID[id]
	if !found {
		return domain.SourceUploadRecord{}, postgres.ErrNotFound
	}
	return upload, nil
}

func newSourceUploadHTTPServer(t *testing.T, limits sourceupload.Limits) (*Server, *http.Cookie, *http.Cookie, *sourceUploadMemoryStore) {
	t.Helper()
	server := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)
	manager, err := sourceupload.New(sourceupload.Config{Root: t.TempDir(), Limits: limits, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	store := &sourceUploadMemoryStore{byID: map[domain.ID]domain.SourceUploadRecord{}, byKey: map[string]domain.SourceUploadRecord{}}
	server.SetG3SourceUpload(&G3SourceUploadHTTPHandler{Store: store, Manager: manager, Clock: func() time.Time { return now }})
	return server, session, csrf, store
}

func TestG3SourceUploadHTTPDirectoryIdempotencyAndNoStorageLeak(t *testing.T) {
	server, session, csrf, store := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	request := sourceUploadDirectoryRequest(t, "upload-directory", "src/main.go", []byte("code"))
	request.AddCookie(session)
	request.Header.Set("Idempotency-Key", "upload-directory")
	addControlPlaneWriteProof(request, csrf)
	created := httptest.NewRecorder()
	server.Handler().ServeHTTP(created, request)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "storage_ref") || strings.Contains(created.Body.String(), "/tmp/") {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	var response struct {
		ID     string                    `json:"id"`
		Status domain.SourceUploadStatus `json:"status"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.ID == "" || response.Status != domain.SourceUploadReady {
		t.Fatalf("response=%+v err=%v", response, err)
	}

	replay := sourceUploadDirectoryRequest(t, "upload-directory", "src/main.go", []byte("code"))
	replay.AddCookie(session)
	replay.Header.Set("Idempotency-Key", "upload-directory")
	addControlPlaneWriteProof(replay, csrf)
	replayed := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusCreated || !strings.Contains(replayed.Body.String(), response.ID) || len(store.byID) != 1 {
		t.Fatalf("replay=%d %s records=%d", replayed.Code, replayed.Body.String(), len(store.byID))
	}

	conflict := sourceUploadDirectoryRequest(t, "upload-directory", "src/main.go", []byte("other"))
	conflict.AddCookie(session)
	conflict.Header.Set("Idempotency-Key", "upload-directory")
	addControlPlaneWriteProof(conflict, csrf)
	conflicted := httptest.NewRecorder()
	server.Handler().ServeHTTP(conflicted, conflict)
	if conflicted.Code != http.StatusConflict {
		t.Fatalf("conflict=%d %s", conflicted.Code, conflicted.Body.String())
	}

	get := httptest.NewRecorder()
	server.Handler().ServeHTTP(get, controlPlaneRequest(http.MethodGet, "/api/v1/source-uploads/"+response.ID, nil, session))
	if get.Code != http.StatusOK || strings.Contains(get.Body.String(), "storage_ref") {
		t.Fatalf("get=%d %s", get.Code, get.Body.String())
	}
	anonymous := httptest.NewRecorder()
	server.Handler().ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/source-uploads/"+response.ID, nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous get=%d", anonymous.Code)
	}
}

func TestG3SourceUploadHTTPRejectsUnsafePathAndLimits(t *testing.T) {
	server, session, csrf, _ := newSourceUploadHTTPServer(t, sourceupload.Limits{MaxTotalBytes: 4, MaxFileBytes: 4, MaxFiles: 10, MaxPathBytes: 512, MaxManifest: 1024})
	unsafe := sourceUploadDirectoryRequest(t, "unsafe", "../outside", []byte("x"))
	unsafe.AddCookie(session)
	unsafe.Header.Set("Idempotency-Key", "unsafe")
	addControlPlaneWriteProof(unsafe, csrf)
	unsafeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unsafeResponse, unsafe)
	if unsafeResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe=%d %s", unsafeResponse.Code, unsafeResponse.Body.String())
	}
	large := sourceUploadDirectoryRequest(t, "large", "src/main.go", []byte("12345"))
	large.AddCookie(session)
	large.Header.Set("Idempotency-Key", "large")
	addControlPlaneWriteProof(large, csrf)
	largeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(largeResponse, large)
	if largeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large=%d %s", largeResponse.Code, largeResponse.Body.String())
	}
}

func TestG3SourceUploadHTTPArchiveKeepsRawDigest(t *testing.T) {
	server, session, csrf, _ := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	content := []byte("not-expanded-archive-bytes")
	request := sourceUploadArchiveRequest(t, "site.tgz", content)
	request.AddCookie(session)
	request.Header.Set("Idempotency-Key", "upload-archive")
	addControlPlaneWriteProof(request, csrf)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	sum := sha256.Sum256(content)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"kind":"archive"`) || !strings.Contains(response.Body.String(), hex.EncodeToString(sum[:])) {
		t.Fatalf("archive=%d %s", response.Code, response.Body.String())
	}
}

func TestCreateApplicationGitSourceIsExplicitlyNotImplemented(t *testing.T) {
	server := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)
	request := controlPlaneRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"git app","source":{"kind":"git","repository_url":"https://example.test/repo.git","ref":"main"}}`), session)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "git-source")
	addControlPlaneWriteProof(request, csrf)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || !strings.Contains(response.Body.String(), "source_git_not_implemented") {
		t.Fatalf("git source=%d %s", response.Code, response.Body.String())
	}
}

func sourceUploadDirectoryRequest(t *testing.T, _ string, path string, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("mode", "directory"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest, err := json.Marshal(map[string]any{"files": []map[string]any{{"path": path, "bytes": len(content), "digest": "sha256:" + hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("manifest", string(manifest)); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("files", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/source-uploads", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func sourceUploadArchiveRequest(t *testing.T, filename string, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("mode", "archive"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("archive", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/source-uploads", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

var _ = errors.Is
