package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/providers/sourceupload"
)

func findFieldInMap(data map[string]any, key string) (any, bool) {
	if val, ok := data[key]; ok {
		return val, true
	}
	for _, v := range data {
		if nested, ok := v.(map[string]any); ok {
			if val, found := findFieldInMap(nested, key); found {
				return val, true
			}
		}
	}
	return nil, false
}

func findStringField(data map[string]any, key string) string {
	if val, found := findFieldInMap(data, key); found {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func makeAcornFoxSourceUploadRequest(t *testing.T, session, csrf *http.Cookie, key, filename string, content []byte) *http.Request {
	t.Helper()
	req := sourceUploadDirectoryRequest(t, key, filename, content)
	req.URL.Path = "/api/v1/acornfox/source-uploads"
	req.RequestURI = "/api/v1/acornfox/source-uploads"
	req.URL.RawPath = ""
	req.Header.Set("Idempotency-Key", key)
	addAcornFoxWriteProof(req, csrf)
	req.AddCookie(session)
	return req
}

func TestAcornFoxSourceUploadEndpointSuccessAndIdempotency(t *testing.T) {
	server, session, csrf, store := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	server.legacyRoutesEnabled = false
	session.Name = acornFoxAuthSessionCookie
	csrf.Name = acornFoxAuthCSRFCookie

	key := "test-idempotency-key-01"
	filename := "index.js"
	content := []byte("console.log('hello acornfox upload');")

	req := makeAcornFoxSourceUploadRequest(t, session, csrf, key, filename, content)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on valid upload, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "storage_ref") {
		t.Errorf("response body must not leak storage_ref: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "workspace_ref") {
		t.Errorf("response body must not leak workspace_ref: %s", bodyStr)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	uploadID, ok := resp["id"].(string)
	if !ok || uploadID == "" {
		t.Fatalf("expected non-empty id in response, got %v", resp["id"])
	}
	status, ok := resp["status"].(string)
	if !ok || status == "" {
		t.Fatalf("expected non-empty status in response, got %v", resp["status"])
	}

	if _, ok := resp["storage_ref"]; ok {
		t.Errorf("response JSON must not contain storage_ref key")
	}
	if _, ok := resp["workspace_ref"]; ok {
		t.Errorf("response JSON must not contain workspace_ref key")
	}

	if len(store.byID) != 1 {
		t.Fatalf("expected store to contain exactly 1 record, got %d", len(store.byID))
	}

	// Idempotent replay with same key and same content
	reqSame := makeAcornFoxSourceUploadRequest(t, session, csrf, key, filename, content)
	recSame := httptest.NewRecorder()
	server.Handler().ServeHTTP(recSame, reqSame)

	if recSame.Code != http.StatusCreated {
		t.Fatalf("expected 201 or 200 on replay, got %d (body: %s)", recSame.Code, recSame.Body.String())
	}

	var respSame map[string]any
	if err := json.Unmarshal(recSame.Body.Bytes(), &respSame); err != nil {
		t.Fatalf("failed to decode replay response JSON: %v", err)
	}
	if respSame["id"] != uploadID {
		t.Errorf("expected same upload id on replay, got %v vs original %v", respSame["id"], uploadID)
	}
	if len(store.byID) != 1 {
		t.Errorf("expected store record count to remain 1 on replay, got %d", len(store.byID))
	}

	// Conflict with same key but different content
	reqDiff := makeAcornFoxSourceUploadRequest(t, session, csrf, key, filename, []byte("console.log('different content');"))
	recDiff := httptest.NewRecorder()
	server.Handler().ServeHTTP(recDiff, reqDiff)

	if recDiff.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when same idempotency key sends different content, got %d", recDiff.Code)
	}
	if len(store.byID) != 1 {
		t.Errorf("store record count must remain 1 after 409 conflict, got %d", len(store.byID))
	}
}

func TestAcornFoxSourceUploadGetEndpoint(t *testing.T) {
	server, session, csrf, _ := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	server.legacyRoutesEnabled = false
	session.Name = acornFoxAuthSessionCookie
	csrf.Name = acornFoxAuthCSRFCookie

	key := "upload-get-test-key"
	req := makeAcornFoxSourceUploadRequest(t, session, csrf, key, "main.go", []byte("package main\n"))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("setup upload failed with code %d: %s", rec.Code, rec.Body.String())
	}

	var createdResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &createdResp); err != nil {
		t.Fatalf("failed to decode created response: %v", err)
	}
	uploadID := createdResp["id"].(string)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/source-uploads/"+uploadID, nil)
	getReq.AddCookie(session)
	getRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET upload by id, got %d", getRec.Code)
	}

	getStr := getRec.Body.String()
	if strings.Contains(getStr, "storage_ref") || strings.Contains(getStr, "workspace_ref") {
		t.Errorf("GET response must not leak storage_ref or workspace_ref: %s", getStr)
	}

	var getResp map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to decode GET response: %v", err)
	}
	if getResp["id"] != uploadID {
		t.Errorf("expected id %q in GET response, got %v", uploadID, getResp["id"])
	}
	if status, ok := getResp["status"].(string); !ok || status == "" {
		t.Errorf("expected non-empty status in GET response, got %v", getResp["status"])
	}

	getMissingReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/source-uploads/upload_nonexistent_999", nil)
	getMissingReq.AddCookie(session)
	getMissingRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(getMissingRec, getMissingReq)

	if getMissingRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for non-existent upload id, got %d", getMissingRec.Code)
	}
}

func TestAcornFoxSourceUploadAuthAndCSRFProtection(t *testing.T) {
	server, session, csrf, store := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	server.legacyRoutesEnabled = false
	session.Name = acornFoxAuthSessionCookie
	csrf.Name = acornFoxAuthCSRFCookie

	initialCount := len(store.byID)

	// Missing session cookie -> 401 Unauthorized
	reqNoSession := sourceUploadDirectoryRequest(t, "key-no-session", "file.txt", []byte("data"))
	reqNoSession.URL.Path = "/api/v1/acornfox/source-uploads"
	reqNoSession.RequestURI = "/api/v1/acornfox/source-uploads"
	reqNoSession.URL.RawPath = ""
	reqNoSession.Header.Set("Idempotency-Key", "key-no-session")
	addAcornFoxWriteProof(reqNoSession, csrf)
	// Do not add session

	recNoSession := httptest.NewRecorder()
	server.Handler().ServeHTTP(recNoSession, reqNoSession)

	if recNoSession.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized when session cookie is absent, got %d", recNoSession.Code)
	}
	if len(store.byID) != initialCount {
		t.Errorf("store record count must not increase after 401, got %d vs %d", len(store.byID), initialCount)
	}

	// Missing CSRF write proof -> 401 Unauthorized
	reqNoCSRF := sourceUploadDirectoryRequest(t, "key-no-csrf", "file.txt", []byte("data"))
	reqNoCSRF.URL.Path = "/api/v1/acornfox/source-uploads"
	reqNoCSRF.RequestURI = "/api/v1/acornfox/source-uploads"
	reqNoCSRF.URL.RawPath = ""
	reqNoCSRF.Header.Set("Idempotency-Key", "key-no-csrf")
	reqNoCSRF.Header.Set("Origin", "https://console.example.test")
	reqNoCSRF.AddCookie(session)
	// Do not call addAcornFoxWriteProof

	recNoCSRF := httptest.NewRecorder()
	server.Handler().ServeHTTP(recNoCSRF, reqNoCSRF)

	if recNoCSRF.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized when CSRF proof is absent, got %d", recNoCSRF.Code)
	}
	if len(store.byID) != initialCount {
		t.Errorf("store record count must not increase after 401, got %d vs %d", len(store.byID), initialCount)
	}

	// GET without session -> 401 Unauthorized
	getReqNoSession := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/source-uploads/upload_test", nil)
	getRecNoSession := httptest.NewRecorder()
	server.Handler().ServeHTTP(getRecNoSession, getReqNoSession)

	if getRecNoSession.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized on GET when session cookie is absent, got %d", getRecNoSession.Code)
	}
}

func TestAcornFoxSourceUploadPathTraversalRejected(t *testing.T) {
	server, session, csrf, store := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	server.legacyRoutesEnabled = false
	session.Name = acornFoxAuthSessionCookie
	csrf.Name = acornFoxAuthCSRFCookie

	initialCount := len(store.byID)

	req := makeAcornFoxSourceUploadRequest(t, session, csrf, "key-traversal", "../outside.txt", []byte("malicious content"))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity for path traversal, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if len(store.byID) != initialCount {
		t.Errorf("store must not record upload with path traversal, count is %d vs %d", len(store.byID), initialCount)
	}
}

func TestAcornFoxSourceUploadRoutingRules(t *testing.T) {
	server, session, csrf, _ := newSourceUploadHTTPServer(t, sourceupload.Limits{})
	server.legacyRoutesEnabled = false
	session.Name = acornFoxAuthSessionCookie
	csrf.Name = acornFoxAuthCSRFCookie

	// OPTIONS /api/v1/acornfox/source-uploads
	optReq := httptest.NewRequest(http.MethodOptions, "/api/v1/acornfox/source-uploads", nil)
	optReq.AddCookie(session)
	optRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Errorf("expected 200 or 204 for OPTIONS on collection, got %d", optRec.Code)
	}
	allowCollection := optRec.Header().Get("Allow")
	if !strings.Contains(allowCollection, "POST") || !strings.Contains(allowCollection, "OPTIONS") {
		t.Errorf("expected Allow to contain POST and OPTIONS on collection, got %q", allowCollection)
	}

	// OPTIONS /api/v1/acornfox/source-uploads/upload_123
	optItemReq := httptest.NewRequest(http.MethodOptions, "/api/v1/acornfox/source-uploads/upload_123", nil)
	optItemReq.AddCookie(session)
	optItemRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(optItemRec, optItemReq)

	if optItemRec.Code != http.StatusNoContent {
		t.Errorf("expected 200 or 204 for OPTIONS on item, got %d", optItemRec.Code)
	}
	allowItem := optItemRec.Header().Get("Allow")
	if !strings.Contains(allowItem, "GET") || !strings.Contains(allowItem, "OPTIONS") {
		t.Errorf("expected Allow to contain GET and OPTIONS on item, got %q", allowItem)
	}

	// Trailing slash rejected on collection: POST /api/v1/acornfox/source-uploads/
	trailingReq := makeAcornFoxSourceUploadRequest(t, session, csrf, "key-trailing", "test.txt", []byte("data"))
	trailingReq.URL.Path = "/api/v1/acornfox/source-uploads/"
	trailingReq.RequestURI = "/api/v1/acornfox/source-uploads/"
	trailingRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(trailingRec, trailingReq)
	if trailingRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for trailing slash on POST, got %d", trailingRec.Code)
	}

	// Trailing slash rejected on item: GET /api/v1/acornfox/source-uploads/upload_123/
	trailingGetReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/source-uploads/upload_123/", nil)
	trailingGetReq.AddCookie(session)
	trailingGetRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(trailingGetRec, trailingGetReq)
	if trailingGetRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for trailing slash on GET item, got %d", trailingGetRec.Code)
	}

	// Nested sub-path rejected: POST /api/v1/acornfox/source-uploads/nested/sub
	nestedReq := makeAcornFoxSourceUploadRequest(t, session, csrf, "key-nested", "test.txt", []byte("data"))
	nestedReq.URL.Path = "/api/v1/acornfox/source-uploads/nested/sub"
	nestedReq.RequestURI = "/api/v1/acornfox/source-uploads/nested/sub"
	nestedRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(nestedRec, nestedReq)
	if nestedRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nested sub-path on POST, got %d", nestedRec.Code)
	}

	// Nested sub-path rejected: GET /api/v1/acornfox/source-uploads/upload_123/extra
	nestedGetReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/source-uploads/upload_123/extra", nil)
	nestedGetReq.AddCookie(session)
	nestedGetRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(nestedGetRec, nestedGetReq)
	if nestedGetRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nested sub-path on GET, got %d", nestedGetRec.Code)
	}

	// Duplicate slash rejected: POST /api/v1/acornfox//source-uploads
	dupSlashReq := makeAcornFoxSourceUploadRequest(t, session, csrf, "key-dupslash", "test.txt", []byte("data"))
	dupSlashReq.URL.Path = "/api/v1/acornfox//source-uploads"
	dupSlashReq.RequestURI = "/api/v1/acornfox//source-uploads"
	dupSlashRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(dupSlashRec, dupSlashReq)
	if dupSlashRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for duplicate slash on POST, got %d", dupSlashRec.Code)
	}
}

func TestAcornFoxSourceUploadServiceUnavailableWithoutStore(t *testing.T) {
	repo := application.NewMemoryRepository()
	server := NewAcornFoxServerWithRepository(repo)
	now := time.Now().UTC()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)

	// POST without store configured -> 503 Service Unavailable without panic
	postBody := bytes.NewReader([]byte(`{"dummy":"payload"}`))
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/source-uploads", postBody)
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Idempotency-Key", "key-without-store")
	addAcornFoxWriteProof(postReq, csrf)
	postReq.AddCookie(session)

	postRec := httptest.NewRecorder()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("server panicked when source upload store is absent: %v", r)
		}
	}()
	server.Handler().ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable on POST when store is missing, got %d", postRec.Code)
	}

	// GET without store configured -> 503 Service Unavailable without panic
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/source-uploads/upload_any_id", nil)
	getReq.AddCookie(session)

	getRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable on GET when store is missing, got %d", getRec.Code)
	}
}

func TestAcornFoxAppCreationWithSourceUploadSuccessAndIdempotency(t *testing.T) {
	repo := application.NewMemoryRepository()
	registerReadySourceUpload(t, repo)
	server := NewAcornFoxServerWithRepository(repo)
	configureTestSourcePreparer(server)
	now := time.Now().UTC()
	_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)

	payload := map[string]any{
		"name": "my-upload-app",
		"source": map[string]any{
			"type":      "upload",
			"upload_id": "upload_test",
		},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal create app body: %v", err)
	}

	idempotencyKey := "app-create-idemp-key-01"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	addAcornFoxWriteProof(req, csrf)
	req.AddCookie(session)

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on app creation with upload source, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	sourceRevisionID := findStringField(resp, "source_revision_id")
	if sourceRevisionID == "" {
		t.Fatalf("expected non-empty source_revision_id in response, body: %s", rec.Body.String())
	}

	appID := findStringField(resp, "id")
	if appID == "" {
		appID = findStringField(resp, "app_id")
	}

	// Idempotent replay with same key
	reqReplay := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps", bytes.NewReader(bodyBytes))
	reqReplay.Header.Set("Content-Type", "application/json")
	reqReplay.Header.Set("Idempotency-Key", idempotencyKey)
	addAcornFoxWriteProof(reqReplay, csrf)
	reqReplay.AddCookie(session)

	recReplay := httptest.NewRecorder()
	server.Handler().ServeHTTP(recReplay, reqReplay)

	if recReplay.Code != http.StatusCreated {
		t.Fatalf("expected 201 or 200 on create app replay, got %d (body: %s)", recReplay.Code, recReplay.Body.String())
	}

	var respReplay map[string]any
	if err := json.Unmarshal(recReplay.Body.Bytes(), &respReplay); err != nil {
		t.Fatalf("failed to decode replay response JSON: %v", err)
	}

	replayRevisionID := findStringField(respReplay, "source_revision_id")
	if replayRevisionID != sourceRevisionID {
		t.Errorf("expected identical source_revision_id %q on replay, got %q", sourceRevisionID, replayRevisionID)
	}
	if appID != "" {
		replayAppID := findStringField(respReplay, "id")
		if replayAppID == "" {
			replayAppID = findStringField(respReplay, "app_id")
		}
		if replayAppID != appID {
			t.Errorf("expected identical app id %q on replay, got %q", appID, replayAppID)
		}
	}

	// Conflict when reusing same upload_id with a different idempotency key
	conflictPayload := map[string]any{
		"name": "my-upload-app-duplicate",
		"source": map[string]any{
			"type":      "upload",
			"upload_id": "upload_test",
		},
	}
	conflictBytes, _ := json.Marshal(conflictPayload)
	reqConflict := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps", bytes.NewReader(conflictBytes))
	reqConflict.Header.Set("Content-Type", "application/json")
	reqConflict.Header.Set("Idempotency-Key", "app-create-idemp-key-02")
	addAcornFoxWriteProof(reqConflict, csrf)
	reqConflict.AddCookie(session)

	recConflict := httptest.NewRecorder()
	server.Handler().ServeHTTP(recConflict, reqConflict)

	if recConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when creating app with already-consumed upload_id, got %d (body: %s)", recConflict.Code, recConflict.Body.String())
	}
}

func TestAcornFoxAppCreationSourceUploadValidationErrors(t *testing.T) {
	testCases := []struct {
		name         string
		payload      map[string]any
		expectedCode int
	}{
		{
			name: "unknown source type rejected with 422",
			payload: map[string]any{
				"name": "app-bad-type",
				"source": map[string]any{
					"type":      "unsupported_ftp",
					"upload_id": "upload_test",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "upload missing upload_id rejected with 422",
			payload: map[string]any{
				"name": "app-missing-upload-id",
				"source": map[string]any{
					"type": "upload",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "upload mixed with repository_url rejected with 422",
			payload: map[string]any{
				"name": "app-mixed-repo-url",
				"source": map[string]any{
					"type":           "upload",
					"upload_id":      "upload_test",
					"repository_url": "https://github.com/example/repo.git",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "upload mixed with empty repository_url rejected with 422",
			payload: map[string]any{
				"name": "app-mixed-empty-repo-url",
				"source": map[string]any{
					"type":           "upload",
					"upload_id":      "upload_test",
					"repository_url": "",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "upload mixed with ref rejected with 422",
			payload: map[string]any{
				"name": "app-mixed-ref",
				"source": map[string]any{
					"type":      "upload",
					"upload_id": "upload_test",
					"ref":       "main",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "upload mixed with empty ref rejected with 422",
			payload: map[string]any{
				"name": "app-mixed-empty-ref",
				"source": map[string]any{
					"type":      "upload",
					"upload_id": "upload_test",
					"ref":       "",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "public_git mixed with upload_id rejected with 422",
			payload: map[string]any{
				"name": "app-git-mixed-upload-id",
				"source": map[string]any{
					"type":           "public_git",
					"repository_url": "https://github.com/example/repo.git",
					"ref":            "main",
					"upload_id":      "upload_test",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "public_git mixed with empty upload_id rejected with 422",
			payload: map[string]any{
				"name": "app-git-mixed-empty-upload-id",
				"source": map[string]any{
					"type":           "public_git",
					"repository_url": "https://github.com/example/repo.git",
					"ref":            "main",
					"upload_id":      "",
				},
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name: "unknown path field in source rejected by decoder with 400",
			payload: map[string]any{
				"name": "app-unknown-path-in-source",
				"source": map[string]any{
					"type":      "upload",
					"upload_id": "upload_test",
					"path":      "subfolder",
				},
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name: "unknown top-level field rejected by decoder with 400",
			payload: map[string]any{
				"name":         "app-unknown-field",
				"unknown_path": "/some/where",
				"source": map[string]any{
					"type":      "upload",
					"upload_id": "upload_test",
				},
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := application.NewMemoryRepository()
			registerReadySourceUpload(t, repo)
			server := NewAcornFoxServerWithRepository(repo)
			configureTestSourcePreparer(server)
			now := time.Now().UTC()
			_, session, csrf := attachTestAcornFoxAdministratorTokens(t, server, &now)

			bodyBytes, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/apps", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "key-"+tc.name)
			addAcornFoxWriteProof(req, csrf)
			req.AddCookie(session)

			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			if rec.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d (body: %s)", tc.expectedCode, rec.Code, rec.Body.String())
			}
		})
	}
}
