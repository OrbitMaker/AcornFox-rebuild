package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/controllers"
)

func TestM4ActiveOperationIsAConflictNotInternalError(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeDomainError(recorder, controllers.ErrM4ActiveOperation)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "active_operation_conflict") {
		t.Fatalf("active operation response=%d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAPI_CONTRACT_001_ServerApplicationRESTAndSSE(t *testing.T) {
	server := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, server, &now)
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status: %s", response.Status)
	}
	response.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, testServer.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(session)
	eventResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer eventResponse.Body.Close()
	if eventResponse.StatusCode != http.StatusOK || !strings.HasPrefix(eventResponse.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected event response: %s %#v", eventResponse.Status, eventResponse.Header)
	}
	scanner := bufio.NewScanner(eventResponse.Body)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), ": connected") {
		t.Fatalf("expected SSE connected comment, got %q", scanner.Text())
	}

	createRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/applications", strings.NewReader(`{"name":"demo"}`))
	if err != nil {
		t.Fatal(err)
	}
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.AddCookie(session)
	createResponse, err := http.DefaultClient.Do(createRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer createResponse.Body.Close()
	if createResponse.StatusCode != http.StatusCreated {
		t.Fatalf("create status: %s", createResponse.Status)
	}
	var application struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var created struct {
		Application struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"application"`
		OperationID string `json:"operation_id"`
	}
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	application = created.Application
	if application.ID == "" || application.Name != "demo" {
		t.Fatalf("unexpected application: %#v", application)
	}
	if created.OperationID == "" {
		t.Fatal("create response omitted operation id")
	}

	foundID := false
	deadline := time.After(2 * time.Second)
	for !foundID {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for application SSE event")
		default:
		}
		if !scanner.Scan() {
			t.Fatalf("SSE closed before event: %v", scanner.Err())
		}
		if strings.HasPrefix(scanner.Text(), "id: ") {
			foundID = true
		}
	}

	getRequest, err := http.NewRequest(http.MethodGet, testServer.URL+"/api/v1/applications/"+application.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	getRequest.AddCookie(session)
	getResponse, err := http.DefaultClient.Do(getRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer getResponse.Body.Close()
	if getResponse.StatusCode != http.StatusOK {
		t.Fatalf("get status: %s", getResponse.Status)
	}

	listRequest, err := http.NewRequest(http.MethodGet, testServer.URL+"/api/v1/applications", nil)
	if err != nil {
		t.Fatal(err)
	}
	listRequest.AddCookie(session)
	listResponse, err := http.DefaultClient.Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer listResponse.Body.Close()
	var applicationList struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResponse.Body).Decode(&applicationList); err != nil {
		t.Fatal(err)
	}
	if len(applicationList.Items) != 1 {
		t.Fatalf("expected one application, got %d", len(applicationList.Items))
	}
}

type unhealthyRepository struct{ *application.MemoryRepository }

func (unhealthyRepository) PingContext(context.Context) error {
	return errors.New("database unavailable")
}

func TestServerReadinessFailsWhenPersistentRepositoryIsUnavailable(t *testing.T) {
	repository := unhealthyRepository{MemoryRepository: application.NewMemoryRepository()}
	serverState := NewServerWithRepository(repository)
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, serverState, &now)
	server := httptest.NewServer(serverState.Handler())
	defer server.Close()
	for _, test := range []struct {
		path string
		want int
	}{{path: "/healthz", want: http.StatusOK}, {path: "/readyz", want: http.StatusServiceUnavailable}} {
		request, err := http.NewRequest(http.MethodGet, server.URL+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.path == "/readyz" {
			request.AddCookie(session)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.want {
			t.Fatalf("%s: got %s want %d", test.path, response.Status, test.want)
		}
	}
}

func TestAPI_SECURITY_001_ServerRejectsUnknownJSONFields(t *testing.T) {
	serverState := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, serverState, &now)
	server := httptest.NewServer(serverState.Handler())
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/applications", strings.NewReader(`{"name":"demo","unexpected":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(session)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("expected bad request, got %s body=%s", response.Status, body)
	}
}

func TestServerReadinessIsDistinctFromLiveness(t *testing.T) {
	serverState := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, serverState, &now)
	serverState.SetReady(false)
	server := httptest.NewServer(serverState.Handler())
	defer server.Close()
	for _, path := range []string{"/healthz", "/readyz"} {
		request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if path == "/readyz" {
			request.AddCookie(session)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if path == "/healthz" && response.StatusCode != http.StatusOK {
			t.Fatalf("liveness should remain healthy: %s", response.Status)
		}
		if path == "/readyz" && response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("readiness should fail closed: %s", response.Status)
		}
		response.Body.Close()
	}
}

func TestAPI_CONTRACT_002_SSEReplaysFromRepositoryAfterServerRestart(t *testing.T) {
	repository := application.NewMemoryRepository()
	firstState := NewServerWithRepository(repository)
	now := time.Unix(1_700_000_000, 0).UTC()
	_, firstSession := attachTestAdministrator(t, firstState, &now)
	firstServer := httptest.NewServer(firstState.Handler())
	request, err := http.NewRequest(http.MethodPost, firstServer.URL+"/api/v1/applications", strings.NewReader(`{"name":"persistent"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "persistent-create")
	request.AddCookie(firstSession)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	firstServer.Close()

	restartedState := NewServerWithRepository(repository)
	_, restartedSession := attachTestAdministrator(t, restartedState, &now)
	restarted := httptest.NewServer(restartedState.Handler())
	defer restarted.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replayRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, restarted.URL+"/api/v1/operations/"+created.OperationID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	replayRequest.Header.Set("Last-Event-ID", "evt-0")
	replayRequest.AddCookie(restartedSession)
	replayResponse, err := http.DefaultClient.Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResponse.Body.Close()
	scanner := bufio.NewScanner(replayResponse.Body)
	found := false
	deadline := time.After(2 * time.Second)
	for !found {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for persisted SSE replay")
		default:
		}
		if !scanner.Scan() {
			t.Fatalf("replay stream closed: %v", scanner.Err())
		}
		found = scanner.Text() == "id: evt-1"
	}
}

func TestAPI_IDEMPOTENCY_001_CreateReplayAndConflict(t *testing.T) {
	serverState := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, serverState, &now)
	server := httptest.NewServer(serverState.Handler())
	defer server.Close()
	create := func(name string) (*http.Response, map[string]any) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/applications", strings.NewReader(`{"name":"`+name+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "same-create")
		request.AddCookie(session)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{}
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			response.Body.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		return response, payload
	}
	firstResponse, first := create("same")
	secondResponse, second := create("same")
	if firstResponse.StatusCode != http.StatusCreated || secondResponse.StatusCode != http.StatusCreated {
		t.Fatalf("idempotent create statuses: %d %d", firstResponse.StatusCode, secondResponse.StatusCode)
	}
	if first["operation_id"] != second["operation_id"] {
		t.Fatalf("retry changed operation: %#v %#v", first, second)
	}
	conflictResponse, _ := create("different")
	if conflictResponse.StatusCode != http.StatusConflict {
		t.Fatalf("expected idempotency conflict, got %d", conflictResponse.StatusCode)
	}
}

func TestAPI_COMPAT_001_NegotiatesNAndNMinusOneAndRejectsMajor(t *testing.T) {
	serverState := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, serverState, &now)
	server := httptest.NewServer(serverState.Handler())
	defer server.Close()
	for _, test := range []struct {
		name         string
		headers      map[string]string
		wantStatus   int
		wantVersion  string
		wantDisabled string
	}{
		{name: "legacy omitted", headers: nil, wantStatus: http.StatusOK, wantVersion: "1.0"},
		{name: "current exact", headers: map[string]string{apiVersionHeader: "1.1"}, wantStatus: http.StatusOK, wantVersion: "1.1"},
		{name: "range chooses current", headers: map[string]string{apiMinVersionHeader: "1.0", apiMaxVersionHeader: "1.1"}, wantStatus: http.StatusOK, wantVersion: "1.1"},
		{name: "major rejected", headers: map[string]string{apiVersionHeader: "2.0"}, wantStatus: http.StatusUpgradeRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/applications", nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			request.AddCookie(session)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status=%s want=%d", response.Status, test.wantStatus)
			}
			if test.wantVersion != "" && response.Header.Get(apiVersionHeader) != test.wantVersion {
				t.Fatalf("negotiated version=%q want=%q", response.Header.Get(apiVersionHeader), test.wantVersion)
			}
			if test.wantDisabled != "" && !strings.Contains(response.Header.Get("Open-Card-Disabled-Capabilities"), test.wantDisabled) {
				t.Fatalf("disabled capabilities=%q", response.Header.Get("Open-Card-Disabled-Capabilities"))
			}
		})
	}
}

func TestAPI_COMPAT_002_CurrentSSEReplayIncludesSchemaVersionWhileLegacyOmitsIt(t *testing.T) {
	repository := application.NewMemoryRepository()
	controller := application.NewController(repository)
	created, err := controller.CreateApplication(context.Background(), "compat-sse", "compat-sse")
	if err != nil {
		t.Fatal(err)
	}
	serverState := NewServerWithRepository(repository)
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session := attachTestAdministrator(t, serverState, &now)
	server := httptest.NewServer(serverState.Handler())
	defer server.Close()
	readReplay := func(version string) string {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/operations/"+created.OperationID.String()+"/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Last-Event-ID", "evt-0")
		if version != "" {
			request.Header.Set(apiVersionHeader, version)
		}
		request.AddCookie(session)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		scanner := bufio.NewScanner(response.Body)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data: ") {
				return scanner.Text()
			}
		}
		t.Fatalf("SSE replay closed without data: %v", scanner.Err())
		return ""
	}
	legacy := readReplay("")
	current := readReplay("1.1")
	if strings.Contains(legacy, "schema_version") {
		t.Fatalf("legacy SSE received new schema field: %s", legacy)
	}
	if !strings.Contains(current, `"schema_version":"1.1"`) {
		t.Fatalf("current SSE omitted schema version: %s", current)
	}
}
