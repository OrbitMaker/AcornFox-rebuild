package assistant

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func actorRequest(actor Actor, method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request = request.WithContext(WithActor(request.Context(), actor))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestHTTPAdapterUsesInjectedActorAndKeepsAcceptedDistinctFromCompleted(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	handler := &Handler{Service: service, SSEPollInterval: 5 * time.Millisecond, SSEHeartbeat: 5 * time.Millisecond, SSEMaxLifetime: 20 * time.Millisecond}

	unauthorized := httptest.NewRecorder()
	handler.Handle(unauthorized, httptest.NewRequest(http.MethodGet, HTTPBasePath+"/sessions", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized=%d %s", unauthorized.Code, unauthorized.Body.String())
	}

	create := httptest.NewRecorder()
	handler.Handle(create, actorRequest(actor, http.MethodPost, HTTPBasePath+"/sessions", `{"scope":{"kind":"host"}}`))
	if create.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", create.Code, create.Body.String())
	}
	var session Session
	if err := json.Unmarshal(create.Body.Bytes(), &session); err != nil || session.ID.Empty() {
		t.Fatalf("session=%+v err=%v", session, err)
	}

	runBody := `{"idempotency_key":"browser-retry","message":"show current host health"}`
	submit := httptest.NewRecorder()
	handler.Handle(submit, actorRequest(actor, http.MethodPost, HTTPBasePath+"/sessions/"+session.ID.String()+"/runs", runBody))
	if submit.Code != http.StatusAccepted || !strings.Contains(submit.Body.String(), `"status":"accepted"`) || strings.Contains(submit.Body.String(), `"status":"completed"`) {
		t.Fatalf("submit=%d %s", submit.Code, submit.Body.String())
	}
	waitStarted(t, runner)

	replay := httptest.NewRecorder()
	handler.Handle(replay, actorRequest(actor, http.MethodPost, HTTPBasePath+"/sessions/"+session.ID.String()+"/runs", runBody))
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replay":true`) {
		t.Fatalf("replay=%d %s", replay.Code, replay.Body.String())
	}
	if calls, _ := runner.counts(); calls != 1 {
		t.Fatalf("runner calls=%d", calls)
	}

	snapshot := httptest.NewRecorder()
	handler.Handle(snapshot, actorRequest(actor, http.MethodGet, HTTPBasePath+"/sessions/"+session.ID.String()+"/events?after=0", ""))
	if snapshot.Code != http.StatusOK || !strings.Contains(snapshot.Body.String(), "show current host health") || snapshot.Header().Get("X-AcornFox-Assistant-Cursor-Status") != string(CursorOK) {
		t.Fatalf("snapshot=%d %s headers=%v", snapshot.Code, snapshot.Body.String(), snapshot.Header())
	}

	sseRequest := actorRequest(actor, http.MethodGet, HTTPBasePath+"/sessions/"+session.ID.String()+"/events?after=0", "")
	sseRequest.Header.Set("Accept", "text/event-stream")
	sse := httptest.NewRecorder()
	handler.Handle(sse, sseRequest)
	if sse.Code != http.StatusOK || !strings.Contains(sse.Header().Get("Content-Type"), "text/event-stream") || !strings.Contains(sse.Body.String(), "event: run.accepted") || !strings.Contains(sse.Body.String(), ": heartbeat") {
		t.Fatalf("sse=%d %s headers=%v", sse.Code, sse.Body.String(), sse.Header())
	}

	runner.permits <- struct{}{}
	waitRunEvent(t, service, actor, session.ID.String(), EventRunCompleted)
}

func TestSSEStreamsEventsCreatedAfterConnectAndDisconnectDoesNotAbortRun(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{})
	service, actor := testService(t, runner, store)
	session := createTestSession(t, service, actor, Scope{Kind: ScopeHost})
	handler := &Handler{Service: service, SSEPollInterval: 5 * time.Millisecond, SSEHeartbeat: 5 * time.Millisecond, SSEMaxLifetime: time.Second}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithActor(r.Context(), actor))
		handler.Handle(w, r)
	}))
	defer server.Close()
	streamCtx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(streamCtx, http.MethodGet, server.URL+HTTPBasePath+"/sessions/"+session.ID.String()+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(response.Body)
	heartbeat := false
	for scanner.Scan() {
		if scanner.Text() == ": heartbeat" {
			heartbeat = true
			break
		}
	}
	if !heartbeat {
		t.Fatalf("stream had no heartbeat: %v", scanner.Err())
	}
	if _, err := service.SubmitRun(context.Background(), actor, session.ID, "live", "event after connection"); err != nil {
		t.Fatal(err)
	}
	found := false
	for scanner.Scan() {
		if scanner.Text() == "event: run.accepted" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("live event missing: %v", scanner.Err())
	}
	waitStarted(t, runner)
	cancel()
	_ = response.Body.Close()
	runner.mu.Lock()
	aborts := len(runner.aborts)
	runner.mu.Unlock()
	if aborts != 0 {
		t.Fatalf("SSE disconnect aborted runner: %d", aborts)
	}
	runner.permits <- struct{}{}
	waitRunEvent(t, service, actor, session.ID.String(), EventRunCompleted)

	resume := httptest.NewRecorder()
	resumeRequest := actorRequest(actor, http.MethodGet, HTTPBasePath+"/sessions/"+session.ID.String()+"/events", "")
	resumeRequest.Header.Set("Last-Event-ID", "1")
	handler.events(resume, resumeRequest, actor, session.ID)
	if resume.Code != http.StatusOK || strings.Contains(resume.Body.String(), `"cursor":1`) {
		t.Fatalf("Last-Event-ID replay=%d %s", resume.Code, resume.Body.String())
	}
}

func TestHTTPAdapterOwnerIsolationStrictBodiesAndCursorErrors(t *testing.T) {
	runner := newFakeRunner()
	store := NewMemoryStore(MemoryStoreConfig{MaxEventsPerSession: 2})
	service, owner := testService(t, runner, store)
	handler := &Handler{Service: service}
	session := createTestSession(t, service, owner, Scope{Kind: ScopeHost})
	other := Actor{AdminID: "admin_other"}
	foreign := httptest.NewRecorder()
	handler.Handle(foreign, actorRequest(other, http.MethodGet, HTTPBasePath+"/sessions/"+session.ID.String()+"/events?after=0", ""))
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign=%d %s", foreign.Code, foreign.Body.String())
	}

	unknown := httptest.NewRecorder()
	handler.Handle(unknown, actorRequest(owner, http.MethodPost, HTTPBasePath+"/sessions", `{"scope":{"kind":"host"},"email":"x@example.test"}`))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown=%d %s", unknown.Code, unknown.Body.String())
	}

	if _, err := service.SubmitRun(context.Background(), owner, session.ID, "cursor", "cursor history message"); err != nil {
		t.Fatal(err)
	}
	waitStarted(t, runner)
	runner.permits <- struct{}{}
	for attempts := 0; attempts < 1000; attempts++ {
		current, _ := service.Events(context.Background(), owner, session.ID, 1)
		complete := false
		for _, event := range current.Events {
			if event.Type == EventRunCompleted {
				complete = true
			}
		}
		if complete {
			break
		}
		if attempts == 999 {
			t.Fatal("HTTP cursor fixture did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	expired := httptest.NewRecorder()
	handler.Handle(expired, actorRequest(owner, http.MethodGet, HTTPBasePath+"/sessions/"+session.ID.String()+"/events?after=0", ""))
	if expired.Code != http.StatusConflict || !strings.Contains(expired.Body.String(), `"status":"expired"`) {
		t.Fatalf("expired=%d %s", expired.Code, expired.Body.String())
	}

	badCursor := httptest.NewRecorder()
	handler.Handle(badCursor, actorRequest(owner, http.MethodGet, HTTPBasePath+"/sessions/"+session.ID.String()+"/events?after=-1", ""))
	if badCursor.Code != http.StatusBadRequest {
		t.Fatalf("bad cursor=%d %s", badCursor.Code, badCursor.Body.String())
	}
}
