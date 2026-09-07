package assistanttools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func grant(t *testing.T, r *Registry, scope Scope) string {
	t.Helper()
	v, e := r.Grant(GrantInput{Actor: "admin_1", SessionID: "session_1", RunID: "run_1", Scope: scope, ExpiresAt: time.Now().Add(time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestHandlerAcceptsWireShapeAndRejectsChangedCallID(t *testing.T) {
	r := NewRegistry()
	token := grant(t, r, Scope{Admin: true})
	var calls atomic.Int32
	h := &Handler{Registry: r, Execute: func(context.Context, Grant, Call) Response {
		calls.Add(1)
		return Response{OK: true, Result: json.RawMessage(`{"ok":true}`)}
	}}
	request := httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(`{"tool":"acornfox_list_apps","call_id":"call_1","arguments":{}}`))
	request.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, request)
	if out.Code != 200 || calls.Load() != 1 {
		t.Fatalf("wire=%d", out.Code)
	}
	changed := httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(`{"tool":"acornfox_host_metrics","call_id":"call_1","arguments":{}}`))
	changed.Header.Set("Authorization", "Bearer "+token)
	out = httptest.NewRecorder()
	h.ServeHTTP(out, changed)
	var body Response
	_ = json.Unmarshal(out.Body.Bytes(), &body)
	if body.Code != "idempotency_conflict" || calls.Load() != 1 {
		t.Fatalf("conflict=%#v", body)
	}
}
func call(name, id string) Call {
	return Call{Tool: name, CallID: id, Arguments: json.RawMessage(`{}`)}
}
func TestGrantExpiryRevocationScopeAndIdempotency(t *testing.T) {
	r := NewRegistry()
	token := grant(t, r, Scope{ApplicationID: "app_1"})
	var calls atomic.Int32
	execute := func(_ context.Context, g Grant, c Call) Response {
		if g.Scope.ApplicationID != "app_1" {
			return Response{Code: "forbidden"}
		}
		calls.Add(1)
		return Response{OK: true, Result: json.RawMessage(`{"application_id":"app_1"}`)}
	}
	if got := r.Execute(context.Background(), token, call("acornfox_app", "call_1"), execute); !got.OK {
		t.Fatalf("first=%#v", got)
	}
	if got := r.Execute(context.Background(), token, call("acornfox_app", "call_1"), execute); !got.OK || calls.Load() != 1 {
		t.Fatalf("replay=%#v calls=%d", got, calls.Load())
	}
	r.Revoke(token)
	if got := r.Execute(context.Background(), token, call("acornfox_app", "call_2"), execute); got.Code != "unauthorized" {
		t.Fatalf("revoked=%#v", got)
	}
	expired := NewRegistry()
	expired.now = func() time.Time { return time.Unix(100, 0) }
	e, _ := expired.Grant(GrantInput{Actor: "admin_1", SessionID: "session_1", RunID: "run_1", Scope: Scope{Admin: true}, ExpiresAt: time.Unix(101, 0)})
	expired.now = func() time.Time { return time.Unix(102, 0) }
	if got := expired.Execute(context.Background(), e, call("acornfox_list_apps", "x"), execute); got.Code != "unauthorized" {
		t.Fatal(got)
	}
}
func TestRegistryRejectsUnknownAndBounds(t *testing.T) {
	r := NewRegistry()
	token := grant(t, r, Scope{Admin: true})
	exec := func(context.Context, Grant, Call) Response { return Response{OK: true, Result: json.RawMessage(`{}`)} }
	if got := r.Execute(context.Background(), token, call("unknown", "x"), exec); got.Code != "invalid_request" {
		t.Fatal(got)
	}
	large := Call{Tool: "acornfox_logs", CallID: "x", Arguments: json.RawMessage(make([]byte, MaxArguments+1))}
	if got := r.Execute(context.Background(), token, large, exec); got.Code != "invalid_request" {
		t.Fatal(got)
	}
	for n := 0; n < MaxCallsPerRun; n++ {
		if got := r.Execute(context.Background(), token, call("acornfox_list_apps", fmt.Sprintf("c%d", n)), exec); !got.OK {
			t.Fatal(got)
		}
	}
	if got := r.Execute(context.Background(), token, call("acornfox_list_apps", "overflow"), exec); got.Code != "call_limit" {
		t.Fatal(got)
	}
}
