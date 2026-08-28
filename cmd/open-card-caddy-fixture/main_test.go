package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func testRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	return r
}

func TestFixtureForwardsAndFailsExactScopeOnce(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/config/" {
			_, _ = w.Write([]byte(`{"apps":{}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	evidence := filepath.Join(t.TempDir(), "events.ndjson")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	f := &fixture{token: "fixture-token-01234567890123456789", taskPrefix: "opencard-mvp-test", listen: "127.0.0.1:2020", upstream: parsed, evidence: evidence, client: &http.Client{Transport: transport}}
	arm := testRequest(http.MethodPost, "/__fixture/fault", `{"rollout_id":"op_rollout","route_set_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mode":"load"}`)
	arm.Header.Set("Authorization", "Bearer "+f.token)
	arm.Header.Set("X-Open-Card-Task-Scope", f.taskPrefix)
	armed := httptest.NewRecorder()
	f.ServeHTTP(armed, arm)
	if armed.Code != 200 {
		t.Fatalf("arm=%d %s", armed.Code, armed.Body.String())
	}
	loadBody := `{"admin":{"listen":"127.0.0.1:2020"},"apps":{}}`
	wrong := testRequest(http.MethodPost, "/load", loadBody)
	wrong.Header.Set("X-Open-Card-Rollout-ID", "op_rollout")
	wrong.Header.Set("X-Open-Card-Route-Digest", "sha256:"+strings.Repeat("b", 64))
	wrongResult := httptest.NewRecorder()
	f.ServeHTTP(wrongResult, wrong)
	if wrongResult.Code != 200 || calls.Load() != 1 {
		t.Fatalf("wrong digest triggered fault: %d calls=%d", wrongResult.Code, calls.Load())
	}
	request := testRequest(http.MethodPost, "/load", loadBody)
	request.Header.Set("X-Open-Card-Rollout-ID", "op_rollout")
	request.Header.Set("X-Open-Card-Route-Digest", "sha256:"+strings.Repeat("a", 64))
	failed := httptest.NewRecorder()
	f.ServeHTTP(failed, request)
	if failed.Code != 503 || calls.Load() != 1 {
		t.Fatalf("exact fault=%d calls=%d", failed.Code, calls.Load())
	}
	replay := testRequest(http.MethodPost, "/load", loadBody)
	replay.Header = request.Header.Clone()
	recovered := httptest.NewRecorder()
	f.ServeHTTP(recovered, replay)
	if recovered.Code != 200 || calls.Load() != 2 {
		t.Fatalf("one-shot did not recover: %d calls=%d", recovered.Code, calls.Load())
	}
	payload, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if json.Unmarshal(payload, &event) != nil || event["rollout_id"] != "op_rollout" || event["mode"] != "load" || event["consumed"] != true {
		t.Fatalf("evidence=%s", payload)
	}
}

func TestFixtureControlAndNetworkScopeFailClosed(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("fixture-token-01234567890123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFixture("0.0.0.0:2020", "http://127.0.0.1:2019", tokenPath, "opencard-mvp-test", "/var/lib/opencard-mvp-test/evidence.ndjson"); err == nil {
		t.Fatal("non-loopback listen accepted")
	}
	if _, err := newFixture("127.0.0.1:2020", "http://192.0.2.1:2019", tokenPath, "opencard-mvp-test", "/var/lib/opencard-mvp-test/evidence.ndjson"); err == nil {
		t.Fatal("external upstream accepted")
	}
	parsed, _ := url.Parse("http://127.0.0.1:2019")
	f := &fixture{token: "fixture-token-01234567890123456789", taskPrefix: "opencard-mvp-test", upstream: parsed, evidence: filepath.Join(t.TempDir(), "events")}
	for _, mutate := range []func(*http.Request){func(r *http.Request) {}, func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+f.token)
		r.Header.Set("X-Open-Card-Task-Scope", "wrong")
	}} {
		r := testRequest(http.MethodPost, "/__fixture/fault", `{"rollout_id":"op","route_set_digest":"sha256:`+strings.Repeat("a", 64)+`","mode":"observe"}`)
		mutate(r)
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("unsafe control=%d", w.Code)
		}
	}
	external := testRequest(http.MethodGet, "/__fixture/ready", "")
	external.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	f.ServeHTTP(w, external)
	if w.Code != http.StatusForbidden {
		t.Fatal("external client accepted")
	}
}

func TestFixtureObserveFailureIsScopedAndOneShot(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{"apps":{}}`)) }))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	f := &fixture{token: "fixture-token-01234567890123456789", taskPrefix: "opencard-mvp-test", upstream: parsed, evidence: filepath.Join(t.TempDir(), "observe.ndjson"), client: upstream.Client()}
	arm := testRequest(http.MethodPost, "/__fixture/fault", `{"rollout_id":"op_observe","route_set_digest":"sha256:`+strings.Repeat("c", 64)+`","mode":"observe"}`)
	arm.Header.Set("Authorization", "Bearer "+f.token)
	arm.Header.Set("X-Open-Card-Task-Scope", f.taskPrefix)
	w := httptest.NewRecorder()
	f.ServeHTTP(w, arm)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	request := testRequest(http.MethodGet, "/config/", "")
	request.Header.Set("X-Open-Card-Rollout-ID", "op_observe")
	request.Header.Set("X-Open-Card-Route-Digest", "sha256:"+strings.Repeat("c", 64))
	failed := httptest.NewRecorder()
	f.ServeHTTP(failed, request)
	if failed.Code != 503 || calls.Load() != 0 {
		t.Fatalf("observe=%d calls=%d", failed.Code, calls.Load())
	}
	replay := testRequest(http.MethodGet, "/config/", "")
	replay.Header = request.Header.Clone()
	ok := httptest.NewRecorder()
	f.ServeHTTP(ok, replay)
	if ok.Code != 200 || calls.Load() != 1 {
		t.Fatalf("observe recovery=%d calls=%d", ok.Code, calls.Load())
	}
}
