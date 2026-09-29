package caddyroute

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

// fakeCaddy is an in-memory Caddy admin API served over a Unix socket. It
// stores the whole config as a nested map so tests can assert that non-af
// servers are preserved.
type fakeCaddy struct {
	mu     sync.Mutex
	config map[string]any // root Caddy config
	srv    *http.Server
	socket string
}

func startFakeCaddy(t *testing.T, initial map[string]any) *fakeCaddy {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	f := &fakeCaddy{config: initial, socket: socket}
	if f.config == nil {
		f.config = map[string]any{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.handle)
	f.srv = &http.Server{Handler: mux}
	go f.srv.Serve(ln)
	t.Cleanup(func() { f.srv.Close() })
	return f
}

// servers returns the current af-aware servers map (may be nil).
func (f *fakeCaddy) servers() map[string]any {
	apps, _ := f.config["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	return servers
}

// getPath descends the config by the admin path.
func (f *fakeCaddy) getPath(path string) (any, bool) {
	if path == "/config/" || path == "/config" {
		return f.config, true
	}
	rel := path[len("/config/"):]
	parts := splitPath(rel)
	var cur any = f.config
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[p]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func splitPath(rel string) []string {
	var parts []string
	cur := ""
	for _, r := range rel {
		if r == '/' {
			if cur != "" {
				parts = append(parts, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

// setPath creates intermediate maps and sets the value at path.
func (f *fakeCaddy) setPath(path string, val any) {
	rel := path[len("/config/"):]
	parts := splitPath(rel)
	cur := f.config
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = val
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

func (f *fakeCaddy) deletePath(path string) {
	rel := path[len("/config/"):]
	parts := splitPath(rel)
	cur := f.config
	for i, p := range parts {
		if i == len(parts)-1 {
			delete(cur, p)
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
}

func (f *fakeCaddy) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		v, ok := f.getPath(r.URL.Path)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	case http.MethodPut, http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var v any
		if len(body) > 0 {
			if err := json.Unmarshal(body, &v); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
		}
		f.setPath(r.URL.Path, v)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if _, ok := f.getPath(r.URL.Path); !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		f.deletePath(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func TestSyncFromEmptyConfig(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket)
	ctx := context.Background()

	routes := []Route{
		{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:32001"},
		{App: "api", PublicPort: 18811, Upstream: "127.0.0.1:32002"},
	}
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	cur, err := r.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(cur) != 2 {
		t.Fatalf("current routes = %d, want 2", len(cur))
	}
	if cur["web"].PublicPort != 18810 || cur["web"].Upstream != "127.0.0.1:32001" {
		t.Errorf("web route wrong: %+v", cur["web"])
	}
	if cur["api"].Upstream != "127.0.0.1:32002" {
		t.Errorf("api route wrong: %+v", cur["api"])
	}
	// automatic_https disabled in the stored server.
	srv := f.servers()["af-web"].(map[string]any)
	ah := srv["automatic_https"].(map[string]any)
	if ah["disable"] != true {
		t.Errorf("automatic_https.disable not set")
	}
}

func TestSyncPreservesNonAfServers(t *testing.T) {
	initial := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"user-site": map[string]any{
						"listen": []any{":8443"},
					},
				},
			},
		},
	}
	f := startFakeCaddy(t, initial)
	r := New(f.socket)
	ctx := context.Background()

	if err := r.Sync(ctx, []Route{{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:1"}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	servers := f.servers()
	if _, ok := servers["user-site"]; !ok {
		t.Errorf("non-af server was clobbered")
	}
	if _, ok := servers["af-web"]; !ok {
		t.Errorf("af server not created")
	}
	// Current must ignore the non-af server.
	cur, _ := r.Current(ctx)
	if _, ok := cur["user-site"]; ok {
		t.Errorf("Current leaked non-af server")
	}
}

func TestSyncDeletesStaleAfServers(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket)
	ctx := context.Background()

	if err := r.Sync(ctx, []Route{
		{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:1"},
		{App: "api", PublicPort: 18811, Upstream: "127.0.0.1:2"},
	}); err != nil {
		t.Fatalf("Sync 1: %v", err)
	}
	// Second sync drops api.
	if err := r.Sync(ctx, []Route{{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:1"}}); err != nil {
		t.Fatalf("Sync 2: %v", err)
	}
	cur, _ := r.Current(ctx)
	if len(cur) != 1 {
		t.Fatalf("routes = %d, want 1", len(cur))
	}
	if _, ok := cur["api"]; ok {
		t.Errorf("stale af-api not deleted")
	}
}

func TestSyncUpdatesChangedRoute(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket)
	ctx := context.Background()

	r.Sync(ctx, []Route{{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:1"}})
	// Change upstream.
	if err := r.Sync(ctx, []Route{{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:9999"}}); err != nil {
		t.Fatalf("Sync update: %v", err)
	}
	cur, _ := r.Current(ctx)
	if cur["web"].Upstream != "127.0.0.1:9999" {
		t.Errorf("upstream not updated: %+v", cur["web"])
	}
}

// countingCaddy wraps the fake to count write requests, verifying Sync skips
// unchanged servers.
func TestSyncSkipsUnchanged(t *testing.T) {
	f := startFakeCaddy(t, nil)

	var writes int
	var mu sync.Mutex
	base := f.srv.Handler
	f.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut || req.Method == http.MethodPost || req.Method == http.MethodDelete {
			mu.Lock()
			writes++
			mu.Unlock()
		}
		base.ServeHTTP(w, req)
	})

	r := New(f.socket)
	ctx := context.Background()
	routes := []Route{{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:1"}}
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync 1: %v", err)
	}
	mu.Lock()
	afterFirst := writes
	mu.Unlock()
	if afterFirst == 0 {
		t.Fatalf("first sync did no writes")
	}

	// Identical sync: expect no server PUT/POST/DELETE (ensureServersPath is a
	// no-op GET now that servers exists).
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync 2: %v", err)
	}
	mu.Lock()
	afterSecond := writes
	mu.Unlock()
	if afterSecond != afterFirst {
		t.Errorf("unchanged sync wrote %d extra requests, want 0", afterSecond-afterFirst)
	}
}

func TestCurrentEmpty(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket)
	cur, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current on empty: %v", err)
	}
	if len(cur) != 0 {
		t.Errorf("current = %d, want 0", len(cur))
	}
}

func TestSyncEmptyRoutesClearsAf(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket)
	ctx := context.Background()
	r.Sync(ctx, []Route{{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:1"}})
	if err := r.Sync(ctx, nil); err != nil {
		t.Fatalf("Sync empty: %v", err)
	}
	cur, _ := r.Current(ctx)
	if len(cur) != 0 {
		t.Errorf("af servers not cleared: %+v", cur)
	}
}

func TestParseListenPort(t *testing.T) {
	cases := map[string]int{
		":18810":         18810,
		"0.0.0.0:443":    443,
		"127.0.0.1:8080": 8080,
		"":               0,
		"noport":         0,
	}
	// deterministic order
	keys := make([]string, 0, len(cases))
	for k := range cases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, in := range keys {
		got := parseListenPort([]string{in})
		if got != cases[in] {
			t.Errorf("parseListenPort(%q) = %d, want %d", in, got, cases[in])
		}
	}
}
