package caddyroute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

// getPath descends the config by the admin path. Numeric segments index into
// arrays; string segments index into maps.
func (f *fakeCaddy) getPath(path string) (any, bool) {
	if path == "/config/" || path == "/config" {
		return f.config, true
	}
	rel := path[len("/config/"):]
	parts := splitPath(rel)
	var cur any = f.config
	for _, p := range parts {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[p]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
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

// setPath creates intermediate maps and sets the value at path. Numeric final
// segments set an array element by index; numeric intermediate segments index
// into existing arrays.
func (f *fakeCaddy) setPath(path string, val any) {
	rel := path[len("/config/"):]
	parts := splitPath(rel)
	var cur any = f.config
	for i, p := range parts {
		last := i == len(parts)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				node[p] = val
				return
			}
			next, ok := node[p]
			if !ok {
				nm := map[string]any{}
				node[p] = nm
				cur = nm
				continue
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(node) {
				return
			}
			if last {
				node[idx] = val
				return
			}
			cur = node[idx]
		default:
			return
		}
	}
}

func (f *fakeCaddy) deletePath(path string) {
	rel := path[len("/config/"):]
	parts := splitPath(rel)
	// Walk to the parent of the final segment, tracking it so we can rewrite an
	// array (delete-by-index splices) or a map (delete key).
	var parent any = f.config
	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		switch node := parent.(type) {
		case map[string]any:
			next, ok := node[p]
			if !ok {
				return
			}
			parent = next
		case []any:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(node) {
				return
			}
			parent = node[idx]
		default:
			return
		}
	}
	last := parts[len(parts)-1]
	switch node := parent.(type) {
	case map[string]any:
		delete(node, last)
	case []any:
		idx, err := strconv.Atoi(last)
		if err != nil || idx < 0 || idx >= len(node) {
			return
		}
		// Splice out the element; write the shortened slice back into its
		// grandparent so the deletion is observed.
		spliced := append(node[:idx], node[idx+1:]...)
		f.setSlice(parts[:len(parts)-1], spliced)
	}
}

// setSlice writes a slice value back at the given path parts (parent of a
// deleted array element).
func (f *fakeCaddy) setSlice(parts []string, val []any) {
	if len(parts) == 0 {
		return
	}
	f.setPath("/config/"+strings.Join(parts, "/"), val)
}

func (f *fakeCaddy) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// /id/<@id> resolves to the config path of the object tagged with that @id.
	path := r.URL.Path
	if strings.HasPrefix(path, "/id/") {
		id := strings.TrimPrefix(path, "/id/")
		resolved, ok := f.resolveID(id)
		if !ok {
			// Unknown @id: GET/DELETE => 404; PUT/POST would need a parent, also 404.
			http.Error(w, "unknown id", http.StatusNotFound)
			return
		}
		path = resolved
	}

	switch r.Method {
	case http.MethodGet:
		v, ok := f.getPath(path)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	case http.MethodPut, http.MethodPost, http.MethodPatch:
		body, _ := io.ReadAll(r.Body)
		var v any
		if len(body) > 0 {
			if err := json.Unmarshal(body, &v); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
		}
		// Array append: a path ending in "/..." appends elements to the array
		// at the parent path (real Caddy semantics).
		if strings.HasSuffix(path, "/...") {
			parent := strings.TrimSuffix(path, "/...")
			cur, _ := f.getPath(parent)
			arr, _ := cur.([]any)
			add, ok := v.([]any)
			if !ok {
				http.Error(w, "append expects array", http.StatusBadRequest)
				return
			}
			arr = append(arr, add...)
			f.setPath(parent, arr)
			w.WriteHeader(http.StatusOK)
			return
		}
		if _, exists := f.getPath(path); !exists && r.Method == http.MethodPatch {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// PATCH replaces an existing value; PUT creates; POST sets object keys.
		if _, exists := f.getPath(path); exists && r.Method == http.MethodPut {
			http.Error(w, `{"error":"key already exists"}`, http.StatusConflict)
			return
		}
		f.setPath(path, v)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if _, ok := f.getPath(path); !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		f.deletePath(path)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

// resolveID walks the config for an object (map) carrying "@id": id and returns
// its /config/... path. Arrays are indexed positionally, matching how Caddy
// addresses array elements.
func (f *fakeCaddy) resolveID(id string) (string, bool) {
	var walk func(node any, path string) (string, bool)
	walk = func(node any, path string) (string, bool) {
		switch n := node.(type) {
		case map[string]any:
			if v, ok := n["@id"]; ok {
				if s, ok := v.(string); ok && s == id {
					return path, true
				}
			}
			// Deterministic key order for stable resolution.
			keys := make([]string, 0, len(n))
			for k := range n {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if p, ok := walk(n[k], path+"/"+k); ok {
					return p, true
				}
			}
		case []any:
			for i, e := range n {
				if p, ok := walk(e, fmt.Sprintf("%s/%d", path, i)); ok {
					return p, true
				}
			}
		}
		return "", false
	}
	return walk(f.config, "/config")
}

func TestSyncFromEmptyConfig(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket, HTTPSConfig{})
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
	r := New(f.socket, HTTPSConfig{})
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
	r := New(f.socket, HTTPSConfig{})
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
	r := New(f.socket, HTTPSConfig{})
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
		if req.Method == http.MethodPut || req.Method == http.MethodPost || req.Method == http.MethodPatch || req.Method == http.MethodDelete {
			mu.Lock()
			writes++
			mu.Unlock()
		}
		base.ServeHTTP(w, req)
	})

	r := New(f.socket, HTTPSConfig{})
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
	r := New(f.socket, HTTPSConfig{})
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
	r := New(f.socket, HTTPSConfig{})
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

// ---------------------------------------------------------------------------
// N3: af-domains server and TLS automation policy
// ---------------------------------------------------------------------------

// tlsPolicies returns the raw apps.tls.automation.policies array (may be nil).
func (f *fakeCaddy) tlsPolicies() []any {
	f.mu.Lock()
	defer f.mu.Unlock()
	apps, _ := f.config["apps"].(map[string]any)
	tls, _ := apps["tls"].(map[string]any)
	auto, _ := tls["automation"].(map[string]any)
	pol, _ := auto["policies"].([]any)
	return pol
}

// afPolicy returns AcornFox's own policy (by @id), or nil.
func (f *fakeCaddy) afPolicy() map[string]any {
	for _, p := range f.tlsPolicies() {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if id, _ := m["@id"].(string); id == tlsPolicyID {
			return m
		}
	}
	return nil
}

func TestSyncCreatesDomainsServerInternalIssuer(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket, HTTPSConfig{HTTPPort: 18080, HTTPSPort: 18443, Issuer: "internal"})
	ctx := context.Background()

	routes := []Route{{
		App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001",
		Domains: []string{"notes.acornfox.test"},
	}}
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// App content is served on HTTPS only; Caddy owns the HTTP redirect listener.
	srv, ok := f.servers()[domainsServer].(map[string]any)
	if !ok {
		t.Fatalf("af-domains server not created")
	}
	listen := srv["listen"].([]any)
	if len(listen) != 1 || listen[0] != ":18443" {
		t.Fatalf("af-domains listen = %v, want HTTPS port only", listen)
	}
	// Automatic HTTPS must NOT be disabled on the domains server.
	if _, disabled := srv["automatic_https"]; disabled {
		t.Errorf("af-domains must keep automatic HTTPS enabled")
	}

	// TLS policy with our @id, subjects, internal issuer.
	pol := f.afPolicy()
	if pol == nil {
		t.Fatalf("af-tls-policy not created")
	}
	subs := pol["subjects"].([]any)
	if len(subs) != 1 || subs[0] != "notes.acornfox.test" {
		t.Errorf("policy subjects = %v", subs)
	}
	iss := pol["issuers"].([]any)[0].(map[string]any)
	if iss["module"] != "internal" {
		t.Errorf("issuer module = %v, want internal", iss["module"])
	}

	// Current reports the domain folded back onto the app.
	cur, _ := r.Current(ctx)
	if got := cur["notes"].Domains; len(got) != 1 || got[0] != "notes.acornfox.test" {
		t.Errorf("Current domains = %v", got)
	}
}

func TestSyncUpdatesDomainsAndPolicy(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket, HTTPSConfig{HTTPPort: 18080, HTTPSPort: 18443, Issuer: "internal"})
	ctx := context.Background()

	r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test"}}})
	// Add a second domain and a second app with a domain.
	if err := r.Sync(ctx, []Route{
		{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test", "b.test"}},
		{App: "blog", PublicPort: 18811, Upstream: "127.0.0.1:40002", Domains: []string{"c.test"}},
	}); err != nil {
		t.Fatalf("Sync update: %v", err)
	}

	srv := f.servers()[domainsServer].(map[string]any)
	routes := srv["routes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("af-domains routes = %d, want 2", len(routes))
	}
	pol := f.afPolicy()
	subs := pol["subjects"].([]any)
	if len(subs) != 3 {
		t.Errorf("policy subjects = %v, want 3", subs)
	}
}

func TestSyncDeletesDomainsServerAndPolicyWhenNoDomains(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket, HTTPSConfig{HTTPPort: 18080, HTTPSPort: 18443, Issuer: "internal"})
	ctx := context.Background()

	r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test"}}})
	if _, ok := f.servers()[domainsServer]; !ok {
		t.Fatalf("precondition: af-domains should exist")
	}
	// Second sync drops all domains (route keeps its per-app server).
	if err := r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001"}}); err != nil {
		t.Fatalf("Sync no domains: %v", err)
	}
	if _, ok := f.servers()[domainsServer]; ok {
		t.Errorf("af-domains server should be deleted when no domains")
	}
	if f.afPolicy() != nil {
		t.Errorf("af-tls-policy should be deleted when no domains")
	}
	// The per-app server survives.
	if _, ok := f.servers()["af-notes"]; !ok {
		t.Errorf("per-app server should survive domain removal")
	}
}

func TestSyncPreservesForeignServersAndPolicies(t *testing.T) {
	initial := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"user-site": map[string]any{"listen": []any{":8443"}},
				},
			},
			"tls": map[string]any{
				"automation": map[string]any{
					"policies": []any{
						map[string]any{
							"subjects": []any{"foreign.example.com"},
							"issuers":  []any{map[string]any{"module": "internal"}},
						},
					},
				},
			},
		},
	}
	f := startFakeCaddy(t, initial)
	r := New(f.socket, HTTPSConfig{HTTPPort: 18080, HTTPSPort: 18443, Issuer: "internal"})
	ctx := context.Background()

	if err := r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test"}}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// Foreign server intact.
	if _, ok := f.servers()["user-site"]; !ok {
		t.Errorf("foreign server clobbered")
	}
	// Foreign policy still present alongside ours.
	pols := f.tlsPolicies()
	if len(pols) != 2 {
		t.Fatalf("policies = %d, want 2 (foreign + ours)", len(pols))
	}
	var foreignFound bool
	for _, p := range pols {
		m := p.(map[string]any)
		if subs, _ := m["subjects"].([]any); len(subs) == 1 && subs[0] == "foreign.example.com" {
			foreignFound = true
		}
	}
	if !foreignFound {
		t.Errorf("foreign TLS policy was removed")
	}

	// Now remove our domains: foreign policy must remain, ours must go.
	if err := r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001"}}); err != nil {
		t.Fatalf("Sync no domains: %v", err)
	}
	pols = f.tlsPolicies()
	if len(pols) != 1 {
		t.Fatalf("after cleanup policies = %d, want 1 (foreign only)", len(pols))
	}
	if subs, _ := pols[0].(map[string]any)["subjects"].([]any); subs[0] != "foreign.example.com" {
		t.Errorf("foreign policy lost after our cleanup: %v", subs)
	}
}

func TestSyncDomainsIdempotentNoOp(t *testing.T) {
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

	r := New(f.socket, HTTPSConfig{HTTPPort: 18080, HTTPSPort: 18443, Issuer: "internal"})
	ctx := context.Background()
	routes := []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test", "b.test"}}}
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync 1: %v", err)
	}
	mu.Lock()
	afterFirst := writes
	mu.Unlock()

	// Identical sync: the servers are unchanged; only the TLS policy is
	// replaced by PATCH at its @id. Assert servers were not rewritten.
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync 2: %v", err)
	}
	mu.Lock()
	afterSecond := writes
	mu.Unlock()
	// At most one write (the policy PUT); the two af-* servers must be skipped.
	if afterSecond-afterFirst > 1 {
		t.Errorf("idempotent domains sync wrote %d extra requests, want <=1", afterSecond-afterFirst)
	}
}

func TestSyncACMEEmailPolicy(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket, HTTPSConfig{Issuer: "acme", Email: "ops@example.com"})
	ctx := context.Background()

	if err := r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test"}}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	pol := f.afPolicy()
	if pol == nil {
		t.Fatalf("acme email policy not created")
	}
	iss := pol["issuers"].([]any)[0].(map[string]any)
	if iss["module"] != "acme" || iss["email"] != "ops@example.com" {
		t.Errorf("acme issuer = %v", iss)
	}
}

func TestSyncACMENoEmailNoPolicy(t *testing.T) {
	f := startFakeCaddy(t, nil)
	// Default public ACME, no email: Caddy's defaults suffice, we own no policy.
	r := New(f.socket, HTTPSConfig{})
	ctx := context.Background()

	if err := r.Sync(ctx, []Route{{App: "notes", PublicPort: 18810, Upstream: "127.0.0.1:40001", Domains: []string{"a.test"}}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if f.afPolicy() != nil {
		t.Errorf("no policy expected for default public ACME without email")
	}
	// But the af-domains server is still created so the host is served.
	if _, ok := f.servers()[domainsServer]; !ok {
		t.Errorf("af-domains server should still be created")
	}
}
