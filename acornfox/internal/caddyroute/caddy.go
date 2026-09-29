package caddyroute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// serverPrefix is the name prefix of every Caddy HTTP server AcornFox owns.
const serverPrefix = "af-"

// caddyRouter talks to the Caddy admin API over a Unix socket. It manages only
// the "af-<app>" HTTP servers and never touches any other part of the Caddy
// configuration.
type caddyRouter struct {
	socket string
	client *http.Client
}

// New returns a Router that reaches Caddy's admin API on the given Unix socket.
func New(adminSocket string) Router {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", adminSocket)
		},
	}
	return &caddyRouter{
		socket: adminSocket,
		client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}
}

// caddyServer is the subset of a Caddy HTTP server we read and write.
type caddyServer struct {
	Listen         []string        `json:"listen"`
	Routes         []caddyRoute    `json:"routes,omitempty"`
	AutomaticHTTPS *automaticHTTPS `json:"automatic_https,omitempty"`
}

type automaticHTTPS struct {
	Disable bool `json:"disable"`
}

type caddyRoute struct {
	Handle []caddyHandler `json:"handle"`
}

type caddyHandler struct {
	Handler   string          `json:"handler"`
	Upstreams []caddyUpstream `json:"upstreams,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

// Current reads Caddy's HTTP servers and returns the "af-*" routes keyed by app.
func (c *caddyRouter) Current(ctx context.Context) (map[string]Route, error) {
	servers, err := c.getServers(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]Route{}
	for name, srv := range servers {
		if !strings.HasPrefix(name, serverPrefix) {
			continue
		}
		app := strings.TrimPrefix(name, serverPrefix)
		route := Route{App: app}
		route.PublicPort = parseListenPort(srv.Listen)
		route.Upstream = firstUpstream(srv.Routes)
		out[app] = route
	}
	return out, nil
}

// Sync makes the set of "af-*" servers exactly equal to routes. It creates the
// apps.http.servers path if the Caddy config is empty, updates or inserts the
// desired servers, deletes stale "af-*" servers, and skips servers that already
// match. Non-"af-*" servers are never touched.
func (c *caddyRouter) Sync(ctx context.Context, routes []Route) error {
	if err := c.ensureServersPath(ctx); err != nil {
		return err
	}
	current, err := c.getServers(ctx)
	if err != nil {
		return err
	}

	desired := make(map[string]caddyServer, len(routes))
	for _, r := range routes {
		desired[serverPrefix+r.App] = desiredServer(r)
	}

	// Delete "af-*" servers that are no longer desired.
	for name := range current {
		if !strings.HasPrefix(name, serverPrefix) {
			continue
		}
		if _, ok := desired[name]; !ok {
			if err := c.deleteServer(ctx, name); err != nil {
				return err
			}
		}
	}

	// Create or update desired servers, skipping unchanged ones. Sort names so
	// behaviour is deterministic (useful for tests and logs).
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		want := desired[name]
		if have, ok := current[name]; ok && serverEqual(have, want) {
			continue
		}
		if err := c.putServer(ctx, name, want); err != nil {
			return err
		}
	}
	return nil
}

// desiredServer builds the Caddy server config for one route.
func desiredServer(r Route) caddyServer {
	return caddyServer{
		Listen: []string{fmt.Sprintf(":%d", r.PublicPort)},
		Routes: []caddyRoute{{
			Handle: []caddyHandler{{
				Handler:   "reverse_proxy",
				Upstreams: []caddyUpstream{{Dial: r.Upstream}},
			}},
		}},
		AutomaticHTTPS: &automaticHTTPS{Disable: true},
	}
}

// serverEqual reports whether an observed server already matches the desired
// one on the fields AcornFox controls.
func serverEqual(a, b caddyServer) bool {
	if parseListenPort(a.Listen) != parseListenPort(b.Listen) {
		return false
	}
	if firstUpstream(a.Routes) != firstUpstream(b.Routes) {
		return false
	}
	aDisabled := a.AutomaticHTTPS != nil && a.AutomaticHTTPS.Disable
	bDisabled := b.AutomaticHTTPS != nil && b.AutomaticHTTPS.Disable
	return aDisabled == bDisabled
}

// getServers reads /config/apps/http/servers, tolerating a null/empty config.
func (c *caddyRouter) getServers(ctx context.Context) (map[string]caddyServer, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/config/apps/http/servers", nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return map[string]caddyServer{}, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("caddy get servers: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	if len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "null" {
		return map[string]caddyServer{}, nil
	}
	var servers map[string]caddyServer
	if err := json.Unmarshal(body, &servers); err != nil {
		return nil, fmt.Errorf("caddy decode servers: %w", err)
	}
	if servers == nil {
		servers = map[string]caddyServer{}
	}
	return servers, nil
}

// ensureServersPath makes sure /config/apps/http/servers exists so that
// per-server PUT/POST/DELETE calls succeed. It never clobbers existing
// non-"af-*" servers: it only creates the container when it is missing or null.
func (c *caddyRouter) ensureServersPath(ctx context.Context) error {
	body, status, err := c.do(ctx, http.MethodGet, "/config/apps/http/servers", nil)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		trimmed := string(bytes.TrimSpace(body))
		if trimmed != "" && trimmed != "null" {
			return nil // servers object already present
		}
	} else if status != http.StatusNotFound {
		return fmt.Errorf("caddy probe servers: status %d: %s", status, strings.TrimSpace(string(body)))
	}

	// The servers object is missing or null. Read the whole config to decide
	// whether we can PUT just the servers node or must build the apps.http
	// scaffold from scratch without disturbing other apps.
	rootBody, rootStatus, err := c.do(ctx, http.MethodGet, "/config/", nil)
	if err != nil {
		return err
	}
	if rootStatus < 200 || rootStatus >= 300 {
		return fmt.Errorf("caddy get config: status %d: %s", rootStatus, strings.TrimSpace(string(rootBody)))
	}
	var root map[string]json.RawMessage
	trimmedRoot := bytes.TrimSpace(rootBody)
	if len(trimmedRoot) != 0 && string(trimmedRoot) != "null" {
		if err := json.Unmarshal(rootBody, &root); err != nil {
			return fmt.Errorf("caddy decode config: %w", err)
		}
	}
	if root == nil {
		root = map[string]json.RawMessage{}
	}

	empty, _ := json.Marshal(map[string]caddyServer{})

	appsRaw, hasApps := root["apps"]
	if !hasApps || isNullOrEmpty(appsRaw) {
		// No apps at all: create apps.http.servers wholesale.
		payload := map[string]any{
			"http": map[string]any{
				"servers": map[string]caddyServer{},
			},
		}
		return c.putJSON(ctx, "/config/apps", payload)
	}

	var apps map[string]json.RawMessage
	if err := json.Unmarshal(appsRaw, &apps); err != nil {
		return fmt.Errorf("caddy decode apps: %w", err)
	}
	httpRaw, hasHTTP := apps["http"]
	if !hasHTTP || isNullOrEmpty(httpRaw) {
		// apps exists but http is absent: add just the http app.
		payload := map[string]any{
			"servers": map[string]caddyServer{},
		}
		return c.putJSON(ctx, "/config/apps/http", payload)
	}
	// apps.http exists but its servers node is missing/null: set only servers,
	// leaving other apps.http keys intact.
	return c.putRaw(ctx, "/config/apps/http/servers", empty)
}

// isNullOrEmpty reports whether a raw JSON value is absent, null, or empty.
func isNullOrEmpty(raw json.RawMessage) bool {
	t := string(bytes.TrimSpace(raw))
	return t == "" || t == "null"
}

// putServer writes one server. PUT replaces the value at an existing path and
// creates it when absent, which is exactly the idempotent behaviour we want.
func (c *caddyRouter) putServer(ctx context.Context, name string, srv caddyServer) error {
	return c.putJSON(ctx, "/config/apps/http/servers/"+name, srv)
}

// deleteServer removes one server by name.
func (c *caddyRouter) deleteServer(ctx context.Context, name string) error {
	body, status, err := c.do(ctx, http.MethodDelete, "/config/apps/http/servers/"+name, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("caddy delete %s: status %d: %s", name, status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *caddyRouter) putJSON(ctx context.Context, path string, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("caddy marshal %s: %w", path, err)
	}
	return c.putRaw(ctx, path, payload)
}

// putRaw sets the object at path, creating or replacing it. Caddy's admin API
// uses POST for "set or replace" on object keys; PUT means "create" and fails
// with "key already exists" when the key is present.
func (c *caddyRouter) putRaw(ctx context.Context, path string, payload []byte) error {
	body, status, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("caddy set %s: status %d: %s", path, status, strings.TrimSpace(string(body)))
	}
	return nil
}

// do performs one admin API request. The unix socket is dialed by the client's
// transport, so the host in the URL is a fixed placeholder.
func (c *caddyRouter) do(ctx context.Context, method, path string, payload []byte) ([]byte, int, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://caddy"+path, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("caddy new request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("caddy request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("caddy read body: %w", err)
	}
	return body, resp.StatusCode, nil
}

// parseListenPort extracts the port from the first ":<port>" listen address.
func parseListenPort(listen []string) int {
	for _, l := range listen {
		idx := strings.LastIndex(l, ":")
		if idx < 0 {
			continue
		}
		portStr := l[idx+1:]
		port := 0
		for _, r := range portStr {
			if r < '0' || r > '9' {
				port = 0
				break
			}
			port = port*10 + int(r-'0')
		}
		if port > 0 {
			return port
		}
	}
	return 0
}

// firstUpstream returns the dial address of the first reverse_proxy upstream.
func firstUpstream(routes []caddyRoute) string {
	for _, r := range routes {
		for _, h := range r.Handle {
			if h.Handler != "reverse_proxy" {
				continue
			}
			if len(h.Upstreams) > 0 {
				return h.Upstreams[0].Dial
			}
		}
	}
	return ""
}
