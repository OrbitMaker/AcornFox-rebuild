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

// domainsServer is the fixed name of the shared HTTPS server that host-matches
// every app's custom domains. It is created only when at least one route has
// Domains and deleted when none do.
const domainsServer = "af-domains"

// tlsPolicyID is the @id tag of the single automation policy AcornFox owns
// inside apps.tls.automation.policies. It lets us find, replace and delete our
// policy through Caddy's /id/<@id> path without touching foreign policies.
const tlsPolicyID = "af-tls-policy"

// Default HTTPS ports used when HTTPSConfig leaves them at zero.
const (
	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
)

// caddyRouter talks to the Caddy admin API over a Unix socket. It manages only
// the "af-<app>" HTTP servers (one per app), the shared "af-domains" server,
// and its own "af-tls-policy" TLS automation policy. Every other part of the
// Caddy configuration is left untouched.
type caddyRouter struct {
	socket string
	client *http.Client
	https  HTTPSConfig
}

// New returns a Router that reaches Caddy's admin API on the given Unix socket.
// https configures the shared "af-domains" HTTPS server; zero HTTPPort/HTTPSPort
// fall back to 80/443.
func New(adminSocket string, https HTTPSConfig) Router {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", adminSocket)
		},
	}
	if https.HTTPPort == 0 {
		https.HTTPPort = defaultHTTPPort
	}
	if https.HTTPSPort == 0 {
		https.HTTPSPort = defaultHTTPSPort
	}
	return &caddyRouter{
		socket: adminSocket,
		client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
		https:  https,
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
	Match  []caddyMatch   `json:"match,omitempty"`
	Handle []caddyHandler `json:"handle"`
}

// caddyMatch is a route matcher set; we only use host matching.
type caddyMatch struct {
	Host []string `json:"host,omitempty"`
}

type caddyHandler struct {
	Handler   string          `json:"handler"`
	Upstreams []caddyUpstream `json:"upstreams,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

// tlsAutomationPolicy is one entry of apps.tls.automation.policies. AcornFox
// owns exactly one, tagged with @id "af-tls-policy".
type tlsAutomationPolicy struct {
	ID       string      `json:"@id,omitempty"`
	Subjects []string    `json:"subjects,omitempty"`
	Issuers  []tlsIssuer `json:"issuers,omitempty"`
}

// tlsIssuer is the subset of a certificate issuer module we emit: the internal
// Caddy CA, or ACME with an optional account email.
type tlsIssuer struct {
	Module string `json:"module"`          // "internal" or "acme"
	Email  string `json:"email,omitempty"` // ACME account email
}

// Current reads Caddy's HTTP servers and returns the "af-*" routes keyed by
// app. Per-app HTTP servers ("af-<app>") report PublicPort and Upstream; the
// shared "af-domains" server contributes each app's Domains, matched back to
// the app by upstream dial address.
func (c *caddyRouter) Current(ctx context.Context) (map[string]Route, error) {
	servers, err := c.getServers(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]Route{}
	for name, srv := range servers {
		if name == domainsServer || !strings.HasPrefix(name, serverPrefix) {
			continue
		}
		app := strings.TrimPrefix(name, serverPrefix)
		route := Route{App: app}
		route.PublicPort = parseListenPort(srv.Listen)
		route.Upstream = firstUpstream(srv.Routes)
		out[app] = route
	}
	// Fold domains from the shared server back onto their apps by upstream.
	if dom, ok := servers[domainsServer]; ok {
		byUpstream := map[string]string{} // upstream dial -> app
		for app, r := range out {
			if r.Upstream != "" {
				byUpstream[r.Upstream] = app
			}
		}
		for _, rt := range dom.Routes {
			hosts := routeHosts(rt)
			up := routeUpstream(rt)
			if len(hosts) == 0 || up == "" {
				continue
			}
			app, ok := byUpstream[up]
			if !ok {
				continue
			}
			r := out[app]
			r.Domains = append(r.Domains, hosts...)
			out[app] = r
		}
	}
	return out, nil
}

// Sync makes the set of "af-*" servers exactly equal to routes. It creates the
// apps.http.servers path if the Caddy config is empty, updates or inserts the
// desired per-app servers, deletes stale "af-*" servers, and skips servers that
// already match. It also maintains the shared "af-domains" HTTPS server and our
// single TLS automation policy. Non-"af-*" servers and foreign TLS policies are
// never touched.
func (c *caddyRouter) Sync(ctx context.Context, routes []Route) error {
	if err := c.ensureServersPath(ctx); err != nil {
		return err
	}
	current, err := c.getServers(ctx)
	if err != nil {
		return err
	}

	// Per-app servers are keyed "af-<app>". The shared "af-domains" server is
	// derived from every route that carries Domains and is handled separately.
	desired := make(map[string]caddyServer, len(routes)+1)
	for _, r := range routes {
		desired[serverPrefix+r.App] = desiredServer(r)
	}
	allDomains := collectDomains(routes)
	if len(allDomains) > 0 {
		desired[domainsServer] = c.desiredDomainsServer(routes)
		// Caddy's automatic HTTPS opens the HTTP and HTTPS ports globally (for
		// the redirect and ACME challenges). Point them at our configured ports
		// so development can avoid privileged 80/443.
		if err := c.ensureHTTPPorts(ctx); err != nil {
			return err
		}
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

	// Maintain our TLS automation policy last so it reflects the final domain
	// set. It exists only for the internal issuer or an ACME email account.
	return c.syncTLSPolicy(ctx, allDomains)
}

// collectDomains returns the sorted, de-duplicated union of every route's
// Domains.
func collectDomains(routes []Route) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range routes {
		for _, d := range r.Domains {
			if d == "" {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// ensureHTTPPorts sets apps.http.http_port and apps.http.https_port to the
// configured ports when they differ from what Caddy already has. These global
// options control the ports automatic HTTPS uses for the HTTP->HTTPS redirect
// and the HTTPS listener, letting development avoid privileged 80/443. Defaults
// (80/443) are left implicit so we do not write when unnecessary.
func (c *caddyRouter) ensureHTTPPorts(ctx context.Context) error {
	if err := c.ensureHTTPPort(ctx, "http_port", c.https.HTTPPort, defaultHTTPPort); err != nil {
		return err
	}
	return c.ensureHTTPPort(ctx, "https_port", c.https.HTTPSPort, defaultHTTPSPort)
}

func (c *caddyRouter) ensureHTTPPort(ctx context.Context, field string, port, def int) error {
	// Read the current value; only write when it differs from what we want.
	body, status, err := c.do(ctx, http.MethodGet, "/config/apps/http/"+field, nil)
	if err != nil {
		return err
	}
	have := 0
	if status >= 200 && status < 300 {
		t := string(bytes.TrimSpace(body))
		if t != "" && t != "null" {
			_ = json.Unmarshal(body, &have)
		}
	} else if status != http.StatusNotFound {
		return fmt.Errorf("caddy get %s: status %d: %s", field, status, strings.TrimSpace(string(body)))
	}
	// Caddy treats an unset field as the default.
	if have == 0 {
		have = def
	}
	if have == port {
		return nil
	}
	// apps.http must exist by now (ensureServersPath ran first).
	return c.putJSON(ctx, "/config/apps/http/"+field, port)
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

// desiredDomainsServer builds the shared "af-domains" server: it listens on the
// HTTP and HTTPS ports and host-matches each app's domains to that app's
// upstream. Automatic HTTPS stays enabled (the default), so Caddy obtains
// certificates and redirects HTTP to HTTPS itself. Routes are emitted in a
// deterministic order (by app, then upstream) so serverEqual sees a stable
// shape.
func (c *caddyRouter) desiredDomainsServer(routes []Route) caddyServer {
	withDomains := make([]Route, 0, len(routes))
	for _, r := range routes {
		if len(r.Domains) == 0 {
			continue
		}
		withDomains = append(withDomains, r)
	}
	sort.Slice(withDomains, func(i, j int) bool {
		if withDomains[i].App != withDomains[j].App {
			return withDomains[i].App < withDomains[j].App
		}
		return withDomains[i].Upstream < withDomains[j].Upstream
	})
	croutes := make([]caddyRoute, 0, len(withDomains))
	for _, r := range withDomains {
		hosts := append([]string(nil), r.Domains...)
		sort.Strings(hosts)
		croutes = append(croutes, caddyRoute{
			Match: []caddyMatch{{Host: hosts}},
			Handle: []caddyHandler{{
				Handler:   "reverse_proxy",
				Upstreams: []caddyUpstream{{Dial: r.Upstream}},
			}},
		})
	}
	return caddyServer{
		Listen: []string{
			fmt.Sprintf(":%d", c.https.HTTPPort),
			fmt.Sprintf(":%d", c.https.HTTPSPort),
		},
		Routes: croutes,
	}
}

// serverEqual reports whether an observed server already matches the desired
// one on the fields AcornFox controls. The shared "af-domains" server has
// multiple host-matched routes, so it is compared route by route; per-app
// servers keep the simpler single-upstream comparison.
func serverEqual(a, b caddyServer) bool {
	if !samePorts(a.Listen, b.Listen) {
		return false
	}
	aDisabled := a.AutomaticHTTPS != nil && a.AutomaticHTTPS.Disable
	bDisabled := b.AutomaticHTTPS != nil && b.AutomaticHTTPS.Disable
	if aDisabled != bDisabled {
		return false
	}
	// Multi-route (domains) servers: compare the full set of host->upstream
	// pairs regardless of order.
	if len(a.Routes) > 1 || len(b.Routes) > 1 || hasHostMatch(a.Routes) || hasHostMatch(b.Routes) {
		return routePairsEqual(a.Routes, b.Routes)
	}
	return firstUpstream(a.Routes) == firstUpstream(b.Routes)
}

// samePorts reports whether two listen lists carry the same set of ports.
func samePorts(a, b []string) bool {
	pa := listenPorts(a)
	pb := listenPorts(b)
	if len(pa) != len(pb) {
		return false
	}
	for k := range pa {
		if pa[k] != pb[k] {
			return false
		}
	}
	return true
}

func listenPorts(listen []string) map[int]int {
	m := map[int]int{}
	for _, l := range listen {
		if p := parseListenPort([]string{l}); p > 0 {
			m[p]++
		}
	}
	return m
}

func hasHostMatch(routes []caddyRoute) bool {
	for _, r := range routes {
		if len(routeHosts(r)) > 0 {
			return true
		}
	}
	return false
}

// routePairsEqual compares two route sets as unordered "host1,host2=>upstream"
// pairs.
func routePairsEqual(a, b []caddyRoute) bool {
	sa := routePairSet(a)
	sb := routePairSet(b)
	if len(sa) != len(sb) {
		return false
	}
	for k, v := range sa {
		if sb[k] != v {
			return false
		}
	}
	return true
}

func routePairSet(routes []caddyRoute) map[string]int {
	set := map[string]int{}
	for _, r := range routes {
		hosts := append([]string(nil), routeHosts(r)...)
		sort.Strings(hosts)
		key := strings.Join(hosts, ",") + "=>" + routeUpstream(r)
		set[key]++
	}
	return set
}

// routeHosts returns the host matchers of a route (may be empty).
func routeHosts(r caddyRoute) []string {
	var hosts []string
	for _, m := range r.Match {
		hosts = append(hosts, m.Host...)
	}
	return hosts
}

// routeUpstream returns the first reverse_proxy upstream of a single route.
func routeUpstream(r caddyRoute) string {
	for _, h := range r.Handle {
		if h.Handler == "reverse_proxy" && len(h.Upstreams) > 0 {
			return h.Upstreams[0].Dial
		}
	}
	return ""
}

// syncTLSPolicy maintains AcornFox's single automation policy inside
// apps.tls.automation.policies. It creates the scaffolding when absent, sets or
// replaces our "af-tls-policy" object, and removes it when there are no domains
// or the configured issuer is neither the internal CA nor an ACME email
// account. Foreign policies are never touched.
func (c *caddyRouter) syncTLSPolicy(ctx context.Context, domains []string) error {
	want := c.desiredTLSPolicy(domains)
	if want == nil {
		// Only issue a DELETE when our policy actually exists, so an unchanged
		// no-domains Sync performs zero writes.
		exists, err := c.getTLSPolicyByID(ctx)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		return c.deleteTLSPolicy(ctx)
	}
	if err := c.ensureTLSPoliciesPath(ctx); err != nil {
		return err
	}
	// Replace our policy in place when it already exists (found by @id), else
	// append it to the policies array without disturbing foreign entries.
	existing, err := c.getTLSPolicyByID(ctx)
	if err != nil {
		return err
	}
	if existing {
		return c.putJSON(ctx, "/id/"+tlsPolicyID, want)
	}
	// Append via the array's "..." path so foreign policies survive.
	return c.appendRaw(ctx, "/config/apps/tls/automation/policies/...", []tlsAutomationPolicy{*want})
}

// desiredTLSPolicy returns the automation policy AcornFox wants, or nil when we
// should own no policy (no domains, or an issuer we do not manage).
func (c *caddyRouter) desiredTLSPolicy(domains []string) *tlsAutomationPolicy {
	if len(domains) == 0 {
		return nil
	}
	switch c.https.Issuer {
	case "internal":
		return &tlsAutomationPolicy{
			ID:       tlsPolicyID,
			Subjects: domains,
			Issuers:  []tlsIssuer{{Module: "internal"}},
		}
	case "", "acme":
		// Public ACME is Caddy's default; we only need an explicit policy when
		// an account email is configured. Otherwise own no policy.
		if c.https.Email == "" {
			return nil
		}
		return &tlsAutomationPolicy{
			ID:       tlsPolicyID,
			Subjects: domains,
			Issuers:  []tlsIssuer{{Module: "acme", Email: c.https.Email}},
		}
	default:
		return nil
	}
}

// getTLSPolicyByID reports whether our @id-tagged policy already exists.
func (c *caddyRouter) getTLSPolicyByID(ctx context.Context) (bool, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/id/"+tlsPolicyID, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status < 200 || status >= 300 {
		return false, fmt.Errorf("caddy get tls policy: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	t := string(bytes.TrimSpace(body))
	return t != "" && t != "null", nil
}

// deleteTLSPolicy removes our policy if present. Deleting by @id keeps foreign
// policies intact.
func (c *caddyRouter) deleteTLSPolicy(ctx context.Context) error {
	body, status, err := c.do(ctx, http.MethodDelete, "/id/"+tlsPolicyID, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("caddy delete tls policy: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

// ensureTLSPoliciesPath creates apps.tls.automation.policies as an empty array
// when any level is missing or null, never clobbering existing policies. Caddy
// returns an error (not 404) when traversing into a missing intermediate key,
// so each level is probed from the top down.
func (c *caddyRouter) ensureTLSPoliciesPath(ctx context.Context) error {
	// Probe apps.tls. A missing/null/erroring value means create the whole app.
	tlsBody, tlsStatus, err := c.do(ctx, http.MethodGet, "/config/apps/tls", nil)
	if err != nil {
		return err
	}
	if !okBody(tlsStatus, tlsBody) {
		return c.putJSON(ctx, "/config/apps/tls", map[string]any{
			"automation": map[string]any{"policies": []tlsAutomationPolicy{}},
		})
	}

	// apps.tls exists: inspect its automation node from the fetched body so we
	// avoid a traversal into a possibly-missing key.
	var tlsApp map[string]json.RawMessage
	if uerr := json.Unmarshal(tlsBody, &tlsApp); uerr != nil {
		return fmt.Errorf("caddy decode tls app: %w", uerr)
	}
	autoRaw, hasAuto := tlsApp["automation"]
	if !hasAuto || isNullOrEmpty(autoRaw) {
		return c.putJSON(ctx, "/config/apps/tls/automation", map[string]any{
			"policies": []tlsAutomationPolicy{},
		})
	}
	var auto map[string]json.RawMessage
	if uerr := json.Unmarshal(autoRaw, &auto); uerr != nil {
		return fmt.Errorf("caddy decode tls automation: %w", uerr)
	}
	polRaw, hasPol := auto["policies"]
	if !hasPol || isNullOrEmpty(polRaw) {
		empty, _ := json.Marshal([]tlsAutomationPolicy{})
		return c.putRaw(ctx, "/config/apps/tls/automation/policies", empty)
	}
	return nil // policies array already present
}

// okBody reports whether a GET returned a usable, non-null body.
func okBody(status int, body []byte) bool {
	if status < 200 || status >= 300 {
		return false
	}
	t := string(bytes.TrimSpace(body))
	return t != "" && t != "null"
}

// appendRaw POSTs to an array's "..." path, appending the given elements
// without replacing existing entries.
func (c *caddyRouter) appendRaw(ctx context.Context, path string, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("caddy marshal %s: %w", path, err)
	}
	body, status, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("caddy append %s: status %d: %s", path, status, strings.TrimSpace(string(body)))
	}
	return nil
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
