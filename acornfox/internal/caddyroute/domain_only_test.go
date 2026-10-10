package caddyroute

import (
	"context"
	"testing"
)

// A domain-only route (PublicPort 0) gets no "af-<app>" server, sits on the
// shared domains server with an @id, and comes back from Current.
func TestSyncDomainOnlyRoute(t *testing.T) {
	f := startFakeCaddy(t, nil)
	r := New(f.socket, HTTPSConfig{})
	ctx := context.Background()

	routes := []Route{
		{App: "web", PublicPort: 18810, Upstream: "127.0.0.1:32001"},
		{App: "_public-console", Upstream: "127.0.0.1:18801", Domains: []string{"panel.example.com"}},
	}
	if err := r.Sync(ctx, routes); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	servers := f.servers()
	if _, ok := servers["af-_public-console"]; ok {
		t.Fatal("domain-only route must not get a per-app server")
	}
	dom, ok := servers[domainsServer].(map[string]any)
	if !ok {
		t.Fatal("af-domains server missing")
	}
	rts := dom["routes"].([]any)
	if len(rts) != 1 || rts[0].(map[string]any)["@id"] != "af-route-_public-console" {
		t.Fatalf("domains routes = %v", rts)
	}

	cur, err := r.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	got := cur["_public-console"]
	if got.Upstream != "127.0.0.1:18801" || len(got.Domains) != 1 || got.Domains[0] != "panel.example.com" || got.PublicPort != 0 {
		t.Fatalf("console route = %+v", got)
	}
	if cur["web"].PublicPort != 18810 {
		t.Fatalf("web route = %+v", cur["web"])
	}

	// Dropping the domain-only route removes the domains server again.
	if err := r.Sync(ctx, routes[:1]); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, ok := f.servers()[domainsServer]; ok {
		t.Fatal("af-domains should be gone without domains")
	}
}

func TestVerifierSetAndClear(t *testing.T) {
	f := startFakeCaddy(t, nil)
	v := NewVerifier(f.socket, HTTPSConfig{HTTPPort: 8080})
	ctx := context.Background()

	if err := v.SetChallenge(ctx, "panel.example.com", "/.well-known/acornfox-verify/abc", "tok"); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}
	srv, ok := f.servers()[verifyServer].(map[string]any)
	if !ok {
		t.Fatal("verify server missing")
	}
	if l := srv["listen"].([]any); len(l) != 1 || l[0] != ":8080" {
		t.Fatalf("listen = %v", l)
	}
	route := srv["routes"].([]any)[0].(map[string]any)
	h := route["handle"].([]any)[0].(map[string]any)
	if h["handler"] != "static_response" || h["body"] != "tok" {
		t.Fatalf("handler = %v", h)
	}

	// Sync never touches the verify server (no "af-" prefix).
	r := New(f.socket, HTTPSConfig{})
	if err := r.Sync(ctx, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, ok := f.servers()[verifyServer]; !ok {
		t.Fatal("Sync deleted the verify server")
	}

	if err := v.ClearChallenge(ctx); err != nil {
		t.Fatalf("ClearChallenge: %v", err)
	}
	if _, ok := f.servers()[verifyServer]; ok {
		t.Fatal("verify server still present")
	}
	if err := v.ClearChallenge(ctx); err != nil {
		t.Fatalf("second ClearChallenge: %v", err)
	}
}
