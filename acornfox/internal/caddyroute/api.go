// Package caddyroute projects AcornFox app routes into Caddy through its admin
// API (Unix socket). AcornFox owns only HTTP servers named "af-<app>"; every
// other part of the Caddy configuration is left untouched.
package caddyroute

import "context"

// Route exposes one app: Caddy listens on ":PublicPort" and reverse-proxies to
// Upstream ("127.0.0.1:<host port of the live container>"). Automatic HTTPS is
// disabled for these servers in N1 (domains and certificates arrive in N3).
type Route struct {
	App        string `json:"app"`
	PublicPort int    `json:"public_port"`
	Upstream   string `json:"upstream"`
}

// Router is what the reconciler depends on.
type Router interface {
	// Sync makes the set of "af-*" servers in Caddy exactly equal to routes
	// (create, update, delete). Idempotent; a no-op when already equal.
	Sync(ctx context.Context, routes []Route) error
	// Current returns the "af-*" routes Caddy currently has, keyed by app.
	Current(ctx context.Context) (map[string]Route, error)
}
