package caddyroute

import (
	"context"
	"fmt"
)

// verifyServer is the temporary plain-HTTP server that answers the domain
// ownership challenge of the public console (ADR-0016). Its name deliberately
// lacks the "af-" prefix so Sync never deletes it mid-verification.
const verifyServer = "acornfox-verify"

// Verifier serves a one-off HTTP challenge on the HTTP port so a client can
// prove that a domain really reaches this server.
type Verifier interface {
	// SetChallenge answers GET http://host/path with body (text/plain).
	// Calling it again replaces the previous challenge.
	SetChallenge(ctx context.Context, host, path, body string) error
	// ClearChallenge removes the challenge server; a no-op when absent.
	ClearChallenge(ctx context.Context) error
}

// NewVerifier returns a Verifier that reaches Caddy's admin API on the given
// Unix socket. The challenge listens on https.HTTPPort (default 80).
func NewVerifier(adminSocket string, https HTTPSConfig) Verifier {
	return New(adminSocket, https).(*caddyRouter)
}

// SetChallenge implements Verifier. The server listens only on the HTTP port,
// so Caddy's automatic HTTPS leaves it alone; when the shared domains server
// exists Caddy adds its HTTP->HTTPS redirects behind our terminal route.
func (c *caddyRouter) SetChallenge(ctx context.Context, host, path, body string) error {
	if err := c.ensureServersPath(ctx); err != nil {
		return err
	}
	srv := map[string]any{
		"listen": []string{fmt.Sprintf(":%d", c.https.HTTPPort)},
		"routes": []any{map[string]any{
			"match": []any{map[string]any{"host": []string{host}, "path": []string{path}}},
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 200,
				"body":        body,
				"headers": map[string][]string{
					"Content-Type":  {"text/plain; charset=utf-8"},
					"Cache-Control": {"no-store"},
				},
			}},
			"terminal": true,
		}},
	}
	return c.putJSON(ctx, "/config/apps/http/servers/"+verifyServer, srv)
}

// ClearChallenge implements Verifier.
func (c *caddyRouter) ClearChallenge(ctx context.Context) error {
	servers, err := c.getServers(ctx)
	if err != nil {
		return err
	}
	if _, ok := servers[verifyServer]; !ok {
		return nil
	}
	return c.deleteServer(ctx, verifyServer)
}
