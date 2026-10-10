package publicconsole

import (
	"context"

	"github.com/acornfox/acornfox/internal/caddyroute"
)

// RouteApp names the public console's domain-only route. It is not a valid
// app name (apps never start with "_"), so it cannot collide with an app.
const RouteApp = "_public-console"

// pendingKey marks a Current result that differs from what the console needs,
// forcing the reconciler to call Sync.
const pendingKey = "_public-console-pending"

// ConfigSource is what the router wrapper reads.
type ConfigSource interface {
	Load() (*Config, error)
}

// WrapRouter adds the public console's domain route to every Sync and hides it
// from Current, so the reconciler keeps managing only apps. When the console
// route is missing (Caddy restarted) or stale (console disabled), Current
// reports a difference and the reconciler's next round re-syncs.
func WrapRouter(inner caddyroute.Router, src ConfigSource, upstream string) caddyroute.Router {
	return &router{inner: inner, src: src, upstream: upstream}
}

type router struct {
	inner    caddyroute.Router
	src      ConfigSource
	upstream string
}

func (r *router) want() (*caddyroute.Route, error) {
	cfg, err := r.src.Load()
	if err != nil || cfg == nil {
		return nil, err
	}
	return &caddyroute.Route{App: RouteApp, Upstream: r.upstream, Domains: []string{cfg.Domain}}, nil
}

func (r *router) Sync(ctx context.Context, routes []caddyroute.Route) error {
	want, err := r.want()
	if err != nil {
		return err
	}
	if want != nil {
		routes = append(append([]caddyroute.Route(nil), routes...), *want)
	}
	return r.inner.Sync(ctx, routes)
}

func (r *router) Current(ctx context.Context) (map[string]caddyroute.Route, error) {
	m, err := r.inner.Current(ctx)
	if err != nil {
		return nil, err
	}
	have, present := m[RouteApp]
	delete(m, RouteApp)
	want, err := r.want()
	if err != nil {
		return nil, err
	}
	switch {
	case want == nil && present,
		want != nil && (!present || have.Upstream != want.Upstream || len(have.Domains) != 1 || have.Domains[0] != want.Domains[0]):
		m[pendingKey] = caddyroute.Route{App: pendingKey}
	}
	return m, nil
}
