// Package reconcile drives every app from its actual state (Docker, read via
// the runner; Caddy, read via caddyroute) to its desired state (state.Store).
//
// See docs/acornfox-rebuild-migration-plan.md sections 3.2, 3.3 and 3.10 and
// the N1 contract in docs/n1-contract.md.
package reconcile
