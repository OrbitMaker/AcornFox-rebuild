package controllers

import (
	"context"
	"errors"

	"github.com/open-card/open-card/internal/domain"
)

// TLSAllowStore is a read-only, indexed lookup over durable M3 facts.
type TLSAllowStore interface {
	TLSAllowState(context.Context, string) (domain.TLSAllowState, error)
}

// TLSAllowController intentionally performs no DNS, ACME, Caddy, or network
// work. It answers only whether persisted facts have reached the safe first
// issuance state.
type TLSAllowController struct{ Store TLSAllowStore }

func (c *TLSAllowController) Allow(ctx context.Context, rawDomain string) (bool, error) {
	if c == nil || c.Store == nil {
		return false, errors.New("TLS allow store is not configured")
	}
	domainName, err := domain.NormalizeTLSAllowDomain(rawDomain)
	if err != nil {
		return false, nil
	}
	state, err := c.Store.TLSAllowState(ctx, domainName)
	if err != nil {
		return false, err
	}
	return state.Allowed(), nil
}
