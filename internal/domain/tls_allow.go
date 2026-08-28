package domain

import "net"

// TLSAllowPhase is the externally useful state-machine vocabulary. The
// durable M3 route state remains `pending` until Caddy is allowed to serve it.
type TLSAllowPhase string

const (
	TLSAllowDNSVerified  TLSAllowPhase = "dns_verified"
	TLSAllowRouteDesired TLSAllowPhase = "route_desired"
	TLSAllowRuntimeReady TLSAllowPhase = "runtime_ready"
)

// TLSAllowState contains only boolean facts needed by Caddy's internal ask
// endpoint. It deliberately contains no certificate, ACME, DNS-provider, or
// route-target material, so a denial cannot expose a domain inventory.
type TLSAllowState struct {
	Domain           string `json:"-"`
	DNSVerified      bool   `json:"dns_verified"`
	RouteDesired     bool   `json:"route_desired"`
	RuntimeReady     bool   `json:"runtime_ready"`
	DisabledOrFailed bool   `json:"disabled_or_failed"`
}

func (s TLSAllowState) Allowed() bool {
	return s.DNSVerified && s.RouteDesired && s.RuntimeReady && !s.DisabledOrFailed
}

func NormalizeTLSAllowDomain(value string) (string, error) {
	normalized, err := NormalizeDNSName(value)
	if err != nil {
		return "", err
	}
	if net.ParseIP(normalized) != nil {
		return "", ValidationError("TLS allow domain must not be an IP literal")
	}
	return normalized, nil
}
