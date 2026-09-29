package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/acornfox/acornfox/internal/state"
)

// listDomains implements GET /v1/apps/{app}/domains.
func (s *server) listDomains(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	doms, err := s.store.ListDomains(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if doms == nil {
		doms = []state.Domain{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": doms})
}

// domainRequest is the POST /v1/apps/{app}/domains body.
type domainRequest struct {
	Name string `json:"name"`
}

// addDomain implements POST /v1/apps/{app}/domains. It validates the name,
// returns 409 domain_taken when another app owns it, and attaches a
// dns_mismatch warning (non-fatal) when PublicHost is an IP not present in the
// domain's A/AAAA records.
func (s *server) addDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	var body domainRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "请求体不是合法 JSON")
		return
	}
	if !state.ValidDomainName(body.Name) {
		writeError(w, http.StatusBadRequest, "invalid_domain",
			"域名不合法：需为小写、合法主机名、至少含一个点、非 IP、长度不超过 253")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	dom, _, err := s.store.AddDomain(ctx, app, body.Name)
	if err != nil {
		if errors.Is(err, state.ErrConflict) {
			writeError(w, http.StatusConflict, "domain_taken", "该域名已被其他应用占用")
			return
		}
		s.mapStoreError(w, err)
		return
	}

	// The reconciler picks up the routing/TLS change.
	s.kicker.Kick(app)

	warnings := s.domainDNSWarnings(ctx, body.Name)
	resp := map[string]any{"domain": dom}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	writeJSON(w, http.StatusOK, resp)
}

// removeDomain implements DELETE /v1/apps/{app}/domains/{name}.
func (s *server) removeDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	name := r.PathValue("name")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if !state.ValidDomainName(name) {
		writeError(w, http.StatusBadRequest, "invalid_domain", "域名不合法")
		return
	}
	if err := s.store.RemoveDomain(ctx, app, name); err != nil {
		s.mapStoreError(w, err)
		return
	}
	s.kicker.Kick(app)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "deleted": true})
}

// domainDNSWarnings resolves the domain's A/AAAA records and returns a
// dns_mismatch warning when PublicHost is an IP literal that does not appear in
// them. It never blocks: resolution errors and non-IP PublicHost yield no
// warning.
func (s *server) domainDNSWarnings(ctx context.Context, name string) []state.Diagnosis {
	ip := net.ParseIP(s.publicHost)
	if ip == nil {
		return nil // PublicHost is empty or a hostname; nothing to compare.
	}
	addrs, err := s.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil // Resolution failure is not a hard error here.
	}
	for _, a := range addrs {
		if a.IP.Equal(ip) {
			return nil
		}
	}
	return []state.Diagnosis{{
		Stage:   "domain",
		Code:    "dns_mismatch",
		Message: "域名的 A/AAAA 记录未指向本服务器地址 " + s.publicHost,
		Hint:    "把域名的 A/AAAA 记录指向 " + s.publicHost + "，否则证书无法签发、也无法通过该域名访问",
	}}
}
