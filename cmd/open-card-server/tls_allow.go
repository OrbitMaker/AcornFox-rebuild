package main

import (
	"net"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/controllers"
)

const tlsAllowPath = "/internal/tls/allow"

// TLSAllowHTTPHandler is the loopback-only Caddy ask endpoint. Every denial
// is intentionally indistinguishable so it cannot enumerate registered hosts.
type TLSAllowHTTPHandler struct {
	Controller *controllers.TLSAllowController
}

func (h *TLSAllowHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if request.URL.Path != tlsAllowPath {
		return false
	}
	if h == nil || h.Controller == nil || request.Method != http.MethodGet || !tlsAllowLoopback(request.RemoteAddr) {
		tlsAllowDeny(writer)
		return true
	}
	values := request.URL.Query()["domain"]
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		tlsAllowDeny(writer)
		return true
	}
	allowed, err := h.Controller.Allow(request.Context(), values[0])
	if err != nil || !allowed {
		tlsAllowDeny(writer)
		return true
	}
	writer.WriteHeader(http.StatusNoContent)
	return true
}

func tlsAllowLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func tlsAllowDeny(writer http.ResponseWriter) { writer.WriteHeader(http.StatusForbidden) }
