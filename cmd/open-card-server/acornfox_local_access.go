package main

import (
	"net/http"
	"strings"
)

type ConsoleAccessMode string

const (
	ConsoleAccessPublicHTTPS   ConsoleAccessMode = "public_https"
	ConsoleAccessLocalLoopback ConsoleAccessMode = "local_loopback"
)

const (
	ExactLocalConsoleHost      = "127.0.0.1:8080"
	ExactInternalListenerHost  = "127.0.0.1:18481"
	acornFoxLocalSessionCookie = "acornfox_local_session"
	acornFoxLocalCSRFCookie    = "acornfox_local_csrf"
	acornFoxLocalCSRFHeader    = "X-AcornFox-CSRF"
)

var localAuthRouteConfig = authRouteConfig{
	sessionCookie: acornFoxLocalSessionCookie,
	csrfCookie:    acornFoxLocalCSRFCookie,
	csrfHeader:    acornFoxLocalCSRFHeader,
	secure:        false,
}

// validateLocalLoopbackRequest enforces strict security gate for local_loopback mode:
//  1. RemoteAddr must resolve to a valid loopback IP.
//  2. Raw Host (r.Host without trimming) must match exact 127.0.0.1:8080 (or 127.0.0.1:18481 for health).
//  3. Absolute-form URIs (containing host or scheme) are denied.
//  4. Forwarded header is denied.
//  5. X-Forwarded-Host, if present, must match exact 127.0.0.1:8080 (no multiple values, commas, or other hosts).
//  6. X-Forwarded-Proto, if present, must match exact "http".
//  7. Health checks (/healthz and /readyz) permit either direct internal host (127.0.0.1:18481)
//     or console host (127.0.0.1:8080).
func validateLocalLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}

	// 1. RemoteAddr must be loopback
	remoteIP := authRemoteIP(r.RemoteAddr)
	if remoteIP == nil || !remoteIP.IsLoopback() {
		return false
	}

	// 2. Reject absolute-form URI
	if r.URL.Host != "" || r.URL.Scheme != "" {
		return false
	}
	if strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://") || strings.HasPrefix(r.RequestURI, "//") {
		return false
	}

	// 3. Reject Forwarded header
	if len(r.Header.Values("Forwarded")) > 0 {
		return false
	}

	// 4. X-Forwarded-Host: if present, must be single value and exact 127.0.0.1:8080
	xfhValues := r.Header.Values("X-Forwarded-Host")
	if len(xfhValues) > 1 {
		return false
	} else if len(xfhValues) == 1 {
		if xfhValues[0] != ExactLocalConsoleHost {
			return false
		}
	}

	// 5. X-Forwarded-Proto: if present, must be single value and exact "http"
	xfpValues := r.Header.Values("X-Forwarded-Proto")
	if len(xfpValues) > 1 {
		return false
	} else if len(xfpValues) == 1 {
		if xfpValues[0] != "http" {
			return false
		}
	}

	// 6. Authority verification: raw r.Host without TrimSpace
	rawHost := r.Host
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		if rawHost == ExactLocalConsoleHost || rawHost == ExactInternalListenerHost {
			return true
		}
		return false
	}

	return rawHost == ExactLocalConsoleHost
}
