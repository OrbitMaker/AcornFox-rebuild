package main

import (
	"net/http"

	"github.com/open-card/open-card/internal/corehttp"
)

type ConsoleAccessMode = corehttp.ConsoleAccessMode

const (
	ConsoleAccessPublicHTTPS   = corehttp.ConsoleAccessPublicHTTPS
	ConsoleAccessLocalLoopback = corehttp.ConsoleAccessLocalLoopback
)

const (
	ExactLocalConsoleHost      = corehttp.ExactLocalConsoleHost
	ExactInternalListenerHost  = corehttp.ExactInternalListenerHost
	acornFoxLocalSessionCookie = corehttp.AcornFoxLocalSessionCookie
	acornFoxLocalCSRFCookie    = corehttp.AcornFoxLocalCSRFCookie
	acornFoxLocalCSRFHeader    = corehttp.AcornFoxLocalCSRFHeader
)

var localAuthRouteConfig = corehttp.LocalAuthRouteConfig

func validateLocalLoopbackRequest(r *http.Request) bool {
	return corehttp.ValidateLocalLoopbackRequest(r)
}
