package main

import (
	"net"
	"net/http"

	"github.com/open-card/open-card/internal/corehttp"
)

const (
	authAPIBase               = corehttp.AuthAPIBase
	acornFoxAuthAPIBase       = corehttp.AcornFoxAuthAPIBase
	authSessionCookie         = corehttp.AuthSessionCookie
	authCSRFCookie            = corehttp.AuthCSRFCookie
	authCSRFHeader            = corehttp.AuthCSRFHeader
	acornFoxAuthSessionCookie = corehttp.AcornFoxAuthSessionCookie
	acornFoxAuthCSRFCookie    = corehttp.AcornFoxAuthCSRFCookie
	acornFoxAuthCSRFHeader    = corehttp.AcornFoxAuthCSRFHeader
	authMaxJSONBody           = corehttp.AuthMaxJSONBody
)

type AuthHTTPHandler = corehttp.AuthHTTPHandler
type authRouteConfig = corehttp.AuthRouteConfig

var legacyAuthRouteConfig = corehttp.LegacyAuthRouteConfig
var acornFoxAuthRouteConfig = corehttp.AcornFoxAuthRouteConfig

func authCookie(request *http.Request, name string) string {
	return corehttp.AuthCookie(request, name)
}

func authCSRF(request *http.Request) string {
	return corehttp.AuthCSRFFor(request, legacyAuthRouteConfig)
}

func authCSRFFor(request *http.Request, config authRouteConfig) string {
	return corehttp.AuthCSRFFor(request, config)
}

func authSource(request *http.Request) string {
	return corehttp.AuthSource(request)
}

func authRemoteIP(remoteAddr string) net.IP {
	return corehttp.AuthRemoteIP(remoteAddr)
}

func authNoStore(writer http.ResponseWriter) {
	corehttp.AuthNoStore(writer)
}

func authHTTPError(writer http.ResponseWriter, status int, message string) {
	corehttp.AuthHTTPError(writer, status, message)
}
