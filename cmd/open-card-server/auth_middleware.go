package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/corehttp"
	"github.com/open-card/open-card/internal/domain"
)

type controlPlaneIdentity = corehttp.ControlPlaneIdentity

func withControlPlaneIdentity(request *http.Request, adminID domain.ID) *http.Request {
	return corehttp.WithControlPlaneIdentity(request, adminID)
}

func controlPlaneIdentityFromContext(ctx context.Context) (controlPlaneIdentity, bool) {
	return corehttp.ControlPlaneIdentityFromContext(ctx)
}

func controlPlaneActor(request *http.Request) string {
	return corehttp.ControlPlaneActor(request)
}

func controlPlaneOperator(request *http.Request) bool {
	return corehttp.ControlPlaneOperator(request)
}

func (s *Server) authenticateControlPlane(writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	return s.authenticateControlPlaneWithAuth(writer, request, legacyAuthRouteConfig)
}

func (s *Server) authenticateAcornFoxControlPlane(writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	config := acornFoxAuthRouteConfig
	if s.consoleAccessMode == ConsoleAccessLocalLoopback {
		config = localAuthRouteConfig
	}
	return s.authenticateControlPlaneWithAuth(writer, request, config)
}

func (s *Server) authenticateControlPlaneWithAuth(writer http.ResponseWriter, request *http.Request, config authRouteConfig) (*http.Request, bool) {
	if s.auth == nil {
		authNoStore(writer)
		authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return nil, false
	}
	return corehttp.AuthenticateControlPlane(s.auth.Service, config, writer, request)
}

func controlPlaneUnsafeMethod(method string) bool {
	return corehttp.ControlPlaneUnsafeMethod(method)
}

func isAuthRoute(path string) bool { return strings.HasPrefix(path, authAPIBase) }

func isAcornFoxAuthRoute(path string) bool { return strings.HasPrefix(path, acornFoxAuthAPIBase) }
