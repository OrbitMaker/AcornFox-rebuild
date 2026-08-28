package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
)

type controlPlaneIdentity struct {
	AdminID domain.ID
}

type controlPlaneIdentityContextKey struct{}

func withControlPlaneIdentity(request *http.Request, adminID domain.ID) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), controlPlaneIdentityContextKey{}, controlPlaneIdentity{AdminID: adminID}))
}

func controlPlaneIdentityFromContext(ctx context.Context) (controlPlaneIdentity, bool) {
	identity, ok := ctx.Value(controlPlaneIdentityContextKey{}).(controlPlaneIdentity)
	return identity, ok && !identity.AdminID.Empty()
}

func controlPlaneActor(request *http.Request) string {
	identity, ok := controlPlaneIdentityFromContext(request.Context())
	if !ok {
		return ""
	}
	return identity.AdminID.String()
}

func controlPlaneOperator(request *http.Request) bool {
	_, ok := controlPlaneIdentityFromContext(request.Context())
	return ok
}

func (s *Server) authenticateControlPlane(writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	authNoStore(writer)
	if s.auth == nil || s.auth.Service == nil {
		authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return nil, false
	}
	var session domain.AdminSession
	var err error
	if controlPlaneUnsafeMethod(request.Method) {
		session, err = s.auth.Service.AuthorizeControlPlaneWrite(request.Context(), request.Header.Get("Origin"), authCookie(request, authSessionCookie), authCSRF(request))
	} else {
		_, session, err = s.auth.Service.Session(request.Context(), authCookie(request, authSessionCookie))
	}
	if err != nil {
		if errors.Is(err, auth.ErrAuthenticationUnavailable) {
			authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
			return nil, false
		}
		if errors.Is(err, auth.ErrOriginDenied) || errors.Is(err, auth.ErrCSRFInvalid) {
			authHTTPError(writer, http.StatusUnauthorized, "authentication failed")
			return nil, false
		}
		clearAuthCookies(writer)
		authHTTPError(writer, http.StatusUnauthorized, "authentication failed")
		return nil, false
	}
	return withControlPlaneIdentity(request, session.AdminID), true
}

func controlPlaneUnsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isAuthRoute(path string) bool { return strings.HasPrefix(path, authAPIBase) }
