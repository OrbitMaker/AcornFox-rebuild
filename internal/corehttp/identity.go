package corehttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
)

type ControlPlaneIdentity struct {
	AdminID domain.ID
}

type controlPlaneIdentityContextKey struct{}

func WithControlPlaneIdentity(request *http.Request, adminID domain.ID) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), controlPlaneIdentityContextKey{}, ControlPlaneIdentity{AdminID: adminID}))
}

func ControlPlaneIdentityFromContext(ctx context.Context) (ControlPlaneIdentity, bool) {
	identity, ok := ctx.Value(controlPlaneIdentityContextKey{}).(ControlPlaneIdentity)
	return identity, ok && !identity.AdminID.Empty()
}

func ControlPlaneActor(request *http.Request) string {
	identity, ok := ControlPlaneIdentityFromContext(request.Context())
	if !ok {
		return ""
	}
	return identity.AdminID.String()
}

func ControlPlaneOperator(request *http.Request) bool {
	_, ok := ControlPlaneIdentityFromContext(request.Context())
	return ok
}

func ControlPlaneUnsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// AuthenticateControlPlane validates session (and Origin/CSRF on unsafe methods)
// using the shared auth service and configuration. Returns updated request with identity context and true on success.
func AuthenticateControlPlane(authService *auth.Service, config AuthRouteConfig, writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	AuthNoStore(writer)
	if authService == nil {
		AuthHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return nil, false
	}
	var session domain.AdminSession
	var err error
	if ControlPlaneUnsafeMethod(request.Method) {
		session, err = authService.AuthorizeControlPlaneWrite(request.Context(), request.Header.Get("Origin"), AuthCookie(request, config.SessionCookie), AuthCSRFFor(request, config))
	} else {
		_, session, err = authService.Session(request.Context(), AuthCookie(request, config.SessionCookie))
	}
	if err != nil {
		if errors.Is(err, auth.ErrAuthenticationUnavailable) {
			AuthHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
			return nil, false
		}
		if errors.Is(err, auth.ErrOriginDenied) || errors.Is(err, auth.ErrCSRFInvalid) {
			AuthHTTPError(writer, http.StatusUnauthorized, "authentication failed")
			return nil, false
		}
		ClearAuthCookies(writer, config)
		AuthHTTPError(writer, http.StatusUnauthorized, "authentication failed")
		return nil, false
	}
	return WithControlPlaneIdentity(request, session.AdminID), true
}
