package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/auth"
)

const (
	authAPIBase       = "/api/v1/auth/"
	authSessionCookie = "__Host-open_card_session"
	authCSRFCookie    = "__Host-open_card_csrf"
	authCSRFHeader    = "X-Open-Card-CSRF"
	authMaxJSONBody   = 16 << 10
)

type AuthHTTPHandler struct{ Service *auth.Service }

type authLoginInput struct {
	Password string `json:"password"`
}

type authPasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *AuthHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if !strings.HasPrefix(request.URL.Path, authAPIBase) {
		return false
	}
	authNoStore(writer)
	if h == nil || h.Service == nil {
		authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return true
	}
	switch request.URL.Path {
	case authAPIBase + "login":
		h.login(writer, request)
	case authAPIBase + "logout":
		h.logout(writer, request)
	case authAPIBase + "session":
		h.session(writer, request)
	case authAPIBase + "password":
		h.password(writer, request)
	default:
		authHTTPError(writer, http.StatusNotFound, "authentication endpoint not found")
	}
	return true
}

func (h *AuthHTTPHandler) login(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		authMethod(writer, http.MethodPost)
		return
	}
	var input authLoginInput
	if !decodeAuthJSON(writer, request, &input) {
		return
	}
	result, err := h.Service.Login(request.Context(), request.Header.Get("Origin"), input.Password, authSource(request))
	if err != nil {
		authServiceError(writer, err)
		return
	}
	setAuthCookies(writer, result.SessionToken, result.CSRFTok, result.Session.AbsoluteExpiresAt)
	writeJSON(writer, http.StatusOK, map[string]any{"authenticated": true, "idle_expires_at": result.Session.IdleExpiresAt, "absolute_expires_at": result.Session.AbsoluteExpiresAt})
}

func (h *AuthHTTPHandler) logout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		authMethod(writer, http.MethodPost)
		return
	}
	err := h.Service.Logout(request.Context(), request.Header.Get("Origin"), authCookie(request, authSessionCookie), authCSRF(request))
	clearAuthCookies(writer)
	if err != nil {
		authServiceError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (h *AuthHTTPHandler) session(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		authMethod(writer, http.MethodGet)
		return
	}
	info, _, err := h.Service.Session(request.Context(), authCookie(request, authSessionCookie))
	if err != nil {
		clearAuthCookiesForInvalidSession(writer, err)
		authServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"authenticated": info.Authenticated, "idle_expires_at": info.IdleExpiresAt, "absolute_expires_at": info.AbsoluteAt})
}

func (h *AuthHTTPHandler) password(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		authMethod(writer, http.MethodPost)
		return
	}
	var input authPasswordInput
	if !decodeAuthJSON(writer, request, &input) {
		return
	}
	err := h.Service.ChangePassword(request.Context(), request.Header.Get("Origin"), authCookie(request, authSessionCookie), authCSRF(request), input.CurrentPassword, input.NewPassword)
	if err != nil {
		clearAuthCookiesForInvalidSession(writer, err)
		authServiceError(writer, err)
		return
	}
	clearAuthCookies(writer)
	writer.WriteHeader(http.StatusNoContent)
}

func decodeAuthJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Type"))), "application/json") || request.Body == nil {
		authHTTPError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, authMaxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		authHTTPError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		authHTTPError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func authCookie(request *http.Request, name string) string {
	cookie, err := request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func authCSRF(request *http.Request) string {
	cookie := authCookie(request, authCSRFCookie)
	header := request.Header.Get(authCSRFHeader)
	if cookie == "" || header == "" || subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) != 1 {
		return ""
	}
	return header
}

func authSource(request *http.Request) string {
	remote := authRemoteIP(request.RemoteAddr)
	if remote == nil {
		return ""
	}
	// The Edge is the only trusted proxy for the digest input. Direct callers
	// (and all forwarded/Open-Card headers) remain unable to select a source.
	if remote.IsLoopback() {
		if edgeSource := net.ParseIP(strings.TrimSpace(request.Header.Get("X-Open-Card-Client-IP"))); edgeSource != nil {
			return edgeSource.String()
		}
	}
	return remote.String()
}

func authRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func setAuthCookies(writer http.ResponseWriter, session, csrf string, expires time.Time) {
	http.SetCookie(writer, &http.Cookie{Name: authSessionCookie, Value: session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires.UTC()})
	http.SetCookie(writer, &http.Cookie{Name: authCSRFCookie, Value: csrf, Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: expires.UTC()})
}

func clearAuthCookies(writer http.ResponseWriter) {
	expires := time.Unix(1, 0).UTC()
	http.SetCookie(writer, &http.Cookie{Name: authSessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: -1})
	http.SetCookie(writer, &http.Cookie{Name: authCSRFCookie, Value: "", Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: -1})
}

func clearAuthCookiesForInvalidSession(writer http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrAuthenticationFailed) {
		clearAuthCookies(writer)
	}
}

func authNoStore(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
}

func authMethod(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	authHTTPError(writer, http.StatusMethodNotAllowed, "method not allowed")
}

func authServiceError(writer http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrAuthenticationUnavailable) {
		authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	if errors.Is(err, auth.ErrPasswordPolicy) {
		authHTTPError(writer, http.StatusBadRequest, "invalid request")
		return
	}
	if errors.Is(err, auth.ErrRateLimited) {
		authHTTPError(writer, http.StatusTooManyRequests, "authentication failed")
		return
	}
	if errors.Is(err, auth.ErrOriginDenied) || errors.Is(err, auth.ErrCSRFInvalid) || errors.Is(err, auth.ErrAuthenticationFailed) {
		authHTTPError(writer, http.StatusUnauthorized, "authentication failed")
		return
	}
	authHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
}

func authHTTPError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"code": "authentication_failed", "message": message})
}
