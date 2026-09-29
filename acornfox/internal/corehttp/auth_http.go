package corehttp

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/auth"
)

const (
	// AuthAPIBase remains the explicit migration-only endpoint. New AcornFox
	// installations expose the same administrator session contract only under
	// their product namespace.
	AuthAPIBase               = "/api/v1/auth/"
	AcornFoxAuthAPIBase       = "/api/v1/acornfox/auth/"
	AuthSessionCookie         = "__Host-open_card_session"
	AuthCSRFCookie            = "__Host-open_card_csrf"
	AuthCSRFHeader            = "X-Open-Card-CSRF"
	AcornFoxAuthSessionCookie = "__Host-acornfox_session"
	AcornFoxAuthCSRFCookie    = "__Host-acornfox_csrf"
	AcornFoxAuthCSRFHeader    = "X-AcornFox-CSRF"
	AuthMaxJSONBody           = 16 << 10
)

type AuthHTTPHandler struct{ Service *auth.Service }

type AuthRouteConfig struct {
	SessionCookie string
	CSRFCookie    string
	CSRFHeader    string
	Secure        bool
}

var LegacyAuthRouteConfig = AuthRouteConfig{
	SessionCookie: AuthSessionCookie,
	CSRFCookie:    AuthCSRFCookie,
	CSRFHeader:    AuthCSRFHeader,
	Secure:        true,
}

var AcornFoxAuthRouteConfig = AuthRouteConfig{
	SessionCookie: AcornFoxAuthSessionCookie,
	CSRFCookie:    AcornFoxAuthCSRFCookie,
	CSRFHeader:    AcornFoxAuthCSRFHeader,
	Secure:        true,
}

type authLoginInput struct {
	Password string `json:"password"`
}

type authPasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *AuthHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	return h.handleAtBase(writer, request, AuthAPIBase, LegacyAuthRouteConfig)
}

// HandleAcornFox serves the clean-install spelling without changing any
// session, cookie, origin, or CSRF behavior of the established auth service.
func (h *AuthHTTPHandler) HandleAcornFox(writer http.ResponseWriter, request *http.Request) bool {
	return h.handleAtBase(writer, request, AcornFoxAuthAPIBase, AcornFoxAuthRouteConfig)
}

func (h *AuthHTTPHandler) HandleAcornFoxWithConfig(writer http.ResponseWriter, request *http.Request, config AuthRouteConfig) bool {
	return h.handleAtBase(writer, request, AcornFoxAuthAPIBase, config)
}

func (h *AuthHTTPHandler) handleAtBase(writer http.ResponseWriter, request *http.Request, base string, config AuthRouteConfig) bool {
	if !strings.HasPrefix(request.URL.Path, base) {
		return false
	}
	AuthNoStore(writer)
	if h == nil || h.Service == nil {
		AuthHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return true
	}
	switch request.URL.Path {
	case base + "login":
		h.login(writer, request, config)
	case base + "logout":
		h.logout(writer, request, config)
	case base + "session":
		h.session(writer, request, config)
	case base + "password":
		h.password(writer, request, config)
	default:
		AuthHTTPError(writer, http.StatusNotFound, "authentication endpoint not found")
	}
	return true
}

func (h *AuthHTTPHandler) login(writer http.ResponseWriter, request *http.Request, config AuthRouteConfig) {
	if request.Method != http.MethodPost {
		AuthMethod(writer, http.MethodPost)
		return
	}
	var input authLoginInput
	if !decodeAuthJSON(writer, request, &input) {
		return
	}
	result, err := h.Service.Login(request.Context(), request.Header.Get("Origin"), input.Password, AuthSource(request))
	if err != nil {
		AuthServiceError(writer, err)
		return
	}
	SetAuthCookies(writer, config, result.SessionToken, result.CSRFTok, result.Session.AbsoluteExpiresAt)
	WriteJSON(writer, http.StatusOK, map[string]any{"authenticated": true, "idle_expires_at": result.Session.IdleExpiresAt, "absolute_expires_at": result.Session.AbsoluteExpiresAt})
}

func (h *AuthHTTPHandler) logout(writer http.ResponseWriter, request *http.Request, config AuthRouteConfig) {
	if request.Method != http.MethodPost {
		AuthMethod(writer, http.MethodPost)
		return
	}
	err := h.Service.Logout(request.Context(), request.Header.Get("Origin"), AuthCookie(request, config.SessionCookie), AuthCSRFFor(request, config))
	ClearAuthCookies(writer, config)
	if err != nil {
		AuthServiceError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (h *AuthHTTPHandler) session(writer http.ResponseWriter, request *http.Request, config AuthRouteConfig) {
	if request.Method != http.MethodGet {
		AuthMethod(writer, http.MethodGet)
		return
	}
	info, _, err := h.Service.Session(request.Context(), AuthCookie(request, config.SessionCookie))
	if err != nil {
		clearAuthCookiesForInvalidSession(writer, config, err)
		AuthServiceError(writer, err)
		return
	}
	WriteJSON(writer, http.StatusOK, map[string]any{"authenticated": info.Authenticated, "idle_expires_at": info.IdleExpiresAt, "absolute_expires_at": info.AbsoluteAt})
}

func (h *AuthHTTPHandler) password(writer http.ResponseWriter, request *http.Request, config AuthRouteConfig) {
	if request.Method != http.MethodPost {
		AuthMethod(writer, http.MethodPost)
		return
	}
	var input authPasswordInput
	if !decodeAuthJSON(writer, request, &input) {
		return
	}
	err := h.Service.ChangePassword(request.Context(), request.Header.Get("Origin"), AuthCookie(request, config.SessionCookie), AuthCSRFFor(request, config), input.CurrentPassword, input.NewPassword)
	if err != nil {
		clearAuthCookiesForInvalidSession(writer, config, err)
		AuthServiceError(writer, err)
		return
	}
	ClearAuthCookies(writer, config)
	writer.WriteHeader(http.StatusNoContent)
}

func decodeAuthJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Type"))), "application/json") || request.Body == nil {
		AuthHTTPError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, AuthMaxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		AuthHTTPError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		AuthHTTPError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func AuthCookie(request *http.Request, name string) string {
	cookie, err := request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func AuthCSRFFor(request *http.Request, config AuthRouteConfig) string {
	cookie := AuthCookie(request, config.CSRFCookie)
	header := request.Header.Get(config.CSRFHeader)
	if cookie == "" || header == "" || subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) != 1 {
		return ""
	}
	return header
}

func AuthSource(request *http.Request) string {
	remote := AuthRemoteIP(request.RemoteAddr)
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

func AuthRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func SetAuthCookies(writer http.ResponseWriter, config AuthRouteConfig, session, csrf string, expires time.Time) {
	http.SetCookie(writer, &http.Cookie{Name: config.SessionCookie, Value: session, Path: "/", Secure: config.Secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires.UTC()})
	http.SetCookie(writer, &http.Cookie{Name: config.CSRFCookie, Value: csrf, Path: "/", Secure: config.Secure, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: expires.UTC()})
}

func ClearAuthCookies(writer http.ResponseWriter, config AuthRouteConfig) {
	expires := time.Unix(1, 0).UTC()
	http.SetCookie(writer, &http.Cookie{Name: config.SessionCookie, Value: "", Path: "/", Secure: config.Secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: -1})
	http.SetCookie(writer, &http.Cookie{Name: config.CSRFCookie, Value: "", Path: "/", Secure: config.Secure, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: -1})
}

func clearAuthCookiesForInvalidSession(writer http.ResponseWriter, config AuthRouteConfig, err error) {
	if errors.Is(err, auth.ErrAuthenticationFailed) {
		ClearAuthCookies(writer, config)
	}
}

func AuthNoStore(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
}

func AuthMethod(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	AuthHTTPError(writer, http.StatusMethodNotAllowed, "method not allowed")
}

func AuthServiceError(writer http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrAuthenticationUnavailable) {
		AuthHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	if errors.Is(err, auth.ErrPasswordPolicy) {
		AuthHTTPError(writer, http.StatusBadRequest, "invalid request")
		return
	}
	if errors.Is(err, auth.ErrRateLimited) {
		AuthHTTPError(writer, http.StatusTooManyRequests, "authentication failed")
		return
	}
	if errors.Is(err, auth.ErrOriginDenied) || errors.Is(err, auth.ErrCSRFInvalid) || errors.Is(err, auth.ErrAuthenticationFailed) {
		AuthHTTPError(writer, http.StatusUnauthorized, "authentication failed")
		return
	}
	AuthHTTPError(writer, http.StatusServiceUnavailable, "authentication unavailable")
}

func AuthHTTPError(writer http.ResponseWriter, status int, message string) {
	WriteJSON(writer, status, map[string]string{"code": "authentication_failed", "message": message})
}
