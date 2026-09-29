package corehttp

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"

	"github.com/open-card/open-card/internal/auth"
)

const (
	AcornFoxSetupPath        = "/api/v1/acornfox/setup"
	AcornFoxSetupMaxJSONBody = 16 << 10
)

// AcornFoxWebSetupHTTPHandler is intentionally separate from authenticated
// API routing. The parent server must dispatch this exact path before AcornFox
// session authentication and must not use prefix routing.
type AcornFoxWebSetupHTTPHandler struct {
	Service *auth.WebSetupService
}

type acornFoxWebSetupInput struct {
	SetupToken string `json:"setup_token"`
	Password   string `json:"password"`
}

// NewAcornFoxWebSetupHTTPHandler consumes the supplied LoadCredential bytes:
// the auth service retains only their digest and this function clears the
// caller-owned slice before returning.
func NewAcornFoxWebSetupHTTPHandler(store auth.WebSetupStore, authService *auth.Service, setupTokenCredential []byte) (*AcornFoxWebSetupHTTPHandler, error) {
	if store == nil || isNilWebSetupStore(store) || authService == nil {
		clear(setupTokenCredential)
		return nil, errors.New("AcornFox web setup dependencies are required")
	}
	service, err := auth.NewWebSetupService(auth.WebSetupConfig{Store: store, Auth: authService, SetupTokenCredential: setupTokenCredential})
	clear(setupTokenCredential)
	if err != nil {
		return nil, err
	}
	return &AcornFoxWebSetupHTTPHandler{Service: service}, nil
}

func isNilWebSetupStore(store auth.WebSetupStore) bool {
	if store == nil {
		return true
	}
	v := reflect.ValueOf(store)
	return (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil()
}

func (h *AcornFoxWebSetupHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	return h.HandleWithPolicy(writer, request, ConsoleAccessPublicHTTPS)
}

func (h *AcornFoxWebSetupHTTPHandler) HandleWithPolicy(writer http.ResponseWriter, request *http.Request, policy ConsoleAccessMode) bool {
	if request.URL.Path != AcornFoxSetupPath {
		return false
	}
	AuthNoStore(writer)
	if request.URL.RawQuery != "" {
		acornFoxSetupError(writer, http.StatusBadRequest, "invalid request")
		return true
	}
	if h == nil || h.Service == nil {
		if request.Method == http.MethodGet {
			WriteJSON(writer, http.StatusOK, map[string]string{"state": string(auth.WebSetupStateUnavailable)})
		} else {
			acornFoxSetupError(writer, http.StatusServiceUnavailable, "setup unavailable")
		}
		return true
	}
	switch request.Method {
	case http.MethodGet:
		WriteJSON(writer, http.StatusOK, map[string]string{"state": string(h.Service.State(request.Context()))})
	case http.MethodPost:
		h.post(writer, request, policy)
	default:
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		acornFoxSetupError(writer, http.StatusMethodNotAllowed, "method not allowed")
	}
	return true
}

func (h *AcornFoxWebSetupHTTPHandler) post(writer http.ResponseWriter, request *http.Request, policy ConsoleAccessMode) {
	if !h.BoundaryAllowed(request, policy) {
		acornFoxSetupError(writer, http.StatusUnauthorized, "setup failed")
		return
	}
	var input acornFoxWebSetupInput
	if !decodeAcornFoxSetupJSON(writer, request, &input) {
		return
	}
	err := h.Service.Setup(request.Context(), request.Header.Get("Origin"), input.SetupToken, input.Password)
	switch {
	case err == nil:
		WriteJSON(writer, http.StatusCreated, map[string]bool{"initialized": true})
	case errors.Is(err, auth.ErrWebSetupInitialized):
		acornFoxSetupError(writer, http.StatusConflict, "setup already initialized")
	case errors.Is(err, auth.ErrRateLimited):
		acornFoxSetupError(writer, http.StatusTooManyRequests, "setup failed")
	case errors.Is(err, auth.ErrWebSetupToken), errors.Is(err, auth.ErrOriginDenied):
		acornFoxSetupError(writer, http.StatusUnauthorized, "setup failed")
	case errors.Is(err, auth.ErrPasswordPolicy):
		acornFoxSetupError(writer, http.StatusBadRequest, "invalid request")
	default:
		acornFoxSetupError(writer, http.StatusServiceUnavailable, "setup unavailable")
	}
}

func (h *AcornFoxWebSetupHTTPHandler) BoundaryAllowed(request *http.Request, policy ConsoleAccessMode) bool {
	switch policy {
	case ConsoleAccessLocalLoopback:
		return TLSAllowLoopback(request.RemoteAddr)
	case "", ConsoleAccessPublicHTTPS:
		return acornFoxSetupHTTPSBoundary(request)
	default:
		return false
	}
}

// The production server is loopback-only behind the HTTPS Edge. Caddy's
// standard X-Forwarded-Proto header is trusted only from that listener; a
// future direct TLS listener is also safe. Other forwarded headers are ignored.
func acornFoxSetupHTTPSBoundary(request *http.Request) bool {
	if request == nil {
		return false
	}
	if request.TLS != nil {
		return true
	}
	return TLSAllowLoopback(request.RemoteAddr) && request.Header.Get("X-Forwarded-Proto") == "https"
}

func decodeAcornFoxSetupJSON(writer http.ResponseWriter, request *http.Request, target *acornFoxWebSetupInput) bool {
	mediaType, _, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" || request.Body == nil {
		acornFoxSetupError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, AcornFoxSetupMaxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		acornFoxSetupError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		acornFoxSetupError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func acornFoxSetupError(writer http.ResponseWriter, status int, message string) {
	WriteJSON(writer, status, map[string]string{"code": "setup_failed", "message": message})
}
