package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	HTTPBasePath           = "/api/v1/acornfox/assistant"
	maxHTTPBody            = MaxMessageBytes + 2048
	defaultSSEPollInterval = 500 * time.Millisecond
	defaultSSEHeartbeat    = 15 * time.Second
	defaultSSEMaxLifetime  = 5 * time.Minute
)

type actorContextKey struct{}

// WithActor is the only HTTP authentication seam. The parent server injects
// the already-authenticated administrator before calling Handler.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

func ActorFromContext(ctx context.Context) (Actor, bool) {
	actor, ok := ctx.Value(actorContextKey{}).(Actor)
	return actor, ok && validActor(actor)
}

type Handler struct {
	Service         *Service
	SSEPollInterval time.Duration
	SSEHeartbeat    time.Duration
	SSEMaxLifetime  time.Duration
}

type createSessionInput struct {
	Scope Scope `json:"scope"`
}
type submitRunInput struct {
	IdempotencyKey string `json:"idempotency_key"`
	Message        string `json:"message"`
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != HTTPBasePath+"/sessions" && !strings.HasPrefix(r.URL.Path, HTTPBasePath+"/sessions/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if h == nil || h.Service == nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "assistant_unavailable", "assistant unavailable")
		return true
	}
	actor, ok := ActorFromContext(r.Context())
	if !ok {
		writeHTTPError(w, http.StatusUnauthorized, "assistant_unauthorized", "authentication required")
		return true
	}
	if r.URL.RawQuery != "" && !strings.HasSuffix(r.URL.Path, "/events") {
		writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid request")
		return true
	}
	if r.URL.Path == HTTPBasePath+"/sessions" {
		switch r.Method {
		case http.MethodGet:
			h.listSessions(w, r, actor)
		case http.MethodPost:
			h.createSession(w, r, actor)
		default:
			methodNotAllowed(w, "GET, POST")
		}
		return true
	}
	relative := strings.TrimPrefix(r.URL.Path, HTTPBasePath+"/sessions/")
	parts := strings.Split(relative, "/")
	if len(parts) != 2 || parts[0] == "" {
		writeHTTPError(w, http.StatusNotFound, "assistant_not_found", "assistant endpoint not found")
		return true
	}
	sessionID := domain.ID(parts[0])
	switch parts[1] {
	case "runs":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return true
		}
		h.submitRun(w, r, actor, sessionID)
	case "events":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return true
		}
		h.events(w, r, actor, sessionID)
	case "abort":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return true
		}
		h.abort(w, r, actor, sessionID)
	default:
		writeHTTPError(w, http.StatusNotFound, "assistant_not_found", "assistant endpoint not found")
	}
	return true
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request, actor Actor) {
	sessions, err := h.Service.ListSessions(r.Context(), actor)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request, actor Actor) {
	var input createSessionInput
	if !decodeJSON(w, r, &input) {
		return
	}
	session, err := h.Service.CreateSession(r.Context(), actor, input.Scope)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (h *Handler) submitRun(w http.ResponseWriter, r *http.Request, actor Actor, sessionID domain.ID) {
	var input submitRunInput
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := h.Service.SubmitRun(r.Context(), actor, sessionID, input.IdempotencyKey, input.Message)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	status := http.StatusAccepted
	if result.Replay {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request, actor Actor, sessionID domain.ID) {
	after, err := parseAfter(r)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid cursor")
		return
	}
	snapshot, err := h.Service.Events(r.Context(), actor, sessionID, after)
	if err != nil {
		if errors.Is(err, ErrCursorExpired) {
			writeJSON(w, http.StatusConflict, snapshot)
			return
		}
		writeServiceError(w, err)
		return
	}
	w.Header().Set("X-AcornFox-Assistant-Cursor-Status", string(snapshot.Status))
	if !acceptsSSE(r) {
		writeJSON(w, http.StatusOK, snapshot)
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		writeHTTPError(w, http.StatusServiceUnavailable, "assistant_unavailable", "event stream unavailable")
		return
	}
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		return
	}
	h.streamEvents(w, r, controller, actor, sessionID, after, snapshot)
}

func (h *Handler) streamEvents(w http.ResponseWriter, r *http.Request, controller *http.ResponseController, actor Actor, sessionID domain.ID, cursor uint64, snapshot EventSnapshot) {
	poll, heartbeat, lifetime := h.sseDurations()
	deadline := time.NewTimer(lifetime)
	defer deadline.Stop()
	heartbeatTicker := time.NewTicker(heartbeat)
	defer heartbeatTicker.Stop()
	for {
		for _, event := range snapshot.Events {
			data, err := json.Marshal(event)
			if err != nil {
				return
			}
			if _, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Cursor, event.Type, data); err != nil {
				return
			}
			if err = controller.Flush(); err != nil {
				return
			}
			cursor = event.Cursor
		}
		if snapshot.Status == CursorSlowConsumer {
			if !writeSSEStatus(w, controller, snapshot) {
				return
			}
			next, err := h.Service.Events(r.Context(), actor, sessionID, cursor)
			if err != nil {
				writeSSEStatus(w, controller, next)
				return
			}
			snapshot = next
			continue
		}
		waitCtx, cancel := context.WithTimeout(r.Context(), poll)
		waitErr := h.Service.WaitForEvents(waitCtx, actor, sessionID)
		cancel()
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return
		case <-heartbeatTicker.C:
			if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		default:
		}
		if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) && !errors.Is(waitErr, context.Canceled) {
			return
		}
		next, err := h.Service.Events(r.Context(), actor, sessionID, cursor)
		if errors.Is(err, ErrCursorExpired) {
			writeSSEStatus(w, controller, next)
			return
		}
		if err != nil {
			return
		}
		snapshot = next
	}
}

func (h *Handler) sseDurations() (time.Duration, time.Duration, time.Duration) {
	poll, heartbeat, lifetime := h.SSEPollInterval, h.SSEHeartbeat, h.SSEMaxLifetime
	if poll <= 0 || poll > defaultSSEPollInterval {
		poll = defaultSSEPollInterval
	}
	if heartbeat <= 0 {
		heartbeat = defaultSSEHeartbeat
	}
	if lifetime <= 0 || lifetime > defaultSSEMaxLifetime {
		lifetime = defaultSSEMaxLifetime
	}
	return poll, heartbeat, lifetime
}

func writeSSEStatus(w http.ResponseWriter, controller *http.ResponseController, snapshot EventSnapshot) bool {
	status := struct {
		Status       CursorStatus `json:"status"`
		OldestCursor uint64       `json:"oldest_cursor"`
		LatestCursor uint64       `json:"latest_cursor"`
	}{snapshot.Status, snapshot.OldestCursor, snapshot.LatestCursor}
	data, err := json.Marshal(status)
	if err != nil {
		return false
	}
	if _, err = fmt.Fprintf(w, "event: stream.status\ndata: %s\n\n", data); err != nil {
		return false
	}
	return controller.Flush() == nil
}

func (h *Handler) abort(w http.ResponseWriter, r *http.Request, actor Actor, sessionID domain.ID) {
	if r.Body != nil {
		limited := http.MaxBytesReader(w, r.Body, 1)
		raw, err := io.ReadAll(limited)
		if err != nil || len(raw) != 0 {
			writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid request")
			return
		}
	}
	result, err := h.Service.Abort(r.Context(), actor, sessionID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func parseAfter(r *http.Request) (uint64, error) {
	query := r.URL.Query()
	if len(query) == 0 {
		if last := strings.TrimSpace(r.Header.Get("Last-Event-ID")); last != "" {
			return strconv.ParseUint(last, 10, 64)
		}
		return 0, nil
	}
	values, ok := query["after"]
	if !ok || len(query) != 1 || len(values) != 1 || values[0] == "" {
		return 0, ErrInvalidInput
	}
	return strconv.ParseUint(values[0], 10, 64)
}

func acceptsSSE(r *http.Request) bool {
	for _, value := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(value))
		if err == nil && mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.Body == nil {
		writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid request")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHTTPBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid request")
		return false
	}
	return true
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		writeHTTPError(w, http.StatusUnauthorized, "assistant_unauthorized", "authentication required")
	case errors.Is(err, ErrNotFound):
		writeHTTPError(w, http.StatusNotFound, "assistant_not_found", "assistant resource not found")
	case errors.Is(err, ErrInvalidInput):
		writeHTTPError(w, http.StatusBadRequest, "assistant_invalid_request", "invalid request")
	case errors.Is(err, ErrIdempotencyConflict):
		writeHTTPError(w, http.StatusConflict, "assistant_idempotency_conflict", "idempotency key conflicts with another message")
	case errors.Is(err, ErrSessionLimit):
		writeHTTPError(w, http.StatusTooManyRequests, "assistant_session_limit", "assistant session limit reached")
	case errors.Is(err, ErrRunLimit):
		writeHTTPError(w, http.StatusTooManyRequests, "assistant_run_limit", "assistant run limit reached")
	default:
		writeHTTPError(w, http.StatusServiceUnavailable, "assistant_unavailable", "assistant unavailable")
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeHTTPError(w, http.StatusMethodNotAllowed, "assistant_method_not_allowed", "method not allowed")
}
func writeHTTPError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
