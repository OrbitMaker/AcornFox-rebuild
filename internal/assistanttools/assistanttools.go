// Package assistanttools is the narrow, in-memory callback boundary for a
// trusted local assistant runner. It has no listener, filesystem, shell, or
// database dependency.
package assistanttools

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	MaxCallsPerRun  = 64
	MaxArguments    = 8 << 10
	MaxResult       = 64 << 10
	MaxActiveGrants = 64
)

var id = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

type Scope struct {
	Admin         bool
	ApplicationID string
}
type GrantInput struct {
	Actor, SessionID, RunID string
	Scope                   Scope
	ExpiresAt               time.Time
}
type Grant struct {
	Actor, SessionID, RunID string
	Scope                   Scope
	ExpiresAt               time.Time
}
type Call struct {
	Tool      string          `json:"tool"`
	CallID    string          `json:"call_id"`
	Arguments json.RawMessage `json:"arguments"`
}
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Code   string          `json:"code,omitempty"`
}
type Executor func(context.Context, Grant, Call) Response

type callResult struct {
	done        chan struct{}
	response    Response
	fingerprint string
}
type entry struct {
	grant   Grant
	revoked bool
	calls   map[string]*callResult
}
type Registry struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*entry
}

func NewRegistry() *Registry { return &Registry{now: time.Now, entries: map[string]*entry{}} }

func (r *Registry) Grant(input GrantInput) (string, error) {
	if r == nil || !id.MatchString(input.Actor) || !id.MatchString(input.SessionID) || !id.MatchString(input.RunID) || input.ExpiresAt.IsZero() || !input.ExpiresAt.After(r.now()) || input.Scope.Admin && input.Scope.ApplicationID != "" || !input.Scope.Admin && !id.MatchString(input.Scope.ApplicationID) {
		return "", errors.New("invalid grant")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if entry.revoked || !entry.grant.ExpiresAt.After(r.now()) {
			delete(r.entries, key)
		}
	}
	if len(r.entries) >= MaxActiveGrants {
		return "", errors.New("grant limit")
	}
	r.entries[token] = &entry{grant: Grant{input.Actor, input.SessionID, input.RunID, input.Scope, input.ExpiresAt.UTC()}, calls: map[string]*callResult{}}
	return token, nil
}
func (r *Registry) Revoke(token string) {
	if r != nil {
		r.mu.Lock()
		delete(r.entries, token)
		r.mu.Unlock()
	}
}

func (r *Registry) Execute(ctx context.Context, token string, call Call, executor Executor) Response {
	if r == nil || executor == nil || !validCall(call) {
		return Response{Code: "invalid_request"}
	}
	r.mu.Lock()
	e := r.entries[token]
	if e == nil || e.revoked || !e.grant.ExpiresAt.After(r.now()) {
		r.mu.Unlock()
		return Response{Code: "unauthorized"}
	}
	fingerprint := call.Tool + "\x00" + string(call.Arguments)
	if cached, ok := e.calls[call.CallID]; ok {
		r.mu.Unlock()
		if cached.fingerprint != fingerprint {
			return Response{Code: "idempotency_conflict"}
		}
		select {
		case <-cached.done:
			return cached.response
		case <-ctx.Done():
			return Response{Code: "unavailable"}
		}
	}
	if len(e.calls) >= MaxCallsPerRun {
		r.mu.Unlock()
		return Response{Code: "call_limit"}
	}
	grant := e.grant
	// Reserve the call before execution. A duplicate concurrent call observes
	// only the stable result after the owner completes it.
	pending := &callResult{done: make(chan struct{}), fingerprint: fingerprint}
	e.calls[call.CallID] = pending
	r.mu.Unlock()
	response := executor(ctx, grant, call)
	response = bounded(response)
	r.mu.Lock()
	pending.response = response
	close(pending.done)
	r.mu.Unlock()
	return response
}

func validCall(call Call) bool {
	return toolSchemas[call.Tool] && id.MatchString(call.CallID) && len(call.Arguments) > 1 && len(call.Arguments) <= MaxArguments && json.Valid(call.Arguments)
}
func bounded(value Response) Response {
	if value.OK && len(value.Result) > MaxResult {
		return Response{Code: "result_too_large"}
	}
	if !value.OK && !stableCode(value.Code) {
		return Response{Code: "unavailable"}
	}
	return value
}
func stableCode(code string) bool {
	switch code {
	case "invalid_request", "unauthorized", "forbidden", "not_found", "unavailable", "result_too_large", "call_limit", "idempotency_conflict":
		return true
	}
	return false
}

var toolSchemas = map[string]bool{
	"acornfox_host_metrics": true, "acornfox_list_apps": true, "acornfox_app": true, "acornfox_sources": true, "acornfox_deliveries": true, "acornfox_delivery_status": true, "acornfox_logs": true, "acornfox_operation_result": true, "acornfox_public_access": true, "acornfox_probe": true, "acornfox_propose_restart": true, "acornfox_propose_redeploy": true,
}

// Handler is suitable for http.Serve on a Unix-domain socket. No HTTP request
// can mint a grant; it can only present a runner-issued in-memory bearer.
type Handler struct {
	Registry *Registry
	Execute  Executor
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/tools" {
		write(w, http.StatusNotFound, Response{Code: "not_found"})
		return
	}
	token := bearer(r.Header.Get("Authorization"))
	if token == "" {
		write(w, http.StatusUnauthorized, Response{Code: "unauthorized"})
		return
	}
	defer r.Body.Close()
	var call Call
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxArguments+512))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&call) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		write(w, http.StatusBadRequest, Response{Code: "invalid_request"})
		return
	}
	response := h.Registry.Execute(r.Context(), token, call, h.Execute)
	status := http.StatusOK
	if response.Code == "unauthorized" {
		status = http.StatusUnauthorized
	}
	write(w, status, response)
}
func bearer(value string) string {
	const prefix = "Bearer "
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return ""
	}
	token := value[len(prefix):]
	if subtle.ConstantTimeEq(int32(len(token)), 43) != 1 || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(token) {
		return ""
	}
	return token
}
func write(w http.ResponseWriter, status int, v Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
