package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/domain"
)

type M6AIInterventionFact struct {
	ID                    string               `json:"id"`
	ApplicationID         string               `json:"application_id"`
	TaskType              string               `json:"task_type"`
	Status                string               `json:"status"`
	Reason                string               `json:"reason"`
	Summary               string               `json:"summary"`
	Suggestion            string               `json:"suggestion"`
	RequiresUserAction    bool                 `json:"requires_user_action"`
	ControllerHandoff     bool                 `json:"controller_handoff"`
	Provider              string               `json:"provider,omitempty"`
	Model                 string               `json:"model,omitempty"`
	Profile               string               `json:"profile,omitempty"`
	ContextManifestDigest string               `json:"context_manifest_digest,omitempty"`
	Plan                  *domain.AIActionPlan `json:"plan,omitempty"`
	Evidence              []domain.EvidenceRef `json:"evidence,omitempty"`
	Tokens                uint64               `json:"tokens,omitempty"`
	DurationMS            int64                `json:"duration_ms,omitempty"`
	RolledBack            bool                 `json:"rolled_back"`
	RuleCandidateID       string               `json:"rule_candidate_id,omitempty"`
	CreatedAt             string               `json:"created_at"`
}

type M6AIInterventionView struct {
	Version         string                 `json:"version"`
	Mode            string                 `json:"mode"`
	AIStatus        string                 `json:"ai_status"`
	Items           []M6AIInterventionFact `json:"items"`
	SuccessCount    int                    `json:"success_count"`
	FailureCount    int                    `json:"failure_count"`
	RollbackCount   int                    `json:"rollback_count"`
	CandidateCount  int                    `json:"candidate_count"`
	TotalTokens     uint64                 `json:"total_tokens"`
	TotalDurationMS int64                  `json:"total_duration_ms"`
}

type M6AISettings struct {
	Version         string   `json:"version"`
	Enabled         bool     `json:"enabled"`
	Status          string   `json:"status"`
	Profile         string   `json:"profile"`
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	DataScopes      []string `json:"data_scopes"`
	MaxTokens       int      `json:"max_tokens"`
	MaxDurationMS   int64    `json:"max_duration_ms"`
	CooldownSeconds int64    `json:"cooldown_seconds"`
	CacheEnabled    bool     `json:"cache_enabled"`
	ExternalCalls   bool     `json:"external_calls"`
}

type M6AIRequest struct {
	TaskType        string `json:"task_type"`
	Reason          string `json:"reason"`
	ExpectedVersion string `json:"expected_version"`
	Confirmed       bool   `json:"confirmed"`
	Actor           string `json:"-"`
	IdempotencyKey  string `json:"-"`
}

type M6AISettingsUpdate struct {
	ExpectedVersion string   `json:"expected_version"`
	Enabled         bool     `json:"enabled"`
	Profile         string   `json:"profile"`
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	DataScopes      []string `json:"data_scopes"`
	MaxTokens       int      `json:"max_tokens"`
	MaxDurationMS   int64    `json:"max_duration_ms"`
	CooldownSeconds int64    `json:"cooldown_seconds"`
	CacheEnabled    bool     `json:"cache_enabled"`
	Actor           string   `json:"-"`
	IdempotencyKey  string   `json:"-"`
}

type M6AIBackend interface {
	ListInterventions(context.Context, domain.ID, bool) (M6AIInterventionView, error)
	RequestIntervention(context.Context, domain.ID, M6AIRequest) (M6AIInterventionFact, error)
	GetSettings(context.Context) (M6AISettings, error)
	UpdateSettings(context.Context, M6AISettingsUpdate) (M6AISettings, error)
}

type M6AIHTTPHandler struct{ Backend M6AIBackend }

func (h *M6AIHTTPHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == apiPrefix+"settings/ai" {
		h.handleSettings(w, r)
		return true
	}
	prefix := apiPrefix + "applications/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/"), "/")
	if len(parts) != 3 || parts[1] != "ai" || parts[2] != "interventions" {
		return false
	}
	if h == nil || h.Backend == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "m6_ai_unavailable", "controlled AI is not composed")
		return true
	}
	appID := domain.ID(strings.TrimSpace(parts[0]))
	if err := domain.RequireID(appID, "AI intervention application id"); err != nil {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return true
	}
	switch r.Method {
	case http.MethodGet:
		operator := strings.TrimSpace(r.URL.Query().Get("mode")) == "operator"
		if operator && !m4Operator(r) {
			writeJSONError(w, http.StatusForbidden, "forbidden", "operator AI intervention facts require operator role")
			return true
		}
		view, err := h.Backend.ListInterventions(r.Context(), appID, operator)
		if err != nil {
			writeApplicationError(w, err)
			return true
		}
		writeJSON(w, http.StatusOK, view)
	case http.MethodPost:
		if !m4Operator(r) {
			writeJSONError(w, http.StatusForbidden, "forbidden", "requesting controlled AI requires operator role")
			return true
		}
		var input M6AIRequest
		if err := decodeJSON(r, &input); err != nil {
			writeJSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return true
		}
		input.Actor = m4Actor(r)
		input.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if input.Actor == "" || input.IdempotencyKey == "" || strings.TrimSpace(input.ExpectedVersion) == "" || strings.TrimSpace(input.TaskType) == "" || strings.TrimSpace(input.Reason) == "" {
			writeJSONError(w, http.StatusBadRequest, "validation_failed", "actor, idempotency key, expected version, task type, and reason are required")
			return true
		}
		fact, err := h.Backend.RequestIntervention(r.Context(), appID, input)
		if err != nil {
			writeApplicationError(w, err)
			return true
		}
		status := http.StatusAccepted
		if fact.Status == "manual_fallback" || fact.Status == "awaiting_confirmation" || fact.Status == "controller_handoff" {
			status = http.StatusOK
		}
		writeJSON(w, status, fact)
	default:
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "AI interventions require GET or POST")
	}
	return true
}

func (h *M6AIHTTPHandler) handleSettings(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Backend == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "m6_ai_unavailable", "controlled AI is not composed")
		return
	}
	if !m4Operator(r) {
		writeJSONError(w, http.StatusForbidden, "forbidden", "AI service settings require operator role")
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings, err := h.Backend.GetSettings(r.Context())
		if err != nil {
			writeApplicationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, settings)
	case http.MethodPut:
		var input M6AISettingsUpdate
		if err := decodeJSON(r, &input); err != nil {
			writeJSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		input.Actor, input.IdempotencyKey = m4Actor(r), strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if input.Actor == "" || input.IdempotencyKey == "" || strings.TrimSpace(input.ExpectedVersion) == "" {
			writeJSONError(w, http.StatusBadRequest, "validation_failed", "actor, idempotency key, and expected version are required")
			return
		}
		settings, err := h.Backend.UpdateSettings(r.Context(), input)
		if err != nil {
			writeApplicationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, settings)
	default:
		w.Header().Set("Allow", "GET, PUT, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "AI settings require GET or PUT")
	}
}
