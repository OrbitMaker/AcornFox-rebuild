package main

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type M4LogsHTTPHandler struct {
	store *postgres.Store
	logs  *observability.LogStore
}
type m4LogEntry struct {
	Category    string    `json:"category"`
	Service     string    `json:"service"`
	ReleaseID   domain.ID `json:"release_id,omitempty"`
	OperationID domain.ID `json:"operation_id,omitempty"`
	At          time.Time `json:"at"`
	Level       string    `json:"level"`
	Content     string    `json:"content,omitempty"`
}

func (h *M4LogsHTTPHandler) HandleApplication(w http.ResponseWriter, r *http.Request) bool {
	const suffix = "/logs"
	if !strings.HasPrefix(r.URL.Path, apiPrefix+"applications/") || !strings.HasSuffix(r.URL.Path, suffix) {
		return false
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "logs requires GET")
		return true
	}
	if h == nil || h.store == nil || h.logs == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "m4_logs_unavailable", "M4 logs are not configured")
		return true
	}
	app := domain.ID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, apiPrefix+"applications/"), suffix))
	if app.Empty() {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", "application ID is required")
		return true
	}
	if err := m4ReconcileOrdinaryLogIndexes(r.Context(), h.store, h.logs, time.Now().UTC()); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "m4_log_integrity_unavailable", "M4 log index reconciliation failed")
		return true
	}
	indexes, err := h.store.ListLogIndexes(r.Context(), app, false, 200)
	if err != nil {
		writeDomainError(w, err)
		return true
	}
	if !m4Operator(r) {
		counts := map[string]int{}
		var latest time.Time
		for _, i := range indexes {
			counts[string(i.Category)]++
			if i.CreatedAt.After(latest) {
				latest = i.CreatedAt
			}
		}
		var auditCount int
		_ = h.store.DB().QueryRowContext(r.Context(), `SELECT count(*) FROM m4_operation_requests m JOIN operations o ON o.id=m.operation_id WHERE o.application_id=$1`, app.String()).Scan(&auditCount)
		counts["audit"] = auditCount
		writeJSON(w, http.StatusOK, map[string]any{"mode": "ordinary", "summary": map[string]any{"counts": counts, "latest_at": latest, "raw_logs_available": false}})
		return true
	}
	query := r.URL.Query()
	service, release, category, level := strings.TrimSpace(query.Get("service")), domain.ID(query.Get("release_id")), strings.TrimSpace(query.Get("category")), strings.TrimSpace(query.Get("level"))
	since, _ := time.Parse(time.RFC3339, query.Get("since"))
	until, _ := time.Parse(time.RFC3339, query.Get("until"))
	entries := []m4LogEntry{}
	seen := map[string]bool{}
	for _, i := range indexes {
		if service != "" && i.ServiceName != service || !release.Empty() && i.ReleaseID != release || category != "" && string(i.Category) != category || !since.IsZero() && i.CreatedAt.Before(since) || !until.IsZero() && i.CreatedAt.After(until) {
			continue
		}
		stream := filepath.Base(filepath.Dir(i.Path))
		key := string(i.Category) + "/" + stream
		if seen[key] {
			continue
		}
		seen[key] = true
		data, readErr := h.logs.Read(observability.LogCategory(i.Category), stream)
		if readErr != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "m4_log_integrity_unavailable", "active M4 log index could not be read")
			return true
		}
		content := foundation.RedactText(string(data))
		if level != "" && !strings.Contains(strings.ToLower(content), strings.ToLower(level)) {
			continue
		}
		entries = append(entries, m4LogEntry{Category: string(i.Category), Service: i.ServiceName, ReleaseID: i.ReleaseID, OperationID: i.OperationID, At: i.CreatedAt, Level: m4LogLevel(content), Content: content})
	}
	auditRows, err := h.store.DB().QueryContext(r.Context(), `SELECT o.operation_type,m.actor_id,m.reason,o.state,o.updated_at FROM m4_operation_requests m JOIN operations o ON o.id=m.operation_id WHERE o.application_id=$1 AND o.updated_at>=COALESCE($2,to_timestamp(0)) AND o.updated_at<=COALESCE($3,'infinity'::timestamptz) ORDER BY o.updated_at DESC LIMIT 100`, app.String(), nullableM4Time(since), nullableM4Time(until))
	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			var action, actor, reason, result string
			var at time.Time
			if auditRows.Scan(&action, &actor, &reason, &result, &at) == nil {
				content := foundation.RedactText(action + " by " + actor + ": " + reason + " (" + result + ")")
				if (category == "" || category == "audit") && service == "" && release.Empty() && (level == "" || level == "info") {
					entries = append(entries, m4LogEntry{Category: "audit", Service: "control-plane", At: at.UTC(), Level: "info", Content: content})
				}
			}
		}
	}
	limit := 100
	if value, parseErr := strconv.Atoi(query.Get("limit")); parseErr == nil && value > 0 && value < limit {
		limit = value
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": "operator", "items": entries})
	return true
}
func m4LogLevel(content string) string {
	lower := strings.ToLower(content)
	for _, level := range []string{"error", "warn", "debug", "info"} {
		if strings.Contains(lower, level) {
			return level
		}
	}
	return "info"
}
func nullableM4Time(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
