package main

import (
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/domain"
)

const acornFoxSourceUploadAPIBase = "/api/v1/acornfox/source-uploads"

func (s *Server) handleAcornFoxSourceUpload(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != acornFoxSourceUploadAPIBase && !strings.HasPrefix(r.URL.Path, acornFoxSourceUploadAPIBase+"/") {
		return false
	}
	if strings.HasSuffix(r.URL.Path, "/") || strings.Contains(strings.TrimPrefix(r.URL.Path, acornFoxSourceUploadAPIBase), "//") {
		writeJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return true
	}
	path := strings.TrimPrefix(r.URL.Path, acornFoxSourceUploadAPIBase)
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST, OPTIONS")
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return true
		}
		if s.g3SourceUpload == nil || s.g3SourceUpload.Store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload storage is unavailable")
			return true
		}
		s.g3SourceUpload.create(w, r)
		return true
	}

	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, OPTIONS")
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return true
		}
		if s.g3SourceUpload == nil || s.g3SourceUpload.Store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload storage is unavailable")
			return true
		}
		s.g3SourceUpload.get(w, r, domain.ID(parts[0]))
		return true
	}

	writeJSONError(w, http.StatusNotFound, "not_found", "route not found")
	return true
}
