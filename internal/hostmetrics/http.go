package hostmetrics

import (
	"encoding/json"
	"net/http"
)

// HTTPHandler exposes an already-running sampler. The caller is responsible
// for placing it behind the server's existing authentication middleware.
type HTTPHandler struct{ Sampler *Sampler }

func NewHTTPHandler(sampler *Sampler) *HTTPHandler { return &HTTPHandler{Sampler: sampler} }

func (h *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed)
		return
	}
	var value Response
	if h == nil || h.Sampler == nil {
		value = unavailableResponse(DefaultStaleAfter, nil)
	} else {
		value = h.Sampler.Snapshot()
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"code": "method_not_allowed", "message": "method not allowed"})
}

var _ http.Handler = (*HTTPHandler)(nil)
