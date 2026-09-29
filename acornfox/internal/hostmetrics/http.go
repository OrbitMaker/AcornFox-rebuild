package hostmetrics

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// HTTPHandler exposes a running sampler's snapshot. The caller is responsible
// for placing it behind the server's authentication middleware.
type HTTPHandler struct{ Sampler *Sampler }

func NewHTTPHandler(sampler *Sampler) *HTTPHandler { return &HTTPHandler{Sampler: sampler} }

func (h *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if request.URL.RawQuery != "" {
		writeError(writer, http.StatusBadRequest, "bad_request", "query parameters are not supported")
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

// RecentResponse is the JSON envelope for GET /api/v1/acornfox/host/metrics/recent.
type RecentResponse struct {
	SchemaVersion    int          `json:"schema_version"`
	Availability     Availability `json:"availability"`
	GeneratedAt      time.Time    `json:"generated_at"`
	Capacity         int          `json:"capacity"`
	RetentionSeconds int          `json:"retention_seconds"`
	Points           []Response   `json:"points"`
}

// RecentHTTPHandler exposes a running sampler's bounded recent history.
type RecentHTTPHandler struct{ Sampler *Sampler }

func NewRecentHTTPHandler(sampler *Sampler) *RecentHTTPHandler {
	return &RecentHTTPHandler{Sampler: sampler}
}

func (h *RecentHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	limit, err := parseRecentLimit(request.URL.RawQuery)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	now := time.Now().UTC()
	if h != nil && h.Sampler != nil && h.Sampler.now != nil {
		now = h.Sampler.now().UTC()
	}

	var availability Availability
	var points []Response

	if h == nil || h.Sampler == nil {
		availability = Unavailable
		points = []Response{}
	} else if h.Sampler.os != "linux" {
		availability = Unsupported
		points = []Response{}
	} else {
		snap := h.Sampler.Snapshot()
		availability = snap.Availability
		points = h.Sampler.Recent(limit)
		if points == nil {
			points = []Response{}
		}
	}

	resp := RecentResponse{
		SchemaVersion:    1,
		Availability:     availability,
		GeneratedAt:      now,
		Capacity:         MaxRecentObservations,
		RetentionSeconds: int(RecentRetention / time.Second),
		Points:           points,
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(resp)
}

func parseRecentLimit(rawQuery string) (int, error) {
	if rawQuery == "" {
		return DefaultRecentLimit, nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return 0, errors.New("malformed query parameters")
	}
	for key := range values {
		if key != "limit" {
			return 0, errors.New("unsupported query parameter")
		}
	}
	limits, ok := values["limit"]
	if !ok || len(limits) != 1 {
		return 0, errors.New("duplicate or invalid limit parameter")
	}
	raw := limits[0]
	if len(raw) == 0 {
		return 0, errors.New("limit parameter cannot be empty")
	}
	val, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || val < 1 || val > MaxRecentObservations {
		return 0, errors.New("limit parameter must be an integer between 1 and 360")
	}
	if strconv.FormatUint(val, 10) != raw {
		return 0, errors.New("invalid limit format")
	}
	return int(val), nil
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"code": code, "message": message})
}

var (
	_ http.Handler = (*HTTPHandler)(nil)
	_ http.Handler = (*RecentHTTPHandler)(nil)
)
