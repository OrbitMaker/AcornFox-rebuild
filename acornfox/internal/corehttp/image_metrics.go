package corehttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
)

// ImageMetricsHandler serves one bounded read sample under normal Core auth.
type ImageMetricsHandler struct {
	Store    appcontracts.ManagedImageObservationStore
	History  appcontracts.ImageMetricsHistoryReader
	Sampler  appcontracts.ImageMetricsBackgroundSampler
	client   appcontracts.ImageMetricsClient
	clientMu sync.RWMutex
	Auth     *auth.Service
	Config   AuthRouteConfig
}

func (h *ImageMetricsHandler) SetClient(client appcontracts.ImageMetricsClient) {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	h.client = client
	if h.Sampler != nil {
		h.Sampler.SetClient(client)
	}
}

func (h *ImageMetricsHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, ImageDeploymentsAPIBase) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, ImageDeploymentsAPIBase), "/")
	recent := len(parts) == 3 && parts[0] != "" && parts[1] == "metrics" && parts[2] == "recent"
	current := len(parts) == 2 && parts[0] != "" && parts[1] == "metrics"
	if !recent && !current {
		return false
	}
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return true
	}
	id, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || id.AdminID.Empty() {
		AuthHTTPError(w, http.StatusUnauthorized, "authentication failed")
		return true
	}
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return true
	}
	if !recent && req.URL.RawQuery != "" {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "metrics query is not supported")
		return true
	}
	h.clientMu.RLock()
	client := h.client
	h.clientMu.RUnlock()
	if h.Store == nil || (!recent && client == nil) || (recent && h.History == nil) {
		WriteJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "metrics unavailable")
		return true
	}
	q := appcontracts.ImageMetricsRequest{AdminID: id.AdminID, DeploymentID: domain.ID(parts[0])}
	if recent {
		h.handleRecent(w, req, q, client)
		return true
	}
	before, err := h.Store.ReadManagedImageObservationBinding(req.Context(), q.AdminID, q.DeploymentID)
	if err != nil {
		writeDeliveryError(w, err)
		return true
	}
	out, err := client.ReadManagedImageMetrics(req.Context(), q)
	if err != nil {
		WriteJSONError(w, http.StatusServiceUnavailable, "metrics_unavailable", "metrics unavailable")
		return true
	}
	after, err := h.Store.ReadManagedImageObservationBinding(req.Context(), q.AdminID, q.DeploymentID)
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	if err != nil || !validMetricsBinding(out, before) || !bytes.Equal(x, y) {
		WriteJSONError(w, http.StatusConflict, "metrics_changed", "metrics target changed")
		return true
	}
	payload, err := json.Marshal(out)
	if err != nil || len(payload) > appcontracts.ImageMetricsJSONBytes {
		WriteJSONError(w, http.StatusBadGateway, "metrics_invalid", "metrics response exceeded limit")
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	return true
}

func validMetricsBinding(out appcontracts.ImageMetricsResult, b appcontracts.ManagedImageObservationBinding) bool {
	r := b.Runtime
	return out.Validate(time.Now().UTC()) == nil && out.State.ContainerID == r.ContainerID && out.State.ImageID == r.ImageID && out.State.ManifestDigest == r.ManifestDigest && out.State.HostPort == r.HostPort && out.State.ContainerPort == r.ContainerPort
}

func parseMetricsRecentLimit(raw string) (int, error) {
	if raw == "" {
		return appcontracts.ImageMetricsHistoryDefault, nil
	}
	query, err := url.ParseQuery(raw)
	if err != nil || len(query) != 1 || len(query["limit"]) != 1 {
		return 0, errors.New("invalid recent metrics query")
	}
	limit, err := strconv.Atoi(query["limit"][0])
	if err != nil || limit < 1 || limit > appcontracts.ImageMetricsHistorySamples {
		return 0, errors.New("invalid recent metrics limit")
	}
	return limit, nil
}

func (h *ImageMetricsHandler) handleRecent(w http.ResponseWriter, req *http.Request, q appcontracts.ImageMetricsRequest, client appcontracts.ImageMetricsClient) {
	limit, err := parseMetricsRecentLimit(req.URL.RawQuery)
	if err != nil {
		WriteJSONError(w, http.StatusBadRequest, "invalid_request", "invalid recent metrics query")
		return
	}
	before, err := h.Store.ReadManagedImageObservationBinding(req.Context(), q.AdminID, q.DeploymentID)
	if err != nil {
		writeDeliveryError(w, err)
		return
	}
	liveRead := false
	var sampled appcontracts.ImageMetricsResult
	selected := h.History.Recent(q.DeploymentID, before.Runtime.ContainerID, 1, time.Now().UTC()).Scheduled
	if selected && client != nil {
		value, readErr := client.ReadManagedImageMetrics(req.Context(), q)
		if readErr == nil {
			if !validMetricsBinding(value, before) {
				WriteJSONError(w, http.StatusConflict, "metrics_changed", "metrics target changed")
				return
			}
			sampled = value
			liveRead = true
		}
	}
	after, err := h.Store.ReadManagedImageObservationBinding(req.Context(), q.AdminID, q.DeploymentID)
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(x, y) {
		WriteJSONError(w, http.StatusConflict, "metrics_changed", "metrics target changed")
		return
	}
	if liveRead {
		if err := h.History.Record(q.DeploymentID, sampled, time.Now().UTC()); err != nil {
			WriteJSONError(w, http.StatusConflict, "metrics_invalid", "metrics sample rejected")
			return
		}
	}
	out := h.History.Recent(q.DeploymentID, before.Runtime.ContainerID, limit, time.Now().UTC())
	if out.Scheduled && !liveRead {
		out.Stale = true
		out.Reason = "read_failed"
		out.RecordingStatus = "stale"
	}
	payload, err := json.Marshal(out)
	if err != nil || len(payload) > appcontracts.ImageMetricsHistoryJSONBytes {
		WriteJSONError(w, http.StatusBadGateway, "metrics_invalid", "metrics history exceeded limit")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
