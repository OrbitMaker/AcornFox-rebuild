package corehttp

import (
	"bytes"
	"encoding/json"
	"errors"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/domain"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ImageObservationHandler is separately injectable; the existing public router
// must explicitly connect it. It creates no task, command or persisted sample.
type ImageObservationHandler struct {
	Store    appcontracts.ManagedImageObservationStore
	client   appcontracts.ImageObservationClient
	clientMu sync.RWMutex
	Auth     *auth.Service
	Config   AuthRouteConfig
}

func (h *ImageObservationHandler) Handle(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, ImageDeploymentsAPIBase) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, ImageDeploymentsAPIBase), "/")
	if len(parts) != 2 || parts[0] == "" || (parts[1] != "observation" && parts[1] != "logs") {
		return false
	}
	req, ok := AuthenticateControlPlane(h.Auth, h.Config, w, r)
	if !ok {
		return true
	}
	id, ok := ControlPlaneIdentityFromContext(req.Context())
	if !ok || id.AdminID.Empty() {
		AuthHTTPError(w, 401, "authentication failed")
		return true
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		WriteJSONError(w, 405, "method_not_allowed", "method not allowed")
		return true
	}
	h.clientMu.RLock()
	client := h.client
	h.clientMu.RUnlock()
	if h.Store == nil || client == nil {
		WriteJSONError(w, 503, "service_unavailable", "observation unavailable")
		return true
	}
	args, err := parseObservationQuery(r.URL.RawQuery)
	if err != nil {
		WriteJSONError(w, 400, "invalid_request", "invalid observation query")
		return true
	}
	q := appcontracts.ImageObservationRequest{AdminID: id.AdminID, DeploymentID: domain.ID(parts[0]), Logs: parts[1] == "logs"}
	if q.Logs {
		q.Tail = 64
	}
	if v, ok := args["tail"]; ok {
		q.Tail, err = strconv.Atoi(v)
		if err != nil {
			WriteJSONError(w, 400, "invalid_request", "invalid tail")
			return true
		}
	}
	if v, ok := args["since"]; ok {
		q.Since, err = time.Parse(time.RFC3339Nano, v)
		if err != nil {
			WriteJSONError(w, 400, "invalid_request", "invalid since")
			return true
		}
		q.Since = q.Since.UTC()
	}
	if !q.Valid(time.Now().UTC()) {
		WriteJSONError(w, 400, "invalid_request", "invalid observation bounds")
		return true
	}
	before, err := h.Store.ReadManagedImageObservationBinding(req.Context(), q.AdminID, q.DeploymentID)
	if err != nil {
		writeDeliveryError(w, err)
		return true
	}
	out, err := client.ReadManagedImageObservation(req.Context(), q)
	if err != nil {
		WriteJSONError(w, 503, "observation_unavailable", "observation unavailable")
		return true
	}
	after, err := h.Store.ReadManagedImageObservationBinding(req.Context(), q.AdminID, q.DeploymentID)
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	b := before.Runtime
	if err != nil || out.Validate(time.Now().UTC()) != nil || !bytes.Equal(x, y) || !out.State.VerifiedIdentity || out.State.ContainerID != b.ContainerID || out.State.ImageID != b.ImageID || out.State.ManifestDigest != b.ManifestDigest || out.State.HostPort != b.HostPort || out.State.ContainerPort != b.ContainerPort {
		WriteJSONError(w, 409, "observation_changed", "observation identity changed")
		return true
	}
	WriteJSON(w, 200, out)
	return true
}

func parseObservationQuery(raw string) (map[string]string, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range q {
		if (k != "tail" && k != "since") || len(v) != 1 || v[0] == "" {
			return nil, errors.New("invalid observation query")
		}
		out[k] = v[0]
	}
	return out, nil
}

func (h *ImageObservationHandler) SetClient(client appcontracts.ImageObservationClient) {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	h.client = client
}
