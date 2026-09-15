package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const (
	acornFoxDiscoveryDefaultLimit = 50
	acornFoxDiscoveryMaximumLimit = 100
)

type acornFoxDiscoveryReader interface {
	ListAcornFoxSourceRevisions(context.Context, domain.ID, *postgres.AcornFoxDiscoveryCursor, int) (postgres.AcornFoxSourceRevisionPage, error)
	ListAcornFoxDeployments(context.Context, domain.ID, *postgres.AcornFoxDiscoveryCursor, int) (postgres.AcornFoxDeploymentPage, error)
}

// AcornFoxDiscoveryHTTPHandler provides server-authoritative list recovery.
// It owns only a derived signing key, never the installation master key.
type AcornFoxDiscoveryHTTPHandler struct {
	Store     acornFoxDiscoveryReader
	cursorKey [32]byte
}

func newAcornFoxDiscoveryHTTPHandler(store acornFoxDiscoveryReader, cursorKey [32]byte) *AcornFoxDiscoveryHTTPHandler {
	return &AcornFoxDiscoveryHTTPHandler{Store: store, cursorKey: cursorKey}
}

func (h *AcornFoxDiscoveryHTTPHandler) Close() {
	if h != nil {
		for i := range h.cursorKey {
			h.cursorKey[i] = 0
		}
	}
}

func (h *AcornFoxDiscoveryHTTPHandler) HandleSources(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if r.Method != http.MethodGet {
		acornFoxDiscoveryMethodNotAllowed(w)
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "source discovery is unavailable")
		return
	}
	limit, cursor, err := h.parseQuery(r, applicationID, "sources")
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid_discovery_query", "discovery query is invalid")
		return
	}
	page, err := h.Store.ListAcornFoxSourceRevisions(r.Context(), applicationID, cursor, limit)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "source discovery is unavailable")
		return
	}
	items := make([]contracts.AcornFoxInputRevision, 0, len(page.Items))
	for _, item := range page.Items {
		projected, err := contracts.ProjectAcornFoxInputRevision(item)
		if err != nil || !isAcornFoxDiscoverySource(item) {
			writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "source discovery is unavailable")
			return
		}
		items = append(items, projected)
	}
	writeJSON(w, http.StatusOK, acornFoxDiscoveryResponse[contracts.AcornFoxInputRevision]{Items: items, NextCursor: h.encodeCursor(applicationID, "sources", page.NextCursor)})
}

func (h *AcornFoxDiscoveryHTTPHandler) HandleDeliveries(w http.ResponseWriter, r *http.Request, applicationID domain.ID) {
	if r.Method != http.MethodGet {
		acornFoxDiscoveryMethodNotAllowed(w)
		return
	}
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "delivery discovery is unavailable")
		return
	}
	limit, cursor, err := h.parseQuery(r, applicationID, "deliveries")
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid_discovery_query", "discovery query is invalid")
		return
	}
	page, err := h.Store.ListAcornFoxDeployments(r.Context(), applicationID, cursor, limit)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "delivery discovery is unavailable")
		return
	}
	items := make([]contracts.AcornFoxDeploymentRuntimeState, 0, len(page.Items))
	for _, item := range page.Items {
		projected, err := contracts.ProjectAcornFoxDeploymentRuntimeState(item)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "discovery_unavailable", "delivery discovery is unavailable")
			return
		}
		items = append(items, projected)
	}
	writeJSON(w, http.StatusOK, acornFoxDiscoveryResponse[contracts.AcornFoxDeploymentRuntimeState]{Items: items, NextCursor: h.encodeCursor(applicationID, "deliveries", page.NextCursor)})
}

func acornFoxDiscoveryMethodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, OPTIONS")
	writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

type acornFoxDiscoveryResponse[T any] struct {
	Items      []T `json:"items"`
	NextCursor any `json:"next_cursor"`
}
type acornFoxDiscoveryCursorWire struct {
	Version   int    `json:"v"`
	CreatedAt string `json:"t"`
	ID        string `json:"i"`
	MAC       string `json:"m"`
}

func (h *AcornFoxDiscoveryHTTPHandler) parseQuery(r *http.Request, applicationID domain.ID, resource string) (int, *postgres.AcornFoxDiscoveryCursor, error) {
	query := r.URL.Query()
	for key := range query {
		if key != "limit" && key != "cursor" {
			return 0, nil, errors.New("unknown query key")
		}
	}
	limit := acornFoxDiscoveryDefaultLimit
	if values, ok := query["limit"]; ok {
		if len(values) != 1 {
			return 0, nil, errors.New("ambiguous limit")
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > acornFoxDiscoveryMaximumLimit {
			return 0, nil, errors.New("invalid limit")
		}
		limit = parsed
	}
	if _, ok := query["cursor"]; !ok {
		return limit, nil, nil
	}
	values := query["cursor"]
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return 0, nil, errors.New("invalid cursor")
	}
	cursor, err := h.decodeCursor(applicationID, resource, values[0])
	if err != nil {
		return 0, nil, err
	}
	return limit, cursor, nil
}

func (h *AcornFoxDiscoveryHTTPHandler) encodeCursor(applicationID domain.ID, resource string, cursor *postgres.AcornFoxDiscoveryCursor) any {
	if cursor == nil {
		return nil
	}
	createdAt := cursor.CreatedAt.UTC().Format(time.RFC3339Nano)
	wire := acornFoxDiscoveryCursorWire{Version: 1, CreatedAt: createdAt, ID: cursor.ID.String()}
	wire.MAC = h.cursorMAC(applicationID, resource, wire.Version, wire.CreatedAt, wire.ID)
	raw, err := json.Marshal(wire)
	if err != nil {
		return nil
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (h *AcornFoxDiscoveryHTTPHandler) decodeCursor(applicationID domain.ID, resource, encoded string) (*postgres.AcornFoxDiscoveryCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 512 {
		return nil, errors.New("cursor encoding invalid")
	}
	var wire acornFoxDiscoveryCursorWire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != 1 || wire.ID == "" || wire.CreatedAt == "" || wire.MAC == "" {
		return nil, errors.New("cursor payload invalid")
	}
	if !hmac.Equal([]byte(wire.MAC), []byte(h.cursorMAC(applicationID, resource, wire.Version, wire.CreatedAt, wire.ID))) {
		return nil, errors.New("cursor signature invalid")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return nil, errors.New("cursor timestamp invalid")
	}
	cursor := &postgres.AcornFoxDiscoveryCursor{CreatedAt: createdAt.UTC(), ID: domain.ID(wire.ID)}
	if cursor.ID.Empty() {
		return nil, errors.New("cursor id invalid")
	}
	return cursor, nil
}

func isAcornFoxDiscoverySource(item domain.SourceRevision) bool {
	if !item.Immutable {
		return false
	}
	switch item.Kind {
	case domain.SourceGitHTTPS:
		parsed, err := url.Parse(item.Locator)
		return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
	case domain.SourceUpload:
		if item.Commit != "" {
			return false
		}
		ref := domain.ID(item.Ref)
		if domain.RequireID(ref, "upload reference") != nil {
			return false
		}
		return item.Locator == "upload://"+item.Ref
	default:
		return false
	}
}

func (h *AcornFoxDiscoveryHTTPHandler) cursorMAC(applicationID domain.ID, resource string, version int, createdAt, id string) string {
	mac := hmac.New(sha256.New, h.cursorKey[:])
	_, _ = mac.Write([]byte("acornfox-discovery-cursor-v1\x00" + applicationID.String() + "\x00" + resource + "\x00" + strconv.Itoa(version) + "\x00" + createdAt + "\x00" + id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
