package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxPublicAccessCommand interface {
	Get(context.Context, domain.ID, domain.ID) (contracts.AcornFoxPublicAccessFact, error)
	Set(context.Context, application.AcornFoxPublicAccessRequest) (contracts.AcornFoxPublicAccessFact, error)
}

// AcornFoxPublicAccessHTTPHandler intentionally has no DNS dependency. This
// leaf can request a local owned route but cannot claim that DNS, TLS, or the
// public Internet is ready.
type AcornFoxPublicAccessHTTPHandler struct{ Service acornFoxPublicAccessCommand }

func (h *AcornFoxPublicAccessHTTPHandler) Handle(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if h == nil || h.Service == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "public_access_unavailable", "public access is unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		fact, err := h.Service.Get(r.Context(), applicationID, deploymentID)
		if err != nil {
			writeAcornFoxPublicAccessError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, acornFoxPublicAccessResponse(fact))
	case http.MethodPut:
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if err := decodeJSON(r, &input); err != nil || input.Enabled == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must contain enabled")
			return
		}
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" {
			writeJSONError(w, http.StatusUnprocessableEntity, "validation_failed", "Idempotency-Key is required")
			return
		}
		fact, err := h.Service.Set(r.Context(), application.AcornFoxPublicAccessRequest{ApplicationID: applicationID, DeploymentID: deploymentID, Enabled: *input.Enabled, IdempotencyKey: key})
		if err != nil {
			writeAcornFoxPublicAccessError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, acornFoxPublicAccessResponse(fact))
	default:
		w.Header().Set("Allow", "GET, PUT, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func acornFoxPublicAccessResponse(fact contracts.AcornFoxPublicAccessFact) map[string]any {
	// Never expose route targets, Caddy identifiers, provider evidence, DNS
	// facts, certificate details, or operation internals from this endpoint.
	return map[string]any{
		"desired_public": fact.DesiredPublic, "url": "https://" + fact.Hostname, "status": fact.Status,
		"endpoint":   map[string]any{"deployment_id": fact.DeploymentID},
		"components": map[string]string{"internal_endpoint": string(fact.InternalEndpoint), "local_route": string(fact.LocalRoute), "dns": "not_validated", "tls": "not_validated", "external": "not_validated"},
	}
}

func writeAcornFoxPublicAccessError(w http.ResponseWriter, err error) {
	if errors.Is(err, application.ErrNotFound) || domain.IsCode(err, domain.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if code, ok := application.AcornFoxPublicAccessErrorCodeOf(err); ok {
		switch code {
		case application.AcornFoxPublicAccessIdempotencyConflict:
			writeJSONError(w, http.StatusConflict, string(code), "idempotency key conflicts with a prior request")
		case application.AcornFoxInternalEndpointNotReady:
			writeJSONError(w, http.StatusConflict, string(code), "an accepted local endpoint is required")
		case application.AcornFoxPublicAccessConflict, application.AcornFoxPublicAccessOwnershipConflict:
			writeJSONError(w, http.StatusConflict, string(code), "public access route conflicts with existing state")
		case application.AcornFoxPublicAccessUnavailable:
			writeJSONError(w, http.StatusServiceUnavailable, string(code), "public access is temporarily unavailable")
		default:
			writeJSONError(w, http.StatusServiceUnavailable, "public_access_unavailable", "public access is temporarily unavailable")
		}
		return
	}
	writeJSONError(w, http.StatusServiceUnavailable, "public_access_unavailable", "public access is temporarily unavailable")
}

type acornFoxPublicAccessRouteAdapter struct {
	Routes contracts.RouteProvider
	Clock  func() time.Time
}

func (adapter acornFoxPublicAccessRouteAdapter) EnsureAcornFoxPublicRoute(ctx context.Context, intent contracts.AcornFoxPublicRouteIntent, key string) error {
	request, err := adapter.request(intent, key, "ensure")
	if err != nil {
		return err
	}
	_, _, err = adapter.Routes.Apply(ctx, request)
	return acornFoxPublicAccessRouteError(err)
}

func (adapter acornFoxPublicAccessRouteAdapter) RemoveAcornFoxPublicRoute(ctx context.Context, intent contracts.AcornFoxPublicRouteIntent, key string) error {
	request, err := adapter.request(intent, key, "remove")
	if err != nil {
		return err
	}
	return acornFoxPublicAccessRouteError(adapter.Routes.Remove(ctx, request))
}

func (adapter acornFoxPublicAccessRouteAdapter) request(intent contracts.AcornFoxPublicRouteIntent, key, action string) (contracts.RouteRequest, error) {
	if adapter.Routes == nil || strings.TrimSpace(key) == "" {
		return contracts.RouteRequest{}, application.ErrAcornFoxPublicAccessUnavailable
	}
	route, err := intent.RouteSpec()
	if err != nil {
		return contracts.RouteRequest{}, application.ErrAcornFoxPublicAccessOwnershipConflict
	}
	now := time.Now().UTC()
	if adapter.Clock != nil {
		now = adapter.Clock().UTC()
	}
	return contracts.RouteRequest{Route: route, Operation: contracts.OperationContext{IdempotencyKey: "acornfox-public-access:" + action + ":" + intent.ApplicationID.String() + ":" + intent.DeploymentID.String() + ":" + key, Actor: "acornfox-public-access", Deadline: now.Add(10 * time.Second)}}, nil
}

func acornFoxPublicAccessRouteError(err error) error {
	if err == nil {
		return nil
	}
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		switch providerErr.Code {
		case contracts.ErrConflict:
			return application.ErrAcornFoxPublicAccessConflict
		case contracts.ErrNotFound:
			return application.ErrAcornFoxPublicAccessOwnershipConflict
		}
	}
	return application.ErrAcornFoxPublicAccessUnavailable
}

// reconcileAcornFoxPublicAccess resumes bounded commands left between durable
// M3 intent and Caddy projection. It only reads canonical M3 route state.
func reconcileAcornFoxPublicAccess(ctx context.Context, store *postgres.Store, root string, router application.AcornFoxPublicAccessRouter, limit int) error {
	items, err := store.ClaimAcornFoxPublicAccessRecoveryCommands(ctx, limit, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, item := range items {
		host, err := contracts.AcornFoxPublicHostname(root, item.ApplicationID, item.DeploymentID)
		if err != nil {
			return err
		}
		intent, found, err := store.GetAcornFoxPublicRouteIntent(ctx, item.ApplicationID, item.DeploymentID)
		if err != nil {
			return err
		}
		if item.RequestedEnabled {
			if !found {
				return application.ErrAcornFoxPublicAccessOwnershipConflict
			}
			err = router.EnsureAcornFoxPublicRoute(ctx, intent, item.IdempotencyKey)
		} else if found {
			err = router.RemoveAcornFoxPublicRoute(ctx, intent, item.IdempotencyKey)
		}
		if err != nil {
			return err
		}
		status := contracts.AcornFoxPublicDisabled
		localRoute := contracts.AcornFoxLocalRouteDisabled
		if item.RequestedEnabled {
			status = contracts.AcornFoxPublicPendingExternalValidation
			localRoute = contracts.AcornFoxLocalRouteConfigured
		}
		fact := contracts.AcornFoxPublicAccessFact{
			ApplicationID:    item.ApplicationID,
			DeploymentID:     item.DeploymentID,
			Hostname:         host,
			Status:           status,
			DesiredPublic:    item.RequestedEnabled,
			InternalEndpoint: contracts.AcornFoxInternalEndpointAccepted,
			LocalRoute:       localRoute,
		}
		if err = store.CommitAcornFoxPublicAccess(ctx, fact, intent, item.IdempotencyKey, item.RequestDigest, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}
