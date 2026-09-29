package main

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/acornfox/acornfox/internal/auth"
	"github.com/acornfox/acornfox/internal/corehttp"
	"github.com/acornfox/acornfox/internal/hostmetrics"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
)

// executorStatus reports which executor subsystems core is currently connected to.
type executorStatus struct {
	container, source, gateway *atomic.Bool
}

func (e executorStatus) snapshot() map[string]bool {
	load := func(b *atomic.Bool) bool { return b != nil && b.Load() }
	return map[string]bool{"container": load(e.container), "source_build": load(e.source), "gateway": load(e.gateway)}
}

type coreServer struct {
	expectedHost         string
	store                *sqlite.Store
	authService          *auth.Service
	authHandler          *corehttp.AuthHTTPHandler
	setupHandler         *corehttp.AcornFoxWebSetupHTTPHandler
	staticHandler        *staticCoreHandler
	metricsHandler       *hostmetrics.HTTPHandler
	recentHandler        *hostmetrics.RecentHTTPHandler
	imageDeliveryHandler *corehttp.ImageDeliveryHandler
	executor             executorStatus
}

type coreServerConfig struct {
	ExpectedHost         string
	Store                *sqlite.Store
	AuthService          *auth.Service
	AuthHandler          *corehttp.AuthHTTPHandler
	SetupHandler         *corehttp.AcornFoxWebSetupHTTPHandler
	StaticHandler        *staticCoreHandler
	Sampler              *hostmetrics.Sampler
	ImageDeliveryHandler *corehttp.ImageDeliveryHandler
	Executor             executorStatus
}

func newCoreServer(cfg coreServerConfig) *coreServer {
	var metricsHandler *hostmetrics.HTTPHandler
	var recentHandler *hostmetrics.RecentHTTPHandler
	if cfg.Sampler != nil {
		metricsHandler = hostmetrics.NewHTTPHandler(cfg.Sampler)
		recentHandler = hostmetrics.NewRecentHTTPHandler(cfg.Sampler)
	}
	return &coreServer{
		expectedHost:         cfg.ExpectedHost,
		store:                cfg.Store,
		authService:          cfg.AuthService,
		authHandler:          cfg.AuthHandler,
		setupHandler:         cfg.SetupHandler,
		staticHandler:        cfg.StaticHandler,
		metricsHandler:       metricsHandler,
		recentHandler:        recentHandler,
		imageDeliveryHandler: cfg.ImageDeliveryHandler,
		executor:             cfg.Executor,
	}
}

func (s *coreServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Loopback request gate
	if !corehttp.ValidateLocalLoopbackRequestWithHost(r, s.expectedHost) {
		corehttp.WriteJSONError(w, http.StatusForbidden, "access_denied", "local loopback access denied")
		return
	}

	// 2. Health & Readiness endpoints (unauthenticated)
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			corehttp.WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if r.URL.Path == "/readyz" {
			if s.store == nil {
				corehttp.WriteJSONError(w, http.StatusServiceUnavailable, "not_ready", "database is not ready")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if _, err := s.store.AdministratorExists(ctx); err != nil {
				corehttp.WriteJSONError(w, http.StatusServiceUnavailable, "not_ready", "database is not ready")
				return
			}
		}
		corehttp.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "ready": true})
		return
	}

	// 4. AcornFox Web Setup endpoint
	if r.URL.Path == corehttp.AcornFoxSetupPath {
		if s.setupHandler != nil {
			s.setupHandler.HandleWithPolicy(w, r, corehttp.ConsoleAccessLocalLoopback)
		} else {
			corehttp.AuthNoStore(w)
			corehttp.WriteJSONError(w, http.StatusServiceUnavailable, "setup_unavailable", "setup unavailable")
		}
		return
	}

	// 5. AcornFox Auth endpoints (/api/v1/acornfox/auth/*)
	if strings.HasPrefix(r.URL.Path, corehttp.AcornFoxAuthAPIBase) {
		if s.authHandler != nil && s.authHandler.HandleAcornFoxWithConfig(w, r, corehttp.LocalAuthRouteConfig) {
			return
		}
		corehttp.AuthNoStore(w)
		corehttp.AuthHTTPError(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}

	// 6. Core status contract (authenticated)
	if r.URL.Path == "/api/v1/acornfox/core/status" {
		req, ok := corehttp.AuthenticateControlPlane(s.authService, corehttp.LocalAuthRouteConfig, w, r)
		if !ok {
			return
		}
		if req.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			corehttp.WriteJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		corehttp.WriteJSON(w, http.StatusOK, map[string]any{
			"storage":  "sqlite",
			"executor": s.executor.snapshot(),
		})
		return
	}

	// 7. Host metrics endpoints (authenticated, strictly loopback)
	if r.URL.Path == "/api/v1/acornfox/host/metrics" || strings.HasPrefix(r.URL.Path, "/api/v1/acornfox/host/metrics/") {
		_, ok := corehttp.AuthenticateControlPlane(s.authService, corehttp.LocalAuthRouteConfig, w, r)
		if !ok {
			return
		}
		switch r.URL.Path {
		case "/api/v1/acornfox/host/metrics":
			if s.metricsHandler != nil {
				s.metricsHandler.ServeHTTP(w, r)
			} else {
				hostmetrics.NewHTTPHandler(nil).ServeHTTP(w, r)
			}
			return
		case "/api/v1/acornfox/host/metrics/recent":
			if s.recentHandler != nil {
				s.recentHandler.ServeHTTP(w, r)
			} else {
				hostmetrics.NewRecentHTTPHandler(nil).ServeHTTP(w, r)
			}
			return
		default:
			corehttp.WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
			return
		}
	}

	// 8. Native immutable image delivery endpoints (/api/v1/acornfox/image-plans, /api/v1/acornfox/operations/*)
	if s.imageDeliveryHandler != nil && s.imageDeliveryHandler.Handle(w, r) {
		return
	}

	// 9. Other /api/* endpoints return JSON 404 (never routed to static index.html)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		corehttp.WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}

	// 9. Static core assets
	if s.staticHandler != nil {
		s.staticHandler.ServeHTTP(w, r)
		return
	}

	corehttp.WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
}
