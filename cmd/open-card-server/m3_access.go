package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

const m3AccessAPIBase = "/api/v1/access/"

// M3AccessHTTPHandler is deliberately separate from Server routing so its
// callers can wire it only after the M3 controller has all of its providers.
// It never treats request-supplied domain facts as sufficient to route traffic:
// ApplyDomainRoutes performs the ready-domain/ready-certificate gate again.
type M3AccessHTTPHandler struct {
	Controller *controllers.M3AccessController
}

type m3IPFallbackInput struct {
	ApplicationID domain.ID `json:"application_id"`
	DeploymentID  domain.ID `json:"deployment_id"`
	ServiceName   string    `json:"service_name"`
	Port          int       `json:"port"`
	Path          string    `json:"path"`
	Routable      bool      `json:"routable"`
	ServerIP      string    `json:"server_ip"`
	RuntimeReady  bool      `json:"runtime_ready"`
}

type m3PlatformDomainInput struct {
	BaseDomain string `json:"base_domain"`
	DNSTarget  string `json:"dns_target"`
}

type m3ApplicationDomainInput struct {
	ApplicationID domain.ID `json:"application_id"`
	Host          string    `json:"host"`
	CNAMETarget   string    `json:"cname_target"`
}

type m3PlatformApplicationDomainInput struct {
	ApplicationID   domain.ID            `json:"application_id"`
	ApplicationName string               `json:"application_name"`
	Platform        domain.DomainBinding `json:"platform"`
}

type m3DomainRoutesInput struct {
	Binding      domain.DomainBinding        `json:"binding"`
	Certificate  domain.CertificateReference `json:"certificate"`
	Targets      []m3RouteTargetInput        `json:"targets"`
	RuntimeReady bool                        `json:"runtime_ready"`
}

type m3PrepareDomainRoutesInput struct {
	Binding      domain.DomainBinding `json:"binding"`
	Targets      []m3RouteTargetInput `json:"targets"`
	RuntimeReady bool                 `json:"runtime_ready"`
}

type m3CertificateRenewInput struct {
	ApplicationID domain.ID                   `json:"application_id"`
	Certificate   domain.CertificateReference `json:"certificate"`
}

type m3TrafficSwitchInput struct {
	ApplicationID  domain.ID             `json:"application_id"`
	Old            []domain.DesiredRoute `json:"old"`
	Candidate      []domain.DesiredRoute `json:"candidate"`
	HealthURL      string                `json:"health_url"`
	ObservationURL string                `json:"observation_url"`
	WindowMS       int                   `json:"window_ms"`
}

type m3RouteTargetInput struct {
	ApplicationID domain.ID `json:"application_id"`
	DeploymentID  domain.ID `json:"deployment_id"`
	ServiceName   string    `json:"service_name"`
	Port          int       `json:"port"`
	Path          string    `json:"path"`
	Routable      bool      `json:"routable"`
}

func (input m3RouteTargetInput) target() controllers.M3RouteTarget {
	return controllers.M3RouteTarget{
		ApplicationID: input.ApplicationID,
		DeploymentID:  input.DeploymentID,
		ServiceName:   input.ServiceName,
		Port:          input.Port,
		Path:          input.Path,
		Routable:      input.Routable,
	}
}

// Handle returns false for paths outside the M3 access API. The parent
// server can therefore compose it without accidentally shadowing other APIs.
func (h *M3AccessHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if !strings.HasPrefix(request.URL.Path, m3AccessAPIBase) {
		return false
	}
	if h == nil || h.Controller == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "m3_access_unavailable", "M3 access controller is not configured")
		return true
	}

	switch request.URL.Path {
	case m3AccessAPIBase + "ip-fallback":
		h.handleIPFallback(writer, request)
	case m3AccessAPIBase + "platform-domains":
		h.handlePlatformDomain(writer, request)
	case m3AccessAPIBase + "application-domains":
		h.handleApplicationDomain(writer, request)
	case m3AccessAPIBase + "platform-application-domains":
		h.handlePlatformApplicationDomain(writer, request)
	case m3AccessAPIBase + "domain-routes":
		h.handleDomainRoutes(writer, request)
	case m3AccessAPIBase + "domain-routes/prepare":
		h.handlePrepareDomainRoutes(writer, request)
	case m3AccessAPIBase + "certificates/renew":
		h.handleCertificateRenew(writer, request)
	case m3AccessAPIBase + "traffic-switches":
		h.handleTrafficSwitch(writer, request)
	default:
		writeJSONError(writer, http.StatusNotFound, "not_found", "M3 access route not found")
	}
	return true
}

func (h *M3AccessHTTPHandler) handleTrafficSwitch(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3TrafficSwitchInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	if input.WindowMS < 0 || input.WindowMS > 10_000 {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", "window_ms is outside the allowed range")
		return
	}
	health, err := m3LoopbackHTTPCheck(input.HealthURL)
	if err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	observe, err := m3LoopbackHTTPCheck(input.ObservationURL)
	if err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	err = h.Controller.Switch(request.Context(), controllers.M3SwitchRequest{ApplicationID: input.ApplicationID, Old: input.Old, Candidate: input.Candidate, IdempotencyKey: key, Actor: m3Actor(request), Window: time.Duration(input.WindowMS) * time.Millisecond, Healthy: func(ctx context.Context, _ domain.ID) error { return health(ctx) }, Observe: func(ctx context.Context, _ domain.ID) error { return observe(ctx) }})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"status": "stable", "serving_deployment_id": input.Candidate[0].Route.DeploymentID})
}

func m3LoopbackHTTPCheck(raw string) (func(context.Context) error, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return nil, errors.New("health URL must be a plain loopback HTTP URL")
	}
	host := parsed.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("health URL must use loopback")
		}
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return errors.New("health observation was not successful")
		}
		return nil
	}, nil
}

func (h *M3AccessHTTPHandler) handleCertificateRenew(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3CertificateRenewInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	certificate, err := h.Controller.RenewCertificate(request.Context(), input.ApplicationID, input.Certificate, key, m3Actor(request))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"certificate": certificate})
}

func (h *M3AccessHTTPHandler) handlePlatformApplicationDomain(writer http.ResponseWriter, request *http.Request) {
	_, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3PlatformApplicationDomainInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	binding, err := h.Controller.CreatePlatformApplicationDomain(request.Context(), input.ApplicationID, input.ApplicationName, input.Platform)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"binding": binding, "access_state": domain.AccessState{ApplicationID: input.ApplicationID, DomainStatus: binding.Status, Domain: binding.Host, HTTPSReady: true, Serving: false, Message: "stable platform hostname is ready for routes"}})
}

func (h *M3AccessHTTPHandler) handleIPFallback(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3IPFallbackInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	state, err := h.Controller.EnsureIPFallback(request.Context(), controllers.M3IPFallbackRequest{
		Target:         m3RouteTargetInput{ApplicationID: input.ApplicationID, DeploymentID: input.DeploymentID, ServiceName: input.ServiceName, Port: input.Port, Path: input.Path, Routable: input.Routable}.target(),
		ServerIP:       input.ServerIP,
		RuntimeReady:   input.RuntimeReady,
		IdempotencyKey: key,
		Actor:          m3Actor(request),
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"access_state": state})
}

func (h *M3AccessHTTPHandler) handlePlatformDomain(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3PlatformDomainInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	binding, certificate, err := h.Controller.BindPlatformDomain(request.Context(), input.BaseDomain, input.DNSTarget, key, m3Actor(request))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"binding":      binding,
		"certificate":  certificate,
		"access_state": m3DomainAccessState(binding, certificate),
	})
}

func (h *M3AccessHTTPHandler) handleApplicationDomain(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3ApplicationDomainInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	binding, certificate, err := h.Controller.BindApplicationDomain(request.Context(), input.ApplicationID, input.Host, input.CNAMETarget, key, m3Actor(request))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"binding":      binding,
		"certificate":  certificate,
		"access_state": m3DomainAccessState(binding, certificate),
	})
}

func (h *M3AccessHTTPHandler) handleDomainRoutes(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3DomainRoutesInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	targets := make([]controllers.M3RouteTarget, 0, len(input.Targets))
	for _, target := range input.Targets {
		targets = append(targets, target.target())
	}
	routes, state, err := h.Controller.ApplyDomainRoutes(request.Context(), controllers.M3DomainRouteRequest{
		Binding:        input.Binding,
		Certificate:    input.Certificate,
		Targets:        targets,
		RuntimeReady:   input.RuntimeReady,
		IdempotencyKey: key,
		Actor:          m3Actor(request),
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"routes": routes, "access_state": state})
}

func (h *M3AccessHTTPHandler) handlePrepareDomainRoutes(writer http.ResponseWriter, request *http.Request) {
	key, ok := m3MutationRequest(writer, request)
	if !ok {
		return
	}
	var input m3PrepareDomainRoutesInput
	if !m3DecodeJSON(writer, request, &input) {
		return
	}
	targets := make([]controllers.M3RouteTarget, 0, len(input.Targets))
	for _, target := range input.Targets {
		targets = append(targets, target.target())
	}
	routes, state, err := h.Controller.PrepareDomainRoutes(request.Context(), controllers.M3PrepareDomainRouteRequest{
		Binding:        input.Binding,
		Targets:        targets,
		RuntimeReady:   input.RuntimeReady,
		IdempotencyKey: key,
		Actor:          m3Actor(request),
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"routes": routes, "access_state": state})
}

func m3MutationRequest(writer http.ResponseWriter, request *http.Request) (string, bool) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return "", false
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func m3DecodeJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	contentType := strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Type")))
	if !strings.HasPrefix(contentType, "application/json") {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	if err := decodeJSON(request, target); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_argument", err.Error())
		return false
	}
	return true
}

func m3Actor(request *http.Request) string {
	return controlPlaneActor(request)
}

func m3DomainAccessState(binding domain.DomainBinding, certificate domain.CertificateReference) domain.AccessState {
	return domain.AccessState{
		ApplicationID: binding.ApplicationID,
		DomainStatus:  binding.Status,
		Domain:        binding.Host,
		HTTPSReady:    binding.Status == domain.DomainReady && certificate.Status == domain.CertificateReady,
		Serving:       false,
		Message:       "domain is ready for routes after verified route targets are applied",
	}
}
