// Package caddy implements the Open Card RouteProvider against Caddy's local
// Admin API. Caddy receives a derived configuration only: route facts remain
// owned by the control plane and the in-memory cache can always be discarded.
package caddy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "caddy-local-admin"
	providerVersion = "m3"
	defaultAdminURL = "http://127.0.0.1:2019"
	defaultListen   = ":443"
	defaultTimeout  = 10 * time.Second
	maxResponseSize = 1 << 20
)

// Config contains only the Caddy Admin and public-listener boundaries. AdminURL
// is deliberately HTTP-only: this API is a local privilege boundary, never a
// network service for the control plane or browser.
type Config struct {
	AdminURL   string
	Listen     string
	Issuer     string
	HTTPClient *http.Client
	Timeout    time.Duration
	Clock      func() time.Time
}

// Provider maintains an in-memory, derived view of routes it has applied.
// It is neither durable state nor a source of truth. A composition root must
// replay RouteProvider.Apply from Open Card facts after a Provider restart.
type Provider struct {
	config     Config
	adminURL   *url.URL
	metadata   contracts.ProviderMetadata
	mu         sync.Mutex
	routes     map[string]routeState
	operations map[string]operationState
}

type routeState struct {
	spec        contracts.RouteSpec
	fingerprint string
	route       domain.Route
}

type operationState struct {
	fingerprint string
	route       domain.Route
}

// New constructs a local-only Caddy adapter. It validates the management
// address before any Caddy request is made, so a public Admin API cannot be
// introduced through this provider configuration.
func New(config Config) (*Provider, error) {
	normalized, adminURL, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Provider{
		config:   normalized,
		adminURL: adminURL,
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityRouteManage),
			SensitiveInputs: []string{"certificate reference"},
		},
		routes:     make(map[string]routeState),
		operations: make(map[string]operationState),
	}, nil
}

func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// Apply atomically loads a full derived Caddy JSON configuration. Caddy's
// /load endpoint keeps the previously active configuration when validation or
// provisioning fails, so this method commits its derived cache only afterwards.
func (p *Provider) Apply(ctx context.Context, request contracts.RouteRequest) (domain.Route, contracts.Evidence, error) {
	if err := p.check(ctx, request.Operation, "apply"); err != nil {
		return domain.Route{}, contracts.Evidence{}, err
	}
	fingerprint, err := routeFingerprint(request.Route)
	if err != nil {
		return domain.Route{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrInvalidArgument, "apply", err.Error(), err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.operations[request.Operation.IdempotencyKey]; ok {
		if previous.fingerprint != fingerprint {
			return domain.Route{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrConflict, "apply", "idempotency key was reused for a different route", nil)
		}
		return previous.route, p.evidence(request.Operation, configDigest(p.config, p.routes), "idempotent route apply replayed"), nil
	}
	identity := routeIdentity(request.Route)
	state, exists := p.routes[identity]
	desired := newRouteState(request.Route, fingerprint, p.config.Clock().UTC())
	candidate := cloneRoutes(p.routes)
	candidate[identity] = desired
	if err := validateRouteSet(candidate); err != nil {
		return domain.Route{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrConflict, "apply", err.Error(), err)
	}

	// A cache hit still checks Caddy. This makes an Apply replay recover a
	// Caddy process whose runtime configuration was lost without trusting that
	// runtime configuration as product state.
	if exists && state.fingerprint == fingerprint {
		present, observeErr := p.routePresent(ctx, request.Route, fingerprint, request.Operation)
		if observeErr == nil && present {
			p.operations[request.Operation.IdempotencyKey] = operationState{fingerprint: fingerprint, route: state.route}
			return state.route, p.evidence(request.Operation, configDigest(p.config, candidate), "route configuration already active"), nil
		}
		if observeErr != nil && !isNotFound(observeErr) {
			return domain.Route{}, contracts.Evidence{}, observeErr
		}
	}
	if err := p.load(ctx, candidate, request.Operation, "apply"); err != nil {
		return domain.Route{}, contracts.Evidence{}, err
	}
	p.routes = candidate
	p.operations[request.Operation.IdempotencyKey] = operationState{fingerprint: fingerprint, route: desired.route}
	return desired.route, p.evidence(request.Operation, configDigest(p.config, candidate), "derived route configuration atomically loaded"), nil
}

// Observe reads Caddy's live configuration. It reports a fact about the
// configured route, not an end-to-end HTTPS health result; the latter belongs
// to the controller's route/certificate health workflow.
func (p *Provider) Observe(ctx context.Context, request contracts.RouteRequest) (domain.Observation, error) {
	if err := p.check(ctx, request.Operation, "observe"); err != nil {
		return domain.Observation{}, err
	}
	fingerprint, err := routeFingerprint(request.Route)
	if err != nil {
		return domain.Observation{}, p.failure(request.Operation, contracts.ErrInvalidArgument, "observe", err.Error(), err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	present, err := p.routePresent(ctx, request.Route, fingerprint, request.Operation)
	if err != nil {
		return domain.Observation{}, err
	}
	if !present {
		return domain.Observation{}, p.failure(request.Operation, contracts.ErrNotFound, "observe", "route is not present in Caddy configuration", nil)
	}
	observation := domain.Observation{
		ID:         domain.ID("obs_" + fingerprint[:32]),
		TargetRef:  normalizedHost(request.Route.Host) + normalizedPath(request.Route.Path),
		Kind:       "route.actual",
		Value:      true,
		Source:     providerName,
		ObservedAt: p.config.Clock().UTC(),
		Evidence:   p.evidence(request.Operation, configDigest(p.config, p.routes), "route observed in Caddy configuration").Refs,
	}
	if err := observation.Validate(); err != nil {
		return domain.Observation{}, p.failure(request.Operation, contracts.ErrValidation, "observe", "route observation is invalid", err)
	}
	return observation, nil
}

// Remove is idempotent. It only reloads Caddy if this derived cache owns the
// route, avoiding a destructive empty load when a freshly started provider is
// asked to remove a route that must instead be reconciled by the control plane.
func (p *Provider) Remove(ctx context.Context, request contracts.RouteRequest) error {
	if err := p.check(ctx, request.Operation, "remove"); err != nil {
		return err
	}
	fingerprint, err := routeFingerprint(request.Route)
	if err != nil {
		return p.failure(request.Operation, contracts.ErrInvalidArgument, "remove", err.Error(), err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	identity := routeIdentity(request.Route)
	state, exists := p.routes[identity]
	if !exists {
		return nil
	}
	if state.fingerprint != fingerprint {
		return p.failure(request.Operation, contracts.ErrConflict, "remove", "route has changed since this remove request was created", nil)
	}
	candidate := cloneRoutes(p.routes)
	delete(candidate, identity)
	if err := p.load(ctx, candidate, request.Operation, "remove"); err != nil {
		return err
	}
	p.routes = candidate
	for key, operationState := range p.operations {
		if operationState.fingerprint == fingerprint {
			delete(p.operations, key)
		}
	}
	return nil
}

// Rebuild reloads only the currently derived cache. If the cache has been
// discarded (including after this Provider restarts), it fails closed rather
// than reading Caddy as a source of truth. The composition root must then
// replay Apply from persisted Open Card Route facts.
func (p *Provider) Rebuild(ctx context.Context, operation contracts.OperationContext) (contracts.Evidence, error) {
	if err := p.check(ctx, operation, "rebuild"); err != nil {
		return contracts.Evidence{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.routes) == 0 {
		return contracts.Evidence{}, p.failure(operation, contracts.ErrConflict, "rebuild", "route rebuild requires the control plane to replay persisted route facts", nil)
	}
	if err := p.load(ctx, p.routes, operation, "rebuild"); err != nil {
		return contracts.Evidence{}, err
	}
	return p.evidence(operation, configDigest(p.config, p.routes), "derived route configuration rebuilt"), nil
}

// RebuildRoutes replaces the entire derived cache from caller-supplied Open
// Card facts and atomically loads it. It is the restart-safe rebuild path: the
// provider neither reads nor promotes a previous Caddy configuration to facts.
func (p *Provider) RebuildRoutes(ctx context.Context, requests []contracts.RouteRequest, operation contracts.OperationContext) (contracts.Evidence, error) {
	if err := p.check(ctx, operation, "rebuild_routes"); err != nil {
		return contracts.Evidence{}, err
	}
	candidate := make(map[string]routeState, len(requests))
	for _, request := range requests {
		fingerprint, err := routeFingerprint(request.Route)
		if err != nil {
			return contracts.Evidence{}, p.failure(operation, contracts.ErrInvalidArgument, "rebuild_routes", err.Error(), err)
		}
		identity := routeIdentity(request.Route)
		if previous, exists := candidate[identity]; exists && previous.fingerprint != fingerprint {
			return contracts.Evidence{}, p.failure(operation, contracts.ErrConflict, "rebuild_routes", "multiple persisted facts claim the same route", nil)
		}
		candidate[identity] = newRouteState(request.Route, fingerprint, p.config.Clock().UTC())
	}
	if err := validateRouteSet(candidate); err != nil {
		return contracts.Evidence{}, p.failure(operation, contracts.ErrConflict, "rebuild_routes", err.Error(), err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.load(ctx, candidate, operation, "rebuild_routes"); err != nil {
		return contracts.Evidence{}, err
	}
	p.routes = candidate
	p.operations = make(map[string]operationState)
	return p.evidence(operation, configDigest(p.config, candidate), "derived route configuration rebuilt from Open Card route facts"), nil
}

// ClearDerivedCache intentionally removes provider-local state only. It never
// contacts Caddy. This supports crash/restart tests and makes it explicit that
// Caddy's configuration is not a substitute for persisted Route facts.
func (p *Provider) ClearDerivedCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes = make(map[string]routeState)
	p.operations = make(map[string]operationState)
}

func normalizeConfig(config Config) (Config, *url.URL, error) {
	if strings.TrimSpace(config.AdminURL) == "" {
		config.AdminURL = defaultAdminURL
	}
	endpoint, err := validateAdminURL(config.AdminURL)
	if err != nil {
		return Config{}, nil, err
	}
	if strings.TrimSpace(config.Listen) == "" {
		config.Listen = defaultListen
	}
	if _, port, err := net.SplitHostPort(config.Listen); err != nil {
		return Config{}, nil, errors.New("caddy listener must be host:port or :port")
	} else if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return Config{}, nil, errors.New("caddy listener port is invalid")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout <= 0 {
		return Config{}, nil, errors.New("caddy timeout must be positive")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if strings.TrimSpace(config.Issuer) == "" {
		config.Issuer = "internal"
	}
	if config.Issuer != "internal" {
		return Config{}, nil, errors.New("M3 Caddy provider only permits the isolated internal issuer")
	}
	transport := http.DefaultTransport
	if config.HTTPClient != nil && config.HTTPClient.Transport != nil {
		transport = config.HTTPClient.Transport
	}
	config.HTTPClient = &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	config.AdminURL = endpoint.String()
	return config, endpoint, nil
}

func validateAdminURL(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return nil, errors.New("caddy admin URL must be a plain loopback http URL")
	}
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		return nil, errors.New("caddy admin URL must include an explicit port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("caddy admin URL port is invalid")
	}
	if strings.EqualFold(host, "localhost") {
		lookupContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		addresses, lookupErr := net.DefaultResolver.LookupNetIP(lookupContext, "ip", host)
		if lookupErr != nil || len(addresses) == 0 {
			return nil, errors.New("caddy admin localhost address could not be verified as loopback")
		}
		for _, address := range addresses {
			if !address.IsLoopback() {
				return nil, errors.New("caddy admin localhost address is not loopback")
			}
		}
	} else {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("caddy admin URL must use a loopback address")
		}
	}
	endpoint.Path = ""
	return endpoint, nil
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, action string) error {
	if err := p.metadata.Supports(contracts.CapabilityRouteManage); err != nil {
		return p.failure(operation, contracts.ErrUnsupportedCapability, action, "Caddy route capability is unavailable", err)
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, contracts.ErrInvalidArgument, action, "provider idempotency key is required", err)
	}
	if err := ctx.Err(); err != nil {
		return p.classify(operation, action, err)
	}
	if !operation.Deadline.IsZero() && !p.config.Clock().Before(operation.Deadline) {
		return p.classify(operation, action, context.DeadlineExceeded)
	}
	return nil
}

func (p *Provider) load(ctx context.Context, routes map[string]routeState, operation contracts.OperationContext, action string) error {
	body, err := configJSON(p.config, routes)
	if err != nil {
		return p.failure(operation, contracts.ErrValidation, action, "derived Caddy configuration could not be encoded", err)
	}
	requestContext, cancel := operationContext(ctx, operation, p.config.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, p.endpoint("/load"), bytes.NewReader(body))
	if err != nil {
		return p.failure(operation, contracts.ErrUnavailable, action, "Caddy Admin request could not be created", err)
	}
	request.Header.Set("Content-Type", "application/json")
	setRouteFixtureScopeHeaders(request, operation)
	response, err := p.config.HTTPClient.Do(request)
	if err != nil {
		return p.classify(operation, action, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseSize))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return p.statusFailure(operation, action, response.StatusCode)
	}
	return nil
}

func (p *Provider) routePresent(ctx context.Context, spec contracts.RouteSpec, fingerprint string, operation contracts.OperationContext) (bool, error) {
	requestContext, cancel := operationContext(ctx, operation, p.config.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, p.endpoint("/config/"), nil)
	if err != nil {
		return false, p.failure(operation, contracts.ErrUnavailable, "observe", "Caddy Admin request could not be created", err)
	}
	setRouteFixtureScopeHeaders(request, operation)
	response, err := p.config.HTTPClient.Do(request)
	if err != nil {
		return false, p.classify(operation, "observe", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return false, p.statusFailure(operation, "observe", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseSize))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return false, p.failure(operation, contracts.ErrValidation, "observe", "Caddy returned invalid configuration JSON", err)
	}
	return routeMatches(document, routeID(fingerprint), spec), nil
}

func setRouteFixtureScopeHeaders(request *http.Request, operation contracts.OperationContext) {
	if request == nil {
		return
	}
	if index := strings.Index(operation.IdempotencyKey, ":"); index > 0 {
		request.Header.Set("X-Open-Card-Rollout-ID", operation.IdempotencyKey[:index])
	}
	evidenceID := operation.EvidenceID.String()
	if strings.HasPrefix(evidenceID, "sha256:") && len(evidenceID) == len("sha256:")+64 {
		request.Header.Set("X-Open-Card-Route-Digest", evidenceID)
	}
}

func (p *Provider) endpoint(path string) string {
	endpoint := *p.adminURL
	endpoint.Path = path
	endpoint.RawPath = ""
	return endpoint.String()
}

func (p *Provider) evidence(operation contracts.OperationContext, digest, summary string) contracts.Evidence {
	if !strings.HasPrefix(digest, "sha256:") {
		digest = "sha256:" + digest
	}
	short := strings.TrimPrefix(digest, "sha256:")
	if len(short) > 32 {
		short = short[:32]
	}
	return contracts.Evidence{
		Refs: []domain.EvidenceRef{
			{ID: domain.ID("ev_" + short), Kind: "route.desired", Digest: digest, Locator: "caddy://route-provider/desired/" + short},
			{ID: domain.ID("ev_actual_" + short), Kind: "route.actual", Digest: digest, Locator: "caddy://route-provider/actual/" + short},
		},
		Summary:  summary,
		Digest:   digest,
		Redacted: true,
	}
}

func (p *Provider) failure(operation contracts.OperationContext, code contracts.ErrorCode, action, message string, cause error) *contracts.ProviderError {
	retry, retryable := contracts.RetryNever, false
	switch code {
	case contracts.ErrUnavailable, contracts.ErrTimeout:
		retry, retryable = contracts.RetryBackoff, true
	case contracts.ErrCancelled:
		retry, retryable = contracts.RetryAfterReconnect, true
	case contracts.ErrConflict:
		retry = contracts.RetryUserAction
	}
	digest := sha256.Sum256([]byte(operation.IdempotencyKey))
	short := hex.EncodeToString(digest[:])[:32]
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: contracts.CapabilityRouteManage, Operation: action, Cause: cause, Details: map[string]string{
		"evidence_ref": "ev_" + short,
		"log_ref":      "caddy://route-provider/operations/" + short,
	}}
}

func (p *Provider) classify(operation contracts.OperationContext, action string, err error) error {
	if errors.Is(err, context.Canceled) {
		return p.failure(operation, contracts.ErrCancelled, action, "Caddy operation was cancelled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return p.failure(operation, contracts.ErrTimeout, action, "Caddy operation timed out", err)
	}
	return p.failure(operation, contracts.ErrUnavailable, action, "Caddy Admin API is unavailable", err)
}

func (p *Provider) statusFailure(operation contracts.OperationContext, action string, status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return p.failure(operation, contracts.ErrUnauthorized, action, "Caddy Admin API rejected the request", nil)
	case status == http.StatusConflict:
		return p.failure(operation, contracts.ErrConflict, action, "Caddy rejected the requested route configuration", nil)
	case status >= 400 && status < 500:
		return p.failure(operation, contracts.ErrValidation, action, "Caddy rejected the derived configuration", nil)
	default:
		return p.failure(operation, contracts.ErrUnavailable, action, "Caddy Admin API did not accept the request", nil)
	}
}

func isNotFound(err error) bool {
	var providerErr *contracts.ProviderError
	return errors.As(err, &providerErr) && providerErr.Code == contracts.ErrNotFound
}

func operationContext(ctx context.Context, operation contracts.OperationContext, timeout time.Duration) (context.Context, context.CancelFunc) {
	if !operation.Deadline.IsZero() {
		return context.WithDeadline(ctx, operation.Deadline)
	}
	return context.WithTimeout(ctx, timeout)
}

func routeFingerprint(spec contracts.RouteSpec) (string, error) {
	host, hostErr := domain.NormalizeRouteHost(spec.Host)
	path, pathErr := domain.NormalizeRoutePath(spec.Path)
	if hostErr != nil || pathErr != nil || spec.DeploymentID.Empty() || spec.Port < 1 || spec.Port > 65535 || !spec.Verified {
		return "", errors.New("verified route host, absolute path, deployment, and port are required")
	}
	return digestString(host, path, string(spec.DeploymentID), spec.ServiceName, strconv.Itoa(spec.Port), spec.CertificateRef, strconv.FormatBool(spec.Verified)), nil
}

// routeIdentity is the externally claimed coordinate. Target deployment,
// backend port, and certificate reference are desired-state details that may
// change during an atomic cutover without creating a second public route.
func routeIdentity(spec contracts.RouteSpec) string {
	host, _ := domain.NormalizeRouteHost(spec.Host)
	path, _ := domain.NormalizeRoutePath(spec.Path)
	return host + "\x00" + path
}

func newRouteState(spec contracts.RouteSpec, fingerprint string, now time.Time) routeState {
	return routeState{
		spec:        spec,
		fingerprint: fingerprint,
		route: domain.Route{
			ID:             domain.ID("route_" + digestString(routeIdentity(spec))[:32]),
			ApplicationID:  domain.ID("app_caddy"), // RouteSpec deliberately carries no application ID.
			DeploymentID:   spec.DeploymentID,
			ServiceName:    spec.ServiceName,
			Host:           normalizedHost(spec.Host),
			Path:           normalizedPath(spec.Path),
			CertificateRef: spec.CertificateRef,
			Verified:       spec.Verified,
			Serving:        true,
			CreatedAt:      now,
		},
	}
}

func cloneRoutes(routes map[string]routeState) map[string]routeState {
	copy := make(map[string]routeState, len(routes))
	for key, route := range routes {
		copy[key] = route
	}
	return copy
}

func validateRouteSet(routes map[string]routeState) error {
	values := make([]routeState, 0, len(routes))
	for _, route := range routes {
		values = append(values, route)
	}
	for index, left := range values {
		for _, right := range values[index+1:] {
			if normalizedHost(left.spec.Host) != normalizedHost(right.spec.Host) {
				continue
			}
			leftPath, rightPath := normalizedPath(left.spec.Path), normalizedPath(right.spec.Path)
			if leftPath == rightPath || (leftPath != "/" && rightPath != "/" && pathsOverlap(leftPath, rightPath)) {
				return fmt.Errorf("Caddy route conflict for host %q between %q and %q", normalizedHost(left.spec.Host), leftPath, rightPath)
			}
		}
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	return strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func configJSON(config Config, routes map[string]routeState) ([]byte, error) {
	ordered := make([]routeState, 0, len(routes))
	for _, route := range routes {
		ordered = append(ordered, route)
	}
	sort.Slice(ordered, func(i, j int) bool {
		leftHost, rightHost := normalizedHost(ordered[i].spec.Host), normalizedHost(ordered[j].spec.Host)
		if leftHost != rightHost {
			return leftHost < rightHost
		}
		leftPath, rightPath := normalizedPath(ordered[i].spec.Path), normalizedPath(ordered[j].spec.Path)
		if len(leftPath) != len(rightPath) {
			return len(leftPath) > len(rightPath) // /api before / fallback.
		}
		return leftPath < rightPath
	})
	caddyRoutes := make([]any, 0, len(ordered))
	for _, state := range ordered {
		caddyRoutes = append(caddyRoutes, caddyRoute(state))
	}
	document := map[string]any{
		"admin": map[string]any{"listen": config.adminListen()},
		"apps": map[string]any{
			"http": map[string]any{"servers": map[string]any{
				"open-card": map[string]any{
					"listen":          []string{config.Listen},
					"routes":          caddyRoutes,
					"automatic_https": map[string]any{"disable_redirects": true},
				},
			}},
			"tls": map[string]any{"automation": map[string]any{"policies": []any{
				map[string]any{"issuers": []any{map[string]any{"module": config.Issuer}}},
			}}},
		},
	}
	return json.Marshal(document)
}

func (c Config) adminListen() string {
	endpoint, _ := url.Parse(c.AdminURL)
	if endpoint == nil {
		return "127.0.0.1:2019"
	}
	return endpoint.Host
}

func caddyRoute(state routeState) map[string]any {
	path := normalizedPath(state.spec.Path)
	paths := []string{path, path + "/*"}
	if path == "/" {
		paths = []string{"/*"}
	}
	return map[string]any{
		"@id":    routeID(state.fingerprint),
		"match":  []any{map[string]any{"host": []string{normalizedHost(state.spec.Host)}, "path": paths}},
		"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": net.JoinHostPort("127.0.0.1", strconv.Itoa(state.spec.Port))}}}},
	}
}

func routeMatches(document any, id string, spec contracts.RouteSpec) bool {
	switch value := document.(type) {
	case map[string]any:
		if value["@id"] == id {
			return routeMapMatches(value, spec)
		}
		for _, nested := range value {
			if routeMatches(nested, id, spec) {
				return true
			}
		}
	case []any:
		for _, nested := range value {
			if routeMatches(nested, id, spec) {
				return true
			}
		}
	}
	return false
}

func routeMapMatches(route map[string]any, spec contracts.RouteSpec) bool {
	matcher, ok := firstMap(route["match"])
	if !ok || !containsString(matcher["host"], normalizedHost(spec.Host)) {
		return false
	}
	path := normalizedPath(spec.Path)
	wantPaths := []string{path, path + "/*"}
	if path == "/" {
		wantPaths = []string{"/*"}
	}
	for _, want := range wantPaths {
		if !containsString(matcher["path"], want) {
			return false
		}
	}
	for _, handler := range maps(route["handle"]) {
		if handler["handler"] != "reverse_proxy" {
			continue
		}
		for _, upstream := range maps(handler["upstreams"]) {
			if upstream["dial"] == net.JoinHostPort("127.0.0.1", strconv.Itoa(spec.Port)) {
				return true
			}
		}
	}
	return false
}

func firstMap(value any) (map[string]any, bool) {
	maps := maps(value)
	if len(maps) == 0 {
		return nil, false
	}
	return maps[0], true
}

func maps(value any) []map[string]any {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if mapped, ok := value.(map[string]any); ok {
			result = append(result, mapped)
		}
	}
	return result
}

func containsString(value any, want string) bool {
	values, ok := value.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		if actual, ok := value.(string); ok && actual == want {
			return true
		}
	}
	return false
}

func validRoutePath(path string) bool {
	return strings.HasPrefix(strings.TrimSpace(path), "/") && !strings.Contains(path, "//") && !strings.Contains(path, "?") && !strings.Contains(path, "#")
}

func normalizedHost(host string) string { return strings.ToLower(strings.TrimSpace(host)) }

func normalizedPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "/" {
		return path
	}
	return strings.TrimRight(path, "/")
}

func routeID(fingerprint string) string { return "open-card-route-" + fingerprint[:32] }

func configDigest(config Config, routes map[string]routeState) string {
	// Hash the exact deterministic config submitted to /load. Certificate
	// material never appears in this JSON; CertificateRef only affects the
	// in-memory idempotency fingerprint.
	document, err := configJSON(config, routes)
	if err != nil {
		return digestString("invalid-derived-caddy-config")
	}
	hash := sha256.Sum256(document)
	return hex.EncodeToString(hash[:])
}

func digestString(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

var (
	_ contracts.RouteProvider     = (*Provider)(nil)
	_ contracts.RouteSetRebuilder = (*Provider)(nil)
)
