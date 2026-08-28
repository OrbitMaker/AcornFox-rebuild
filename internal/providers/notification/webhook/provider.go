// Package webhook implements the outbound, signed NotificationProvider used
// by M4. It is intentionally strict about egress: a configured endpoint may
// only resolve to public addresses, except for an explicit 127.0.0.1 fixture.
package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	providerName    = "signed-webhook"
	providerVersion = "m4"
	requestTimeout  = 3 * time.Second
)

var (
	errConflict         = errors.New("webhook operation conflicts with existing state")
	errSensitivePayload = errors.New("notification payload contains raw private key material")
	errUnsafeTarget     = errors.New("webhook target is not publicly routable")
	errDNSResolve       = errors.New("webhook target DNS resolution failed")
	defaultRetryDelays  = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}
	privateNetworks     = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	)
)

// Config keeps the signing secret in process memory only. No String method,
// log entry, or result exposes it. RetryDelays may contain at most three
// entries, preserving the bounded retry policy from ADR-0008.
type Config struct {
	Endpoint string
	Secret   string

	RetryDelays []time.Duration
	Clock       func() time.Time
	LookupIP    func(context.Context, string) ([]net.IPAddr, error)

	// AllowLoopbackFixture is task-fixture-only. It accepts the literal
	// 127.0.0.1 or the single fixed internal hostname
	// opencard-webhook-fixture.test when it resolves only to 127.0.0.1.
	// localhost, IPv6 loopback, arbitrary fixture hostnames, and private DNS
	// answers remain rejected.
	AllowLoopbackFixture bool
}

type operationRecord struct {
	eventID     domain.ID
	fingerprint string
	done        chan struct{}
	err         error
}

// Provider is concurrency-safe within one control-plane process. Durable
// cross-restart delivery records belong to the controller persistence layer;
// callers must not infer durability from this in-memory dedupe cache.
type Provider struct {
	metadata contracts.ProviderMetadata
	endpoint *url.URL
	secret   string
	clock    func() time.Time
	lookupIP func(context.Context, string) ([]net.IPAddr, error)
	retries  []time.Duration
	loopback bool

	mu          sync.Mutex
	eventHashes map[domain.ID]string
	delivered   map[domain.ID]struct{}
	operations  map[string]*operationRecord
	testEvents  map[string]contracts.Notification
}

func New(config Config) (*Provider, error) {
	endpoint, err := parseEndpoint(config.Endpoint, config.AllowLoopbackFixture)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.Secret) == "" {
		return nil, errors.New("webhook signing secret is required")
	}
	retries, err := normalizeRetries(config.RetryDelays)
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	lookup := config.LookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	return &Provider{
		metadata: contracts.ProviderMetadata{
			Name: providerName, Version: providerVersion, ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityNotification),
			SensitiveInputs: []string{"webhook.signing_secret", "notification.payload"},
		},
		endpoint: endpoint, secret: config.Secret, clock: clock, lookupIP: lookup, retries: retries, loopback: config.AllowLoopbackFixture,
		eventHashes: make(map[domain.ID]string), delivered: make(map[domain.ID]struct{}), operations: make(map[string]*operationRecord), testEvents: make(map[string]contracts.Notification),
	}, nil
}

func NewProvider(config Config) (*Provider, error)                      { return New(config) }
func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }
func (p *Provider) String() string                                      { return providerName }
func (p *Provider) GoString() string                                    { return providerName + "{}" }

// Send redacts and validates a JSON payload before any outbound request. The
// EventID is the receiver's dedupe key and is sent unchanged across retries.
func (p *Provider) Send(ctx context.Context, notification contracts.Notification, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, "send"); err != nil {
		return err
	}
	if !operation.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, operation.Deadline)
		defer cancel()
	}
	if notification.EventID.Empty() || strings.TrimSpace(notification.EventType) == "" || notification.OccurredAt.IsZero() {
		return p.failure("send", contracts.ErrInvalidArgument, "notification event id, type, and time are required", nil, false)
	}
	payload, err := p.redactedPayload(notification.Payload)
	if err != nil {
		return p.failure("send", contracts.ErrInvalidArgument, "notification payload is invalid or contains raw key material", err, false)
	}
	stamp := notification.OccurredAt.UTC()
	fingerprint := notificationFingerprint(notification, payload)

	p.mu.Lock()
	if prior, exists := p.operations[operation.IdempotencyKey]; exists {
		if prior.eventID != notification.EventID || prior.fingerprint != fingerprint {
			p.mu.Unlock()
			return p.failure("send", contracts.ErrConflict, "webhook operation conflicts with existing state", errConflict, false)
		}
		done := prior.done
		p.mu.Unlock()
		select {
		case <-done:
			return prior.err
		case <-ctx.Done():
			return p.contextFailure("send", ctx.Err())
		}
	}
	if previous, exists := p.eventHashes[notification.EventID]; exists && previous != fingerprint {
		p.mu.Unlock()
		return p.failure("send", contracts.ErrConflict, "webhook event id was reused for different content", errConflict, false)
	}
	if _, exists := p.delivered[notification.EventID]; exists {
		p.operations[operation.IdempotencyKey] = &operationRecord{eventID: notification.EventID, fingerprint: fingerprint, done: closedChannel()}
		p.mu.Unlock()
		return nil
	}
	record := &operationRecord{eventID: notification.EventID, fingerprint: fingerprint, done: make(chan struct{})}
	p.eventHashes[notification.EventID] = fingerprint
	p.operations[operation.IdempotencyKey] = record
	p.mu.Unlock()

	err = p.deliver(ctx, notification.EventID, notification.EventType, stamp, payload)
	p.mu.Lock()
	record.err = err
	if err == nil {
		p.delivered[notification.EventID] = struct{}{}
	}
	close(record.done)
	p.mu.Unlock()
	return err
}

// Test sends a deterministic, redacted test event through the actual endpoint.
func (p *Provider) Test(ctx context.Context, operation contracts.OperationContext) error {
	if err := operation.Validate(); err != nil {
		return p.failure("test", contracts.ErrInvalidArgument, "provider idempotency key is required", err, false)
	}
	p.mu.Lock()
	notification, exists := p.testEvents[operation.IdempotencyKey]
	if !exists {
		sum := sha256.Sum256([]byte(p.endpoint.String() + "\x00" + operation.IdempotencyKey))
		notification = contracts.Notification{
			EventID: domain.ID("webhook-test-" + hex.EncodeToString(sum[:])[:24]), EventType: "notification.test",
			Payload: map[string]any{"test": true}, OccurredAt: p.clock().UTC(),
		}
		p.testEvents[operation.IdempotencyKey] = notification
	}
	p.mu.Unlock()
	operation.IdempotencyKey += ":webhook-test"
	return p.Send(ctx, notification, operation)
}

func (p *Provider) deliver(ctx context.Context, eventID domain.ID, eventType string, occurredAt time.Time, payload []byte) error {
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			delay := p.retries[attempt-1]
			if delay > 0 {
				select {
				case <-ctx.Done():
					return p.contextFailure("send", ctx.Err())
				case <-time.After(delay):
				}
			}
		}
		err := p.deliverOnce(ctx, eventID, eventType, occurredAt, payload)
		if err == nil {
			return nil
		}
		if !retryable(err) || attempt >= len(p.retries) {
			return err
		}
	}
}

func (p *Provider) deliverOnce(ctx context.Context, eventID domain.ID, eventType string, occurredAt time.Time, payload []byte) error {
	requestCtx, cancel := withBoundedTimeout(ctx)
	defer cancel()
	ips, err := p.resolveTarget(requestCtx)
	if err != nil {
		if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			return p.failure("send", contracts.ErrTimeout, "webhook delivery timed out", err, true)
		}
		if errors.Is(err, errDNSResolve) {
			return p.failure("send", contracts.ErrUnavailable, "webhook target could not be resolved", err, true)
		}
		return p.failure("send", contracts.ErrForbidden, "webhook target is not allowed", err, false)
	}
	signature, err := foundation.SignWebhook(p.secret, occurredAt.Unix(), eventID.String(), payload)
	if err != nil {
		return p.failure("send", contracts.ErrInvalidArgument, "webhook signature inputs are invalid", err, false)
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, p.endpoint.String(), strings.NewReader(string(payload)))
	if err != nil {
		return p.failure("send", contracts.ErrInvalidArgument, "webhook request is invalid", err, false)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "open-card-webhook/"+providerVersion)
	request.Header.Set("X-Open-Card-Event-ID", eventID.String())
	request.Header.Set("X-Open-Card-Event-Type", eventType)
	request.Header.Set("X-Open-Card-Timestamp", fmt.Sprint(occurredAt.Unix()))
	request.Header.Set("X-Open-Card-Signature", signature)
	client := p.clientFor(ips)
	response, err := client.Do(request)
	client.CloseIdleConnections()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			return p.failure("send", contracts.ErrTimeout, "webhook delivery timed out", err, true)
		}
		if errors.Is(err, context.Canceled) || errors.Is(requestCtx.Err(), context.Canceled) {
			return p.failure("send", contracts.ErrCancelled, "webhook delivery was cancelled", err, true)
		}
		return p.failure("send", contracts.ErrUnavailable, "webhook delivery failed", err, true)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return p.failure("send", contracts.ErrForbidden, "webhook redirect response was rejected", nil, false)
	}
	if response.StatusCode >= http.StatusInternalServerError || response.StatusCode == http.StatusTooManyRequests {
		return p.failure("send", contracts.ErrUnavailable, "webhook receiver is unavailable", nil, true)
	}
	return p.failure("send", contracts.ErrUnavailable, "webhook receiver rejected delivery", nil, false)
}

func (p *Provider) clientFor(ips []net.IPAddr) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialResolvedIPs(ips)
	return &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *Provider) resolveTarget(ctx context.Context) ([]net.IPAddr, error) {
	host := strings.TrimSuffix(strings.ToLower(p.endpoint.Hostname()), ".")
	if host == "" || host == "localhost" {
		return nil, errUnsafeTarget
	}
	if p.loopback && !webhookLoopbackFixtureHost(host) {
		return nil, errUnsafeTarget
	}
	if parsed := net.ParseIP(host); parsed != nil {
		ips := []net.IPAddr{{IP: parsed}}
		if err := validateIPs(ips, p.loopback); err != nil {
			return nil, err
		}
		return ips, nil
	}
	ips, err := p.lookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errDNSResolve
	}
	if err := validateIPs(ips, p.loopback); err != nil {
		return nil, err
	}
	return ips, nil
}

func (p *Provider) redactedPayload(value map[string]any) ([]byte, error) {
	redactor := foundation.NewRedactor(p.secret)
	redacted := redactor.RedactMap(value)
	payload, err := json.Marshal(redacted)
	if err != nil {
		return nil, err
	}
	upper := strings.ToUpper(string(payload))
	if strings.Contains(upper, "-----BEGIN") && strings.Contains(upper, "PRIVATE KEY-----") {
		return nil, errSensitivePayload
	}
	return payload, nil
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, action string) error {
	if err := p.metadata.Supports(contracts.CapabilityNotification); err != nil {
		return p.failure(action, contracts.ErrUnsupportedCapability, "provider capability is not enabled", err, false)
	}
	if err := operation.Validate(); err != nil {
		return p.failure(action, contracts.ErrInvalidArgument, "provider idempotency key is required", err, false)
	}
	if !operation.Deadline.IsZero() && !operation.Deadline.After(p.clock()) {
		return p.failure(action, contracts.ErrTimeout, "webhook delivery timed out", context.DeadlineExceeded, true)
	}
	if err := ctx.Err(); err != nil {
		return p.contextFailure(action, err)
	}
	return nil
}

func (p *Provider) contextFailure(action string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return p.failure(action, contracts.ErrTimeout, "webhook delivery timed out", err, true)
	}
	return p.failure(action, contracts.ErrCancelled, "webhook delivery was cancelled", err, true)
}
func (p *Provider) failure(action string, code contracts.ErrorCode, message string, cause error, retryable bool) *contracts.ProviderError {
	retry := contracts.RetryNever
	if retryable {
		retry = contracts.RetryBackoff
	}
	if code == contracts.ErrCancelled {
		retry = contracts.RetryAfterReconnect
	}
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: contracts.CapabilityNotification, Operation: action, Cause: cause}
}

func parseEndpoint(raw string, loopback bool) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint == nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Hostname() == "" {
		return nil, errors.New("webhook endpoint must be an HTTP(S) URL without user info")
	}
	if port := endpoint.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return nil, errors.New("webhook endpoint port is invalid")
		}
	}
	host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
	if host == "localhost" || (loopback && !webhookLoopbackFixtureHost(host)) {
		return nil, errors.New("webhook endpoint is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && validateIPs([]net.IPAddr{{IP: ip}}, loopback) != nil {
		return nil, errors.New("webhook endpoint is not allowed")
	}
	return endpoint, nil
}

func webhookLoopbackFixtureHost(host string) bool {
	return host == "127.0.0.1" || host == "opencard-webhook-fixture.test"
}

func normalizeRetries(value []time.Duration) ([]time.Duration, error) {
	if value == nil {
		return append([]time.Duration(nil), defaultRetryDelays...), nil
	}
	if len(value) > 3 {
		return nil, errors.New("webhook retry schedule must have at most three entries")
	}
	result := append([]time.Duration(nil), value...)
	for _, delay := range result {
		if delay < 0 {
			return nil, errors.New("webhook retry delay is invalid")
		}
	}
	return result, nil
}
func withBoundedTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, requestTimeout)
}
func retryable(err error) bool {
	var providerErr *contracts.ProviderError
	return errors.As(err, &providerErr) && providerErr.Retryable
}
func closedChannel() chan struct{} { done := make(chan struct{}); close(done); return done }
func notificationFingerprint(notification contracts.Notification, payload []byte) string {
	sum := sha256.Sum256([]byte(notification.EventID.String() + "\x00" + notification.EventType + "\x00" + notification.OccurredAt.UTC().Format(time.RFC3339Nano) + "\x00" + string(payload)))
	return hex.EncodeToString(sum[:])
}

func dialResolvedIPs(ips []net.IPAddr) func(context.Context, string, string) (net.Conn, error) {
	copyIPs := append([]net.IPAddr(nil), ips...)
	return func(ctx context.Context, _, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{}
		var last error
		for _, ip := range copyIPs {
			connection, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			last = dialErr
		}
		if last == nil {
			last = errUnsafeTarget
		}
		return nil, last
	}
}

func validateIPs(ips []net.IPAddr, loopback bool) error {
	if len(ips) == 0 {
		return errUnsafeTarget
	}
	for _, ipAddress := range ips {
		if ipAddress.IP == nil {
			return errUnsafeTarget
		}
		if loopback && ipAddress.IP.Equal(net.ParseIP("127.0.0.1")) {
			continue
		}
		if !isPublicIP(ipAddress.IP) {
			return errUnsafeTarget
		}
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, network := range privateNetworks {
		if network.Contains(address) {
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(err)
		}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	return prefixes
}

var _ contracts.NotificationProvider = (*Provider)(nil)
