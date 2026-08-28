// Package dnsfixture provides a deterministic, isolated DNS authority for
// M3 tests. It never opens sockets or calls an external DNS provider.
package dnsfixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

const (
	providerName    = "isolated-dns-fixture"
	providerVersion = "m3"
)

var (
	errConflict = errors.New("fixture operation conflicts with existing state")
	errMissing  = errors.New("fixture DNS record was not found")
	domainRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Config selects an optional JSON snapshot for restart tests. An empty
// StatePath keeps all records only in memory. StatePath is never inferred from
// a request and the provider performs no network I/O in either mode.
type Config struct {
	StatePath string
	Clock     func() time.Time
}

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int64  `json:"ttl_seconds"`
}

type PlatformBinding struct {
	Domain        string `json:"domain"`
	Wildcard      string `json:"wildcard"`
	Target        string `json:"target"`
	Verified      bool   `json:"verified"`
	Verification  string `json:"verification_record"`
	VerificationV string `json:"verification_value"`
}

type CNAMEBinding struct {
	Host     string `json:"host"`
	Target   string `json:"target"`
	Verified bool   `json:"verified"`
}

type DNS01Challenge struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Token  string `json:"-"`
}

// Fault is a bounded, test-only failure injection. Remaining is decremented
// only after a matching operation; a zero Remaining makes the fault persistent.
type Fault struct {
	Operation string
	Code      contracts.ErrorCode
	Message   string
	Delay     time.Duration
	Remaining int
}

type operationRecord struct {
	Fingerprint string `json:"fingerprint"`
}
type persistedState struct {
	Records map[string]Record          `json:"records"`
	Ops     map[string]operationRecord `json:"operations"`
}

// Provider is safe for concurrent fixture callers. Its String forms exclude
// DNS challenge values, preventing accidental token disclosure in test logs.
type Provider struct {
	metadata contracts.ProviderMetadata
	state    string
	clock    func() time.Time

	mu      sync.Mutex
	records map[string]Record
	ops     map[string]operationRecord
	faults  map[string]Fault
}

func New(config Config) (*Provider, error) {
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	p := &Provider{
		metadata: contracts.ProviderMetadata{Name: providerName, Version: providerVersion, ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityRouteManage)},
		state:    config.StatePath, clock: clock, records: map[string]Record{}, ops: map[string]operationRecord{}, faults: map[string]Fault{},
	}
	if config.StatePath != "" {
		if err := p.load(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func NewProvider(config Config) (*Provider, error)                      { return New(config) }
func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }
func (p *Provider) String() string                                      { return providerName }
func (p *Provider) GoString() string                                    { return providerName + "{}" }

// StableSlug derives an RFC-friendly, stable app label without reserving a
// public hostname. The hash suffix prevents collisions after normalization.
func StableSlug(input string) string {
	clean := strings.ToLower(strings.TrimSpace(input))
	clean = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(clean, "-")
	clean = strings.Trim(clean, "-")
	if clean == "" {
		clean = "app"
	}
	if len(clean) > 42 {
		clean = clean[:42]
		clean = strings.TrimRight(clean, "-")
	}
	digest := sha256.Sum256([]byte(input))
	return clean + "-" + hex.EncodeToString(digest[:])[:10]
}

// BindPlatformDomain installs the platform's verification TXT and wildcard
// CNAME records. A caller must call VerifyPlatformDomain before treating this
// binding as verified.
func (p *Provider) BindPlatformDomain(ctx context.Context, domain, target string, operation contracts.OperationContext) (PlatformBinding, error) {
	domain, err := canonicalDomain(domain)
	if err != nil {
		return PlatformBinding{}, p.failure("bind_platform", contracts.ErrInvalidArgument, "platform domain is invalid", err)
	}
	target, err = canonicalDomain(target)
	if err != nil {
		return PlatformBinding{}, p.failure("bind_platform", contracts.ErrInvalidArgument, "platform target is invalid", err)
	}
	if err := p.check(ctx, operation, "bind_platform"); err != nil {
		return PlatformBinding{}, err
	}
	verification := "_open-card-verify." + domain
	value := "ocv-" + shortDigest(domain)
	binding := PlatformBinding{Domain: domain, Wildcard: "*." + domain, Target: target, Verification: verification, VerificationV: value}
	fingerprint := "bind_platform:" + domain + ":" + target
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return PlatformBinding{}, p.failure("bind_platform", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	if err := p.upsertLocked(Record{Name: verification, Type: "TXT", Value: value, TTL: 60}); err != nil {
		return PlatformBinding{}, err
	}
	if err := p.upsertLocked(Record{Name: "*." + domain, Type: "CNAME", Value: target, TTL: 60}); err != nil {
		return PlatformBinding{}, err
	}
	if err := p.saveLocked(); err != nil {
		return PlatformBinding{}, p.failure("bind_platform", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return binding, nil
}

func (p *Provider) VerifyPlatformDomain(ctx context.Context, binding PlatformBinding, operation contracts.OperationContext) (PlatformBinding, error) {
	if err := p.check(ctx, operation, "verify_platform"); err != nil {
		return PlatformBinding{}, err
	}
	fingerprint := "verify_platform:" + binding.Domain + ":" + binding.Target
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return PlatformBinding{}, p.failure("verify_platform", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	if !p.hasLocked(binding.Verification, "TXT", binding.VerificationV) || !p.hasLocked(binding.Wildcard, "CNAME", binding.Target) {
		return PlatformBinding{}, p.failure("verify_platform", contracts.ErrNotFound, "platform DNS verification is not present", errMissing)
	}
	binding.Verified = true
	if err := p.saveLocked(); err != nil {
		return PlatformBinding{}, p.failure("verify_platform", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return binding, nil
}

// BindApplicationCNAME records only the customer-side CNAME. It never creates
// an A/AAAA record and therefore cannot accidentally expose a worker or DB.
func (p *Provider) BindApplicationCNAME(ctx context.Context, host, target string, operation contracts.OperationContext) (CNAMEBinding, error) {
	host, err := canonicalDomain(host)
	if err != nil {
		return CNAMEBinding{}, p.failure("bind_cname", contracts.ErrInvalidArgument, "application hostname is invalid", err)
	}
	target, err = canonicalDomain(target)
	if err != nil {
		return CNAMEBinding{}, p.failure("bind_cname", contracts.ErrInvalidArgument, "CNAME target is invalid", err)
	}
	if err := p.check(ctx, operation, "bind_cname"); err != nil {
		return CNAMEBinding{}, err
	}
	binding := CNAMEBinding{Host: host, Target: target}
	fingerprint := "bind_cname:" + host + ":" + target
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return CNAMEBinding{}, p.failure("bind_cname", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	if err := p.upsertLocked(Record{Name: host, Type: "CNAME", Value: target, TTL: 60}); err != nil {
		return CNAMEBinding{}, err
	}
	if err := p.saveLocked(); err != nil {
		return CNAMEBinding{}, p.failure("bind_cname", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return binding, nil
}

func (p *Provider) VerifyApplicationCNAME(ctx context.Context, binding CNAMEBinding, operation contracts.OperationContext) (CNAMEBinding, error) {
	if err := p.check(ctx, operation, "verify_cname"); err != nil {
		return CNAMEBinding{}, err
	}
	fingerprint := "verify_cname:" + binding.Host + ":" + binding.Target
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return CNAMEBinding{}, p.failure("verify_cname", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	if !p.hasLocked(binding.Host, "CNAME", binding.Target) {
		return CNAMEBinding{}, p.failure("verify_cname", contracts.ErrNotFound, "application CNAME verification is not present", errMissing)
	}
	binding.Verified = true
	if err := p.saveLocked(); err != nil {
		return CNAMEBinding{}, p.failure("verify_cname", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return binding, nil
}

// PresentDNS01 and VerifyDNS01 form the certfixture authority boundary.
func (p *Provider) PresentDNS01(ctx context.Context, domain, token string, operation contracts.OperationContext) (DNS01Challenge, error) {
	domain, err := canonicalDomain(strings.TrimPrefix(domain, "*."))
	if err != nil {
		return DNS01Challenge{}, p.failure("present_dns01", contracts.ErrInvalidArgument, "DNS-01 domain is invalid", err)
	}
	if strings.TrimSpace(token) == "" {
		return DNS01Challenge{}, p.failure("present_dns01", contracts.ErrInvalidArgument, "DNS-01 token is invalid", nil)
	}
	if err := p.check(ctx, operation, "present_dns01"); err != nil {
		return DNS01Challenge{}, err
	}
	challenge := DNS01Challenge{Domain: domain, Name: "_acme-challenge." + domain, Token: token}
	fingerprint := "present_dns01:" + domain + ":" + shortDigest(token)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return DNS01Challenge{}, p.failure("present_dns01", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	if err := p.upsertLocked(Record{Name: challenge.Name, Type: "TXT", Value: token, TTL: 60}); err != nil {
		return DNS01Challenge{}, err
	}
	if err := p.saveLocked(); err != nil {
		return DNS01Challenge{}, p.failure("present_dns01", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return challenge, nil
}

func (p *Provider) VerifyDNS01(ctx context.Context, challenge DNS01Challenge, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, "verify_dns01"); err != nil {
		return err
	}
	fingerprint := "verify_dns01:" + challenge.Domain + ":" + shortDigest(challenge.Token)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return p.failure("verify_dns01", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	if !p.hasLocked(challenge.Name, "TXT", challenge.Token) {
		return p.failure("verify_dns01", contracts.ErrNotFound, "DNS-01 challenge is not present", errMissing)
	}
	if err := p.saveLocked(); err != nil {
		return p.failure("verify_dns01", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return nil
}

func (p *Provider) CleanupDNS01(ctx context.Context, challenge DNS01Challenge, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, "cleanup_dns01"); err != nil {
		return err
	}
	fingerprint := "cleanup_dns01:" + challenge.Domain + ":" + shortDigest(challenge.Token)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.idempotent(operation, fingerprint); err != nil {
		return p.failure("cleanup_dns01", contracts.ErrConflict, "fixture operation conflicts with existing state", err)
	}
	delete(p.records, recordKey(challenge.Name, "TXT"))
	if err := p.saveLocked(); err != nil {
		return p.failure("cleanup_dns01", contracts.ErrUnavailable, "fixture DNS state could not be saved", err)
	}
	return nil
}

func (p *Provider) Records() []Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Record, 0, len(p.records))
	for _, record := range p.records {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return recordKey(out[i].Name, out[i].Type) < recordKey(out[j].Name, out[j].Type) })
	return out
}

func (p *Provider) SetFault(fault Fault) error {
	if strings.TrimSpace(fault.Operation) == "" || fault.Delay < 0 || fault.Remaining < 0 {
		return errors.New("fixture fault is invalid")
	}
	if fault.Code == "" {
		fault.Code = contracts.ErrUnavailable
	}
	if fault.Message == "" {
		fault.Message = "fixture operation was injected to fail"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.faults[fault.Operation] = fault
	return nil
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, action string) error {
	if err := operation.Validate(); err != nil {
		return p.failure(action, contracts.ErrInvalidArgument, "provider idempotency key is required", err)
	}
	if !operation.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, operation.Deadline)
		defer cancel()
	}
	p.mu.Lock()
	fault, active := p.faults[action]
	if active && fault.Remaining > 0 {
		fault.Remaining--
		if fault.Remaining == 0 {
			delete(p.faults, action)
		} else {
			p.faults[action] = fault
		}
	}
	p.mu.Unlock()
	if active && fault.Delay > 0 {
		select {
		case <-ctx.Done():
			return p.contextFailure(action, ctx.Err())
		case <-time.After(fault.Delay):
		}
	}
	if err := ctx.Err(); err != nil {
		return p.contextFailure(action, err)
	}
	if active {
		return p.failure(action, fault.Code, fault.Message, nil)
	}
	return nil
}

func (p *Provider) contextFailure(action string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return p.failure(action, contracts.ErrTimeout, "fixture DNS operation timed out", err)
	}
	return p.failure(action, contracts.ErrCancelled, "fixture DNS operation was cancelled", err)
}
func (p *Provider) failure(action string, code contracts.ErrorCode, message string, cause error) *contracts.ProviderError {
	retry := contracts.RetryNever
	retryable := false
	if code == contracts.ErrTimeout || code == contracts.ErrUnavailable {
		retry, retryable = contracts.RetryBackoff, true
	}
	if code == contracts.ErrCancelled {
		retry, retryable = contracts.RetryAfterReconnect, true
	}
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: contracts.CapabilityRouteManage, Operation: action, Cause: cause}
}
func (p *Provider) idempotent(operation contracts.OperationContext, fingerprint string) error {
	if previous, ok := p.ops[operation.IdempotencyKey]; ok && previous.Fingerprint != fingerprint {
		return errConflict
	}
	p.ops[operation.IdempotencyKey] = operationRecord{Fingerprint: fingerprint}
	return nil
}
func (p *Provider) upsertLocked(record Record) error {
	key := recordKey(record.Name, record.Type)
	if current, ok := p.records[key]; ok && current.Value != record.Value {
		return p.failure("upsert", contracts.ErrConflict, "fixture DNS record conflicts with existing state", errConflict)
	}
	p.records[key] = record
	return nil
}
func (p *Provider) hasLocked(name, recordType, value string) bool {
	record, ok := p.records[recordKey(name, recordType)]
	return ok && record.Value == value
}
func recordKey(name, recordType string) string {
	return strings.ToUpper(recordType) + ":" + strings.TrimSuffix(strings.ToLower(name), ".")
}
func canonicalDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if !domainRE.MatchString(value) || len(value) > 253 {
		return "", errors.New("invalid domain")
	}
	return value, nil
}
func shortDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
func (p *Provider) load() error {
	data, err := os.ReadFile(p.state)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("fixture DNS state could not be loaded: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return errors.New("fixture DNS state is invalid")
	}
	if state.Records != nil {
		p.records = state.Records
	}
	if state.Ops != nil {
		p.ops = state.Ops
	}
	return nil
}
func (p *Provider) saveLocked() error {
	if p.state == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p.state), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(persistedState{Records: p.records, Ops: p.ops})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(p.state), ".dnsfixture-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, p.state)
}
