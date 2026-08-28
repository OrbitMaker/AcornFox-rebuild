// Package certfixture provides an internal-CA issuer for isolated M3 tests.
// It deliberately has no ACME, filesystem key, or public-network path.
package certfixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "internal-test-ca-fixture"
	providerVersion = "m3"
)

var errConflict = errors.New("fixture operation conflicts with existing state")

// DNS01Authority is intentionally small so a production ACME adapter can be
// verified against the same contract without importing this fixture package.
type DNS01Authority interface {
	PresentDNS01(context.Context, string, string, contracts.OperationContext) (DNS01Challenge, error)
	VerifyDNS01(context.Context, DNS01Challenge, contracts.OperationContext) error
	CleanupDNS01(context.Context, DNS01Challenge, contracts.OperationContext) error
}

type DNS01Challenge struct {
	Domain string
	Name   string
	Token  string
}

// DNSAdapter converts a fixture with structurally identical DNS-01 methods to
// DNS01Authority while keeping package boundaries explicit.
type DNSAdapter struct {
	Present func(context.Context, string, string, contracts.OperationContext) (DNS01Challenge, error)
	Verify  func(context.Context, DNS01Challenge, contracts.OperationContext) error
	Cleanup func(context.Context, DNS01Challenge, contracts.OperationContext) error
}

func (d DNSAdapter) PresentDNS01(ctx context.Context, domain, token string, op contracts.OperationContext) (DNS01Challenge, error) {
	return d.Present(ctx, domain, token, op)
}
func (d DNSAdapter) VerifyDNS01(ctx context.Context, c DNS01Challenge, op contracts.OperationContext) error {
	return d.Verify(ctx, c, op)
}
func (d DNSAdapter) CleanupDNS01(ctx context.Context, c DNS01Challenge, op contracts.OperationContext) error {
	return d.Cleanup(ctx, c, op)
}

// Config constrains issuance to the supplied SecretProvider. The CA signing
// key stays in provider memory; leaf keys are sent straight to SecretProvider
// and never returned, logged, or kept in certificate metadata.
type Config struct {
	Secrets  contracts.SecretProvider
	DNS      DNS01Authority
	Clock    func() time.Time
	Validity time.Duration
}

type CertificateRequest struct {
	Domains        []string
	SecretID       domain.ID
	SecretName     string
	SecretProvider string
	Operation      contracts.OperationContext
}

// Certificate is safe to store in controller state or audit evidence. It has
// no PEM or private-key field, only a SecretReference and public metadata.
type Certificate struct {
	Reference   domain.SecretReference `json:"reference"`
	Domains     []string               `json:"domains"`
	Serial      string                 `json:"serial"`
	Fingerprint string                 `json:"fingerprint"`
	Issuer      string                 `json:"issuer"`
	NotBefore   time.Time              `json:"not_before"`
	NotAfter    time.Time              `json:"not_after"`
	RenewedFrom string                 `json:"renewed_from,omitempty"`
}

// Revocation is public metadata only. The leaf bundle remains in the
// restricted SecretProvider; a composition root can later revoke its secret
// material after every active route has switched away from it.
type Revocation struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
}

type Fault struct {
	Operation string
	Code      contracts.ErrorCode
	Message   string
	Delay     time.Duration
	Remaining int
}

type operationRecord struct {
	fingerprint string
	certificate Certificate
}

type Provider struct {
	metadata contracts.ProviderMetadata
	secrets  contracts.SecretProvider
	dns      DNS01Authority
	clock    func() time.Time
	validity time.Duration

	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	mu      sync.Mutex
	serial  uint64
	ops     map[string]operationRecord
	issued  map[string]Certificate
	revoked map[string]Revocation
	faults  map[string]Fault
}

func New(config Config) (*Provider, error) {
	if config.Secrets == nil || config.DNS == nil {
		return nil, errors.New("internal test CA requires secret and DNS fixtures")
	}
	validity := config.Validity
	if validity == 0 {
		validity = 24 * time.Hour
	}
	if validity < time.Minute || validity > 30*24*time.Hour {
		return nil, errors.New("internal test CA validity is outside allowed range")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Open Card isolated test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(366 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	return &Provider{metadata: contracts.ProviderMetadata{Name: providerName, Version: providerVersion, ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretManage), SensitiveInputs: []string{"certificate.private_key", "dns01.token"}}, secrets: config.Secrets, dns: config.DNS, clock: clock, validity: validity, caCert: caCert, caKey: caKey, ops: map[string]operationRecord{}, issued: map[string]Certificate{}, revoked: map[string]Revocation{}, faults: map[string]Fault{}}, nil
}

func NewProvider(config Config) (*Provider, error)                      { return New(config) }
func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }
func (p *Provider) String() string                                      { return providerName }
func (p *Provider) GoString() string                                    { return providerName + "{}" }

// Issue proves DNS-01 for every name, stores a PEM keypair through the secret
// provider, then returns reference-only public metadata. Cleanup is attempted
// even when signing or storage fails.
func (p *Provider) Issue(ctx context.Context, request CertificateRequest) (Certificate, error) {
	if err := p.check(ctx, request.Operation, "issue"); err != nil {
		return Certificate{}, err
	}
	domains, err := canonicalDomains(request.Domains)
	if err != nil {
		return Certificate{}, p.failure("issue", contracts.ErrInvalidArgument, "certificate domains are invalid", err)
	}
	if err := domain.RequireID(request.SecretID, "certificate secret id"); err != nil || strings.TrimSpace(request.SecretName) == "" || strings.TrimSpace(request.SecretProvider) == "" {
		return Certificate{}, p.failure("issue", contracts.ErrInvalidArgument, "certificate secret reference is invalid", err)
	}
	fingerprint := "issue:" + strings.Join(domains, ",") + ":" + request.SecretID.String() + ":" + request.SecretName + ":" + request.SecretProvider
	p.mu.Lock()
	if previous, ok := p.ops[request.Operation.IdempotencyKey]; ok {
		p.mu.Unlock()
		if previous.fingerprint != fingerprint {
			return Certificate{}, p.failure("issue", contracts.ErrConflict, "fixture operation conflicts with existing state", errConflict)
		}
		return previous.certificate, nil
	}
	p.mu.Unlock()

	challenges := make([]DNS01Challenge, 0, len(domains))
	verifiedNames := make(map[string]struct{}, len(domains))
	for index, name := range domains {
		authorizationName := strings.TrimPrefix(name, "*.")
		if _, exists := verifiedNames[authorizationName]; exists {
			continue
		}
		token := "oc-dns01-" + digest(request.Operation.IdempotencyKey+":"+name)
		challenge, presentErr := p.dns.PresentDNS01(ctx, authorizationName, token, childOperation(request.Operation, "present", index))
		if presentErr != nil {
			p.cleanup(ctx, challenges, request.Operation)
			return Certificate{}, p.wrap("issue", presentErr)
		}
		challenges = append(challenges, challenge)
		if verifyErr := p.dns.VerifyDNS01(ctx, challenge, childOperation(request.Operation, "verify", index)); verifyErr != nil {
			p.cleanup(ctx, challenges, request.Operation)
			return Certificate{}, p.wrap("issue", verifyErr)
		}
		verifiedNames[authorizationName] = struct{}{}
	}
	defer p.cleanup(ctx, challenges, request.Operation)
	certificate, bundle, err := p.sign(domains, request)
	if err != nil {
		return Certificate{}, p.failure("issue", contracts.ErrUnavailable, "internal test CA could not sign certificate", err)
	}
	defer zero(bundle)
	stored, err := p.secrets.Store(ctx, contracts.SecretRequest{Reference: certificate.Reference, Value: bundle, Operation: childOperation(request.Operation, "store", 0)})
	if err != nil {
		return Certificate{}, p.wrap("issue", err)
	}
	certificate.Reference = stored
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.ops[request.Operation.IdempotencyKey]; ok {
		if previous.fingerprint != fingerprint {
			return Certificate{}, p.failure("issue", contracts.ErrConflict, "fixture operation conflicts with existing state", errConflict)
		}
		return previous.certificate, nil
	}
	p.ops[request.Operation.IdempotencyKey] = operationRecord{fingerprint: fingerprint, certificate: certificate}
	p.issued[certificate.Serial] = certificate
	return certificate, nil
}

// Revoke records certificate revocation without exposing or copying private
// material. It is idempotent and only accepts certificates issued by this
// provider instance. It intentionally does not delete the secret reference:
// deletion is a separate, route-safe lifecycle step absent from SecretProvider.
func (p *Provider) Revoke(ctx context.Context, certificate Certificate, operation contracts.OperationContext) (Revocation, error) {
	if err := p.check(ctx, operation, "revoke"); err != nil {
		return Revocation{}, err
	}
	if strings.TrimSpace(certificate.Serial) == "" {
		return Revocation{}, p.failure("revoke", contracts.ErrInvalidArgument, "certificate metadata is invalid", nil)
	}
	fingerprint := "revoke:" + certificate.Serial
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.ops[operation.IdempotencyKey]; ok {
		if previous.fingerprint != fingerprint {
			return Revocation{}, p.failure("revoke", contracts.ErrConflict, "fixture operation conflicts with existing state", errConflict)
		}
		if revocation, exists := p.revoked[certificate.Serial]; exists {
			return revocation, nil
		}
	}
	if _, exists := p.issued[certificate.Serial]; !exists {
		return Revocation{}, p.failure("revoke", contracts.ErrNotFound, "certificate was not issued by this fixture", nil)
	}
	revocation, exists := p.revoked[certificate.Serial]
	if !exists {
		revocation = Revocation{Serial: certificate.Serial, RevokedAt: p.clock().UTC()}
		p.revoked[certificate.Serial] = revocation
	}
	p.ops[operation.IdempotencyKey] = operationRecord{fingerprint: fingerprint}
	return revocation, nil
}

func (p *Provider) IsRevoked(serial string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.revoked[serial]
	return exists
}

// Renew issues a new secret version. The old certificate stays referenced and
// usable until a higher layer proves the new route healthy and revokes it.
func (p *Provider) Renew(ctx context.Context, previous Certificate, operation contracts.OperationContext) (Certificate, error) {
	if previous.Reference.ID.Empty() || len(previous.Domains) == 0 {
		return Certificate{}, p.failure("renew", contracts.ErrInvalidArgument, "previous certificate metadata is invalid", nil)
	}
	request := CertificateRequest{Domains: previous.Domains, SecretID: previous.Reference.ID, SecretName: previous.Reference.Name, SecretProvider: previous.Reference.Provider, Operation: operation}
	certificate, err := p.Issue(ctx, request)
	if err != nil {
		return Certificate{}, err
	}
	certificate.RenewedFrom = previous.Serial
	return certificate, nil
}

// CACertificatePEM returns only the public test trust anchor, suitable for a
// loopback TLS client. It intentionally does not expose the CA signing key.
func (p *Provider) CACertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caCert.Raw})
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

func (p *Provider) sign(domains []string, request CertificateRequest) (Certificate, []byte, error) {
	now := p.clock().UTC()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, nil, err
	}
	p.mu.Lock()
	p.serial++
	serial := p.serial
	p.mu.Unlock()
	template := &x509.Certificate{SerialNumber: new(big.Int).SetUint64(serial), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(p.validity), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		return Certificate{}, nil, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return Certificate{}, nil, err
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return Certificate{}, nil, err
	}
	return Certificate{Reference: domain.SecretReference{ID: request.SecretID, Name: request.SecretName, Provider: request.SecretProvider, Version: "tls-" + parsed.SerialNumber.String()}, Domains: domains, Serial: parsed.SerialNumber.String(), Fingerprint: digest(string(parsed.Raw)), Issuer: p.caCert.Subject.CommonName, NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter}, bundle, nil
}

func (p *Provider) cleanup(ctx context.Context, challenges []DNS01Challenge, operation contracts.OperationContext) {
	for index := len(challenges) - 1; index >= 0; index-- {
		_ = p.dns.CleanupDNS01(ctx, challenges[index], childOperation(operation, "cleanup", index))
	}
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
		return p.failure(action, contracts.ErrTimeout, "certificate fixture operation timed out", err)
	}
	return p.failure(action, contracts.ErrCancelled, "certificate fixture operation was cancelled", err)
}
func (p *Provider) wrap(action string, err error) error {
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		return p.failure(action, providerErr.Code, "certificate verification dependency failed", err)
	}
	return p.failure(action, contracts.ErrUnavailable, "certificate verification dependency failed", err)
}
func (p *Provider) failure(action string, code contracts.ErrorCode, message string, cause error) *contracts.ProviderError {
	retry, retryable := contracts.RetryNever, false
	if code == contracts.ErrTimeout || code == contracts.ErrUnavailable {
		retry, retryable = contracts.RetryBackoff, true
	}
	if code == contracts.ErrCancelled {
		retry, retryable = contracts.RetryAfterReconnect, true
	}
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: contracts.CapabilitySecretManage, Operation: action, Cause: cause}
}
func canonicalDomains(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("no domains")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		bare := strings.TrimPrefix(value, "*.")
		if bare == value && strings.HasPrefix(value, "*") {
			return nil, errors.New("invalid wildcard")
		}
		if len(bare) < 3 || strings.ContainsAny(bare, "/\\\x00 \t\r\n") || !strings.Contains(bare, ".") {
			return nil, errors.New("invalid domain")
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}
func childOperation(parent contracts.OperationContext, action string, index int) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: parent.IdempotencyKey + ":cert:" + action + ":" + strconv.Itoa(index), Deadline: parent.Deadline, EvidenceID: parent.EvidenceID, Actor: parent.Actor}
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
