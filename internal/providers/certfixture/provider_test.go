package certfixture

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/dnsfixture"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

type dnsAuthority struct{ provider *dnsfixture.Provider }

func (d dnsAuthority) PresentDNS01(ctx context.Context, domain, token string, op contracts.OperationContext) (DNS01Challenge, error) {
	value, err := d.provider.PresentDNS01(ctx, domain, token, op)
	return DNS01Challenge{Domain: value.Domain, Name: value.Name, Token: value.Token}, err
}
func (d dnsAuthority) VerifyDNS01(ctx context.Context, value DNS01Challenge, op contracts.OperationContext) error {
	return d.provider.VerifyDNS01(ctx, dnsfixture.DNS01Challenge{Domain: value.Domain, Name: value.Name, Token: value.Token}, op)
}
func (d dnsAuthority) CleanupDNS01(ctx context.Context, value DNS01Challenge, op contracts.OperationContext) error {
	return d.provider.CleanupDNS01(ctx, dnsfixture.DNS01Challenge{Domain: value.Domain, Name: value.Name, Token: value.Token}, op)
}

func certificateOperation(key string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key}
}
func certificateCode(err error) contracts.ErrorCode {
	var value *contracts.ProviderError
	if errors.As(err, &value) {
		return value.Code
	}
	return ""
}

func testIssuer(t *testing.T) (*Provider, *secretprovider.Provider, *dnsfixture.Provider) {
	t.Helper()
	base := t.TempDir()
	secrets, err := secretprovider.New(secretprovider.Config{Root: filepath.Join(base, "vault"), MaterialRoot: filepath.Join(base, "material"), MasterKeyPath: filepath.Join(base, "master.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secrets.Close() })
	dns, err := dnsfixture.New(dnsfixture.Config{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{Secrets: secrets, DNS: dnsAuthority{provider: dns}, Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return issuer, secrets, dns
}

func TestIssueRenewRevokeUsesDNS01AndSecretReferenceOnly(t *testing.T) {
	issuer, secrets, dns := testIssuer(t)
	request := CertificateRequest{Domains: []string{"app.fixture.test", "*.platform.fixture.test"}, SecretID: domain.ID("certificate_1"), SecretName: "tls_bundle", SecretProvider: "fixture-secret", Operation: certificateOperation("issue")}
	certificate, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := issuer.Issue(context.Background(), request)
	if err != nil || retry.Reference != certificate.Reference || retry.Serial != certificate.Serial {
		t.Fatalf("issue was not idempotent: %#v %v", retry, err)
	}
	encoded, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "BEGIN") {
		t.Fatalf("certificate metadata leaked secret material: %s", encoded)
	}
	if certificate.Reference.Version == "" || certificate.Issuer != "Open Card isolated test CA" {
		t.Fatalf("certificate metadata was incomplete: %#v", certificate)
	}
	for _, record := range dns.Records() {
		if strings.HasPrefix(record.Name, "_acme-challenge.") {
			t.Fatalf("DNS-01 record was not cleaned up: %#v", record)
		}
	}

	material, err := secrets.ResolveBuildSecret(context.Background(), certificate.Reference, certificateOperation("resolve"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(material.Path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(bundle)
	if block == nil {
		t.Fatal("secret did not contain a certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issuer.CACertificatePEM()) {
		t.Fatal("unable to parse test CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "app.fixture.test", Roots: roots, CurrentTime: time.Now()}); err != nil {
		t.Fatalf("stored test certificate did not validate: %v", err)
	}
	if err := secrets.RevokeBuildSecret(context.Background(), material, certificateOperation("unmount")); err != nil {
		t.Fatal(err)
	}

	renewed, err := issuer.Renew(context.Background(), certificate, certificateOperation("renew"))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Reference.Version == certificate.Reference.Version || renewed.RenewedFrom != certificate.Serial {
		t.Fatalf("renewal did not create a new secret version: old=%#v new=%#v", certificate, renewed)
	}
	revocation, err := issuer.Revoke(context.Background(), certificate, certificateOperation("revoke"))
	if err != nil || revocation.Serial != certificate.Serial || !issuer.IsRevoked(certificate.Serial) {
		t.Fatalf("revocation was not recorded: %#v %v", revocation, err)
	}
	if _, err := issuer.Revoke(context.Background(), certificate, certificateOperation("revoke")); err != nil {
		t.Fatalf("revocation was not idempotent: %v", err)
	}
}

func TestCertificateFailureTimeoutAndZeroPlaintextOutput(t *testing.T) {
	issuer, _, _ := testIssuer(t)
	if err := issuer.SetFault(Fault{Operation: "issue", Delay: 20 * time.Millisecond, Remaining: 1}); err != nil {
		t.Fatal(err)
	}
	_, err := issuer.Issue(context.Background(), CertificateRequest{Domains: []string{"app.fixture.test"}, SecretID: domain.ID("certificate_2"), SecretName: "tls_bundle", SecretProvider: "fixture-secret", Operation: contracts.OperationContext{IdempotencyKey: "timeout", Deadline: time.Now().Add(time.Millisecond)}})
	if certificateCode(err) != contracts.ErrTimeout {
		t.Fatalf("certificate deadline was not honored: %v", err)
	}
	if err := issuer.SetFault(Fault{Operation: "issue", Code: contracts.ErrUnavailable, Message: "fixture issuance failure", Remaining: 1}); err != nil {
		t.Fatal(err)
	}
	_, err = issuer.Issue(context.Background(), CertificateRequest{Domains: []string{"app.fixture.test"}, SecretID: domain.ID("certificate_3"), SecretName: "tls_bundle", SecretProvider: "fixture-secret", Operation: certificateOperation("failure")})
	if certificateCode(err) != contracts.ErrUnavailable || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("certificate failure was unsafe: %v", err)
	}
}
