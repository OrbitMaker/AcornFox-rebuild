package publicdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

type fixtureResolver struct {
	records map[string][]contracts.PublicDNSRecord
	errors  map[string]error
	delay   time.Duration
}

func (r fixtureResolver) Lookup(ctx context.Context, name, recordType string) ([]contracts.PublicDNSRecord, error) {
	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	key := name + "|" + recordType
	if err := r.errors[key]; err != nil {
		return nil, err
	}
	return append([]contracts.PublicDNSRecord(nil), r.records[key]...), nil
}

func records(values ...string) []contracts.PublicDNSRecord {
	result := make([]contracts.PublicDNSRecord, 0, len(values))
	for _, value := range values {
		result = append(result, contracts.PublicDNSRecord{Type: "CNAME", Value: value})
	}
	return result
}

func newVerifier(t *testing.T, resolvers ...contracts.PublicDNSResolver) *Verifier {
	t.Helper()
	value, err := New(Config{Resolvers: resolvers, QueryTimeout: 20 * time.Millisecond, OverallTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPlatformRequiresTwoConsistentPublicResolverAnswers(t *testing.T) {
	expected := "8.8.8.8"
	good := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{"apps.example.test|A": {{Type: "A", Value: expected}}}}
	mismatch := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{"apps.example.test|A": {{Type: "A", Value: "1.1.1.1"}}}}
	result, err := newVerifier(t, good, good).VerifyPlatformAddress(context.Background(), "Apps.Example.Test.", expected)
	if err != nil || result.Status != contracts.PublicDNSVerified || result.Hostname != "apps.example.test" {
		t.Fatalf("verified result=%+v err=%v", result, err)
	}
	result, err = newVerifier(t, good, mismatch).VerifyPlatformAddress(context.Background(), "apps.example.test", expected)
	if err != nil || result.Status != contracts.PublicDNSConflict {
		t.Fatalf("single resolver success was accepted: %+v %v", result, err)
	}
	result, err = newVerifier(t, mismatch, mismatch).VerifyPlatformAddress(context.Background(), "apps.example.test", expected)
	if err != nil || result.Status != contracts.PublicDNSMismatch {
		t.Fatalf("mismatch result=%+v err=%v", result, err)
	}
	benchmark := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{"apps.example.test|A": {{Type: "A", Value: "198.18.0.1"}}}}
	result, err = newVerifier(t, benchmark, benchmark).VerifyPlatformAddress(context.Background(), "apps.example.test", expected)
	if err != nil || result.Status != contracts.PublicDNSMismatch {
		t.Fatalf("benchmark answer was not mismatch: %+v err=%v", result, err)
	}
}

func TestPlatformTimeoutPendingAndReservedAddressAreFailClosed(t *testing.T) {
	empty := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{}}
	result, err := newVerifier(t, empty, empty).VerifyPlatformAddress(context.Background(), "apps.example.test", "8.8.8.8")
	if err != nil || result.Status != contracts.PublicDNSNotFound {
		t.Fatalf("pending result=%+v err=%v", result, err)
	}
	timeout := fixtureResolver{delay: 50 * time.Millisecond}
	result, err = newVerifier(t, timeout, timeout).VerifyPlatformAddress(context.Background(), "apps.example.test", "8.8.8.8")
	if err != nil || result.Status != contracts.PublicDNSTimeout {
		t.Fatalf("timeout result=%+v err=%v", result, err)
	}
	for _, address := range []string{"198.18.0.1", "192.0.2.1", "10.0.0.1", "127.0.0.1", "::1", "2001:db8::1"} {
		if _, err := newVerifier(t, empty, empty).VerifyPlatformAddress(context.Background(), "apps.example.test", address); err == nil {
			t.Fatalf("reserved expected address accepted: %s", address)
		}
	}
}

func TestCustomerCNAMEChainConflictLoopAndUnsafeTarget(t *testing.T) {
	chain := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{
		"customer.example.test|CNAME": records("hop.example.test"),
		"hop.example.test|CNAME":      records("ingress.apps.example.test"),
	}}
	result, err := newVerifier(t, chain, chain).VerifyCustomerIngress(context.Background(), "customer.example.test", "apps.example.test")
	if err != nil || result.Status != contracts.PublicDNSVerified || result.Expected != "ingress.apps.example.test" {
		t.Fatalf("CNAME verified result=%+v err=%v", result, err)
	}
	redirectedIngress := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{
		"customer.example.test|CNAME":     records("ingress.apps.example.test"),
		"ingress.apps.example.test|CNAME": records("attacker.example.test"),
	}}
	result, err = newVerifier(t, redirectedIngress, redirectedIngress).VerifyCustomerIngress(context.Background(), "customer.example.test", "apps.example.test")
	if err != nil || result.Status != contracts.PublicDNSMismatch {
		t.Fatalf("redirected ingress was accepted: %+v err=%v", result, err)
	}
	loop := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{
		"customer.example.test|CNAME": records("hop.example.test"),
		"hop.example.test|CNAME":      records("customer.example.test"),
	}}
	result, err = newVerifier(t, loop, loop).VerifyCustomerIngress(context.Background(), "customer.example.test", "apps.example.test")
	if err != nil || result.Status != contracts.PublicDNSConflict {
		t.Fatalf("loop result=%+v err=%v", result, err)
	}
	unsafe := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{"customer.example.test|CNAME": records("127.0.0.1")}}
	result, err = newVerifier(t, unsafe, unsafe).VerifyCustomerIngress(context.Background(), "customer.example.test", "apps.example.test")
	if err != nil || result.Status != contracts.PublicDNSMismatch {
		t.Fatalf("unsafe target result=%+v err=%v", result, err)
	}
}

func TestResolverErrorsAndConfigurationDoNotUseLocalDefaults(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty resolver configuration was accepted")
	}
	if _, err := New(Config{ResolverEndpoints: []string{"localhost:53", "8.8.8.8:53"}}); err == nil {
		t.Fatal("hostname resolver endpoint was accepted")
	}
	if _, err := New(Config{ResolverEndpoints: []string{"8.8.8.8:53", "8.8.8.8:53"}}); err == nil {
		t.Fatal("duplicate recursive resolver endpoint was accepted")
	}
	broken := fixtureResolver{errors: map[string]error{"apps.example.test|A": errors.New("fixture resolver failed"), "apps.example.test|AAAA": errors.New("fixture resolver failed")}}
	result, err := newVerifier(t, broken, broken).VerifyPlatformAddress(context.Background(), "apps.example.test", "8.8.8.8")
	if err != nil || result.Status != contracts.PublicDNSResolverError {
		t.Fatalf("resolver error result=%+v err=%v", result, err)
	}
	if len(result.Observations) != 2 || result.Observations[0].Resolver != "resolver-1" || result.Observations[0].Records != nil {
		t.Fatalf("unsafe observation=%+v", result.Observations)
	}
}

func TestASCIIHostnameBoundaryAndCNAMEHopLimit(t *testing.T) {
	empty := fixtureResolver{records: map[string][]contracts.PublicDNSRecord{}}
	for _, hostname := range []string{"éxample.test", "localhost", "127.0.0.1", "a..example.test", " app.example.test"} {
		if _, err := newVerifier(t, empty, empty).VerifyCustomerIngress(context.Background(), hostname, "apps.example.test"); err == nil {
			t.Fatalf("unsafe hostname accepted: %q", hostname)
		}
	}
	chainRecords := map[string][]contracts.PublicDNSRecord{}
	for index := 0; index < maximumCNAMEHops; index++ {
		current, next := "customer.example.test", "hop0.example.test"
		if index > 0 {
			current = "hop" + string(rune('0'+index-1)) + ".example.test"
		}
		next = "hop" + string(rune('0'+index)) + ".example.test"
		chainRecords[current+"|CNAME"] = records(next)
	}
	result, err := newVerifier(t, fixtureResolver{records: chainRecords}, fixtureResolver{records: chainRecords}).VerifyCustomerIngress(context.Background(), "customer.example.test", "apps.example.test")
	if err != nil || result.Status != contracts.PublicDNSUnknown {
		t.Fatalf("hop-limit result=%+v err=%v", result, err)
	}
}
