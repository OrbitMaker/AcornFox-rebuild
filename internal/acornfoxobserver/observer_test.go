package acornfoxobserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type timeoutFailure struct{}

func (timeoutFailure) Error() string   { return "resolver detail must not escape" }
func (timeoutFailure) Timeout() bool   { return true }
func (timeoutFailure) Temporary() bool { return true }

type trackedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *trackedConn) Close() error { c.once.Do(func() { close(c.closed) }); return c.Conn.Close() }

func TestObserveUsesFixedPublicIPStandardTLSAndBoundedSample(t *testing.T) {
	body := strings.Repeat("a", ResponseSampleLimit+17)
	var headers http.Header
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	dialed := ""
	observer, _ := New(Config{Resolver: resolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "example.com" {
			t.Fatalf("host=%q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}), Dialer: dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}), Clock: func() time.Time { return time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC) }})
	observer.roots = pool
	report := observer.Observe(context.Background(), "report_1", "https://example.com/")
	if report.DNS.State != DNSObserved || len(report.DNS.Addresses) != 1 || report.DNS.Addresses[0] != "93.184.216.34" || dialed != "93.184.216.34:443" {
		t.Fatalf("dns=%+v dialed=%q", report.DNS, dialed)
	}
	if report.TLS.State != LayerObserved || len(report.TLS.CertificateSHA256) != 71 || !strings.HasPrefix(report.TLS.CertificateSHA256, "sha256:") {
		t.Fatalf("tls=%+v", report.TLS)
	}
	want := sha256.Sum256([]byte(body[:ResponseSampleLimit]))
	if report.HTTPS.State != LayerObserved || report.HTTPS.HTTPStatus == nil || *report.HTTPS.HTTPStatus != 503 || report.HTTPS.ResponseSampleBytes == nil || *report.HTTPS.ResponseSampleBytes != ResponseSampleLimit || report.HTTPS.ResponseTruncated == nil || !*report.HTTPS.ResponseTruncated || report.HTTPS.ResponseSampleSHA256 != "sha256:"+hex.EncodeToString(want[:]) {
		t.Fatalf("https=%+v", report.HTTPS)
	}
	if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
		t.Fatalf("credential headers=%v", headers)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var contract contracts.AcornFoxAccessObservationReport
	if err = decoder.Decode(&contract); err != nil {
		t.Fatalf("backend strict decode rejected observer report: %v payload=%s", err, encoded)
	}
	if err = contract.Validate(); err != nil {
		t.Fatalf("backend contract rejected observer report: %v payload=%s", err, encoded)
	}
}

func TestObserveDoesNotFollowRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://should-not-be-requested.invalid/", http.StatusFound)
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	observer, _ := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}), Dialer: dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})})
	observer.roots = pool
	report := observer.Observe(context.Background(), "report_redirect", "https://example.com")
	if report.HTTPS.State != LayerObserved || report.HTTPS.HTTPStatus == nil || *report.HTTPS.HTTPStatus != 302 {
		t.Fatalf("redirect=%+v", report)
	}
}

func TestObserveRejectsNonPublicDNSBeforeDial(t *testing.T) {
	calls := 0
	observer, _ := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("93.184.216.34")}}, nil
	}), Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("must not dial")
	})})
	report := observer.Observe(context.Background(), "report_private", "https://example.com/")
	if report.DNS.State != DNSFailed || report.DNS.FailureCode != DNSLookupFailed || report.TLS.State != LayerNotAttempted || report.HTTPS.State != LayerNotAttempted || calls != 0 {
		t.Fatalf("report=%+v calls=%d", report, calls)
	}
}

func TestObserveClassifiesDNSAndTLSWithoutRawErrors(t *testing.T) {
	observer, _ := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return nil, timeoutFailure{} })})
	report := observer.Observe(context.Background(), "report_timeout", "https://example.com/")
	if report.DNS.FailureCode != DNSTimeout || strings.Contains(report.DNS.FailureCode, "detail") {
		t.Fatalf("dns=%+v", report.DNS)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	dial := dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	resolver := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	invalid, _ := New(Config{Resolver: resolver, Dialer: dial})
	report = invalid.Observe(context.Background(), "report_cert", "https://example.com/")
	if report.TLS.FailureCode != TLSCertificateInvalid || report.HTTPS.State != LayerNotAttempted {
		t.Fatalf("invalid tls=%+v", report)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	mismatch, _ := New(Config{Resolver: resolver, Dialer: dial})
	mismatch.roots = pool
	report = mismatch.Observe(context.Background(), "report_name", "https://other.example/")
	if report.TLS.FailureCode != TLSNameMismatch {
		t.Fatalf("name mismatch=%+v", report)
	}
}

func TestObserveClosesEstablishedTLSConnectionWhenHTTPSContextCancels(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	closed := make(chan struct{})
	observer, _ := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}), Dialer: dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &trackedConn{Conn: connection, closed: closed}, nil
	})})
	observer.roots = pool
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	report := observer.Observe(ctx, "report_cancel", "https://example.com/")
	if report.TLS.State != LayerObserved || report.HTTPS.State != LayerFailed || report.HTTPS.FailureCode != HTTPSTimeout {
		t.Fatalf("report=%+v", report)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("TLS connection was not closed")
	}
}

func TestObserveCanonicalizesNanosecondClockToUTCMicroseconds(t *testing.T) {
	clock := time.Date(2026, 9, 8, 4, 5, 6, 123456789, time.FixedZone("test", 8*60*60))
	observer, err := New(Config{Clock: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	report := observer.Observe(context.Background(), "report_precision", "not-an-https-url")
	want := clock.UTC().Truncate(time.Microsecond)
	if !report.ObservedAt.Equal(want) || report.ObservedAt.Location() != time.UTC || report.ObservedAt.Nanosecond() != 123456000 {
		t.Fatalf("observed_at=%s want=%s", report.ObservedAt.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}
