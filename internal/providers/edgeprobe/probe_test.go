package edgeprobe

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testProbe(t *testing.T, handler http.Handler) Prober {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	dialer := &net.Dialer{Timeout: time.Second}
	value, err := newProbe(Config{RootCAs: pool, ConnectTimeout: time.Second, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second, OverallTimeout: 2 * time.Second}, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestProbeUsesVerifiedSNIAndFixedLogicalTarget(t *testing.T) {
	prober := testProbe(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "example.com" {
			t.Errorf("Host=%q", request.Host)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	observation, err := prober.Probe(context.Background(), "example.com")
	if err != nil || observation.Hostname != "example.com" || observation.StatusCode != http.StatusNoContent || observation.Fingerprint == "" || !observation.NotAfter.After(observation.NotBefore) {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
}

func TestProbeRejectsUnsafeHostAndBadEdgeResponses(t *testing.T) {
	prober := testProbe(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect" {
			writer.Header().Set("Location", "https://elsewhere.example/")
			writer.WriteHeader(http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	if _, err := prober.Probe(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("IP literal was accepted")
	}
	if _, err := prober.Probe(context.Background(), "example.com"); err == nil {
		t.Fatal("HTTP 500 was accepted")
	}
	redirect := testProbe(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", "https://elsewhere.example/")
		writer.WriteHeader(http.StatusFound)
	}))
	if _, err := redirect.Probe(context.Background(), "example.com"); err == nil {
		t.Fatal("cross-host redirect was accepted")
	}
}

func TestProbeRejectsNonFixedProductionDialAddress(t *testing.T) {
	if _, err := New(Config{LoopbackAddress: "127.0.0.1:8443"}); err == nil {
		t.Fatal("non-fixed loopback port was accepted")
	}
}
