package edgeprobe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTaskCertificateObserverUsesFixedDialSNIAndNoHTTP(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	certificate, roots := testCertificate(t, []string{"console.example.test", "app.example.test"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	server := startCertificateTLSServer(t, certificate)
	var mu sync.Mutex
	var networks, addresses []string
	observer, err := NewTaskCertificateObserver(func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		networks, addresses = append(networks, network), append(addresses, address)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, server.listener.Addr().String())
	}, roots, func() time.Time { return now }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"CONSOLE.EXAMPLE.TEST.", "app.example.test"} {
		observation, err := observer.ObserveCertificate(context.Background(), hostname)
		if err != nil || observation.Hostname == "" || !strings.HasPrefix(observation.Fingerprint, "sha256:") || !observation.NotAfter.After(observation.NotBefore) {
			t.Fatalf("hostname=%q observation=%+v err=%v", hostname, observation, err)
		}
	}
	mu.Lock()
	gotNetworks, gotAddresses := append([]string(nil), networks...), append([]string(nil), addresses...)
	mu.Unlock()
	for index := range gotNetworks {
		if gotNetworks[index] != "tcp" || gotAddresses[index] != defaultLoopbackAddress {
			t.Fatalf("dial=%q %q", gotNetworks[index], gotAddresses[index])
		}
	}
	for _, want := range []string{"console.example.test", "app.example.test"} {
		if got := <-server.sni; got != want {
			t.Fatalf("SNI=%q want=%q", got, want)
		}
		if bytes := <-server.requestBytes; bytes != 0 {
			t.Fatalf("certificate observer wrote %d application bytes", bytes)
		}
	}
}

func TestTaskCertificateObserverRejectsInvalidTrustHostnameAndValidity(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	certificate, roots := testCertificate(t, []string{"valid.example.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	server := startCertificateTLSServer(t, certificate)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.listener.Addr().String())
	}
	observer, err := NewTaskCertificateObserver(dial, roots, func() time.Time { return now }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.ObserveCertificate(context.Background(), "other.example.test"); err == nil {
		t.Fatal("hostname mismatch was accepted")
	}
	untrusted, err := NewTaskCertificateObserver(dial, x509.NewCertPool(), func() time.Time { return now }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.ObserveCertificate(context.Background(), "valid.example.test"); err == nil {
		t.Fatal("untrusted CA was accepted")
	}
	if _, err := observer.ObserveCertificate(context.Background(), "https://valid.example.test"); err == nil {
		t.Fatal("URL hostname was accepted")
	}
	if _, err := observer.ObserveCertificate(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("IP hostname was accepted")
	}

	expired, expiredRoots := testCertificate(t, []string{"expired.example.test"}, now.Add(-2*time.Hour), now.Add(-time.Hour))
	expiredServer := startCertificateTLSServer(t, expired)
	expiredObserver, err := NewTaskCertificateObserver(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, expiredServer.listener.Addr().String())
	}, expiredRoots, func() time.Time { return now }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expiredObserver.ObserveCertificate(context.Background(), "expired.example.test"); err == nil {
		t.Fatal("expired certificate was accepted")
	}
	notYetValid, futureRoots := testCertificate(t, []string{"future.example.test"}, now.Add(time.Hour), now.Add(2*time.Hour))
	futureServer := startCertificateTLSServer(t, notYetValid)
	futureObserver, err := NewTaskCertificateObserver(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, futureServer.listener.Addr().String())
	}, futureRoots, func() time.Time { return now }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := futureObserver.ObserveCertificate(context.Background(), "future.example.test"); err == nil {
		t.Fatal("not-yet-valid certificate was accepted")
	}
}

func TestTaskCertificateObserverHonorsCancellation(t *testing.T) {
	called := false
	observer, err := NewTaskCertificateObserver(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	}, x509.NewCertPool(), time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.ObserveCertificate(ctx, "cancel.example.test"); err == nil || called {
		t.Fatalf("err=%v called=%t", err, called)
	}
}

func TestTaskCertificateObserverBoundsDialAndHandshakeAndFreezesClock(t *testing.T) {
	observer, err := NewTaskCertificateObserver(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, x509.NewCertPool(), time.Now, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := observer.ObserveCertificate(context.Background(), "dial.example.test"); err == nil || time.Since(started) > time.Second {
		t.Fatalf("unbounded dial err=%v elapsed=%s", err, time.Since(started))
	}

	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	observer, err = NewTaskCertificateObserver(func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}, x509.NewCertPool(), time.Now, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	if _, err := observer.ObserveCertificate(context.Background(), "handshake.example.test"); err == nil || time.Since(started) > time.Second {
		t.Fatalf("unbounded handshake err=%v elapsed=%s", err, time.Since(started))
	}

	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	certificate, roots := testCertificate(t, []string{"clock.example.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	tlsServer := startCertificateTLSServer(t, certificate)
	calls := 0
	observer, err = NewTaskCertificateObserver(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, tlsServer.listener.Addr().String())
	}, roots, func() time.Time {
		calls++
		if calls == 1 {
			return now
		}
		return now.Add(2 * time.Hour)
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.ObserveCertificate(context.Background(), "clock.example.test"); err != nil || calls != 1 {
		t.Fatalf("clock calls=%d err=%v", calls, err)
	}
}

type certificateTLSServer struct {
	listener     net.Listener
	sni          chan string
	requestBytes chan int
}

func startCertificateTLSServer(t *testing.T, certificate tls.Certificate) *certificateTLSServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &certificateTLSServer{listener: listener, sni: make(chan string, 16), requestBytes: make(chan int, 16)}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}}
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		server.sni <- info.ServerName
		return config, nil
	}
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				tlsConnection := tls.Server(connection, config)
				if tlsConnection.Handshake() != nil {
					return
				}
				_ = tlsConnection.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 1)
				n, _ := tlsConnection.Read(buffer)
				server.requestBytes <- n
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func testCertificate(t *testing.T, names []string, notBefore, notAfter time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "certificate test CA"}, NotBefore: notBefore.Add(-365 * 24 * time.Hour), NotAfter: notAfter.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leafPrivateDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPrivateDER}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) {
		t.Fatal("could not add test CA")
	}
	return certificate, roots
}
