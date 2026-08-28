package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAGENT_CT_001_RequiresTrustedValidClientCertificate(t *testing.T) {
	serverFiles, validClient, roots := writeMTLSFixture(t, false)
	config, err := loadMTLSConfig(serverFiles.ca, serverFiles.cert, serverFiles.key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(NewAgent("instance-1", "node-1", "test").Handler())
	server.TLS = config
	server.StartTLS()
	defer server.Close()

	withoutCertificate := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	if response, err := withoutCertificate.Get(server.URL + "/healthz"); err == nil {
		response.Body.Close()
		t.Fatal("server accepted a client without a certificate")
	}

	valid := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{validClient}, MinVersion: tls.VersionTLS12}}}
	response, err := valid.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("trusted client was rejected: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("trusted client got %s", response.Status)
	}

	_, expiredClient, _ := writeMTLSFixture(t, true)
	expired := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{expiredClient}, MinVersion: tls.VersionTLS12}}}
	if response, err := expired.Get(server.URL + "/healthz"); err == nil {
		response.Body.Close()
		t.Fatal("server accepted an expired client certificate")
	}
}

type tlsFixtureFiles struct{ ca, cert, key string }

func writeMTLSFixture(t *testing.T, expiredClient bool) (tlsFixtureFiles, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Open Card test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	serverCert, serverKey := issueCertificate(t, ca, caKey, big.NewInt(2), "127.0.0.1", now.Add(-time.Minute), now.Add(time.Hour), true)
	clientNotBefore, clientNotAfter := now.Add(-time.Minute), now.Add(time.Hour)
	if expiredClient {
		clientNotBefore, clientNotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	clientCertPEM, clientKeyPEM := issueCertificate(t, ca, caKey, big.NewInt(3), "client", clientNotBefore, clientNotAfter, false)
	clientCertificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	files := tlsFixtureFiles{ca: filepath.Join(directory, "ca.pem"), cert: filepath.Join(directory, "server.pem"), key: filepath.Join(directory, "server-key.pem")}
	if err := os.WriteFile(files.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.cert, serverCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.key, serverKey, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return files, clientCertificate, roots
}

func issueCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial *big.Int, commonName string, notBefore, notAfter time.Time, server bool) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
