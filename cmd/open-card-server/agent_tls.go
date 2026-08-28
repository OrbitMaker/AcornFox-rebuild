package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func loadAgentGatewayMTLSConfig(caPath, certificatePath, keyPath string) (*tls.Config, error) {
	if caPath == "" || certificatePath == "" || keyPath == "" {
		return nil, errors.New("Agent gateway mTLS requires CA, certificate, and key paths")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read Agent gateway client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("Agent gateway client CA contains no valid certificate")
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load Agent gateway server certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}, nil
}
