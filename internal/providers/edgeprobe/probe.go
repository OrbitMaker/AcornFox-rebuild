// Package edgeprobe observes the public Edge only through a fixed local
// loopback TLS endpoint. It deliberately accepts a hostname rather than a URL
// so application input can never choose a dial address, port, path, or redirect.
package edgeprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const defaultLoopbackAddress = "127.0.0.1:443"

type Config struct {
	LoopbackAddress       string
	RootCAs               *x509.CertPool
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	OverallTimeout        time.Duration
}

type Observation struct {
	Hostname    string
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
	Issuer      string
	StatusCode  int
}

type Prober interface {
	Probe(context.Context, string) (Observation, error)
}

type probe struct {
	config Config
	dial   func(context.Context, string, string) (net.Conn, error)
	now    func() time.Time
}

func New(config Config) (Prober, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: config.ConnectTimeout}
	return newProbe(config, dialer.DialContext, time.Now)
}

func newProbe(config Config, dial func(context.Context, string, string) (net.Conn, error), now func() time.Time) (Prober, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	if dial == nil || now == nil {
		return nil, errors.New("edge probe test dependencies are required")
	}
	return &probe{config: config, dial: dial, now: now}, nil
}

func validateConfig(config *Config) error {
	if strings.TrimSpace(config.LoopbackAddress) == "" {
		config.LoopbackAddress = defaultLoopbackAddress
	}
	if config.LoopbackAddress != defaultLoopbackAddress {
		return errors.New("edge probe must use fixed 127.0.0.1:443")
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 3 * time.Second
	}
	if config.TLSHandshakeTimeout == 0 {
		config.TLSHandshakeTimeout = 5 * time.Second
	}
	if config.ResponseHeaderTimeout == 0 {
		config.ResponseHeaderTimeout = 10 * time.Second
	}
	if config.OverallTimeout == 0 {
		config.OverallTimeout = 15 * time.Second
	}
	if config.ConnectTimeout <= 0 || config.TLSHandshakeTimeout <= 0 || config.ResponseHeaderTimeout <= 0 || config.OverallTimeout <= 0 {
		return errors.New("edge probe timeouts must be positive")
	}
	return nil
}

func (p *probe) Probe(ctx context.Context, hostname string) (Observation, error) {
	hostname, err := domain.NormalizeTLSAllowDomain(hostname)
	if err != nil {
		return Observation{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, p.config.OverallTimeout)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(callContext context.Context, network, _ string) (net.Conn, error) {
			return p.dial(callContext, network, p.config.LoopbackAddress)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.config.RootCAs, ServerName: hostname},
		TLSHandshakeTimeout:   p.config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: p.config.ResponseHeaderTimeout,
		ForceAttemptHTTP2:     false,
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, "https://"+hostname+"/", nil)
	if err != nil {
		return Observation{}, fmt.Errorf("create edge probe request: %w", err)
	}
	request.Host = hostname
	response, err := client.Do(request)
	if err != nil {
		return Observation{}, fmt.Errorf("probe edge TLS: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode >= http.StatusInternalServerError {
		return Observation{}, fmt.Errorf("edge probe returned HTTP %d", response.StatusCode)
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		if location := strings.TrimSpace(response.Header.Get("Location")); location != "" {
			target, parseErr := url.Parse(location)
			if parseErr != nil || (target.Hostname() != "" && !strings.EqualFold(target.Hostname(), hostname)) {
				return Observation{}, errors.New("edge probe cross-host redirect is not allowed")
			}
		}
	}
	state := response.TLS
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return Observation{}, errors.New("edge probe TLS chain was not verified")
	}
	leaf := state.PeerCertificates[0]
	now := p.now().UTC()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return Observation{}, errors.New("edge probe certificate is outside its validity interval")
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return Observation{}, fmt.Errorf("edge probe certificate hostname: %w", err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	return Observation{Hostname: hostname, Fingerprint: fmt.Sprintf("sha256:%x", fingerprint[:]), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), Issuer: leaf.Issuer.String(), StatusCode: response.StatusCode}, nil
}
