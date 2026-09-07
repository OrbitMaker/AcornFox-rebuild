package acornfoxobserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type Config struct {
	Resolver Resolver
	Dialer   Dialer
	Clock    func() time.Time
}
type Observer struct {
	resolver Resolver
	dialer   Dialer
	clock    func() time.Time
	roots    *x509.CertPool
}

func New(config Config) (*Observer, error) {
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := config.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Observer{resolver: resolver, dialer: dialer, clock: clock}, nil
}

func ValidateTarget(raw string) error { _, _, err := parseTarget(raw); return err }

func (o *Observer) Observe(ctx context.Context, reportID, targetURL string) Report {
	report := Report{ReportID: reportID, DNS: DNSFact{State: DNSFailed, FailureCode: DNSLookupFailed}, TLS: TLSFact{State: LayerNotAttempted}, HTTPS: HTTPSFact{State: LayerNotAttempted}}
	bounded, cancel := context.WithTimeout(ctx, ObservationTimeout)
	defer cancel()
	parsed, host, err := parseTarget(targetURL)
	if err != nil {
		report.ObservedAt = o.now()
		return report
	}
	addresses, err := o.resolver.LookupIPAddr(bounded, host)
	if err != nil {
		report.DNS.FailureCode = dnsFailure(err)
		report.ObservedAt = o.now()
		return report
	}
	public, ok := publicAddresses(addresses)
	if !ok {
		if len(addresses) == 0 {
			report.DNS.FailureCode = DNSNoAnswer
		}
		report.ObservedAt = o.now()
		return report
	}
	report.DNS = DNSFact{State: DNSObserved, Addresses: public}
	raw, err := o.dialAny(bounded, public)
	if err != nil {
		report.TLS = TLSFact{State: LayerFailed, FailureCode: tlsFailure(err)}
		report.ObservedAt = o.now()
		return report
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: o.roots})
	if err = tlsConn.HandshakeContext(bounded); err != nil {
		_ = raw.Close()
		report.TLS = TLSFact{State: LayerFailed, FailureCode: tlsFailure(err)}
		report.ObservedAt = o.now()
		return report
	}
	defer tlsConn.Close()
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = tlsConn.Close()
		report.TLS = TLSFact{State: LayerFailed, FailureCode: TLSCertificateInvalid}
		report.ObservedAt = o.now()
		return report
	}
	certificate := sha256.Sum256(state.PeerCertificates[0].Raw)
	report.TLS = TLSFact{State: LayerObserved, CertificateSHA256: "sha256:" + hex.EncodeToString(certificate[:])}
	one := &singleTLSConnection{connection: tlsConn, expectedAddress: net.JoinHostPort(host, "443")}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialTLSContext: one.DialTLSContext, TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: o.roots}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, parsed.String(), nil)
	if err != nil {
		_ = tlsConn.Close()
		report.HTTPS = HTTPSFact{State: LayerFailed, FailureCode: HTTPSTransportFailed}
		report.ObservedAt = o.now()
		return report
	}
	response, err := client.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		report.HTTPS = HTTPSFact{State: LayerFailed, FailureCode: httpsFailure(err)}
		report.ObservedAt = o.now()
		return report
	}
	sample, readErr := io.ReadAll(io.LimitReader(response.Body, ResponseSampleLimit+1))
	closeErr := response.Body.Close()
	transport.CloseIdleConnections()
	if readErr != nil || closeErr != nil {
		report.HTTPS = HTTPSFact{State: LayerFailed, FailureCode: httpsFailure(firstError(readErr, closeErr))}
		report.ObservedAt = o.now()
		return report
	}
	truncated := len(sample) > ResponseSampleLimit
	if truncated {
		sample = sample[:ResponseSampleLimit]
	}
	sum := sha256.Sum256(sample)
	size := len(sample)
	status := response.StatusCode
	report.HTTPS = HTTPSFact{State: LayerObserved, HTTPStatus: &status, ResponseSampleSHA256: "sha256:" + hex.EncodeToString(sum[:]), ResponseSampleBytes: &size, ResponseTruncated: &truncated}
	report.ObservedAt = o.now()
	return report
}

func (o *Observer) dialAny(ctx context.Context, addresses []string) (net.Conn, error) {
	var last error
	for _, address := range addresses {
		connection, err := o.dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, "443"))
		if err == nil {
			return connection, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no address")
	}
	return nil, last
}

// PostgreSQL timestamptz and the server-side report canonicalizer preserve
// microseconds. Freeze that precision before the CLI submits the report so an
// accepted response can echo ObservedAt exactly.
func (o *Observer) now() time.Time { return o.clock().UTC().Truncate(time.Microsecond) }
func parseTarget(raw string) (*url.URL, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || (parsed.Port() != "" && parsed.Port() != "443") || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", errors.New("invalid target")
	}
	parsed.Path = "/"
	return parsed, strings.ToLower(parsed.Hostname()), nil
}

func publicAddresses(values []net.IPAddr) ([]string, bool) {
	if len(values) == 0 {
		return nil, false
	}
	set := map[string]struct{}{}
	for _, value := range values {
		address, ok := netip.AddrFromSlice(value.IP)
		if !ok {
			return nil, false
		}
		address = address.Unmap()
		if !publicAddress(address) {
			return nil, false
		}
		set[address.String()] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for address := range set {
		result = append(result, address)
	}
	sort.Strings(result)
	return result, len(result) > 0
}
func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var reservedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28")}

func dnsFailure(err error) string {
	if timeoutError(err) {
		return DNSTimeout
	}
	return DNSLookupFailed
}
func tlsFailure(err error) string {
	if timeoutError(err) {
		return TLSTimeout
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return TLSNameMismatch
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	if errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &roots) {
		return TLSCertificateInvalid
	}
	return TLSConnectFailed
}
func httpsFailure(err error) string {
	if timeoutError(err) {
		return HTTPSTimeout
	}
	return HTTPSTransportFailed
}
func timeoutError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || func() bool { var value net.Error; return errors.As(err, &value) && value.Timeout() }()
}
func firstError(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

type singleTLSConnection struct {
	mu              sync.Mutex
	connection      net.Conn
	expectedAddress string
	used            bool
}

func (s *singleTLSConnection) DialTLSContext(_ context.Context, network, address string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.connection == nil || network != "tcp" || address != s.expectedAddress {
		return nil, errors.New("connection already used")
	}
	s.used = true
	return s.connection, nil
}
