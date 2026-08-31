package edgeprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

// CertificateObservation is the verified public portion of the leaf presented
// by the fixed local Edge endpoint. It deliberately contains no certificate
// bytes, issuer text, private-key reference, or caller-provided address.
type CertificateObservation struct {
	Hostname    string
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
}

// CertificateObserver observes one DNS hostname through the fixed Edge TLS
// endpoint. Implementations must not turn Hostname into a network address.
type CertificateObserver interface {
	ObserveCertificate(context.Context, string) (CertificateObservation, error)
}

type certificateObserver struct {
	dial    func(context.Context, string, string) (net.Conn, error)
	rootCAs *x509.CertPool
	now     func() time.Time
	timeout time.Duration
}

const productionCertificateObservationTimeout = 3 * time.Second

// NewCertificateObserver constructs the production observer. TLS uses the
// platform system roots and always dials TCP 127.0.0.1:443.
func NewCertificateObserver() CertificateObserver {
	dialer := &net.Dialer{Timeout: productionCertificateObservationTimeout}
	return &certificateObserver{dial: dialer.DialContext, now: time.Now, timeout: productionCertificateObservationTimeout}
}

// NewTaskCertificateObserver provides the narrow task seam for a local TLS
// fixture. Production callers must use NewCertificateObserver so they cannot
// replace the fixed dial target or the system trust roots.
func NewTaskCertificateObserver(dial func(context.Context, string, string) (net.Conn, error), rootCAs *x509.CertPool, now func() time.Time, timeout time.Duration) (CertificateObserver, error) {
	if dial == nil || now == nil || timeout <= 0 || timeout > productionCertificateObservationTimeout {
		return nil, errors.New("certificate observer dependencies are required")
	}
	return &certificateObserver{dial: dial, rootCAs: rootCAs, now: now, timeout: timeout}, nil
}

func (p *certificateObserver) ObserveCertificate(ctx context.Context, hostname string) (CertificateObservation, error) {
	if ctx == nil {
		return CertificateObservation{}, errors.New("certificate observation context is required")
	}
	if err := ctx.Err(); err != nil {
		return CertificateObservation{}, err
	}
	hostname, err := domain.NormalizeTLSAllowDomain(hostname)
	if err != nil {
		return CertificateObservation{}, errors.New("certificate observation hostname is invalid")
	}
	if p == nil || p.dial == nil || p.now == nil || p.timeout <= 0 {
		return CertificateObservation{}, errors.New("certificate observer is unavailable")
	}
	observedAt := p.now().UTC()
	if observedAt.IsZero() {
		return CertificateObservation{}, errors.New("certificate observation clock is invalid")
	}
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	connection, err := p.dial(probeCtx, "tcp", defaultLoopbackAddress)
	if err != nil {
		if ctx.Err() != nil {
			return CertificateObservation{}, ctx.Err()
		}
		return CertificateObservation{}, errors.New("certificate TLS connection failed")
	}
	defer connection.Close()

	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    p.rootCAs,
		ServerName: hostname,
		Time:       func() time.Time { return observedAt },
	})
	if err := tlsConnection.HandshakeContext(probeCtx); err != nil {
		if ctx.Err() != nil {
			return CertificateObservation{}, ctx.Err()
		}
		return CertificateObservation{}, errors.New("certificate TLS verification failed")
	}
	state := tlsConnection.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return CertificateObservation{}, errors.New("certificate TLS verification failed")
	}
	leaf := state.PeerCertificates[0]
	if err := leaf.VerifyHostname(hostname); err != nil {
		return CertificateObservation{}, errors.New("certificate TLS hostname verification failed")
	}
	if observedAt.Before(leaf.NotBefore) || !observedAt.Before(leaf.NotAfter) {
		return CertificateObservation{}, errors.New("certificate is outside its validity interval")
	}
	sum := sha256.Sum256(leaf.Raw)
	return CertificateObservation{
		Hostname:    hostname,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		NotBefore:   leaf.NotBefore.UTC(),
		NotAfter:    leaf.NotAfter.UTC(),
	}, nil
}
