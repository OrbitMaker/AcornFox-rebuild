package reconcile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// appDomainNames returns the domain names configured for one app, or nil. It is
// used to attach Domains to a route only when the app has a live container.
func (r *Reconciler) appDomainNames(ctx context.Context, app string) []string {
	domains, err := r.cfg.Store.ListDomains(ctx, app)
	if err != nil {
		r.log.Error("list domains", "app", app, "err", err)
		return nil
	}
	if len(domains) == 0 {
		return nil
	}
	names := make([]string, 0, len(domains))
	for _, d := range domains {
		names = append(names, d.Name)
	}
	return names
}

// hasLiveRunningContainer reports whether the app's live deployment container is
// present and running among the observed containers.
func hasLiveRunningContainer(app state.App, containers []runner.ContainerInfo) bool {
	if app.CurrentDeployment == "" {
		return false
	}
	name := runner.ContainerName(app.Name, app.CurrentDeployment)
	for _, c := range containers {
		if c.Name == name {
			return c.Running
		}
	}
	return false
}

// reconcileDomains probes each of the app's domains once and updates its status
// with the pending->ready, pending->failed and failed->ready transitions from
// the contract. It writes to the store only when the status or diagnosis
// changes, and records one event per change.
//
// Probing only makes sense once the app is actually serving, so domains are
// left untouched (kept pending) until the app has a live running container.
func (r *Reconciler) reconcileDomains(ctx context.Context, app state.App, containers []runner.ContainerInfo) {
	domains, err := r.cfg.Store.ListDomains(ctx, app.Name)
	if err != nil {
		r.log.Error("list domains", "app", app.Name, "err", err)
		return
	}
	if len(domains) == 0 {
		return
	}
	if !hasLiveRunningContainer(app, containers) {
		return // not serving yet; leave domains pending
	}

	roots, rerr := r.caRoots()
	if rerr != nil {
		r.log.Error("load domain ca roots", "err", rerr)
		// Fall back to system roots rather than block every domain.
		roots = nil
	}

	httpsAddr := fmt.Sprintf("127.0.0.1:%d", r.httpsPort())
	now := r.cfg.Now()
	for _, d := range domains {
		probeErr := r.cfg.DomainProbe(ctx, httpsAddr, d.Name, roots)
		r.applyDomainStatus(ctx, d, probeErr, now)
	}
}

// applyDomainStatus computes the next status for one domain and persists it only
// when it differs from the stored one.
func (r *Reconciler) applyDomainStatus(ctx context.Context, d state.Domain, probeErr error, now time.Time) {
	var (
		nextStatus string
		nextDiag   *state.Diagnosis
	)
	if probeErr == nil {
		// pending->ready and failed->ready.
		nextStatus = state.DomainReady
	} else {
		// Stay pending until the budget elapses since creation, then fail. A
		// failed domain keeps being retried and stays failed until it succeeds.
		switch d.Status {
		case state.DomainFailed:
			nextStatus = state.DomainFailed
			nextDiag = certPendingDiagnosis(d.Name)
		default:
			if now.Sub(d.CreatedAt) >= r.cfg.DomainPendingBudget {
				nextStatus = state.DomainFailed
				nextDiag = certPendingDiagnosis(d.Name)
			} else {
				nextStatus = state.DomainPending
			}
		}
	}

	if nextStatus == d.Status && diagnosisEqual(d.Diagnosis, nextDiag) {
		return // no change; do not write or emit an event
	}
	if err := r.cfg.Store.SetDomainStatus(ctx, d.App, d.Name, nextStatus, nextDiag); err != nil {
		r.log.Error("set domain status", "app", d.App, "domain", d.Name, "err", err)
		return
	}
	r.event(ctx, d.App, "", "domain", domainStatusMessage(d.Name, nextStatus))
}

// certPendingDiagnosis is the exact domain/cert_pending diagnosis from the N3
// contract (section 3).
func certPendingDiagnosis(name string) *state.Diagnosis {
	return &state.Diagnosis{
		Stage:   "domain",
		Code:    "cert_pending",
		Message: "域名 " + name + " 的 HTTPS 证书尚未签发",
		Hint:    "确认域名 A 记录指向本服务器、80 与 443 端口已放行；中国大陆服务器的域名须已完成 ICP 备案，否则 80/443 会被拦截、证书无法签发。未备案时请继续使用 http://IP:端口",
	}
}

func domainStatusMessage(name, status string) string {
	switch status {
	case state.DomainReady:
		return "域名 " + name + " 的 HTTPS 证书已就绪"
	case state.DomainFailed:
		return "域名 " + name + " 的 HTTPS 证书签发失败"
	default:
		return "域名 " + name + " 等待 HTTPS 证书"
	}
}

// diagnosisEqual compares two diagnoses by value (both may be nil).
func diagnosisEqual(a, b *state.Diagnosis) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (r *Reconciler) httpsPort() int {
	if r.cfg.HTTPS.HTTPSPort != 0 {
		return r.cfg.HTTPS.HTTPSPort
	}
	return 443
}

// caRoots returns the CA pool for domain probing: the configured PEM file, or
// nil for system roots. The file is read at most once per Reconciler.
func (r *Reconciler) caRoots() (*x509.CertPool, error) {
	if r.cfg.HTTPSCAFile == "" {
		return nil, nil
	}
	r.caOnce.Do(func() {
		pem, err := os.ReadFile(r.cfg.HTTPSCAFile)
		if err != nil {
			r.caErr = err
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			r.caErr = fmt.Errorf("no certificates parsed from %s", r.cfg.HTTPSCAFile)
			return
		}
		r.caPool = pool
	})
	return r.caPool, r.caErr
}

// DefaultDomainProbe dials httpsAddr with TLS, sends SNI=name, and verifies the
// presented chain against roots (system roots when nil) plus VerifyHostname. It
// returns nil only when the certificate is valid for name.
func DefaultDomainProbe(ctx context.Context, httpsAddr, name string, roots *x509.CertPool) error {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config: &tls.Config{
			ServerName: name,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(cctx, "tcp", httpsAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// tls.Dialer already completed the handshake and verified the chain (no
	// InsecureSkipVerify), so a successful dial means the certificate is valid
	// for name. VerifyHostname is re-checked defensively.
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("domain probe: unexpected connection type")
	}
	if err := tconn.ConnectionState().PeerCertificates[0].VerifyHostname(name); err != nil {
		return err
	}
	return nil
}
