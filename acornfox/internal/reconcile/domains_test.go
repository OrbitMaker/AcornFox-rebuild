package reconcile

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// domainProbe lets a test drive DefaultDomainProbe's outcome per domain name.
type domainProbe struct {
	// fail maps domain name -> error to return; absent name = success (nil).
	fail map[string]error
}

func (p *domainProbe) probe(_ context.Context, _, name string, _ *x509.CertPool) error {
	if p.fail == nil {
		return nil
	}
	return p.fail[name]
}

// liveApp sets up an app with a live, running container so domains are probed.
func liveApp(h *harness, app, id string) {
	a := baseApp(app)
	a.CurrentDeployment = id
	h.store.putApp(a)
	h.store.putDeployment(state.Deployment{ID: id, App: app, Seq: 1, SourceKind: state.SourceUpload, Status: state.StatusLive, ImageID: "sha256:" + app + "-" + id})
	name := runner.ContainerName(app, id)
	h.runner.containers[name] = runner.ContainerInfo{
		ID: "c-" + id, Name: name, App: app, DeploymentID: id,
		Role: runner.RoleApp, State: "running", Running: true, HostPort: 45000,
	}
}

func domainStatus(h *harness, app, name string) state.Domain {
	return h.store.getDomain(app, name)
}

func TestDomainPendingToReady(t *testing.T) {
	h := newHarness(t)
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainPending, CreatedAt: h.clock.Now()})

	dp := &domainProbe{} // all probes succeed
	h.rec.cfg.DomainProbe = dp.probe

	h.rec.round(context.Background(), "web")

	d := domainStatus(h, "web", "notes.test")
	if d.Status != state.DomainReady {
		t.Fatalf("want ready, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
	if d.CheckedAt == nil {
		t.Errorf("CheckedAt not set")
	}
}

func TestDomainPendingStaysPendingWithinBudget(t *testing.T) {
	h := newHarness(t)
	h.rec.cfg.DomainPendingBudget = 10 * time.Minute
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainPending, CreatedAt: h.clock.Now()})

	dp := &domainProbe{fail: map[string]error{"notes.test": fmt.Errorf("no cert")}}
	h.rec.cfg.DomainProbe = dp.probe

	// Within budget: still pending, and no status change means no write/event.
	h.clock.Advance(5 * time.Minute)
	h.rec.round(context.Background(), "web")

	d := domainStatus(h, "web", "notes.test")
	if d.Status != state.DomainPending {
		t.Fatalf("want pending within budget, got %s", d.Status)
	}
	if d.CheckedAt != nil {
		t.Errorf("no-op should not have written CheckedAt")
	}
}

func TestDomainPendingToFailedAfterBudget(t *testing.T) {
	h := newHarness(t)
	h.rec.cfg.DomainPendingBudget = 10 * time.Minute
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainPending, CreatedAt: h.clock.Now()})

	dp := &domainProbe{fail: map[string]error{"notes.test": fmt.Errorf("no cert")}}
	h.rec.cfg.DomainProbe = dp.probe

	h.clock.Advance(11 * time.Minute)
	h.rec.round(context.Background(), "web")

	d := domainStatus(h, "web", "notes.test")
	if d.Status != state.DomainFailed {
		t.Fatalf("want failed after budget, got %s", d.Status)
	}
	if d.Diagnosis == nil || d.Diagnosis.Stage != "domain" || d.Diagnosis.Code != "cert_pending" {
		t.Fatalf("want domain/cert_pending diagnosis, got %+v", d.Diagnosis)
	}
	if d.Diagnosis.Message != "域名 notes.test 的 HTTPS 证书尚未签发" {
		t.Errorf("unexpected message: %q", d.Diagnosis.Message)
	}
	// hint carries the ICP/备案 guidance
	if !containsAll(d.Diagnosis.Hint, "ICP 备案", "80 与 443") {
		t.Errorf("hint missing required guidance: %q", d.Diagnosis.Hint)
	}
}

func TestDomainFailedToReady(t *testing.T) {
	h := newHarness(t)
	h.rec.cfg.DomainPendingBudget = 10 * time.Minute
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainFailed, Diagnosis: certPendingDiagnosis("notes.test"), CreatedAt: h.clock.Now()})

	dp := &domainProbe{} // now succeeds
	h.rec.cfg.DomainProbe = dp.probe

	h.rec.round(context.Background(), "web")

	d := domainStatus(h, "web", "notes.test")
	if d.Status != state.DomainReady {
		t.Fatalf("want ready after recovery, got %s", d.Status)
	}
	if d.Diagnosis != nil {
		t.Errorf("ready domain should clear diagnosis, got %+v", d.Diagnosis)
	}
}

func TestDomainStaysFailedWhileProbeFails(t *testing.T) {
	h := newHarness(t)
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainFailed, Diagnosis: certPendingDiagnosis("notes.test"), CreatedAt: h.clock.Now()})

	dp := &domainProbe{fail: map[string]error{"notes.test": fmt.Errorf("still failing")}}
	h.rec.cfg.DomainProbe = dp.probe

	// Failed stays failed with the same diagnosis: no-op, no new event.
	h.rec.round(context.Background(), "web")
	d := domainStatus(h, "web", "notes.test")
	if d.Status != state.DomainFailed {
		t.Fatalf("want failed, got %s", d.Status)
	}
	if d.CheckedAt != nil {
		t.Errorf("unchanged failed domain must not be re-written")
	}
}

func TestDomainNotProbedWithoutLiveContainer(t *testing.T) {
	h := newHarness(t)
	// App exists but has no live container.
	h.store.putApp(baseApp("web"))
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainPending, CreatedAt: h.clock.Now()})

	probed := false
	h.rec.cfg.DomainProbe = func(context.Context, string, string, *x509.CertPool) error {
		probed = true
		return nil
	}
	h.rec.round(context.Background(), "web")
	if probed {
		t.Fatalf("domains must not be probed before the app is serving")
	}
	if domainStatus(h, "web", "notes.test").Status != state.DomainPending {
		t.Errorf("status must stay pending until the app serves")
	}
}

func TestDesiredRoutesIncludeDomains(t *testing.T) {
	h := newHarness(t)
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "b.test", Status: state.DomainReady, CreatedAt: h.clock.Now()})
	h.store.putDomain(state.Domain{App: "web", Name: "a.test", Status: state.DomainReady, CreatedAt: h.clock.Now()})

	routes, err := h.rec.observedRoutes(context.Background())
	if err != nil {
		t.Fatalf("observedRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if len(routes[0].Domains) != 2 {
		t.Fatalf("want 2 domains on the route, got %v", routes[0].Domains)
	}
}

func TestDomainsSyncedToRouter(t *testing.T) {
	h := newHarness(t)
	liveApp(h, "web", "live00000001")
	h.store.putDomain(state.Domain{App: "web", Name: "notes.test", Status: state.DomainReady, CreatedAt: h.clock.Now()})
	h.rec.cfg.DomainProbe = (&domainProbe{}).probe

	h.rec.round(context.Background(), "web")

	h.router.mu.Lock()
	rt := h.router.routes["web"]
	h.router.mu.Unlock()
	if len(rt.Domains) != 1 || rt.Domains[0] != "notes.test" {
		t.Fatalf("router route missing domain: %+v", rt)
	}
}

// TestDefaultDomainProbeAgainstTLSServer exercises the real DefaultDomainProbe
// against an httptest TLS server, using that server's own cert pool as roots.
func TestDefaultDomainProbeAgainstTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest's default cert is issued for "example.com" and 127.0.0.1.
	roots := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		for _, der := range c.Certificate {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parse cert: %v", err)
			}
			roots.AddCert(cert)
		}
	}
	// Alternatively use the client's configured pool.
	if cp := srv.Client(); cp != nil {
		if tr, ok := cp.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
			roots = tr.TLSClientConfig.RootCAs
		}
	}

	addr := srv.Listener.Addr().String()
	ctx := context.Background()

	// Correct SNI + trusted roots -> success.
	if err := DefaultDomainProbe(ctx, addr, "example.com", roots); err != nil {
		t.Fatalf("probe with correct name/roots failed: %v", err)
	}
	// Wrong hostname -> failure.
	if err := DefaultDomainProbe(ctx, addr, "wrong.invalid", roots); err == nil {
		t.Fatalf("probe with wrong hostname should fail")
	}
	// Untrusted roots (system roots) -> failure.
	if err := DefaultDomainProbe(ctx, addr, "example.com", x509.NewCertPool()); err == nil {
		t.Fatalf("probe with empty roots should fail chain verification")
	}
}

// containsAll reports whether s contains every substring.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
