package healthcheck

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

type postgresHealthConnectionFake struct {
	runtime          []install.RuntimePortFact
	platform, routes []install.CertificateCoverageFact
	err, closeErr    error
	closes           int
}

func (f *postgresHealthConnectionFake) RuntimePortFacts(context.Context) ([]install.RuntimePortFact, error) {
	return append([]install.RuntimePortFact(nil), f.runtime...), f.err
}
func (f *postgresHealthConnectionFake) PlatformCertificateCoverage(context.Context) ([]install.CertificateCoverageFact, error) {
	return append([]install.CertificateCoverageFact(nil), f.platform...), f.err
}
func (f *postgresHealthConnectionFake) ServingCertificateCoverage(context.Context) ([]install.CertificateCoverageFact, error) {
	return append([]install.CertificateCoverageFact(nil), f.routes...), f.err
}
func (f *postgresHealthConnectionFake) Close() error { f.closes++; return f.closeErr }

func postgresResolved(digest string) install.ResolvedActiveDatabase {
	return install.ResolvedActiveDatabase{ActivationJSONSHA256: digest, DatabaseEnv: []byte("OPEN_CARD_DATABASE_URL=postgresql://user:secret@db.invalid/open_card\n")}
}
func ptr[T any](value T) *T { return &value }

func TestPostgresRuntimePortSourceUsesUnreleasedLeaseFacts(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	good := []install.RuntimePortFact{
		{LeaseID: "lease-a", ApplicationID: "app-a", DeploymentID: "deploy-a", ServiceName: "web", BindHost: "127.0.0.1", Port: 18482, AcquiredAt: now.Add(-time.Hour), DeploymentState: ptr("serving"), DeploymentHealthy: ptr(true)},
		{LeaseID: "lease-b", ApplicationID: "app-b", DeploymentID: "deploy-b", ServiceName: "api", BindHost: "127.0.0.1", Port: 18481, AcquiredAt: now.Add(-time.Hour), ExpiresAt: ptr(now.Add(time.Hour)), DeploymentState: ptr("runtime_ready"), DeploymentHealthy: ptr(true)},
	}
	resolved := postgresResolved(strings.Repeat("a", 64))
	for _, tc := range []struct {
		name   string
		facts  []install.RuntimePortFact
		accept bool
	}{
		{"candidate and serving leases", good, true},
		{"expired", []install.RuntimePortFact{leaseFact(now, func(v *install.RuntimePortFact) { v.ExpiresAt = ptr(now) })}, false},
		{"released", []install.RuntimePortFact{leaseFact(now, func(v *install.RuntimePortFact) { v.ReleasedAt = ptr(now) })}, false},
		{"wrong binding", []install.RuntimePortFact{leaseFact(now, func(v *install.RuntimePortFact) { v.BindHost = "0.0.0.0" })}, false},
		{"missing deployment", []install.RuntimePortFact{leaseFact(now, func(v *install.RuntimePortFact) { v.DeploymentHealthy = nil })}, false},
		{"duplicate port", []install.RuntimePortFact{leaseFact(now, nil), leaseFact(now, func(v *install.RuntimePortFact) { v.LeaseID = "lease-b" })}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}
			connection := &postgresHealthConnectionFake{runtime: tc.facts}
			var env []byte
			source, err := NewTaskPostgresRuntimePortSource(resolver, func(value []byte) (postgresHealthConnection, error) {
				env = append([]byte(nil), value...)
				return connection, nil
			}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			ports, err := source.RuntimePorts(context.Background())
			if tc.accept {
				if err != nil || !reflect.DeepEqual(ports, []uint16{18481, 18482}) {
					t.Fatalf("ports=%v err=%v", ports, err)
				}
			} else if !errors.Is(err, errPostgresSourceUnavailable) || ports != nil {
				t.Fatalf("ports=%v err=%v", ports, err)
			}
			if resolver.calls != 2 || connection.closes != 1 || string(env) != string(resolved.DatabaseEnv) {
				t.Fatalf("calls=%d closes=%d env=%q", resolver.calls, connection.closes, env)
			}
		})
	}
}

func leaseFact(now time.Time, mutate func(*install.RuntimePortFact)) install.RuntimePortFact {
	value := install.RuntimePortFact{LeaseID: "lease-a", ApplicationID: "app-a", DeploymentID: "deploy-a", ServiceName: "web", BindHost: "127.0.0.1", Port: 18481, AcquiredAt: now.Add(-time.Hour), DeploymentState: ptr("serving"), DeploymentHealthy: ptr(true)}
	if mutate != nil {
		mutate(&value)
	}
	return value
}

func TestPostgresSourcesFailClosedForErrorsDriftCancellationAndClock(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resolved, drift := postgresResolved(strings.Repeat("a", 64)), postgresResolved(strings.Repeat("b", 64))
	connection := &postgresHealthConnectionFake{runtime: []install.RuntimePortFact{leaseFact(now, nil)}}
	for _, tc := range []struct {
		name     string
		resolver *databaseResolverFake
		mutate   func()
	}{
		{"resolver secret", &databaseResolverFake{err: errors.New("postgresql://user:secret@db.invalid")}, func() {}},
		{"query private", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func() { connection.err = errors.New("private-reference") }},
		{"close private", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func() { connection.closeErr = errors.New("private-reference") }},
		{"pointer drift", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, drift}}, func() {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection.err, connection.closeErr, connection.closes = nil, nil, 0
			tc.mutate()
			source, err := NewTaskPostgresRuntimePortSource(tc.resolver, func([]byte) (postgresHealthConnection, error) { return connection, nil }, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.RuntimePorts(context.Background())
			if !errors.Is(err, errPostgresSourceUnavailable) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("err=%v", err)
			}
		})
	}
	resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved}}
	source, err := NewTaskPostgresRuntimePortSource(resolver, func([]byte) (postgresHealthConnection, error) { t.Fatal("opened"); return nil, nil }, func() time.Time { return time.Time{} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.RuntimePorts(context.Background()); !errors.Is(err, errPostgresSourceUnavailable) || resolver.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, resolver.calls)
	}
	source, err = NewTaskPostgresRuntimePortSource(resolver, func([]byte) (postgresHealthConnection, error) { t.Fatal("opened"); return nil, nil }, func() time.Time { return now.In(time.FixedZone("offset", 3600)) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.RuntimePorts(context.Background()); !errors.Is(err, errPostgresSourceUnavailable) || resolver.calls != 0 {
		t.Fatalf("non-utc err=%v calls=%d", err, resolver.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source, err = NewTaskPostgresRuntimePortSource(resolver, func([]byte) (postgresHealthConnection, error) { t.Fatal("opened"); return nil, nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.RuntimePorts(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestPostgresCertificateTargetSourceUsesPlatformAndRouteTopology(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	platform, route := validPlatform(now), validRoute(now)
	resolved := postgresResolved(strings.Repeat("a", 64))
	connection := &postgresHealthConnectionFake{platform: []install.CertificateCoverageFact{platform}, routes: []install.CertificateCoverageFact{route}}
	resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}
	source, err := NewTaskPostgresCertificateTargetSource(resolver, func([]byte) (postgresHealthConnection, error) { return connection, nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	targets, err := source.CertificateTargets(context.Background())
	if err != nil || len(targets) != 2 || targets[0].Hostname != "api.apps.example.test" || targets[1].Hostname != "console.example.test" || targets[1].ExpectedLeafSHA256 != "" || targets[1].PersistedNotAfter != nil || !targets[1].Console || targets[0].ExpectedLeafSHA256 == "" || targets[0].PersistedNotAfter == nil {
		t.Fatalf("targets=%#v err=%v", targets, err)
	}
}

func TestPostgresCertificateTargetSourceRejectsBrokenTopology(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	platform, route := validPlatform(now), validRoute(now)
	for _, tc := range []struct {
		name     string
		platform []install.CertificateCoverageFact
		route    install.CertificateCoverageFact
	}{
		{"missing platform", nil, route}, {"duplicate platform", []install.CertificateCoverageFact{platform, platform}, route},
		{"unverified", []install.CertificateCoverageFact{func() install.CertificateCoverageFact {
			x := platform
			x.PlatformVerificationStatus = "pending"
			return x
		}()}, route},
		{"missing pointer", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.PointerLeaseID = nil; return x }()},
		{"wrong pointer deployment", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.PointerDeploymentID = ptr("other"); return x }()},
		{"wrong lease binding", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.LeaseBindHost = ptr("0.0.0.0"); return x }()},
		{"expired lease", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.LeaseExpiresAt = ptr(now); return x }()},
		{"released lease", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.LeaseReleasedAt = ptr(now); return x }()},
		{"missing deployment", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.RuntimeHealthy = nil; return x }()},
		{"bad certificate", []install.CertificateCoverageFact{platform}, func() install.CertificateCoverageFact { x := route; x.CertificateNotBefore = nil; return x }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved := postgresResolved(strings.Repeat("a", 64))
			resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}
			connection := &postgresHealthConnectionFake{platform: tc.platform, routes: []install.CertificateCoverageFact{tc.route}}
			source, err := NewTaskPostgresCertificateTargetSource(resolver, func([]byte) (postgresHealthConnection, error) { return connection, nil }, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.CertificateTargets(context.Background()); !errors.Is(err, errPostgresSourceUnavailable) || connection.closes != 1 {
				t.Fatalf("err=%v closes=%d", err, connection.closes)
			}
		})
	}
}

func TestPostgresCertificateTargetSourceFailsClosedForLifecycleErrors(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resolved := postgresResolved(strings.Repeat("a", 64))
	drift := postgresResolved(strings.Repeat("b", 64))
	for _, tc := range []struct {
		name     string
		resolver *databaseResolverFake
		queryErr error
		closeErr error
	}{
		{"query", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, errors.New("postgresql://user:secret@db.invalid"), nil},
		{"close", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, nil, errors.New("private certificate reference")},
		{"identity drift", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, drift}}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := &postgresHealthConnectionFake{platform: []install.CertificateCoverageFact{validPlatform(now)}, routes: []install.CertificateCoverageFact{validRoute(now)}, err: tc.queryErr, closeErr: tc.closeErr}
			source, err := NewTaskPostgresCertificateTargetSource(tc.resolver, func([]byte) (postgresHealthConnection, error) { return connection, nil }, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.CertificateTargets(context.Background())
			if !errors.Is(err, errPostgresSourceUnavailable) || connection.closes != 1 || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
				t.Fatalf("err=%v closes=%d", err, connection.closes)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved}}
	source, err := NewTaskPostgresCertificateTargetSource(resolver, func([]byte) (postgresHealthConnection, error) {
		t.Fatal("opened cancelled certificate source")
		return nil, nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.CertificateTargets(ctx); !errors.Is(err, context.Canceled) || resolver.calls != 0 {
		t.Fatalf("cancel err=%v calls=%d", err, resolver.calls)
	}
	source, err = NewTaskPostgresCertificateTargetSource(resolver, func([]byte) (postgresHealthConnection, error) {
		t.Fatal("opened non-UTC certificate source")
		return nil, nil
	}, func() time.Time { return now.In(time.FixedZone("offset", 3600)) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.CertificateTargets(context.Background()); !errors.Is(err, errPostgresSourceUnavailable) || resolver.calls != 0 {
		t.Fatalf("clock err=%v calls=%d", err, resolver.calls)
	}
}

func validPlatform(_ time.Time) install.CertificateCoverageFact {
	return install.CertificateCoverageFact{ID: "platform", Hostname: "example.test", PlatformVerificationStatus: "verified", PlatformWildcardEnabled: false}
}
func validRoute(now time.Time) install.CertificateCoverageFact {
	return install.CertificateCoverageFact{ID: "route", Hostname: "api.apps.example.test", ApplicationID: "app", DeploymentID: "deployment", ServiceName: "web", DesiredState: "active", RouteVerified: true, PointerDeploymentID: ptr("deployment"), PointerLeaseID: ptr("lease"), LeaseApplicationID: ptr("app"), LeaseDeploymentID: ptr("deployment"), LeaseServiceName: ptr("web"), LeaseBindHost: ptr("127.0.0.1"), LeasePort: ptr(18481), DomainVerificationStatus: ptr("verified"), RuntimeHealthy: ptr(true), RuntimeState: ptr("serving"), CertificateStatus: ptr("ready"), CertificateSubject: ptr("api.apps.example.test"), CertificateSecretReference: ptr(edgeCaddyObservationPrefix + strings.Repeat("b", 64)), CertificateNotBefore: ptr(now.Add(-time.Hour)), CertificateNotAfter: ptr(now.Add(time.Hour))}
}
