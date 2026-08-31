package healthcheck

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const edgeCaddyObservationPrefix = "edge-caddy-observation:sha256:"

var errPostgresSourceUnavailable = errors.New("postgres health facts unavailable")

// postgresHealthConnection is the narrow read-only selected-database surface
// shared by the production sources. It intentionally cannot expose a DSN.
type postgresHealthConnection interface {
	RuntimePortFacts(context.Context) ([]install.RuntimePortFact, error)
	PlatformCertificateCoverage(context.Context) ([]install.CertificateCoverageFact, error)
	ServingCertificateCoverage(context.Context) ([]install.CertificateCoverageFact, error)
	Close() error
}

type postgresHealthConnectionFactory func([]byte) (postgresHealthConnection, error)

// NewProductionPostgresRuntimePortSource binds listener expectations to the
// fixed production active activation and its selected database.
func NewProductionPostgresRuntimePortSource() (RuntimePortSource, error) {
	resolver, err := install.ProductionActiveDatabaseResolver()
	if err != nil {
		return nil, errPostgresSourceUnavailable
	}
	return NewTaskPostgresRuntimePortSource(resolver, func(databaseEnv []byte) (postgresHealthConnection, error) {
		return install.NewSelectedPostgresDatabase(databaseEnv)
	}, func() time.Time { return time.Now().UTC() })
}

// NewTaskPostgresRuntimePortSource is the explicit task seam for the active
// resolver and selected connection. Both bindings are rechecked around each
// read so a source never mixes rows from a replaced activation.
func NewTaskPostgresRuntimePortSource(resolver ActiveDatabaseIdentityResolver, open postgresHealthConnectionFactory, clock func() time.Time) (RuntimePortSource, error) {
	if resolver == nil || open == nil || clock == nil {
		return nil, errPostgresSourceUnavailable
	}
	return postgresRuntimePortSource{resolver: resolver, open: open, clock: clock}, nil
}

type postgresRuntimePortSource struct {
	resolver ActiveDatabaseIdentityResolver
	open     postgresHealthConnectionFactory
	clock    func() time.Time
}

func (s postgresRuntimePortSource) RuntimePorts(ctx context.Context) ([]uint16, error) {
	now, ok := sourceUTCNow(s.clock)
	if !ok {
		return nil, errPostgresSourceUnavailable
	}
	before, connection, err := s.openActive(ctx)
	if err != nil {
		return nil, err
	}
	facts, readErr := connection.RuntimePortFacts(ctx)
	closeErr := connection.Close()
	if ctxErr := contextError(ctx); ctxErr != nil {
		return nil, ctxErr
	}
	if readErr != nil || closeErr != nil {
		return nil, errPostgresSourceUnavailable
	}
	if err := s.recheck(before); err != nil {
		return nil, err
	}
	ports, ok := runtimePorts(facts, now)
	if !ok {
		return nil, errPostgresSourceUnavailable
	}
	return ports, nil
}

// NewProductionPostgresCertificateTargetSource binds certificate coverage to
// the same fixed active activation database as runtime-port coverage.
func NewProductionPostgresCertificateTargetSource() (CertificateTargetSource, error) {
	resolver, err := install.ProductionActiveDatabaseResolver()
	if err != nil {
		return nil, errPostgresSourceUnavailable
	}
	return NewTaskPostgresCertificateTargetSource(resolver, func(databaseEnv []byte) (postgresHealthConnection, error) {
		return install.NewSelectedPostgresDatabase(databaseEnv)
	}, func() time.Time { return time.Now().UTC() })
}

// NewTaskPostgresCertificateTargetSource exposes explicit test seams without
// allowing callers to substitute an ambient URL or a systemd/CLI source.
func NewTaskPostgresCertificateTargetSource(resolver ActiveDatabaseIdentityResolver, open postgresHealthConnectionFactory, clock func() time.Time) (CertificateTargetSource, error) {
	if resolver == nil || open == nil || clock == nil {
		return nil, errPostgresSourceUnavailable
	}
	return postgresCertificateTargetSource{resolver: resolver, open: open, clock: clock}, nil
}

type postgresCertificateTargetSource struct {
	resolver ActiveDatabaseIdentityResolver
	open     postgresHealthConnectionFactory
	clock    func() time.Time
}

func (s postgresCertificateTargetSource) CertificateTargets(ctx context.Context) ([]CertificateTarget, error) {
	now, ok := sourceUTCNow(s.clock)
	if !ok {
		return nil, errPostgresSourceUnavailable
	}
	before, connection, err := s.openActive(ctx)
	if err != nil {
		return nil, err
	}
	platform, platformErr := connection.PlatformCertificateCoverage(ctx)
	routes, routesErr := connection.ServingCertificateCoverage(ctx)
	closeErr := connection.Close()
	if ctxErr := contextError(ctx); ctxErr != nil {
		return nil, ctxErr
	}
	if platformErr != nil || routesErr != nil || closeErr != nil {
		return nil, errPostgresSourceUnavailable
	}
	if err := s.recheck(before); err != nil {
		return nil, err
	}
	targets, ok := certificateTargets(platform, routes, now)
	if !ok {
		return nil, errPostgresSourceUnavailable
	}
	return targets, nil
}

func (s postgresRuntimePortSource) openActive(ctx context.Context) (install.ResolvedActiveDatabase, postgresHealthConnection, error) {
	return openActivePostgresHealthConnection(ctx, s.resolver, s.open)
}

func (s postgresCertificateTargetSource) openActive(ctx context.Context) (install.ResolvedActiveDatabase, postgresHealthConnection, error) {
	return openActivePostgresHealthConnection(ctx, s.resolver, s.open)
}

func openActivePostgresHealthConnection(ctx context.Context, resolver ActiveDatabaseIdentityResolver, open postgresHealthConnectionFactory) (install.ResolvedActiveDatabase, postgresHealthConnection, error) {
	if err := contextError(ctx); err != nil {
		return install.ResolvedActiveDatabase{}, nil, err
	}
	before, err := resolver.ResolveResolved()
	if err != nil || !validHealthSHA256(before.ActivationJSONSHA256) || len(before.DatabaseEnv) == 0 {
		return install.ResolvedActiveDatabase{}, nil, errPostgresSourceUnavailable
	}
	connection, err := open(append([]byte(nil), before.DatabaseEnv...))
	if err != nil || connection == nil {
		return install.ResolvedActiveDatabase{}, nil, errPostgresSourceUnavailable
	}
	return before, connection, nil
}

func (s postgresRuntimePortSource) recheck(before install.ResolvedActiveDatabase) error {
	after, err := s.resolver.ResolveResolved()
	if err != nil || !sameActivationJSONIdentity(before, after) {
		return errPostgresSourceUnavailable
	}
	return nil
}

func (s postgresCertificateTargetSource) recheck(before install.ResolvedActiveDatabase) error {
	after, err := s.resolver.ResolveResolved()
	if err != nil || !sameActivationJSONIdentity(before, after) {
		return errPostgresSourceUnavailable
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func sourceUTCNow(clock func() time.Time) (time.Time, bool) {
	if clock == nil {
		return time.Time{}, false
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return time.Time{}, false
	}
	return now, true
}

func runtimePorts(facts []install.RuntimePortFact, now time.Time) ([]uint16, bool) {
	ports := make([]uint16, 0, len(facts))
	seen := make(map[uint16]struct{}, len(facts))
	for _, fact := range facts {
		if fact.LeaseID == "" || fact.ApplicationID == "" || fact.DeploymentID == "" || fact.ServiceName == "" || fact.BindHost != "127.0.0.1" || fact.Port < 1 || fact.Port > 65535 || fact.AcquiredAt.IsZero() || fact.ReleasedAt != nil || fact.ExpiresAt != nil && !fact.ExpiresAt.After(now) || !valueOfBool(fact.DeploymentHealthy) || !runtimeStateAllowed(valueOf(fact.DeploymentState)) {
			return nil, false
		}
		port := uint16(fact.Port)
		if _, exists := seen[port]; exists {
			return nil, false
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, true
}

func runtimeStateAllowed(state string) bool {
	return state == "runtime_ready" || state == "degraded" || state == "serving"
}

func certificateTargets(platform, routes []install.CertificateCoverageFact, now time.Time) ([]CertificateTarget, bool) {
	if len(platform) != 1 {
		return nil, false
	}
	base := platform[0]
	if base.ID == "" || base.Hostname == "" || base.PlatformVerificationStatus != "verified" {
		return nil, false
	}
	byHostname := map[string]CertificateTarget{
		"console." + base.Hostname: {Hostname: "console." + base.Hostname, Console: true},
	}
	for _, route := range routes {
		if route.ID == "" || route.Hostname == "" || route.ApplicationID == "" || route.DeploymentID == "" || route.ServiceName == "" || route.DesiredState != "active" || !route.RouteVerified || valueOf(route.DomainVerificationStatus) != "verified" || valueOf(route.PointerDeploymentID) != route.DeploymentID || route.PointerLeaseID == nil || valueOf(route.LeaseApplicationID) != route.ApplicationID || valueOf(route.LeaseDeploymentID) != route.DeploymentID || valueOf(route.LeaseServiceName) != route.ServiceName || valueOf(route.LeaseBindHost) != "127.0.0.1" || route.LeasePort == nil || *route.LeasePort < 1 || *route.LeasePort > 65535 || route.LeaseReleasedAt != nil || route.LeaseExpiresAt != nil && !route.LeaseExpiresAt.After(now) || !valueOfBool(route.RuntimeHealthy) || !runtimeStateAllowed(valueOf(route.RuntimeState)) || !certificateReady(route) || valueOf(route.CertificateSubject) != route.Hostname {
			return nil, false
		}
		fingerprint, ok := observationFingerprint(route.CertificateSecretReference)
		if !ok {
			return nil, false
		}
		target := CertificateTarget{Hostname: route.Hostname, ExpectedLeafSHA256: fingerprint, PersistedNotAfter: utcCertificateTime(route.CertificateNotAfter)}
		if previous, exists := byHostname[target.Hostname]; exists {
			if previous.ExpectedLeafSHA256 != target.ExpectedLeafSHA256 || !sameCertificateTime(previous.PersistedNotAfter, target.PersistedNotAfter) {
				return nil, false
			}
			target.Console = previous.Console
		}
		byHostname[target.Hostname] = target
	}
	targets := make([]CertificateTarget, 0, len(byHostname))
	for _, target := range byHostname {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Hostname < targets[j].Hostname })
	return targets, true
}

func certificateReady(fact install.CertificateCoverageFact) bool {
	return valueOf(fact.CertificateStatus) == "ready" && fact.CertificateSubject != nil && fact.CertificateNotBefore != nil && fact.CertificateNotAfter != nil && !fact.CertificateNotBefore.IsZero() && !fact.CertificateNotAfter.IsZero() && fact.CertificateNotAfter.After(*fact.CertificateNotBefore)
}

func observationFingerprint(reference *string) (string, bool) {
	if reference == nil || !strings.HasPrefix(*reference, edgeCaddyObservationPrefix) {
		return "", false
	}
	digest := strings.TrimPrefix(*reference, edgeCaddyObservationPrefix)
	if !validHealthSHA256(digest) {
		return "", false
	}
	return "sha256:" + digest, true
}

func valueOf(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func valueOfBool(value *bool) bool { return value != nil && *value }

func utcCertificateTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func sameCertificateTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.UTC().Equal(right.UTC())
}
