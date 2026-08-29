//go:build g4b2e2e

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	caddyprovider "github.com/open-card/open-card/internal/providers/caddy"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
)

const g4b2E2EDatabasePrefix = "open_card_g4b2_e2e_"

func TestG4B2TaskLocalCompositionE2E(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_E2E_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_E2E_DATABASE_URL is required for task-local G4B2 E2E")
	}
	validateG4B2E2EDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	repositoryRoot := g4b2E2ERepositoryRoot(t)
	if err := postgres.ResetG4B2E2ESchema(ctx, db, repositoryRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := postgres.ResetG4B2E2ESchema(context.Background(), db, repositoryRoot); err != nil {
			t.Errorf("reset task-local G4B2 E2E schema: %v", err)
		}
		_ = db.Close()
	})

	store := postgres.NewStore(db)
	seed := seedG4B2E2E(t, ctx, store)
	admin := newG4B2E2EAdmin(t)
	pool, dial := newG4B2E2ETLSServer(t, seed.customHost, seed.platformHost)
	probe, err := edgeprobe.NewG4B2E2EProbe(edgeprobe.Config{
		RootCAs:               pool,
		ConnectTimeout:        time.Second,
		TLSHandshakeTimeout:   time.Second,
		ResponseHeaderTimeout: time.Second,
		OverallTimeout:        3 * time.Second,
	}, dial, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := caddyprovider.New(caddyprovider.Config{AdminURL: admin.server.URL, Listen: "127.0.0.1:18481", Issuer: "internal"})
	if err != nil {
		t.Fatal(err)
	}
	controller := &controllers.DomainConvergenceController{
		Store:  &g4b2ConvergenceAdapter{store: store},
		Routes: routes,
		Probe:  probe,
		Lease:  time.Minute,
	}

	for range 2 {
		claimed, err := controller.ReconcileOnce(ctx, "g4b2-e2e-worker")
		if err != nil || !claimed {
			t.Fatalf("converge claimed=%v err=%v", claimed, err)
		}
	}
	assertG4B2E2EConverged(t, ctx, db, store, seed, 18081)
	config, loads := admin.snapshot()
	assertG4B2E2EConfig(t, config, seed.customHost, seed.platformHost)
	if loads != 2 {
		t.Fatalf("converge Caddy loads=%d, want 2", loads)
	}
	assertG4B2E2ESharedLeaseCutover(t, ctx, db, store, controller, seed)
	assertG4B2E2EConverged(t, ctx, db, store, seed, 18082)
	_, loads = admin.snapshot()

	intent, replay, err := store.BeginDomainUnbind(ctx, seed.applicationID, seed.customDomainID, "admin-g4b2-e2e", "unbind-"+seed.suffix, time.Now().UTC())
	if err != nil || replay {
		t.Fatalf("begin custom unbind intent=%+v replay=%v err=%v", intent, replay, err)
	}
	beforeFailureConfig, beforeFailureLoads := admin.snapshot()
	admin.failNextLoad(http.StatusBadGateway)
	if _, err := controller.ReconcileOnce(ctx, "g4b2-e2e-worker"); err == nil {
		t.Fatal("Caddy rejection did not fail the unbind attempt")
	}
	failed, err := store.LoadDomainConvergenceRequest(ctx, intent.Request.ID)
	if err != nil || failed.Phase != postgres.DomainConvergenceQueued || failed.Status != postgres.DomainConvergenceQueuedStatus {
		t.Fatalf("failed unbind request=%+v err=%v", failed, err)
	}
	assertG4B2E2EBindingPresent(t, ctx, db, seed.customDomainID)
	afterFailureConfig, afterFailureLoads := admin.snapshot()
	if !bytes.Equal(beforeFailureConfig, afterFailureConfig) || beforeFailureLoads != afterFailureLoads {
		t.Fatal("rejected Caddy load changed the active fake Admin configuration")
	}

	claimed, err := controller.ReconcileOnce(ctx, "g4b2-e2e-worker")
	if err != nil || !claimed {
		t.Fatalf("unbind retry claimed=%v err=%v", claimed, err)
	}
	completed, err := store.LoadDomainConvergenceRequest(ctx, intent.Request.ID)
	if err != nil || completed.Phase != postgres.DomainConvergenceCompleted || completed.Status != postgres.DomainConvergenceCompletedStatus {
		t.Fatalf("completed unbind request=%+v err=%v", completed, err)
	}
	assertG4B2E2EBindingAbsent(t, ctx, db, seed.customDomainID)
	finalConfig, finalLoads := admin.snapshot()
	assertG4B2E2EConfig(t, finalConfig, seed.platformHost)
	if strings.Contains(string(finalConfig), seed.customHost) || finalLoads != loads+1 {
		t.Fatalf("unbind did not atomically leave the remaining route set: loads=%d config=%s", finalLoads, finalConfig)
	}
	assertG4B2E2ECrossApplicationRebind(t, ctx, db, store, controller, seed)
}

type g4b2E2ESeed struct {
	applicationID, customDomainID, platformDomainID domain.ID
	customHost, platformHost                        string
	suffix                                          string
}

func seedG4B2E2E(t *testing.T, ctx context.Context, store *postgres.Store) g4b2E2ESeed {
	t.Helper()
	db := store.DB()
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := fmt.Sprintf("%x", now.UnixNano())
	app := domain.ID("app_g4b2e2e_" + suffix)
	seedG4B2E2ERuntime(t, ctx, db, app, suffix, 18081, now)
	verifiedAt := now
	customID, platformID, platformBaseID := domain.ID("custom_g4b2e2e_"+suffix), domain.ID("platform_g4b2e2e_"+suffix), domain.ID("platform_base_g4b2e2e_"+suffix)
	customHost := "custom-" + suffix + ".example.test"
	platformHost := "app-" + suffix + ".apps.example.test"
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_platform_domains(id,hostname,dns_provider_ref,verification_status,wildcard_enabled,verification_ref,verified_at,created_at,updated_at) VALUES($1,'apps.example.test','task-e2e','verified',true,'task-e2e',$2,$2,$2)`, platformBaseID.String(), now); err != nil {
		t.Fatal(err)
	}
	for _, record := range []postgres.ApplicationDomainRecord{
		{ID: customID, ApplicationID: app, Hostname: customHost, Kind: "custom", VerificationMethod: "cname", VerificationStatus: postgres.DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now},
		{ID: platformID, ApplicationID: app, PlatformDomainID: platformBaseID, Hostname: platformHost, Kind: "platform", StableSlug: "app-" + suffix, VerificationMethod: "dns01", VerificationStatus: postgres.DomainVerificationVerified, VerificationRef: "task-e2e", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now},
	} {
		if err := store.UpsertApplicationDomain(ctx, record, now); err != nil {
			t.Fatalf("seed G4B2 E2E binding: %v", err)
		}
	}
	for _, domainRecord := range []struct {
		id   domain.ID
		host string
	}{{customID, customHost}, {platformID, platformHost}} {
		if _, replay, err := store.WakeDomainConvergence(ctx, domainRecord.id, app, domainRecord.host, now); err != nil || replay {
			t.Fatalf("wake G4B2 E2E host=%s replay=%v err=%v", domainRecord.host, replay, err)
		}
	}
	return g4b2E2ESeed{applicationID: app, customDomainID: customID, platformDomainID: platformID, customHost: customHost, platformHost: platformHost, suffix: suffix}
}

func seedG4B2E2ERuntime(t *testing.T, ctx context.Context, db *sql.DB, app domain.ID, suffix string, port int, now time.Time) {
	t.Helper()
	environment, source := domain.ID("env_g4b2e2e_"+suffix), domain.ID("src_g4b2e2e_"+suffix)
	definition, release, deployment := domain.ID("def_g4b2e2e_"+suffix), domain.ID("release_g4b2e2e_"+suffix), domain.ID("deploy_g4b2e2e_"+suffix)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "G4B2 E2E " + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, []any{environment.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://g4b2-e2e',$3,$4,'/tmp/g4b2-e2e','prepared',true)`, []any{source.String(), app.String(), suffix, "sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definition.String(), app.String(), source.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,canonical_digest) VALUES($1,$2,$3,1,$4::jsonb,$5)`, []any{release.String(), app.String(), definition.String(), `{"web":"sha256:` + strings.Repeat("b", 64) + `"}`, "sha256:" + strings.Repeat("c", 64)}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'runtime_ready',true)`, []any{deployment.String(), environment.String(), release.String()}},
		{`INSERT INTO m2_release_runtime_specs(release_id,schema_version,spec,canonical_digest) VALUES($1,'1',$2::jsonb,$3)`, []any{release.String(), `{"entry_service":"web","services":[{"name":"web"}]}`, "sha256:" + strings.Repeat("c", 64)}},
		{`INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,host_port,observed_at) VALUES($1,$2,$3,$4,$5,$6,'web','ingress','running',true,true,$7,$8)`, []any{"obs_g4b2e2e_" + suffix, "sample_g4b2e2e_" + suffix, app.String(), environment.String(), deployment.String(), release.String(), port, now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed G4B2 E2E runtime: %v", err)
		}
	}
}

type g4b2E2EAdmin struct {
	server *httptest.Server
	mu     sync.Mutex
	config []byte
	loads  int
	fail   int
}

func newG4B2E2EAdmin(t *testing.T) *g4b2E2EAdmin {
	t.Helper()
	admin := &g4b2E2EAdmin{}
	admin.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		admin.mu.Lock()
		defer admin.mu.Unlock()
		switch request.URL.Path {
		case "/load":
			if request.Method != http.MethodPost {
				writer.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if admin.fail != 0 {
				status := admin.fail
				admin.fail = 0
				writer.WriteHeader(status)
				return
			}
			payload, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
			if err != nil || !json.Valid(payload) {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			admin.config = append(admin.config[:0], payload...)
			admin.loads++
			writer.WriteHeader(http.StatusOK)
		case "/config/":
			if request.Method != http.MethodGet || len(admin.config) == 0 {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(admin.config)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(admin.server.Close)
	return admin
}

func (a *g4b2E2EAdmin) failNextLoad(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = status
}

func (a *g4b2E2EAdmin) snapshot() ([]byte, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.config...), a.loads
}

func newG4B2E2ETLSServer(t *testing.T, hosts ...string) (*x509.CertPool, func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "G4B2 E2E Task CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	certificates := make(map[string]tls.Certificate, len(hosts))
	for index, host := range hosts {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 2)), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		certificates[host] = tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		certificate, found := certificates[info.ServerName]
		if !found {
			return nil, fmt.Errorf("unexpected G4B2 E2E SNI %q", info.ServerName)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, nil
	}}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" || request.TLS == nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(tls.NewListener(listener, tlsConfig)) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	dialer := &net.Dialer{Timeout: time.Second}
	return pool, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, listener.Addr().String())
	}
}

func assertG4B2E2EConverged(t *testing.T, ctx context.Context, db *sql.DB, store *postgres.Store, seed g4b2E2ESeed, wantPort int) {
	t.Helper()
	for _, item := range []struct {
		id   domain.ID
		host string
	}{{seed.customDomainID, seed.customHost}, {seed.platformDomainID, seed.platformHost}} {
		var state, pointerHost, opaque string
		var serving bool
		var port int
		err := db.QueryRowContext(ctx, `SELECT r.desired_state,r.serving,l.bind_host,l.port,c.secret_reference_id FROM m3_desired_routes r JOIN m3_route_pointers p ON p.route_id=r.id JOIN m3_port_leases l ON l.id=p.port_lease_id JOIN m3_certificate_references c ON c.id=r.certificate_reference_id WHERE r.application_domain_id=$1`, item.id.String()).Scan(&state, &serving, &pointerHost, &port, &opaque)
		if err != nil || state != "active" || !serving || pointerHost != "127.0.0.1" || port != wantPort || !strings.HasPrefix(opaque, "edge-caddy-observation:sha256:") || len(opaque) != len("edge-caddy-observation:sha256:")+64 {
			t.Fatalf("converged route host=%s state=%s serving=%v pointer=%s:%d opaque=%q err=%v", item.host, state, serving, pointerHost, port, opaque, err)
		}
	}
	items, err := store.ListApplicationDomains(ctx, seed.applicationID)
	if err != nil || len(items) != 2 {
		t.Fatalf("G3 durable domains items=%+v err=%v", items, err)
	}
	for _, item := range items {
		if !item.Serving || item.Certificate == nil || !item.Certificate.Observed || item.ConvergencePhase != string(postgres.DomainConvergenceCompleted) {
			t.Fatalf("G3 durable ready fact=%+v", item)
		}
	}
	var leaseCount int
	if err := db.QueryRowContext(ctx, `SELECT count(DISTINCT p.port_lease_id) FROM m3_route_pointers p JOIN m3_desired_routes r ON r.id=p.route_id WHERE r.application_domain_id IN ($1,$2)`, seed.customDomainID.String(), seed.platformDomainID.String()).Scan(&leaseCount); err != nil || leaseCount != 1 {
		t.Fatalf("platform/custom shared endpoint lease count=%d err=%v", leaseCount, err)
	}
	var audits int
	wantAudits := 2
	if wantPort == 18082 {
		wantAudits = 4
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE action='domain.route.serving'`).Scan(&audits); err != nil || audits != wantAudits {
		t.Fatalf("route-serving audits=%d want=%d err=%v", audits, wantAudits, err)
	}
}

func assertG4B2E2ESharedLeaseCutover(t *testing.T, ctx context.Context, db *sql.DB, store *postgres.Store, controller *controllers.DomainConvergenceController, seed g4b2E2ESeed) {
	t.Helper()
	var oldLease string
	if err := db.QueryRowContext(ctx, `SELECT p.port_lease_id FROM m3_route_pointers p JOIN m3_desired_routes r ON r.id=p.route_id WHERE r.application_domain_id=$1`, seed.customDomainID.String()).Scan(&oldLease); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(time.Second)
	if _, err := db.ExecContext(ctx, `INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,host_port,observed_at) SELECT $1,$2,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,18082,$3 FROM m4_service_observations WHERE application_id=$4 ORDER BY observed_at DESC,id DESC LIMIT 1`, "obs_cutover_g4b2e2e_"+seed.suffix, "sample_cutover_g4b2e2e_"+seed.suffix, now, seed.applicationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, replay, err := store.WakeDomainConvergence(ctx, seed.customDomainID, seed.applicationID, seed.customHost, now); err != nil || replay {
		t.Fatalf("wake custom cutover replay=%v err=%v", replay, err)
	}
	if claimed, err := controller.ReconcileOnce(ctx, "g4b2-e2e-worker"); err != nil || !claimed {
		t.Fatalf("custom cutover claimed=%v err=%v", claimed, err)
	}
	var firstRelease sql.NullTime
	var firstReferences int
	if err := db.QueryRowContext(ctx, `SELECT released_at FROM m3_port_leases WHERE id=$1`, oldLease).Scan(&firstRelease); err != nil || firstRelease.Valid {
		t.Fatalf("first shared endpoint mover released old lease=%+v err=%v", firstRelease, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_route_pointers WHERE port_lease_id=$1`, oldLease).Scan(&firstReferences); err != nil || firstReferences != 1 {
		t.Fatalf("first shared endpoint mover references=%d err=%v", firstReferences, err)
	}
	if _, replay, err := store.WakeDomainConvergence(ctx, seed.platformDomainID, seed.applicationID, seed.platformHost, now.Add(time.Second)); err != nil || replay {
		t.Fatalf("wake platform cutover replay=%v err=%v", replay, err)
	}
	if claimed, err := controller.ReconcileOnce(ctx, "g4b2-e2e-worker"); err != nil || !claimed {
		t.Fatalf("platform cutover claimed=%v err=%v", claimed, err)
	}
	var finalRelease sql.NullTime
	var finalReferences int
	if err := db.QueryRowContext(ctx, `SELECT released_at FROM m3_port_leases WHERE id=$1`, oldLease).Scan(&finalRelease); err != nil || !finalRelease.Valid {
		t.Fatalf("last shared endpoint mover did not release old lease=%+v err=%v", finalRelease, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_route_pointers WHERE port_lease_id=$1`, oldLease).Scan(&finalReferences); err != nil || finalReferences != 0 {
		t.Fatalf("last shared endpoint mover references=%d err=%v", finalReferences, err)
	}
}

func assertG4B2E2EConfig(t *testing.T, config []byte, hosts ...string) {
	t.Helper()
	if !json.Valid(config) || strings.Contains(strings.ToLower(string(config)), "acme") || strings.Contains(string(config), "BEGIN CERTIFICATE") {
		t.Fatalf("unsafe or invalid fake Caddy config: %s", config)
	}
	for _, host := range hosts {
		if !strings.Contains(string(config), host) {
			t.Fatalf("fake Caddy config does not contain host %q: %s", host, config)
		}
	}
}

func assertG4B2E2EBindingPresent(t *testing.T, ctx context.Context, db *sql.DB, id domain.ID) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_application_domains WHERE id=$1`, id.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("binding present count=%d err=%v", count, err)
	}
}

func assertG4B2E2EBindingAbsent(t *testing.T, ctx context.Context, db *sql.DB, id domain.ID) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_application_domains WHERE id=$1`, id.String()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("binding absent count=%d err=%v", count, err)
	}
}

func assertG4B2E2ECrossApplicationRebind(t *testing.T, ctx context.Context, db *sql.DB, store *postgres.Store, controller *controllers.DomainConvergenceController, seed g4b2E2ESeed) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	applicationID := domain.ID("app_rebind_g4b2e2e_" + seed.suffix)
	seedG4B2E2ERuntime(t, ctx, db, applicationID, "rebind-"+seed.suffix, 18083, now)
	verifiedAt := now
	bindingID := domain.ID("domain_rebind_g4b2e2e_" + seed.suffix)
	if err := store.UpsertApplicationDomain(ctx, postgres.ApplicationDomainRecord{ID: bindingID, ApplicationID: applicationID, Hostname: seed.customHost, Kind: "custom", VerificationMethod: "cname", VerificationStatus: postgres.DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatalf("create cross-application rebind: %v", err)
	}
	if _, replay, err := store.WakeDomainConvergence(ctx, bindingID, applicationID, seed.customHost, now); err != nil || replay {
		t.Fatalf("wake cross-application rebind replay=%v err=%v", replay, err)
	}
	claimed, err := controller.ReconcileOnce(ctx, "g4b2-e2e-worker")
	if err != nil || !claimed {
		t.Fatalf("cross-application rebind claimed=%v err=%v", claimed, err)
	}
	var active, disabled, port int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE desired_state='active'), count(*) FILTER (WHERE desired_state='disabled') FROM m3_desired_routes WHERE hostname=$1 AND path_prefix='/'`, seed.customHost).Scan(&active, &disabled); err != nil || active != 1 || disabled != 1 {
		t.Fatalf("cross-application route states active=%d disabled=%d err=%v", active, disabled, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT l.port FROM m3_desired_routes r JOIN m3_route_pointers p ON p.route_id=r.id JOIN m3_port_leases l ON l.id=p.port_lease_id WHERE r.application_domain_id=$1 AND r.desired_state='active'`, bindingID.String()).Scan(&port); err != nil || port != 18083 {
		t.Fatalf("cross-application rebind port=%d err=%v", port, err)
	}
}

func validateG4B2E2EDSN(t *testing.T, raw string) {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("G4B2 E2E database URL is invalid")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("G4B2 E2E database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, g4b2E2EDatabasePrefix) {
		t.Fatalf("G4B2 E2E database name must use %q prefix", g4b2E2EDatabasePrefix)
	}
}

func g4b2E2ERepositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(workingDirectory, "../.."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve G4B2 E2E repository root: %v", err)
	}
	return root
}
