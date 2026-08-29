package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

func TestDomainConvergenceRequestRejectsUnsafePayloadAndInvalidLease(t *testing.T) {
	target := DomainConvergenceRuntimeTarget{ApplicationID: "app_1", DeploymentID: "dep_1", ServiceName: "web", Port: 18081, Path: "/", ReleaseVersion: 1, RuntimeDigest: "sha256:" + strings.Repeat("a", 64)}
	payload, err := domainConvergencePayloadForTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	base := DomainConvergenceRequest{ID: "convergence_1", ApplicationDomainID: "domain_1", ApplicationID: "app_1", Hostname: "app.example.test", Kind: DomainConvergenceConverge, TargetDeploymentID: "dep_1", RequestDigest: domainConvergenceRequestDigest("domain_1", target), IdempotencyKey: "converge-1", ActorType: "system", ActorID: "domain-convergence-controller", Phase: DomainConvergenceQueued, Status: DomainConvergenceQueuedStatus, MaxAttempts: 20, Payload: payload}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	base.Payload = json.RawMessage(`{"private_key":"no"}`)
	if err := base.Validate(); err == nil {
		t.Fatal("sensitive payload accepted")
	}
	base.Payload = payload
	base.LeaseOwner = "worker"
	if err := base.Validate(); err == nil {
		t.Fatal("partial lease accepted")
	}
	base.Kind, base.TargetDeploymentID = DomainConvergenceUnbind, domain.ID("dep_1")
	if err := base.Validate(); err == nil {
		t.Fatal("unbind target deployment accepted")
	}
}

func TestDomainConvergenceRequestRejectsInconsistentLifecycleState(t *testing.T) {
	now := time.Now().UTC()
	leaseUntil := now.Add(time.Minute)
	target := DomainConvergenceRuntimeTarget{ApplicationID: "app_lifecycle_1", DeploymentID: "dep_lifecycle_1", ServiceName: "web", Port: 18081, Path: "/", ReleaseVersion: 1, RuntimeDigest: "sha256:" + strings.Repeat("a", 64)}
	payload, err := domainConvergencePayloadForTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	base := DomainConvergenceRequest{
		ID:                  "convergence_lifecycle_1",
		ApplicationDomainID: "domain_lifecycle_1",
		ApplicationID:       "app_lifecycle_1",
		Hostname:            "app.example.test",
		Kind:                DomainConvergenceConverge,
		TargetDeploymentID:  "dep_lifecycle_1",
		RequestDigest:       domainConvergenceRequestDigest("domain_lifecycle_1", target),
		IdempotencyKey:      "converge-lifecycle-1",
		ActorType:           "system",
		ActorID:             "domain-convergence-controller",
		Phase:               DomainConvergenceQueued,
		Status:              DomainConvergenceQueuedStatus,
		MaxAttempts:         2,
		Payload:             payload,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid queued lifecycle rejected: %v", err)
	}
	for name, mutate := range map[string]func(*DomainConvergenceRequest){
		"leased without lease":   func(r *DomainConvergenceRequest) { r.Status = DomainConvergenceLeased },
		"queued with completion": func(r *DomainConvergenceRequest) { r.CompletedAt = &now },
		"recovery without resume": func(r *DomainConvergenceRequest) {
			r.Phase, r.Status = DomainConvergenceRecoveryRequired, DomainConvergenceRecoveryStatus
		},
		"recovery terminal resume": func(r *DomainConvergenceRequest) {
			r.Phase, r.Status, r.ResumePhase = DomainConvergenceRecoveryRequired, DomainConvergenceRecoveryStatus, DomainConvergenceCompleted
		},
		"failed completed": func(r *DomainConvergenceRequest) {
			r.Phase, r.Status, r.CompletedAt = DomainConvergenceFailed, DomainConvergenceFailedStatus, &now
		},
		"completed without timestamp": func(r *DomainConvergenceRequest) {
			r.Phase, r.Status = DomainConvergenceCompleted, DomainConvergenceCompletedStatus
		},
		"leased valid shape": func(r *DomainConvergenceRequest) {
			r.Phase, r.Status, r.LeaseOwner, r.LeaseUntil = DomainConvergenceTLSAllowed, DomainConvergenceLeased, "worker", &leaseUntil
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			err := candidate.Validate()
			if name == "leased valid shape" {
				if err != nil {
					t.Fatalf("valid leased lifecycle rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("inconsistent lifecycle state accepted")
			}
		})
	}
}

func TestDomainConvergenceFrozenPayloadRequiresExactCompleteTarget(t *testing.T) {
	target := DomainConvergenceRuntimeTarget{ApplicationID: "app_payload_1", DeploymentID: "dep_payload_1", ServiceName: "web", Port: 18081, Path: "/", ReleaseVersion: 7, RuntimeDigest: "sha256:" + strings.Repeat("b", 64)}
	payload, err := domainConvergencePayloadForTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseDomainConvergencePayload(payload, target.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(parsed, target) {
		t.Fatalf("valid frozen target rejected: target=%+v err=%v", parsed, err)
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"deployment_id":"dep_payload_1","service_name":"web","port":18081,"path":"/","release_version":7}`),
		json.RawMessage(`{"deployment_id":"dep_payload_1","service_name":"web","port":18081,"path":"/","release_version":7,"runtime_digest":"sha256:` + strings.Repeat("b", 64) + `","extra":true}`),
		json.RawMessage(`{"deployment_id":"dep_payload_1","service_name":"web","port":0,"path":"/","release_version":7,"runtime_digest":"sha256:` + strings.Repeat("b", 64) + `"}`),
		json.RawMessage(`{"deployment_id":"dep_payload_1","service_name":"web","port":18081,"path":"/other","release_version":7,"runtime_digest":"sha256:` + strings.Repeat("b", 64) + `"}`),
		json.RawMessage(`{"deployment_id":"dep_payload_1","service_name":"web","port":18081,"path":"/","release_version":0,"runtime_digest":"sha256:` + strings.Repeat("b", 64) + `"}`),
	} {
		if _, err := parseDomainConvergencePayload(invalid, target.ApplicationID); err == nil {
			t.Fatalf("invalid frozen target accepted: %s", invalid)
		}
	}
}

func TestDomainConvergenceRequestDigestCoversEveryFrozenTargetField(t *testing.T) {
	base := DomainConvergenceRuntimeTarget{ApplicationID: "app_digest_1", DeploymentID: "dep_digest_1", ServiceName: "web", Port: 18081, Path: "/", ReleaseVersion: 1, RuntimeDigest: "sha256:" + strings.Repeat("c", 64)}
	digest := domainConvergenceRequestDigest("domain_digest_1", base)
	for name, mutate := range map[string]func(*DomainConvergenceRuntimeTarget){
		"service": func(target *DomainConvergenceRuntimeTarget) { target.ServiceName = "api" },
		"port":    func(target *DomainConvergenceRuntimeTarget) { target.Port = 18082 },
		"release": func(target *DomainConvergenceRuntimeTarget) { target.ReleaseVersion = 2 },
		"runtime": func(target *DomainConvergenceRuntimeTarget) {
			target.RuntimeDigest = "sha256:" + strings.Repeat("d", 64)
		},
		"deployment": func(target *DomainConvergenceRuntimeTarget) { target.DeploymentID = "dep_digest_2" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if domainConvergenceRequestDigest("domain_digest_1", candidate) == digest {
				t.Fatalf("%s drift did not change frozen request digest", name)
			}
		})
	}
}

func TestDomainConvergenceRouteIDIsIndependentOfDeploymentAndService(t *testing.T) {
	domainID := domain.ID("domain_route_identity_1")
	stable := DomainConvergenceRouteID(domainID)
	if stable.Empty() || stable != DomainConvergenceRouteID(domainID) {
		t.Fatalf("route identity is not stable: %q", stable)
	}
	if stable == DomainConvergenceRouteID("domain_route_identity_2") {
		t.Fatalf("different application domains shared route identity: %q", stable)
	}
}

func TestDomainConvergencePreparedSnapshotRequiresExactRouteAndPointerVersion(t *testing.T) {
	snapshot := domainConvergencePreparedSnapshot{
		RouteID:             "route_snapshot_1",
		RouteUpdatedAt:      "2026-08-29T00:00:00Z",
		PointerDeploymentID: "dep_snapshot_1",
		PointerLeaseID:      "lease_snapshot_1",
		PointerRevision:     3,
	}
	raw, err := domainConvergencePreparedSnapshotJSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseDomainConvergencePreparedSnapshot(raw)
	if err != nil || parsed != snapshot {
		t.Fatalf("snapshot parsed=%+v err=%v", parsed, err)
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"route_id":"route_snapshot_1","route_updated_at":"2026-08-29T00:00:00Z","pointer_deployment_id":"","pointer_lease_id":"lease_snapshot_1","pointer_revision":0}`),
		json.RawMessage(`{"route_id":"route_snapshot_1","route_updated_at":"2026-08-29T00:00:00+00:00","pointer_deployment_id":"","pointer_lease_id":"","pointer_revision":0}`),
		json.RawMessage(`{"route_id":"route_snapshot_1","route_updated_at":"2026-08-29T00:00:00Z","pointer_deployment_id":"dep_snapshot_1","pointer_lease_id":"lease_snapshot_1","pointer_revision":0}`),
	} {
		if _, err := parseDomainConvergencePreparedSnapshot(invalid); err == nil {
			t.Fatalf("invalid snapshot accepted: %s", invalid)
		}
	}
}

func TestDomainConvergenceSafeCodeRejectsRawProviderDetails(t *testing.T) {
	for _, value := range []string{"probe_failed", "route:observe-failed", "lease_exhausted"} {
		if !domainConvergenceSafeCode(value) {
			t.Fatalf("safe code rejected: %q", value)
		}
	}
	for _, value := range []string{"probe https://user:secret@example.test", "certificate PEM", "UPPERCASE", strings.Repeat("a", 121)} {
		if domainConvergenceSafeCode(value) {
			t.Fatalf("unsafe code accepted: %q", value)
		}
	}
}

func TestParseDomainUnbindPayloadRequiresExactPublicFrozenSchema(t *testing.T) {
	digest := "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	valid := json.RawMessage(`{"binding_id":"domain_1","binding_updated_at":"2026-08-29T00:00:00Z","target_route_digest":"` + digest + `","target_route_count":1,"remaining_route_digest":"` + digest + `","remaining_route_count":2}`)
	payload, err := parseDomainUnbindPayload(valid)
	if err != nil {
		t.Fatalf("valid frozen payload rejected: %v", err)
	}
	if payload.BindingID != "domain_1" || payload.TargetRouteCount != 1 || payload.RemainingRouteCount != 2 {
		t.Fatalf("unexpected parsed payload: %+v", payload)
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"binding_id":"domain_1"}`),
		json.RawMessage(`{"binding_id":"domain_1","binding_updated_at":"2026-08-29T00:00:00Z","target_route_digest":"` + digest + `","target_route_count":1,"remaining_route_digest":"` + digest + `","remaining_route_count":2,"certificate":"secret"}`),
		json.RawMessage(`{"binding_id":"domain_1","binding_updated_at":"2026-08-29T00:00:00Z","target_route_digest":"sha256:ABC","target_route_count":1,"remaining_route_digest":"` + digest + `","remaining_route_count":2}`),
		json.RawMessage(`{"binding_id":"domain_1","binding_updated_at":"2026-08-29T00:00:00+00:00","target_route_digest":"` + digest + `","target_route_count":1,"remaining_route_digest":"` + digest + `","remaining_route_count":2}`),
	} {
		if _, err := parseDomainUnbindPayload(raw); err == nil {
			t.Fatalf("invalid frozen payload accepted: %s", raw)
		}
	}
}

func TestParseDomainUnbindRemovedResultRequiresExactRedactedSchema(t *testing.T) {
	digest := "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	result, err := parseDomainUnbindRemovedResult(json.RawMessage(`{"remaining_route_digest":"` + digest + `","remaining_route_count":3}`))
	if err != nil {
		t.Fatalf("valid redacted result rejected: %v", err)
	}
	if result.RemainingRouteDigest != digest || result.RemainingRouteCount != 3 {
		t.Fatalf("unexpected parsed result: %+v", result)
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"remaining_route_digest":"` + digest + `"}`),
		json.RawMessage(`{"remaining_route_digest":"` + digest + `","remaining_route_count":3,"certificate":"opaque-but-unneeded"}`),
		json.RawMessage(`{"remaining_route_digest":"sha256:ABC","remaining_route_count":3}`),
		json.RawMessage(`{"remaining_route_digest":"` + digest + `","remaining_route_count":-1}`),
	} {
		if _, err := parseDomainUnbindRemovedResult(raw); err == nil {
			t.Fatalf("unsafe or malformed unbind result accepted: %s", raw)
		}
	}
}

func TestDomainUnbindDeletesOnlyUnsharedOpaqueObservationCertificates(t *testing.T) {
	if !domainUnbindObservationCertificateDeletable("edge-caddy-observation:sha256-example", false) {
		t.Fatal("unreferenced opaque edge observation must be deletable")
	}
	if domainUnbindObservationCertificateDeletable("edge-caddy-observation:sha256-example", true) {
		t.Fatal("shared opaque edge observation must not be deleted")
	}
	if domainUnbindObservationCertificateDeletable("secret:certificate_1", false) {
		t.Fatal("non-observation certificate must not be deleted")
	}
}

func TestDomainConvergenceCertificateResultRequiresExactPublicSchema(t *testing.T) {
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	valid := json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","issuer":"Example Test CA","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204}`)
	value, status, err := parseDomainConvergenceCertificateObservationResult(valid, "app.example.test")
	if err != nil || value.Fingerprint != fingerprint || value.Issuer != "Example Test CA" || status != 204 {
		t.Fatalf("valid public observation rejected: value=%+v status=%d err=%v", value, status, err)
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204,"pem":"secret"}`),
		json.RawMessage(`{"fingerprint":"sha256:` + strings.Repeat("A", 64) + `","hostname":"app.example.test","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204}`),
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"other.example.test","issuer":"Example Test CA","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204}`),
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","issuer":"Example Test CA","not_before":"2026-08-30T00:00:00Z","not_after":"2026-08-29T00:00:00Z","status":204}`),
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","issuer":"","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204}`),
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","issuer":"Example\nCA","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204}`),
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","issuer":"-----BEGIN CERTIFICATE-----","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204}`),
		json.RawMessage(`{"fingerprint":"` + fingerprint + `","hostname":"app.example.test","issuer":"Example Test CA","not_before":"2026-08-29T00:00:00Z","not_after":"2026-08-30T00:00:00Z","status":204,"extra":true}`),
	} {
		if _, _, err := parseDomainConvergenceCertificateObservationResult(invalid, "app.example.test"); err == nil {
			t.Fatalf("unsafe public observation accepted: %s", invalid)
		}
	}
}

// TestFinalizeDomainConvergenceCertificateOnTaskScopedPostgres covers the
// short durable CAS against the actual 0024 schema. It is opt-in and uses the
// same loopback/prefix guard as the unbind transaction test above.
func TestFinalizeDomainConvergenceCertificateOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG4B2UnbindTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	t.Run("happy finalize and serving recovery", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		target, err := fixture.store.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
		if err != nil || request.RequestDigest != domainConvergenceRequestDigest(request.ApplicationDomainID, target) {
			t.Fatalf("fixture runtime target drift: target=%+v digest=%s request=%+v err=%v", target, domainConvergenceRequestDigest(request.ApplicationDomainID, target), request, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		locked, err := loadDomainConvergenceRequestForUpdate(ctx, tx, fixture.requestID)
		if err == nil {
			_, _, err = fixture.store.lockDomainConvergenceRouteTx(ctx, tx, locked, fixture.now)
		}
		_ = tx.Rollback()
		if err != nil {
			t.Fatalf("fixture durable target lock rejected: %v", err)
		}
		storedObservation, _, err := parseDomainConvergenceCertificateObservationResult(request.Result, request.Hostname)
		if err != nil || storedObservation.Fingerprint != fixture.observation.Fingerprint || storedObservation.Issuer != fixture.observation.Issuer || storedObservation.NotBefore != fixture.observation.NotBefore.UTC() || storedObservation.NotAfter != fixture.observation.NotAfter.UTC() {
			t.Fatalf("fixture observation mismatch: stored=%+v input=%+v err=%v", storedObservation, fixture.observation, err)
		}
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now); err != nil {
			t.Fatalf("finalize certificate: %v", err)
		}
		completed, err := fixture.store.RecoverDomainConvergenceCompleted(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second))
		if err != nil || !completed {
			t.Fatalf("recover serving completion: completed=%v err=%v", completed, err)
		}
		var serving bool
		if err := db.QueryRowContext(ctx, `SELECT serving FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&serving); err != nil || !serving {
			t.Fatalf("durable route not serving: serving=%v err=%v", serving, err)
		}
		var auditCount int
		var actorType, actorID, evidence string
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE action='domain.route.serving'`).Scan(&auditCount); err != nil || auditCount != 1 {
			t.Fatalf("serving audit count=%d err=%v", auditCount, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT actor_type,actor_id,evidence_refs::text FROM audit_evidence WHERE action='domain.route.serving'`).Scan(&actorType, &actorID, &evidence); err != nil {
			t.Fatal(err)
		}
		if actorType != "system" || actorID != "domain-convergence-controller" || strings.Contains(evidence, "edge-caddy-observation") || strings.Contains(evidence, "private") || strings.Contains(evidence, "BEGIN CERTIFICATE") {
			t.Fatalf("unsafe serving audit actor=%s/%s evidence=%s", actorType, actorID, evidence)
		}
	})

	t.Run("due renewal creates one observation-only request and preserves serving route", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now); err != nil {
			t.Fatal(err)
		}
		if completed, err := fixture.store.RecoverDomainConvergenceCompleted(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); err != nil || !completed {
			t.Fatalf("complete initial convergence=%v err=%v", completed, err)
		}
		initial, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_certificate_references SET renewal_due_at=$2,updated_at=$3 WHERE id=(SELECT certificate_reference_id FROM m3_desired_routes WHERE id=$1)`, fixture.routeID.String(), fixture.now.Add(-time.Minute), fixture.now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		renewal, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, fixture.now)
		if err != nil || replay || renewal.Phase != DomainConvergenceInternalRouteActive || renewal.Status != DomainConvergenceQueuedStatus {
			t.Fatalf("due renewal=%+v replay=%v err=%v", renewal, replay, err)
		}
		replayed, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, fixture.now.Add(30*time.Minute))
		if err != nil || !replay || replayed.ID != renewal.ID {
			t.Fatalf("renewal busy-loop replay=%+v replay=%v err=%v", replayed, replay, err)
		}
		claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now)
		if err != nil || !ok || claimed.ID != renewal.ID || claimed.Phase != DomainConvergenceInternalRouteActive {
			t.Fatalf("renewal claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		if err := fixture.store.AllowDomainConvergenceTLS(ctx, renewal.ID, fixture.owner, fixture.now); err != nil {
			t.Fatal(err)
		}
		renewed := DomainConvergenceCertificateObservation{Fingerprint: "sha256:" + strings.Repeat("e", 64), Issuer: "task-ca-renewed", NotBefore: fixture.now.Add(-time.Minute), NotAfter: fixture.now.Add(2 * time.Hour)}
		if err := fixture.store.RecordDomainConvergenceCertificateObservation(ctx, renewal.ID, fixture.owner, renewed, 204, fixture.now); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, renewal.ID, fixture.owner, renewed, fixture.now); err != nil {
			t.Fatal(err)
		}
		if completed, err := fixture.store.RecoverDomainConvergenceCompleted(ctx, renewal.ID, fixture.owner, fixture.now.Add(time.Second)); err != nil || !completed {
			t.Fatalf("complete renewal=%v err=%v", completed, err)
		}
		var serving bool
		var opaque string
		if err := db.QueryRowContext(ctx, `SELECT r.serving,c.secret_reference_id FROM m3_desired_routes r JOIN m3_certificate_references c ON c.id=r.certificate_reference_id WHERE r.id=$1`, fixture.routeID.String()).Scan(&serving, &opaque); err != nil || !serving || opaque != "edge-caddy-observation:"+renewed.Fingerprint {
			t.Fatalf("renewal route serving=%v opaque=%q err=%v", serving, opaque, err)
		}
		if next, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, fixture.now.Add(30*time.Minute)); err != nil || replay || !next.ID.Empty() {
			t.Fatalf("renewed certificate created premature work=%+v replay=%v err=%v", next, replay, err)
		}
		var auditCount int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE action='domain.certificate.renewed'`).Scan(&auditCount); err != nil || auditCount != 1 {
			t.Fatalf("renewal audit count=%d err=%v", auditCount, err)
		}
	})

	t.Run("expired observed certificate creates a fresh renewal request", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now); err != nil {
			t.Fatal(err)
		}
		if completed, err := fixture.store.RecoverDomainConvergenceCompleted(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); err != nil || !completed {
			t.Fatalf("complete initial convergence=%v err=%v", completed, err)
		}
		initial, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		expiredAt := fixture.now.Add(time.Minute)
		if _, err := db.ExecContext(ctx, `UPDATE m3_certificate_references SET not_before=$2,not_after=$3,renewal_due_at=$4,updated_at=$5 WHERE id=(SELECT certificate_reference_id FROM m3_desired_routes WHERE id=$1)`, fixture.routeID.String(), fixture.now.Add(-time.Hour), expiredAt, fixture.now.Add(time.Hour), fixture.now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		renewal, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, expiredAt.Add(time.Second))
		if err != nil || replay || renewal.ID == initial.ID || renewal.Phase != DomainConvergenceInternalRouteActive || renewal.Status != DomainConvergenceQueuedStatus || !strings.HasPrefix(renewal.IdempotencyKey, "g4b2-renewal:") {
			t.Fatalf("expired renewal=%+v replay=%v err=%v", renewal, replay, err)
		}
	})

	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed valid renewal rearms on next hourly window", true: "failed expired renewal rearms on next hourly window"}[expired], func(t *testing.T) {
			fixture := newG4B2CertificateFixture(t, ctx, db)
			if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now); err != nil {
				t.Fatal(err)
			}
			if completed, err := fixture.store.RecoverDomainConvergenceCompleted(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); err != nil || !completed {
				t.Fatalf("complete initial convergence=%v err=%v", completed, err)
			}
			initial, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
			if err != nil {
				t.Fatal(err)
			}
			updatedAt := fixture.now.Add(-2 * time.Hour)
			notAfter := fixture.now.Add(time.Hour)
			if expired {
				notAfter = fixture.now.Add(-time.Minute)
			}
			if _, err := db.ExecContext(ctx, `UPDATE m3_certificate_references SET not_before=$2,not_after=$3,renewal_due_at=$4,updated_at=$5 WHERE id=(SELECT certificate_reference_id FROM m3_desired_routes WHERE id=$1)`, fixture.routeID.String(), fixture.now.Add(-3*time.Hour), notAfter, fixture.now.Add(-time.Minute), updatedAt); err != nil {
				t.Fatal(err)
			}
			first, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, fixture.now)
			if err != nil || replay || first.ID.Empty() {
				t.Fatalf("first renewal=%+v replay=%v err=%v", first, replay, err)
			}
			if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET max_attempts=1 WHERE id=$1`, first.ID.String()); err != nil {
				t.Fatal(err)
			}
			if claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now); err != nil || !ok || claimed.ID != first.ID {
				t.Fatalf("failed renewal claim=%+v ok=%v err=%v", claimed, ok, err)
			}
			if err := fixture.store.FailDomainConvergenceRequest(ctx, first.ID, fixture.owner, DomainConvergenceInternalRouteActive, "probe_failed", fixture.now); err != nil {
				t.Fatal(err)
			}
			sameWindow, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, fixture.now.Add(30*time.Minute))
			if err != nil || !replay || sameWindow.ID != first.ID {
				t.Fatalf("same renewal window=%+v replay=%v err=%v", sameWindow, replay, err)
			}
			nextWindow, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, fixture.now.Add(time.Hour+time.Second))
			if err != nil || replay || nextWindow.ID.Empty() || nextWindow.ID == first.ID {
				t.Fatalf("rearmed renewal=%+v replay=%v err=%v", nextWindow, replay, err)
			}
		})
	}

	t.Run("expired observation is rejected at record load and finalize boundaries", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		expired := DomainConvergenceCertificateObservation{Fingerprint: "sha256:" + strings.Repeat("f", 64), Issuer: "expired-task-ca", NotBefore: fixture.now.Add(-2 * time.Hour), NotAfter: fixture.now.Add(-time.Hour)}
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='tls_allowed',result='{"tls":"allowed"}'::jsonb WHERE id=$1`, fixture.requestID.String()); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.RecordDomainConvergenceCertificateObservation(ctx, fixture.requestID, fixture.owner, expired, 204, fixture.now); err == nil {
			t.Fatal("expired observation was recorded")
		}
		var phase string
		if err := db.QueryRowContext(ctx, `SELECT phase FROM m3_domain_convergence_requests WHERE id=$1`, fixture.requestID.String()).Scan(&phase); err != nil || phase != "tls_allowed" {
			t.Fatalf("expired record changed phase=%s err=%v", phase, err)
		}
		fixture = newG4B2CertificateFixture(t, ctx, db)
		delayed := fixture.observation.NotAfter.Add(time.Second)
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET lease_until=$2 WHERE id=$1`, fixture.requestID.String(), delayed.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.LoadDomainConvergenceCertificateObservation(ctx, fixture.requestID, fixture.owner, delayed); !errorsIsConvergenceConflict(err) {
			t.Fatalf("expired stored observation load error=%v", err)
		}
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, delayed); err == nil {
			t.Fatal("crash-delayed expired observation finalized")
		}
		var serving bool
		if err := db.QueryRowContext(ctx, `SELECT serving FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&serving); err != nil || serving {
			t.Fatalf("expired observation marked serving=%v err=%v", serving, err)
		}
	})

	t.Run("endpoint cutover rotates an unreferenced old certificate fingerprint", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now); err != nil {
			t.Fatal(err)
		}
		if completed, err := fixture.store.RecoverDomainConvergenceCompleted(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); err != nil || !completed {
			t.Fatalf("complete initial convergence=%v err=%v", completed, err)
		}
		initial, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		var environmentID, definitionID string
		if err := db.QueryRowContext(ctx, `SELECT d.environment_id,r.definition_id FROM deployments d JOIN releases r ON r.id=d.release_id WHERE d.id=$1`, initial.TargetDeploymentID.String()).Scan(&environmentID, &definitionID); err != nil {
			t.Fatal(err)
		}
		cutoverSuffix := strings.ReplaceAll(domain.MustNewID("g4b2rotation").String(), "_", "")
		deploymentID, releaseID := domain.ID("dep_"+cutoverSuffix), domain.ID("release_"+cutoverSuffix)
		digest := "sha256:" + strings.Repeat("e", 64)
		cutoverAt := fixture.now.Add(2 * time.Second)
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,canonical_digest) VALUES($1,$2,$3,2,$4::jsonb,$5)`, []any{releaseID.String(), initial.ApplicationID.String(), definitionID, `{"web":"sha256:` + strings.Repeat("d", 64) + `"}`, digest}},
			{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,updated_at) VALUES($1,$2,$3,'runtime_ready',true,$4)`, []any{deploymentID.String(), environmentID, releaseID.String(), cutoverAt}},
			{`INSERT INTO m2_release_runtime_specs(release_id,schema_version,spec,canonical_digest) VALUES($1,'1',$2::jsonb,$3)`, []any{releaseID.String(), `{"entry_service":"web","services":[{"name":"web"}]}`, digest}},
			{`INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,host_port,observed_at) VALUES($1,$2,$3,$4,$5,$6,'web','ingress','running',true,true,18082,$7)`, []any{"obs_" + cutoverSuffix, "sample_" + cutoverSuffix, initial.ApplicationID.String(), environmentID, deploymentID.String(), releaseID.String(), cutoverAt}},
		} {
			if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		cutover, replay, err := fixture.store.WakeDomainConvergence(ctx, initial.ApplicationDomainID, initial.ApplicationID, initial.Hostname, cutoverAt)
		if err != nil || replay || cutover.ID == initial.ID {
			t.Fatalf("cutover request=%+v replay=%v err=%v", cutover, replay, err)
		}
		if claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, cutoverAt); err != nil || !ok || claimed.ID != cutover.ID {
			t.Fatalf("cutover claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		if _, err := fixture.store.PrepareDomainConvergenceRequest(ctx, cutover.ID, fixture.owner, cutoverAt); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, cutover.ID, fixture.owner, cutoverAt); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.AllowDomainConvergenceTLS(ctx, cutover.ID, fixture.owner, cutoverAt); err != nil {
			t.Fatal(err)
		}
		rotated := DomainConvergenceCertificateObservation{Fingerprint: "sha256:" + strings.Repeat("9", 64), Issuer: "rotated-task-ca", NotBefore: cutoverAt.Add(-time.Minute), NotAfter: cutoverAt.Add(time.Hour)}
		if err := fixture.store.RecordDomainConvergenceCertificateObservation(ctx, cutover.ID, fixture.owner, rotated, 204, cutoverAt); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, cutover.ID, fixture.owner, rotated, cutoverAt); err != nil {
			t.Fatalf("cutover rotation finalization: %v", err)
		}
		var opaque string
		if err := db.QueryRowContext(ctx, `SELECT c.secret_reference_id FROM m3_desired_routes r JOIN m3_certificate_references c ON c.id=r.certificate_reference_id WHERE r.id=$1`, fixture.routeID.String()).Scan(&opaque); err != nil || opaque != "edge-caddy-observation:"+rotated.Fingerprint {
			t.Fatalf("cutover rotation opaque=%q err=%v", opaque, err)
		}
	})

	for _, mutate := range []struct {
		name string
		fn   func(t *testing.T, fixture g4b2CertificateFixture)
	}{
		{"pointer route swap", func(t *testing.T, fixture g4b2CertificateFixture) {
			if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) SELECT $2,application_id,deployment_id,service_name,bind_host,18082,$3 FROM m3_port_leases WHERE id=$1`, fixture.leaseID.String(), "lease_other_"+fixture.suffix, fixture.now); err != nil {
				t.Fatal(err)
			}
			_, err := db.ExecContext(ctx, `UPDATE m3_route_pointers SET port_lease_id=$2 WHERE route_id=$1`, fixture.routeID.String(), "lease_other_"+fixture.suffix)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"released lease", func(t *testing.T, fixture g4b2CertificateFixture) {
			_, err := db.ExecContext(ctx, `UPDATE m3_port_leases SET released_at=$2 WHERE id=$1`, fixture.leaseID.String(), fixture.now)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"missing pointer", func(t *testing.T, fixture g4b2CertificateFixture) {
			if _, err := db.ExecContext(ctx, `DELETE FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()); err != nil {
				t.Fatal(err)
			}
		}},
		{"lease endpoint drift", func(t *testing.T, fixture g4b2CertificateFixture) {
			if _, err := db.ExecContext(ctx, `UPDATE m3_port_leases SET bind_host='127.0.0.2',port=18082 WHERE id=$1`, fixture.leaseID.String()); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			fixture := newG4B2CertificateFixture(t, ctx, db)
			mutate.fn(t, fixture)
			if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now.Add(time.Second)); !errorsIsConvergenceConflict(err) {
				t.Fatalf("finalize drift error=%v, want conflict", err)
			}
			var serving bool
			if err := db.QueryRowContext(ctx, `SELECT serving FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&serving); err != nil || serving {
				t.Fatalf("conflicting finalize changed route: serving=%v err=%v", serving, err)
			}
		})
	}

	t.Run("route compare and set zero rows rolls back certificate", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		if _, err := db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION g4b2_block_route_serving_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER g4b2_block_route_serving_update BEFORE UPDATE ON m3_desired_routes FOR EACH ROW EXECUTE FUNCTION g4b2_block_route_serving_update()`); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.FinalizeDomainConvergenceCertificate(ctx, fixture.requestID, fixture.owner, fixture.observation, fixture.now.Add(time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("zero-row route CAS error=%v, want conflict", err)
		}
		var serving sql.NullBool
		var certificate sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT serving,certificate_reference_id FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&serving, &certificate); err != nil || serving.Bool || certificate.Valid {
			t.Fatalf("zero-row route CAS changed durable route: serving=%v certificate=%v err=%v", serving.Bool, certificate.Valid, err)
		}
	})
}

type g4b2CertificateFixture struct {
	store       *Store
	requestID   domain.ID
	routeID     domain.ID
	leaseID     domain.ID
	owner       string
	now         time.Time
	observation DomainConvergenceCertificateObservation
	suffix      string
}

func TestSelectDomainConvergenceRuntimeTargetOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG4B2UnbindTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()

	t.Run("M2 entry service uses latest healthy M4 host port", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		target, err := fixture.store.SelectDomainConvergenceRuntimeTarget(ctx, fixture.storeMustApplicationID(t, fixture.requestID))
		if err != nil {
			t.Fatal(err)
		}
		if target.ServiceName != "web" || target.Port != 18081 || target.Path != "/" || target.ReleaseVersion != 1 || !domainConvergenceFingerprint(target.RuntimeDigest) {
			t.Fatalf("unexpected M2 target: %+v", target)
		}
	})

	for _, tc := range []struct {
		name          string
		artifactCount int
		healthy       bool
		hostIP        string
		wantErr       bool
	}{
		{name: "legacy one service", artifactCount: 1, healthy: true, hostIP: "127.0.0.1"},
		{name: "legacy no artifacts", artifactCount: 0, healthy: true, hostIP: "127.0.0.1", wantErr: true},
		{name: "legacy multiple artifacts", artifactCount: 2, healthy: true, hostIP: "127.0.0.1", wantErr: true},
		{name: "legacy unhealthy", artifactCount: 1, healthy: false, hostIP: "127.0.0.1", wantErr: true},
		{name: "legacy nonloopback", artifactCount: 1, healthy: true, hostIP: "198.51.100.10", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, applicationID := newG4B2LegacySelectorFixture(t, ctx, db, tc.artifactCount, tc.healthy, tc.hostIP)
			target, err := store.SelectDomainConvergenceRuntimeTarget(ctx, applicationID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("unsafe legacy target accepted: %+v", target)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target.ServiceName != "legacy-web" || target.Port != 19081 || target.Path != "/" || target.ReleaseVersion != 1 || !domainConvergenceFingerprint(target.RuntimeDigest) {
				t.Fatalf("unexpected legacy target: %+v", target)
			}
		})
	}
}

func (f g4b2CertificateFixture) storeMustApplicationID(t *testing.T, requestID domain.ID) domain.ID {
	t.Helper()
	request, err := f.store.LoadDomainConvergenceRequest(context.Background(), requestID)
	if err != nil {
		t.Fatal(err)
	}
	return request.ApplicationID
}

func newG4B2LegacySelectorFixture(t *testing.T, ctx context.Context, db *sql.DB, artifactCount int, healthy bool, hostIP string) (*Store, domain.ID) {
	t.Helper()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := NewStore(db)
	suffix := strings.ReplaceAll(domain.MustNewID("g4b2legacy").String(), "_", "")
	now := time.Now().UTC().Truncate(time.Microsecond)
	app, environment, source := domain.ID("app_"+suffix), domain.ID("env_"+suffix), domain.ID("src_"+suffix)
	definition, release, deployment := domain.ID("def_"+suffix), domain.ID("release_"+suffix), domain.ID("dep_"+suffix)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "g4b2-legacy-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, []any{environment.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://g4b2',$3,$4,'/tmp/g4b2','prepared',true)`, []any{source.String(), app.String(), suffix, "sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definition.String(), app.String(), source.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,canonical_digest) VALUES($1,$2,$3,1,$4::jsonb,$5)`, []any{release.String(), app.String(), definition.String(), `{"legacy-web":"sha256:` + strings.Repeat("b", 64) + `","legacy-worker":"sha256:` + strings.Repeat("c", 64) + `"}`, "sha256:" + strings.Repeat("d", 64)}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,host_ip,host_port) VALUES($1,$2,$3,'runtime_ready',$4,$5,19081)`, []any{deployment.String(), environment.String(), release.String(), healthy, hostIP}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed legacy selector fixture: %v", err)
		}
	}
	if artifactCount == 0 {
		return store, app
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < artifactCount; index++ {
		service := "legacy-web"
		if index > 0 {
			service = "legacy-worker"
		}
		planID, buildID, artifactID := fmt.Sprintf("plan_%s_%d", suffix, index), fmt.Sprintf("build_%s_%d", suffix, index), fmt.Sprintf("artifact_%s_%d", suffix, index)
		digest := "sha256:" + strings.Repeat(string(rune('b'+index)), 64)
		if _, err := tx.ExecContext(ctx, `INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,static_runtime_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES($1,$2,$3,$4,'static','.',$5,$6,'{}'::jsonb,'[]'::jsonb,$7,$8)`, planID, source.String(), "sha256:"+strings.Repeat("a", 64), service, "sha256:"+strings.Repeat("e", 64), "open-card.test/"+service, "legacy-"+suffix+fmt.Sprintf("-%d", index), now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO builds(id,plan_id,state,artifact_id,created_at,updated_at) VALUES($1,$2,'succeeded',$3,$4,$4)`, buildID, planID, artifactID, now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES($1,$2,$3,$4,$5,1,$6)`, artifactID, buildID, "open-card.test/"+service, digest, "oci://"+artifactID, now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES($1,$2,$3)`, release.String(), service, artifactID); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return store, app
}

func newG4B2CertificateFixture(t *testing.T, ctx context.Context, db *sql.DB) g4b2CertificateFixture {
	t.Helper()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := NewStore(db)
	suffix := strings.ReplaceAll(domain.MustNewID("g4b2cert").String(), "_", "")
	now := time.Now().UTC().Truncate(time.Microsecond)
	app, environment, source := domain.ID("app_"+suffix), domain.ID("env_"+suffix), domain.ID("src_"+suffix)
	definition, release, deployment := domain.ID("def_"+suffix), domain.ID("release_"+suffix), domain.ID("dep_"+suffix)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "g4b2-cert-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, []any{environment.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://g4b2',$3,$4,'/tmp/g4b2','prepared',true)`, []any{source.String(), app.String(), suffix, "sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definition.String(), app.String(), source.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,canonical_digest) VALUES($1,$2,$3,1,$4::jsonb,$5)`, []any{release.String(), app.String(), definition.String(), `{"web":"sha256:` + strings.Repeat("b", 64) + `"}`, "sha256:" + strings.Repeat("c", 64)}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'runtime_ready',true)`, []any{deployment.String(), environment.String(), release.String()}},
		{`INSERT INTO m2_release_runtime_specs(release_id,schema_version,spec,canonical_digest) VALUES($1,'1',$2::jsonb,$3)`, []any{release.String(), `{"entry_service":"web","services":[{"name":"web"}]}`, "sha256:" + strings.Repeat("c", 64)}},
		{`INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,host_port,observed_at) VALUES($1,$2,$3,$4,$5,$6,'web','ingress','running',true,true,18081,$7)`, []any{"obs_" + suffix, "sample_" + suffix, app.String(), environment.String(), deployment.String(), release.String(), now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed certificate fixture: %v", err)
		}
	}
	verifiedAt := now
	bindingID := domain.ID("domain_" + suffix)
	hostname := "cert-" + suffix[:12] + ".example.test"
	if err := store.UpsertApplicationDomain(ctx, ApplicationDomainRecord{ID: bindingID, ApplicationID: app, Hostname: hostname, Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatalf("seed certificate binding: %v", err)
	}
	target := DomainConvergenceRuntimeTarget{ApplicationID: app, DeploymentID: deployment, ServiceName: "web", Port: 18081, Path: "/", ReleaseVersion: 1, RuntimeDigest: "sha256:" + strings.Repeat("c", 64)}
	payload, err := domainConvergencePayloadForTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	routeID := DomainConvergenceRouteID(bindingID)
	leaseID := tlsAllowLeaseID(app, deployment, target.ServiceName, target.Port)
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'web','127.0.0.1',18081,$4)`, leaseID.String(), app.String(), deployment.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,'web',$5,'/','active',true,false,$6,$6)`, routeID.String(), app.String(), bindingID.String(), deployment.String(), hostname, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, routeID.String(), deployment.String(), leaseID.String(), now); err != nil {
		t.Fatal(err)
	}
	requestID := domain.ID("convergence_" + suffix)
	owner := "worker-g4b2"
	observation := DomainConvergenceCertificateObservation{Fingerprint: "sha256:" + strings.Repeat("d", 64), Issuer: "task-ca", NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	result, err := observation.PublicResult(hostname, 204)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,target_deployment_id,request_digest,idempotency_key,actor_type,actor_id,phase,status,lease_owner,lease_until,attempt,max_attempts,payload,result,created_at,updated_at) VALUES($1,$2,$3,$4,'converge',$5,$6,$7,'system','domain-convergence-controller','certificate_observed','leased',$8,$9,1,20,$10::jsonb,$11,$12,$12)`, requestID.String(), bindingID.String(), app.String(), hostname, deployment.String(), domainConvergenceRequestDigest(bindingID, target), "cert-"+suffix, owner, now.Add(time.Minute), string(payload), []byte(result), now); err != nil {
		t.Fatal(err)
	}
	return g4b2CertificateFixture{store: store, requestID: requestID, routeID: routeID, leaseID: leaseID, owner: owner, now: now, observation: observation, suffix: suffix}
}

// TestActivateDomainConvergenceRouteOnTaskScopedPostgres exercises the
// route/pointer/lease lock sequence against PostgreSQL. It is opt-in so a
// normal developer test run cannot connect to any non-task database.
func TestActivateDomainConvergenceRouteOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG4B2UnbindTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	newFixture := func(t *testing.T) g4b2CertificateFixture {
		t.Helper()
		fixture := newG4B2CertificateFixture(t, ctx, db)
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='queued',result=NULL WHERE id=$1`, fixture.requestID.String()); err != nil {
			t.Fatal(err)
		}
		prepared, err := fixture.store.PrepareDomainConvergenceRequest(ctx, fixture.requestID, fixture.owner, fixture.now)
		if err != nil {
			t.Fatalf("prepare initial route: %v", err)
		}
		fixture.routeID = prepared.Route.ID
		fixture.leaseID = tlsAllowLeaseID(prepared.Route.ApplicationID, prepared.Route.DeploymentID, prepared.Route.ServiceName, prepared.Port)
		return fixture
	}
	prepareTarget := func(t *testing.T, fixture g4b2CertificateFixture, target DomainConvergenceRuntimeTarget, key string) (DomainConvergenceRequest, DomainConvergencePreparedRoute) {
		t.Helper()
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := domainConvergencePayloadForTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		created, _, err := fixture.store.CreateDomainConvergenceRequest(ctx, DomainConvergenceRequest{
			ID:                  domain.ID("convergence_cutover_" + strings.ReplaceAll(domain.MustNewID("g4b2cutover").String(), "_", "")),
			ApplicationDomainID: request.ApplicationDomainID,
			ApplicationID:       request.ApplicationID,
			Hostname:            request.Hostname,
			Kind:                DomainConvergenceConverge,
			TargetDeploymentID:  target.DeploymentID,
			RequestDigest:       domainConvergenceRequestDigest(request.ApplicationDomainID, target),
			IdempotencyKey:      key,
			ActorType:           domainConvergenceSystemActorType,
			ActorID:             domainConvergenceSystemActorID,
			Payload:             payload,
		}, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now)
		if err != nil || !ok || claimed.ID != created.ID {
			t.Fatalf("claim target=%+v claimed=%+v ok=%v err=%v", target, claimed, ok, err)
		}
		prepared, err := fixture.store.PrepareDomainConvergenceRequest(ctx, created.ID, fixture.owner, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		return created, prepared
	}
	seedReplacementTarget := func(t *testing.T, fixture g4b2CertificateFixture) DomainConvergenceRuntimeTarget {
		t.Helper()
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		var environmentID, definitionID string
		if err := db.QueryRowContext(ctx, `SELECT d.environment_id,r.definition_id FROM deployments d JOIN releases r ON r.id=d.release_id WHERE d.id=$1`, request.TargetDeploymentID.String()).Scan(&environmentID, &definitionID); err != nil {
			t.Fatal(err)
		}
		suffix := strings.ReplaceAll(domain.MustNewID("g4b2replacement").String(), "_", "")
		releaseID, deploymentID := domain.ID("release_"+suffix), domain.ID("dep_"+suffix)
		digest := "sha256:" + strings.Repeat("e", 64)
		if _, err := db.ExecContext(ctx, `INSERT INTO releases(id,application_id,definition_id,version,service_digests,canonical_digest) VALUES($1,$2,$3,2,$4::jsonb,$5)`, releaseID.String(), request.ApplicationID.String(), definitionID, `{"web":"sha256:`+strings.Repeat("f", 64)+`"}`, digest); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'runtime_ready',true)`, deploymentID.String(), environmentID, releaseID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE deployments SET updated_at=$2 WHERE id=$1`, deploymentID.String(), fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m2_release_runtime_specs(release_id,schema_version,spec,canonical_digest) VALUES($1,'1',$2::jsonb,$3)`, releaseID.String(), `{"entry_service":"web","services":[{"name":"web"}]}`, digest); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,host_port,observed_at) VALUES($1,$2,$3,$4,$5,$6,'web','ingress','running',true,true,18082,$7)`, "obs_"+suffix, "sample_"+suffix, request.ApplicationID.String(), environmentID, deploymentID.String(), releaseID.String(), fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		target, err := fixture.store.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
		if err != nil || target.DeploymentID != deploymentID || target.Port != 18082 || target.ServiceName != "web" {
			t.Fatalf("replacement target=%+v err=%v", target, err)
		}
		return target
	}

	t.Run("happy route pointer and lease", func(t *testing.T) {
		fixture := newFixture(t)
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		frozen, err := fixture.store.LoadDomainConvergenceFrozenTarget(ctx, fixture.requestID, fixture.owner, fixture.now)
		if err != nil || fixture.routeID != DomainConvergenceRouteID(request.ApplicationDomainID) || frozen.Port != 18081 {
			t.Fatalf("prepared recovery target=%+v route=%s err=%v", frozen, fixture.routeID, err)
		}
		prepared, err := fixture.store.ActivateDomainConvergenceRoute(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second))
		if err != nil {
			t.Fatalf("activate: %v", err)
		}
		if prepared.Request.Phase != DomainConvergenceInternalRouteActive || prepared.Route.ID != fixture.routeID {
			t.Fatalf("unexpected activation result: %+v", prepared)
		}
		var state string
		var pointerLease string
		if err := db.QueryRowContext(ctx, `SELECT r.desired_state,p.port_lease_id FROM m3_desired_routes r JOIN m3_route_pointers p ON p.route_id=r.id WHERE r.id=$1`, fixture.routeID.String()).Scan(&state, &pointerLease); err != nil || state != "active" || pointerLease != fixture.leaseID.String() {
			t.Fatalf("activation did not preserve durable pointer/lease: state=%s lease=%s err=%v", state, pointerLease, err)
		}
	})

	t.Run("same target preserves active route and pointer", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		target, err := fixture.store.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
		if err != nil {
			t.Fatal(err)
		}
		created, _ := prepareTarget(t, fixture, target, "same-target-"+fixture.suffix)
		var beforeDeployment, beforeLease string
		var beforeRevision int64
		if err := db.QueryRowContext(ctx, `SELECT deployment_id,port_lease_id,revision FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()).Scan(&beforeDeployment, &beforeLease, &beforeRevision); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, created.ID, fixture.owner, fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var afterDeployment, afterLease string
		var afterRevision int64
		if err := db.QueryRowContext(ctx, `SELECT deployment_id,port_lease_id,revision FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()).Scan(&afterDeployment, &afterLease, &afterRevision); err != nil || beforeDeployment != afterDeployment || beforeLease != afterLease || beforeRevision != afterRevision {
			t.Fatalf("same target changed pointer before=%s/%s/%d after=%s/%s/%d err=%v", beforeDeployment, beforeLease, beforeRevision, afterDeployment, afterLease, afterRevision, err)
		}
	})

	t.Run("replacement updates stable route and releases old lease", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		replacement := seedReplacementTarget(t, fixture)
		created, prepared := prepareTarget(t, fixture, replacement, "replacement-"+fixture.suffix)
		if prepared.Route.ID != fixture.routeID {
			t.Fatalf("replacement route identity drifted: got=%s want=%s", prepared.Route.ID, fixture.routeID)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, created.ID, fixture.owner, fixture.now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		candidateLeaseID := tlsAllowLeaseID(fixture.storeMustApplicationID(t, fixture.requestID), replacement.DeploymentID, replacement.ServiceName, replacement.Port)
		var routeDeployment, routeService, pointerDeployment, pointerLease, state string
		var serving bool
		var revision int64
		if err := db.QueryRowContext(ctx, `SELECT r.deployment_id,r.service_name,r.desired_state,r.serving,p.deployment_id,p.port_lease_id,p.revision FROM m3_desired_routes r JOIN m3_route_pointers p ON p.route_id=r.id WHERE r.id=$1`, fixture.routeID.String()).Scan(&routeDeployment, &routeService, &state, &serving, &pointerDeployment, &pointerLease, &revision); err != nil || routeDeployment != replacement.DeploymentID.String() || routeService != replacement.ServiceName || pointerDeployment != replacement.DeploymentID.String() || pointerLease != candidateLeaseID.String() || revision != 2 || state != "active" || serving {
			t.Fatalf("replacement cutover route=%s/%s/%s/%v pointer=%s/%s/%d err=%v", routeDeployment, routeService, state, serving, pointerDeployment, pointerLease, revision, err)
		}
		var released sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT released_at FROM m3_port_leases WHERE id=$1`, fixture.leaseID.String()).Scan(&released); err != nil || !released.Valid {
			t.Fatalf("old lease was not released: released=%+v err=%v", released, err)
		}
	})

	t.Run("replacement route drift rolls back activation", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		replacement := seedReplacementTarget(t, fixture)
		created, _ := prepareTarget(t, fixture, replacement, "replacement-drift-"+fixture.suffix)
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET updated_at=$2 WHERE id=$1`, fixture.routeID.String(), fixture.now.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, created.ID, fixture.owner, fixture.now.Add(6*time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("replacement drift activation error=%v, want conflict", err)
		}
		var deployment, lease string
		if err := db.QueryRowContext(ctx, `SELECT r.deployment_id,p.port_lease_id FROM m3_desired_routes r JOIN m3_route_pointers p ON p.route_id=r.id WHERE r.id=$1`, fixture.routeID.String()).Scan(&deployment, &lease); err != nil || deployment == replacement.DeploymentID.String() || lease != fixture.leaseID.String() {
			t.Fatalf("drift activation changed durable route: deployment=%s lease=%s err=%v", deployment, lease, err)
		}
	})

	t.Run("activation restore rebuild snapshot requeues prepared work", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		target, err := fixture.store.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
		if err != nil {
			t.Fatal(err)
		}
		created, _ := prepareTarget(t, fixture, target, "activation-restore-"+fixture.suffix)
		ipRouteID := "route_ip_restore_" + fixture.suffix
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving,created_at,updated_at) SELECT $1,application_id,deployment_id,service_name,'198.51.100.10','/','active',true,false,$3,$3 FROM m3_desired_routes WHERE id=$2`, ipRouteID, fixture.routeID.String(), fixture.now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) SELECT $1,deployment_id,port_lease_id,1,$3 FROM m3_route_pointers WHERE route_id=$2`, ipRouteID, fixture.routeID.String(), fixture.now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET updated_at=$2 WHERE id=$1`, fixture.routeID.String(), fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, created.ID, fixture.owner, fixture.now.Add(2*time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("activation drift error=%v", err)
		}
		if err := fixture.store.MarkDomainConvergenceRecoveryRequired(ctx, created.ID, fixture.owner, DomainConvergenceRoutePrepared, "route_activation_restore_required", fixture.now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now.Add(3*time.Second))
		if err != nil || !ok || claimed.ID != created.ID || claimed.Phase != DomainConvergenceRoutePrepared || claimed.LastError != "route_activation_restore_required" {
			t.Fatalf("restore claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		restore, err := fixture.store.LoadDomainConvergenceActivationRestore(ctx, created.ID, fixture.owner, fixture.now.Add(3*time.Second))
		if err != nil || restore.Count != 2 || restore.Digest == "" {
			t.Fatalf("activation restore=%+v err=%v", restore, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET updated_at=$2 WHERE id=$1`, fixture.routeID.String(), fixture.now.Add(4*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.RestoreDomainConvergenceActivation(ctx, created.ID, fixture.owner, restore.Digest, restore.Count, fixture.now.Add(4*time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("set drift restore error=%v", err)
		}
		restore, err = fixture.store.LoadDomainConvergenceActivationRestore(ctx, created.ID, fixture.owner, fixture.now.Add(4*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.RestoreDomainConvergenceActivation(ctx, created.ID, fixture.owner, restore.Digest, restore.Count, fixture.now.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		requeued, err := fixture.store.LoadDomainConvergenceRequest(ctx, created.ID)
		if err != nil || requeued.Phase != DomainConvergenceRoutePrepared || requeued.Status != DomainConvergenceQueuedStatus || requeued.LastError != "route_activation_restored" || requeued.LeaseUntil != nil {
			t.Fatalf("activation restore requeue=%+v err=%v", requeued, err)
		}
		claimed, ok, err = fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now.Add(6*time.Second))
		if err != nil || !ok || claimed.LastError != "route_activation_restored" {
			t.Fatalf("requeued claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, created.ID, fixture.owner, fixture.now.Add(6*time.Second)); err != nil {
			t.Fatalf("fresh activation after restore: %v", err)
		}
	})

	t.Run("activation compensation at normal max terminalizes only after restore", func(t *testing.T) {
		fixture := newG4B2CertificateFixture(t, ctx, db)
		request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		target, err := fixture.store.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
		if err != nil {
			t.Fatal(err)
		}
		created, _ := prepareTarget(t, fixture, target, "activation-compensation-max-"+fixture.suffix)
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET max_attempts=1 WHERE id=$1`, created.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET updated_at=$2 WHERE id=$1`, fixture.routeID.String(), fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, created.ID, fixture.owner, fixture.now.Add(2*time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("activation drift error=%v", err)
		}
		if err := fixture.store.MarkDomainConvergenceRecoveryRequired(ctx, created.ID, fixture.owner, DomainConvergenceRoutePrepared, "route_activation_restore_required", fixture.now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now.Add(3*time.Second))
		if err != nil || !ok || claimed.Attempt != 1 || claimed.RecoveryAttempt != 1 || claimed.Phase != DomainConvergenceRoutePrepared {
			t.Fatalf("compensation claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		restore, err := fixture.store.LoadDomainConvergenceActivationRestore(ctx, created.ID, fixture.owner, fixture.now.Add(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.RestoreDomainConvergenceActivation(ctx, created.ID, fixture.owner, restore.Digest, restore.Count, fixture.now.Add(4*time.Second)); err != nil {
			t.Fatal(err)
		}
		terminal, err := fixture.store.LoadDomainConvergenceRequest(ctx, created.ID)
		if err != nil || terminal.Phase != DomainConvergenceFailed || terminal.Status != DomainConvergenceFailedStatus || terminal.LastError != "route_activation_restored_exhausted" || terminal.LeaseUntil != nil {
			t.Fatalf("post-compensation terminal=%+v err=%v", terminal, err)
		}
	})

	t.Run("nullable pointer is created after route lock", func(t *testing.T) {
		fixture := newFixture(t)
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); err != nil {
			t.Fatalf("activate nullable pointer: %v", err)
		}
		var pointerLease string
		if err := db.QueryRowContext(ctx, `SELECT port_lease_id FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()).Scan(&pointerLease); err != nil || pointerLease != fixture.leaseID.String() {
			t.Fatalf("nullable pointer was not safely created: lease=%s err=%v", pointerLease, err)
		}
	})

	t.Run("conflicting pointer and stale lease reject without route change", func(t *testing.T) {
		fixture := newFixture(t)
		otherLease := "lease_conflict_" + fixture.suffix
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) SELECT $1,application_id,deployment_id,service_name,bind_host,18082,$2 FROM m3_port_leases WHERE id=$3`, otherLease, fixture.now, fixture.leaseID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) SELECT $1,deployment_id,$2,1,$3 FROM m3_port_leases WHERE id=$4`, fixture.routeID.String(), otherLease, fixture.now, fixture.leaseID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("conflicting pointer activation error=%v, want conflict", err)
		}
		var state string
		if err := db.QueryRowContext(ctx, `SELECT desired_state FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&state); err != nil || state != "pending" {
			t.Fatalf("pointer conflict changed route state=%s err=%v", state, err)
		}

		fixture = newFixture(t)
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET lease_until=$2 WHERE id=$1`, fixture.requestID.String(), fixture.now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, fixture.requestID, fixture.owner, fixture.now); !errorsIsConvergenceConflict(err) {
			t.Fatalf("stale lease activation error=%v, want conflict", err)
		}

		fixture = newFixture(t)
		if _, err := db.ExecContext(ctx, `UPDATE m3_port_leases SET released_at=$2 WHERE id=$1`, fixture.leaseID.String(), fixture.now); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.ActivateDomainConvergenceRoute(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("released port lease activation error=%v, want conflict", err)
		}
	})
}

// TestFinalizeDomainUnbindOnTaskScopedPostgres validates the final short
// transaction against the actual 0024 schema. It is deliberately opt-in and
// rejects any non-loopback database, so regular test runs cannot touch a
// shared or production PostgreSQL instance.
func TestFinalizeDomainUnbindOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG4B2UnbindTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	t.Run("concurrent first attempts serialize by binding and replay", func(t *testing.T) {
		fixture := newG4B2UnbindFixture(t, ctx, db, false, false)
		if _, err := db.ExecContext(ctx, `DELETE FROM m3_domain_convergence_requests WHERE id=$1`, fixture.requestID.String()); err != nil {
			t.Fatal(err)
		}
		type result struct {
			intent DomainUnbindIntent
			replay bool
			err    error
		}
		run := func(keys ...string) []result {
			start := make(chan struct{})
			results := make(chan result, len(keys))
			for _, key := range keys {
				key := key
				go func() {
					<-start
					intent, replay, err := fixture.store.BeginDomainUnbind(context.Background(), fixture.applicationID, fixture.bindingID, "admin_g4b2", key, fixture.now.Add(2*time.Second))
					results <- result{intent: intent, replay: replay, err: err}
				}()
			}
			close(start)
			values := make([]result, 0, len(keys))
			for range keys {
				values = append(values, <-results)
			}
			return values
		}
		for _, keys := range [][]string{{"unbind-concurrent-a", "unbind-concurrent-b"}, {"unbind-same-key", "unbind-same-key"}} {
			if _, err := db.ExecContext(ctx, `DELETE FROM m3_domain_convergence_requests WHERE application_domain_id=$1`, fixture.bindingID.String()); err != nil {
				t.Fatal(err)
			}
			values := run(keys...)
			if values[0].err != nil || values[1].err != nil || values[0].intent.Request.ID.Empty() || values[0].intent.Request.ID != values[1].intent.Request.ID || values[0].replay == values[1].replay {
				t.Fatalf("keys=%v values=%+v", keys, values)
			}
			var active int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_domain_convergence_requests WHERE application_domain_id=$1 AND request_kind='unbind' AND status IN ('queued','leased','recovery_required')`, fixture.bindingID.String()).Scan(&active); err != nil || active != 1 {
				t.Fatalf("keys=%v active=%d err=%v", keys, active, err)
			}
		}
	})

	t.Run("failed terminal creates fresh keyed attempt while original replays", func(t *testing.T) {
		fixture := newG4B2UnbindFixture(t, ctx, db, false, false)
		original, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='failed',status='failed',resume_phase=NULL,lease_owner=NULL,lease_until=NULL,last_error='test_failed',updated_at=$2 WHERE id=$1`, fixture.requestID.String(), fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		replayed, replay, err := fixture.store.BeginDomainUnbind(ctx, fixture.applicationID, fixture.bindingID, "admin_g4b2", original.IdempotencyKey, fixture.now.Add(2*time.Second))
		if err != nil || !replay || replayed.Request.ID != fixture.requestID || replayed.Request.Status != DomainConvergenceFailedStatus {
			t.Fatalf("failed original replay=%+v replay=%v err=%v", replayed, replay, err)
		}
		fresh, replay, err := fixture.store.BeginDomainUnbind(ctx, fixture.applicationID, fixture.bindingID, "admin_g4b2", "unbind-fresh-after-failed", fixture.now.Add(2*time.Second))
		if err != nil || replay || fresh.Request.ID == fixture.requestID || fresh.Request.Status != DomainConvergenceQueuedStatus || fresh.Request.Phase != DomainConvergenceQueued {
			t.Fatalf("failed fresh attempt=%+v replay=%v err=%v", fresh, replay, err)
		}
	})

	t.Run("custom success and replay", func(t *testing.T) {
		fixture := newG4B2UnbindFixture(t, ctx, db, false, false)
		created, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
		if err != nil {
			t.Fatal(err)
		}
		otherApplicationID := domain.ID("app_other_" + strings.ReplaceAll(domain.MustNewID("g4b2crossunbind").String(), "_", ""))
		if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,$2)`, otherApplicationID.String(), "g4b2-cross-app"); err != nil {
			t.Fatal(err)
		}
		const crossApplicationKey = "cross-application-unbind"
		if _, _, err := fixture.store.BeginDomainUnbind(ctx, otherApplicationID, fixture.bindingID, "admin_g4b2", crossApplicationKey, fixture.now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross application begin error=%v, want not found", err)
		}
		var crossApplicationRequests, stillBound int
		var routeState string
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_domain_convergence_requests WHERE request_kind='unbind' AND idempotency_key=$1`, crossApplicationKey).Scan(&crossApplicationRequests); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_application_domains WHERE id=$1`, fixture.bindingID.String()).Scan(&stillBound); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT desired_state FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&routeState); err != nil {
			t.Fatal(err)
		}
		if crossApplicationRequests != 0 || stillBound != 1 || routeState != "active" {
			t.Fatalf("cross application unbind mutated durable facts: requests=%d binding=%d route=%s", crossApplicationRequests, stillBound, routeState)
		}
		replayed, replay, err := fixture.store.BeginDomainUnbind(ctx, fixture.applicationID, fixture.bindingID, "admin_g4b2", created.IdempotencyKey, fixture.now)
		if err != nil || !replay || replayed.Request.ID != fixture.requestID {
			t.Fatalf("begin replay before finalization: intent=%+v replay=%v err=%v", replayed, replay, err)
		}
		genericID := domain.ID("converge_after_unbind_" + strings.ReplaceAll(domain.MustNewID("projection").String(), "_", ""))
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,target_deployment_id,request_digest,idempotency_key,actor_type,actor_id,phase,status,attempt,recovery_attempt,max_attempts,payload,created_at,updated_at) SELECT $1,application_domain_id,application_id,hostname,'converge',deployment_id,$2,$3,'system','scanner','queued','queued',0,0,20,'{}'::jsonb,$4,$4 FROM m3_desired_routes WHERE id=$5`, genericID.String(), "sha256:"+strings.Repeat("d", 64), "ordinary-after-unbind", fixture.now.Add(time.Second), fixture.routeID.String()); err != nil {
			t.Fatalf("insert newer ordinary convergence: %v", err)
		}
		projected, err := fixture.store.ListApplicationDomains(ctx, fixture.applicationID)
		if err != nil || len(projected) != 1 || projected[0].ConvergenceID != fixture.requestID || projected[0].ConvergenceKind != string(DomainConvergenceUnbind) {
			t.Fatalf("active unbind projection=%+v err=%v", projected, err)
		}
		suppressed, replay, err := fixture.store.BeginDomainUnbind(ctx, fixture.applicationID, fixture.bindingID, "admin_g4b2", "different-active-unbind-key", fixture.now.Add(time.Second))
		if err != nil || !replay || suppressed.Request.ID != fixture.requestID {
			t.Fatalf("active unbind was not suppressed across idempotency keys: intent=%+v replay=%v err=%v", suppressed, replay, err)
		}
		if err := fixture.store.FinalizeDomainUnbind(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); err != nil {
			t.Fatalf("finalize custom unbind: %v", err)
		}
		if err := fixture.store.FinalizeDomainUnbind(ctx, fixture.requestID, fixture.owner, fixture.now.Add(2*time.Second)); err != nil {
			t.Fatalf("completed unbind replay: %v", err)
		}
		var bindings, pointers, certificates int
		var state string
		var serving bool
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_application_domains WHERE id=$1`, fixture.bindingID.String()).Scan(&bindings); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT desired_state,serving FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&state, &serving); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_route_pointers WHERE route_id=$1`, fixture.routeID.String()).Scan(&pointers); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_certificate_references WHERE id=$1`, fixture.certificateID.String()).Scan(&certificates); err != nil {
			t.Fatal(err)
		}
		if bindings != 0 || state != "disabled" || serving || pointers != 0 || certificates != 0 {
			t.Fatalf("custom unbind left durable target facts: binding=%d state=%s serving=%v pointers=%d certificates=%d", bindings, state, serving, pointers, certificates)
		}
		var phase, status string
		if err := db.QueryRowContext(ctx, `SELECT phase,status FROM m3_domain_convergence_requests WHERE id=$1`, fixture.requestID.String()).Scan(&phase, &status); err != nil {
			t.Fatal(err)
		}
		if phase != string(DomainConvergenceCompleted) || status != string(DomainConvergenceCompletedStatus) {
			t.Fatalf("unbind request terminal state=%s/%s", phase, status)
		}
		var auditCount int
		var actorType, actorID, evidence string
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE action='domain.unbind.completed'`).Scan(&auditCount); err != nil || auditCount != 1 {
			t.Fatalf("unbind audit count=%d err=%v", auditCount, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT actor_type,actor_id,evidence_refs::text FROM audit_evidence WHERE action='domain.unbind.completed'`).Scan(&actorType, &actorID, &evidence); err != nil {
			t.Fatal(err)
		}
		if actorType != "administrator" || actorID != "admin_g4b2" || strings.Contains(evidence, "edge-caddy-observation") || strings.Contains(evidence, "private") || strings.Contains(evidence, "BEGIN CERTIFICATE") {
			t.Fatalf("unsafe unbind audit actor=%s/%s evidence=%s", actorType, actorID, evidence)
		}
		// The binding is intentionally gone. The original tuple still identifies
		// the immutable completed operation; a new key would reach the missing
		// binding and return NotFound instead.
		replayed, replay, err = fixture.store.BeginDomainUnbind(ctx, fixture.applicationID, fixture.bindingID, "admin_g4b2", created.IdempotencyKey, fixture.now.Add(3*time.Second))
		if err != nil || !replay || replayed.Request.ID != fixture.requestID {
			t.Fatalf("completed binding replay: intent=%+v replay=%v err=%v", replayed, replay, err)
		}
		if _, _, err := fixture.store.BeginDomainUnbind(ctx, fixture.applicationID, fixture.bindingID, "admin_g4b2", "different-key", fixture.now.Add(3*time.Second)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleted binding with a new key error=%v, want not found", err)
		}
	})

	t.Run("target drift and shared certificate preserve facts", func(t *testing.T) {
		fixture := newG4B2UnbindFixture(t, ctx, db, true, false)
		if _, err := db.ExecContext(ctx, `UPDATE m3_desired_routes SET updated_at=$2 WHERE id=$1`, fixture.routeID.String(), fixture.now.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.FinalizeDomainUnbind(ctx, fixture.requestID, fixture.owner, fixture.now.Add(6*time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("target drift finalization error=%v, want conflict", err)
		}
		assertG4B2UnbindTargetStillActive(t, ctx, db, fixture)

		fixture = newG4B2UnbindFixture(t, ctx, db, true, false)
		if err := fixture.store.FinalizeDomainUnbind(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second)); !errorsIsConvergenceConflict(err) {
			t.Fatalf("shared certificate finalization error=%v, want conflict", err)
		}
		assertG4B2UnbindTargetStillActive(t, ctx, db, fixture)
	})

	t.Run("platform binding is explicitly unsupported", func(t *testing.T) {
		fixture := newG4B2UnbindFixture(t, ctx, db, false, true)
		assertG4B2UnbindTargetStillActive(t, ctx, db, fixture)
	})

	t.Run("route removed reloads frozen set before finalization", func(t *testing.T) {
		fixture := newG4B2UnbindFixture(t, ctx, db, true, false)
		work, err := fixture.store.LoadDomainUnbindWork(ctx, fixture.requestID, fixture.owner, fixture.now.Add(time.Second))
		if err != nil || work.Request.Phase != DomainConvergenceUnbindRouteRemoved || work.Restore || len(work.RemainingRoutes) != 1 {
			t.Fatalf("route removed frozen work=%+v err=%v", work, err)
		}
	})

	for _, phase := range []DomainConvergencePhase{DomainConvergenceQueued, DomainConvergenceUnbindRouteRemoved} {
		t.Run("restore current durable set from "+string(phase), func(t *testing.T) {
			fixture := newG4B2UnbindFixture(t, ctx, db, true, false)
			if phase == DomainConvergenceQueued {
				if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='queued',status='leased',resume_phase=NULL,last_error='',lease_owner=$2,lease_until=$3,result=NULL WHERE id=$1`, fixture.requestID.String(), fixture.owner, fixture.now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			if err := fixture.store.MarkDomainConvergenceRecoveryRequired(ctx, fixture.requestID, fixture.owner, phase, "unbind_restore_required", fixture.now.Add(time.Second)); err != nil {
				t.Fatalf("mark restore recovery: %v", err)
			}
			claimed, ok, err := fixture.store.ClaimDomainConvergenceRequest(ctx, fixture.owner, time.Minute, fixture.now.Add(2*time.Second))
			if err != nil || !ok || claimed.Phase != phase || claimed.LastError != "unbind_restore_required" {
				t.Fatalf("restore claim=%+v ok=%v err=%v", claimed, ok, err)
			}
			work, err := fixture.store.LoadDomainUnbindWork(ctx, fixture.requestID, fixture.owner, fixture.now.Add(2*time.Second))
			if err != nil || !work.Restore || work.Request.Phase != phase || len(work.RemainingRoutes) != 2 {
				t.Fatalf("restore work=%+v err=%v", work, err)
			}
			if err := fixture.store.RestoreDomainUnbind(ctx, fixture.requestID, fixture.owner, work.RemainingRouteDigest, work.RemainingRouteCount, fixture.now.Add(3*time.Second)); err != nil {
				t.Fatalf("restore terminalization: %v", err)
			}
			request, err := fixture.store.LoadDomainConvergenceRequest(ctx, fixture.requestID)
			if err != nil || request.Phase != DomainConvergenceFailed || request.Status != DomainConvergenceFailedStatus || request.LastError != "unbind_restore_completed" || request.LeaseUntil != nil {
				t.Fatalf("restore terminal request=%+v err=%v", request, err)
			}
			assertG4B2UnbindTargetStillActive(t, ctx, db, fixture)
		})
	}
}

// TestDomainConvergenceRetryAndResumeOnTaskScopedPostgres exercises the
// lifecycle constraints against a task-only database. It intentionally uses
// no RouteProvider or network provider; the store must be safe before a
// worker can call either one.
func TestDomainConvergenceRetryAndResumeOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG4B2UnbindTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		resetAuthTestSchema(t, context.Background(), db)
		_ = db.Close()
	}()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := NewStore(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := strings.ReplaceAll(domain.MustNewID("g4b2retry").String(), "_", "")
	appID := domain.ID("app_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,$2)`, appID.String(), "g4b2-retry-"+suffix); err != nil {
		t.Fatal(err)
	}
	insertLeased := func(t *testing.T, id string, phase DomainConvergencePhase, attempt, max int) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,request_digest,idempotency_key,actor_type,actor_id,phase,status,lease_owner,lease_until,attempt,max_attempts,payload,created_at,updated_at) VALUES($1,$2,$3,$4,'unbind',$5,$6,'system','domain-convergence-controller',$7,'leased','worker-a',$8,$9,$10,'{}'::jsonb,$11,$11)`, id, "domain_"+id, appID.String(), "retry-"+suffix[:12]+".example.test", "sha256:"+strings.Repeat("a", 64), "key-"+id, phase, now.Add(time.Minute), attempt, max, now); err != nil {
			t.Fatalf("seed leased request: %v", err)
		}
	}

	t.Run("transient retry then terminal max attempt", func(t *testing.T) {
		id := "request_retry_" + suffix
		insertLeased(t, id, DomainConvergenceQueued, 1, 2)
		if err := store.FailDomainConvergenceRequest(ctx, domain.ID(id), "worker-a", DomainConvergenceQueued, "caddy_unavailable", now); err != nil {
			t.Fatalf("transient failure: %v", err)
		}
		request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.Phase != DomainConvergenceQueued || request.Status != DomainConvergenceQueuedStatus || request.CompletedAt != nil || request.LeaseUntil != nil {
			t.Fatalf("transient retry state=%+v err=%v", request, err)
		}
		claimed, ok, err := store.ClaimDomainConvergenceRequest(ctx, "worker-b", time.Minute, now.Add(time.Second))
		if err != nil || !ok || claimed.ID != domain.ID(id) || claimed.Attempt != 2 || claimed.Phase != DomainConvergenceQueued {
			t.Fatalf("retry claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		if err := store.FailDomainConvergenceRequest(ctx, domain.ID(id), "worker-b", DomainConvergenceQueued, "caddy_unavailable", now.Add(2*time.Second)); err != nil {
			t.Fatalf("terminal failure: %v", err)
		}
		request, err = store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.Phase != DomainConvergenceFailed || request.Status != DomainConvergenceFailedStatus || request.CompletedAt != nil || request.LeaseUntil != nil {
			t.Fatalf("terminal state=%+v err=%v", request, err)
		}
		if _, ok, err := store.ClaimDomainConvergenceRequest(ctx, "worker-c", time.Minute, now.Add(3*time.Second)); err != nil || ok {
			t.Fatalf("terminal request claimed ok=%v err=%v", ok, err)
		}
	})

	t.Run("expired max-attempt lease is terminalized before claim", func(t *testing.T) {
		id := "request_expired_max_" + suffix
		insertLeased(t, id, DomainConvergenceQueued, 3, 3)
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET lease_until=$2 WHERE id=$1`, id, now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := store.ClaimDomainConvergenceRequest(ctx, "worker-expired", time.Minute, now); err != nil || ok {
			t.Fatalf("expired max request claimed=%v err=%v", ok, err)
		}
		request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.Phase != DomainConvergenceFailed || request.Status != DomainConvergenceFailedStatus || request.LeaseUntil != nil || request.LeaseOwner != "" || request.LastError != "lease_exhausted" || request.CompletedAt != nil {
			t.Fatalf("expired max request state=%+v err=%v", request, err)
		}
	})

	t.Run("compensation recovery at max attempt remains claimable", func(t *testing.T) {
		id := "request_recovery_max_" + suffix
		insertLeased(t, id, DomainConvergenceUnbindRouteRemoved, 3, 3)
		if err := store.MarkDomainConvergenceRecoveryRequired(ctx, domain.ID(id), "worker-a", DomainConvergenceUnbindRouteRemoved, "unbind_restore_required", now); err != nil {
			t.Fatalf("mark compensation recovery: %v", err)
		}
		request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.Phase != DomainConvergenceRecoveryRequired || request.Status != DomainConvergenceRecoveryStatus || request.ResumePhase != DomainConvergenceUnbindRouteRemoved || request.RecoveryAttempt != 0 || request.LastError != "unbind_restore_required" {
			t.Fatalf("compensation recovery state=%+v err=%v", request, err)
		}
		claimed, ok, err := store.ClaimDomainConvergenceRequest(ctx, "worker-b", time.Minute, now.Add(time.Second))
		if err != nil || !ok || claimed.ID != domain.ID(id) || claimed.Attempt != 3 || claimed.RecoveryAttempt != 1 || claimed.Phase != DomainConvergenceUnbindRouteRemoved {
			t.Fatalf("compensation claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET lease_until=$2 WHERE id=$1`, id, now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		claimed, ok, err = store.ClaimDomainConvergenceRequest(ctx, "worker-c", time.Minute, now.Add(3*time.Second))
		if err != nil || !ok || claimed.Attempt != 3 || claimed.RecoveryAttempt != 2 || claimed.Phase != DomainConvergenceUnbindRouteRemoved {
			t.Fatalf("expired compensation takeover=%+v ok=%v err=%v", claimed, ok, err)
		}
		laterID := "request_later_" + suffix
		insertLeased(t, laterID, DomainConvergenceQueued, 0, 3)
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET lease_until=$2 WHERE id=$1`, laterID, now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkDomainConvergenceRecoveryRequired(ctx, domain.ID(id), "worker-c", DomainConvergenceUnbindRouteRemoved, "unbind_restore_required", now.Add(4*time.Second)); err != nil {
			t.Fatalf("repeat compensation recovery: %v", err)
		}
		claimed, ok, err = store.ClaimDomainConvergenceRequest(ctx, "worker-later", time.Minute, now.Add(5*time.Second))
		if err != nil || !ok || claimed.ID != domain.ID(laterID) || claimed.Attempt != 1 {
			t.Fatalf("later work starved by compensation: claim=%+v ok=%v err=%v", claimed, ok, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='failed',status='failed',resume_phase=NULL,lease_owner=NULL,lease_until=NULL,last_error='test_cleanup' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ordinary recovery at max attempt terminalizes immediately", func(t *testing.T) {
		id := "request_ordinary_recovery_max_" + suffix
		insertLeased(t, id, DomainConvergenceUnbindRouteRemoved, 3, 3)
		if err := store.MarkDomainConvergenceRecoveryRequired(ctx, domain.ID(id), "worker-a", DomainConvergenceUnbindRouteRemoved, "durable_fact_mismatch", now); err != nil {
			t.Fatal(err)
		}
		request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.Phase != DomainConvergenceFailed || request.Status != DomainConvergenceFailedStatus || request.ResumePhase != "" || request.LastError != "recovery_exhausted" {
			t.Fatalf("ordinary exhausted recovery=%+v err=%v", request, err)
		}
	})

	t.Run("historical exhausted recovery is terminalized by claim sweep", func(t *testing.T) {
		id := "request_historical_recovery_max_" + suffix
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,request_digest,idempotency_key,actor_type,actor_id,phase,status,resume_phase,attempt,max_attempts,payload,last_error,created_at,updated_at) VALUES($1,$2,$3,$4,'unbind',$5,$6,'system','domain-convergence-controller','recovery_required','recovery_required','queued',3,3,'{}'::jsonb,'durable_fact_mismatch',$7,$7)`, id, "domain_"+id, appID.String(), "historical-"+suffix[:12]+".example.test", "sha256:"+strings.Repeat("c", 64), "key-"+id, now); err != nil {
			t.Fatal(err)
		}
		if _, claimed, err := store.ClaimDomainConvergenceRequest(ctx, "worker-sweep", time.Minute, now.Add(time.Second)); err != nil || claimed {
			t.Fatalf("historical exhausted recovery claimed=%v err=%v", claimed, err)
		}
		request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.Phase != DomainConvergenceFailed || request.Status != DomainConvergenceFailedStatus || request.ResumePhase != "" || request.LastError != "recovery_exhausted" {
			t.Fatalf("historical exhausted recovery state=%+v err=%v", request, err)
		}
	})

	t.Run("failure persistence rejects raw provider detail", func(t *testing.T) {
		id := "request_unsafe_error_" + suffix
		insertLeased(t, id, DomainConvergenceQueued, 1, 3)
		if err := store.FailDomainConvergenceRequest(ctx, domain.ID(id), "worker-a", DomainConvergenceQueued, "probe https://user:secret@example.test", now); err == nil {
			t.Fatal("raw convergence error was accepted")
		}
		request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
		if err != nil || request.LastError != "" || request.Status != DomainConvergenceLeased {
			t.Fatalf("raw failure mutated request=%+v err=%v", request, err)
		}
	})

	for _, phase := range []DomainConvergencePhase{
		DomainConvergenceInternalRouteActive,
		DomainConvergenceTLSAllowed,
		DomainConvergenceCertificateObserved,
		DomainConvergenceUnbindRouteRemoved,
	} {
		t.Run("resume "+string(phase), func(t *testing.T) {
			id := "request_resume_" + strings.ReplaceAll(string(phase), "_", "") + "_" + suffix
			insertLeased(t, id, phase, 1, 3)
			if err := store.MarkDomainConvergenceRecoveryRequired(ctx, domain.ID(id), "worker-a", phase, "durable_fact_mismatch", now); err != nil {
				t.Fatalf("mark recovery: %v", err)
			}
			request, err := store.LoadDomainConvergenceRequest(ctx, domain.ID(id))
			if err != nil || request.Phase != DomainConvergenceRecoveryRequired || request.Status != DomainConvergenceRecoveryStatus || request.ResumePhase != phase || request.LeaseUntil != nil {
				t.Fatalf("recovery state=%+v err=%v", request, err)
			}
			claimed, ok, err := store.ClaimDomainConvergenceRequest(ctx, "worker-b", time.Minute, now.Add(time.Second))
			if err != nil || !ok || claimed.ID != domain.ID(id) || claimed.Phase != phase || claimed.ResumePhase != "" || claimed.Status != DomainConvergenceLeased {
				t.Fatalf("resumed claim=%+v ok=%v err=%v", claimed, ok, err)
			}
		})
	}

	t.Run("database rejects invalid status phase combinations", func(t *testing.T) {
		_, err := db.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,request_digest,idempotency_key,actor_type,actor_id,phase,status,attempt,max_attempts,payload,created_at,updated_at) VALUES($1,$2,$3,$4,'unbind',$5,$6,'system','domain-convergence-controller','queued','leased',0,1,'{}'::jsonb,$7,$7)`, "request_invalid_"+suffix, "domain_invalid_"+suffix, appID.String(), "invalid-"+suffix[:12]+".example.test", "sha256:"+strings.Repeat("b", 64), "key-invalid-"+suffix, now)
		if err == nil {
			t.Fatal("invalid queued/leased state was persisted")
		}
	})
}

// TestDomainConvergenceLeaderOnTaskScopedPostgres verifies the session-scoped
// lock with two independent database handles. It changes no schema or durable
// rows and is guarded by the same task-only DSN policy as the other G4B2
// integration tests.
func TestDomainConvergenceLeaderOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_G4B2_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_G4B2_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	validateG4B2UnbindTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dbA, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer dbA.Close()
	dbB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer dbB.Close()
	storeA, storeB := NewStore(dbA), NewStore(dbB)
	first, err := storeA.AcquireDomainConvergenceLeader(ctx)
	if err != nil {
		t.Fatalf("first leader: %v", err)
	}
	defer first.Release(context.Background())
	if second, err := storeB.AcquireDomainConvergenceLeader(ctx); !errors.Is(err, ErrDomainConvergenceLeaderHeld) || second != nil {
		t.Fatalf("second contender lease=%v err=%v", second, err)
	}
	if err := first.Release(ctx); err != nil {
		t.Fatalf("release first leader: %v", err)
	}
	second, err := storeB.AcquireDomainConvergenceLeader(ctx)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := second.Release(cancelled); err != nil {
		t.Fatalf("release with cancelled context: %v", err)
	}
	third, err := storeA.AcquireDomainConvergenceLeader(context.Background())
	if err != nil {
		t.Fatalf("acquire after cancelled release: %v", err)
	}
	if err := third.Release(context.Background()); err != nil {
		t.Fatalf("release third leader: %v", err)
	}
}

type g4b2UnbindFixture struct {
	store         *Store
	applicationID domain.ID
	requestID     domain.ID
	bindingID     domain.ID
	routeID       domain.ID
	certificateID domain.ID
	owner         string
	now           time.Time
}

func newG4B2UnbindFixture(t *testing.T, ctx context.Context, db *sql.DB, shared, platform bool) g4b2UnbindFixture {
	t.Helper()
	resetAuthTestSchema(t, ctx, db)
	applyControlPlaneMigrations(t, ctx, db)
	store := NewStore(db)
	suffix := strings.ReplaceAll(domain.MustNewID("g4b2unbind").String(), "_", "")
	now := time.Now().UTC().Truncate(time.Microsecond)
	app, environment, source := domain.ID("app_"+suffix), domain.ID("env_"+suffix), domain.ID("src_"+suffix)
	definition, release, deployment := domain.ID("def_"+suffix), domain.ID("release_"+suffix), domain.ID("dep_"+suffix)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "g4b2-unbind-" + suffix}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'default')`, []any{environment.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','upload://g4b2',$3,$4,'/tmp/g4b2','prepared',true)`, []any{source.String(), app.String(), suffix, "sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}'::jsonb)`, []any{definition.String(), app.String(), source.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,$4::jsonb)`, []any{release.String(), app.String(), definition.String(), `{"web":"sha256:` + strings.Repeat("b", 64) + `"}`}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy) VALUES($1,$2,$3,'runtime_ready',true)`, []any{deployment.String(), environment.String(), release.String()}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed unbind fixture: %v", err)
		}
	}
	bindingID, routeID, certificateID, leaseID := domain.ID("domain_"+suffix), domain.ID("route_"+suffix), domain.ID("cert_"+suffix), domain.ID("lease_"+suffix)
	verifiedAt := now
	binding := ApplicationDomainRecord{ID: bindingID, ApplicationID: app, Hostname: "unbind-" + suffix[:12] + ".example.test", Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}
	if platform {
		platformID := domain.ID("platform_" + suffix)
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_platform_domains(id,hostname,dns_provider_ref,verification_status,wildcard_enabled,verification_ref,verified_at,created_at,updated_at) VALUES($1,$2,'task-fixture','verified',true,'task-fixture',$3,$3,$3)`, platformID.String(), "example.test", now); err != nil {
			t.Fatal(err)
		}
		slug := "app" + suffix[:12]
		binding = ApplicationDomainRecord{ID: bindingID, ApplicationID: app, PlatformDomainID: platformID, Hostname: slug + ".apps.example.test", Kind: "platform", StableSlug: slug, VerificationMethod: "dns01", VerificationStatus: DomainVerificationVerified, VerificationRef: "task-fixture", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}
	}
	if err := store.UpsertApplicationDomain(ctx, binding, now); err != nil {
		t.Fatalf("seed custom binding: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'web','127.0.0.1',18081,$4)`, leaseID.String(), app.String(), deployment.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_certificate_references(id,application_domain_id,secret_reference_id,subject_hostname,issuer,status,not_before,not_after,created_at,updated_at) VALUES($1,$2,$3,$4,'task-ca','ready',$5,$6,$7,$7)`, certificateID.String(), bindingID.String(), "edge-caddy-observation:sha256:"+strings.Repeat("c", 64), binding.Hostname, now, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,certificate_reference_id,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,'web',$5,'/',$6,'active',true,true,$7,$7)`, routeID.String(), app.String(), bindingID.String(), deployment.String(), binding.Hostname, certificateID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, routeID.String(), deployment.String(), leaseID.String(), now); err != nil {
		t.Fatal(err)
	}
	if shared {
		otherDomain, otherRoute, otherLease := domain.ID("domain_other_"+suffix), domain.ID("route_other_"+suffix), domain.ID("lease_other_"+suffix)
		otherBinding := ApplicationDomainRecord{ID: otherDomain, ApplicationID: app, Hostname: "remaining-" + suffix[:12] + ".example.test", Kind: "custom", VerificationMethod: "cname", VerificationStatus: DomainVerificationVerified, VerificationRef: "ingress.example.test", VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}
		if err := store.UpsertApplicationDomain(ctx, otherBinding, now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_port_leases(id,application_id,deployment_id,service_name,bind_host,port,acquired_at) VALUES($1,$2,$3,'api','127.0.0.1',18082,$4)`, otherLease.String(), app.String(), deployment.String(), now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_desired_routes(id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,certificate_reference_id,desired_state,verified,serving,created_at,updated_at) VALUES($1,$2,$3,$4,'api',$5,'/',$6,'active',true,true,$7,$7)`, otherRoute.String(), app.String(), otherDomain.String(), deployment.String(), otherBinding.Hostname, certificateID.String(), now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, otherRoute.String(), deployment.String(), otherLease.String(), now); err != nil {
			t.Fatal(err)
		}
	}
	intent, _, err := store.BeginDomainUnbind(ctx, app, bindingID, "admin_g4b2", "unbind-"+suffix, now)
	if platform {
		if !errorsIsConvergenceConflict(err) {
			t.Fatalf("platform begin unbind error=%v, want conflict", err)
		}
		return g4b2UnbindFixture{store: store, applicationID: app, bindingID: bindingID, routeID: routeID, certificateID: certificateID, now: now}
	}
	if err != nil {
		t.Fatalf("begin unbind: %v", err)
	}
	owner := "worker-g4b2"
	claimed, ok, err := store.ClaimDomainConvergenceRequest(ctx, owner, time.Minute, now)
	if err != nil || !ok || claimed.ID != intent.Request.ID {
		t.Fatalf("claim unbind: request=%+v ok=%v err=%v", claimed, ok, err)
	}
	work, err := store.LoadDomainUnbindWork(ctx, intent.Request.ID, owner, now)
	if err != nil {
		t.Fatalf("load unbind work: %v", err)
	}
	if err := store.MarkDomainUnbindRouteRemoved(ctx, intent.Request.ID, owner, work.RemainingRouteDigest, work.RemainingRouteCount, now); err != nil {
		t.Fatalf("mark route removed: %v", err)
	}
	return g4b2UnbindFixture{store: store, applicationID: app, requestID: intent.Request.ID, bindingID: bindingID, routeID: routeID, certificateID: certificateID, owner: owner, now: now}
}

func assertG4B2UnbindTargetStillActive(t *testing.T, ctx context.Context, db *sql.DB, fixture g4b2UnbindFixture) {
	t.Helper()
	var bindings int
	var state string
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m3_application_domains WHERE id=$1`, fixture.bindingID.String()).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT desired_state FROM m3_desired_routes WHERE id=$1`, fixture.routeID.String()).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if bindings != 1 || state != "active" {
		t.Fatalf("conflicting unbind changed business facts: binding=%d route=%s", bindings, state)
	}
}

func errorsIsConvergenceConflict(err error) bool { return err == ErrDomainConvergenceConflict }

func validateG4B2UnbindTestDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped G4B2 database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped G4B2 database must be loopback-only")
	}
	if database := strings.TrimPrefix(parsed.EscapedPath(), "/"); !strings.HasPrefix(database, "open_card_g4b2_") {
		t.Fatal("task-scoped G4B2 database name must use open_card_g4b2_ prefix")
	}
}
