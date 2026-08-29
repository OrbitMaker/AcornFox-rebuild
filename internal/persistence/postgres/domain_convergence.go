package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-card/open-card/internal/domain"
)

type DomainConvergenceKind string

const (
	DomainConvergenceConverge DomainConvergenceKind = "converge"
	DomainConvergenceUnbind   DomainConvergenceKind = "unbind"
)

type DomainConvergencePhase string

const (
	DomainConvergenceQueued              DomainConvergencePhase = "queued"
	DomainConvergenceRoutePrepared       DomainConvergencePhase = "route_prepared"
	DomainConvergenceInternalRouteActive DomainConvergencePhase = "internal_route_active"
	DomainConvergenceTLSAllowed          DomainConvergencePhase = "tls_allowed"
	DomainConvergenceCertificateObserved DomainConvergencePhase = "certificate_observed"
	DomainConvergenceServing             DomainConvergencePhase = "serving"
	DomainConvergenceUnbindRouteRemoved  DomainConvergencePhase = "unbind_route_removed"
	DomainConvergenceCompleted           DomainConvergencePhase = "completed"
	DomainConvergenceFailed              DomainConvergencePhase = "failed"
	DomainConvergenceRecoveryRequired    DomainConvergencePhase = "recovery_required"
)

type DomainConvergenceStatus string

const (
	DomainConvergenceQueuedStatus    DomainConvergenceStatus = "queued"
	DomainConvergenceLeased          DomainConvergenceStatus = "leased"
	DomainConvergenceCompletedStatus DomainConvergenceStatus = "completed"
	DomainConvergenceFailedStatus    DomainConvergenceStatus = "failed"
	DomainConvergenceRecoveryStatus  DomainConvergenceStatus = "recovery_required"
)

type DomainConvergenceRequest struct {
	ID                  domain.ID
	ApplicationDomainID domain.ID
	ApplicationID       domain.ID
	Hostname            string
	Kind                DomainConvergenceKind
	TargetDeploymentID  domain.ID
	RequestDigest       string
	IdempotencyKey      string
	ActorType           string
	ActorID             string
	Phase               DomainConvergencePhase
	Status              DomainConvergenceStatus
	ResumePhase         DomainConvergencePhase
	LeaseOwner          string
	LeaseUntil          *time.Time
	Attempt             int
	RecoveryAttempt     int
	MaxAttempts         int
	Payload             json.RawMessage
	Result              json.RawMessage
	LastError           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	CompletedAt         *time.Time
}

const (
	domainConvergenceSystemActorType = "system"
	domainConvergenceSystemActorID   = "domain-convergence-controller"
	domainConvergenceAdminActorType  = "administrator"
)

type DomainConvergenceRuntimeTarget struct {
	ApplicationID  domain.ID
	DeploymentID   domain.ID
	ServiceName    string
	Port           int
	Path           string
	ReleaseVersion int64
	RuntimeDigest  string
}

// domainConvergencePayload is the immutable, complete upstream selected when a
// convergence intent is created.  Every transition reselects the current
// target and compares it to this payload; accepting only deployment_id would
// allow an in-place service, port, release, or runtime-digest change to be
// routed after an external Edge operation has started.
type domainConvergencePayload struct {
	DeploymentID   string `json:"deployment_id"`
	ServiceName    string `json:"service_name"`
	Port           int    `json:"port"`
	Path           string `json:"path"`
	ReleaseVersion int64  `json:"release_version"`
	RuntimeDigest  string `json:"runtime_digest"`
}

type DomainConvergencePreparedRoute struct {
	Request DomainConvergenceRequest
	Route   domain.Route
	Port    int
}

// domainConvergencePreparedSnapshot binds the Caddy operation to the durable
// route facts observed before the provider call.  It is intentionally small,
// public-material-free, and parsed strictly before activation so a Caddy
// success can never commit over a route or pointer that changed meanwhile.
type domainConvergencePreparedSnapshot struct {
	RouteID             string `json:"route_id"`
	RouteUpdatedAt      string `json:"route_updated_at"`
	PointerDeploymentID string `json:"pointer_deployment_id"`
	PointerLeaseID      string `json:"pointer_lease_id"`
	PointerRevision     int64  `json:"pointer_revision"`
}

type DomainConvergenceApplication struct {
	ID   domain.ID
	Name string
}

type DomainConvergenceBinding struct {
	ID            domain.ID
	ApplicationID domain.ID
	Hostname      string
	Kind          string
}

type DomainUnbindIntent struct {
	Request           DomainConvergenceRequest
	FrozenRouteDigest string
	FrozenRouteCount  int
}

// DomainUnbindWork is the leased, immutable route-set snapshot used by the
// unbind worker.  It deliberately contains durable route facts only; the
// worker must rebuild Caddy from RemainingRoutes rather than infer facts from
// a live Caddy configuration.
type DomainUnbindWork struct {
	Request              DomainConvergenceRequest
	Restore              bool
	Binding              ApplicationDomainRecord
	TargetRoutes         []DesiredRouteProjection
	TargetRouteDigest    string
	TargetRouteCount     int
	RemainingRoutes      []DesiredRouteProjection
	RemainingRouteDigest string
	RemainingRouteCount  int
}

// DomainConvergenceActivationRestore is a strict snapshot of the current
// durable active route set. It is used only to compensate an uncertain
// Caddy-success/Activate-CAS outcome; Caddy configuration is never read back
// as product state.
type DomainConvergenceActivationRestore struct {
	Request DomainConvergenceRequest
	Routes  []DesiredRouteProjection
	Digest  string
	Count   int
}

type domainUnbindPayload struct {
	BindingID            string `json:"binding_id"`
	BindingUpdatedAt     string `json:"binding_updated_at"`
	TargetRouteDigest    string `json:"target_route_digest"`
	TargetRouteCount     int    `json:"target_route_count"`
	RemainingRouteDigest string `json:"remaining_route_digest"`
	RemainingRouteCount  int    `json:"remaining_route_count"`
}

// domainUnbindRemovedResult is the only worker result accepted by the final
// custom-domain deletion transaction.  It intentionally repeats neither a
// hostname nor a provider response: the frozen payload remains the authority
// for those facts.
type domainUnbindRemovedResult struct {
	RemainingRouteDigest string `json:"remaining_route_digest"`
	RemainingRouteCount  int    `json:"remaining_route_count"`
}

type DomainConvergenceCertificateObservation struct {
	Fingerprint string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
}

// appendDomainConvergenceAuditTx records only the immutable identity needed to
// prove a completed state transition.  In particular it must never receive a
// convergence payload/result, a certificate body, or a secret reference.
func appendDomainConvergenceAuditTx(ctx context.Context, tx *sql.Tx, request DomainConvergenceRequest, action, fingerprint string, now time.Time) error {
	if request.ActorType != domainConvergenceSystemActorType && request.ActorType != domainConvergenceAdminActorType || strings.TrimSpace(request.ActorID) == "" {
		return domain.ValidationError("domain convergence audit actor is invalid")
	}
	if strings.TrimSpace(fingerprint) != "" && !domainConvergenceFingerprint(fingerprint) {
		return domain.ValidationError("domain convergence audit fingerprint is invalid")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('open-card-audit-evidence-chain',0))`); err != nil {
		return err
	}
	var previous sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	input := request.RequestDigest
	recordInput := previous.String + "\x00" + action + "\x00" + input + "\x00" + now.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(recordInput))
	recordHash := "sha256:" + hex.EncodeToString(sum[:])
	auditID := domain.ID("audit_convergence_" + hex.EncodeToString(sum[:16]))
	refs, err := json.Marshal([]string{
		"request:" + request.ID.String(),
		"application-domain:" + request.ApplicationDomainID.String(),
		"hostname:" + request.Hostname,
		"fingerprint:" + fingerprint,
	})
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,created_at) VALUES($1,$2,$3,$4,'M3 durable domain convergence transition',$5,'recorded',$6::jsonb,$7,$8,$9) ON CONFLICT (id) DO NOTHING`, auditID.String(), request.ActorType, request.ActorID, action, input, []byte(refs), nullableM3String(previous.String), recordHash, now.UTC())
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || (rows != 0 && rows != 1) {
		if err != nil {
			return err
		}
		return ErrDomainConvergenceConflict
	}
	return nil
}

type DomainConvergenceServingFact struct {
	Request         DomainConvergenceRequest
	RouteID         domain.ID
	RouteState      DesiredRouteState
	Serving         bool
	Pointer         *RoutePointer
	CertificateID   domain.ID
	OpaqueReference string
}

type DomainConvergenceServingFactState string

const (
	DomainConvergenceNotServing      DomainConvergenceServingFactState = "not_serving"
	DomainConvergenceMatchingServing DomainConvergenceServingFactState = "matching_serving"
	DomainConvergenceRenewalPending  DomainConvergenceServingFactState = "renewal_pending"
)

type domainConvergenceLockedRoute struct {
	ID                   domain.ID
	ApplicationID        domain.ID
	ApplicationDomainID  domain.ID
	DeploymentID         domain.ID
	ServiceName          string
	Hostname             string
	Path                 string
	State                DesiredRouteState
	Verified             bool
	Serving              bool
	CertificateReference domain.ID
	UpdatedAt            time.Time
	Pointer              RoutePointer
	Lease                PortLease
}

func (s *Store) InspectDomainConvergenceServingFact(ctx context.Context, id domain.ID, owner, expectedFingerprint string, now time.Time) (DomainConvergenceServingFactState, error) {
	if err := s.requireDB(); err != nil {
		return "", err
	}
	if !domainConvergenceFingerprint(expectedFingerprint) {
		return "", domain.ValidationError("domain convergence fingerprint is invalid")
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	fail := func(e error) (DomainConvergenceServingFactState, error) {
		return "", rollbackTx(tx, e)
	}
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if !domainConvergenceLeaseMatches(request, owner, now) || request.Phase != DomainConvergenceCertificateObserved {
		return fail(ErrDomainConvergenceConflict)
	}
	_, route, err := s.lockDomainConvergenceRouteTx(ctx, tx, request, now)
	if err != nil {
		return fail(err)
	}
	if !route.Serving && route.CertificateReference.Empty() {
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return DomainConvergenceNotServing, nil
	}
	if !route.Serving || route.CertificateReference.Empty() {
		return fail(ErrDomainConvergenceConflict)
	}
	reference, err := lockDomainConvergenceCertificateReferenceTx(ctx, tx, route.CertificateReference)
	if err != nil || reference.applicationDomainID != request.ApplicationDomainID || reference.hostname != request.Hostname {
		return fail(ErrDomainConvergenceConflict)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if reference.opaque != "edge-caddy-observation:"+expectedFingerprint {
		return DomainConvergenceRenewalPending, nil
	}
	return DomainConvergenceMatchingServing, nil
}

func (s *Store) LoadDomainConvergenceServingFact(ctx context.Context, id domain.ID) (DomainConvergenceServingFact, error) {
	request, err := s.LoadDomainConvergenceRequest(ctx, id)
	if err != nil {
		return DomainConvergenceServingFact{}, err
	}
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return DomainConvergenceServingFact{}, ErrDomainConvergenceConflict
	}
	current, err := s.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(current, frozen) {
		return DomainConvergenceServingFact{}, ErrDomainConvergenceConflict
	}
	fact := DomainConvergenceServingFact{Request: request}
	var route, cert, pointer, deploy, lease, opaque sql.NullString
	var state sql.NullString
	var serving sql.NullBool
	routeID := DomainConvergenceRouteID(request.ApplicationDomainID)
	err = s.db.QueryRowContext(ctx, `SELECT r.id,r.desired_state,r.serving,r.certificate_reference_id,p.deployment_id,p.port_lease_id,c.secret_reference_id FROM m3_desired_routes r LEFT JOIN m3_route_pointers p ON p.route_id=r.id LEFT JOIN m3_certificate_references c ON c.id=r.certificate_reference_id WHERE r.id=$1 AND r.application_domain_id=$2 AND r.deployment_id=$3 AND r.service_name=$4 AND r.path_prefix=$5`, routeID.String(), request.ApplicationDomainID.String(), frozen.DeploymentID.String(), frozen.ServiceName, frozen.Path).Scan(&route, &state, &serving, &cert, &deploy, &lease, &opaque)
	if errors.Is(err, sql.ErrNoRows) {
		return fact, nil
	}
	if err != nil {
		return DomainConvergenceServingFact{}, err
	}
	fact.RouteID = domain.ID(route.String)
	fact.RouteState = DesiredRouteState(state.String)
	fact.Serving = serving.Bool
	fact.CertificateID = domain.ID(cert.String)
	fact.OpaqueReference = opaque.String
	if pointer.Valid && deploy.Valid && lease.Valid {
		fact.Pointer = &RoutePointer{RouteID: fact.RouteID, DeploymentID: domain.ID(deploy.String), PortLeaseID: domain.ID(lease.String)}
	}
	return fact, nil
}

func (s *Store) RecoverDomainConvergenceCompleted(ctx context.Context, id domain.ID, owner string, now time.Time) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	fail := func(e error) (bool, error) { return false, rollbackTx(tx, e) }
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if request.Phase != DomainConvergenceServing {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if !domainConvergenceLeaseMatches(request, owner, now) {
		return fail(ErrDomainConvergenceConflict)
	}
	fingerprint, err := parseDomainConvergenceServingResult(request.Result)
	if err != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	_, route, err := s.lockDomainConvergenceRouteTx(ctx, tx, request, now)
	if err != nil || !route.Serving || route.CertificateReference.Empty() {
		return fail(ErrDomainConvergenceConflict)
	}
	reference, err := lockDomainConvergenceCertificateReferenceTx(ctx, tx, route.CertificateReference)
	if err != nil || reference.applicationDomainID != request.ApplicationDomainID || reference.hostname != request.Hostname || reference.opaque != "edge-caddy-observation:"+fingerprint {
		return fail(ErrDomainConvergenceConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='completed',status='completed',result=$1,resume_phase=NULL,lease_owner=NULL,lease_until=NULL,updated_at=$2,completed_at=$2 WHERE id=$3 AND status='leased' AND lease_owner=$4 AND lease_until >= $2 AND phase='serving'`, []byte(`{"status":"completed"}`), now, id.String(), owner)
	if err != nil {
		return fail(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

type domainConvergenceCertificateReference struct {
	id                  domain.ID
	applicationDomainID domain.ID
	hostname            string
	opaque              string
}

func domainConvergenceLeaseMatches(request DomainConvergenceRequest, owner string, now time.Time) bool {
	return request.Status == DomainConvergenceLeased && request.LeaseOwner == strings.TrimSpace(owner) && request.LeaseUntil != nil && !request.LeaseUntil.Before(now)
}

func domainConvergenceFingerprint(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, value := range value[len("sha256:"):] {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}

func domainConvergenceSafeCode(value string) bool {
	if len(value) < 1 || len(value) > 120 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' || char == ':' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func domainConvergenceCompensationCode(code string) bool {
	switch code {
	case "route_activation_restore_required", "unbind_restore_required", "unbind_restore_retry":
		return true
	default:
		return false
	}
}

func domainConvergenceRequestDigest(applicationDomainID domain.ID, target DomainConvergenceRuntimeTarget) string {
	sum := sha256.Sum256([]byte("g4b2-converge\x00" + applicationDomainID.String() + "\x00" + target.DeploymentID.String() + "\x00" + target.ServiceName + "\x00" + fmt.Sprintf("%d", target.Port) + "\x00" + target.Path + "\x00" + fmt.Sprintf("%d", target.ReleaseVersion) + "\x00" + target.RuntimeDigest))
	return fmt.Sprintf("sha256:%x", sum[:])
}

func domainConvergenceTargetValid(target DomainConvergenceRuntimeTarget) bool {
	return !target.ApplicationID.Empty() && !target.DeploymentID.Empty() && strings.TrimSpace(target.ServiceName) != "" && target.Port >= 1 && target.Port <= 65535 && target.Path == "/" && target.ReleaseVersion > 0 && domainConvergenceFingerprint(target.RuntimeDigest)
}

func domainConvergenceTargetEqual(left, right DomainConvergenceRuntimeTarget) bool {
	return left.ApplicationID == right.ApplicationID && left.DeploymentID == right.DeploymentID && left.ServiceName == right.ServiceName && left.Port == right.Port && left.Path == right.Path && left.ReleaseVersion == right.ReleaseVersion && left.RuntimeDigest == right.RuntimeDigest
}

func domainConvergencePayloadForTarget(target DomainConvergenceRuntimeTarget) (json.RawMessage, error) {
	if !domainConvergenceTargetValid(target) {
		return nil, domain.ValidationError("domain convergence frozen target is invalid")
	}
	return json.Marshal(domainConvergencePayload{DeploymentID: target.DeploymentID.String(), ServiceName: target.ServiceName, Port: target.Port, Path: target.Path, ReleaseVersion: target.ReleaseVersion, RuntimeDigest: target.RuntimeDigest})
}

func parseDomainConvergencePayload(value json.RawMessage, applicationID domain.ID) (DomainConvergenceRuntimeTarget, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(value, &raw) != nil || len(raw) != 6 {
		return DomainConvergenceRuntimeTarget{}, domain.ValidationError("domain convergence frozen target is invalid")
	}
	for _, key := range []string{"deployment_id", "service_name", "port", "path", "release_version", "runtime_digest"} {
		if _, ok := raw[key]; !ok {
			return DomainConvergenceRuntimeTarget{}, domain.ValidationError("domain convergence frozen target is invalid")
		}
	}
	var payload domainConvergencePayload
	if json.Unmarshal(value, &payload) != nil {
		return DomainConvergenceRuntimeTarget{}, domain.ValidationError("domain convergence frozen target is invalid")
	}
	target := DomainConvergenceRuntimeTarget{ApplicationID: applicationID, DeploymentID: domain.ID(payload.DeploymentID), ServiceName: payload.ServiceName, Port: payload.Port, Path: payload.Path, ReleaseVersion: payload.ReleaseVersion, RuntimeDigest: payload.RuntimeDigest}
	if domain.RequireID(target.DeploymentID, "domain convergence frozen deployment id") != nil || !domainConvergenceTargetValid(target) {
		return DomainConvergenceRuntimeTarget{}, domain.ValidationError("domain convergence frozen target is invalid")
	}
	return target, nil
}

func domainConvergenceFrozenTarget(request DomainConvergenceRequest) (DomainConvergenceRuntimeTarget, error) {
	if request.Kind != DomainConvergenceConverge || request.TargetDeploymentID.Empty() {
		return DomainConvergenceRuntimeTarget{}, ErrDomainConvergenceConflict
	}
	target, err := parseDomainConvergencePayload(request.Payload, request.ApplicationID)
	if err != nil || target.DeploymentID != request.TargetDeploymentID || request.RequestDigest != domainConvergenceRequestDigest(request.ApplicationDomainID, target) {
		return DomainConvergenceRuntimeTarget{}, ErrDomainConvergenceConflict
	}
	return target, nil
}

// DomainConvergenceRouteID is stable for the lifetime of one application
// domain's only supported convergence path.  Deployment, service and port are
// deliberately absent: M4 and B2 must cut over the same route/pointer row.
func DomainConvergenceRouteID(applicationDomainID domain.ID) domain.ID {
	sum := sha256.Sum256([]byte("domain-convergence:" + applicationDomainID.String() + ":/"))
	return domain.ID(fmt.Sprintf("route_%x", sum[:16]))
}

func parseDomainConvergencePreparedSnapshot(raw json.RawMessage) (domainConvergencePreparedSnapshot, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 5 {
		return domainConvergencePreparedSnapshot{}, domain.ValidationError("domain convergence prepared snapshot is invalid")
	}
	for _, key := range []string{"route_id", "route_updated_at", "pointer_deployment_id", "pointer_lease_id", "pointer_revision"} {
		if _, found := fields[key]; !found {
			return domainConvergencePreparedSnapshot{}, domain.ValidationError("domain convergence prepared snapshot is invalid")
		}
	}
	var snapshot domainConvergencePreparedSnapshot
	if json.Unmarshal(raw, &snapshot) != nil || domain.RequireID(domain.ID(snapshot.RouteID), "domain convergence prepared route id") != nil {
		return domainConvergencePreparedSnapshot{}, domain.ValidationError("domain convergence prepared snapshot is invalid")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, snapshot.RouteUpdatedAt)
	if err != nil || updatedAt.IsZero() || updatedAt.UTC().Format(time.RFC3339Nano) != snapshot.RouteUpdatedAt {
		return domainConvergencePreparedSnapshot{}, domain.ValidationError("domain convergence prepared snapshot is invalid")
	}
	if snapshot.PointerDeploymentID == "" || snapshot.PointerLeaseID == "" {
		if snapshot.PointerDeploymentID != "" || snapshot.PointerLeaseID != "" || snapshot.PointerRevision != 0 {
			return domainConvergencePreparedSnapshot{}, domain.ValidationError("domain convergence prepared snapshot is invalid")
		}
		return snapshot, nil
	}
	if domain.RequireID(domain.ID(snapshot.PointerDeploymentID), "domain convergence prepared pointer deployment") != nil || domain.RequireID(domain.ID(snapshot.PointerLeaseID), "domain convergence prepared pointer lease") != nil || snapshot.PointerRevision < 1 {
		return domainConvergencePreparedSnapshot{}, domain.ValidationError("domain convergence prepared snapshot is invalid")
	}
	return snapshot, nil
}

func domainConvergencePreparedSnapshotJSON(snapshot domainConvergencePreparedSnapshot) (json.RawMessage, error) {
	value, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if _, err := parseDomainConvergencePreparedSnapshot(value); err != nil {
		return nil, err
	}
	return value, nil
}

func parseDomainConvergenceServingResult(raw json.RawMessage) (string, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != 2 {
		return "", domain.ValidationError("domain convergence serving result is invalid")
	}
	if _, ok := object["fingerprint"]; !ok {
		return "", domain.ValidationError("domain convergence serving result is invalid")
	}
	if _, ok := object["status"]; !ok {
		return "", domain.ValidationError("domain convergence serving result is invalid")
	}
	var result struct {
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
	}
	if json.Unmarshal(raw, &result) != nil || !domainConvergenceFingerprint(result.Fingerprint) || result.Status != "observed" {
		return "", domain.ValidationError("domain convergence serving result is invalid")
	}
	return result.Fingerprint, nil
}

func loadDomainConvergenceRequestForUpdate(ctx context.Context, tx *sql.Tx, id domain.ID) (DomainConvergenceRequest, error) {
	var request DomainConvergenceRequest
	found, err := scanDomainConvergenceRequestWithActor(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE id=$1 FOR UPDATE`, id.String()), &request)
	if err != nil {
		return DomainConvergenceRequest{}, err
	}
	if !found {
		return DomainConvergenceRequest{}, ErrDomainConvergenceConflict
	}
	return request, nil
}

// lockDomainConvergenceRouteTx locks all mutable durable facts which bind a
// convergence request to its upstream. Provider calls deliberately occur
// before this function is entered; callers get one short, all-or-nothing CAS
// transaction for the durable observation.
func (s *Store) lockDomainConvergenceRouteTx(ctx context.Context, tx *sql.Tx, request DomainConvergenceRequest, now time.Time) (DomainConvergenceRuntimeTarget, domainConvergenceLockedRoute, error) {
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	target, err := s.selectDomainConvergenceRuntimeTargetTx(ctx, tx, request.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(target, frozen) {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	var deployment, application string
	if err := tx.QueryRowContext(ctx, `SELECT d.id,e.application_id FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1 FOR UPDATE OF d`, target.DeploymentID.String()).Scan(&deployment, &application); err != nil || deployment != target.DeploymentID.String() || application != request.ApplicationID.String() {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	routeID := DomainConvergenceRouteID(request.ApplicationDomainID)
	var route domainConvergenceLockedRoute
	var certificate sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving,certificate_reference_id,updated_at FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, routeID.String()).Scan(&route.ID, &route.ApplicationID, &route.ApplicationDomainID, &route.DeploymentID, &route.ServiceName, &route.Hostname, &route.Path, &route.State, &route.Verified, &route.Serving, &certificate, &route.UpdatedAt); err != nil {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	route.UpdatedAt = route.UpdatedAt.UTC()
	route.CertificateReference = domain.ID(certificate.String)
	if route.ApplicationID != request.ApplicationID || route.ApplicationDomainID != request.ApplicationDomainID || route.DeploymentID != target.DeploymentID || route.ServiceName != target.ServiceName || route.Hostname != request.Hostname || route.Path != "/" || route.State != DesiredRouteActive || !route.Verified {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	if err := tx.QueryRowContext(ctx, `SELECT route_id,deployment_id,port_lease_id,revision,updated_at FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, routeID.String()).Scan(&route.Pointer.RouteID, &route.Pointer.DeploymentID, &route.Pointer.PortLeaseID, &route.Pointer.Revision, &route.Pointer.UpdatedAt); err != nil {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	route.Pointer.UpdatedAt = route.Pointer.UpdatedAt.UTC()
	expectedLeaseID, err := findTLSAllowLeaseIDTx(ctx, tx, request.ApplicationID, target.DeploymentID, target.ServiceName, target.Port)
	if err != nil {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	if route.Pointer.RouteID != routeID || route.Pointer.DeploymentID != target.DeploymentID || route.Pointer.PortLeaseID != expectedLeaseID || route.Pointer.Revision < 1 {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	var expires, released sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT id,application_id,deployment_id,service_name,bind_host,port,acquired_at,expires_at,released_at FROM m3_port_leases WHERE id=$1 FOR UPDATE`, expectedLeaseID.String()).Scan(&route.Lease.ID, &route.Lease.ApplicationID, &route.Lease.DeploymentID, &route.Lease.ServiceName, &route.Lease.BindHost, &route.Lease.Port, &route.Lease.AcquiredAt, &expires, &released); err != nil {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	route.Lease.AcquiredAt = route.Lease.AcquiredAt.UTC()
	if expires.Valid {
		value := expires.Time.UTC()
		route.Lease.ExpiresAt = &value
	}
	if released.Valid {
		value := released.Time.UTC()
		route.Lease.ReleasedAt = &value
	}
	if route.Lease.ApplicationID != request.ApplicationID || route.Lease.DeploymentID != target.DeploymentID || route.Lease.ServiceName != target.ServiceName || route.Lease.BindHost != "127.0.0.1" || route.Lease.Port != target.Port || route.Lease.ReleasedAt != nil || (route.Lease.ExpiresAt != nil && !route.Lease.ExpiresAt.After(now)) {
		return DomainConvergenceRuntimeTarget{}, domainConvergenceLockedRoute{}, ErrDomainConvergenceConflict
	}
	return target, route, nil
}

func lockDomainConvergenceCertificateReferenceTx(ctx context.Context, tx *sql.Tx, id domain.ID) (domainConvergenceCertificateReference, error) {
	var value domainConvergenceCertificateReference
	if err := tx.QueryRowContext(ctx, `SELECT id,application_domain_id,subject_hostname,secret_reference_id FROM m3_certificate_references WHERE id=$1 FOR UPDATE`, id.String()).Scan(&value.id, &value.applicationDomainID, &value.hostname, &value.opaque); err != nil {
		return domainConvergenceCertificateReference{}, ErrDomainConvergenceConflict
	}
	return value, nil
}

func lockDomainConvergenceCertificateForHostnameTx(ctx context.Context, tx *sql.Tx, applicationDomainID domain.ID, hostname string) (domainConvergenceCertificateReference, bool, error) {
	var value domainConvergenceCertificateReference
	err := tx.QueryRowContext(ctx, `SELECT id,application_domain_id,subject_hostname,secret_reference_id FROM m3_certificate_references WHERE application_domain_id=$1 AND subject_hostname=$2 FOR UPDATE`, applicationDomainID.String(), hostname).Scan(&value.id, &value.applicationDomainID, &value.hostname, &value.opaque)
	if errors.Is(err, sql.ErrNoRows) {
		return domainConvergenceCertificateReference{}, false, nil
	}
	if err != nil {
		return domainConvergenceCertificateReference{}, false, err
	}
	return value, true, nil
}

func (o DomainConvergenceCertificateObservation) PublicResult(hostname string, status int) (json.RawMessage, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	host, err := NormalizeM3Hostname(hostname)
	if err != nil {
		return nil, err
	}
	if status < 100 || status >= 500 {
		return nil, domain.ValidationError("domain convergence probe HTTP status is invalid")
	}
	return json.RawMessage(fmt.Sprintf(`{"fingerprint":%q,"hostname":%q,"issuer":%q,"not_before":%q,"not_after":%q,"status":%d}`, o.Fingerprint, host, o.Issuer, o.NotBefore.UTC().Format(time.RFC3339Nano), o.NotAfter.UTC().Format(time.RFC3339Nano), status)), nil
}

func (s *Store) RecordDomainConvergenceCertificateObservation(ctx context.Context, id domain.ID, owner string, observation DomainConvergenceCertificateObservation, status int, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if !domainConvergenceObservationValidAt(observation, now) {
		return domain.ValidationError("domain convergence certificate observation is not currently valid")
	}
	request, err := s.LoadDomainConvergenceRequest(ctx, id)
	if err != nil {
		return err
	}
	if request.Status != DomainConvergenceLeased || request.LeaseOwner != owner || request.LeaseUntil == nil || request.LeaseUntil.Before(now) || request.Phase != DomainConvergenceTLSAllowed {
		return ErrDomainConvergenceConflict
	}
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return ErrDomainConvergenceConflict
	}
	current, err := s.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(current, frozen) {
		return ErrDomainConvergenceConflict
	}
	result, err := observation.PublicResult(request.Hostname, status)
	if err != nil {
		return err
	}
	return s.AdvanceDomainConvergenceRequest(ctx, id, owner, DomainConvergenceTLSAllowed, DomainConvergenceCertificateObserved, DomainConvergenceLeased, result, now)
}

func (s *Store) LoadDomainConvergenceCertificateObservation(ctx context.Context, id domain.ID, owner string, now time.Time) (DomainConvergenceCertificateObservation, error) {
	now = m3Now(s, now)
	request, err := s.LoadDomainConvergenceRequest(ctx, id)
	if err != nil {
		return DomainConvergenceCertificateObservation{}, err
	}
	if request.Status != DomainConvergenceLeased || request.LeaseOwner != owner || request.LeaseUntil == nil || request.LeaseUntil.Before(now) || request.Phase != DomainConvergenceCertificateObserved {
		return DomainConvergenceCertificateObservation{}, ErrDomainConvergenceConflict
	}
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return DomainConvergenceCertificateObservation{}, ErrDomainConvergenceConflict
	}
	target, err := s.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(target, frozen) {
		return DomainConvergenceCertificateObservation{}, ErrDomainConvergenceConflict
	}
	value, _, err := parseDomainConvergenceCertificateObservationResult(request.Result, request.Hostname)
	if err != nil {
		return DomainConvergenceCertificateObservation{}, err
	}
	if !domainConvergenceObservationValidAt(value, now) {
		return DomainConvergenceCertificateObservation{}, ErrDomainConvergenceConflict
	}
	return value, nil
}

func parseDomainConvergenceCertificateObservationResult(raw json.RawMessage, hostname string) (DomainConvergenceCertificateObservation, int, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != 6 {
		return DomainConvergenceCertificateObservation{}, 0, domain.ValidationError("stored certificate observation is invalid")
	}
	for _, key := range []string{"fingerprint", "hostname", "issuer", "not_before", "not_after", "status"} {
		if _, ok := object[key]; !ok {
			return DomainConvergenceCertificateObservation{}, 0, domain.ValidationError("stored certificate observation is invalid")
		}
	}
	var decoded struct {
		Fingerprint string `json:"fingerprint"`
		Hostname    string `json:"hostname"`
		Issuer      string `json:"issuer"`
		NotBefore   string `json:"not_before"`
		NotAfter    string `json:"not_after"`
		Status      int    `json:"status"`
	}
	if json.Unmarshal(raw, &decoded) != nil || decoded.Hostname != hostname || decoded.Status < 100 || decoded.Status >= 500 || !domainConvergenceFingerprint(decoded.Fingerprint) {
		return DomainConvergenceCertificateObservation{}, 0, domain.ValidationError("stored certificate observation is invalid")
	}
	before, beforeErr := time.Parse(time.RFC3339Nano, decoded.NotBefore)
	after, afterErr := time.Parse(time.RFC3339Nano, decoded.NotAfter)
	value := DomainConvergenceCertificateObservation{Fingerprint: decoded.Fingerprint, Issuer: decoded.Issuer, NotBefore: before.UTC(), NotAfter: after.UTC()}
	if beforeErr != nil || afterErr != nil || value.Validate() != nil {
		return DomainConvergenceCertificateObservation{}, 0, domain.ValidationError("stored certificate observation is invalid")
	}
	return value, decoded.Status, nil
}

func domainConvergencePublicIssuer(value string) bool {
	if len(value) < 1 || len(value) > 200 || strings.TrimSpace(value) != value {
		return false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "begin certificate") || strings.Contains(lower, "private key") || strings.Contains(value, "-----") {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func (o DomainConvergenceCertificateObservation) Validate() error {
	if !domainConvergenceFingerprint(o.Fingerprint) || o.NotBefore.IsZero() || !o.NotAfter.After(o.NotBefore) || !domainConvergencePublicIssuer(o.Issuer) {
		return domain.ValidationError("domain convergence certificate observation is invalid")
	}
	return nil
}

func domainConvergenceObservationValidAt(observation DomainConvergenceCertificateObservation, now time.Time) bool {
	return observation.Validate() == nil && !now.Before(observation.NotBefore.UTC()) && now.Before(observation.NotAfter.UTC())
}

var (
	ErrDomainConvergenceConflict   = errors.New("domain convergence request conflict")
	ErrDomainConvergenceLeaderHeld = errors.New("domain convergence leader is already held")
)

const domainConvergenceLeaderLockName = "open-card:m3-domain-convergence:v1"

// DomainConvergenceLeaderLease holds a PostgreSQL session advisory lock on a
// dedicated connection.  It is deliberately not a transaction lock: the
// production worker must call Caddy and the probe outside database
// transactions, but only one process may own the convergence loop at a time.
type DomainConvergenceLeaderLease struct {
	conn *sql.Conn

	once       sync.Once
	releaseErr error
}

// Release is idempotent. Closing the dedicated connection is a second,
// PostgreSQL-enforced release mechanism if an unlock round-trip cannot finish
// (for example because the caller's lifecycle context has already been
// cancelled).
func (l *DomainConvergenceLeaderLease) Release(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.conn == nil {
			return
		}
		releaseCtx := ctx
		var cancel context.CancelFunc
		if releaseCtx == nil || releaseCtx.Err() != nil {
			releaseCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		var unlocked bool
		err := l.conn.QueryRowContext(releaseCtx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, domainConvergenceLeaderLockName).Scan(&unlocked)
		if err != nil {
			l.releaseErr = fmt.Errorf("release domain convergence leader: %w", err)
		} else if !unlocked {
			l.releaseErr = errors.New("release domain convergence leader: advisory lock was not owned")
		}
		if closeErr := l.conn.Close(); closeErr != nil && l.releaseErr == nil {
			l.releaseErr = fmt.Errorf("close domain convergence leader connection: %w", closeErr)
		}
		l.conn = nil
	})
	return l.releaseErr
}

// AcquireDomainConvergenceLeader establishes a session-scoped advisory lock
// on a dedicated connection. A false pg_try_advisory_lock result is explicit
// contention, not a standby mode: production startup must remain not-ready.
func (s *Store) AcquireDomainConvergenceLeader(ctx context.Context) (*DomainConvergenceLeaderLease, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, domain.ValidationError("domain convergence leader context is required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open domain convergence leader connection: %w", err)
	}
	closeWith := func(cause error) (*DomainConvergenceLeaderLease, error) {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w; close domain convergence leader connection: %v", cause, closeErr)
		}
		return nil, cause
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, domainConvergenceLeaderLockName).Scan(&acquired); err != nil {
		return closeWith(fmt.Errorf("acquire domain convergence leader: %w", err))
	}
	if !acquired {
		return closeWith(ErrDomainConvergenceLeaderHeld)
	}
	return &DomainConvergenceLeaderLease{conn: conn}, nil
}

func (r DomainConvergenceRequest) Validate() error {
	if err := domain.RequireID(r.ID, "domain convergence request id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.ApplicationDomainID, "domain convergence application domain id"); err != nil {
		return err
	}
	if err := domain.RequireID(r.ApplicationID, "domain convergence application id"); err != nil {
		return err
	}
	if r.Kind != DomainConvergenceConverge && r.Kind != DomainConvergenceUnbind {
		return domain.ValidationError("domain convergence request kind is unsupported")
	}
	if r.Kind == DomainConvergenceConverge {
		if err := domain.RequireID(r.TargetDeploymentID, "domain convergence target deployment id"); err != nil {
			return err
		}
		frozen, err := parseDomainConvergencePayload(r.Payload, r.ApplicationID)
		if err != nil || frozen.DeploymentID != r.TargetDeploymentID || r.RequestDigest != domainConvergenceRequestDigest(r.ApplicationDomainID, frozen) {
			return domain.ValidationError("domain convergence frozen target is invalid")
		}
	} else if !r.TargetDeploymentID.Empty() {
		return domain.ValidationError("unbind convergence request cannot select a target deployment")
	}
	host, err := NormalizeM3Hostname(r.Hostname)
	if err != nil || host != r.Hostname {
		if err != nil {
			return err
		}
		return domain.ValidationError("domain convergence hostname must be normalized")
	}
	if len(r.RequestDigest) != len("sha256:")+64 || !strings.HasPrefix(r.RequestDigest, "sha256:") {
		return domain.ValidationError("domain convergence request digest is invalid")
	}
	if strings.TrimSpace(r.IdempotencyKey) == "" || len(r.IdempotencyKey) > 200 {
		return domain.ValidationError("domain convergence idempotency key is required")
	}
	if (r.ActorType != domainConvergenceSystemActorType && r.ActorType != domainConvergenceAdminActorType) || strings.TrimSpace(r.ActorID) == "" || len(r.ActorID) > 200 {
		return domain.ValidationError("domain convergence request actor is invalid")
	}
	if !domainConvergencePhase(r.Phase) || !domainConvergenceStatus(r.Status) {
		return domain.ValidationError("domain convergence phase or status is unsupported")
	}
	if r.MaxAttempts < 1 || r.MaxAttempts > 100 || r.Attempt < 0 || r.Attempt > r.MaxAttempts || r.RecoveryAttempt < 0 {
		return domain.ValidationError("domain convergence attempt bounds are invalid")
	}
	if (r.LeaseUntil == nil) != (strings.TrimSpace(r.LeaseOwner) == "") {
		return domain.ValidationError("domain convergence lease owner and expiry must agree")
	}
	if r.ResumePhase != "" && !domainConvergenceExecutablePhase(r.ResumePhase) {
		return domain.ValidationError("domain convergence resume phase is invalid")
	}
	switch r.Status {
	case DomainConvergenceQueuedStatus:
		if !domainConvergenceExecutablePhase(r.Phase) || r.LeaseUntil != nil || r.ResumePhase != "" || r.CompletedAt != nil {
			return domain.ValidationError("queued domain convergence state is invalid")
		}
	case DomainConvergenceLeased:
		if !domainConvergenceExecutablePhase(r.Phase) || r.LeaseUntil == nil || r.ResumePhase != "" || r.CompletedAt != nil {
			return domain.ValidationError("leased domain convergence state is invalid")
		}
	case DomainConvergenceRecoveryStatus:
		if r.Phase != DomainConvergenceRecoveryRequired || r.LeaseUntil != nil || !domainConvergenceExecutablePhase(r.ResumePhase) || r.CompletedAt != nil {
			return domain.ValidationError("recovery-required domain convergence state is invalid")
		}
	case DomainConvergenceCompletedStatus:
		if r.Phase != DomainConvergenceCompleted || r.LeaseUntil != nil || r.ResumePhase != "" || r.CompletedAt == nil {
			return domain.ValidationError("completed domain convergence state is invalid")
		}
	case DomainConvergenceFailedStatus:
		if r.Phase != DomainConvergenceFailed || r.LeaseUntil != nil || r.ResumePhase != "" || r.CompletedAt != nil {
			return domain.ValidationError("failed domain convergence state is invalid")
		}
	}
	if err := validateConvergenceJSON("payload", r.Payload, false); err != nil {
		return err
	}
	return validateConvergenceJSON("result", r.Result, true)
}

func domainConvergencePhase(value DomainConvergencePhase) bool {
	switch value {
	case DomainConvergenceQueued, DomainConvergenceRoutePrepared, DomainConvergenceInternalRouteActive, DomainConvergenceTLSAllowed, DomainConvergenceCertificateObserved, DomainConvergenceServing, DomainConvergenceUnbindRouteRemoved, DomainConvergenceCompleted, DomainConvergenceFailed, DomainConvergenceRecoveryRequired:
		return true
	default:
		return false
	}
}

func domainConvergenceStatus(value DomainConvergenceStatus) bool {
	return value == DomainConvergenceQueuedStatus || value == DomainConvergenceLeased || value == DomainConvergenceCompletedStatus || value == DomainConvergenceFailedStatus || value == DomainConvergenceRecoveryStatus
}

func domainConvergenceExecutablePhase(value DomainConvergencePhase) bool {
	switch value {
	case DomainConvergenceQueued, DomainConvergenceRoutePrepared, DomainConvergenceInternalRouteActive, DomainConvergenceTLSAllowed, DomainConvergenceCertificateObserved, DomainConvergenceServing, DomainConvergenceUnbindRouteRemoved:
		return true
	default:
		return false
	}
}

func validateConvergenceJSON(label string, value json.RawMessage, nullable bool) error {
	if len(value) == 0 || string(value) == "null" {
		if nullable {
			return nil
		}
		return domain.ValidationError("domain convergence " + label + " is required")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return domain.ValidationError("domain convergence " + label + " must be an object")
	}
	for key := range object {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "private") || strings.Contains(lower, "certificate") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "pem") {
			return domain.ValidationError("domain convergence " + label + " contains a sensitive field")
		}
	}
	return nil
}

func (s *Store) CreateDomainConvergenceRequest(ctx context.Context, request DomainConvergenceRequest, now time.Time) (DomainConvergenceRequest, bool, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	now = m3Now(s, now)
	if request.Phase == "" {
		request.Phase = DomainConvergenceQueued
	}
	if request.Status == "" {
		request.Status = DomainConvergenceQueuedStatus
	}
	if request.MaxAttempts == 0 {
		request.MaxAttempts = 20
	}
	if len(request.Payload) == 0 {
		request.Payload = json.RawMessage(`{}`)
	}
	request.Hostname = strings.ToLower(strings.TrimSpace(request.Hostname))
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.ActorType = strings.TrimSpace(request.ActorType)
	request.ActorID = strings.TrimSpace(request.ActorID)
	if request.ActorType == "" && request.ActorID == "" {
		request.ActorType, request.ActorID = domainConvergenceSystemActorType, domainConvergenceSystemActorID
	}
	if err := request.Validate(); err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	rollback := func(cause error) (DomainConvergenceRequest, bool, error) {
		return DomainConvergenceRequest{}, false, rollbackTx(tx, cause)
	}
	inserted, err := tx.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,target_deployment_id,request_digest,idempotency_key,actor_type,actor_id,phase,status,attempt,recovery_attempt,max_attempts,payload,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,0,0,$13,$14,$15,$15) ON CONFLICT(request_kind,idempotency_key) DO NOTHING`, request.ID.String(), request.ApplicationDomainID.String(), request.ApplicationID.String(), request.Hostname, request.Kind, nullableM3ID(request.TargetDeploymentID), request.RequestDigest, request.IdempotencyKey, request.ActorType, request.ActorID, request.Phase, request.Status, request.MaxAttempts, []byte(request.Payload), now)
	if err != nil {
		return rollback(fmt.Errorf("create domain convergence request: %w", err))
	}
	rows, err := inserted.RowsAffected()
	if err != nil || (rows != 0 && rows != 1) {
		if err != nil {
			return rollback(err)
		}
		return rollback(ErrDomainConvergenceConflict)
	}
	var stored DomainConvergenceRequest
	found, err := scanDomainConvergenceRequestWithActor(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE request_kind=$1 AND idempotency_key=$2 FOR UPDATE`, request.Kind, request.IdempotencyKey), &stored)
	if err != nil {
		return rollback(err)
	}
	if !found {
		return rollback(ErrNotFound)
	}
	if stored.RequestDigest != request.RequestDigest || stored.ApplicationDomainID != request.ApplicationDomainID || stored.ApplicationID != request.ApplicationID || stored.Hostname != request.Hostname || stored.TargetDeploymentID != request.TargetDeploymentID || stored.ActorType != request.ActorType || stored.ActorID != request.ActorID {
		return rollback(ErrDomainConvergenceConflict)
	}
	if request.Kind == DomainConvergenceConverge {
		storedTarget, storedErr := domainConvergenceFrozenTarget(stored)
		requestTarget, requestErr := domainConvergenceFrozenTarget(request)
		if storedErr != nil || requestErr != nil || !domainConvergenceTargetEqual(storedTarget, requestTarget) {
			return rollback(ErrDomainConvergenceConflict)
		}
	}
	if err := tx.Commit(); err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	return stored, rows == 0, nil
}

func (s *Store) ClaimDomainConvergenceRequest(ctx context.Context, owner string, lease time.Duration, now time.Time) (DomainConvergenceRequest, bool, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || lease <= 0 {
		return DomainConvergenceRequest{}, false, domain.ValidationError("domain convergence lease owner and duration are required")
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	rollback := func(cause error) (DomainConvergenceRequest, bool, error) {
		return DomainConvergenceRequest{}, false, rollbackTx(tx, cause)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='failed',status='failed',resume_phase=NULL,last_error='lease_exhausted',lease_owner=NULL,lease_until=NULL,updated_at=$1,completed_at=NULL WHERE status='leased' AND lease_until < $1 AND attempt >= max_attempts AND COALESCE(last_error,'') NOT IN ('route_activation_restore_required','unbind_restore_required','unbind_restore_retry')`, now); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='failed',status='failed',resume_phase=NULL,last_error='recovery_exhausted',lease_owner=NULL,lease_until=NULL,updated_at=$1,completed_at=NULL WHERE status='recovery_required' AND phase='recovery_required' AND attempt >= max_attempts AND COALESCE(last_error,'') NOT IN ('route_activation_restore_required','unbind_restore_required','unbind_restore_retry')`, now); err != nil {
		return rollback(err)
	}
	var request DomainConvergenceRequest
	found, err := scanDomainConvergenceRequest(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE (status='queued' AND phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed') AND attempt < max_attempts) OR (status='recovery_required' AND phase='recovery_required' AND resume_phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed') AND (attempt < max_attempts OR last_error IN ('route_activation_restore_required','unbind_restore_required','unbind_restore_retry'))) OR (status='leased' AND phase IN ('queued','route_prepared','internal_route_active','tls_allowed','certificate_observed','serving','unbind_route_removed') AND lease_until < $1 AND (attempt < max_attempts OR last_error IN ('route_activation_restore_required','unbind_restore_required','unbind_restore_retry'))) ORDER BY CASE WHEN COALESCE(last_error,'') IN ('route_activation_restore_required','unbind_restore_required','unbind_restore_retry') THEN recovery_attempt ELSE 0 END,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, now), &request)
	if err != nil {
		return rollback(err)
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return DomainConvergenceRequest{}, false, err
		}
		return DomainConvergenceRequest{}, false, nil
	}
	compensation := domainConvergenceCompensationCode(request.LastError)
	if request.Attempt >= request.MaxAttempts && !compensation {
		return rollback(domain.NewError(domain.ErrConflict, "domain convergence request exhausted attempts"))
	}
	claimedPhase := request.Phase
	if request.Status == DomainConvergenceRecoveryStatus {
		claimedPhase = request.ResumePhase
	}
	if !domainConvergenceExecutablePhase(claimedPhase) {
		return rollback(ErrDomainConvergenceConflict)
	}
	until := now.Add(lease)
	if _, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase=$2,status='leased',resume_phase=NULL,lease_owner=$3,lease_until=$4,attempt=attempt+CASE WHEN $5 THEN 0 ELSE 1 END,recovery_attempt=recovery_attempt+CASE WHEN $5 THEN 1 ELSE 0 END,updated_at=$1 WHERE id=$6`, now, claimedPhase, owner, until, compensation, request.ID.String()); err != nil {
		return rollback(err)
	}
	request.Phase, request.Status, request.ResumePhase, request.LeaseOwner, request.LeaseUntil, request.UpdatedAt = claimedPhase, DomainConvergenceLeased, "", owner, &until, now
	if compensation {
		request.RecoveryAttempt++
	} else {
		request.Attempt++
	}
	if err := tx.Commit(); err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	return request, true, nil
}

func (s *Store) AdvanceDomainConvergenceRequest(ctx context.Context, id domain.ID, owner string, expected, next DomainConvergencePhase, status DomainConvergenceStatus, result json.RawMessage, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(id, "domain convergence request id"); err != nil {
		return err
	}
	if strings.TrimSpace(owner) == "" || !domainConvergencePhase(expected) || !domainConvergencePhase(next) || !domainConvergenceStatus(status) {
		return domain.ValidationError("domain convergence compare-and-set arguments are invalid")
	}
	if err := validateConvergenceJSON("result", result, true); err != nil {
		return err
	}
	now = m3Now(s, now)
	completed := any(nil)
	if status == DomainConvergenceCompletedStatus {
		completed = now
	}
	resultValue := any(nil)
	if len(result) > 0 {
		resultValue = []byte(result)
	}
	update, err := s.db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase=$1,status=$2,result=$3,resume_phase=NULL,lease_owner=CASE WHEN $2='leased' THEN lease_owner ELSE NULL END,lease_until=CASE WHEN $2='leased' THEN lease_until ELSE NULL END,updated_at=$4,completed_at=$5 WHERE id=$6 AND lease_owner=$7 AND phase=$8 AND status='leased' AND lease_until >= $4`, next, status, resultValue, now, completed, id.String(), strings.TrimSpace(owner), expected)
	if err != nil {
		return fmt.Errorf("advance domain convergence request: %w", err)
	}
	changed, err := update.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrDomainConvergenceConflict
	}
	return nil
}

// AllowDomainConvergenceTLS is the durable boundary between an internally
// active route and permission for the loopback TLS endpoint to issue or renew.
// Keeping it separate from route activation makes a crash between the two
// states recoverable without probing before the allow fact exists.
func (s *Store) AllowDomainConvergenceTLS(ctx context.Context, id domain.ID, owner string, now time.Time) error {
	return s.AdvanceDomainConvergenceRequest(
		ctx,
		id,
		owner,
		DomainConvergenceInternalRouteActive,
		DomainConvergenceTLSAllowed,
		DomainConvergenceLeased,
		json.RawMessage(`{"tls":"allowed"}`),
		now,
	)
}

func (s *Store) RenewDomainConvergenceLease(ctx context.Context, id domain.ID, owner string, lease time.Duration, now time.Time) (time.Time, error) {
	if err := s.requireDB(); err != nil {
		return time.Time{}, err
	}
	if err := domain.RequireID(id, "domain convergence request id"); err != nil {
		return time.Time{}, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || lease <= 0 {
		return time.Time{}, domain.ValidationError("domain convergence lease owner and duration are required")
	}
	now = m3Now(s, now)
	until := now.Add(lease)
	result, err := s.db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET lease_until=$1,updated_at=$2 WHERE id=$3 AND status='leased' AND lease_owner=$4 AND lease_until >= $2`, until, now, id.String(), owner)
	if err != nil {
		return time.Time{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return time.Time{}, err
	}
	if count != 1 {
		return time.Time{}, ErrDomainConvergenceConflict
	}
	return until, nil
}

func (s *Store) LoadDomainConvergenceRequest(ctx context.Context, id domain.ID) (DomainConvergenceRequest, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergenceRequest{}, err
	}
	if err := domain.RequireID(id, "domain convergence request id"); err != nil {
		return DomainConvergenceRequest{}, err
	}
	var request DomainConvergenceRequest
	found, err := scanDomainConvergenceRequestWithActor(s.db.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE id=$1`, id.String()), &request)
	if err != nil {
		return DomainConvergenceRequest{}, err
	}
	if !found {
		return DomainConvergenceRequest{}, ErrNotFound
	}
	return request, nil
}

// LoadDomainConvergenceFrozenTarget is the only adapter-facing way to derive
// an upstream for a claimed convergence request. It validates the lease and
// complete frozen payload, then proves the selected runtime has not drifted.
func (s *Store) LoadDomainConvergenceFrozenTarget(ctx context.Context, id domain.ID, owner string, now time.Time) (DomainConvergenceRuntimeTarget, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergenceRuntimeTarget{}, err
	}
	if err := domain.RequireID(id, "domain convergence request id"); err != nil {
		return DomainConvergenceRuntimeTarget{}, err
	}
	now = m3Now(s, now)
	request, err := s.LoadDomainConvergenceRequest(ctx, id)
	if err != nil {
		return DomainConvergenceRuntimeTarget{}, err
	}
	if !domainConvergenceLeaseMatches(request, strings.TrimSpace(owner), now) || !domainConvergenceExecutablePhase(request.Phase) {
		return DomainConvergenceRuntimeTarget{}, ErrDomainConvergenceConflict
	}
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return DomainConvergenceRuntimeTarget{}, ErrDomainConvergenceConflict
	}
	current, err := s.SelectDomainConvergenceRuntimeTarget(ctx, request.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(current, frozen) {
		return DomainConvergenceRuntimeTarget{}, ErrDomainConvergenceConflict
	}
	return frozen, nil
}

// PrepareDomainConvergenceRequest persists a candidate lease and a strict
// pre-provider snapshot. Initial convergence creates the stable pending route;
// replacement deliberately leaves the serving route/pointer untouched until
// Caddy has accepted the candidate configuration.
func (s *Store) PrepareDomainConvergenceRequest(ctx context.Context, id domain.ID, owner string, now time.Time) (DomainConvergencePreparedRoute, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergencePreparedRoute{}, err
	}
	now = m3Now(s, now)
	owner = strings.TrimSpace(owner)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainConvergencePreparedRoute{}, err
	}
	fail := func(e error) (DomainConvergencePreparedRoute, error) {
		return DomainConvergencePreparedRoute{}, rollbackTx(tx, e)
	}
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if !domainConvergenceLeaseMatches(request, owner, now) || (request.Phase != DomainConvergenceQueued && request.Phase != DomainConvergenceRecoveryRequired) {
		return fail(ErrDomainConvergenceConflict)
	}
	var application, host, verification string
	if err := tx.QueryRowContext(ctx, `SELECT application_id,hostname,verification_status FROM m3_application_domains WHERE id=$1 FOR SHARE`, request.ApplicationDomainID.String()).Scan(&application, &host, &verification); err != nil {
		return fail(err)
	}
	if application != request.ApplicationID.String() || host != request.Hostname || verification != string(DomainVerificationVerified) {
		return fail(domain.NewError(domain.ErrInvalidTransition, "domain convergence binding is not verified"))
	}
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	current, err := s.selectDomainConvergenceRuntimeTargetTx(ctx, tx, request.ApplicationID)
	if err != nil || !domainConvergenceTargetEqual(current, frozen) {
		return fail(ErrDomainConvergenceConflict)
	}
	route := domain.Route{ID: DomainConvergenceRouteID(request.ApplicationDomainID), ApplicationID: request.ApplicationID, DeploymentID: frozen.DeploymentID, ServiceName: frozen.ServiceName, Host: request.Hostname, Path: frozen.Path, Verified: true, CreatedAt: now}
	if err := prepareTLSAllowLeaseTx(ctx, tx, route, frozen.Port, now); err != nil {
		return fail(err)
	}

	snapshot := domainConvergencePreparedSnapshot{RouteID: route.ID.String(), RouteUpdatedAt: now.UTC().Format(time.RFC3339Nano)}
	var existingApplication, existingDomain, existingDeployment, existingService, existingHost, existingPath, existingState string
	var existingVerified, existingServing bool
	var existingCertificate sql.NullString
	var existingUpdatedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving,certificate_reference_id,updated_at FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, route.ID.String()).Scan(&existingApplication, &existingDomain, &existingDeployment, &existingService, &existingHost, &existingPath, &existingState, &existingVerified, &existingServing, &existingCertificate, &existingUpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if err := prepareTLSAllowRouteTx(ctx, tx, request.ApplicationDomainID, route, now); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(err)
	} else {
		existingUpdatedAt = existingUpdatedAt.UTC()
		if existingApplication != request.ApplicationID.String() || existingDomain != request.ApplicationDomainID.String() || existingHost != request.Hostname || existingPath != frozen.Path || !existingVerified {
			return fail(ErrDomainConvergenceConflict)
		}
		snapshot.RouteUpdatedAt = existingUpdatedAt.Format(time.RFC3339Nano)
		switch DesiredRouteState(existingState) {
		case DesiredRoutePending:
			if existingDeployment != frozen.DeploymentID.String() || existingService != frozen.ServiceName || existingServing || existingCertificate.Valid {
				return fail(ErrDomainConvergenceConflict)
			}
			var pointerID string
			if err := tx.QueryRowContext(ctx, `SELECT route_id FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, route.ID.String()).Scan(&pointerID); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fail(err)
			} else if err == nil {
				return fail(ErrDomainConvergenceConflict)
			}
		case DesiredRouteActive:
			var pointer RoutePointer
			if err := tx.QueryRowContext(ctx, `SELECT route_id,deployment_id,port_lease_id,revision,updated_at FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, route.ID.String()).Scan(&pointer.RouteID, &pointer.DeploymentID, &pointer.PortLeaseID, &pointer.Revision, &pointer.UpdatedAt); err != nil {
				return fail(ErrDomainConvergenceConflict)
			}
			if pointer.RouteID != route.ID || pointer.Revision < 1 {
				return fail(ErrDomainConvergenceConflict)
			}
			snapshot.PointerDeploymentID = pointer.DeploymentID.String()
			snapshot.PointerLeaseID = pointer.PortLeaseID.String()
			snapshot.PointerRevision = pointer.Revision
		default:
			return fail(ErrDomainConvergenceConflict)
		}
	}
	result, err := domainConvergencePreparedSnapshotJSON(snapshot)
	if err != nil {
		return fail(err)
	}
	write, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='route_prepared',result=$1,resume_phase=NULL,updated_at=$2 WHERE id=$3 AND phase IN ('queued','recovery_required') AND status='leased' AND lease_owner=$4 AND lease_until >= $2`, []byte(result), now, id.String(), owner)
	if err != nil {
		return fail(err)
	}
	changed, err := write.RowsAffected()
	if err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	request.Phase, request.Result, request.UpdatedAt = DomainConvergenceRoutePrepared, result, now
	if err := tx.Commit(); err != nil {
		return DomainConvergencePreparedRoute{}, err
	}
	return DomainConvergencePreparedRoute{Request: request, Route: route, Port: frozen.Port}, nil
}

// ActivateDomainConvergenceRoute is the post-Observe CAS. The Caddy call has
// already completed before this short transaction begins.
func (s *Store) ActivateDomainConvergenceRoute(ctx context.Context, id domain.ID, owner string, now time.Time) (DomainConvergencePreparedRoute, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergencePreparedRoute{}, err
	}
	now = m3Now(s, now)
	owner = strings.TrimSpace(owner)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainConvergencePreparedRoute{}, err
	}
	fail := func(e error) (DomainConvergencePreparedRoute, error) {
		return DomainConvergencePreparedRoute{}, rollbackTx(tx, e)
	}
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if !domainConvergenceLeaseMatches(request, owner, now) || request.Phase != DomainConvergenceRoutePrepared {
		return fail(ErrDomainConvergenceConflict)
	}
	frozen, err := domainConvergenceFrozenTarget(request)
	if err != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	target, err := s.selectDomainConvergenceRuntimeTargetTx(ctx, tx, request.ApplicationID)
	if err != nil {
		return fail(err)
	}
	if !domainConvergenceTargetEqual(target, frozen) {
		return fail(ErrDomainConvergenceConflict)
	}
	snapshot, err := parseDomainConvergencePreparedSnapshot(request.Result)
	if err != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	routeID := DomainConvergenceRouteID(request.ApplicationDomainID)
	if snapshot.RouteID != routeID.String() {
		return fail(ErrDomainConvergenceConflict)
	}
	candidateLeaseID, err := findTLSAllowLeaseIDTx(ctx, tx, request.ApplicationID, frozen.DeploymentID, frozen.ServiceName, frozen.Port)
	if err != nil {
		return fail(ErrDomainConvergenceConflict)
	}

	type lockedLease struct {
		id, applicationID, deploymentID, serviceName, bindHost string
		port                                                   int
		expiresAt, releasedAt                                  sql.NullTime
	}
	loadLease := func(leaseID domain.ID) (lockedLease, error) {
		var value lockedLease
		err := tx.QueryRowContext(ctx, `SELECT id,application_id,deployment_id,service_name,bind_host,port,expires_at,released_at FROM m3_port_leases WHERE id=$1 FOR UPDATE`, leaseID.String()).Scan(&value.id, &value.applicationID, &value.deploymentID, &value.serviceName, &value.bindHost, &value.port, &value.expiresAt, &value.releasedAt)
		return value, err
	}
	validateLease := func(lease lockedLease, leaseID, deploymentID domain.ID, service string, port int) bool {
		return lease.id == leaseID.String() && lease.applicationID == request.ApplicationID.String() && lease.deploymentID == deploymentID.String() && lease.serviceName == service && lease.bindHost == "127.0.0.1" && lease.port == port && !lease.releasedAt.Valid && (!lease.expiresAt.Valid || !lease.expiresAt.Time.UTC().Before(now))
	}
	candidateLease, err := loadLease(candidateLeaseID)
	if err != nil || !validateLease(candidateLease, candidateLeaseID, frozen.DeploymentID, frozen.ServiceName, frozen.Port) {
		return fail(ErrDomainConvergenceConflict)
	}

	var route domainConvergenceLockedRoute
	var certificate sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT id,application_id,application_domain_id,deployment_id,service_name,hostname,path_prefix,desired_state,verified,serving,certificate_reference_id,updated_at FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, routeID.String()).Scan(&route.ID, &route.ApplicationID, &route.ApplicationDomainID, &route.DeploymentID, &route.ServiceName, &route.Hostname, &route.Path, &route.State, &route.Verified, &route.Serving, &certificate, &route.UpdatedAt); err != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	route.UpdatedAt = route.UpdatedAt.UTC()
	route.CertificateReference = domain.ID(certificate.String)
	if route.ID != routeID || route.ApplicationID != request.ApplicationID || route.ApplicationDomainID != request.ApplicationDomainID || route.Hostname != request.Hostname || route.Path != frozen.Path || !route.Verified || route.UpdatedAt.Format(time.RFC3339Nano) != snapshot.RouteUpdatedAt {
		return fail(ErrDomainConvergenceConflict)
	}

	var pointer RoutePointer
	pointerFound := true
	if err := tx.QueryRowContext(ctx, `SELECT route_id,deployment_id,port_lease_id,revision,updated_at FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, routeID.String()).Scan(&pointer.RouteID, &pointer.DeploymentID, &pointer.PortLeaseID, &pointer.Revision, &pointer.UpdatedAt); errors.Is(err, sql.ErrNoRows) {
		pointerFound = false
	} else if err != nil {
		return fail(err)
	}
	if pointerFound && (pointer.RouteID != routeID || pointer.DeploymentID.String() != snapshot.PointerDeploymentID || pointer.PortLeaseID.String() != snapshot.PointerLeaseID || pointer.Revision != snapshot.PointerRevision) {
		return fail(ErrDomainConvergenceConflict)
	}
	if !pointerFound && (snapshot.PointerDeploymentID != "" || snapshot.PointerLeaseID != "" || snapshot.PointerRevision != 0) {
		return fail(ErrDomainConvergenceConflict)
	}

	switch route.State {
	case DesiredRoutePending:
		if pointerFound || route.DeploymentID != frozen.DeploymentID || route.ServiceName != frozen.ServiceName || route.Serving || !route.CertificateReference.Empty() {
			return fail(ErrDomainConvergenceConflict)
		}
		write, err := tx.ExecContext(ctx, `INSERT INTO m3_route_pointers(route_id,deployment_id,port_lease_id,revision,updated_at) VALUES($1,$2,$3,1,$4)`, routeID.String(), frozen.DeploymentID.String(), candidateLeaseID.String(), now)
		if err != nil {
			return fail(err)
		}
		if changed, err := write.RowsAffected(); err != nil || changed != 1 {
			return fail(ErrDomainConvergenceConflict)
		}
		write, err = tx.ExecContext(ctx, `UPDATE m3_desired_routes SET desired_state='active',updated_at=$2 WHERE id=$1 AND desired_state='pending' AND verified=true AND serving=false AND certificate_reference_id IS NULL AND updated_at=$3`, routeID.String(), now, route.UpdatedAt)
		if err != nil {
			return fail(err)
		}
		if changed, err := write.RowsAffected(); err != nil || changed != 1 {
			return fail(ErrDomainConvergenceConflict)
		}
	case DesiredRouteActive:
		if !pointerFound {
			return fail(ErrDomainConvergenceConflict)
		}
		oldLease, err := loadLease(pointer.PortLeaseID)
		if err != nil || !validateLease(oldLease, pointer.PortLeaseID, route.DeploymentID, route.ServiceName, oldLease.port) || pointer.DeploymentID != route.DeploymentID {
			return fail(ErrDomainConvergenceConflict)
		}
		if pointer.PortLeaseID != candidateLeaseID {
			write, err := tx.ExecContext(ctx, `UPDATE m3_route_pointers SET deployment_id=$1,port_lease_id=$2,revision=revision+1,updated_at=$3 WHERE route_id=$4 AND deployment_id=$5 AND port_lease_id=$6 AND revision=$7`, frozen.DeploymentID.String(), candidateLeaseID.String(), now, routeID.String(), pointer.DeploymentID.String(), pointer.PortLeaseID.String(), pointer.Revision)
			if err != nil {
				return fail(err)
			}
			if changed, err := write.RowsAffected(); err != nil || changed != 1 {
				return fail(ErrDomainConvergenceConflict)
			}
			write, err = tx.ExecContext(ctx, `UPDATE m3_desired_routes SET deployment_id=$1,service_name=$2,certificate_reference_id=NULL,serving=false,updated_at=$3 WHERE id=$4 AND application_id=$5 AND application_domain_id=$6 AND deployment_id=$7 AND service_name=$8 AND hostname=$9 AND path_prefix=$10 AND desired_state='active' AND verified=true AND updated_at=$11`, frozen.DeploymentID.String(), frozen.ServiceName, now, routeID.String(), request.ApplicationID.String(), request.ApplicationDomainID.String(), route.DeploymentID.String(), route.ServiceName, request.Hostname, frozen.Path, route.UpdatedAt)
			if err != nil {
				return fail(err)
			}
			if changed, err := write.RowsAffected(); err != nil || changed != 1 {
				return fail(ErrDomainConvergenceConflict)
			}
			if _, err := releaseTLSAllowLeaseIfUnreferencedTx(ctx, tx, pointer.PortLeaseID, request.ApplicationID, route.DeploymentID, route.ServiceName, oldLease.port, now); err != nil {
				return fail(err)
			}
		}
	default:
		return fail(ErrDomainConvergenceConflict)
	}

	write, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='internal_route_active',result='{"route":"active"}'::jsonb,resume_phase=NULL,updated_at=$1 WHERE id=$2 AND phase='route_prepared' AND status='leased' AND lease_owner=$3 AND lease_until >= $1`, now, id.String(), owner)
	if err != nil {
		return fail(err)
	}
	changed, err := write.RowsAffected()
	if err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	request.Phase, request.UpdatedAt = DomainConvergenceInternalRouteActive, now
	if err = tx.Commit(); err != nil {
		return DomainConvergencePreparedRoute{}, err
	}
	preparedRoute := domain.Route{ID: routeID, ApplicationID: request.ApplicationID, DeploymentID: frozen.DeploymentID, ServiceName: frozen.ServiceName, Host: request.Hostname, Path: frozen.Path, Verified: true, CreatedAt: now}
	return DomainConvergencePreparedRoute{Request: request, Route: preparedRoute, Port: frozen.Port}, nil
}

// FinalizeDomainConvergenceCertificate atomically binds an opaque edge
// observation and marks the already active route serving. The observation ID
// is deliberately not a SecretProvider record and contains no certificate.
func (s *Store) FinalizeDomainConvergenceCertificate(ctx context.Context, id domain.ID, owner string, observation DomainConvergenceCertificateObservation, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := observation.Validate(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if !domainConvergenceObservationValidAt(observation, now) {
		return domain.ValidationError("domain convergence certificate observation is not currently valid")
	}
	owner = strings.TrimSpace(owner)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(e error) error { return rollbackTx(tx, e) }
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if !domainConvergenceLeaseMatches(request, owner, now) || request.Phase != DomainConvergenceCertificateObserved {
		return fail(ErrDomainConvergenceConflict)
	}
	expected, _, err := parseDomainConvergenceCertificateObservationResult(request.Result, request.Hostname)
	if err != nil || expected.Fingerprint != observation.Fingerprint || expected.Issuer != observation.Issuer || expected.NotBefore != observation.NotBefore.UTC() || expected.NotAfter != observation.NotAfter.UTC() {
		return fail(ErrDomainConvergenceConflict)
	}
	target, route, err := s.lockDomainConvergenceRouteTx(ctx, tx, request, now)
	if err != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	renewal := route.Serving && !route.CertificateReference.Empty()
	if route.Serving != !route.CertificateReference.Empty() {
		return fail(ErrDomainConvergenceConflict)
	}
	sum := sha256.Sum256([]byte("edge-certificate:" + request.ApplicationDomainID.String() + ":" + observation.Fingerprint))
	certificateID := domain.ID(fmt.Sprintf("certificate_%x", sum[:16]))
	opaque := domain.ID("edge-caddy-observation:" + observation.Fingerprint)
	if renewal {
		existing, err := lockDomainConvergenceCertificateReferenceTx(ctx, tx, route.CertificateReference)
		if err != nil || existing.applicationDomainID != request.ApplicationDomainID || existing.hostname != request.Hostname {
			return fail(ErrDomainConvergenceConflict)
		}
		certificateID = existing.id
		write, err := tx.ExecContext(ctx, `UPDATE m3_certificate_references SET secret_reference_id=$1,issuer=$2,status='ready',not_before=$3,not_after=$4,renewal_due_at=$5,updated_at=$6 WHERE id=$7 AND application_domain_id=$8 AND subject_hostname=$9`, opaque.String(), observation.Issuer, observation.NotBefore.UTC(), observation.NotAfter.UTC(), observation.NotBefore.Add(observation.NotAfter.Sub(observation.NotBefore)*2/3).UTC(), now, certificateID.String(), request.ApplicationDomainID.String(), request.Hostname)
		if err != nil {
			return fail(err)
		}
		changed, err := write.RowsAffected()
		if err != nil || changed != 1 {
			return fail(ErrDomainConvergenceConflict)
		}
	} else {
		existing, found, err := lockDomainConvergenceCertificateForHostnameTx(ctx, tx, request.ApplicationDomainID, request.Hostname)
		if err != nil {
			return fail(err)
		}
		if found {
			if existing.applicationDomainID != request.ApplicationDomainID || existing.hostname != request.Hostname {
				return fail(ErrDomainConvergenceConflict)
			}
			if existing.opaque != opaque.String() {
				var referencedElsewhere bool
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m3_desired_routes WHERE certificate_reference_id=$1 AND id<>$2)`, existing.id.String(), route.ID.String()).Scan(&referencedElsewhere); err != nil || referencedElsewhere {
					return fail(ErrDomainConvergenceConflict)
				}
			}
			certificateID = existing.id
			write, err := tx.ExecContext(ctx, `UPDATE m3_certificate_references SET secret_reference_id=$1,issuer=$2,status='ready',not_before=$3,not_after=$4,renewal_due_at=$5,updated_at=$6 WHERE id=$7 AND application_domain_id=$8 AND subject_hostname=$9`, opaque.String(), observation.Issuer, observation.NotBefore.UTC(), observation.NotAfter.UTC(), observation.NotBefore.Add(observation.NotAfter.Sub(observation.NotBefore)*2/3).UTC(), now, certificateID.String(), request.ApplicationDomainID.String(), request.Hostname)
			if err != nil {
				return fail(err)
			}
			changed, err := write.RowsAffected()
			if err != nil || changed != 1 {
				return fail(ErrDomainConvergenceConflict)
			}
		} else {
			write, err := tx.ExecContext(ctx, `INSERT INTO m3_certificate_references(id,application_domain_id,secret_reference_id,subject_hostname,issuer,status,not_before,not_after,renewal_due_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'ready',$6,$7,$8,$9,$9)`, certificateID.String(), request.ApplicationDomainID.String(), opaque.String(), request.Hostname, observation.Issuer, observation.NotBefore.UTC(), observation.NotAfter.UTC(), observation.NotBefore.Add(observation.NotAfter.Sub(observation.NotBefore)*2/3).UTC(), now)
			if err != nil {
				return fail(err)
			}
			changed, err := write.RowsAffected()
			if err != nil || changed != 1 {
				return fail(ErrDomainConvergenceConflict)
			}
		}
	}
	if !renewal {
		write, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET certificate_reference_id=$1,serving=true,updated_at=$2 WHERE id=$3 AND application_id=$4 AND application_domain_id=$5 AND deployment_id=$6 AND service_name=$7 AND hostname=$8 AND path_prefix='/' AND desired_state='active' AND verified=true AND serving=false AND certificate_reference_id IS NULL AND updated_at=$9`, certificateID.String(), now, route.ID.String(), request.ApplicationID.String(), request.ApplicationDomainID.String(), target.DeploymentID.String(), target.ServiceName, request.Hostname, route.UpdatedAt)
		if err != nil {
			return fail(err)
		}
		changed, err := write.RowsAffected()
		if err != nil || changed != 1 {
			return fail(ErrDomainConvergenceConflict)
		}
	}
	result := []byte(fmt.Sprintf(`{"fingerprint":%q,"status":"observed"}`, observation.Fingerprint))
	write, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='serving',status='leased',result=$1,resume_phase=NULL,updated_at=$2 WHERE id=$3 AND status='leased' AND lease_owner=$4 AND lease_until >= $2 AND phase='certificate_observed'`, result, now, id.String(), owner)
	if err != nil {
		return fail(err)
	}
	changed, err := write.RowsAffected()
	if err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	action := "domain.route.serving"
	if renewal {
		action = "domain.certificate.renewed"
	}
	if err := appendDomainConvergenceAuditTx(ctx, tx, request, action, observation.Fingerprint, now); err != nil {
		return fail(err)
	}
	return tx.Commit()
}

func (s *Store) FailDomainConvergenceRequest(ctx context.Context, id domain.ID, owner string, expected DomainConvergencePhase, code string, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(id, "domain convergence request id"); err != nil {
		return err
	}
	if strings.TrimSpace(owner) == "" || !domainConvergencePhase(expected) || !domainConvergenceSafeCode(code) {
		return domain.ValidationError("domain convergence failure compare-and-set is invalid")
	}
	now = m3Now(s, now)
	result, err := s.db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase=CASE WHEN attempt >= max_attempts THEN 'failed' ELSE $1 END,status=CASE WHEN attempt >= max_attempts THEN 'failed' ELSE 'queued' END,resume_phase=NULL,last_error=$2,lease_owner=NULL,lease_until=NULL,updated_at=$3,completed_at=NULL WHERE id=$4 AND status='leased' AND lease_owner=$5 AND lease_until >= $3 AND phase=$1`, expected, code, now, id.String(), owner)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrDomainConvergenceConflict
	}
	return nil
}

func (s *Store) MarkDomainConvergenceRecoveryRequired(ctx context.Context, id domain.ID, owner string, expected DomainConvergencePhase, code string, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m3Now(s, now)
	if !domainConvergenceSafeCode(code) {
		return domain.ValidationError("domain convergence recovery code is invalid")
	}
	compensation := domainConvergenceCompensationCode(code)
	result, err := s.db.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase=CASE WHEN attempt >= max_attempts AND NOT $3 THEN 'failed' ELSE 'recovery_required' END,status=CASE WHEN attempt >= max_attempts AND NOT $3 THEN 'failed' ELSE 'recovery_required' END,resume_phase=CASE WHEN attempt >= max_attempts AND NOT $3 THEN NULL ELSE $1 END,lease_owner=NULL,lease_until=NULL,last_error=CASE WHEN attempt >= max_attempts AND NOT $3 THEN 'recovery_exhausted' ELSE $2 END,updated_at=$4,completed_at=NULL WHERE id=$5 AND status='leased' AND lease_owner=$6 AND lease_until >= $4 AND phase=$1`, expected, code, compensation, now, id.String(), owner)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrDomainConvergenceConflict
	}
	return nil
}

func (s *Store) AcknowledgeDomainConvergenceCompleted(ctx context.Context, id domain.ID, owner string, now time.Time) error {
	return s.AdvanceDomainConvergenceRequest(ctx, id, owner, DomainConvergenceServing, DomainConvergenceCompleted, DomainConvergenceCompletedStatus, json.RawMessage(`{"status":"completed"}`), now)
}

func scanDomainConvergenceRequest(row interface{ Scan(...any) error }, request *DomainConvergenceRequest) (bool, error) {
	var target, resume, owner string
	var lease, completed sql.NullTime
	var result []byte
	err := row.Scan(&request.ID, &request.ApplicationDomainID, &request.ApplicationID, &request.Hostname, &request.Kind, &target, &request.RequestDigest, &request.IdempotencyKey, &request.Phase, &request.Status, &resume, &owner, &lease, &request.Attempt, &request.RecoveryAttempt, &request.MaxAttempts, &request.Payload, &result, &request.LastError, &request.CreatedAt, &request.UpdatedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	request.TargetDeploymentID, request.ResumePhase, request.LeaseOwner = domain.ID(target), DomainConvergencePhase(resume), owner
	// Older local-only 0024 test fixtures select the pre-actor projection.  All
	// write paths normalize an explicit actor before insertion; treating this
	// compatibility projection as the controller actor prevents a read helper
	// from manufacturing an administrator identity.
	request.ActorType, request.ActorID = domainConvergenceSystemActorType, domainConvergenceSystemActorID
	if lease.Valid {
		value := lease.Time.UTC()
		request.LeaseUntil = &value
	}
	if len(result) > 0 {
		request.Result = append(json.RawMessage(nil), result...)
	}
	if completed.Valid {
		value := completed.Time.UTC()
		request.CompletedAt = &value
	}
	request.CreatedAt, request.UpdatedAt = request.CreatedAt.UTC(), request.UpdatedAt.UTC()
	return true, request.Validate()
}

// scanDomainConvergenceRequestWithActor is used wherever actor identity is a
// business input (creation replay and auditable finalization).  Keep the
// legacy scanner separate so existing narrow projection queries do not lose
// their stable scan shape.
func scanDomainConvergenceRequestWithActor(row interface{ Scan(...any) error }, request *DomainConvergenceRequest) (bool, error) {
	var target, resume, owner string
	var lease, completed sql.NullTime
	var result []byte
	err := row.Scan(&request.ID, &request.ApplicationDomainID, &request.ApplicationID, &request.Hostname, &request.Kind, &target, &request.RequestDigest, &request.IdempotencyKey, &request.ActorType, &request.ActorID, &request.Phase, &request.Status, &resume, &owner, &lease, &request.Attempt, &request.RecoveryAttempt, &request.MaxAttempts, &request.Payload, &result, &request.LastError, &request.CreatedAt, &request.UpdatedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	request.TargetDeploymentID, request.ResumePhase, request.LeaseOwner = domain.ID(target), DomainConvergencePhase(resume), owner
	if lease.Valid {
		value := lease.Time.UTC()
		request.LeaseUntil = &value
	}
	if len(result) > 0 {
		request.Result = append(json.RawMessage(nil), result...)
	}
	if completed.Valid {
		value := completed.Time.UTC()
		request.CompletedAt = &value
	}
	request.CreatedAt, request.UpdatedAt = request.CreatedAt.UTC(), request.UpdatedAt.UTC()
	return true, request.Validate()
}

// SelectDomainConvergenceRuntimeTarget derives the only routable upstream
// from immutable M2 spec and healthy M4 facts. It never accepts a port or
// service from an HTTP request. Legacy deployments are accepted only where a
// release declares exactly one service.
func (s *Store) SelectDomainConvergenceRuntimeTarget(ctx context.Context, applicationID domain.ID) (DomainConvergenceRuntimeTarget, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergenceRuntimeTarget{}, err
	}
	if err := domain.RequireID(applicationID, "domain convergence application id"); err != nil {
		return DomainConvergenceRuntimeTarget{}, err
	}
	return selectDomainConvergenceRuntimeTarget(ctx, s.db.QueryRowContext, applicationID)
}

func (s *Store) ListDomainConvergenceRuntimeApplications(ctx context.Context) ([]DomainConvergenceApplication, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT a.id,a.name FROM applications a JOIN environments e ON e.application_id=a.id JOIN deployments d ON d.environment_id=e.id WHERE d.state IN ('runtime_ready','degraded','serving') ORDER BY a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DomainConvergenceApplication{}
	for rows.Next() {
		var item DomainConvergenceApplication
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListVerifiedDomainConvergenceBindings(ctx context.Context) ([]DomainConvergenceBinding, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,application_id,hostname,domain_kind FROM m3_application_domains WHERE verification_status='verified' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DomainConvergenceBinding{}
	for rows.Next() {
		var item DomainConvergenceBinding
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.Hostname, &item.Kind); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) EnsureDomainConvergencePlatformDomain(ctx context.Context, platformID, applicationID domain.ID, applicationName, base, verificationRef string, now time.Time) (ApplicationDomainRecord, error) {
	if err := domain.RequireID(platformID, "platform domain id"); err != nil {
		return ApplicationDomainRecord{}, err
	}
	host, err := domain.StableApplicationHost(applicationName, applicationID, base)
	if err != nil {
		return ApplicationDomainRecord{}, err
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ApplicationDomainRecord{}, domain.ValidationError("platform hostname is malformed")
	}
	stableID, err := domain.StablePlatformApplicationDomainID(platformID, applicationID)
	if err != nil {
		return ApplicationDomainRecord{}, err
	}
	verifiedAt := now
	record := ApplicationDomainRecord{ID: stableID, ApplicationID: applicationID, PlatformDomainID: platformID, Hostname: host, Kind: "platform", StableSlug: parts[0], VerificationMethod: "dns01", VerificationStatus: DomainVerificationVerified, VerificationRef: verificationRef, VerifiedAt: &verifiedAt, CreatedAt: now, UpdatedAt: now}
	if err := s.UpsertApplicationDomain(ctx, record, now); err != nil {
		return ApplicationDomainRecord{}, err
	}
	return record, nil
}

func (s *Store) WakeDomainConvergence(ctx context.Context, applicationDomainID, applicationID domain.ID, hostname string, now time.Time) (DomainConvergenceRequest, bool, error) {
	now = m3Now(s, now)
	target, err := s.SelectDomainConvergenceRuntimeTarget(ctx, applicationID)
	if err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	payload, err := domainConvergencePayloadForTarget(target)
	if err != nil {
		return DomainConvergenceRequest{}, false, err
	}
	requestDigest := domainConvergenceRequestDigest(applicationDomainID, target)
	routeID := DomainConvergenceRouteID(applicationDomainID)
	var certificateID, opaque string
	var renewalDueAt, certificateUpdatedAt time.Time
	var certificateNotBefore, certificateNotAfter time.Time
	err = s.db.QueryRowContext(ctx, `SELECT c.id,c.secret_reference_id,c.renewal_due_at,c.updated_at,c.not_before,c.not_after FROM m3_desired_routes r JOIN m3_route_pointers p ON p.route_id=r.id JOIN m3_port_leases l ON l.id=p.port_lease_id JOIN m3_certificate_references c ON c.id=r.certificate_reference_id WHERE r.id=$1 AND r.application_id=$2 AND r.application_domain_id=$3 AND r.hostname=$4 AND r.path_prefix=$5 AND r.deployment_id=$6 AND r.service_name=$7 AND r.desired_state='active' AND r.verified=true AND r.serving=true AND p.deployment_id=r.deployment_id AND l.application_id=r.application_id AND l.deployment_id=r.deployment_id AND l.service_name=r.service_name AND l.bind_host='127.0.0.1' AND l.port=$8 AND l.released_at IS NULL AND (l.expires_at IS NULL OR l.expires_at > $9) AND c.status='ready' AND c.subject_hostname=r.hostname AND c.secret_reference_id ~ '^edge-caddy-observation:sha256:[0-9a-f]{64}$' AND c.not_before IS NOT NULL AND c.not_after IS NOT NULL`, routeID.String(), applicationID.String(), applicationDomainID.String(), hostname, target.Path, target.DeploymentID.String(), target.ServiceName, target.Port, now).Scan(&certificateID, &opaque, &renewalDueAt, &certificateUpdatedAt, &certificateNotBefore, &certificateNotAfter)
	if err == nil {
		renewalDueAt, certificateUpdatedAt, certificateNotBefore, certificateNotAfter = renewalDueAt.UTC(), certificateUpdatedAt.UTC(), certificateNotBefore.UTC(), certificateNotAfter.UTC()
		if !now.Before(certificateNotAfter) || now.Before(certificateNotBefore) {
			// An expired/invalid observation is still a durable certificate fact,
			// but it must create a fresh observation-only renewal intent rather
			// than falling back to the original completed initial request.
		} else if renewalDueAt.After(now) || certificateUpdatedAt.Add(time.Hour).After(now) {
			return DomainConvergenceRequest{}, false, nil
		}
		window := domainConvergenceRenewalWindow(now, certificateUpdatedAt)
		generation := sha256.Sum256([]byte("g4b2-renewal:" + certificateID + ":" + opaque + ":" + certificateUpdatedAt.Format(time.RFC3339Nano) + ":" + fmt.Sprint(window)))
		request := DomainConvergenceRequest{ID: domain.ID(fmt.Sprintf("convergence_%x", generation[:16])), ApplicationDomainID: applicationDomainID, ApplicationID: applicationID, Hostname: hostname, Kind: DomainConvergenceConverge, TargetDeploymentID: target.DeploymentID, RequestDigest: requestDigest, IdempotencyKey: "g4b2-renewal:" + applicationDomainID.String() + ":" + fmt.Sprint(window) + ":" + fmt.Sprintf("%x", generation[:]), ActorType: domainConvergenceSystemActorType, ActorID: domainConvergenceSystemActorID, Phase: DomainConvergenceInternalRouteActive, Status: DomainConvergenceQueuedStatus, Payload: payload}
		return s.CreateDomainConvergenceRequest(ctx, request, now)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DomainConvergenceRequest{}, false, err
	}
	sum := sha256.Sum256([]byte("g4b2-converge:" + applicationDomainID.String() + ":" + target.DeploymentID.String() + ":" + target.ServiceName + ":" + target.RuntimeDigest + ":" + requestDigest))
	request := DomainConvergenceRequest{ID: domain.ID(fmt.Sprintf("convergence_%x", sum[:16])), ApplicationDomainID: applicationDomainID, ApplicationID: applicationID, Hostname: hostname, Kind: DomainConvergenceConverge, TargetDeploymentID: target.DeploymentID, RequestDigest: requestDigest, IdempotencyKey: "g4b2:" + applicationDomainID.String() + ":" + target.DeploymentID.String() + ":" + target.ServiceName + ":" + fmt.Sprintf("%d", target.Port) + ":" + target.RuntimeDigest, ActorType: domainConvergenceSystemActorType, ActorID: domainConvergenceSystemActorID, Payload: payload}
	return s.CreateDomainConvergenceRequest(ctx, request, now)
}

func domainConvergenceRenewalWindow(now, certificateUpdatedAt time.Time) int64 {
	if now.Before(certificateUpdatedAt) {
		return 0
	}
	return int64(now.Sub(certificateUpdatedAt) / time.Hour)
}

func parseDomainUnbindPayload(value json.RawMessage) (domainUnbindPayload, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(value, &raw) != nil || len(raw) != 6 {
		return domainUnbindPayload{}, domain.ValidationError("domain unbind payload is invalid")
	}
	for _, key := range []string{"binding_id", "binding_updated_at", "target_route_digest", "target_route_count", "remaining_route_digest", "remaining_route_count"} {
		if _, ok := raw[key]; !ok {
			return domainUnbindPayload{}, domain.ValidationError("domain unbind payload is invalid")
		}
	}
	var payload domainUnbindPayload
	if json.Unmarshal(value, &payload) != nil {
		return domainUnbindPayload{}, domain.ValidationError("domain unbind payload is invalid")
	}
	if err := domain.RequireID(domain.ID(payload.BindingID), "domain unbind binding id"); err != nil || !domainConvergenceSHA256(payload.TargetRouteDigest) || !domainConvergenceSHA256(payload.RemainingRouteDigest) || payload.TargetRouteCount < 0 || payload.RemainingRouteCount < 0 {
		return domainUnbindPayload{}, domain.ValidationError("domain unbind payload is invalid")
	}
	updated, err := time.Parse(time.RFC3339Nano, payload.BindingUpdatedAt)
	if err != nil || updated.IsZero() || updated.UTC().Format(time.RFC3339Nano) != payload.BindingUpdatedAt {
		return domainUnbindPayload{}, domain.ValidationError("domain unbind payload is invalid")
	}
	return payload, nil
}

func parseDomainUnbindRemovedResult(value json.RawMessage) (domainUnbindRemovedResult, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(value, &raw) != nil || len(raw) != 2 {
		return domainUnbindRemovedResult{}, domain.ValidationError("domain unbind removed result is invalid")
	}
	for _, key := range []string{"remaining_route_digest", "remaining_route_count"} {
		if _, ok := raw[key]; !ok {
			return domainUnbindRemovedResult{}, domain.ValidationError("domain unbind removed result is invalid")
		}
	}
	var result domainUnbindRemovedResult
	if json.Unmarshal(value, &result) != nil || !domainConvergenceSHA256(result.RemainingRouteDigest) || result.RemainingRouteCount < 0 {
		return domainUnbindRemovedResult{}, domain.ValidationError("domain unbind removed result is invalid")
	}
	return result, nil
}

func domainUnbindObservationCertificateDeletable(reference string, stillReferenced bool) bool {
	return strings.HasPrefix(reference, "edge-caddy-observation:") && !stillReferenced
}

func domainConvergenceSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func domainUnbindTargetRouteDigest(routes []DesiredRouteProjection) string {
	return domainUnbindCanonicalRouteDigest(routes)
}

func domainUnbindRemainingRouteDigest(routes []DesiredRouteProjection) string {
	return domainUnbindCanonicalRouteDigest(routes)
}

func domainUnbindCanonicalRouteDigest(routes []DesiredRouteProjection) string {
	parts := make([]string, 0, len(routes))
	for _, route := range routes {
		pointerID, pointerDeployment, revision := "", "", int64(0)
		leaseID, leaseHost, leaseService, leasePort := "", "", "", 0
		if route.Pointer != nil {
			pointerID, pointerDeployment, revision = route.Pointer.PortLeaseID.String(), route.Pointer.DeploymentID.String(), route.Pointer.Revision
		}
		if route.Lease != nil {
			leaseID, leaseHost, leaseService, leasePort = route.Lease.ID.String(), route.Lease.BindHost, route.Lease.ServiceName, route.Lease.Port
		}
		parts = append(parts, strings.Join([]string{
			route.Route.ID.String(), route.Route.ApplicationID.String(), route.ApplicationDomainID.String(), route.Route.DeploymentID.String(), route.Route.ServiceName, route.Route.Host, route.Route.Path,
			string(route.State), fmt.Sprint(route.Route.Verified), fmt.Sprint(route.Route.Serving), route.CertificateID.String(), pointerID, pointerDeployment, fmt.Sprint(revision), leaseID, leaseHost, leaseService, fmt.Sprint(leasePort), route.UpdatedAt.UTC().Format(time.RFC3339Nano),
		}, ":"))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("sha256:%x", sum[:])
}

func validateDomainUnbindActiveProjection(route DesiredRouteProjection) error {
	if route.State != DesiredRouteActive || !route.Route.Verified || route.Pointer == nil || route.Lease == nil || route.Lease.ReleasedAt != nil || route.Pointer.DeploymentID != route.Route.DeploymentID || route.Lease.ApplicationID != route.Route.ApplicationID || route.Lease.DeploymentID != route.Route.DeploymentID || route.Lease.ServiceName != route.Route.ServiceName || route.Lease.BindHost != "127.0.0.1" || route.Lease.Port < 1 || route.Lease.Port > 65535 {
		return ErrDomainConvergenceConflict
	}
	if _, err := NormalizeM3Hostname(route.Route.Host); err != nil {
		return ErrDomainConvergenceConflict
	}
	if _, err := NormalizeM3PathPrefix(route.Route.Path); err != nil {
		return ErrDomainConvergenceConflict
	}
	return nil
}

func loadDomainUnbindRouteProjectionsTx(ctx context.Context, tx *sql.Tx, where string, arguments ...any) ([]DesiredRouteProjection, error) {
	// Pointers and leases are nullable LEFT JOIN sides; PostgreSQL rejects an
	// unqualified FOR SHARE here. Lock the route truth rows only, then validate
	// every pointer/lease projection before committing any unbind transition.
	rows, err := tx.QueryContext(ctx, `SELECT r.id,r.application_id,r.application_domain_id,r.deployment_id,r.service_name,r.hostname,r.path_prefix,r.certificate_reference_id,r.desired_state,r.verified,r.serving,r.created_at,r.updated_at,p.deployment_id,p.port_lease_id,p.revision,p.updated_at,l.application_id,l.deployment_id,l.service_name,l.bind_host,l.port,l.acquired_at,l.expires_at,l.released_at FROM m3_desired_routes r LEFT JOIN m3_route_pointers p ON p.route_id=r.id LEFT JOIN m3_port_leases l ON l.id=p.port_lease_id WHERE `+where+` ORDER BY r.hostname,r.path_prefix,r.id FOR SHARE OF r`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DesiredRouteProjection{}
	for rows.Next() {
		item, err := scanM3DesiredRouteProjection(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// BeginDomainUnbind freezes the target and the full remaining active route set
// before any Caddy operation. It never deletes business facts.
func (s *Store) BeginDomainUnbind(ctx context.Context, applicationID, bindingID domain.ID, actor, key string, now time.Time) (DomainUnbindIntent, bool, error) {
	if err := s.requireDB(); err != nil {
		return DomainUnbindIntent{}, false, err
	}
	if err := domain.RequireID(applicationID, "unbind application id"); err != nil {
		return DomainUnbindIntent{}, false, err
	}
	if err := domain.RequireID(bindingID, "unbind binding id"); err != nil {
		return DomainUnbindIntent{}, false, err
	}
	actor = strings.TrimSpace(actor)
	key = strings.TrimSpace(key)
	if actor == "" || key == "" {
		return DomainUnbindIntent{}, false, domain.ValidationError("unbind actor and idempotency key are required")
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainUnbindIntent{}, false, err
	}
	fail := func(e error) (DomainUnbindIntent, bool, error) { return DomainUnbindIntent{}, false, rollbackTx(tx, e) }
	// Replay is deliberately checked before the binding.  A completed custom
	// unbind removes its binding, but the accepted operation must remain
	// replayable by its original (kind, idempotency key) tuple.  Locking this
	// row in the same transaction also makes a concurrent first invocation
	// serialize with the binding/route snapshot below.
	var existing DomainConvergenceRequest
	found, err := scanDomainConvergenceRequestWithActor(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE request_kind='unbind' AND idempotency_key=$1 FOR UPDATE`, key), &existing)
	if err != nil {
		return fail(err)
	}
	if found {
		payload, parseErr := parseDomainUnbindPayload(existing.Payload)
		if parseErr != nil || existing.Kind != DomainConvergenceUnbind || existing.ApplicationID != applicationID || existing.ApplicationDomainID != bindingID || payload.BindingID != bindingID.String() || existing.ActorType != domainConvergenceAdminActorType || existing.ActorID != actor {
			return fail(ErrDomainConvergenceConflict)
		}
		sum := sha256.Sum256([]byte("unbind:" + payload.BindingID + ":" + payload.TargetRouteDigest + ":" + payload.RemainingRouteDigest))
		if existing.RequestDigest != fmt.Sprintf("sha256:%x", sum[:]) {
			return fail(ErrDomainConvergenceConflict)
		}
		if err := tx.Commit(); err != nil {
			return DomainUnbindIntent{}, false, err
		}
		return DomainUnbindIntent{Request: existing, FrozenRouteDigest: payload.RemainingRouteDigest, FrozenRouteCount: payload.RemainingRouteCount}, true, nil
	}
	var app, host, kind string
	var bindingUpdatedAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT application_id,hostname,domain_kind,updated_at FROM m3_application_domains WHERE id=$1 AND application_id=$2 FOR UPDATE`, bindingID.String(), applicationID.String()).Scan(&app, &host, &kind, &bindingUpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fail(ErrNotFound)
		}
		return fail(err)
	}
	if kind != "custom" {
		return fail(ErrDomainConvergenceConflict)
	}
	// The binding row is the serialization point for all first attempts. A
	// concurrent transaction waits above, then re-evaluates the active unbind
	// under READ COMMITTED and returns the first operation instead of creating
	// a second route-removal intent.
	var active DomainConvergenceRequest
	found, err = scanDomainConvergenceRequestWithActor(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE application_domain_id=$1 AND request_kind='unbind' AND status IN ('queued','leased','recovery_required') ORDER BY updated_at DESC,id DESC LIMIT 1 FOR UPDATE`, bindingID.String()), &active)
	if err != nil {
		return fail(err)
	}
	if found {
		payload, parseErr := parseDomainUnbindPayload(active.Payload)
		if parseErr != nil || active.ApplicationID != applicationID || active.ApplicationDomainID != bindingID {
			return fail(ErrDomainConvergenceConflict)
		}
		if err := tx.Commit(); err != nil {
			return DomainUnbindIntent{}, false, err
		}
		return DomainUnbindIntent{Request: active, FrozenRouteDigest: payload.RemainingRouteDigest, FrozenRouteCount: payload.RemainingRouteCount}, true, nil
	}
	targetRoutes, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.application_domain_id=$1`, bindingID.String())
	if err != nil {
		return fail(err)
	}
	remainingRoutes, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active' AND COALESCE(r.application_domain_id,'') <> $1`, bindingID.String())
	if err != nil {
		return fail(err)
	}
	targetDigest := domainUnbindTargetRouteDigest(targetRoutes)
	remainingDigest := domainUnbindRemainingRouteDigest(remainingRoutes)
	payload := domainUnbindPayload{
		BindingID:            bindingID.String(),
		BindingUpdatedAt:     bindingUpdatedAt.UTC().Format(time.RFC3339Nano),
		TargetRouteDigest:    targetDigest,
		TargetRouteCount:     len(targetRoutes),
		RemainingRouteDigest: remainingDigest,
		RemainingRouteCount:  len(remainingRoutes),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fail(err)
	}
	requestSum := sha256.Sum256([]byte("unbind:" + bindingID.String() + ":" + targetDigest + ":" + remainingDigest))
	attemptSum := sha256.Sum256([]byte("unbind-attempt:" + key))
	operationSum := sha256.Sum256([]byte("unbind-operation:" + bindingID.String() + ":" + targetDigest + ":" + remainingDigest + ":" + fmt.Sprintf("%x", attemptSum[:])))
	request := DomainConvergenceRequest{ID: domain.ID(fmt.Sprintf("convergence_%x", operationSum[:16])), ApplicationDomainID: bindingID, ApplicationID: domain.ID(app), Hostname: host, Kind: DomainConvergenceUnbind, RequestDigest: fmt.Sprintf("sha256:%x", requestSum[:]), IdempotencyKey: key, ActorType: domainConvergenceAdminActorType, ActorID: actor, Phase: DomainConvergenceQueued, Status: DomainConvergenceQueuedStatus, MaxAttempts: 20, Payload: payloadBytes}
	if err := request.Validate(); err != nil {
		return fail(err)
	}
	// This insert belongs to the binding/route freeze transaction.  In
	// particular, do not commit the snapshot and then call Create... in a
	// separate transaction: a binding or route could drift in that gap.
	inserted, err := tx.ExecContext(ctx, `INSERT INTO m3_domain_convergence_requests(id,application_domain_id,application_id,hostname,request_kind,target_deployment_id,request_digest,idempotency_key,actor_type,actor_id,phase,status,attempt,recovery_attempt,max_attempts,payload,created_at,updated_at) VALUES($1,$2,$3,$4,$5,NULL,$6,$7,$8,$9,$10,$11,0,0,$12,$13,$14,$14) ON CONFLICT(request_kind,idempotency_key) DO NOTHING`, request.ID.String(), request.ApplicationDomainID.String(), request.ApplicationID.String(), request.Hostname, request.Kind, request.RequestDigest, request.IdempotencyKey, request.ActorType, request.ActorID, request.Phase, request.Status, request.MaxAttempts, []byte(request.Payload), now)
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && databaseError.Code == "23505" {
			return fail(ErrDomainConvergenceConflict)
		}
		return fail(fmt.Errorf("create domain unbind intent: %w", err))
	}
	rows, err := inserted.RowsAffected()
	if err != nil {
		return fail(err)
	}
	if rows != 1 {
		var replay DomainConvergenceRequest
		found, err := scanDomainConvergenceRequestWithActor(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE request_kind='unbind' AND idempotency_key=$1 FOR UPDATE`, key), &replay)
		if err != nil || !found {
			if err == nil {
				err = ErrNotFound
			}
			return fail(err)
		}
		frozen, parseErr := parseDomainUnbindPayload(replay.Payload)
		if parseErr != nil || replay.ApplicationDomainID != bindingID || replay.ApplicationID != request.ApplicationID || replay.RequestDigest != request.RequestDigest || replay.ActorType != request.ActorType || replay.ActorID != request.ActorID || frozen != payload {
			return fail(ErrDomainConvergenceConflict)
		}
		if err := tx.Commit(); err != nil {
			return DomainUnbindIntent{}, false, err
		}
		return DomainUnbindIntent{Request: replay, FrozenRouteDigest: frozen.RemainingRouteDigest, FrozenRouteCount: frozen.RemainingRouteCount}, true, nil
	}
	if err := tx.Commit(); err != nil {
		return DomainUnbindIntent{}, false, err
	}
	return DomainUnbindIntent{Request: request, FrozenRouteDigest: remainingDigest, FrozenRouteCount: len(remainingRoutes)}, false, nil
}

// LoadDomainUnbindWork loads the immutable unbind snapshot for a current
// lease.  It rejects any route-set, binding, pointer, or lease drift before a
// caller can remove an external Caddy route.
func (s *Store) LoadDomainUnbindWork(ctx context.Context, id domain.ID, owner string, now time.Time) (DomainUnbindWork, error) {
	if err := s.requireDB(); err != nil {
		return DomainUnbindWork{}, err
	}
	if err := domain.RequireID(id, "domain unbind request id"); err != nil {
		return DomainUnbindWork{}, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return DomainUnbindWork{}, domain.ValidationError("domain unbind lease owner is required")
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainUnbindWork{}, err
	}
	fail := func(cause error) (DomainUnbindWork, error) { return DomainUnbindWork{}, rollbackTx(tx, cause) }
	var request DomainConvergenceRequest
	found, err := scanDomainConvergenceRequest(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE id=$1 FOR UPDATE`, id.String()), &request)
	if err != nil {
		return fail(err)
	}
	if !found {
		return fail(ErrNotFound)
	}
	if request.Kind != DomainConvergenceUnbind || (request.Phase != DomainConvergenceQueued && request.Phase != DomainConvergenceRecoveryRequired && request.Phase != DomainConvergenceUnbindRouteRemoved) || request.Status != DomainConvergenceLeased || request.LeaseOwner != owner || request.LeaseUntil == nil || request.LeaseUntil.Before(now) {
		return fail(ErrDomainConvergenceConflict)
	}
	if domainUnbindRestoreRequired(request.LastError) {
		current, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active'`)
		if err != nil {
			return fail(err)
		}
		for _, route := range current {
			if err := validateDomainUnbindActiveProjection(route); err != nil {
				return fail(ErrDomainConvergenceConflict)
			}
		}
		if err := tx.Commit(); err != nil {
			return DomainUnbindWork{}, err
		}
		return DomainUnbindWork{Request: request, Restore: true, RemainingRoutes: current, RemainingRouteDigest: domainUnbindRemainingRouteDigest(current), RemainingRouteCount: len(current)}, nil
	}
	payload, err := parseDomainUnbindPayload(request.Payload)
	if err != nil || payload.BindingID != request.ApplicationDomainID.String() {
		return fail(ErrDomainConvergenceConflict)
	}
	var binding DomainUnbindWork
	var platformID, stableSlug, verificationRef sql.NullString
	var verifiedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,application_id,platform_domain_id,hostname,domain_kind,stable_slug,verification_method,verification_status,verification_ref,verified_at,created_at,updated_at FROM m3_application_domains WHERE id=$1 FOR UPDATE`, request.ApplicationDomainID.String()).Scan(&binding.Binding.ID, &binding.Binding.ApplicationID, &platformID, &binding.Binding.Hostname, &binding.Binding.Kind, &stableSlug, &binding.Binding.VerificationMethod, &binding.Binding.VerificationStatus, &verificationRef, &verifiedAt, &binding.Binding.CreatedAt, &binding.Binding.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrDomainConvergenceConflict)
	}
	if err != nil {
		return fail(err)
	}
	if platformID.Valid {
		binding.Binding.PlatformDomainID = domain.ID(platformID.String)
	}
	if stableSlug.Valid {
		binding.Binding.StableSlug = stableSlug.String
	}
	if verificationRef.Valid {
		binding.Binding.VerificationRef = verificationRef.String
	}
	if verifiedAt.Valid {
		value := verifiedAt.Time.UTC()
		binding.Binding.VerifiedAt = &value
	}
	binding.Binding.CreatedAt, binding.Binding.UpdatedAt = binding.Binding.CreatedAt.UTC(), binding.Binding.UpdatedAt.UTC()
	if binding.Binding.ApplicationID != request.ApplicationID || binding.Binding.Hostname != request.Hostname || binding.Binding.UpdatedAt.Format(time.RFC3339Nano) != payload.BindingUpdatedAt || binding.Binding.Validate() != nil {
		return fail(ErrDomainConvergenceConflict)
	}
	target, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.application_domain_id=$1`, request.ApplicationDomainID.String())
	if err != nil {
		return fail(err)
	}
	if len(target) != payload.TargetRouteCount || domainUnbindTargetRouteDigest(target) != payload.TargetRouteDigest {
		return fail(ErrDomainConvergenceConflict)
	}
	remaining, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active' AND COALESCE(r.application_domain_id,'') <> $1`, request.ApplicationDomainID.String())
	if err != nil {
		return fail(err)
	}
	if len(remaining) != payload.RemainingRouteCount || domainUnbindRemainingRouteDigest(remaining) != payload.RemainingRouteDigest {
		return fail(ErrDomainConvergenceConflict)
	}
	for _, route := range remaining {
		if err := validateDomainUnbindActiveProjection(route); err != nil {
			return fail(ErrDomainConvergenceConflict)
		}
	}
	if err := tx.Commit(); err != nil {
		return DomainUnbindWork{}, err
	}
	binding.Request = request
	binding.TargetRoutes = target
	binding.TargetRouteDigest = payload.TargetRouteDigest
	binding.TargetRouteCount = payload.TargetRouteCount
	binding.RemainingRoutes = remaining
	binding.RemainingRouteDigest = payload.RemainingRouteDigest
	binding.RemainingRouteCount = payload.RemainingRouteCount
	return binding, nil
}

// RestoreDomainUnbind acknowledges that Caddy has been rebuilt from the
// current durable active set after an outcome-unknown unbind conflict. It
// keeps the binding/routes intact and terminalizes only the original intent.
func (s *Store) RestoreDomainUnbind(ctx context.Context, id domain.ID, owner, digest string, count int, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(cause error) error { return rollbackTx(tx, cause) }
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if request.Kind != DomainConvergenceUnbind || !domainConvergenceLeaseMatches(request, owner, now) || !domainUnbindRestoreRequired(request.LastError) || (request.Phase != DomainConvergenceQueued && request.Phase != DomainConvergenceRecoveryRequired && request.Phase != DomainConvergenceUnbindRouteRemoved) {
		return fail(ErrDomainConvergenceConflict)
	}
	current, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active'`)
	if err != nil {
		return fail(err)
	}
	for _, route := range current {
		if err := validateDomainUnbindActiveProjection(route); err != nil {
			return fail(ErrDomainConvergenceConflict)
		}
	}
	if len(current) != count || domainUnbindRemainingRouteDigest(current) != digest {
		return fail(ErrDomainConvergenceConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='failed',status='failed',resume_phase=NULL,last_error='unbind_restore_completed',lease_owner=NULL,lease_until=NULL,updated_at=$1,completed_at=NULL WHERE id=$2 AND status='leased' AND lease_owner=$3 AND lease_until >= $1`, now, id.String(), owner)
	if err != nil {
		return fail(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	return tx.Commit()
}

func domainConvergenceActivationRestoreRequired(code string) bool {
	return code == "route_activation_restore_required"
}

// LoadDomainConvergenceActivationRestore reads the complete current durable
// active route set under the request lease. It intentionally includes IP
// fallback routes and excludes disabled/failed facts, matching startup rebuild
// semantics rather than trusting a prior Caddy payload.
func (s *Store) LoadDomainConvergenceActivationRestore(ctx context.Context, id domain.ID, owner string, now time.Time) (DomainConvergenceActivationRestore, error) {
	if err := s.requireDB(); err != nil {
		return DomainConvergenceActivationRestore{}, err
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainConvergenceActivationRestore{}, err
	}
	fail := func(cause error) (DomainConvergenceActivationRestore, error) {
		return DomainConvergenceActivationRestore{}, rollbackTx(tx, cause)
	}
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if request.Kind != DomainConvergenceConverge || !domainConvergenceLeaseMatches(request, owner, now) || request.Phase != DomainConvergenceRoutePrepared || !domainConvergenceActivationRestoreRequired(request.LastError) {
		return fail(ErrDomainConvergenceConflict)
	}
	routes, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active'`)
	if err != nil {
		return fail(err)
	}
	for _, route := range routes {
		if err := validateDomainUnbindActiveProjection(route); err != nil {
			return fail(ErrDomainConvergenceConflict)
		}
	}
	if err := tx.Commit(); err != nil {
		return DomainConvergenceActivationRestore{}, err
	}
	return DomainConvergenceActivationRestore{Request: request, Routes: routes, Digest: domainUnbindRemainingRouteDigest(routes), Count: len(routes)}, nil
}

// RestoreDomainConvergenceActivation acknowledges that Caddy was rebuilt from
// the current durable route facts. A matching CAS queues the original prepared
// request for a fresh Observe/Activate attempt; a drift leaves it recoverable.
func (s *Store) RestoreDomainConvergenceActivation(ctx context.Context, id domain.ID, owner, digest string, count int, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(cause error) error { return rollbackTx(tx, cause) }
	request, err := loadDomainConvergenceRequestForUpdate(ctx, tx, id)
	if err != nil {
		return fail(err)
	}
	if request.Kind != DomainConvergenceConverge || !domainConvergenceLeaseMatches(request, owner, now) || request.Phase != DomainConvergenceRoutePrepared || !domainConvergenceActivationRestoreRequired(request.LastError) || !domainConvergenceSHA256(digest) || count < 0 {
		return fail(ErrDomainConvergenceConflict)
	}
	routes, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active'`)
	if err != nil {
		return fail(err)
	}
	for _, route := range routes {
		if err := validateDomainUnbindActiveProjection(route); err != nil {
			return fail(ErrDomainConvergenceConflict)
		}
	}
	if len(routes) != count || domainUnbindRemainingRouteDigest(routes) != digest {
		return fail(ErrDomainConvergenceConflict)
	}
	prepared, err := currentDomainConvergencePreparedSnapshotTx(ctx, tx, request)
	if err != nil {
		return fail(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase=CASE WHEN attempt >= max_attempts THEN 'failed' ELSE 'route_prepared' END,status=CASE WHEN attempt >= max_attempts THEN 'failed' ELSE 'queued' END,result=$2,resume_phase=NULL,last_error=CASE WHEN attempt >= max_attempts THEN 'route_activation_restored_exhausted' ELSE 'route_activation_restored' END,lease_owner=NULL,lease_until=NULL,updated_at=$1,completed_at=NULL WHERE id=$3 AND status='leased' AND lease_owner=$4 AND lease_until >= $1 AND phase='route_prepared'`, now, []byte(prepared), id.String(), owner)
	if err != nil {
		return fail(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	return tx.Commit()
}

func currentDomainConvergencePreparedSnapshotTx(ctx context.Context, tx *sql.Tx, request DomainConvergenceRequest) (json.RawMessage, error) {
	routeID := DomainConvergenceRouteID(request.ApplicationDomainID)
	var applicationID, domainID, hostname, path, state string
	var verified bool
	var updatedAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT application_id,application_domain_id,hostname,path_prefix,desired_state,verified,updated_at FROM m3_desired_routes WHERE id=$1 FOR UPDATE`, routeID.String()).Scan(&applicationID, &domainID, &hostname, &path, &state, &verified, &updatedAt); err != nil {
		return nil, ErrDomainConvergenceConflict
	}
	if applicationID != request.ApplicationID.String() || domainID != request.ApplicationDomainID.String() || hostname != request.Hostname || path != "/" || !verified || (state != string(DesiredRoutePending) && state != string(DesiredRouteActive)) {
		return nil, ErrDomainConvergenceConflict
	}
	snapshot := domainConvergencePreparedSnapshot{RouteID: routeID.String(), RouteUpdatedAt: updatedAt.UTC().Format(time.RFC3339Nano)}
	var pointer RoutePointer
	err := tx.QueryRowContext(ctx, `SELECT route_id,deployment_id,port_lease_id,revision,updated_at FROM m3_route_pointers WHERE route_id=$1 FOR UPDATE`, routeID.String()).Scan(&pointer.RouteID, &pointer.DeploymentID, &pointer.PortLeaseID, &pointer.Revision, &pointer.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if state != string(DesiredRoutePending) {
			return nil, ErrDomainConvergenceConflict
		}
	} else if err != nil {
		return nil, err
	} else {
		if state != string(DesiredRouteActive) || pointer.RouteID != routeID || pointer.Revision < 1 {
			return nil, ErrDomainConvergenceConflict
		}
		snapshot.PointerDeploymentID = pointer.DeploymentID.String()
		snapshot.PointerLeaseID = pointer.PortLeaseID.String()
		snapshot.PointerRevision = pointer.Revision
	}
	return domainConvergencePreparedSnapshotJSON(snapshot)
}

func domainUnbindRestoreRequired(code string) bool {
	return code == "unbind_restore_required"
}

func (s *Store) MarkDomainUnbindRouteRemoved(ctx context.Context, id domain.ID, owner, remainingDigest string, remainingCount int, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(id, "domain unbind request id"); err != nil {
		return err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || !domainConvergenceSHA256(remainingDigest) || remainingCount < 0 {
		return domain.ValidationError("domain unbind removed result is invalid")
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(e error) error { return rollbackTx(tx, e) }
	var request DomainConvergenceRequest
	found, err := scanDomainConvergenceRequest(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE id=$1 FOR UPDATE`, id.String()), &request)
	if err != nil {
		return fail(err)
	}
	if !found || request.Kind != DomainConvergenceUnbind || request.Status != DomainConvergenceLeased || request.LeaseOwner != owner || request.LeaseUntil == nil || request.LeaseUntil.Before(now) || (request.Phase != DomainConvergenceQueued && request.Phase != DomainConvergenceRecoveryRequired) {
		return fail(ErrDomainConvergenceConflict)
	}
	payload, err := parseDomainUnbindPayload(request.Payload)
	if err != nil || payload.RemainingRouteDigest != remainingDigest || payload.RemainingRouteCount != remainingCount {
		return fail(ErrDomainConvergenceConflict)
	}
	target, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.application_domain_id=$1`, request.ApplicationDomainID.String())
	if err != nil || len(target) != payload.TargetRouteCount || domainUnbindTargetRouteDigest(target) != payload.TargetRouteDigest {
		return fail(ErrDomainConvergenceConflict)
	}
	remaining, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active' AND COALESCE(r.application_domain_id,'') <> $1`, request.ApplicationDomainID.String())
	if err != nil || len(remaining) != payload.RemainingRouteCount || domainUnbindRemainingRouteDigest(remaining) != payload.RemainingRouteDigest {
		return fail(ErrDomainConvergenceConflict)
	}
	for _, route := range remaining {
		if err := validateDomainUnbindActiveProjection(route); err != nil {
			return fail(ErrDomainConvergenceConflict)
		}
	}
	result := []byte(fmt.Sprintf(`{"remaining_route_digest":%q,"remaining_route_count":%d}`, remainingDigest, remainingCount))
	if _, err = tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='unbind_route_removed',result=$1,resume_phase=NULL,updated_at=$2 WHERE id=$3 AND status='leased' AND lease_owner=$4 AND phase=$5`, result, now, id.String(), owner, request.Phase); err != nil {
		return fail(err)
	}
	return tx.Commit()
}

// FinalizeDomainUnbind commits the local half of a custom-domain unbind only
// after the worker has already replaced Caddy with the frozen remaining route
// set.  It never calls an external provider.  Any changed durable fact is a
// conflict, so the transaction leaves the old binding/routes intact for a
// recovery worker to inspect.
//
// Platform bindings intentionally return a conflict here.  Their retention
// semantics are not interchangeable with a customer-controlled CNAME.
func (s *Store) FinalizeDomainUnbind(ctx context.Context, id domain.ID, owner string, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if err := domain.RequireID(id, "domain unbind request id"); err != nil {
		return err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return domain.ValidationError("domain unbind lease owner is required")
	}
	now = m3Now(s, now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(cause error) error { return rollbackTx(tx, cause) }

	var request DomainConvergenceRequest
	found, err := scanDomainConvergenceRequestWithActor(tx.QueryRowContext(ctx, `SELECT id,application_domain_id,application_id,hostname,request_kind,COALESCE(target_deployment_id,''),request_digest,idempotency_key,actor_type,actor_id,phase,status,COALESCE(resume_phase,''),COALESCE(lease_owner,''),lease_until,attempt,recovery_attempt,max_attempts,payload,result,COALESCE(last_error,''),created_at,updated_at,completed_at FROM m3_domain_convergence_requests WHERE id=$1 FOR UPDATE`, id.String()), &request)
	if err != nil {
		return fail(err)
	}
	if !found || request.Kind != DomainConvergenceUnbind {
		return fail(ErrDomainConvergenceConflict)
	}
	// A caller may have lost the acknowledgement after the DB commit.  Do not
	// recreate any business fact; accept only the already terminal request.
	if request.Phase == DomainConvergenceCompleted && request.Status == DomainConvergenceCompletedStatus && request.LeaseOwner == "" && request.LeaseUntil == nil {
		var stillBound bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m3_application_domains WHERE id=$1)`, request.ApplicationDomainID.String()).Scan(&stillBound); err != nil {
			return fail(err)
		}
		if stillBound {
			return fail(ErrDomainConvergenceConflict)
		}
		return tx.Commit()
	}
	if request.Phase != DomainConvergenceUnbindRouteRemoved || request.Status != DomainConvergenceLeased || request.LeaseOwner != owner || request.LeaseUntil == nil || request.LeaseUntil.Before(now) {
		return fail(ErrDomainConvergenceConflict)
	}
	payload, err := parseDomainUnbindPayload(request.Payload)
	if err != nil || payload.BindingID != request.ApplicationDomainID.String() {
		return fail(ErrDomainConvergenceConflict)
	}
	result, err := parseDomainUnbindRemovedResult(request.Result)
	if err != nil || result.RemainingRouteDigest != payload.RemainingRouteDigest || result.RemainingRouteCount != payload.RemainingRouteCount {
		return fail(ErrDomainConvergenceConflict)
	}

	var applicationID, hostname, kind string
	var bindingUpdatedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT application_id,hostname,domain_kind,updated_at FROM m3_application_domains WHERE id=$1 FOR UPDATE`, request.ApplicationDomainID.String()).Scan(&applicationID, &hostname, &kind, &bindingUpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrDomainConvergenceConflict)
	}
	if err != nil {
		return fail(err)
	}
	if kind != "custom" || applicationID != request.ApplicationID.String() || hostname != request.Hostname || bindingUpdatedAt.UTC().Format(time.RFC3339Nano) != payload.BindingUpdatedAt {
		return fail(ErrDomainConvergenceConflict)
	}

	target, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.application_domain_id=$1`, request.ApplicationDomainID.String())
	if err != nil {
		return fail(err)
	}
	if len(target) != payload.TargetRouteCount || domainUnbindTargetRouteDigest(target) != payload.TargetRouteDigest {
		return fail(ErrDomainConvergenceConflict)
	}
	remaining, err := loadDomainUnbindRouteProjectionsTx(ctx, tx, `r.desired_state='active' AND COALESCE(r.application_domain_id,'') <> $1`, request.ApplicationDomainID.String())
	if err != nil {
		return fail(err)
	}
	if len(remaining) != payload.RemainingRouteCount || domainUnbindRemainingRouteDigest(remaining) != payload.RemainingRouteDigest {
		return fail(ErrDomainConvergenceConflict)
	}
	for _, route := range remaining {
		if err := validateDomainUnbindActiveProjection(route); err != nil {
			return fail(ErrDomainConvergenceConflict)
		}
	}

	// A binding cannot be removed while it owns a non-observation certificate,
	// or while an observation is still referenced by a non-target route.  Check
	// this before mutating route rows so every such condition rolls back whole.
	certRows, err := tx.QueryContext(ctx, `SELECT id,secret_reference_id FROM m3_certificate_references WHERE application_domain_id=$1 FOR UPDATE`, request.ApplicationDomainID.String())
	if err != nil {
		return fail(err)
	}
	type certificateCandidate struct{ id, reference string }
	certificates := []certificateCandidate{}
	for certRows.Next() {
		var candidate certificateCandidate
		if err := certRows.Scan(&candidate.id, &candidate.reference); err != nil {
			certRows.Close()
			return fail(err)
		}
		if !strings.HasPrefix(candidate.reference, "edge-caddy-observation:") {
			certRows.Close()
			return fail(ErrDomainConvergenceConflict)
		}
		certificates = append(certificates, candidate)
	}
	if err := certRows.Err(); err != nil {
		certRows.Close()
		return fail(err)
	}
	if err := certRows.Close(); err != nil {
		return fail(err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM m3_route_pointers WHERE route_id IN (SELECT id FROM m3_desired_routes WHERE application_domain_id=$1)`, request.ApplicationDomainID.String()); err != nil {
		return fail(err)
	}
	// Keep the disabled route as an audit fact, but sever both binding and
	// certificate FKs before deleting the custom binding.
	updated, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET application_domain_id=NULL,certificate_reference_id=NULL,desired_state='disabled',serving=false,updated_at=$2 WHERE application_domain_id=$1`, request.ApplicationDomainID.String(), now)
	if err != nil {
		return fail(err)
	}
	changed, err := updated.RowsAffected()
	if err != nil || int(changed) != len(target) {
		if err != nil {
			return fail(err)
		}
		return fail(ErrDomainConvergenceConflict)
	}
	for _, certificate := range certificates {
		var referenced bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m3_desired_routes WHERE certificate_reference_id=$1)`, certificate.id).Scan(&referenced); err != nil {
			return fail(err)
		}
		if !domainUnbindObservationCertificateDeletable(certificate.reference, referenced) {
			return fail(ErrDomainConvergenceConflict)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM m3_certificate_references WHERE id=$1 AND application_domain_id=$2 AND secret_reference_id LIKE 'edge-caddy-observation:%'`, certificate.id, request.ApplicationDomainID.String()); err != nil {
			return fail(err)
		}
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM m3_application_domains WHERE id=$1 AND domain_kind='custom'`, request.ApplicationDomainID.String())
	if err != nil {
		return fail(err)
	}
	changed, err = deleted.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return fail(err)
		}
		return fail(ErrDomainConvergenceConflict)
	}
	if err := appendDomainConvergenceAuditTx(ctx, tx, request, "domain.unbind.completed", "", now); err != nil {
		return fail(err)
	}
	completed, err := tx.ExecContext(ctx, `UPDATE m3_domain_convergence_requests SET phase='completed',status='completed',resume_phase=NULL,lease_owner=NULL,lease_until=NULL,updated_at=$1,completed_at=$1 WHERE id=$2 AND request_kind='unbind' AND phase='unbind_route_removed' AND status='leased' AND lease_owner=$3`, now, id.String(), owner)
	if err != nil {
		return fail(err)
	}
	changed, err = completed.RowsAffected()
	if err != nil || changed != 1 {
		return fail(ErrDomainConvergenceConflict)
	}
	return tx.Commit()
}

func (s *Store) selectDomainConvergenceRuntimeTargetTx(ctx context.Context, tx *sql.Tx, applicationID domain.ID) (DomainConvergenceRuntimeTarget, error) {
	return selectDomainConvergenceRuntimeTarget(ctx, tx.QueryRowContext, applicationID)
}

func selectDomainConvergenceRuntimeTarget(ctx context.Context, query func(context.Context, string, ...any) *sql.Row, applicationID domain.ID) (DomainConvergenceRuntimeTarget, error) {
	var target DomainConvergenceRuntimeTarget
	var entry sql.NullString
	err := query(ctx, `
		WITH candidate AS (
			SELECT d.id AS deployment_id,e.application_id,d.release_id,r.version,
			       d.runtime_healthy,COALESCE(host(d.host_ip),'') AS host_ip,COALESCE(d.host_port,0) AS host_port,
			       m2.spec,m2.canonical_digest,r.canonical_digest AS release_digest
			  FROM deployments d
			  JOIN environments e ON e.id=d.environment_id
			  JOIN releases r ON r.id=d.release_id
			  LEFT JOIN m2_release_runtime_specs m2 ON m2.release_id=d.release_id
			 WHERE e.application_id=$1 AND d.state IN ('runtime_ready','degraded','serving')
			 ORDER BY d.updated_at DESC,d.id DESC LIMIT 1
		), m2_target AS (
			SELECT c.application_id,c.deployment_id,c.version,
			       NULLIF(c.spec->>'entry_service','') AS service_name,
			       c.canonical_digest AS runtime_digest
			  FROM candidate c
			 WHERE c.runtime_healthy=true
			   AND NULLIF(c.spec->>'entry_service','') IS NOT NULL
			   AND c.canonical_digest ~ '^sha256:[0-9a-f]{64}$'
			   AND EXISTS (
			       SELECT 1 FROM jsonb_array_elements(COALESCE(c.spec->'services','[]'::jsonb)) service
			        WHERE service->>'name'=NULLIF(c.spec->>'entry_service','')
			   )
		), legacy_target AS (
			SELECT c.application_id,c.deployment_id,c.version,artifacts.service_name,
			       c.release_digest AS runtime_digest,c.host_port
			  FROM candidate c
			  JOIN LATERAL (
			      SELECT min(service_name) AS service_name,count(*) AS service_count
			        FROM release_artifacts
			       WHERE release_id=c.release_id
			  ) artifacts ON artifacts.service_count=1
			 WHERE c.runtime_healthy=true
			   AND c.host_ip='127.0.0.1'
			   AND c.host_port BETWEEN 1 AND 65535
			   AND c.release_digest ~ '^sha256:[0-9a-f]{64}$'
			   AND NOT EXISTS (
			       SELECT 1 FROM jsonb_array_elements(COALESCE(c.spec->'services','[]'::jsonb)) service
			        WHERE NULLIF(c.spec->>'entry_service','') IS NOT NULL
			          AND service->>'name'=NULLIF(c.spec->>'entry_service','')
			   )
		)
		SELECT m2.application_id,m2.deployment_id,m2.service_name,observed.host_port,m2.version,m2.runtime_digest
		  FROM m2_target m2
		  JOIN LATERAL (
		      SELECT host_port FROM m4_service_observations observed
		       WHERE observed.deployment_id=m2.deployment_id
		         AND observed.service_name=m2.service_name
		         AND observed.healthy=true AND observed.host_port BETWEEN 1 AND 65535
		       ORDER BY observed.observed_at DESC,observed.id DESC LIMIT 1
		  ) observed ON true
		UNION ALL
		SELECT legacy.application_id,legacy.deployment_id,legacy.service_name,legacy.host_port,legacy.version,legacy.runtime_digest
		  FROM legacy_target legacy
	`, applicationID.String()).Scan(&target.ApplicationID, &target.DeploymentID, &entry, &target.Port, &target.ReleaseVersion, &target.RuntimeDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return DomainConvergenceRuntimeTarget{}, ErrNotFound
	}
	if err != nil {
		return DomainConvergenceRuntimeTarget{}, fmt.Errorf("select domain convergence runtime target: %w", err)
	}
	target.ServiceName, target.Path = entry.String, "/"
	if target.ApplicationID != applicationID || !domainConvergenceTargetValid(target) {
		return DomainConvergenceRuntimeTarget{}, domain.NewError(domain.ErrConflict, "domain convergence runtime target is incomplete")
	}
	return target, nil
}
