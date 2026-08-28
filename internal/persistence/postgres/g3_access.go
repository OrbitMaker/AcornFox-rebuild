package postgres

// G3 access queries reuse the durable M3 domain, certificate, route, and
// deployment tables. They add no DNS provider, credential, or Caddy write
// surface; public DNS verification remains in the controller's injected
// read-only contract.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

var ErrG3AccessConflict = errors.New("g3 access conflict")

type G3VerificationStatus string

const (
	G3VerificationPending  G3VerificationStatus = "pending"
	G3VerificationVerified G3VerificationStatus = "verified"
	G3VerificationFailed   G3VerificationStatus = "failed"
)

type G3CertificateFact struct {
	ID       domain.ID
	Status   string
	Subject  string
	NotAfter *time.Time
}

type G3PlatformDomainFact struct {
	ID                 domain.ID
	BaseDomain         string
	VerificationStatus G3VerificationStatus
	VerifiedAt         *time.Time
	Certificate        *G3CertificateFact
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type G3ApplicationDomainFact struct {
	ID                 domain.ID
	ApplicationID      domain.ID
	Hostname           string
	Kind               string
	CNAME              string
	VerificationStatus G3VerificationStatus
	VerifiedAt         *time.Time
	Certificate        *G3CertificateFact
	Serving            bool
	RouteID            domain.ID
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type G3RouteFact struct {
	ID          domain.ID
	DomainID    domain.ID
	Hostname    string
	Desired     bool
	Serving     bool
	Certificate *G3CertificateFact
}

type G3RuntimeFact struct {
	RuntimeReady bool
	IPFallback   *string
}

type G3ApplicationAccessFacts struct {
	Runtime G3RuntimeFact
	Routes  []G3RouteFact
}

type G3Idempotency struct {
	Scope  string
	Key    string
	Digest string
}

func (s *Store) ReplayG3Idempotency(ctx context.Context, request G3Idempotency) ([]byte, bool, error) {
	if err := s.requireDB(); err != nil {
		return nil, false, err
	}
	if err := validateG3Idempotency(request); err != nil {
		return nil, false, err
	}
	var digest, status string
	var response []byte
	err := s.db.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=$1 AND idempotency_key=$2`, request.Scope, request.Key).Scan(&digest, &status, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if digest != request.Digest {
		return nil, false, ErrIdempotencyConflict
	}
	if status == "completed" && json.Valid(response) {
		return append([]byte(nil), response...), true, nil
	}
	if status == "in_progress" {
		return nil, false, ErrIdempotencyInProgress
	}
	return nil, false, ErrIdempotencyCorrupt
}

func validateG3Idempotency(request G3Idempotency) error {
	request.Scope, request.Key, request.Digest = strings.TrimSpace(request.Scope), strings.TrimSpace(request.Key), strings.TrimSpace(request.Digest)
	if request.Scope == "" || request.Key == "" || len(request.Digest) != len("sha256:")+64 || !strings.HasPrefix(request.Digest, "sha256:") {
		return domain.ValidationError("G3 idempotency scope, key, and request digest are required")
	}
	for _, character := range request.Digest[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return domain.ValidationError("G3 idempotency digest is invalid")
		}
	}
	return nil
}

func reserveG3IdempotencyTx(ctx context.Context, tx *sql.Tx, request G3Idempotency, now time.Time) ([]byte, bool, error) {
	if err := validateG3Idempotency(request); err != nil {
		return nil, false, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,$3,'in_progress',$4,$4) ON CONFLICT(scope,idempotency_key) DO NOTHING`, request.Scope, request.Key, request.Digest, now.UTC())
	if err != nil {
		return nil, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if inserted == 1 {
		return nil, false, nil
	}
	var digest, status string
	var response []byte
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=$1 AND idempotency_key=$2 FOR UPDATE`, request.Scope, request.Key).Scan(&digest, &status, &response); err != nil {
		return nil, false, err
	}
	if digest != request.Digest {
		return nil, false, ErrIdempotencyConflict
	}
	if status == "completed" && json.Valid(response) {
		return append([]byte(nil), response...), true, nil
	}
	if status == "in_progress" {
		return nil, false, ErrIdempotencyInProgress
	}
	return nil, false, ErrIdempotencyCorrupt
}

func completeG3IdempotencyTx(ctx context.Context, tx *sql.Tx, request G3Idempotency, response any, now time.Time) error {
	payload, err := json.Marshal(response)
	if err != nil || !json.Valid(payload) {
		if err != nil {
			return err
		}
		return ErrIdempotencyCorrupt
	}
	result, err := tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=$4::jsonb,updated_at=$5 WHERE scope=$1 AND idempotency_key=$2 AND request_digest=$3 AND status='in_progress'`, request.Scope, request.Key, request.Digest, payload, now.UTC())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrIdempotencyCorrupt
	}
	return nil
}

func (s *Store) ApplicationName(ctx context.Context, applicationID domain.ID) (string, bool, error) {
	if err := s.requireDB(); err != nil {
		return "", false, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return "", false, err
	}
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM applications WHERE id=$1`, applicationID.String()).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read application name: %w", err)
	}
	return name, true, nil
}

func (s *Store) PlatformDomain(ctx context.Context) (G3PlatformDomainFact, bool, error) {
	if err := s.requireDB(); err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,hostname,verification_status,verified_at,created_at,updated_at FROM m3_platform_domains ORDER BY created_at,id`)
	if err != nil {
		return G3PlatformDomainFact{}, false, fmt.Errorf("list platform domains: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return G3PlatformDomainFact{}, false, rows.Err()
	}
	fact, err := scanG3PlatformDomain(rows)
	if err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	if rows.Next() {
		return G3PlatformDomainFact{}, false, ErrG3AccessConflict
	}
	if err := rows.Err(); err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	fact.Certificate, err = s.g3PlatformCertificate(ctx, fact.ID)
	if err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	return fact, true, nil
}

func (s *Store) PutPlatformDomain(ctx context.Context, fact G3PlatformDomainFact, request G3Idempotency) (G3PlatformDomainFact, bool, error) {
	if err := s.requireDB(); err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	if err := domain.RequireID(fact.ID, "platform domain id"); err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	base, err := NormalizeM3Hostname(fact.BaseDomain)
	if err != nil || base != fact.BaseDomain {
		if err != nil {
			return G3PlatformDomainFact{}, false, err
		}
		return G3PlatformDomainFact{}, false, domain.ValidationError("platform base domain must be normalized")
	}
	if !g3VerificationStatus(fact.VerificationStatus) {
		return G3PlatformDomainFact{}, false, domain.ValidationError("platform verification status is unsupported")
	}
	now := fact.UpdatedAt.UTC()
	if now.IsZero() {
		now = m3Now(s, time.Time{})
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	rollback := func(cause error) (G3PlatformDomainFact, bool, error) {
		return G3PlatformDomainFact{}, false, rollbackTx(tx, cause)
	}
	stored, replay, err := reserveG3IdempotencyTx(ctx, tx, request, now)
	if err != nil {
		return rollback(err)
	}
	if replay {
		var value G3PlatformDomainFact
		if err := json.Unmarshal(stored, &value); err != nil || value.ID.Empty() {
			return rollback(ErrIdempotencyCorrupt)
		}
		if err := tx.Commit(); err != nil {
			return G3PlatformDomainFact{}, false, err
		}
		return value, true, nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('open-card-g3-platform-domain-singleton',0))`); err != nil {
		return rollback(err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,hostname FROM m3_platform_domains ORDER BY created_at,id FOR UPDATE`)
	if err != nil {
		return rollback(err)
	}
	var existingID, existingHost string
	if rows.Next() {
		if err := rows.Scan(&existingID, &existingHost); err != nil {
			rows.Close()
			return rollback(err)
		}
		if rows.Next() {
			rows.Close()
			return rollback(ErrG3AccessConflict)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return rollback(err)
	}
	rows.Close()
	if existingID != "" && existingHost != base {
		return rollback(ErrG3AccessConflict)
	}
	if existingID == "" {
		created := fact.CreatedAt.UTC()
		if created.IsZero() {
			created = now
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO m3_platform_domains(id,hostname,dns_provider_ref,verification_status,wildcard_enabled,verification_ref,verified_at,created_at,updated_at) VALUES($1,$2,'public-dns-read-only',$3,false,'public-dns-read-only',$4,$5,$6)`, fact.ID.String(), base, fact.VerificationStatus, fact.VerifiedAt, created, now)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE m3_platform_domains SET verification_status=$2,wildcard_enabled=false,verification_ref='public-dns-read-only',verified_at=$3,updated_at=$4 WHERE id=$1`, existingID, fact.VerificationStatus, fact.VerifiedAt, now)
	}
	if err != nil {
		return rollback(err)
	}
	if existingID != "" {
		fact.ID = domain.ID(existingID)
	}
	fact.BaseDomain, fact.UpdatedAt = base, now
	if err := completeG3IdempotencyTx(ctx, tx, request, fact, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return G3PlatformDomainFact{}, false, err
	}
	return fact, false, nil
}

func (s *Store) ListApplicationDomains(ctx context.Context, applicationID domain.ID) ([]G3ApplicationDomainFact, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id,d.application_id,d.hostname,d.domain_kind,COALESCE(d.verification_ref,''),d.verification_status,d.verified_at,d.created_at,d.updated_at,
		       route.id,COALESCE(route.serving,false),
		       cert.id,cert.status,cert.subject_hostname,cert.not_after
		  FROM m3_application_domains d
		  LEFT JOIN LATERAL (
			SELECT id,serving FROM m3_desired_routes
			 WHERE application_domain_id=d.id AND desired_state NOT IN ('disabled','failed')
			 ORDER BY serving DESC,updated_at DESC,id LIMIT 1
		  ) route ON true
		  LEFT JOIN LATERAL (
			SELECT id,status,subject_hostname,not_after FROM m3_certificate_references
			 WHERE application_domain_id=d.id ORDER BY updated_at DESC,id DESC LIMIT 1
		  ) cert ON true
		 WHERE d.application_id=$1
		 ORDER BY d.created_at,d.id
	`, applicationID.String())
	if err != nil {
		return nil, fmt.Errorf("list application domains: %w", err)
	}
	defer rows.Close()
	items := make([]G3ApplicationDomainFact, 0)
	for rows.Next() {
		item, err := scanG3ApplicationDomain(rows)
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

func (s *Store) ApplicationDomain(ctx context.Context, applicationID, domainID domain.ID) (G3ApplicationDomainFact, bool, error) {
	items, err := s.ListApplicationDomains(ctx, applicationID)
	if err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	for _, item := range items {
		if item.ID == domainID {
			return item, true, nil
		}
	}
	return G3ApplicationDomainFact{}, false, nil
}

func (s *Store) BindCustomDomain(ctx context.Context, fact G3ApplicationDomainFact, request G3Idempotency) (G3ApplicationDomainFact, bool, error) {
	if err := s.requireDB(); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	if err := domain.RequireID(fact.ID, "application domain id"); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	if err := domain.RequireID(fact.ApplicationID, "application domain application id"); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	host, err := NormalizeM3Hostname(fact.Hostname)
	if err != nil || host != fact.Hostname || fact.Kind != "custom" {
		if err != nil {
			return G3ApplicationDomainFact{}, false, err
		}
		return G3ApplicationDomainFact{}, false, domain.ValidationError("custom domain is malformed")
	}
	cname, err := NormalizeM3Hostname(fact.CNAME)
	if err != nil || cname != fact.CNAME {
		if err != nil {
			return G3ApplicationDomainFact{}, false, err
		}
		return G3ApplicationDomainFact{}, false, domain.ValidationError("custom domain CNAME target is malformed")
	}
	now := fact.UpdatedAt.UTC()
	if now.IsZero() {
		now = m3Now(s, time.Time{})
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	rollback := func(cause error) (G3ApplicationDomainFact, bool, error) {
		return G3ApplicationDomainFact{}, false, rollbackTx(tx, cause)
	}
	stored, replay, err := reserveG3IdempotencyTx(ctx, tx, request, now)
	if err != nil {
		return rollback(err)
	}
	if replay {
		var value G3ApplicationDomainFact
		if err := json.Unmarshal(stored, &value); err != nil || value.ID.Empty() {
			return rollback(ErrIdempotencyCorrupt)
		}
		if err := tx.Commit(); err != nil {
			return G3ApplicationDomainFact{}, false, err
		}
		return value, false, nil
	}
	var existingID, existingApplication, existingCNAME string
	var existingStatus G3VerificationStatus
	var existingVerified sql.NullTime
	var existingCreated, existingUpdated time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,application_id,COALESCE(verification_ref,''),verification_status,verified_at,created_at,updated_at FROM m3_application_domains WHERE hostname=$1 FOR UPDATE`, host).Scan(&existingID, &existingApplication, &existingCNAME, &existingStatus, &existingVerified, &existingCreated, &existingUpdated)
	if err == nil {
		if existingApplication != fact.ApplicationID.String() {
			return rollback(ErrG3AccessConflict)
		}
		if existingCNAME != cname {
			return rollback(ErrG3AccessConflict)
		}
		fact.ID, fact.CNAME, fact.VerificationStatus, fact.CreatedAt, fact.UpdatedAt = domain.ID(existingID), existingCNAME, existingStatus, existingCreated.UTC(), existingUpdated.UTC()
		if existingVerified.Valid {
			value := existingVerified.Time.UTC()
			fact.VerifiedAt = &value
		}
		if err := completeG3IdempotencyTx(ctx, tx, request, fact, now); err != nil {
			return rollback(err)
		}
		if err := tx.Commit(); err != nil {
			return G3ApplicationDomainFact{}, false, err
		}
		return fact, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	created := fact.CreatedAt.UTC()
	if created.IsZero() {
		created = now
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO m3_application_domains(id,application_id,platform_domain_id,hostname,domain_kind,stable_slug,verification_method,verification_status,verification_ref,verified_at,created_at,updated_at) VALUES($1,$2,NULL,$3,'custom',NULL,'cname','pending',$4,NULL,$5,$5)`, fact.ID.String(), fact.ApplicationID.String(), host, cname, created)
	if err != nil {
		return rollback(g3MapWriteConflict(err))
	}
	fact.CNAME, fact.VerificationStatus, fact.CreatedAt, fact.UpdatedAt = cname, G3VerificationPending, created, now
	if err := completeG3IdempotencyTx(ctx, tx, request, fact, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	return fact, true, nil
}

func (s *Store) SetApplicationDomainVerification(ctx context.Context, applicationID, domainID domain.ID, status G3VerificationStatus, verifiedAt *time.Time, request G3Idempotency) (G3ApplicationDomainFact, bool, error) {
	if err := s.requireDB(); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	if !g3VerificationStatus(status) {
		return G3ApplicationDomainFact{}, false, domain.ValidationError("application domain verification status is unsupported")
	}
	if status == G3VerificationVerified && verifiedAt == nil {
		return G3ApplicationDomainFact{}, false, domain.ValidationError("verified application domain requires an observation timestamp")
	}
	if status != G3VerificationVerified {
		verifiedAt = nil
	}
	now := m3Now(s, time.Time{})
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	rollback := func(cause error) (G3ApplicationDomainFact, bool, error) {
		return G3ApplicationDomainFact{}, false, rollbackTx(tx, cause)
	}
	stored, replay, err := reserveG3IdempotencyTx(ctx, tx, request, now)
	if err != nil {
		return rollback(err)
	}
	if replay {
		var value G3ApplicationDomainFact
		if err := json.Unmarshal(stored, &value); err != nil || value.ID.Empty() {
			return rollback(ErrIdempotencyCorrupt)
		}
		if err := tx.Commit(); err != nil {
			return G3ApplicationDomainFact{}, false, err
		}
		return value, true, nil
	}
	var fact G3ApplicationDomainFact
	var existingVerified sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,application_id,hostname,domain_kind,COALESCE(verification_ref,''),created_at,updated_at FROM m3_application_domains WHERE id=$1 AND application_id=$2 FOR UPDATE`, domainID.String(), applicationID.String()).Scan(&fact.ID, &fact.ApplicationID, &fact.Hostname, &fact.Kind, &fact.CNAME, &fact.CreatedAt, &fact.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(domain.NewError(domain.ErrNotFound, "application domain not found"))
	}
	if err != nil {
		return rollback(err)
	}
	_ = existingVerified
	result, err := tx.ExecContext(ctx, `UPDATE m3_application_domains SET verification_status=$3,verified_at=$4,updated_at=$5 WHERE id=$1 AND application_id=$2`, domainID.String(), applicationID.String(), status, verifiedAt, now)
	if err != nil {
		return rollback(err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return rollback(domain.NewError(domain.ErrNotFound, "application domain not found"))
	}
	fact.VerificationStatus, fact.VerifiedAt, fact.UpdatedAt = status, verifiedAt, now
	if err := completeG3IdempotencyTx(ctx, tx, request, fact, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return G3ApplicationDomainFact{}, false, err
	}
	return fact, false, nil
}

func (s *Store) UnbindCustomDomain(ctx context.Context, applicationID, domainID domain.ID, actor string, request G3Idempotency) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	if strings.TrimSpace(actor) == "" {
		return false, domain.NewError(domain.ErrUnauthorized, "authenticated administrator identity is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	rollback := func(cause error) (bool, error) { return false, rollbackTx(tx, cause) }
	now := m3Now(s, time.Time{})
	_, replay, err := reserveG3IdempotencyTx(ctx, tx, request, now)
	if err != nil {
		return rollback(err)
	}
	if replay {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return true, nil
	}
	var kind string
	err = tx.QueryRowContext(ctx, `SELECT domain_kind FROM m3_application_domains WHERE id=$1 AND application_id=$2 FOR UPDATE`, domainID.String(), applicationID.String()).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(domain.NewError(domain.ErrNotFound, "application domain not found"))
	}
	if err != nil {
		return rollback(err)
	}
	if kind != "custom" {
		return rollback(ErrG3AccessConflict)
	}
	var servingRoute, readyCertificate bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m3_desired_routes WHERE application_domain_id=$1 AND serving), EXISTS(SELECT 1 FROM m3_certificate_references WHERE application_domain_id=$1 AND status='ready')`, domainID.String()).Scan(&servingRoute, &readyCertificate); err != nil {
		return rollback(err)
	}
	if servingRoute || readyCertificate {
		return rollback(ErrG3AccessConflict)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m3_desired_routes SET application_domain_id=NULL,certificate_reference_id=NULL,desired_state='disabled',serving=false,updated_at=$2 WHERE application_domain_id=$1`, domainID.String(), now); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM m3_certificate_references WHERE application_domain_id=$1`, domainID.String()); err != nil {
		return rollback(err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM m3_application_domains WHERE id=$1 AND application_id=$2`, domainID.String(), applicationID.String())
	if err != nil {
		return rollback(err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return rollback(domain.NewError(domain.ErrNotFound, "application domain not found"))
	}
	if err := completeG3IdempotencyTx(ctx, tx, request, map[string]bool{"unbound": true}, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) ApplicationAccessFacts(ctx context.Context, applicationID domain.ID) (G3ApplicationAccessFacts, error) {
	if err := s.requireDB(); err != nil {
		return G3ApplicationAccessFacts{}, err
	}
	result := G3ApplicationAccessFacts{}
	var state string
	var healthy bool
	var host sql.NullString
	var port sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT d.state,d.runtime_healthy,d.host_ip,d.host_port
		  FROM deployments d JOIN environments e ON e.id=d.environment_id
		 WHERE e.application_id=$1
		 ORDER BY d.updated_at DESC,d.id DESC LIMIT 1
	`, applicationID.String()).Scan(&state, &healthy, &host, &port)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return G3ApplicationAccessFacts{}, err
	}
	if err == nil && healthy && (state == "runtime_ready" || state == "degraded" || state == "serving") {
		result.Runtime.RuntimeReady = true
		if ip := net.ParseIP(host.String); ip != nil && port.Valid && port.Int64 > 0 && port.Int64 <= 65535 {
			address := "http://" + net.JoinHostPort(ip.String(), strconv.FormatInt(port.Int64, 10))
			result.Runtime.IPFallback = &address
		}
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id,COALESCE(r.application_domain_id,''),r.hostname,
		       (r.desired_state IN ('pending','active') AND r.verified),
		       (r.desired_state='active' AND r.verified AND r.serving),
		       cert.id,cert.status,cert.subject_hostname,cert.not_after
		  FROM m3_desired_routes r
		  LEFT JOIN m3_certificate_references cert ON cert.id=r.certificate_reference_id
		 WHERE r.application_id=$1
		 ORDER BY r.updated_at DESC,r.id
	`, applicationID.String())
	if err != nil {
		return G3ApplicationAccessFacts{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var route G3RouteFact
		var domainID sql.NullString
		var certificateID, certificateStatus, certificateSubject sql.NullString
		var certificateNotAfter sql.NullTime
		if err := rows.Scan(&route.ID, &domainID, &route.Hostname, &route.Desired, &route.Serving, &certificateID, &certificateStatus, &certificateSubject, &certificateNotAfter); err != nil {
			return G3ApplicationAccessFacts{}, err
		}
		if domainID.Valid {
			route.DomainID = domain.ID(domainID.String)
		}
		if certificateID.Valid {
			route.Certificate = g3CertificateFact(certificateID, certificateStatus, certificateSubject, certificateNotAfter)
		}
		result.Routes = append(result.Routes, route)
	}
	if err := rows.Err(); err != nil {
		return G3ApplicationAccessFacts{}, err
	}
	return result, nil
}

func scanG3PlatformDomain(scanner interface{ Scan(...any) error }) (G3PlatformDomainFact, error) {
	var fact G3PlatformDomainFact
	var verified sql.NullTime
	if err := scanner.Scan(&fact.ID, &fact.BaseDomain, &fact.VerificationStatus, &verified, &fact.CreatedAt, &fact.UpdatedAt); err != nil {
		return G3PlatformDomainFact{}, err
	}
	if !g3VerificationStatus(fact.VerificationStatus) {
		return G3PlatformDomainFact{}, domain.NewError(domain.ErrConflict, "platform domain has an unsupported verification state")
	}
	if verified.Valid {
		value := verified.Time.UTC()
		fact.VerifiedAt = &value
	}
	fact.CreatedAt, fact.UpdatedAt = fact.CreatedAt.UTC(), fact.UpdatedAt.UTC()
	return fact, nil
}

func scanG3ApplicationDomain(scanner interface{ Scan(...any) error }) (G3ApplicationDomainFact, error) {
	var fact G3ApplicationDomainFact
	var verified sql.NullTime
	var routeID sql.NullString
	var certificateID, certificateStatus, certificateSubject sql.NullString
	var certificateNotAfter sql.NullTime
	if err := scanner.Scan(&fact.ID, &fact.ApplicationID, &fact.Hostname, &fact.Kind, &fact.CNAME, &fact.VerificationStatus, &verified, &fact.CreatedAt, &fact.UpdatedAt, &routeID, &fact.Serving, &certificateID, &certificateStatus, &certificateSubject, &certificateNotAfter); err != nil {
		return G3ApplicationDomainFact{}, err
	}
	if !g3VerificationStatus(fact.VerificationStatus) {
		return G3ApplicationDomainFact{}, domain.NewError(domain.ErrConflict, "application domain has an unsupported verification state")
	}
	if verified.Valid {
		value := verified.Time.UTC()
		fact.VerifiedAt = &value
	}
	if routeID.Valid {
		fact.RouteID = domain.ID(routeID.String)
	}
	if certificateID.Valid {
		fact.Certificate = g3CertificateFact(certificateID, certificateStatus, certificateSubject, certificateNotAfter)
	}
	fact.CreatedAt, fact.UpdatedAt = fact.CreatedAt.UTC(), fact.UpdatedAt.UTC()
	return fact, nil
}

func (s *Store) g3PlatformCertificate(ctx context.Context, platformID domain.ID) (*G3CertificateFact, error) {
	var id, status, subject sql.NullString
	var notAfter sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,status,subject_hostname,not_after FROM m3_certificate_references WHERE platform_domain_id=$1 ORDER BY updated_at DESC,id DESC LIMIT 1`, platformID.String()).Scan(&id, &status, &subject, &notAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g3CertificateFact(id, status, subject, notAfter), nil
}

func g3CertificateFact(id, status, subject sql.NullString, notAfter sql.NullTime) *G3CertificateFact {
	if !id.Valid {
		return nil
	}
	fact := &G3CertificateFact{ID: domain.ID(id.String), Status: status.String, Subject: subject.String}
	if notAfter.Valid {
		value := notAfter.Time.UTC()
		fact.NotAfter = &value
	}
	return fact
}

func g3VerificationStatus(value G3VerificationStatus) bool {
	return value == G3VerificationPending || value == G3VerificationVerified || value == G3VerificationFailed
}

func g3MapWriteConflict(err error) error {
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "unique") || strings.Contains(text, "duplicate") || strings.Contains(text, "conflict") {
		return ErrG3AccessConflict
	}
	return err
}
