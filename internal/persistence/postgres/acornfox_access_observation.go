package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const acornFoxAccessObservationSelect = `SELECT report_id,hostname,observed_at,received_at,expires_at,dns,tls,https,report_digest,owner_admin_id FROM acornfox_access_observations`

// CreateAcornFoxAccessObservation appends an administrator-client fact for the
// exact currently desired public route. replayed is true only when the same
// administrator repeats the same canonical report_id payload; the persisted
// timestamps are returned unchanged.
func (s *Store) CreateAcornFoxAccessObservation(ctx context.Context, applicationID, deploymentID, ownerAdminID domain.ID, report contracts.AcornFoxAccessObservationReport, now time.Time) (contracts.AcornFoxAccessObservation, bool, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, domain.ValidationError("access observation target is invalid")
	}
	if err := domain.RequireID(deploymentID, "deployment id"); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, domain.ValidationError("access observation target is invalid")
	}
	if err := domain.RequireID(ownerAdminID, "administrator id"); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, domain.ValidationError("access observation administrator is invalid")
	}
	canonical, err := report.Canonical()
	if err != nil {
		return contracts.AcornFoxAccessObservation{}, false, domain.ValidationError("access observation report is invalid")
	}
	now = acornFoxAccessObservationNow(s, now)
	payload, err := json.Marshal(canonical)
	if err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	digestBytes := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	fail := func(cause error) (contracts.AcornFoxAccessObservation, bool, error) {
		return contracts.AcornFoxAccessObservation{}, false, rollbackTx(tx, cause)
	}
	hostname, available, err := acornFoxAccessObservationTargetTx(ctx, tx, applicationID, deploymentID, true)
	if err != nil {
		return fail(err)
	}
	if !available {
		return fail(domain.NewError(domain.ErrConflict, "public access is not enabled"))
	}
	existing, storedDigest, storedOwner, err := scanAcornFoxAccessObservation(tx.QueryRowContext(ctx, acornFoxAccessObservationSelect+` WHERE application_id=$1 AND deployment_id=$2 AND report_id=$3`, applicationID.String(), deploymentID.String(), canonical.ReportID), applicationID, deploymentID)
	if err == nil {
		if existing.Hostname != hostname || storedDigest != digest || storedOwner != ownerAdminID.String() {
			return fail(ErrIdempotencyConflict)
		}
		if err := tx.Commit(); err != nil {
			return contracts.AcornFoxAccessObservation{}, false, err
		}
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}
	// The freshness window admits only a new observation. A later exact replay
	// above remains stable and never refreshes its server timestamps or expiry.
	if canonical.ObservedAt.Before(now.Add(-15*time.Minute)) || canonical.ObservedAt.After(now.Add(time.Minute)) {
		return fail(domain.ValidationError("access observation time is invalid"))
	}
	dns, err := json.Marshal(canonical.DNS)
	if err != nil {
		return fail(err)
	}
	tls, err := json.Marshal(canonical.TLS)
	if err != nil {
		return fail(err)
	}
	https, err := json.Marshal(canonical.HTTPS)
	if err != nil {
		return fail(err)
	}
	expiresAt := now.Add(contracts.AcornFoxAccessObservationLifetime)
	result, err := tx.ExecContext(ctx, `
		INSERT INTO acornfox_access_observations(
			application_id,deployment_id,report_id,report_digest,owner_admin_id,
			hostname,observed_at,received_at,expires_at,dns,tls,https
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb)
		ON CONFLICT (application_id,deployment_id,report_id) DO NOTHING
	`, applicationID.String(), deploymentID.String(), canonical.ReportID, digest, ownerAdminID.String(), hostname, canonical.ObservedAt, now, expiresAt, dns, tls, https)
	if err != nil {
		return fail(fmt.Errorf("insert access observation: %w", err))
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fail(err)
	}

	observation, storedDigest, storedOwner, err := scanAcornFoxAccessObservation(tx.QueryRowContext(ctx, acornFoxAccessObservationSelect+` WHERE application_id=$1 AND deployment_id=$2 AND report_id=$3`, applicationID.String(), deploymentID.String(), canonical.ReportID), applicationID, deploymentID)
	if err != nil {
		return fail(err)
	}
	if observation.Hostname != hostname {
		return fail(domain.NewError(domain.ErrConflict, "access observation target changed"))
	}
	if inserted == 0 && (storedDigest != digest || storedOwner != ownerAdminID.String()) {
		return fail(ErrIdempotencyConflict)
	}
	if inserted != 0 && inserted != 1 {
		return fail(fmt.Errorf("unexpected access observation insert count %d", inserted))
	}
	if err := tx.Commit(); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	return observation, inserted == 0, nil
}

// GetCurrentAcornFoxAccessObservation returns the latest fact for the exact
// current route even after it expires, allowing the HTTP projection to
// distinguish expired from never observed.
func (s *Store) GetCurrentAcornFoxAccessObservation(ctx context.Context, applicationID, deploymentID domain.ID, _ time.Time) (contracts.AcornFoxAccessObservation, bool, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	if applicationID.Empty() || deploymentID.Empty() {
		return contracts.AcornFoxAccessObservation{}, false, domain.ValidationError("access observation target is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	fail := func(cause error) (contracts.AcornFoxAccessObservation, bool, error) {
		return contracts.AcornFoxAccessObservation{}, false, rollbackTx(tx, cause)
	}
	// Hold the exact route graph and command locks through the observation
	// select. Under READ COMMITTED this prevents a disable or retarget from
	// committing between target validation and the fact read.
	hostname, available, err := acornFoxAccessObservationTargetTx(ctx, tx, applicationID, deploymentID, true)
	if err != nil {
		return fail(err)
	}
	if !available {
		if err := tx.Commit(); err != nil {
			return contracts.AcornFoxAccessObservation{}, false, err
		}
		return contracts.AcornFoxAccessObservation{}, false, nil
	}
	observation, _, _, err := scanAcornFoxAccessObservation(tx.QueryRowContext(ctx, acornFoxAccessObservationSelect+` WHERE application_id=$1 AND deployment_id=$2 AND hostname=$3 ORDER BY received_at DESC,report_id DESC LIMIT 1`, applicationID.String(), deploymentID.String(), hostname), applicationID, deploymentID)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return contracts.AcornFoxAccessObservation{}, false, err
		}
		return contracts.AcornFoxAccessObservation{}, false, nil
	}
	if err != nil {
		return fail(err)
	}
	if err := tx.Commit(); err != nil {
		return contracts.AcornFoxAccessObservation{}, false, err
	}
	return observation, true, nil
}

// acornFoxAccessObservationTargetTx binds a report to the exact durable route
// graph and its latest completed enable command. When lock is true the graph
// rows and command row remain locked until the append commits, so a concurrent
// disable or retarget cannot leave a fact for an obsolete hostname.
func acornFoxAccessObservationTargetTx(ctx context.Context, tx *sql.Tx, applicationID, deploymentID domain.ID, lock bool) (string, bool, error) {
	if err := afpaAssert(ctx, tx, applicationID, deploymentID); err != nil {
		return "", false, err
	}
	routeID := afpaID("route", applicationID.String(), deploymentID.String())
	intent, state, found, err := afpaRouteIntentTx(ctx, tx, applicationID, deploymentID, routeID, lock)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	if state != "active" {
		return "", false, nil
	}
	query := `SELECT requested_enabled,phase,COALESCE(result_hostname,'') FROM acornfox_public_access_commands WHERE application_id=$1 AND deployment_id=$2 AND route_id=$3 ORDER BY created_at DESC,updated_at DESC,idempotency_key DESC LIMIT 1`
	if lock {
		query += ` FOR UPDATE`
	}
	var enabled bool
	var phase, hostname string
	if err := tx.QueryRowContext(ctx, query, applicationID.String(), deploymentID.String(), routeID.String()).Scan(&enabled, &phase, &hostname); errors.Is(err, sql.ErrNoRows) {
		return "", false, domain.NewError(domain.ErrConflict, "public access has no route command")
	} else if err != nil {
		return "", false, err
	}
	if !enabled || phase != "completed" || hostname != intent.Hostname {
		return "", false, domain.NewError(domain.ErrConflict, "public access route is not current")
	}
	return intent.Hostname, true, nil
}

type accessObservationScanner interface {
	Scan(...any) error
}

func scanAcornFoxAccessObservation(row accessObservationScanner, applicationID, deploymentID domain.ID) (contracts.AcornFoxAccessObservation, string, string, error) {
	var observation contracts.AcornFoxAccessObservation
	var dns, tls, https []byte
	var digest, owner string
	if err := row.Scan(&observation.ReportID, &observation.Hostname, &observation.ObservedAt, &observation.ReceivedAt, &observation.ExpiresAt, &dns, &tls, &https, &digest, &owner); err != nil {
		return contracts.AcornFoxAccessObservation{}, "", "", err
	}
	observation, err := decodeAcornFoxAccessObservation(observation, applicationID, deploymentID, dns, tls, https)
	return observation, digest, owner, err
}

func decodeAcornFoxAccessObservation(observation contracts.AcornFoxAccessObservation, applicationID, deploymentID domain.ID, dns, tls, https []byte) (contracts.AcornFoxAccessObservation, error) {
	observation.Observer = "administrator_client"
	observation.ApplicationID = applicationID.String()
	observation.DeploymentID = deploymentID.String()
	observation.ObservedAt = observation.ObservedAt.UTC()
	observation.ReceivedAt = observation.ReceivedAt.UTC()
	observation.ExpiresAt = observation.ExpiresAt.UTC()
	if err := json.Unmarshal(dns, &observation.DNS); err != nil {
		return contracts.AcornFoxAccessObservation{}, fmt.Errorf("decode access observation DNS: %w", err)
	}
	if err := json.Unmarshal(tls, &observation.TLS); err != nil {
		return contracts.AcornFoxAccessObservation{}, fmt.Errorf("decode access observation TLS: %w", err)
	}
	if err := json.Unmarshal(https, &observation.HTTPS); err != nil {
		return contracts.AcornFoxAccessObservation{}, fmt.Errorf("decode access observation HTTPS: %w", err)
	}
	if err := observation.Validate(); err != nil {
		return contracts.AcornFoxAccessObservation{}, fmt.Errorf("invalid stored access observation: %w", err)
	}
	return observation, nil
}

func acornFoxAccessObservationNow(s *Store, now time.Time) time.Time {
	if now.IsZero() {
		now = s.now()
	}
	return now.UTC().Truncate(time.Microsecond)
}
