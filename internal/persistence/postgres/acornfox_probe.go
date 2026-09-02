package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	acornFoxProbeMaxLatencyMS     int64  = 60_000
	acornFoxProbeMaxAgentSequence uint64 = 1<<63 - 1
)

// AcornFoxProbeObservation is an immutable, transport-level loopback fact.
// It intentionally contains neither a target address nor response material,
// and cannot itself claim an application is healthy or publicly reachable.
type AcornFoxProbeObservation struct {
	ID            string
	SampleID      string
	TaskID        string
	AgentSequence uint64
	ApplicationID string
	EnvironmentID string
	ReleaseID     string
	DeploymentID  string
	ServiceName   string
	Protocol      contracts.AcornFoxProbeProtocol
	TargetClass   string
	Outcome       contracts.AcornFoxProbeOutcome
	HTTPStatus    *int
	LatencyMS     int64
	ErrorCode     string
	ObservedAt    time.Time
	CreatedAt     time.Time
	FactDigest    string
}

// Validate rejects shapes that are not independently meaningful probe facts.
// PostgreSQL repeats these checks so direct SQL cannot weaken the boundary.
func (observation AcornFoxProbeObservation) Validate() error {
	for field, value := range map[string]string{
		"probe observation id": observation.ID,
		"probe sample id":      observation.SampleID,
		"probe task id":        observation.TaskID,
		"application id":       observation.ApplicationID,
		"environment id":       observation.EnvironmentID,
		"release id":           observation.ReleaseID,
		"deployment id":        observation.DeploymentID,
		"service name":         observation.ServiceName,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if observation.AgentSequence == 0 || observation.AgentSequence > acornFoxProbeMaxAgentSequence || observation.TargetClass != contracts.AcornFoxProbeTargetClassLoopback || observation.ObservedAt.IsZero() || !validAcornFoxProbeFactDigest(observation.FactDigest) {
		return errors.New("probe observation is invalid")
	}
	if observation.Protocol != contracts.AcornFoxProbeProtocolHTTP && observation.Protocol != contracts.AcornFoxProbeProtocolTCP {
		return errors.New("probe observation protocol is invalid")
	}
	if observation.LatencyMS < 0 || observation.LatencyMS > acornFoxProbeMaxLatencyMS {
		return errors.New("probe observation latency is invalid")
	}
	switch observation.Outcome {
	case contracts.AcornFoxProbeOutcomeResponded:
		if observation.ErrorCode != "" {
			return errors.New("responded probe observation has an error code")
		}
		if observation.Protocol == contracts.AcornFoxProbeProtocolHTTP {
			if observation.HTTPStatus == nil || *observation.HTTPStatus < 100 || *observation.HTTPStatus > 599 {
				return errors.New("HTTP response probe observation has an invalid status")
			}
		} else if observation.HTTPStatus != nil {
			return errors.New("TCP probe observation has an HTTP status")
		}
	case contracts.AcornFoxProbeOutcomeNotApplicable:
		if observation.HTTPStatus != nil || observation.LatencyMS != 0 || observation.ErrorCode != "" {
			return errors.New("not applicable probe observation has a result")
		}
	case contracts.AcornFoxProbeOutcomeTimeout:
		if observation.HTTPStatus != nil || observation.ErrorCode != contracts.AcornFoxProbeErrorTimeout {
			return errors.New("timeout probe observation is invalid")
		}
	case contracts.AcornFoxProbeOutcomeRefused:
		if observation.HTTPStatus != nil || observation.ErrorCode != contracts.AcornFoxProbeErrorConnectionRefused {
			return errors.New("refused probe observation is invalid")
		}
	case contracts.AcornFoxProbeOutcomeMalformedResponse:
		if observation.Protocol != contracts.AcornFoxProbeProtocolHTTP || observation.HTTPStatus != nil || observation.ErrorCode != contracts.AcornFoxProbeErrorMalformedResponse {
			return errors.New("malformed probe observation is invalid")
		}
	case contracts.AcornFoxProbeOutcomeCancelled:
		if observation.HTTPStatus != nil || observation.ErrorCode != contracts.AcornFoxProbeErrorCancelled {
			return errors.New("cancelled probe observation is invalid")
		}
	default:
		return errors.New("probe observation outcome is invalid")
	}
	return nil
}

// AppendAcornFoxProbeObservation appends exactly one fact per Agent task
// sequence. A retry with the same sequence, sample identity, and digest is a
// no-op; any changed or cross-wired replay is an idempotency conflict.
func (s *Store) AppendAcornFoxProbeObservation(ctx context.Context, observation AcornFoxProbeObservation) (AcornFoxProbeObservation, bool, error) {
	if err := s.requireDB(); err != nil {
		return AcornFoxProbeObservation{}, false, err
	}
	if observation.CreatedAt.IsZero() {
		observation.CreatedAt = s.now().UTC()
	} else {
		observation.CreatedAt = observation.CreatedAt.UTC()
	}
	observation.ObservedAt = observation.ObservedAt.UTC()
	if err := observation.Validate(); err != nil {
		return AcornFoxProbeObservation{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AcornFoxProbeObservation{}, false, err
	}
	rollback := func(cause error) (AcornFoxProbeObservation, bool, error) {
		return AcornFoxProbeObservation{}, false, rollbackTx(tx, cause)
	}
	stored, replayed, err := appendAcornFoxProbeObservationTx(ctx, tx, observation)
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return AcornFoxProbeObservation{}, false, fmt.Errorf("%w: commit probe observation: %v", ErrOutcomeUnknown, err)
	}
	return stored, replayed, nil
}

// appendAcornFoxProbeObservationTx is the single insertion authority for a
// probe fact. RecordAgentEvent calls it after appending the matching raw Agent
// event, so both durable records commit or roll back together.
func appendAcornFoxProbeObservationTx(ctx context.Context, tx *sql.Tx, observation AcornFoxProbeObservation) (AcornFoxProbeObservation, bool, error) {
	if err := observation.Validate(); err != nil {
		return AcornFoxProbeObservation{}, false, err
	}
	inserted, err := tx.ExecContext(ctx, `
		INSERT INTO acornfox_probe_observations(
			id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,
			protocol,target_class,outcome,http_status,latency_ms,error_code,observed_at,created_at,fact_digest
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT DO NOTHING`,
		observation.ID, observation.SampleID, observation.TaskID, observation.AgentSequence, observation.ApplicationID, observation.EnvironmentID,
		observation.ReleaseID, observation.DeploymentID, observation.ServiceName, observation.Protocol, observation.TargetClass, observation.Outcome,
		observation.HTTPStatus, observation.LatencyMS, nullableString(observation.ErrorCode), observation.ObservedAt, observation.CreatedAt, observation.FactDigest)
	if err != nil {
		return AcornFoxProbeObservation{}, false, fmt.Errorf("append AcornFox probe observation: %w", err)
	}
	rows, err := inserted.RowsAffected()
	if err != nil {
		return AcornFoxProbeObservation{}, false, err
	}
	if rows == 1 {
		return observation, false, nil
	}
	stored, err := loadAcornFoxProbeReplayTx(ctx, tx, observation.TaskID, observation.AgentSequence, observation.SampleID)
	if err != nil {
		return AcornFoxProbeObservation{}, false, err
	}
	if len(stored) != 1 || !sameAcornFoxProbeIdentity(stored[0], observation) || stored[0].FactDigest != observation.FactDigest {
		return AcornFoxProbeObservation{}, false, ErrIdempotencyConflict
	}
	return stored[0], true, nil
}

func verifyAcornFoxProbeObservationReplayTx(ctx context.Context, tx *sql.Tx, observation AcornFoxProbeObservation) error {
	stored, err := loadAcornFoxProbeReplayTx(ctx, tx, observation.TaskID, observation.AgentSequence, observation.SampleID)
	if err != nil {
		return err
	}
	if len(stored) != 1 || !sameAcornFoxProbeIdentity(stored[0], observation) || stored[0].FactDigest != observation.FactDigest {
		return ErrIdempotencyConflict
	}
	return nil
}

// GetAcornFoxProbeObservation loads one durable observation by its opaque
// sample identity. It is read-only and has no projection side effects.
func (s *Store) GetAcornFoxProbeObservation(ctx context.Context, sampleID string) (AcornFoxProbeObservation, error) {
	if err := s.requireDB(); err != nil {
		return AcornFoxProbeObservation{}, err
	}
	if strings.TrimSpace(sampleID) == "" {
		return AcornFoxProbeObservation{}, errors.New("probe sample id is required")
	}
	item, err := scanAcornFoxProbeObservation(s.db.QueryRowContext(ctx, acornFoxProbeObservationSelect+` WHERE sample_id=$1`, sampleID))
	if errors.Is(err, sql.ErrNoRows) {
		return AcornFoxProbeObservation{}, ErrNotFound
	}
	return item, err
}

// ListAcornFoxProbeObservations returns task-scoped facts in Agent sequence
// order. It never derives readiness or changes a deployment, route, or task.
func (s *Store) ListAcornFoxProbeObservations(ctx context.Context, taskID string, limit int) ([]AcornFoxProbeObservation, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(taskID) == "" {
		return nil, errors.New("probe task id is required")
	}
	limit, err := normalizeLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, acornFoxProbeObservationSelect+` WHERE task_id=$1 ORDER BY agent_sequence,id LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AcornFoxProbeObservation, 0)
	for rows.Next() {
		item, err := scanAcornFoxProbeObservation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetLatestAcornFoxProbeObservation returns one immutable response fact for a
// deployment. It does not infer health from absence, a port, or a runtime
// state; callers must represent a missing fact as null.
func (s *Store) GetLatestAcornFoxProbeObservation(ctx context.Context, applicationID, deploymentID domain.ID) (AcornFoxProbeObservation, error) {
	if err := s.requireDB(); err != nil {
		return AcornFoxProbeObservation{}, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return AcornFoxProbeObservation{}, err
	}
	if err := domain.RequireID(deploymentID, "deployment id"); err != nil {
		return AcornFoxProbeObservation{}, err
	}
	item, err := scanAcornFoxProbeObservation(s.db.QueryRowContext(ctx, acornFoxProbeObservationSelect+` WHERE application_id=$1 AND deployment_id=$2 ORDER BY observed_at DESC,created_at DESC,agent_sequence DESC LIMIT 1`, applicationID.String(), deploymentID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return AcornFoxProbeObservation{}, ErrNotFound
	}
	return item, err
}

const acornFoxProbeObservationSelect = `
	SELECT id,sample_id,task_id,agent_sequence,application_id,environment_id,release_id,deployment_id,service_name,
		protocol,target_class,outcome,http_status,latency_ms,COALESCE(error_code,''),observed_at,created_at,fact_digest
	FROM acornfox_probe_observations`

type acornFoxProbeScanner interface{ Scan(...any) error }

func scanAcornFoxProbeObservation(row acornFoxProbeScanner) (AcornFoxProbeObservation, error) {
	var item AcornFoxProbeObservation
	var status sql.NullInt64
	if err := row.Scan(&item.ID, &item.SampleID, &item.TaskID, &item.AgentSequence, &item.ApplicationID, &item.EnvironmentID, &item.ReleaseID, &item.DeploymentID, &item.ServiceName, &item.Protocol, &item.TargetClass, &item.Outcome, &status, &item.LatencyMS, &item.ErrorCode, &item.ObservedAt, &item.CreatedAt, &item.FactDigest); err != nil {
		return AcornFoxProbeObservation{}, err
	}
	if status.Valid {
		value := int(status.Int64)
		item.HTTPStatus = &value
	}
	item.ObservedAt = item.ObservedAt.UTC()
	item.CreatedAt = item.CreatedAt.UTC()
	if err := item.Validate(); err != nil {
		return AcornFoxProbeObservation{}, fmt.Errorf("invalid persisted AcornFox probe observation: %w", err)
	}
	return item, nil
}

func loadAcornFoxProbeReplayTx(ctx context.Context, tx *sql.Tx, taskID string, sequence uint64, sampleID string) ([]AcornFoxProbeObservation, error) {
	rows, err := tx.QueryContext(ctx, acornFoxProbeObservationSelect+` WHERE (task_id=$1 AND agent_sequence=$2) OR sample_id=$3 FOR UPDATE`, taskID, sequence, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AcornFoxProbeObservation, 0, 2)
	for rows.Next() {
		item, err := scanAcornFoxProbeObservation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func sameAcornFoxProbeIdentity(left, right AcornFoxProbeObservation) bool {
	return left.ID == right.ID && left.SampleID == right.SampleID && left.TaskID == right.TaskID && left.AgentSequence == right.AgentSequence
}

func validAcornFoxProbeFactDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
