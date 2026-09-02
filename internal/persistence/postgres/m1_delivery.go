package postgres

// M1 delivery persistence deliberately lives beside the M0 repository rather
// than changing its application.Repository contract.  The ReleaseController
// can depend on these concrete methods while the public API is still being
// wired.  All execution transitions below write their audit and outbox facts
// in the same SQL transaction as the state change.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const m1BuildPlanIdempotencyScope = "m1.build_plan"

var ErrBuildNotSuccessful = errors.New("release requires successful persistent artifacts")
var ErrPublishPreviouslyFailed = errors.New("publish request previously failed")
var ErrAcornFoxPublishAbandoned = errors.New("AcornFox publish request was abandoned")

const acornFoxPublishAbandonedReason = "AcornFox delivery did not reach durable task commit before its recovery lease expired"

func (s *Store) ReplayPublish(ctx context.Context, key, requestDigest string) (json.RawMessage, bool, error) {
	if err := s.requireDB(); err != nil {
		return nil, false, err
	}
	var storedDigest, status string
	var response []byte
	var failure sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT request_digest,status,response,failure_reason FROM m1_publish_requests WHERE idempotency_key=$1`, strings.TrimSpace(key)).Scan(&storedDigest, &status, &response, &failure)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if storedDigest != strings.TrimSpace(requestDigest) {
		return nil, false, ErrIdempotencyConflict
	}
	switch status {
	case "completed":
		if len(response) == 0 {
			return nil, false, ErrIdempotencyCorrupt
		}
		return append(json.RawMessage(nil), response...), true, nil
	case "failed":
		return nil, false, publishFailureError(key, failure.String)
	default:
		return nil, false, ErrIdempotencyInProgress
	}
}

func (s *Store) ReservePublish(ctx context.Context, key, requestDigest string, now time.Time) (json.RawMessage, bool, error) {
	if err := s.requireDB(); err != nil {
		return nil, false, err
	}
	key, requestDigest = strings.TrimSpace(key), strings.TrimSpace(requestDigest)
	if key == "" || !strings.HasPrefix(requestDigest, "sha256:") {
		return nil, false, domain.ValidationError("publish idempotency key and request digest are required")
	}
	if now.IsZero() {
		now = s.now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	rollback := func(cause error) (json.RawMessage, bool, error) { return nil, false, rollbackTx(tx, cause) }
	result, err := tx.ExecContext(ctx, `INSERT INTO m1_publish_requests(idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,'in_progress',$3,$3) ON CONFLICT(idempotency_key) DO NOTHING`, key, requestDigest, now.UTC())
	if err != nil {
		return rollback(err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if inserted == 1 {
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	var storedDigest, status string
	var response []byte
	var failure sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response,failure_reason FROM m1_publish_requests WHERE idempotency_key=$1 FOR UPDATE`, key).Scan(&storedDigest, &status, &response, &failure); err != nil {
		return rollback(err)
	}
	if storedDigest != requestDigest {
		return rollback(ErrIdempotencyConflict)
	}
	switch status {
	case "completed":
		if len(response) == 0 {
			return rollback(ErrIdempotencyCorrupt)
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return append(json.RawMessage(nil), response...), true, nil
	case "failed":
		return rollback(publishFailureError(key, failure.String))
	default:
		return rollback(ErrIdempotencyInProgress)
	}
}

// AbandonExpiredAcornFoxPublish is deliberately namespaced to new AcornFox
// commands. A process that dies before it can durably queue its Agent task
// must not leave that idempotency key in_progress forever, nor may a retry
// rebuild or enqueue the same command a second time. Legacy M1 publish rows
// retain their existing semantics.
func (s *Store) AbandonExpiredAcornFoxPublish(ctx context.Context, key, requestDigest string, now time.Time, lease time.Duration) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	key, requestDigest = strings.TrimSpace(key), strings.TrimSpace(requestDigest)
	if !strings.HasPrefix(key, "acornfox:") || !strings.HasPrefix(requestDigest, "sha256:") || lease <= 0 {
		return domain.ValidationError("AcornFox publish recovery request is invalid")
	}
	if now.IsZero() {
		now = s.now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(cause error) error { return rollbackTx(tx, cause) }
	var storedDigest, status string
	var updatedAt time.Time
	var failure sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,updated_at,failure_reason FROM m1_publish_requests WHERE idempotency_key=$1 FOR UPDATE`, key).Scan(&storedDigest, &status, &updatedAt, &failure); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(err)
	}
	if storedDigest != requestDigest {
		return rollback(ErrIdempotencyConflict)
	}
	switch status {
	case "completed":
		return rollback(ErrOutcomeUnknown)
	case "failed":
		return rollback(publishFailureError(key, failure.String))
	case "in_progress":
		if updatedAt.After(now.UTC().Add(-lease)) {
			return rollback(ErrIdempotencyInProgress)
		}
		result, err := tx.ExecContext(ctx, `UPDATE m1_publish_requests SET status='failed',failure_reason=$1,response=NULL,updated_at=$2 WHERE idempotency_key=$3 AND request_digest=$4 AND status='in_progress'`, acornFoxPublishAbandonedReason, now.UTC(), key, requestDigest)
		if err != nil {
			return rollback(err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return rollback(err)
		}
		if rows != 1 {
			return rollback(ErrOutcomeUnknown)
		}
		// A create command has a deterministic build-plan idempotency key. If
		// the process died after the provider returned but before build
		// completion was persisted, do not leave that build running forever.
		// Completed builds/releases are immutable evidence and are not changed.
		if strings.HasPrefix(key, "acornfox:create:") {
			if _, err := tx.ExecContext(ctx, `UPDATE builds SET state='failed',failure_reason=$1,version=version+1,updated_at=$2 WHERE state IN ('pending','running') AND plan_id IN (SELECT id FROM build_plans WHERE idempotency_key=$3)`, acornFoxPublishAbandonedReason, now.UTC(), key+":build"); err != nil {
				return rollback(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: commit abandoned AcornFox publish: %v", ErrOutcomeUnknown, err)
		}
		return ErrAcornFoxPublishAbandoned
	default:
		return rollback(ErrOutcomeUnknown)
	}
}

func publishFailureError(key, reason string) error {
	if strings.HasPrefix(strings.TrimSpace(key), "acornfox:") && strings.TrimSpace(reason) == acornFoxPublishAbandonedReason {
		return ErrAcornFoxPublishAbandoned
	}
	return fmt.Errorf("%w: %s", ErrPublishPreviouslyFailed, reason)
}

func (s *Store) CompletePublish(ctx context.Context, key, requestDigest string, response json.RawMessage, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	if len(response) == 0 || !json.Valid(response) {
		return domain.ValidationError("publish response must be valid JSON")
	}
	if now.IsZero() {
		now = s.now()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE m1_publish_requests SET status='completed',response=$1::jsonb,failure_reason=NULL,updated_at=$2 WHERE idempotency_key=$3 AND request_digest=$4 AND status='in_progress'`, response, now.UTC(), key, requestDigest)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrOutcomeUnknown
	}
	return nil
}

func (s *Store) FailPublish(ctx context.Context, key, requestDigest, reason string, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	reason = foundation.RedactText(strings.TrimSpace(reason))
	if reason == "" {
		reason = "publish failed"
	}
	if now.IsZero() {
		now = s.now()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE m1_publish_requests SET status='failed',failure_reason=$1,response=NULL,updated_at=$2 WHERE idempotency_key=$3 AND request_digest=$4 AND status='in_progress'`, reason, now.UTC(), key, requestDigest)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrOutcomeUnknown
	}
	return nil
}

type DeploymentEndpoint struct {
	DeploymentID domain.ID `json:"deployment_id"`
	HostIP       string    `json:"host_ip"`
	HostPort     int       `json:"host_port"`
	Healthy      bool      `json:"healthy"`
	ObservedAt   time.Time `json:"observed_at"`
}

func (s *Store) AppendPublishEvent(ctx context.Context, operationID, applicationID domain.ID, status domain.PublishStatus, kind, message string, evidence []string, now time.Time) (application.Event, error) {
	if err := s.requireDB(); err != nil {
		return application.Event{}, err
	}
	if operationID.Empty() || applicationID.Empty() || strings.TrimSpace(kind) == "" {
		return application.Event{}, domain.ValidationError("publish event identity and kind are required")
	}
	if status != domain.PublishPreparing && status != domain.PublishBuilding && status != domain.PublishDeploying && status != domain.PublishSucceeded && status != domain.PublishFailed {
		return application.Event{}, domain.ValidationError("publish event status is unsupported")
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return application.Event{}, err
	}
	rollback := func(cause error) (application.Event, error) { return application.Event{}, rollbackTx(tx, cause) }
	if err := s.appendM1AuditTx(ctx, tx, kind, []byte(operationID.String()+"\x00"+string(status)), now); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-publish:"+operationID.String()); err != nil {
		return rollback(err)
	}
	var aggregateSequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id=$1`, operationID.String()).Scan(&aggregateSequence); err != nil {
		return rollback(err)
	}
	stream, err := s.nextStreamSequence(ctx, tx)
	if err != nil {
		return rollback(err)
	}
	event := application.Event{SchemaVersion: "1.1", ID: "evt-" + formatSequence(uint64(stream)), OperationID: operationID.String(), ApplicationID: applicationID.String(), Sequence: uint64(stream), OccurredAt: now, Kind: kind, Status: string(status), Message: message, EvidenceIDs: append([]string(nil), evidence...)}
	payload, err := json.Marshal(event)
	if err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,'operation',$2,$3,$3,$4,$5,$6::jsonb,$7,'1.1')`, event.ID, operationID.String(), aggregateSequence, stream, kind, payload, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return application.Event{}, fmt.Errorf("%w: commit publish event: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

func (s *Store) GetDeploymentEndpoint(ctx context.Context, deploymentID domain.ID) (DeploymentEndpoint, error) {
	if err := s.requireDB(); err != nil {
		return DeploymentEndpoint{}, err
	}
	if err := domain.RequireID(deploymentID, "deployment id"); err != nil {
		return DeploymentEndpoint{}, err
	}
	endpoint := DeploymentEndpoint{DeploymentID: deploymentID}
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(host(host_ip),''),COALESCE(host_port,0),runtime_healthy,COALESCE(last_observed_at,to_timestamp(0)) FROM deployments WHERE id=$1`, deploymentID.String()).Scan(&endpoint.HostIP, &endpoint.HostPort, &endpoint.Healthy, &endpoint.ObservedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeploymentEndpoint{}, ErrNotFound
	}
	if err != nil {
		return DeploymentEndpoint{}, fmt.Errorf("get deployment endpoint: %w", err)
	}
	endpoint.ObservedAt = endpoint.ObservedAt.UTC()
	return endpoint, nil
}

// ReleaseCreation binds a frozen ready Release to the immutable delivery
// definition that produced it.  The definition is explicit because the
// domain Release intentionally contains a service-group identifier, not a
// mutable definition reference.
type ReleaseCreation struct {
	Release      domain.Release
	DefinitionID domain.ID
}

// WorkspaceLifecycle is the append-only cleanup state for a retained source
// workspace. It is intentionally not a mutable field on SourceRevision.
type WorkspaceLifecycle string

const (
	WorkspacePrepared WorkspaceLifecycle = "prepared"
	WorkspaceReleased WorkspaceLifecycle = "released"
	WorkspaceFailed   WorkspaceLifecycle = "failed"
)

func (s *Store) GetSourceWorkspaceLifecycle(ctx context.Context, sourceID domain.ID) (WorkspaceLifecycle, error) {
	if err := s.requireDB(); err != nil {
		return "", err
	}
	if err := domain.RequireID(sourceID, "source revision id"); err != nil {
		return "", err
	}
	var state WorkspaceLifecycle
	err := s.db.QueryRowContext(ctx, `SELECT workspace_lifecycle FROM source_revisions WHERE id=$1 AND source_kind IS NOT NULL`, sourceID.String()).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if state != WorkspacePrepared && state != WorkspaceReleased && state != WorkspaceFailed {
		return "", ErrIdempotencyCorrupt
	}
	return state, nil
}

type WorkspaceLifecycleEvent struct {
	SourceRevisionID domain.ID          `json:"source_revision_id"`
	WorkspaceRef     string             `json:"workspace_ref"`
	State            WorkspaceLifecycle `json:"state"`
	Sequence         int64              `json:"sequence"`
	CreatedAt        time.Time          `json:"created_at"`
}

func (r ReleaseCreation) validate() error {
	if err := r.Release.Validate(); err != nil {
		return err
	}
	if !r.Release.IsImmutable() || r.Release.Status != domain.ReleaseReady {
		return domain.ValidationError("M1 persists only immutable ready releases")
	}
	return domain.RequireID(r.DefinitionID, "release definition id")
}

// CreateSourceRevision persists immutable source provenance and the retained
// workspace lifecycle.  The source content itself is never put in the outbox.
func (s *Store) CreateSourceRevision(ctx context.Context, revision domain.SourceRevision) (domain.SourceRevision, error) {
	if err := s.requireDB(); err != nil {
		return domain.SourceRevision{}, err
	}
	if err := revision.Validate(); err != nil {
		return domain.SourceRevision{}, err
	}
	if revision.CreatedAt.IsZero() {
		revision.CreatedAt = s.now().UTC()
	} else {
		revision.CreatedAt = revision.CreatedAt.UTC()
	}
	provider := "upload"
	if revision.Kind == domain.SourceGitHTTPS || revision.Kind == domain.SourceGitSSH {
		provider = "git"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.SourceRevision{}, fmt.Errorf("begin source revision: %w", err)
	}
	rollback := func(cause error) (domain.SourceRevision, error) {
		return domain.SourceRevision{}, rollbackTx(tx, cause)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO source_revisions
			(id, application_id, provider, git_commit, content_digest, workspace_manifest,
			 source_kind, locator, source_ref, workspace_ref, workspace_lifecycle, immutable, created_at)
		VALUES ($1,$2,$3,$4,$5,'{}'::jsonb,$6,$7,$8,$9,'prepared',true,$10)
	`, revision.ID.String(), revision.ApplicationID.String(), provider, nullableString(revision.Commit), revision.ContentDigest,
		string(revision.Kind), revision.Locator, nullableString(revision.Ref), revision.WorkspaceRef, revision.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert source revision: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES($1,1,$2,'prepared',$3)`, revision.ID.String(), revision.WorkspaceRef, revision.CreatedAt); err != nil {
		return rollback(fmt.Errorf("record source workspace preparation: %w", err))
	}
	if err := s.appendM1FactsTx(ctx, tx, "source_revision", revision.ID.String(), "source_revision.created", revision, revision.CreatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.SourceRevision{}, fmt.Errorf("%w: commit source revision: %v", ErrOutcomeUnknown, err)
	}
	return revision, nil
}

// TransitionSourceWorkspace records the cleanup result without modifying the
// source revision. Only the natural prepared -> terminal lifecycle is allowed.
func (s *Store) TransitionSourceWorkspace(ctx context.Context, sourceID domain.ID, to WorkspaceLifecycle, now time.Time) (WorkspaceLifecycleEvent, error) {
	if err := s.requireDB(); err != nil {
		return WorkspaceLifecycleEvent{}, err
	}
	if err := domain.RequireID(sourceID, "source revision id"); err != nil {
		return WorkspaceLifecycleEvent{}, err
	}
	if to != WorkspaceReleased && to != WorkspaceFailed {
		return WorkspaceLifecycleEvent{}, domain.ValidationError("workspace lifecycle target is unsupported")
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WorkspaceLifecycleEvent{}, err
	}
	rollback := func(cause error) (WorkspaceLifecycleEvent, error) {
		return WorkspaceLifecycleEvent{}, rollbackTx(tx, cause)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-source-workspace:"+sourceID.String()); err != nil {
		return rollback(err)
	}
	var workspaceRef string
	if err := tx.QueryRowContext(ctx, `SELECT workspace_ref FROM source_revisions WHERE id=$1 AND source_kind IS NOT NULL`, sourceID.String()).Scan(&workspaceRef); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(fmt.Errorf("load source workspace: %w", err))
	}
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM source_workspace_events WHERE source_revision_id=$1 ORDER BY sequence DESC LIMIT 1`, sourceID.String()).Scan(&previous); err != nil {
		return rollback(fmt.Errorf("load source workspace lifecycle: %w", err))
	}
	if previous == string(to) {
		var event WorkspaceLifecycleEvent
		err := tx.QueryRowContext(ctx, `SELECT source_revision_id,workspace_ref,state,sequence,created_at FROM source_workspace_events WHERE source_revision_id=$1 ORDER BY sequence DESC LIMIT 1`, sourceID.String()).Scan(&event.SourceRevisionID, &event.WorkspaceRef, &event.State, &event.Sequence, &event.CreatedAt)
		if err != nil {
			return rollback(err)
		}
		if err := tx.Commit(); err != nil {
			return WorkspaceLifecycleEvent{}, fmt.Errorf("%w: commit workspace replay: %v", ErrOutcomeUnknown, err)
		}
		event.CreatedAt = event.CreatedAt.UTC()
		return event, nil
	}
	if previous != string(WorkspacePrepared) {
		return rollback(domain.ValidationError("workspace lifecycle is already terminal"))
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM source_workspace_events WHERE source_revision_id=$1`, sourceID.String()).Scan(&sequence); err != nil {
		return rollback(err)
	}
	event := WorkspaceLifecycleEvent{SourceRevisionID: sourceID, WorkspaceRef: workspaceRef, State: to, Sequence: sequence, CreatedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES($1,$2,$3,$4,$5)`, sourceID.String(), sequence, workspaceRef, string(to), now); err != nil {
		return rollback(fmt.Errorf("record source workspace lifecycle: %w", err))
	}
	if err := s.appendM1FactsTx(ctx, tx, "source_revision", sourceID.String(), "source_workspace."+string(to), event, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return WorkspaceLifecycleEvent{}, fmt.Errorf("%w: commit workspace transition: %v", ErrOutcomeUnknown, err)
	}
	return event, nil
}

func (s *Store) GetSourceRevision(ctx context.Context, id domain.ID) (domain.SourceRevision, error) {
	if err := s.requireDB(); err != nil {
		return domain.SourceRevision{}, err
	}
	if err := domain.RequireID(id, "source revision id"); err != nil {
		return domain.SourceRevision{}, err
	}
	var item domain.SourceRevision
	var kind, ref, commit string
	err := s.db.QueryRowContext(ctx, `
		SELECT id,application_id,source_kind,locator,COALESCE(source_ref,''),COALESCE(git_commit,''),
		       content_digest,workspace_ref,created_at,immutable
		  FROM source_revisions WHERE id=$1 AND source_kind IS NOT NULL
	`, id.String()).Scan(&item.ID, &item.ApplicationID, &kind, &item.Locator, &ref, &commit, &item.ContentDigest, &item.WorkspaceRef, &item.CreatedAt, &item.Immutable)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SourceRevision{}, ErrNotFound
	}
	if err != nil {
		return domain.SourceRevision{}, fmt.Errorf("get source revision: %w", err)
	}
	item.Kind, item.Ref, item.Commit, item.CreatedAt = domain.SourceKind(kind), ref, commit, item.CreatedAt.UTC()
	if err := item.Validate(); err != nil {
		return domain.SourceRevision{}, fmt.Errorf("invalid persisted source revision: %w", err)
	}
	return item, nil
}

func (s *Store) CreateDeliveryDefinition(ctx context.Context, definition domain.ApplicationDeliveryDefinition) (domain.ApplicationDeliveryDefinition, error) {
	if err := s.requireDB(); err != nil {
		return domain.ApplicationDeliveryDefinition{}, err
	}
	if err := definition.Validate(); err != nil {
		return domain.ApplicationDeliveryDefinition{}, err
	}
	if definition.CreatedAt.IsZero() {
		definition.CreatedAt = s.now().UTC()
	} else {
		definition.CreatedAt = definition.CreatedAt.UTC()
	}
	configuration, err := json.Marshal(definition.Facts)
	if err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("encode delivery facts: %w", err)
	}
	observations, err := json.Marshal(definition.Observations)
	if err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("encode delivery observations: %w", err)
	}
	recommendations, err := json.Marshal(definition.Recommendations)
	if err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("encode delivery recommendations: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("begin delivery definition: %w", err)
	}
	rollback := func(cause error) (domain.ApplicationDeliveryDefinition, error) {
		return domain.ApplicationDeliveryDefinition{}, rollbackTx(tx, cause)
	}
	var sourceApplicationID string
	if err := tx.QueryRowContext(ctx, `SELECT application_id FROM source_revisions WHERE id=$1`, definition.SourceRevisionID.String()).Scan(&sourceApplicationID); err != nil {
		return rollback(fmt.Errorf("load delivery definition source revision: %w", err))
	}
	if sourceApplicationID != definition.ApplicationID.String() {
		return rollback(domain.ValidationError("delivery definition source revision belongs to another application"))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,observations,recommendations,created_at)
		VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8)
	`, definition.ID.String(), definition.ApplicationID.String(), definition.SourceRevisionID.String(), definition.Version, configuration, observations, recommendations, definition.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert delivery definition: %w", err))
	}
	if err := s.appendM1FactsTx(ctx, tx, "delivery_definition", definition.ID.String(), "delivery_definition.created", definition, definition.CreatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("%w: commit delivery definition: %v", ErrOutcomeUnknown, err)
	}
	return definition, nil
}

func (s *Store) GetDeliveryDefinition(ctx context.Context, id domain.ID) (domain.ApplicationDeliveryDefinition, error) {
	if err := s.requireDB(); err != nil {
		return domain.ApplicationDeliveryDefinition{}, err
	}
	if err := domain.RequireID(id, "delivery definition id"); err != nil {
		return domain.ApplicationDeliveryDefinition{}, err
	}
	var item domain.ApplicationDeliveryDefinition
	var configuration, observations, recommendations []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,application_id,source_revision_id,version,configuration,observations,recommendations,created_at FROM delivery_definitions WHERE id=$1`, id.String()).Scan(
		&item.ID, &item.ApplicationID, &item.SourceRevisionID, &item.Version, &configuration, &observations, &recommendations, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ApplicationDeliveryDefinition{}, ErrNotFound
	}
	if err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("get delivery definition: %w", err)
	}
	if err := json.Unmarshal(configuration, &item.Facts); err != nil || json.Unmarshal(observations, &item.Observations) != nil || json.Unmarshal(recommendations, &item.Recommendations) != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("%w: invalid delivery definition JSON", ErrIdempotencyCorrupt)
	}
	item.CreatedAt, item.Immutable = item.CreatedAt.UTC(), true
	if err := item.Validate(); err != nil {
		return domain.ApplicationDeliveryDefinition{}, fmt.Errorf("invalid persisted delivery definition: %w", err)
	}
	return item, nil
}

// CreateBuildPlan uses the caller's idempotency key as a durable command key.
// A completed duplicate returns the same immutable plan; a changed request is
// rejected rather than silently bound to the old build input.
func (s *Store) CreateBuildPlan(ctx context.Context, plan domain.BuildPlan) (domain.BuildPlan, error) {
	if err := s.requireDB(); err != nil {
		return domain.BuildPlan{}, err
	}
	if err := plan.Validate(); err != nil {
		return domain.BuildPlan{}, err
	}
	if plan.CreatedAt.IsZero() {
		plan.CreatedAt = s.now().UTC()
	} else {
		plan.CreatedAt = plan.CreatedAt.UTC()
	}
	requestDigest, err := m1JSONDigest(plan)
	if err != nil {
		return domain.BuildPlan{}, err
	}
	output, err := json.Marshal(plan.Output)
	if err != nil {
		return domain.BuildPlan{}, err
	}
	secretRefs := plan.SecretRefs
	if secretRefs == nil {
		secretRefs = []domain.SecretReference{}
	}
	secrets, err := json.Marshal(secretRefs)
	if err != nil {
		return domain.BuildPlan{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BuildPlan{}, fmt.Errorf("begin build plan: %w", err)
	}
	rollback := func(cause error) (domain.BuildPlan, error) { return domain.BuildPlan{}, rollbackTx(tx, cause) }
	reserved, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES($1,$2,$3,'in_progress',$4,$4) ON CONFLICT(scope,idempotency_key) DO NOTHING`, m1BuildPlanIdempotencyScope, plan.IdempotencyKey, requestDigest, plan.CreatedAt)
	if err != nil {
		return rollback(fmt.Errorf("reserve build plan idempotency: %w", err))
	}
	inserted, err := reserved.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("inspect build plan idempotency: %w", err))
	}
	if inserted == 0 {
		var storedDigest, status string
		if err := tx.QueryRowContext(ctx, `SELECT request_digest,status FROM idempotency_records WHERE scope=$1 AND idempotency_key=$2 FOR UPDATE`, m1BuildPlanIdempotencyScope, plan.IdempotencyKey).Scan(&storedDigest, &status); err != nil {
			return rollback(fmt.Errorf("read build plan idempotency: %w", err))
		}
		if storedDigest != requestDigest {
			return rollback(ErrIdempotencyConflict)
		}
		if status != "completed" {
			return rollback(ErrIdempotencyInProgress)
		}
		item, err := loadBuildPlanTx(ctx, tx, plan.SourceRevisionID, plan.ServiceName, plan.IdempotencyKey)
		if err != nil {
			return rollback(fmt.Errorf("replay build plan: %w", err))
		}
		if err := tx.Commit(); err != nil {
			return domain.BuildPlan{}, fmt.Errorf("%w: commit build plan replay: %v", ErrOutcomeUnknown, err)
		}
		return item, nil
	}
	var actualSourceDigest string
	if err := tx.QueryRowContext(ctx, `SELECT content_digest FROM source_revisions WHERE id=$1 AND source_kind IS NOT NULL`, plan.SourceRevisionID.String()).Scan(&actualSourceDigest); err != nil {
		return rollback(fmt.Errorf("load build plan source revision: %w", err))
	}
	if actualSourceDigest != plan.SourceDigest {
		return rollback(domain.ValidationError("build plan source digest does not match source revision"))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,static_runtime_digest,acornfox_definition_digest,acornfox_dockerfile_digest,acornfox_network_mode,acornfox_worker_policy_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16,$17)`, plan.ID.String(), plan.SourceRevisionID.String(), plan.SourceDigest, plan.ServiceName, string(plan.Kind), plan.ContextPath, nullableString(plan.DockerfilePath), nullableString(plan.StaticRuntimeDigest), nullableString(plan.AcornFoxDefinitionDigest), nullableString(plan.AcornFoxDockerfileDigest), nullableString(plan.AcornFoxNetworkMode), nullableString(plan.AcornFoxWorkerPolicyDigest), plan.TargetRepository, output, secrets, plan.IdempotencyKey, plan.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert build plan: %w", err))
	}
	if err := s.appendM1FactsTx(ctx, tx, "build_plan", plan.ID.String(), "build_plan.created", plan, plan.CreatedAt); err != nil {
		return rollback(err)
	}
	response, err := json.Marshal(plan)
	if err != nil {
		return rollback(err)
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE idempotency_records SET status='completed',response=$3::jsonb,updated_at=$4 WHERE scope=$1 AND idempotency_key=$2 AND status='in_progress'`, m1BuildPlanIdempotencyScope, plan.IdempotencyKey, response, plan.CreatedAt); err != nil {
		return rollback(fmt.Errorf("complete build plan idempotency: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return domain.BuildPlan{}, fmt.Errorf("%w: commit build plan: %v", ErrOutcomeUnknown, err)
	}
	return plan, nil
}

func (s *Store) GetBuildPlan(ctx context.Context, id domain.ID) (domain.BuildPlan, error) {
	if err := s.requireDB(); err != nil {
		return domain.BuildPlan{}, err
	}
	if err := domain.RequireID(id, "build plan id"); err != nil {
		return domain.BuildPlan{}, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT id,source_revision_id,source_digest,service_name,build_kind,context_path,COALESCE(dockerfile_path,''),COALESCE(static_runtime_digest,''),COALESCE(acornfox_definition_digest,''),COALESCE(acornfox_dockerfile_digest,''),COALESCE(acornfox_network_mode,''),COALESCE(acornfox_worker_policy_digest,''),target_repository,output_contract,secret_refs,idempotency_key,created_at FROM build_plans WHERE id=$1`, id.String())
	return scanBuildPlan(row)
}

func (s *Store) CreateBuild(ctx context.Context, build domain.Build) (domain.Build, error) {
	if err := s.requireDB(); err != nil {
		return domain.Build{}, err
	}
	if err := validateM1Build(build); err != nil {
		return domain.Build{}, err
	}
	if build.Status != domain.BuildPending {
		return domain.Build{}, domain.ValidationError("new build must be pending")
	}
	if build.CreatedAt.IsZero() {
		build.CreatedAt = s.now().UTC()
	} else {
		build.CreatedAt = build.CreatedAt.UTC()
	}
	if build.UpdatedAt.IsZero() {
		build.UpdatedAt = build.CreatedAt
	} else {
		build.UpdatedAt = build.UpdatedAt.UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Build{}, err
	}
	rollback := func(cause error) (domain.Build, error) { return domain.Build{}, rollbackTx(tx, cause) }
	if _, err := tx.ExecContext(ctx, `INSERT INTO builds(id,plan_id,state,created_at,updated_at) VALUES($1,$2,'pending',$3,$3)`, build.ID.String(), build.PlanID.String(), build.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert build: %w", err))
	}
	if err := s.appendM1FactsTx(ctx, tx, "build", build.ID.String(), "build.created", build, build.CreatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Build{}, fmt.Errorf("%w: commit build: %v", ErrOutcomeUnknown, err)
	}
	return build, nil
}

func (s *Store) StartBuild(ctx context.Context, id domain.ID, now time.Time) (domain.Build, error) {
	if err := s.requireDB(); err != nil {
		return domain.Build{}, err
	}
	if err := domain.RequireID(id, "build id"); err != nil {
		return domain.Build{}, err
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Build{}, err
	}
	rollback := func(cause error) (domain.Build, error) { return domain.Build{}, rollbackTx(tx, cause) }
	build, version, err := loadBuildTx(ctx, tx, id, true)
	if err != nil {
		return rollback(err)
	}
	if build.Status == domain.BuildRunning {
		if err := tx.Commit(); err != nil {
			return domain.Build{}, fmt.Errorf("%w: commit build start replay: %v", ErrOutcomeUnknown, err)
		}
		return build, nil
	}
	if build.Status != domain.BuildPending {
		return rollback(domain.ValidationError("build is not startable"))
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE builds SET state='running',version=version+1,updated_at=$1 WHERE id=$2 AND version=$3`, now, id.String(), version); err != nil {
		return rollback(err)
	}
	build.Status, build.UpdatedAt = domain.BuildRunning, now
	if err := s.appendM1FactsTx(ctx, tx, "build", id.String(), "build.started", build, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Build{}, fmt.Errorf("%w: commit build start: %v", ErrOutcomeUnknown, err)
	}
	return build, nil
}

// CompleteBuild atomically persists the artifact, marks its build successful,
// and optionally creates a ready release.  A failed build has no code path to
// this method, which makes "success release on build failure" impossible.
func (s *Store) CompleteBuild(ctx context.Context, artifact domain.Artifact, release *ReleaseCreation, now time.Time) (domain.Build, error) {
	if err := s.requireDB(); err != nil {
		return domain.Build{}, err
	}
	if err := artifact.Validate(); err != nil {
		return domain.Build{}, err
	}
	if release != nil {
		if err := release.validate(); err != nil {
			return domain.Build{}, err
		}
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = now
	} else {
		artifact.CreatedAt = artifact.CreatedAt.UTC()
	}
	evidence, err := json.Marshal(artifact.Evidence)
	if err != nil {
		return domain.Build{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Build{}, err
	}
	rollback := func(cause error) (domain.Build, error) { return domain.Build{}, rollbackTx(tx, cause) }
	build, version, err := loadBuildTx(ctx, tx, artifact.BuildID, true)
	if err != nil {
		return rollback(err)
	}
	if build.Status != domain.BuildRunning {
		return rollback(domain.ValidationError("only a running build can succeed"))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO artifacts(id,build_id,image_repository,image_digest,resolved_tag,oci_storage_ref,size_bytes,evidence,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`, artifact.ID.String(), artifact.BuildID.String(), artifact.Image.Repository, artifact.Image.Digest, nullableString(artifact.Image.ResolvedTag), artifact.OCIStorageRef, artifact.SizeBytes, evidence, artifact.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert artifact: %w", err))
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE builds SET state='succeeded',artifact_id=$1,failure_reason=NULL,version=version+1,updated_at=$2 WHERE id=$3 AND version=$4`, artifact.ID.String(), now, build.ID.String(), version); err != nil {
		return rollback(fmt.Errorf("complete build: %w", err))
	}
	build.Status, build.ArtifactID, build.UpdatedAt = domain.BuildSucceeded, artifact.ID, now
	if release != nil {
		if err := s.insertReadyReleaseTx(ctx, tx, *release, build.PlanID, now); err != nil {
			return rollback(err)
		}
	}
	if err := s.appendM1FactsTx(ctx, tx, "build", build.ID.String(), "build.succeeded", struct {
		Build    domain.Build    `json:"build"`
		Artifact domain.Artifact `json:"artifact"`
	}{build, artifact}, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Build{}, fmt.Errorf("%w: commit build completion: %v", ErrOutcomeUnknown, err)
	}
	return build, nil
}

func (s *Store) FailBuild(ctx context.Context, id domain.ID, reason string, now time.Time) (domain.Build, error) {
	if err := s.requireDB(); err != nil {
		return domain.Build{}, err
	}
	if err := domain.RequireID(id, "build id"); err != nil {
		return domain.Build{}, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return domain.Build{}, domain.ValidationError("build failure reason is required")
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Build{}, err
	}
	rollback := func(cause error) (domain.Build, error) { return domain.Build{}, rollbackTx(tx, cause) }
	build, version, err := loadBuildTx(ctx, tx, id, true)
	if err != nil {
		return rollback(err)
	}
	if build.Status == domain.BuildFailed {
		if build.Failure != reason {
			return rollback(ErrTaskResultConflict)
		}
		if err := tx.Commit(); err != nil {
			return domain.Build{}, err
		}
		return build, nil
	}
	if build.Status != domain.BuildPending && build.Status != domain.BuildRunning {
		return rollback(domain.ValidationError("build is not fail-able"))
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE builds SET state='failed',failure_reason=$1,version=version+1,updated_at=$2 WHERE id=$3 AND version=$4`, reason, now, id.String(), version); err != nil {
		return rollback(err)
	}
	build.Status, build.Failure, build.UpdatedAt = domain.BuildFailed, reason, now
	if err := s.appendM1FactsTx(ctx, tx, "build", build.ID.String(), "build.failed", build, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Build{}, fmt.Errorf("%w: commit build failure: %v", ErrOutcomeUnknown, err)
	}
	return build, nil
}

func (s *Store) CreateDeployment(ctx context.Context, deployment domain.Deployment) (domain.Deployment, error) {
	if err := s.requireDB(); err != nil {
		return domain.Deployment{}, err
	}
	if err := deployment.Validate(); err != nil {
		return domain.Deployment{}, err
	}
	if deployment.Status != domain.DeploymentPending {
		return domain.Deployment{}, domain.ValidationError("new deployment must be pending")
	}
	if deployment.CreatedAt.IsZero() {
		deployment.CreatedAt = s.now().UTC()
	} else {
		deployment.CreatedAt = deployment.CreatedAt.UTC()
	}
	if deployment.UpdatedAt.IsZero() {
		deployment.UpdatedAt = deployment.CreatedAt
	} else {
		deployment.UpdatedAt = deployment.UpdatedAt.UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Deployment{}, err
	}
	rollback := func(cause error) (domain.Deployment, error) { return domain.Deployment{}, rollbackTx(tx, cause) }
	var environmentApplication, releaseApplication, releaseStatus string
	if err := tx.QueryRowContext(ctx, `SELECT application_id FROM environments WHERE id=$1`, deployment.EnvironmentID.String()).Scan(&environmentApplication); err != nil {
		return rollback(fmt.Errorf("load deployment environment: %w", err))
	}
	if err := tx.QueryRowContext(ctx, `SELECT application_id,release_status FROM releases WHERE id=$1`, deployment.ReleaseID.String()).Scan(&releaseApplication, &releaseStatus); err != nil {
		return rollback(fmt.Errorf("load deployment release: %w", err))
	}
	if environmentApplication != deployment.ApplicationID.String() || releaseApplication != deployment.ApplicationID.String() || releaseStatus != string(domain.ReleaseReady) {
		return rollback(domain.ValidationError("deployment application or ready release mismatch"))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deployments(id,environment_id,release_id,state,version,created_at,updated_at) VALUES($1,$2,$3,'pending',1,$4,$4)`, deployment.ID.String(), deployment.EnvironmentID.String(), deployment.ReleaseID.String(), deployment.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert deployment: %w", err))
	}
	if err := s.appendM1FactsTx(ctx, tx, "deployment", deployment.ID.String(), "deployment.created", deployment, deployment.CreatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Deployment{}, fmt.Errorf("%w: commit deployment: %v", ErrOutcomeUnknown, err)
	}
	return deployment, nil
}

func (s *Store) TransitionDeployment(ctx context.Context, id domain.ID, to domain.DeploymentStatus, failureReason string, now time.Time) (domain.Deployment, error) {
	if err := s.requireDB(); err != nil {
		return domain.Deployment{}, err
	}
	if err := domain.RequireID(id, "deployment id"); err != nil {
		return domain.Deployment{}, err
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Deployment{}, err
	}
	rollback := func(cause error) (domain.Deployment, error) { return domain.Deployment{}, rollbackTx(tx, cause) }
	deployment, version, err := loadM1DeploymentTx(ctx, tx, id, true)
	if err != nil {
		return rollback(err)
	}
	if deployment.Status == to {
		if err := tx.Commit(); err != nil {
			return domain.Deployment{}, err
		}
		return deployment, nil
	}
	if err := deployment.Transition(to, now); err != nil {
		return rollback(err)
	}
	if to == domain.DeploymentFailed {
		deployment.FailureReason = strings.TrimSpace(failureReason)
		if deployment.FailureReason == "" {
			return rollback(domain.ValidationError("failed deployment requires a reason"))
		}
	} else {
		deployment.FailureReason = ""
	}
	if err := execExactlyOneTx(ctx, tx, `UPDATE deployments SET state=$1,failure_reason=$2,version=version+1,updated_at=$3 WHERE id=$4 AND version=$5`, string(deployment.Status), nullableString(deployment.FailureReason), now, id.String(), version); err != nil {
		return rollback(err)
	}
	if err := s.appendM1FactsTx(ctx, tx, "deployment", id.String(), "deployment."+string(to), deployment, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Deployment{}, fmt.Errorf("%w: commit deployment transition: %v", ErrOutcomeUnknown, err)
	}
	return deployment, nil
}

func (s *Store) insertReadyReleaseTx(ctx context.Context, tx *sql.Tx, creation ReleaseCreation, planID domain.ID, now time.Time) error {
	var definitionApplication, definitionSource, planSource string
	if err := tx.QueryRowContext(ctx, `SELECT application_id,source_revision_id FROM delivery_definitions WHERE id=$1`, creation.DefinitionID.String()).Scan(&definitionApplication, &definitionSource); err != nil {
		return fmt.Errorf("load release definition: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT source_revision_id FROM build_plans WHERE id=$1`, planID.String()).Scan(&planSource); err != nil {
		return fmt.Errorf("load release build plan: %w", err)
	}
	if definitionApplication != creation.Release.ApplicationID.String() || definitionSource != planSource {
		return domain.ValidationError("release definition does not match completed build source")
	}
	digests := creation.Release.ServiceDigests()
	artifactByService := make(map[string]string, len(digests))
	for service, image := range digests {
		var artifactID string
		err := tx.QueryRowContext(ctx, `SELECT a.id FROM artifacts a JOIN builds b ON b.id=a.build_id JOIN build_plans p ON p.id=b.plan_id JOIN source_revisions src ON src.id=p.source_revision_id WHERE src.application_id=$1 AND b.state='succeeded' AND a.image_repository=$2 AND a.image_digest=$3 ORDER BY a.created_at DESC LIMIT 1`, creation.Release.ApplicationID.String(), image.Repository, image.Digest).Scan(&artifactID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: service %q", ErrBuildNotSuccessful, service)
		}
		if err != nil {
			return fmt.Errorf("load release artifact: %w", err)
		}
		artifactByService[service] = artifactID
	}
	scalarDigests := make(map[string]string, len(digests))
	for service, image := range digests {
		scalarDigests[service] = image.Digest
	}
	encodedDigests, err := json.Marshal(scalarDigests)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO releases(id,application_id,definition_id,version,service_digests,service_group_id,config_digest,release_status,created_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,'ready',$8)`, creation.Release.ID.String(), creation.Release.ApplicationID.String(), creation.DefinitionID.String(), creation.Release.Version, encodedDigests, creation.Release.ServiceGroupID.String(), creation.Release.ConfigDigest, creation.Release.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("insert ready release: %w", err)
	}
	for service, artifactID := range artifactByService {
		if _, err := tx.ExecContext(ctx, `INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES($1,$2,$3)`, creation.Release.ID.String(), service, artifactID); err != nil {
			return fmt.Errorf("link release artifact: %w", err)
		}
	}
	return s.appendM1FactsTx(ctx, tx, "release", creation.Release.ID.String(), "release.created", creation.Release, now)
}

func (s *Store) GetBuild(ctx context.Context, id domain.ID) (domain.Build, error) {
	if err := s.requireDB(); err != nil {
		return domain.Build{}, err
	}
	if err := domain.RequireID(id, "build id"); err != nil {
		return domain.Build{}, err
	}
	build, _, err := loadBuildQuery(s.db.QueryRowContext(ctx, `SELECT id,plan_id,state,COALESCE(artifact_id,''),COALESCE(failure_reason,''),created_at,updated_at,version FROM builds WHERE id=$1`, id.String()))
	return build, err
}

func (s *Store) GetArtifact(ctx context.Context, id domain.ID) (domain.Artifact, error) {
	if err := s.requireDB(); err != nil {
		return domain.Artifact{}, err
	}
	if err := domain.RequireID(id, "artifact id"); err != nil {
		return domain.Artifact{}, err
	}
	return scanArtifact(s.db.QueryRowContext(ctx, `SELECT id,build_id,image_repository,image_digest,COALESCE(resolved_tag,''),oci_storage_ref,size_bytes,evidence,created_at FROM artifacts WHERE id=$1`, id.String()))
}

// GetRelease reconstructs the private digest map through release_artifacts,
// never by trusting a mutable caller-owned map.
func (s *Store) GetRelease(ctx context.Context, id domain.ID) (domain.Release, error) {
	if err := s.requireDB(); err != nil {
		return domain.Release{}, err
	}
	if err := domain.RequireID(id, "release id"); err != nil {
		return domain.Release{}, err
	}
	var releaseID, applicationID, serviceGroupID, configDigest, status string
	var version int
	var createdAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT id,application_id,service_group_id,version,config_digest,release_status,created_at FROM releases WHERE id=$1`, id.String()).Scan(&releaseID, &applicationID, &serviceGroupID, &version, &configDigest, &status, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Release{}, ErrNotFound
	}
	if err != nil {
		return domain.Release{}, fmt.Errorf("get release: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ra.service_name,a.image_repository,a.image_digest,COALESCE(a.resolved_tag,'') FROM release_artifacts ra JOIN artifacts a ON a.id=ra.artifact_id WHERE ra.release_id=$1 ORDER BY ra.service_name`, id.String())
	if err != nil {
		return domain.Release{}, fmt.Errorf("list release artifacts: %w", err)
	}
	defer rows.Close()
	digests := map[string]domain.ImageDigest{}
	for rows.Next() {
		var service, repository, digest, tag string
		if err := rows.Scan(&service, &repository, &digest, &tag); err != nil {
			return domain.Release{}, fmt.Errorf("scan release artifact: %w", err)
		}
		image, err := domain.ParseImageDigest(repository, digest)
		if err != nil {
			return domain.Release{}, fmt.Errorf("invalid persisted release artifact: %w", err)
		}
		image.ResolvedTag = tag
		digests[service] = image
	}
	if err := rows.Err(); err != nil {
		return domain.Release{}, fmt.Errorf("iterate release artifacts: %w", err)
	}
	payload, err := json.Marshal(struct {
		ID             domain.ID                     `json:"id"`
		ApplicationID  domain.ID                     `json:"application_id"`
		ServiceGroupID domain.ID                     `json:"service_group_id"`
		Version        int                           `json:"version"`
		ConfigDigest   string                        `json:"config_digest"`
		Status         domain.ReleaseStatus          `json:"status"`
		ServiceDigests map[string]domain.ImageDigest `json:"service_digests"`
		CreatedAt      time.Time                     `json:"created_at"`
		Immutable      bool                          `json:"immutable"`
	}{domain.ID(releaseID), domain.ID(applicationID), domain.ID(serviceGroupID), version, configDigest, domain.ReleaseStatus(status), digests, createdAt.UTC(), true})
	if err != nil {
		return domain.Release{}, err
	}
	var release domain.Release
	if err := json.Unmarshal(payload, &release); err != nil {
		return domain.Release{}, fmt.Errorf("invalid persisted release: %w", err)
	}
	return release, nil
}

func (s *Store) GetDeployment(ctx context.Context, id domain.ID) (domain.Deployment, error) {
	if err := s.requireDB(); err != nil {
		return domain.Deployment{}, err
	}
	if err := domain.RequireID(id, "deployment id"); err != nil {
		return domain.Deployment{}, err
	}
	deployment, _, err := loadM1DeploymentQuery(s.db.QueryRowContext(ctx, `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,COALESCE(d.failure_reason,''),d.version,d.created_at,d.updated_at FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`, id.String()))
	return deployment, err
}

func validateM1Build(build domain.Build) error {
	if err := domain.RequireID(build.ID, "build id"); err != nil {
		return err
	}
	if err := domain.RequireID(build.PlanID, "build plan id"); err != nil {
		return err
	}
	switch build.Status {
	case domain.BuildPending, domain.BuildRunning, domain.BuildSucceeded, domain.BuildFailed, domain.BuildCancelled:
	default:
		return domain.ValidationError("build status is unsupported")
	}
	return nil
}

func loadBuildTx(ctx context.Context, tx *sql.Tx, id domain.ID, lock bool) (domain.Build, int, error) {
	query := `SELECT id,plan_id,state,COALESCE(artifact_id,''),COALESCE(failure_reason,''),created_at,updated_at,version FROM builds WHERE id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	return loadBuildQuery(tx.QueryRowContext(ctx, query, id.String()))
}

func loadBuildQuery(row interface{ Scan(...any) error }) (domain.Build, int, error) {
	var build domain.Build
	var status string
	var version int
	err := row.Scan(&build.ID, &build.PlanID, &status, &build.ArtifactID, &build.Failure, &build.CreatedAt, &build.UpdatedAt, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Build{}, 0, ErrNotFound
	}
	if err != nil {
		return domain.Build{}, 0, err
	}
	build.Status, build.CreatedAt, build.UpdatedAt = domain.BuildStatus(status), build.CreatedAt.UTC(), build.UpdatedAt.UTC()
	if err := validateM1Build(build); err != nil {
		return domain.Build{}, 0, err
	}
	return build, version, nil
}

func loadM1DeploymentTx(ctx context.Context, tx *sql.Tx, id domain.ID, lock bool) (domain.Deployment, int, error) {
	query := `SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,COALESCE(d.failure_reason,''),d.version,d.created_at,d.updated_at FROM deployments d JOIN environments e ON e.id=d.environment_id WHERE d.id=$1`
	if lock {
		query += ` FOR UPDATE OF d`
	}
	return loadM1DeploymentQuery(tx.QueryRowContext(ctx, query, id.String()))
}

func loadM1DeploymentQuery(row interface{ Scan(...any) error }) (domain.Deployment, int, error) {
	var deployment domain.Deployment
	var state string
	var version int
	err := row.Scan(&deployment.ID, &deployment.ApplicationID, &deployment.EnvironmentID, &deployment.ReleaseID, &state, &deployment.FailureReason, &version, &deployment.CreatedAt, &deployment.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Deployment{}, 0, ErrNotFound
	}
	if err != nil {
		return domain.Deployment{}, 0, err
	}
	deployment.Status, deployment.CreatedAt, deployment.UpdatedAt = domain.DeploymentStatus(state), deployment.CreatedAt.UTC(), deployment.UpdatedAt.UTC()
	if err := deployment.Validate(); err != nil {
		return domain.Deployment{}, 0, err
	}
	return deployment, version, nil
}

func loadBuildPlanTx(ctx context.Context, tx *sql.Tx, sourceID domain.ID, service, key string) (domain.BuildPlan, error) {
	return scanBuildPlan(tx.QueryRowContext(ctx, `SELECT id,source_revision_id,source_digest,service_name,build_kind,context_path,COALESCE(dockerfile_path,''),COALESCE(static_runtime_digest,''),COALESCE(acornfox_definition_digest,''),COALESCE(acornfox_dockerfile_digest,''),COALESCE(acornfox_network_mode,''),COALESCE(acornfox_worker_policy_digest,''),target_repository,output_contract,secret_refs,idempotency_key,created_at FROM build_plans WHERE source_revision_id=$1 AND service_name=$2 AND idempotency_key=$3`, sourceID.String(), service, key))
}

func scanBuildPlan(row interface{ Scan(...any) error }) (domain.BuildPlan, error) {
	var plan domain.BuildPlan
	var kind string
	var output, secrets []byte
	err := row.Scan(&plan.ID, &plan.SourceRevisionID, &plan.SourceDigest, &plan.ServiceName, &kind, &plan.ContextPath, &plan.DockerfilePath, &plan.StaticRuntimeDigest, &plan.AcornFoxDefinitionDigest, &plan.AcornFoxDockerfileDigest, &plan.AcornFoxNetworkMode, &plan.AcornFoxWorkerPolicyDigest, &plan.TargetRepository, &output, &secrets, &plan.IdempotencyKey, &plan.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BuildPlan{}, ErrNotFound
	}
	if err != nil {
		return domain.BuildPlan{}, err
	}
	if err := json.Unmarshal(output, &plan.Output); err != nil {
		return domain.BuildPlan{}, fmt.Errorf("%w: invalid build output", ErrIdempotencyCorrupt)
	}
	if err := json.Unmarshal(secrets, &plan.SecretRefs); err != nil {
		return domain.BuildPlan{}, fmt.Errorf("%w: invalid build secret refs", ErrIdempotencyCorrupt)
	}
	plan.Kind, plan.CreatedAt = domain.BuildKind(kind), plan.CreatedAt.UTC()
	if err := plan.Validate(); err != nil {
		return domain.BuildPlan{}, err
	}
	return plan, nil
}

func scanArtifact(row interface{ Scan(...any) error }) (domain.Artifact, error) {
	var artifact domain.Artifact
	var repository, digest, tag string
	var evidence []byte
	err := row.Scan(&artifact.ID, &artifact.BuildID, &repository, &digest, &tag, &artifact.OCIStorageRef, &artifact.SizeBytes, &evidence, &artifact.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Artifact{}, ErrNotFound
	}
	if err != nil {
		return domain.Artifact{}, err
	}
	image, err := domain.ParseImageDigest(repository, digest)
	if err != nil {
		return domain.Artifact{}, err
	}
	image.ResolvedTag = tag
	artifact.Image = image
	if err := json.Unmarshal(evidence, &artifact.Evidence); err != nil {
		return domain.Artifact{}, fmt.Errorf("%w: invalid artifact evidence", ErrIdempotencyCorrupt)
	}
	artifact.CreatedAt = artifact.CreatedAt.UTC()
	if err := artifact.Validate(); err != nil {
		return domain.Artifact{}, err
	}
	return artifact, nil
}

func (s *Store) appendM1FactsTx(ctx context.Context, tx *sql.Tx, aggregateType, aggregateID, eventType string, value any, now time.Time) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode M1 event payload: %w", err)
	}
	if err := s.appendM1AuditTx(ctx, tx, eventType, payload, now); err != nil {
		return err
	}
	lockKey := "open-card-outbox:" + aggregateType + ":" + aggregateID
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return err
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type=$1 AND aggregate_id=$2`, aggregateType, aggregateID).Scan(&sequence); err != nil {
		return err
	}
	stream, err := s.nextStreamSequence(ctx, tx)
	if err != nil {
		return err
	}
	eventPayload, err := json.Marshal(map[string]any{"schema_version": "1.1", "aggregate_type": aggregateType, "aggregate_id": aggregateID, "event_type": eventType, "data": json.RawMessage(payload)})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,'1.1')`, "evt-"+formatSequence(uint64(stream)), aggregateType, aggregateID, sequence, sequence, stream, eventType, eventPayload, now.UTC())
	if err != nil {
		return fmt.Errorf("insert M1 outbox event: %w", err)
	}
	return nil
}

func (s *Store) appendM1AuditTx(ctx context.Context, tx *sql.Tx, action string, payload []byte, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('open-card-audit-evidence-chain',0))`); err != nil {
		return err
	}
	var previous sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	input := m1Digest(payload)
	recordHash := m1Digest([]byte(previous.String + "\x00" + action + "\x00" + input + "\x00" + now.UTC().Format(time.RFC3339Nano)))
	id, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,created_at) VALUES($1,'system','release-controller',$2,'M1 durable delivery transition',$3,'recorded','[]'::jsonb,$4,$5,$6)`, id.String(), action, input, nullableString(previous.String), recordHash, now.UTC())
	if err != nil {
		return fmt.Errorf("append M1 audit evidence: %w", err)
	}
	return nil
}

func m1JSONDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return m1Digest(payload), nil
}
func m1Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
