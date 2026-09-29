package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const acornFoxFixCandidateSelect = `SELECT candidate_id,application_id,base_source_revision_id,base_repository_url,base_commit,base_tree_digest,canonical_diff,patch_digest,result_tree_digest,container_port,changed_paths,validated_image_repository,validated_image_digest,build_log_ref,build_evidence_digest,runtime_evidence,matched_source_revision_id,matched_commit,owner_admin_id,idempotency_key,state,created_at,expires_at FROM acornfox_fix_candidates`

type acornFoxFixCandidateDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var ErrAcornFoxFixCandidateLeaderHeld = errors.New("fix candidate execution leader is already held")

const acornFoxFixCandidateLeaderLockName = "open-card:acornfox-fix-candidate:v1"

type AcornFoxFixCandidateLeaderLease struct {
	conn       *sql.Conn
	once       sync.Once
	releaseErr error
}

func (l *AcornFoxFixCandidateLeaderLease) Release(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.conn == nil {
			return
		}
		releaseContext := ctx
		var cancel context.CancelFunc
		if releaseContext == nil || releaseContext.Err() != nil {
			releaseContext, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		var unlocked bool
		if err := l.conn.QueryRowContext(releaseContext, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, acornFoxFixCandidateLeaderLockName).Scan(&unlocked); err != nil {
			l.releaseErr = fmt.Errorf("release fix candidate leader: %w", err)
		} else if !unlocked {
			l.releaseErr = errors.New("release fix candidate leader: advisory lock was not owned")
		}
		if err := l.conn.Close(); err != nil && l.releaseErr == nil {
			l.releaseErr = fmt.Errorf("close fix candidate leader connection: %w", err)
		}
		l.conn = nil
	})
	return l.releaseErr
}

// Monitor proves that the same dedicated PostgreSQL session remains alive.
// Session advisory locks are released by PostgreSQL when this connection is
// lost, so a failed probe is also a loss of execution authority.
func (l *AcornFoxFixCandidateLeaderLease) Monitor(ctx context.Context, interval time.Duration) error {
	if l == nil || l.conn == nil || ctx == nil || interval < 50*time.Millisecond || interval > 5*time.Second {
		return domain.ValidationError("fix candidate leader monitor is invalid")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			probeContext, cancel := context.WithTimeout(ctx, interval)
			var one int
			err := l.conn.QueryRowContext(probeContext, `SELECT 1`).Scan(&one)
			cancel()
			if err != nil || one != 1 {
				if err == nil {
					err = errors.New("fix candidate leader probe returned invalid result")
				}
				return fmt.Errorf("monitor fix candidate leader: %w", err)
			}
		}
	}
}

func (s *Store) AcquireAcornFoxFixCandidateLeader(ctx context.Context) (*AcornFoxFixCandidateLeaderLease, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, domain.ValidationError("fix candidate leader context is required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open fix candidate leader connection: %w", err)
	}
	closeWith := func(cause error) (*AcornFoxFixCandidateLeaderLease, error) {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w; close fix candidate leader connection: %v", cause, closeErr)
		}
		return nil, cause
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, acornFoxFixCandidateLeaderLockName).Scan(&acquired); err != nil {
		return closeWith(fmt.Errorf("acquire fix candidate leader: %w", err))
	}
	if !acquired {
		return closeWith(ErrAcornFoxFixCandidateLeaderHeld)
	}
	return &AcornFoxFixCandidateLeaderLease{conn: conn}, nil
}

// AcornFoxFixCandidateFencedStore routes every candidate state mutation
// through the same dedicated session that owns the advisory leader lock. If
// that session is lost, PostgreSQL releases the lock and these writes fail on
// the dead connection rather than succeeding through an unfenced pool
// connection.
type AcornFoxFixCandidateFencedStore struct {
	store  *Store
	leader *AcornFoxFixCandidateLeaderLease
}

func NewAcornFoxFixCandidateFencedStore(store *Store, leader *AcornFoxFixCandidateLeaderLease) (*AcornFoxFixCandidateFencedStore, error) {
	if store == nil || leader == nil || leader.conn == nil {
		return nil, domain.ValidationError("fix candidate fenced store is unavailable")
	}
	return &AcornFoxFixCandidateFencedStore{store: store, leader: leader}, nil
}

func (f *AcornFoxFixCandidateFencedStore) GetSourceRevision(ctx context.Context, id domain.ID) (domain.SourceRevision, error) {
	return f.store.GetSourceRevision(ctx, id)
}
func (f *AcornFoxFixCandidateFencedStore) GetAcornFoxSourceMetadata(ctx context.Context, applicationID, sourceRevisionID domain.ID) (contracts.AcornFoxSourceMetadata, error) {
	return f.store.GetAcornFoxSourceMetadata(ctx, applicationID, sourceRevisionID)
}
func (f *AcornFoxFixCandidateFencedStore) AcornFoxApplicationHasActiveSecrets(ctx context.Context, applicationID domain.ID) (bool, error) {
	return f.store.AcornFoxApplicationHasActiveSecrets(ctx, applicationID)
}
func (f *AcornFoxFixCandidateFencedStore) ReplayAcornFoxFixCandidate(ctx context.Context, request application.AcornFoxFixCandidateCreateRequest, digest string) (*application.AcornFoxFixCandidate, error) {
	return f.store.ReplayAcornFoxFixCandidate(ctx, request, digest)
}
func (f *AcornFoxFixCandidateFencedStore) BeginAcornFoxFixCandidate(ctx context.Context, request application.AcornFoxFixCandidateCreateRequest, digest string, now time.Time) (*application.AcornFoxFixCandidate, error) {
	return f.store.beginAcornFoxFixCandidate(ctx, f.leader.conn, request, digest, now)
}
func (f *AcornFoxFixCandidateFencedStore) CompleteAcornFoxFixCandidate(ctx context.Context, candidate application.AcornFoxFixCandidate, digest string) error {
	return f.store.completeAcornFoxFixCandidate(ctx, f.leader.conn, candidate, digest)
}
func (f *AcornFoxFixCandidateFencedStore) FailAcornFoxFixCandidate(ctx context.Context, applicationID domain.ID, key, digest string, now time.Time) error {
	return f.store.failAcornFoxFixCandidate(ctx, f.leader.conn, applicationID, key, digest, now)
}
func (f *AcornFoxFixCandidateFencedStore) GetAcornFoxFixCandidate(ctx context.Context, applicationID, candidateID domain.ID) (application.AcornFoxFixCandidate, error) {
	return f.store.GetAcornFoxFixCandidate(ctx, applicationID, candidateID)
}
func (f *AcornFoxFixCandidateFencedStore) MatchAcornFoxFixCandidateSource(ctx context.Context, applicationID, candidateID, sourceRevisionID domain.ID, commit string, now time.Time) (application.AcornFoxFixCandidate, error) {
	return f.store.matchAcornFoxFixCandidateSource(ctx, f.leader.conn, applicationID, candidateID, sourceRevisionID, commit, now)
}
func (f *AcornFoxFixCandidateFencedStore) RecoverAcornFoxFixCandidates(ctx context.Context, now time.Time) error {
	return f.store.recoverAcornFoxFixCandidates(ctx, f.leader.conn, now)
}

func (s *Store) AcornFoxApplicationHasActiveSecrets(ctx context.Context, applicationID domain.ID) (bool, error) {
	if err := s.requireDB(); err != nil {
		return false, err
	}
	if applicationID.Empty() {
		return false, domain.ValidationError("application identity is invalid")
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM secret_references WHERE application_id=$1 AND revoked_at IS NULL)`, applicationID.String()).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Store) BeginAcornFoxFixCandidate(ctx context.Context, request application.AcornFoxFixCandidateCreateRequest, digest string, now time.Time) (*application.AcornFoxFixCandidate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	return s.beginAcornFoxFixCandidate(ctx, s.db, request, digest, now)
}

func (s *Store) beginAcornFoxFixCandidate(ctx context.Context, db acornFoxFixCandidateDB, request application.AcornFoxFixCandidateCreateRequest, digest string, now time.Time) (*application.AcornFoxFixCandidate, error) {
	if request.ApplicationID.Empty() || request.BaseSourceRevisionID.Empty() || request.OwnerAdminID.Empty() || request.IdempotencyKey == "" || len(request.IdempotencyKey) > 256 || !postgresCandidateDigest(digest) {
		return nil, domain.ValidationError("fix candidate reservation is invalid")
	}
	if now.IsZero() {
		now = s.now()
	}
	var appManagementState string
	if err := db.QueryRowContext(ctx, `SELECT management_state FROM applications WHERE id=$1`, request.ApplicationID.String()).Scan(&appManagementState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if appManagementState != "active" {
		return nil, domain.NewError(domain.ErrConflict, "application is archiving or archived")
	}
	var activeMgmtID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM acornfox_management_commands WHERE application_id=$1 AND phase NOT IN ('completed', 'failed')`, request.ApplicationID.String()).Scan(&activeMgmtID); err == nil {
		return nil, domain.NewError(domain.ErrConflict, "application management operation in progress")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	result, err := db.ExecContext(ctx, `INSERT INTO acornfox_fix_candidates(application_id,idempotency_key,request_digest,base_source_revision_id,owner_admin_id,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'preparing',$6,$6) ON CONFLICT(application_id,idempotency_key) DO NOTHING`, request.ApplicationID.String(), request.IdempotencyKey, digest, request.BaseSourceRevisionID.String(), request.OwnerAdminID.String(), now.UTC())
	if err != nil {
		return nil, fmt.Errorf("reserve fix candidate: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if inserted == 1 {
		return nil, nil
	}
	var storedDigest, owner string
	if err := db.QueryRowContext(ctx, `SELECT request_digest,owner_admin_id FROM acornfox_fix_candidates WHERE application_id=$1 AND idempotency_key=$2`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&storedDigest, &owner); err != nil {
		return nil, err
	}
	if storedDigest != digest || owner != request.OwnerAdminID.String() {
		return nil, ErrIdempotencyConflict
	}
	candidate, err := s.GetAcornFoxFixCandidate(ctx, request.ApplicationID, application.AcornFoxFixCandidateIDFromRequestDigest(digest))
	if err != nil {
		return nil, err
	}
	return &candidate, nil
}

func (s *Store) ReplayAcornFoxFixCandidate(ctx context.Context, request application.AcornFoxFixCandidateCreateRequest, digest string) (*application.AcornFoxFixCandidate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if request.ApplicationID.Empty() || request.OwnerAdminID.Empty() || request.IdempotencyKey == "" || !postgresCandidateDigest(digest) {
		return nil, domain.ValidationError("fix candidate replay is invalid")
	}
	var storedDigest, owner string
	err := s.db.QueryRowContext(ctx, `SELECT request_digest,owner_admin_id FROM acornfox_fix_candidates WHERE application_id=$1 AND idempotency_key=$2`, request.ApplicationID.String(), request.IdempotencyKey).Scan(&storedDigest, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if storedDigest != digest || owner != request.OwnerAdminID.String() {
		return nil, ErrIdempotencyConflict
	}
	candidate, err := s.GetAcornFoxFixCandidate(ctx, request.ApplicationID, application.AcornFoxFixCandidateIDFromRequestDigest(digest))
	if err != nil {
		return nil, err
	}
	return &candidate, nil
}

type AcornFoxFixCandidateRuntimeTaskRequest struct {
	CandidateID, ApplicationID domain.ID
	Image                      domain.ImageDigest
	ContainerPort              int
	IdempotencyKey             string
	Actor                      string
	Now                        time.Time
}

type acornFoxCandidateAgentResources struct {
	CPUMillis            int64 `json:"cpu_millis"`
	MemoryBytes          int64 `json:"memory_bytes"`
	PIDs                 int64 `json:"pids"`
	DiskReservationBytes int64 `json:"disk_reservation_bytes"`
}

type acornFoxCandidateAgentSpec struct {
	CandidateID   domain.ID                       `json:"candidate_id"`
	ApplicationID domain.ID                       `json:"application_id"`
	Image         domain.ImageDigest              `json:"image"`
	ContainerPort int                             `json:"container_port"`
	Resources     acornFoxCandidateAgentResources `json:"resources"`
}

type acornFoxCandidateAgentWrapper struct {
	PayloadType string                     `json:"acornfox_candidate_payload_type"`
	Request     acornFoxCandidateAgentSpec `json:"request"`
}

type acornFoxCandidateTaskPayload struct {
	Kind       v1.TaskKind     `json:"kind"`
	Parameters json.RawMessage `json:"parameters"`
}

const acornFoxCandidateEnvironmentName = "acornfox-candidate-validation"

func (s *Store) EnqueueAcornFoxFixCandidateRuntimeTask(ctx context.Context, request AcornFoxFixCandidateRuntimeTaskRequest) (domain.ID, error) {
	if request.CandidateID.Empty() || request.ApplicationID.Empty() || request.Image.Validate() != nil || request.ContainerPort < 1 || request.ContainerPort > 65535 || request.IdempotencyKey == "" || request.Actor == "" {
		return "", domain.ValidationError("candidate runtime task is invalid")
	}
	if request.Now.IsZero() {
		request.Now = s.now()
	}
	environmentID := domain.ID("env_candidate_" + candidateStoreID("environment", request.ApplicationID.String())[:24])
	identity := candidateStoreID(request.CandidateID.String(), request.Image.Repository, request.Image.Digest, request.IdempotencyKey)
	operation, err := domain.NewOperation(request.ApplicationID, environmentID, domain.OperationDeploy, "candidate/"+request.CandidateID.String()+"/runtime", request.IdempotencyKey, request.Now.UTC())
	if err != nil {
		return "", err
	}
	operation.ID = domain.ID("op_candidate_" + identity[:24])
	taskID := domain.ID("task_candidate_" + identity[:24])
	spec := acornFoxCandidateAgentSpec{CandidateID: request.CandidateID, ApplicationID: request.ApplicationID, Image: request.Image, ContainerPort: request.ContainerPort, Resources: acornFoxCandidateAgentResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}}
	parameters, err := json.Marshal(acornFoxCandidateAgentWrapper{PayloadType: "acornfox_candidate_validation_v1", Request: spec})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(acornFoxCandidateTaskPayload{Kind: v1.TaskDeploy, Parameters: parameters})
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	rollback := func(cause error) (domain.ID, error) { return "", rollbackTx(tx, cause) }
	if _, err := tx.ExecContext(ctx, `INSERT INTO environments(id,application_id,name,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(application_id,name) DO NOTHING`, environmentID.String(), request.ApplicationID.String(), acornFoxCandidateEnvironmentName, request.Now.UTC()); err != nil {
		return rollback(err)
	}
	var storedID, storedApplication, storedName string
	if err := tx.QueryRowContext(ctx, `SELECT id,application_id,name FROM environments WHERE application_id=$1 AND name=$2 FOR SHARE`, request.ApplicationID.String(), acornFoxCandidateEnvironmentName).Scan(&storedID, &storedApplication, &storedName); err != nil {
		return rollback(err)
	}
	if storedID != environmentID.String() || storedApplication != request.ApplicationID.String() || storedName != acornFoxCandidateEnvironmentName {
		return rollback(domain.ValidationError("candidate runtime environment scope is not platform-owned"))
	}
	if _, err := s.enqueueControllerTaskTx(ctx, tx, EnqueueControllerTaskRequest{Operation: operation, TaskID: taskID, Payload: payload, MaxAttempts: 3}); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit candidate runtime task: %w", err)
	}
	return taskID, nil
}

func (s *Store) GetAcornFoxFixCandidateRuntimeEvidence(ctx context.Context, taskID domain.ID, image domain.ImageDigest) (application.AcornFoxFixCandidateRuntimeEvidence, bool, error) {
	task, err := s.GetControllerTask(ctx, taskID)
	if err != nil {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, err
	}
	if task.Task.State == TaskReady || task.Task.State == TaskLeased {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, nil
	}
	if task.Task.State != TaskCompleted || task.Operation.Status != domain.OperationSucceeded {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, application.ErrAcornFoxFixCandidateFailed
	}
	var durable acornFoxCandidateTaskPayload
	if err := decodeControllerTaskJSON(task.Task.Payload, &durable); err != nil || durable.Kind != v1.TaskDeploy {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, errors.New("candidate runtime task payload is invalid")
	}
	var wrapper acornFoxCandidateAgentWrapper
	expectedEnvironmentID := domain.ID("env_candidate_" + candidateStoreID("environment", task.Operation.ApplicationID.String())[:24])
	if err := decodeControllerTaskJSON(durable.Parameters, &wrapper); err != nil || wrapper.PayloadType != "acornfox_candidate_validation_v1" || wrapper.Request.Image != image || wrapper.Request.CandidateID.Empty() || wrapper.Request.ApplicationID != task.Operation.ApplicationID || wrapper.Request.ContainerPort < 1 || task.Operation.Type != domain.OperationDeploy || task.Operation.EnvironmentID != expectedEnvironmentID || task.Operation.TargetRef != "candidate/"+wrapper.Request.CandidateID.String()+"/runtime" || wrapper.Request.Resources != (acornFoxCandidateAgentResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}) {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, errors.New("candidate runtime task identity is invalid")
	}
	runtimeID, err := candidateAgentRuntimeID(wrapper.Request)
	if err != nil {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, err
	}
	var payload json.RawMessage
	if err := s.db.QueryRowContext(ctx, `SELECT payload FROM task_agent_events WHERE task_id=$1 AND event_type='observation' ORDER BY sequence DESC LIMIT 1`, taskID.String()).Scan(&payload); err != nil {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, err
	}
	var observation v1.Observation
	if err := json.Unmarshal(payload, &observation); err != nil || observation.Validate() != nil || observation.TaskID != taskID.String() || observation.Sequence != 1 || len(observation.Details) == 0 || observation.Status != "stopped" || observation.Healthy || observation.TargetRef != "candidate/"+wrapper.Request.CandidateID.String()+"/runtime" {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, errors.New("candidate runtime observation is invalid")
	}
	var details struct {
		CandidateID domain.ID                       `json:"candidate_id"`
		RuntimeID   string                          `json:"runtime_id"`
		Image       domain.ImageDigest              `json:"image"`
		Resources   acornFoxCandidateAgentResources `json:"resources"`
		Probe       struct {
			RuntimeID   string    `json:"runtime_id"`
			ContainerID string    `json:"container_id"`
			TargetClass string    `json:"target_class"`
			Outcome     string    `json:"outcome"`
			EvidenceRef string    `json:"evidence_ref"`
			ObservedAt  time.Time `json:"observed_at"`
		} `json:"probe"`
		Absence struct {
			RuntimeID   string    `json:"runtime_id"`
			Absent      bool      `json:"absent"`
			EvidenceRef string    `json:"evidence_ref"`
			ObservedAt  time.Time `json:"observed_at"`
		} `json:"absence"`
	}
	if err := decodeControllerTaskJSON(observation.Details, &details); err != nil || details.CandidateID != wrapper.Request.CandidateID || details.RuntimeID != runtimeID || details.Image != image || details.Resources != wrapper.Request.Resources || details.Probe.RuntimeID != runtimeID || len(details.Probe.ContainerID) != 64 || details.Probe.TargetClass != "loopback" || details.Probe.Outcome != "responded" || details.Probe.EvidenceRef == "" || details.Probe.ObservedAt.IsZero() || details.Absence.RuntimeID != runtimeID || !details.Absence.Absent || details.Absence.EvidenceRef == "" || details.Absence.ObservedAt.IsZero() || len(observation.EvidenceRefs) != 2 || observation.EvidenceRefs[0] != details.Probe.EvidenceRef || observation.EvidenceRefs[1] != details.Absence.EvidenceRef {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, errors.New("candidate runtime evidence is invalid")
	}
	for _, character := range details.Probe.ContainerID {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return application.AcornFoxFixCandidateRuntimeEvidence{}, false, errors.New("candidate runtime container identity is invalid")
		}
	}
	absenceDigest := sha256.Sum256([]byte("candidate-container-absent\x00" + details.Probe.ContainerID))
	expectedAbsenceRef := "candidate-absence:sha256:" + hex.EncodeToString(absenceDigest[:])
	if details.Absence.EvidenceRef != expectedAbsenceRef {
		return application.AcornFoxFixCandidateRuntimeEvidence{}, false, errors.New("candidate runtime absence evidence does not match the observed container")
	}
	digest := candidateStoreEvidence(taskID.String(), wrapper.Request.CandidateID.String(), runtimeID, image.Repository, image.Digest, details.Probe.ContainerID, observation.EvidenceRefs[0], observation.EvidenceRefs[1])
	return application.AcornFoxFixCandidateRuntimeEvidence{TaskID: taskID, Image: image, RuntimeState: "stopped", ProbeOutcome: "responded", CleanupConfirmed: true, EvidenceDigest: digest}, true, nil
}

func (s *Store) CompleteAcornFoxFixCandidate(ctx context.Context, candidate application.AcornFoxFixCandidate, requestDigest string) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	return s.completeAcornFoxFixCandidate(ctx, s.db, candidate, requestDigest)
}

func (s *Store) completeAcornFoxFixCandidate(ctx context.Context, db acornFoxFixCandidateDB, candidate application.AcornFoxFixCandidate, requestDigest string) error {
	if candidate.Validate() != nil || candidate.Status != application.AcornFoxFixCandidateValidated || !postgresCandidateDigest(requestDigest) {
		return domain.ValidationError("fix candidate completion is invalid")
	}
	changedPaths, err := json.Marshal(candidate.ChangedPaths)
	if err != nil {
		return err
	}
	runtime, err := json.Marshal(candidate.Runtime)
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `UPDATE acornfox_fix_candidates SET state='validated',candidate_id=$1,base_repository_url=$2,base_commit=$3,base_tree_digest=$4,canonical_diff=$5,patch_digest=$6,result_tree_digest=$7,container_port=$8,changed_paths=$9::jsonb,validated_image_repository=$10,validated_image_digest=$11,build_log_ref=$12,build_evidence_digest=$13,runtime_evidence=$14::jsonb,expires_at=$15,updated_at=$16 WHERE application_id=$17 AND idempotency_key=$18 AND request_digest=$19 AND base_source_revision_id=$20 AND owner_admin_id=$21 AND state='preparing'`, candidate.ID.String(), candidate.BaseRepositoryURL, candidate.BaseCommit, candidate.BaseTreeDigest, []byte(candidate.CanonicalDiff), candidate.PatchDigest, candidate.ResultTreeDigest, candidate.ContainerPort, changedPaths, candidate.ValidatedImage.Repository, candidate.ValidatedImage.Digest, candidate.BuildLogRef, candidate.BuildEvidenceDigest, runtime, candidate.ExpiresAt.UTC(), candidate.CreatedAt.UTC(), candidate.ApplicationID.String(), candidate.RequestKey, requestDigest, candidate.BaseSourceRevisionID.String(), candidate.OwnerAdminID.String())
	if err != nil {
		return fmt.Errorf("complete fix candidate: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Store) FailAcornFoxFixCandidate(ctx context.Context, applicationID domain.ID, idempotencyKey, digest string, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	return s.failAcornFoxFixCandidate(ctx, s.db, applicationID, idempotencyKey, digest, now)
}

func (s *Store) failAcornFoxFixCandidate(ctx context.Context, db acornFoxFixCandidateDB, applicationID domain.ID, idempotencyKey, digest string, now time.Time) error {
	if applicationID.Empty() || idempotencyKey == "" || !postgresCandidateDigest(digest) {
		return domain.ValidationError("fix candidate failure is invalid")
	}
	if now.IsZero() {
		now = s.now()
	}
	_, err := db.ExecContext(ctx, `UPDATE acornfox_fix_candidates SET state='failed',failure_code='candidate_failed',updated_at=$1 WHERE application_id=$2 AND idempotency_key=$3 AND request_digest=$4 AND state='preparing'`, now.UTC(), applicationID.String(), idempotencyKey, digest)
	return err
}

func (s *Store) RecoverAcornFoxFixCandidates(ctx context.Context, now time.Time) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	return s.recoverAcornFoxFixCandidates(ctx, s.db, now)
}

func (s *Store) recoverAcornFoxFixCandidates(ctx context.Context, db acornFoxFixCandidateDB, now time.Time) error {
	if now.IsZero() {
		now = s.now()
	}
	_, err := db.ExecContext(ctx, `UPDATE acornfox_fix_candidates SET state='failed',failure_code='candidate_failed',updated_at=$1 WHERE state='preparing'`, now.UTC())
	return err
}

func (s *Store) GetAcornFoxFixCandidate(ctx context.Context, applicationID, candidateID domain.ID) (application.AcornFoxFixCandidate, error) {
	if err := s.requireDB(); err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	if applicationID.Empty() || candidateID.Empty() {
		return application.AcornFoxFixCandidate{}, domain.ValidationError("fix candidate identity is invalid")
	}
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT state FROM acornfox_fix_candidates WHERE application_id=$1 AND COALESCE(candidate_id,'candidate_'||substr(request_digest,8,32))=$2`, applicationID.String(), candidateID.String()).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return application.AcornFoxFixCandidate{}, ErrNotFound
	}
	if err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	if state == string(application.AcornFoxFixCandidatePreparing) || state == string(application.AcornFoxFixCandidateFailed) {
		return scanAcornFoxFixCandidateLifecycle(s.db.QueryRowContext(ctx, `SELECT 'candidate_'||substr(request_digest,8,32),application_id,base_source_revision_id,owner_admin_id,idempotency_key,state,created_at FROM acornfox_fix_candidates WHERE application_id=$1 AND COALESCE(candidate_id,'candidate_'||substr(request_digest,8,32))=$2`, applicationID.String(), candidateID.String()))
	}
	candidate, err := scanAcornFoxFixCandidate(s.db.QueryRowContext(ctx, acornFoxFixCandidateSelect+` WHERE application_id=$1 AND candidate_id=$2`, applicationID.String(), candidateID.String()))
	return candidate, err
}

func (s *Store) ListAcornFoxFixCandidates(ctx context.Context, applicationID, ownerAdminID domain.ID) ([]application.AcornFoxFixCandidate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if applicationID.Empty() || ownerAdminID.Empty() {
		return nil, domain.ValidationError("fix candidate list identity is invalid")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(candidate_id,'candidate_'||substr(request_digest,8,32)) FROM acornfox_fix_candidates WHERE application_id=$1 AND owner_admin_id=$2 ORDER BY created_at DESC,idempotency_key DESC LIMIT 50`, applicationID.String(), ownerAdminID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]domain.ID, 0, 50)
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]application.AcornFoxFixCandidate, 0, len(ids))
	for _, id := range ids {
		candidate, err := s.GetAcornFoxFixCandidate(ctx, applicationID, id)
		if err != nil {
			return nil, err
		}
		if candidate.OwnerAdminID != ownerAdminID {
			return nil, errors.New("fix candidate list ownership changed")
		}
		result = append(result, candidate)
	}
	return result, nil
}

func (s *Store) MatchAcornFoxFixCandidateSource(ctx context.Context, applicationID, candidateID, sourceRevisionID domain.ID, commit string, now time.Time) (application.AcornFoxFixCandidate, error) {
	if err := s.requireDB(); err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	return s.matchAcornFoxFixCandidateSource(ctx, s.db, applicationID, candidateID, sourceRevisionID, commit, now)
}

func (s *Store) matchAcornFoxFixCandidateSource(ctx context.Context, db acornFoxFixCandidateDB, applicationID, candidateID, sourceRevisionID domain.ID, commit string, now time.Time) (application.AcornFoxFixCandidate, error) {
	if applicationID.Empty() || candidateID.Empty() || sourceRevisionID.Empty() || commit == "" {
		return application.AcornFoxFixCandidate{}, domain.ValidationError("fix candidate match is invalid")
	}
	if now.IsZero() {
		now = s.now()
	}
	result, err := db.ExecContext(ctx, `UPDATE acornfox_fix_candidates candidate SET state='source_matched',matched_source_revision_id=$1,matched_commit=$2,updated_at=$3 WHERE candidate.application_id=$4 AND candidate.candidate_id=$5 AND candidate.state='validated' AND candidate.expires_at>$3 AND EXISTS(SELECT 1 FROM source_revisions source JOIN acornfox_source_metadata metadata ON metadata.source_revision_id=source.id WHERE source.id=$1 AND source.application_id=candidate.application_id AND source.source_kind='git_https' AND source.locator=candidate.base_repository_url AND source.content_digest=candidate.result_tree_digest AND source.git_commit=$2 AND metadata.repository_url=candidate.base_repository_url)`, sourceRevisionID.String(), commit, now.UTC(), applicationID.String(), candidateID.String())
	if err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	if changed != 1 {
		return application.AcornFoxFixCandidate{}, application.ErrAcornFoxFixCandidateMismatch
	}
	return s.GetAcornFoxFixCandidate(ctx, applicationID, candidateID)
}

type acornFoxFixCandidateScanner interface {
	Scan(...any) error
}

func scanAcornFoxFixCandidateLifecycle(row acornFoxFixCandidateScanner) (application.AcornFoxFixCandidate, error) {
	var candidate application.AcornFoxFixCandidate
	var state string
	if err := row.Scan(&candidate.ID, &candidate.ApplicationID, &candidate.BaseSourceRevisionID, &candidate.OwnerAdminID, &candidate.RequestKey, &state, &candidate.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return application.AcornFoxFixCandidate{}, ErrNotFound
		}
		return application.AcornFoxFixCandidate{}, err
	}
	candidate.Status = application.AcornFoxFixCandidateStatus(state)
	candidate.CreatedAt = candidate.CreatedAt.UTC()
	if err := candidate.Validate(); err != nil {
		return application.AcornFoxFixCandidate{}, fmt.Errorf("stored fix candidate lifecycle is invalid: %w", err)
	}
	return candidate, nil
}

func scanAcornFoxFixCandidate(row acornFoxFixCandidateScanner) (application.AcornFoxFixCandidate, error) {
	var candidate application.AcornFoxFixCandidate
	var canonicalDiff, changedPaths, runtime []byte
	var matchedSource, matchedCommit sql.NullString
	var state string
	err := row.Scan(&candidate.ID, &candidate.ApplicationID, &candidate.BaseSourceRevisionID, &candidate.BaseRepositoryURL, &candidate.BaseCommit, &candidate.BaseTreeDigest, &canonicalDiff, &candidate.PatchDigest, &candidate.ResultTreeDigest, &candidate.ContainerPort, &changedPaths, &candidate.ValidatedImage.Repository, &candidate.ValidatedImage.Digest, &candidate.BuildLogRef, &candidate.BuildEvidenceDigest, &runtime, &matchedSource, &matchedCommit, &candidate.OwnerAdminID, &candidate.RequestKey, &state, &candidate.CreatedAt, &candidate.ExpiresAt)
	if err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	if err := json.Unmarshal(changedPaths, &candidate.ChangedPaths); err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	if err := json.Unmarshal(runtime, &candidate.Runtime); err != nil {
		return application.AcornFoxFixCandidate{}, err
	}
	candidate.CanonicalDiff = string(canonicalDiff)
	if matchedSource.Valid {
		candidate.MatchedSourceRevisionID = domain.ID(matchedSource.String)
	}
	if matchedCommit.Valid {
		candidate.MatchedCommit = matchedCommit.String
	}
	candidate.Status = application.AcornFoxFixCandidateStatus(state)
	candidate.CreatedAt = candidate.CreatedAt.UTC()
	candidate.ExpiresAt = candidate.ExpiresAt.UTC()
	if err := candidate.Validate(); err != nil {
		return application.AcornFoxFixCandidate{}, fmt.Errorf("stored fix candidate is invalid: %w", err)
	}
	return candidate, nil
}

func postgresCandidateDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, char := range value[7:] {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func candidateStoreID(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func candidateStoreEvidence(values ...string) string {
	return "sha256:" + candidateStoreID(values...)
}

func candidateAgentRuntimeID(spec acornFoxCandidateAgentSpec) (string, error) {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "candidate_runtime_" + hex.EncodeToString(digest[:16]), nil
}
