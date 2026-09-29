package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

var _ appcontracts.ImagePublicAccessStore = (*Store)(nil)

var ErrImagePublicAccessUnavailable = errors.New("image public access schema is not registered")

const imagePublicAccessScope = "image.public_access.v1"

// Older databases without registered 0013 must fail explicitly rather than
// allowing a table-not-found error or a partial domain write.
func (s *Store) checkImagePublicAccess(ctx context.Context) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM _schema_migrations WHERE version=?`, version0013_image_public_access).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrImagePublicAccessUnavailable
	}
	return nil
}

func (s *Store) ImagePublicAccessSchemaReady(ctx context.Context) error {
	return s.checkImagePublicAccess(ctx)
}

// imageEndpointVersion binds an allocated loopback endpoint to the immutable
// deployment/container and the endpoint's allocation identity. Observation
// timestamps are excluded: Stop/Start retain the same lease and route.
func imageEndpointVersion(endpointID, deploymentID, containerID, createdAt string, hostPort, containerPort int) string {
	return "sha256:" + sha256Hex(fmt.Sprintf("image-endpoint-v1\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d", endpointID, deploymentID, containerID, createdAt, hostPort, containerPort))
}

// Match the route projector's finite loopback target restriction before an
// approval is persisted. The projector performs its own final check as well.
func imagePublicRoutablePort(port int) bool {
	if port < 1024 || port > 65535 {
		return false
	}
	switch port {
	case 2019, 2020, 5432, 8080, 8092, 18481, 18482:
		return false
	}
	return true
}

type imagePublicTarget struct {
	endpointID, endpointCreated, deploymentStatus, adminID string
	imageID, manifestDigest, planDigest                    string
	planID, deployOperationID                              domain.ID
	command                                                appcontracts.ImagePublicAccessCommand
}

func imagePublicTargetTx(ctx context.Context, tx *sql.Tx, deploymentID domain.ID) (imagePublicTarget, error) {
	var t imagePublicTarget
	err := tx.QueryRowContext(ctx, `SELECT d.id,d.application_id,d.environment_id,d.release_id,d.container_id,e.id,e.created_at,e.host_port,e.container_port,d.status,p.admin_id,
	 d.image_id,r.digest,r.plan_id,r.plan_digest,d.operation_id
 FROM image_deployments d JOIN image_releases r ON r.id=d.release_id AND r.application_id=d.application_id
 JOIN image_deploy_intents i ON i.operation_id=d.operation_id AND i.application_id=d.application_id AND i.environment_id=d.environment_id AND i.plan_id=r.plan_id AND i.plan_digest=r.plan_digest
 JOIN image_plans p ON p.id=r.plan_id AND p.plan_digest=r.plan_digest
 JOIN operations o ON o.id=d.operation_id AND o.state='succeeded'
 JOIN image_endpoints e ON e.deployment_id=d.id AND e.application_id=d.application_id AND e.environment_id=d.environment_id AND e.host_ip='127.0.0.1' AND e.protocol='http'
 WHERE d.id=? AND d.container_id IS NOT NULL AND d.image_id IS NOT NULL AND EXISTS(SELECT 1 FROM image_artifacts a WHERE a.release_id=r.id AND a.digest=r.digest AND a.image_id=d.image_id)`, deploymentID.String()).Scan(
		&t.command.DeploymentID, &t.command.ApplicationID, &t.command.EnvironmentID, &t.command.ReleaseID, &t.command.ContainerID,
		&t.endpointID, &t.endpointCreated, &t.command.HostPort, &t.command.ContainerPort, &t.deploymentStatus, &t.adminID,
		&t.imageID, &t.manifestDigest, &t.planID, &t.planDigest, &t.deployOperationID)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	if !validSha256Digest(t.imageID) || !validSha256Digest(t.manifestDigest) || !validSha256Digest(t.planDigest) {
		return t, ErrCorruptData
	}
	// Reuse the deploy path's canonical plan/digest verification. The complete
	// plan stays in this transaction and is never copied into the route DTO.
	if _, err := readLifecyclePlanTx(ctx, tx, appcontracts.ImageLifecycleBinding{
		DeploymentID: t.command.DeploymentID, ApplicationID: t.command.ApplicationID,
		EnvironmentID: t.command.EnvironmentID, ReleaseID: t.command.ReleaseID,
		DeployOperationID: t.deployOperationID, PlanID: t.planID,
		PlanDigest: t.planDigest, ManifestDigest: t.manifestDigest,
		ContainerPort: t.command.ContainerPort,
	}, domain.ID(t.adminID)); err != nil {
		return t, err
	}
	t.command.EndpointVersion = imageEndpointVersion(t.endpointID, deploymentID.String(), t.command.ContainerID, t.endpointCreated, t.command.HostPort, t.command.ContainerPort)
	if !imagePublicRoutablePort(t.command.HostPort) || t.command.ContainerPort < 1 || t.command.ContainerPort > 65535 {
		return t, domain.NewError(domain.ErrForbidden, "managed endpoint is not routable")
	}
	return t, nil
}

func (s *Store) BeginImagePublicAccess(ctx context.Context, adminID domain.ID, in appcontracts.ImagePublicAccessRequest) (appcontracts.ImagePublicAccessCommand, error) {
	var b appcontracts.ImagePublicAccessCommand
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return b, err
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if adminID.Empty() || in.DeploymentID.Empty() || key == "" || len(key) > 256 ||
		(in.Action != appcontracts.ImagePublicAccessEnsure && in.Action != appcontracts.ImagePublicAccessRemove) || appcontracts.ValidateImagePublicHostname(in.Hostname) != nil {
		return b, domain.ValidationError("invalid public access command")
	}
	now := time.Now().UTC()
	stamp := FormatTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	digest := sha256Hex(fmt.Sprintf("%s\x00%s\x00%s\x00%s", adminID, in.DeploymentID, in.Hostname, in.Action))
	res, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,created_at,updated_at) VALUES(?,?,?,'in_progress',?,?) ON CONFLICT(scope,idempotency_key) DO NOTHING`, imagePublicAccessScope, key, digest, stamp, stamp)
	if err != nil {
		return b, err
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return b, err
	}
	var savedDigest, state string
	var response sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, imagePublicAccessScope, key).Scan(&savedDigest, &state, &response); err != nil {
		return b, err
	}
	if savedDigest != digest {
		return b, ErrIdempotencyConflict
	}
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE id=? AND disabled_at IS NULL`, adminID.String()).Scan(&enabled); err != nil {
		return b, err
	}
	if enabled != 1 {
		return b, domain.NewError(domain.ErrUnauthorized, "administrator unavailable")
	}
	if inserted == 0 {
		if state != "completed" {
			return b, ErrIdempotencyInProgress
		}
		if !response.Valid || json.Unmarshal([]byte(response.String), &b) != nil || b.DeploymentID != in.DeploymentID || b.Hostname != in.Hostname || b.Action != in.Action || b.OperationID.Empty() || b.TaskID.Empty() {
			return b, ErrIdempotencyCorrupt
		}
		var owner string
		if err := tx.QueryRowContext(ctx, `SELECT admin_id FROM image_public_access_commands WHERE operation_id=? AND task_id=? AND approval_id=?`, b.OperationID.String(), b.TaskID.String(), b.ApprovalID.String()).Scan(&owner); err != nil || owner != adminID.String() {
			return b, ErrIdempotencyCorrupt
		}
		return b, lifecycleCommit(tx)
	}
	target, err := imagePublicTargetTx(ctx, tx, in.DeploymentID)
	if err != nil {
		return b, err
	}
	if target.adminID != adminID.String() {
		return b, domain.NewError(domain.ErrForbidden, "deployment owner mismatch")
	}
	if in.Action == appcontracts.ImagePublicAccessEnsure && target.deploymentStatus != "running" {
		return b, domain.NewError(domain.ErrConflict, "running managed deployment required")
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM image_lifecycle_commands c JOIN operations o ON o.id=c.operation_id WHERE c.deployment_id=? AND o.state IN ('pending','leased','running','waiting','cancelling')`, in.DeploymentID.String()).Scan(&active); err != nil {
		return b, err
	}
	if active != 0 {
		return b, domain.NewError(domain.ErrConflict, "lifecycle command active")
	}
	var existingID, existingHost, existingState, existingEndpoint string
	err = tx.QueryRowContext(ctx, `SELECT id,hostname,local_route_state,endpoint_id FROM image_public_access WHERE deployment_id=?`, in.DeploymentID.String()).Scan(&existingID, &existingHost, &existingState, &existingEndpoint)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return b, err
	}
	if in.Action == appcontracts.ImagePublicAccessRemove {
		if err != nil || existingHost != in.Hostname || existingState == "disabled" {
			return b, domain.NewError(domain.ErrConflict, "no managed route to remove")
		}
	} else if err == nil && (existingHost != in.Hostname || existingState != "disabled" || existingEndpoint != target.endpointID) {
		return b, domain.NewError(domain.ErrConflict, "deployment hostname already assigned")
	}
	b = target.command
	b.Hostname, b.Action, b.CreatedAt, b.State = in.Hostname, in.Action, now, "pending"
	if err == nil {
		b.ApprovalID = domain.ID(existingID)
	} else {
		b.ApprovalID, err = domain.NewID("access")
		if err != nil {
			return b, err
		}
	}
	b.OperationID, err = domain.NewID("op")
	if err != nil {
		return b, err
	}
	b.TaskID, err = domain.NewID("task")
	if err != nil {
		return b, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,version,target_ref,target_kind,created_at,updated_at) VALUES(?,?,?,?,?,'pending',1,?,'application',?,?)`, b.OperationID.String(), b.ApplicationID.String(), b.EnvironmentID.String(), "image.public_access."+string(b.Action), key, b.ApplicationID.String(), stamp, stamp); err != nil {
		return b, err
	}
	payload, err := json.Marshal(map[string]any{"kind": appcontracts.ImagePublicAccessTaskKind, "binding": b})
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_leases(task_id,operation_id,lease_owner,lease_until,attempt,max_attempts,state,payload,created_at,updated_at) VALUES(?,?,NULL,NULL,0,?,'ready',?,?,?)`, b.TaskID.String(), b.OperationID.String(), defaultTaskMaxAttempts, string(payload), stamp, stamp); err != nil {
		return b, err
	}
	if existingID == "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO image_public_access(id,deployment_id,application_id,environment_id,release_id,admin_id,hostname,endpoint_id,endpoint_version,container_id,host_port,container_port,desired_public,local_route_state,operation_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,'desired',?,?,?)`, b.ApprovalID.String(), b.DeploymentID.String(), b.ApplicationID.String(), b.EnvironmentID.String(), b.ReleaseID.String(), adminID.String(), b.Hostname, target.endpointID, b.EndpointVersion, b.ContainerID, b.HostPort, b.ContainerPort, b.OperationID.String(), stamp, stamp)
	} else {
		// Removal remains desired until Core has actually projected the removal;
		// the endpoint trigger continues to fence release through this interval.
		_, err = tx.ExecContext(ctx, `UPDATE image_public_access SET desired_public=?,local_route_state='desired',operation_id=?,endpoint_version=?,container_id=?,host_port=?,container_port=?,certificate_fingerprint=NULL,certificate_expires_at=NULL,observed_at=NULL,updated_at=? WHERE id=? AND admin_id=?`, in.Action == appcontracts.ImagePublicAccessEnsure, b.OperationID.String(), b.EndpointVersion, b.ContainerID, b.HostPort, b.ContainerPort, stamp, existingID, adminID.String())
	}
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO image_public_access_commands(operation_id,task_id,approval_id,deployment_id,admin_id,action,binding,created_at) VALUES(?,?,?,?,?,?,?,?)`, b.OperationID.String(), b.TaskID.String(), b.ApprovalID.String(), b.DeploymentID.String(), adminID.String(), string(b.Action), string(raw), stamp); err != nil {
		return b, err
	}
	if err := imagePublicEvidenceTx(ctx, tx, b, "accepted", adminID, now, 1); err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=?,updated_at=? WHERE scope=? AND idempotency_key=?`, string(raw), stamp, imagePublicAccessScope, key); err != nil {
		return b, err
	}
	return b, lifecycleCommit(tx)
}

// ReplayImagePublicAccess is a read-only recovery path for an accepted
// command whose HTTP response was lost while Gateway became unavailable. It
// cannot create a fresh intent or accept a different body under the same key.
func (s *Store) ReplayImagePublicAccess(ctx context.Context, adminID domain.ID, in appcontracts.ImagePublicAccessRequest) (appcontracts.ImagePublicAccessCommand, error) {
	var b appcontracts.ImagePublicAccessCommand
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return b, err
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if adminID.Empty() || in.DeploymentID.Empty() || key == "" || len(key) > 256 || appcontracts.ValidateImagePublicHostname(in.Hostname) != nil ||
		(in.Action != appcontracts.ImagePublicAccessEnsure && in.Action != appcontracts.ImagePublicAccessRemove) {
		return b, domain.ValidationError("invalid public access replay")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE id=? AND disabled_at IS NULL`, adminID.String()).Scan(&enabled); err != nil {
		return b, err
	}
	if enabled != 1 {
		return b, domain.NewError(domain.ErrUnauthorized, "administrator unavailable")
	}
	var digest, state string
	var response sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT request_digest,status,response FROM idempotency_records WHERE scope=? AND idempotency_key=?`, imagePublicAccessScope, key).Scan(&digest, &state, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	if err != nil {
		return b, err
	}
	want := sha256Hex(fmt.Sprintf("%s\x00%s\x00%s\x00%s", adminID, in.DeploymentID, in.Hostname, in.Action))
	if digest != want {
		return b, ErrIdempotencyConflict
	}
	if state != "completed" {
		return b, ErrIdempotencyInProgress
	}
	if !response.Valid || json.Unmarshal([]byte(response.String), &b) != nil || b.OperationID.Empty() || b.TaskID.Empty() || b.ApprovalID.Empty() || b.CreatedAt.IsZero() || b.State != "pending" || b.DeploymentID != in.DeploymentID || b.Hostname != in.Hostname || b.Action != in.Action {
		return b, ErrIdempotencyCorrupt
	}
	var owner string
	if err := tx.QueryRowContext(ctx, `SELECT admin_id FROM image_public_access_commands WHERE operation_id=? AND task_id=? AND approval_id=? AND deployment_id=? AND action=?`, b.OperationID.String(), b.TaskID.String(), b.ApprovalID.String(), b.DeploymentID.String(), string(b.Action)).Scan(&owner); err != nil || owner != adminID.String() {
		return b, ErrIdempotencyCorrupt
	}
	return b, lifecycleCommit(tx)
}

func imagePublicEvidenceTx(ctx context.Context, tx *sql.Tx, b appcontracts.ImagePublicAccessCommand, outcome string, adminID domain.ID, now time.Time, version int64) error {
	evt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{AggregateType: "operation", AggregateID: b.OperationID.String(), AggregateVersion: version, EventType: "image.public_access." + outcome, CreatedAt: now, PayloadVersion: "1.0"}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{"event_id": id, "sequence": cursor, "operation_id": b.OperationID, "approval_id": b.ApprovalID, "deployment_id": b.DeploymentID, "outcome": outcome})
	})
	if err != nil {
		return err
	}
	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	actor := appcontracts.AuditContext{ActorType: "system", ActorID: "core-system", Reason: "image.public_access"}
	if !adminID.Empty() {
		actor = auditContextFromAdmin(adminID)
	}
	_, err = appendAuditTx(ctx, tx, auditInput{ID: auditID.String(), Actor: actor, Action: "image.public_access." + outcome, InputDigest: "sha256:" + sha256Hex(fmt.Sprintf("%s:%s:%s", b.OperationID, b.DeploymentID, b.Action)), Result: outcome, EvidenceRefs: []string{b.ApplicationID.String(), b.OperationID.String(), b.TaskID.String(), evt.ID}, CreatedAt: now})
	return err
}

func readImagePublicCommandTx(ctx context.Context, tx *sql.Tx, opID domain.ID) (appcontracts.ImagePublicAccessCommand, string, int64, error) {
	var b appcontracts.ImagePublicAccessCommand
	var raw, opState, action, approvalID, taskID, owner string
	var version int64
	err := tx.QueryRowContext(ctx, `SELECT c.binding,o.state,o.version,c.action,c.approval_id,c.task_id,c.admin_id
 FROM image_public_access_commands c JOIN operations o ON o.id=c.operation_id
 WHERE c.operation_id=? AND o.operation_type='image.public_access.'||c.action`, opID.String()).Scan(&raw, &opState, &version, &action, &approvalID, &taskID, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return b, "", 0, ErrNotFound
	}
	if err != nil {
		return b, "", 0, err
	}
	if json.Unmarshal([]byte(raw), &b) != nil || b.OperationID != opID || b.TaskID.String() != taskID || b.ApprovalID.String() != approvalID || string(b.Action) != action || b.DeploymentID.Empty() || b.ContainerID == "" || b.EndpointVersion == "" {
		return b, "", 0, ErrCorruptData
	}
	b.State = opState
	return b, owner, version, nil
}

func (s *Store) authorizeImagePublicTx(ctx context.Context, tx *sql.Tx, in appcontracts.ImagePublicAccessAuthority) (appcontracts.ImagePublicAccessCommand, int64, error) {
	var b appcontracts.ImagePublicAccessCommand
	if in.OperationID.Empty() || in.TaskID.Empty() || in.ApprovalID.Empty() || in.DeploymentID.Empty() || in.Owner == "" || in.CoreGeneration <= 0 || in.LeaseGeneration <= 0 {
		return b, 0, domain.ValidationError("incomplete public access authority")
	}
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{TaskID: in.TaskID, Owner: in.Owner, CoreGeneration: in.CoreGeneration, LeaseGeneration: in.LeaseGeneration, Now: time.Now().UTC()})
	if err != nil {
		return b, 0, err
	}
	if task.OperationID != in.OperationID {
		return b, 0, appcontracts.ErrLeaseLost
	}
	var commandOwner string
	var version int64
	b, commandOwner, version, err = readImagePublicCommandTx(ctx, tx, in.OperationID)
	if err != nil {
		return b, 0, err
	}
	if b.TaskID != in.TaskID || b.ApprovalID != in.ApprovalID || b.DeploymentID != in.DeploymentID || b.EndpointVersion != in.EndpointVersion || b.ContainerID != in.ContainerID || b.Action != in.Action ||
		(b.State != "pending" && b.State != "running" && b.State != "waiting") {
		return b, 0, appcontracts.ErrLeaseLost
	}
	var approvalEndpoint, approvalVersion, approvalContainer, approvalAction string
	err = tx.QueryRowContext(ctx, `SELECT a.endpoint_id,a.endpoint_version,a.container_id,
	 CASE WHEN a.desired_public=1 THEN 'ensure' ELSE 'remove' END
 FROM image_public_access a JOIN image_public_access_commands c ON c.approval_id=a.id AND c.operation_id=a.operation_id
	 JOIN task_leases t ON t.task_id=c.task_id AND t.operation_id=c.operation_id
 JOIN operations o ON o.id=c.operation_id AND o.application_id=a.application_id AND o.environment_id=a.environment_id AND o.target_kind='application' AND o.target_ref=a.application_id
	 WHERE a.id=? AND a.deployment_id=? AND a.release_id=? AND a.application_id=? AND a.environment_id=? AND a.hostname=? AND c.admin_id=a.admin_id
	 AND c.task_id=? AND c.action=? AND json_extract(t.payload,'$.kind')=? AND json_extract(t.payload,'$.binding')=json(c.binding)`, b.ApprovalID.String(), b.DeploymentID.String(), b.ReleaseID.String(), b.ApplicationID.String(), b.EnvironmentID.String(), b.Hostname, b.TaskID.String(), string(b.Action), appcontracts.ImagePublicAccessTaskKind).Scan(&approvalEndpoint, &approvalVersion, &approvalContainer, &approvalAction)
	if err != nil || approvalVersion != b.EndpointVersion || approvalContainer != b.ContainerID || approvalAction != string(b.Action) {
		return b, 0, domain.NewError(domain.ErrForbidden, "public access approval drift")
	}
	current, err := imagePublicTargetTx(ctx, tx, b.DeploymentID)
	if err != nil || current.adminID != commandOwner || current.endpointID != approvalEndpoint || current.command.EndpointVersion != b.EndpointVersion || current.command.ContainerID != b.ContainerID || current.command.HostPort != b.HostPort || current.command.ContainerPort != b.ContainerPort || current.command.ReleaseID != b.ReleaseID || current.command.ApplicationID != b.ApplicationID || current.command.EnvironmentID != b.EnvironmentID {
		return b, 0, domain.NewError(domain.ErrForbidden, "managed endpoint drift")
	}
	if b.Action == appcontracts.ImagePublicAccessEnsure && current.deploymentStatus != "running" {
		return b, 0, domain.NewError(domain.ErrConflict, "running deployment required for route ensure")
	}
	return b, version, nil
}

func (s *Store) AuthorizeImagePublicAccess(ctx context.Context, in appcontracts.ImagePublicAccessAuthority) (appcontracts.ImagePublicAccessCommand, error) {
	var b appcontracts.ImagePublicAccessCommand
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return b, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	b, _, err = s.authorizeImagePublicTx(ctx, tx, in)
	if err != nil {
		return b, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='running',version=version+1,updated_at=max(updated_at,?) WHERE id=? AND state='pending'`, FormatTime(time.Now().UTC()), b.OperationID.String()); err != nil {
		return b, err
	}
	return b, lifecycleCommit(tx)
}

func (s *Store) CommitImagePublicAccess(ctx context.Context, in appcontracts.ImagePublicAccessAuthority, observed appcontracts.ImagePublicAccessObservation) error {
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	if !observed.RouteApplied || observed.ObservedAt.IsZero() || observed.ObservedAt.Before(now.Add(-2*time.Minute)) || observed.ObservedAt.After(now.Add(time.Minute)) ||
		observed.CertificateFingerprint != "" && (!validSha256Digest(observed.CertificateFingerprint) || observed.CertificateExpiresAt.IsZero() || !observed.CertificateExpiresAt.After(observed.ObservedAt)) ||
		observed.CertificateFingerprint == "" && !observed.CertificateExpiresAt.IsZero() {
		return domain.ValidationError("invalid route/certificate observation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, version, err := s.authorizeImagePublicTx(ctx, tx, in)
	if err != nil {
		return err
	}
	state := "configured"
	var fingerprint, expires any = nil, nil
	if b.Action == appcontracts.ImagePublicAccessRemove {
		state = "disabled"
	} else if observed.CertificateFingerprint != "" {
		fingerprint, expires = observed.CertificateFingerprint, FormatTime(observed.CertificateExpiresAt)
	}
	stamp := FormatTime(now)
	res, err := tx.ExecContext(ctx, `UPDATE image_public_access SET local_route_state=?,certificate_fingerprint=?,certificate_expires_at=?,observed_at=?,updated_at=max(updated_at,?) WHERE id=? AND operation_id=?`, state, fingerprint, expires, FormatTime(observed.ObservedAt), stamp, b.ApprovalID.String(), b.OperationID.String())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return domain.NewError(domain.ErrConflict, "approval changed before result")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO image_public_access_results(operation_id,observed_at,certificate_fingerprint,certificate_expires_at,created_at) VALUES(?,?,?,?,?)`, b.OperationID.String(), FormatTime(observed.ObservedAt), fingerprint, expires, stamp); err != nil {
		return err
	}
	if _, err := s.mutateTaskTx(ctx, tx, appcontracts.TaskMutationRequest{TaskID: in.TaskID, Owner: in.Owner, CoreGeneration: in.CoreGeneration, LeaseGeneration: in.LeaseGeneration, Now: now}, "completed", ""); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state='succeeded',version=version+1,failure_reason=NULL,updated_at=max(updated_at,?) WHERE id=?`, stamp, b.OperationID.String()); err != nil {
		return err
	}
	if err := imagePublicEvidenceTx(ctx, tx, b, "succeeded", "", now, version+1); err != nil {
		return err
	}
	return lifecycleCommit(tx)
}

func (s *Store) RecordImagePublicAccessUnknown(ctx context.Context, in appcontracts.ImagePublicAccessAuthority, reason string) error {
	return s.finishImagePublicAccessWithoutReceipt(ctx, in, reason, "waiting", "ready")
}

func (s *Store) FailImagePublicAccess(ctx context.Context, in appcontracts.ImagePublicAccessAuthority, reason string) error {
	return s.finishImagePublicAccessWithoutReceipt(ctx, in, reason, "failed", "failed")
}

func (s *Store) finishImagePublicAccessWithoutReceipt(ctx context.Context, in appcontracts.ImagePublicAccessAuthority, reason, operationState, taskState string) error {
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, version, err := s.authorizeImagePublicTx(ctx, tx, in)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	stamp := FormatTime(now)
	reason = cleanLastErrorReason(reason)
	if _, err := s.mutateTaskTx(ctx, tx, appcontracts.TaskMutationRequest{TaskID: in.TaskID, Owner: in.Owner, CoreGeneration: in.CoreGeneration, LeaseGeneration: in.LeaseGeneration, Now: now}, taskState, reason); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE image_public_access SET local_route_state='reconcile_required',updated_at=max(updated_at,?) WHERE id=? AND operation_id=?`, stamp, b.ApprovalID.String(), b.OperationID.String()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state=?,version=version+1,failure_reason=?,updated_at=max(updated_at,?) WHERE id=?`, operationState, reason, stamp, b.OperationID.String()); err != nil {
		return err
	}
	event := operationState
	if operationState == "waiting" {
		event = "unknown"
	}
	if err := imagePublicEvidenceTx(ctx, tx, b, event, "", now, version+1); err != nil {
		return err
	}
	return lifecycleCommit(tx)
}

func (s *Store) GetImagePublicAccess(ctx context.Context, adminID, deploymentID domain.ID) (appcontracts.ImagePublicAccessApproval, error) {
	var out appcontracts.ImagePublicAccessApproval
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return out, err
	}
	if adminID.Empty() || deploymentID.Empty() {
		return out, domain.ValidationError("administrator and deployment required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var opID, approvalID, hostname, owner, state string
	var desired int
	var fingerprint, expiry, observed sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT a.operation_id,a.id,a.hostname,a.admin_id,a.desired_public,a.local_route_state,a.certificate_fingerprint,a.certificate_expires_at,a.observed_at,d.status
 FROM image_public_access a JOIN admin_credentials owner ON owner.id=a.admin_id AND owner.disabled_at IS NULL
	 JOIN image_deployments d ON d.id=a.deployment_id AND d.application_id=a.application_id AND d.environment_id=a.environment_id AND d.release_id=a.release_id
	 WHERE a.deployment_id=?`, deploymentID.String()).Scan(&opID, &approvalID, &hostname, &owner, &desired, &state, &fingerprint, &expiry, &observed, &out.DeploymentStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if owner != adminID.String() {
		return out, domain.NewError(domain.ErrForbidden, "public access owner mismatch")
	}
	out.Command, _, _, err = readImagePublicCommandTx(ctx, tx, domain.ID(opID))
	if err != nil {
		return out, err
	}
	if out.Command.ApprovalID.String() != approvalID || out.Command.DeploymentID != deploymentID || out.Command.Hostname != hostname {
		return appcontracts.ImagePublicAccessApproval{}, ErrCorruptData
	}
	out.DesiredPublic, out.LocalRouteState = desired == 1, state
	if fingerprint.Valid {
		out.CertificateFingerprint = fingerprint.String
	}
	if expiry.Valid {
		t, err := ParseTime(expiry.String)
		if err != nil {
			return out, ErrCorruptData
		}
		out.CertificateExpiresAt = &t
	}
	if observed.Valid {
		t, err := ParseTime(observed.String)
		if err != nil {
			return out, ErrCorruptData
		}
		out.ObservedAt = &t
	}
	return out, lifecycleCommit(tx)
}

// ReadImagePublicAccessOperation returns one historical command with only its
// immutable observed result. It never borrows the current approval's state or
// exposes private task errors, container identity or Caddy Admin location.
func (s *Store) ReadImagePublicAccessOperation(ctx context.Context, adminID, operationID domain.ID) (appcontracts.ImagePublicAccessOperation, error) {
	var out appcontracts.ImagePublicAccessOperation
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return out, err
	}
	if adminID.Empty() || operationID.Empty() {
		return out, domain.ValidationError("administrator and domain operation required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var raw, owner, state, action, approvalID, taskID, deploymentID, hostname string
	var observed, fingerprint, expiry sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT c.binding,c.admin_id,o.state,c.action,c.approval_id,c.task_id,c.deployment_id,a.hostname,
	 r.observed_at,r.certificate_fingerprint,r.certificate_expires_at
	 FROM image_public_access_commands c
	 JOIN operations o ON o.id=c.operation_id AND o.operation_type='image.public_access.'||c.action
	 JOIN image_public_access a ON a.id=c.approval_id AND a.deployment_id=c.deployment_id AND a.admin_id=c.admin_id
	 JOIN admin_credentials owner ON owner.id=c.admin_id AND owner.disabled_at IS NULL
	 LEFT JOIN image_public_access_results r ON r.operation_id=c.operation_id
	 WHERE c.operation_id=?`, operationID.String()).Scan(&raw, &owner, &state, &action, &approvalID, &taskID, &deploymentID, &hostname, &observed, &fingerprint, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if owner != adminID.String() {
		return out, domain.NewError(domain.ErrForbidden, "domain operation owner mismatch")
	}
	var b appcontracts.ImagePublicAccessCommand
	if json.Unmarshal([]byte(raw), &b) != nil || b.OperationID != operationID || b.TaskID.String() != taskID || b.ApprovalID.String() != approvalID || b.DeploymentID.String() != deploymentID || b.Hostname != hostname || string(b.Action) != action || b.CreatedAt.IsZero() {
		return out, ErrCorruptData
	}
	out = appcontracts.ImagePublicAccessOperation{OperationID: b.OperationID, TaskID: b.TaskID, ApprovalID: b.ApprovalID, DeploymentID: b.DeploymentID, Hostname: b.Hostname, Action: b.Action, State: state, CreatedAt: b.CreatedAt}
	if state == "waiting" {
		out.State = "unknown"
		out.Reason = "local route outcome requires reconciliation"
	} else if state == "failed" {
		out.Reason = "local route command failed"
	}
	if observed.Valid {
		if state != "succeeded" {
			return appcontracts.ImagePublicAccessOperation{}, ErrCorruptData
		}
		t, err := ParseTime(observed.String)
		if err != nil {
			return appcontracts.ImagePublicAccessOperation{}, ErrCorruptData
		}
		result := &appcontracts.ImagePublicAccessPublicResult{ObservedAt: t}
		if fingerprint.Valid {
			if !validSha256Digest(fingerprint.String) || !expiry.Valid {
				return appcontracts.ImagePublicAccessOperation{}, ErrCorruptData
			}
			result.CertificateFingerprint = fingerprint.String
			expires, err := ParseTime(expiry.String)
			if err != nil || !expires.After(t) {
				return appcontracts.ImagePublicAccessOperation{}, ErrCorruptData
			}
			result.CertificateExpiresAt = &expires
		} else if expiry.Valid {
			return appcontracts.ImagePublicAccessOperation{}, ErrCorruptData
		}
		out.Result = result
	} else if state == "succeeded" || fingerprint.Valid || expiry.Valid {
		return appcontracts.ImagePublicAccessOperation{}, ErrCorruptData
	}
	return out, lifecycleCommit(tx)
}

// ListImagePublicAccessRoutes returns a consistent, finite snapshot. The read
// transaction ends before any caller performs network I/O. A projector must
// recheck its exact row with CheckImagePublicAccessRoute immediately before a
// Caddy write and hold its own command authority/lease for that operation.
func (s *Store) ListImagePublicAccessRoutes(ctx context.Context) ([]appcontracts.ImagePublicAccessRoute, error) {
	if err := s.checkImagePublicAccess(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT a.id,a.operation_id,a.application_id,a.deployment_id,a.hostname,a.host_port,a.endpoint_version,a.desired_public,a.local_route_state,
 a.endpoint_id,a.container_id,a.container_port,a.release_id
 FROM image_public_access a ORDER BY a.hostname`)
	if err != nil {
		return nil, err
	}
	var routes []appcontracts.ImagePublicAccessRoute
	type routeBinding struct {
		endpointID, containerID, releaseID string
		containerPort                      int
	}
	var bindings []routeBinding
	for rows.Next() {
		var r appcontracts.ImagePublicAccessRoute
		var desired int
		var state string
		var binding routeBinding
		if err := rows.Scan(&r.ApprovalID, &r.OperationID, &r.ApplicationID, &r.DeploymentID, &r.Hostname, &r.HostPort, &r.EndpointVersion, &desired, &state, &binding.endpointID, &binding.containerID, &binding.containerPort, &binding.releaseID); err != nil {
			rows.Close()
			return nil, err
		}
		if appcontracts.ValidateImagePublicHostname(r.Hostname) != nil || !imagePublicRoutablePort(r.HostPort) || r.EndpointVersion == "" || r.ApprovalID.Empty() || r.OperationID.Empty() {
			rows.Close()
			return nil, ErrCorruptData
		}
		r.Enabled = desired == 1 && state != "disabled"
		r.ServiceName = "web"
		routes = append(routes, r)
		bindings = append(bindings, binding)
		if len(routes) > 1024 {
			rows.Close()
			return nil, domain.NewError(domain.ErrConflict, "route inventory exceeds bounded projector scope")
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i, r := range routes {
		if !r.Enabled {
			continue
		}
		current, err := imagePublicTargetTx(ctx, tx, r.DeploymentID)
		bound := bindings[i]
		if err != nil || current.endpointID != bound.endpointID || current.command.EndpointVersion != r.EndpointVersion || current.command.ReleaseID.String() != bound.releaseID || current.command.ContainerID != bound.containerID || current.command.ContainerPort != bound.containerPort || current.command.HostPort != r.HostPort {
			return nil, domain.NewError(domain.ErrForbidden, "route inventory endpoint drift")
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return routes, nil
}

// CheckImagePublicAccessRoute is a fresh, exact pre-write fence. It must be
// paired with the active Core task authority for command execution; Caddy's
// owned-subtree ETag remains the network-side compare-and-swap boundary.
func (s *Store) CheckImagePublicAccessRoute(ctx context.Context, expected appcontracts.ImagePublicAccessRoute) error {
	if expected.ApprovalID.Empty() || expected.OperationID.Empty() || expected.DeploymentID.Empty() || expected.EndpointVersion == "" {
		return domain.ValidationError("incomplete route fence")
	}
	routes, err := s.ListImagePublicAccessRoutes(ctx)
	if err != nil {
		return err
	}
	for _, actual := range routes {
		if actual.ApprovalID == expected.ApprovalID {
			if actual != expected {
				return domain.NewError(domain.ErrForbidden, "route approval changed")
			}
			return nil
		}
	}
	return ErrNotFound
}
