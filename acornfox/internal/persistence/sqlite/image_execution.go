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

func validSha256Digest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, r := range s[7:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// BeginImageExecution prepares an image deployment execution under active task fencing.
func (s *Store) BeginImageExecution(ctx context.Context, input appcontracts.BeginImageExecutionInput) (appcontracts.ImageExecutionBinding, error) {
	if err := s.checkOpen(); err != nil {
		return appcontracts.ImageExecutionBinding{}, err
	}
	if input.TaskID.Empty() || input.OperationID.Empty() || strings.TrimSpace(input.Owner) == "" || input.CoreGeneration == 0 || input.LeaseGeneration == 0 {
		return appcontracts.ImageExecutionBinding{}, domain.ValidationError("task, operation, owner, and generation tokens are required")
	}

	now := time.Now().UTC()
	if !input.Now.IsZero() {
		now = input.Now.UTC()
	}
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return appcontracts.ImageExecutionBinding{}, fmt.Errorf("begin execution tx: %w", err)
	}
	rollback := func(cause error) (appcontracts.ImageExecutionBinding, error) {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return appcontracts.ImageExecutionBinding{}, fmt.Errorf("%w (rollback: %v)", cause, rbErr)
		}
		return appcontracts.ImageExecutionBinding{}, cause
	}

	// 1. Verify task lease and DB singleton using shared verifyTaskLeaseTx helper
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		return rollback(err)
	}
	if task.OperationID != input.OperationID {
		return rollback(appcontracts.ErrLeaseLost)
	}

	// 2. Load operation, intent, and verified plan
	var (
		opState, appIDStr, envIDStr, planIDStr, intentPlanDigest string
		planAdminID, planAppName, planStatus, storedPlanDigest   string
		canonicalJSON, resolvedJSON, provenanceJSON, missingJSON string
		planCreatedStr, planUpdatedStr                           string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT o.state, o.application_id, o.environment_id, i.plan_id, i.plan_digest,
		       p.admin_id, p.app_name, p.status, p.plan_digest,
		       p.canonical_input, p.resolved_image, p.resolver_provenance, p.missing_inputs,
		       p.created_at, p.updated_at
		  FROM operations o
		  JOIN image_deploy_intents i ON o.id = i.operation_id
		  JOIN image_plans p ON i.plan_id = p.id
		 WHERE o.id = ?;
	`, input.OperationID.String()).Scan(
		&opState, &appIDStr, &envIDStr, &planIDStr, &intentPlanDigest,
		&planAdminID, &planAppName, &planStatus, &storedPlanDigest,
		&canonicalJSON, &resolvedJSON, &provenanceJSON, &missingJSON,
		&planCreatedStr, &planUpdatedStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(fmt.Errorf("query operation plan: %w", err))
	}

	if opState != "pending" && opState != "running" && opState != "waiting" && opState != "unknown" {
		return rollback(domain.NewError(domain.ErrConflict, fmt.Sprintf("operation is in state %q, cannot execute", opState)))
	}

	// Verify task payload matches operation/plan intent
	var taskPayload struct {
		Kind          string `json:"kind"`
		ApplicationID string `json:"application_id"`
		EnvironmentID string `json:"environment_id"`
		OperationID   string `json:"operation_id"`
		PlanID        string `json:"plan_id"`
		PlanDigest    string `json:"plan_digest"`
	}
	if err := json.Unmarshal(task.Payload, &taskPayload); err != nil {
		return rollback(fmt.Errorf("%w: decode task payload: %v", ErrCorruptData, err))
	}
	if taskPayload.Kind != "image.deploy" || taskPayload.OperationID != input.OperationID.String() ||
		taskPayload.ApplicationID != appIDStr || taskPayload.EnvironmentID != envIDStr ||
		taskPayload.PlanID != planIDStr || taskPayload.PlanDigest != intentPlanDigest {
		return rollback(domain.NewError(domain.ErrForbidden, "task payload does not match operation intent"))
	}

	planCreatedAt, err := ParseTime(planCreatedStr)
	if err != nil {
		return rollback(fmt.Errorf("%w: parse plan created_at: %v", ErrCorruptData, err))
	}
	planUpdatedAt, err := ParseTime(planUpdatedStr)
	if err != nil {
		return rollback(fmt.Errorf("%w: parse plan updated_at: %v", ErrCorruptData, err))
	}
	var canonicalInput appcontracts.CanonicalExecutionInput
	if err := json.Unmarshal([]byte(canonicalJSON), &canonicalInput); err != nil {
		return rollback(fmt.Errorf("%w: decode canonical input: %v", ErrCorruptData, err))
	}
	var resolvedImage appcontracts.ResolvedImage
	if err := json.Unmarshal([]byte(resolvedJSON), &resolvedImage); err != nil {
		return rollback(fmt.Errorf("%w: decode resolved image: %v", ErrCorruptData, err))
	}
	var provenance appcontracts.ResolverProvenance
	if err := json.Unmarshal([]byte(provenanceJSON), &provenance); err != nil {
		return rollback(fmt.Errorf("%w: decode resolver provenance: %v", ErrCorruptData, err))
	}
	var missingInputs []string
	if err := json.Unmarshal([]byte(missingJSON), &missingInputs); err != nil {
		return rollback(fmt.Errorf("%w: decode missing inputs: %v", ErrCorruptData, err))
	}

	plan := appcontracts.ImagePlan{
		ID:                 domain.ID(planIDStr),
		AdminID:            domain.ID(planAdminID),
		AppName:            planAppName,
		Status:             appcontracts.ImagePlanStatus(planStatus),
		PlanDigest:         storedPlanDigest,
		CanonicalInput:     canonicalInput,
		ResolvedImage:      resolvedImage,
		ResolverProvenance: provenance,
		MissingInputs:      missingInputs,
		CreatedAt:          planCreatedAt,
		UpdatedAt:          planUpdatedAt,
	}
	if err := appcontracts.ValidatePlanConsistency(plan); err != nil {
		return rollback(fmt.Errorf("%w: plan consistency failed: %v", ErrCorruptData, err))
	}
	if plan.PlanDigest != intentPlanDigest {
		return rollback(domain.NewError(domain.ErrConflict, "plan digest mismatch between intent and stored plan"))
	}

	sourceArtifact, err := s.sourceArtifactForImagePlanTx(ctx, tx, plan, domain.ID(appIDStr), domain.ID(envIDStr))
	if err != nil {
		return rollback(err)
	}

	// 3. Obtain or persist stable release and deployment identity
	var (
		depIDStr, relIDStr, depAppIDStr, depEnvIDStr, depTaskIDStr, depStatus string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, release_id, application_id, environment_id, task_id, status
		  FROM image_deployments
		 WHERE operation_id = ?;
	`, input.OperationID.String()).Scan(&depIDStr, &relIDStr, &depAppIDStr, &depEnvIDStr, &depTaskIDStr, &depStatus)

	if errors.Is(err, sql.ErrNoRows) {
		// Fresh execution: generate stable release and deployment
		relID, err := domain.NewID("rel")
		if err != nil {
			return rollback(err)
		}
		depID, err := domain.NewID("dep")
		if err != nil {
			return rollback(err)
		}
		relIDStr = relID.String()
		depIDStr = depID.String()

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO image_releases (
				id, application_id, plan_id, plan_digest, repository, digest, platform, created_at
			) VALUES (?, ?, ?, ?, ?, ?, 'linux/amd64', ?);
		`, relIDStr, appIDStr, planIDStr, storedPlanDigest, resolvedImage.Repository, resolvedImage.Digest, nowStr); err != nil {
			return rollback(fmt.Errorf("insert image release: %w", err))
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO image_deployments (
				id, release_id, application_id, environment_id, operation_id, task_id, status, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, 'deploying', ?, ?);
		`, depIDStr, relIDStr, appIDStr, envIDStr, input.OperationID.String(), input.TaskID.String(), nowStr, nowStr); err != nil {
			return rollback(fmt.Errorf("insert image deployment: %w", err))
		}
	} else if err != nil {
		return rollback(fmt.Errorf("query existing image deployment: %w", err))
	} else {
		// Existing deployment replay: enforce exact tuple agreement
		if depTaskIDStr != input.TaskID.String() || depAppIDStr != appIDStr || depEnvIDStr != envIDStr {
			return rollback(domain.NewError(domain.ErrConflict, "existing deployment tuple conflict with claimed task"))
		}
		var relPlanID, relPlanDigest, relDigest string
		if err := tx.QueryRowContext(ctx, `
			SELECT plan_id, plan_digest, digest
			  FROM image_releases
			 WHERE id = ?;
		`, relIDStr).Scan(&relPlanID, &relPlanDigest, &relDigest); err != nil {
			return rollback(fmt.Errorf("query existing release: %w", err))
		}
		if relPlanID != planIDStr || relPlanDigest != storedPlanDigest || relDigest != resolvedImage.Digest {
			return rollback(domain.NewError(domain.ErrConflict, "existing release identity does not match plan"))
		}
	}

	// Update operation state to running if pending, waiting, or unknown
	if opState == "pending" || opState == "waiting" || opState == "unknown" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE operations
			   SET state = 'running', updated_at = ?
			 WHERE id = ? AND state IN ('pending', 'waiting', 'unknown');
		`, nowStr, input.OperationID.String()); err != nil {
			return rollback(fmt.Errorf("advance operation to running: %w", err))
		}
	}

	if err := tx.Commit(); err != nil {
		return appcontracts.ImageExecutionBinding{}, fmt.Errorf("%w: commit begin execution: %v", ErrOutcomeUnknown, err)
	}

	return appcontracts.ImageExecutionBinding{
		ReleaseID:       domain.ID(relIDStr),
		DeploymentID:    domain.ID(depIDStr),
		ApplicationID:   domain.ID(appIDStr),
		EnvironmentID:   domain.ID(envIDStr),
		OperationID:     input.OperationID,
		TaskID:          input.TaskID,
		Plan:            plan,
		SourceArtifact:  sourceArtifact,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
	}, nil
}

// AuthorizeImageExecution verifies live authority for an in-flight deployment stage.
func (s *Store) AuthorizeImageExecution(ctx context.Context, input appcontracts.AuthorizeImageExecutionInput) (appcontracts.AuthorityBindingFacts, error) {
	if err := s.checkOpen(); err != nil {
		return appcontracts.AuthorityBindingFacts{}, err
	}
	if input.TaskID.Empty() || input.OperationID.Empty() || input.DeploymentID.Empty() || input.Owner == "" || input.CoreGeneration == 0 || input.LeaseGeneration == 0 {
		return appcontracts.AuthorityBindingFacts{}, domain.ValidationError("incomplete authorization input")
	}
	if input.PlanDigest == "" {
		return appcontracts.AuthorityBindingFacts{}, domain.ValidationError("plan digest must be exact and non-empty")
	}

	// Always use Core's authoritative local clock
	now := time.Now().UTC()

	// Authorize inside a single read transaction for consistent snapshot
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return appcontracts.AuthorityBindingFacts{}, fmt.Errorf("begin authorize tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Verify task lease and DB singleton using shared verifyTaskLeaseTx helper
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		return appcontracts.AuthorityBindingFacts{}, err
	}
	if task.OperationID != input.OperationID {
		return appcontracts.AuthorityBindingFacts{}, appcontracts.ErrLeaseLost
	}

	// 2. Atomically verify deployment, operation, and plan intent
	var (
		taskKind, depStatus, opState string
		intentDigest                 string
		appIDStr, envIDStr, relIDStr string
		approvedPort                 int
	)
	err = tx.QueryRowContext(ctx, `
		SELECT json_extract(t.payload, '$.kind'), d.status, o.state, i.plan_digest,
		       d.application_id, d.environment_id, d.release_id,
		       json_extract(p.canonical_input, '$.port')
		  FROM task_leases t
		  JOIN image_deployments d ON t.task_id = d.task_id AND t.operation_id = d.operation_id
		  JOIN operations o ON t.operation_id = o.id
		  JOIN image_deploy_intents i ON t.operation_id = i.operation_id
		  JOIN image_plans p ON i.plan_id = p.id
		 WHERE t.task_id = ? AND d.id = ? AND t.operation_id = ?;
	`, input.TaskID.String(), input.DeploymentID.String(), input.OperationID.String()).Scan(
		&taskKind, &depStatus, &opState, &intentDigest,
		&appIDStr, &envIDStr, &relIDStr, &approvedPort,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return appcontracts.AuthorityBindingFacts{}, appcontracts.ErrLeaseLost
	}
	if err != nil {
		return appcontracts.AuthorityBindingFacts{}, fmt.Errorf("query authorization state: %w", err)
	}

	if taskKind != "image.deploy" {
		return appcontracts.AuthorityBindingFacts{}, domain.NewError(domain.ErrForbidden, "task kind mismatch")
	}
	if intentDigest != input.PlanDigest {
		return appcontracts.AuthorityBindingFacts{}, domain.NewError(domain.ErrForbidden, "plan digest mismatched")
	}
	if opState != "running" && opState != "pending" && opState != "unknown" {
		return appcontracts.AuthorityBindingFacts{}, domain.NewError(domain.ErrConflict, fmt.Sprintf("operation is in inactive state %q", opState))
	}
	if depStatus != "deploying" && depStatus != "running" {
		return appcontracts.AuthorityBindingFacts{}, domain.NewError(domain.ErrConflict, fmt.Sprintf("deployment is in inactive status %q", depStatus))
	}

	var sourceArtifact *appcontracts.SourceBuiltArtifactFact
	imageOrigin := "registryhttp"
	var owner, provenanceJSON, resolvedJSON, canonicalJSON string
	err = tx.QueryRowContext(ctx, `SELECT p.admin_id,p.resolver_provenance,p.resolved_image,p.canonical_input FROM image_deploy_intents i JOIN image_plans p ON p.id=i.plan_id WHERE i.operation_id=? AND i.application_id=? AND i.environment_id=?`, input.OperationID.String(), appIDStr, envIDStr).Scan(&owner, &provenanceJSON, &resolvedJSON, &canonicalJSON)
	if err != nil {
		return appcontracts.AuthorityBindingFacts{}, ErrCorruptData
	}
	var provenance appcontracts.ResolverProvenance
	var resolved appcontracts.ResolvedImage
	var canonical appcontracts.CanonicalExecutionInput
	if json.Unmarshal([]byte(provenanceJSON), &provenance) != nil || json.Unmarshal([]byte(resolvedJSON), &resolved) != nil || json.Unmarshal([]byte(canonicalJSON), &canonical) != nil {
		return appcontracts.AuthorityBindingFacts{}, ErrCorruptData
	}
	imageOrigin = provenance.Provider
	if imageOrigin == "source-build" {
		plan := appcontracts.ImagePlan{AdminID: domain.ID(owner), ResolverProvenance: provenance, ResolvedImage: resolved, CanonicalInput: canonical}
		sourceArtifact, err = s.sourceArtifactForImagePlanTx(ctx, tx, plan, domain.ID(appIDStr), domain.ID(envIDStr))
		if err != nil {
			return appcontracts.AuthorityBindingFacts{}, err
		}
	} else if imageOrigin != "registryhttp" {
		return appcontracts.AuthorityBindingFacts{}, ErrCorruptData
	}
	return appcontracts.AuthorityBindingFacts{
		PlanDigest:     intentDigest,
		ApplicationID:  domain.ID(appIDStr),
		EnvironmentID:  domain.ID(envIDStr),
		ReleaseID:      domain.ID(relIDStr),
		ApprovedPort:   approvedPort,
		ImageOrigin:    imageOrigin,
		SourceArtifact: sourceArtifact,
	}, nil
}

// CommitImageExecutionResult records observed container effects and completes task and operation atomically.
func (s *Store) CommitImageExecutionResult(ctx context.Context, input appcontracts.CommitImageExecutionResultInput) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if input.TaskID.Empty() || input.OperationID.Empty() || input.DeploymentID.Empty() || input.ReleaseID.Empty() || input.Owner == "" {
		return domain.ValidationError("execution result input incomplete")
	}
	if strings.TrimSpace(input.ContainerID) == "" {
		return domain.ValidationError("container_id is required")
	}
	if !validSha256Digest(input.ImageID) {
		return domain.ValidationError("image_id must be a valid sha256 digest")
	}
	if !validSha256Digest(input.ManifestDigest) {
		return domain.ValidationError("manifest_digest must be a valid sha256 digest")
	}
	if input.HostPort <= 0 || input.HostPort > 65535 {
		return domain.ValidationError("observed host port is invalid")
	}
	if input.ContainerPort <= 0 || input.ContainerPort > 65535 {
		return domain.ValidationError("observed container port is invalid")
	}
	if input.ObservedAt.IsZero() {
		return domain.ValidationError("observed_at timestamp is required")
	}
	now := time.Now().UTC()
	if !input.Now.IsZero() {
		now = input.Now.UTC()
	}
	nowStr := FormatTime(now)

	if input.ObservedAt.After(now.Add(time.Minute)) {
		return domain.ValidationError("observed_at is in the future")
	}
	if input.ObservedAt.Before(now.Add(-2 * time.Hour)) {
		return domain.ValidationError("observed_at is excessively stale")
	}
	if input.Artifact.SizeBytes <= 0 || strings.TrimSpace(input.Artifact.StorageRef) == "" || !validSha256Digest(input.Artifact.ContentDigest) {
		return domain.ValidationError("valid image artifact storage receipt is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin commit tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Verify task lease and DB singleton using shared verifyTaskLeaseTx helper
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		return err
	}
	if task.OperationID != input.OperationID {
		return appcontracts.ErrLeaseLost
	}

	// 2. Verify deployment, operation, release, and approved plan port
	var appIDStr, envIDStr, opState string
	var releaseRepo, releaseDigest string
	var planPort int
	err = tx.QueryRowContext(ctx, `
		SELECT d.application_id, d.environment_id, o.state, r.repository, r.digest,
		       json_extract(p.canonical_input, '$.port')
		  FROM image_deployments d
		  JOIN operations o ON d.operation_id = o.id
		  JOIN image_releases r ON d.release_id = r.id
		  JOIN image_deploy_intents i ON o.id = i.operation_id
		  JOIN image_plans p ON i.plan_id = p.id
		 WHERE d.id = ? AND d.operation_id = ? AND d.release_id = ? AND d.task_id = ?;
	`, input.DeploymentID.String(), input.OperationID.String(), input.ReleaseID.String(), input.TaskID.String()).Scan(
		&appIDStr, &envIDStr, &opState, &releaseRepo, &releaseDigest, &planPort,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NewError(domain.ErrForbidden, "deployment record not found or mismatched")
	}
	if err != nil {
		return fmt.Errorf("query deployment for commit: %w", err)
	}

	if opState != "running" && opState != "pending" && opState != "unknown" {
		return domain.NewError(domain.ErrConflict, fmt.Sprintf("operation is in terminal state %q", opState))
	}
	if input.ContainerPort != planPort {
		return domain.NewError(domain.ErrConflict, fmt.Sprintf("observed container port %d does not match approved plan port %d", input.ContainerPort, planPort))
	}
	if input.ManifestDigest != releaseDigest {
		return domain.NewError(domain.ErrConflict, fmt.Sprintf("manifest digest %s does not match release digest %s", input.ManifestDigest, releaseDigest))
	}

	// 3. Persist verified image artifact receipt (TP05 requirement)
	artifactID, err := domain.NewID("art")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO image_artifacts (
			id, release_id, repository, digest, image_id, content_digest, size_bytes, storage_ref, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
	`, artifactID.String(), input.ReleaseID.String(), releaseRepo, input.ManifestDigest,
		input.ImageID, input.Artifact.ContentDigest, input.Artifact.SizeBytes, input.Artifact.StorageRef, nowStr); err != nil {
		return fmt.Errorf("insert image artifact: %w", err)
	}

	// 4. Update deployment state with observed container facts
	containerName := strings.TrimSpace(input.ContainerName)
	if containerName == "" {
		containerName = input.ContainerID
	}
	depRes, err := tx.ExecContext(ctx, `
		UPDATE image_deployments
		   SET status = 'running',
		       container_id = ?,
		       container_name = ?,
		       image_id = ?,
		       updated_at = ?
		 WHERE id = ?;
	`, input.ContainerID, containerName, input.ImageID, nowStr, input.DeploymentID.String())
	if err != nil {
		return fmt.Errorf("update image deployment: %w", err)
	}
	if n, _ := depRes.RowsAffected(); n != 1 {
		return fmt.Errorf("update deployment rows affected = %d, want 1", n)
	}

	// 5. Persist loopback endpoint
	endpointID, err := domain.NewID("end")
	if err != nil {
		return err
	}
	observedAtStr := FormatTime(input.ObservedAt.UTC())
	endRes, err := tx.ExecContext(ctx, `
		INSERT INTO image_endpoints (
			id, deployment_id, application_id, environment_id, protocol, host_ip, host_port, container_port, observed_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, 'http', '127.0.0.1', ?, ?, ?, ?, ?)
		ON CONFLICT (deployment_id) DO UPDATE SET
			host_port = excluded.host_port,
			container_port = excluded.container_port,
			observed_at = excluded.observed_at,
			updated_at = excluded.updated_at;
	`, endpointID.String(), input.DeploymentID.String(), appIDStr, envIDStr,
		input.HostPort, input.ContainerPort, observedAtStr, nowStr, nowStr)
	if err != nil {
		return fmt.Errorf("insert image endpoint: %w", err)
	}
	if n, _ := endRes.RowsAffected(); n == 0 {
		return fmt.Errorf("endpoint rows affected = 0")
	}

	// 6. Advance operation to succeeded
	opRes, err := tx.ExecContext(ctx, `
		UPDATE operations
		   SET state = 'succeeded',
		       version = version + 1,
		       updated_at = ?
		 WHERE id = ? AND state IN ('pending', 'running', 'unknown');
	`, nowStr, input.OperationID.String())
	if err != nil {
		return fmt.Errorf("advance operation to succeeded: %w", err)
	}
	if n, _ := opRes.RowsAffected(); n != 1 {
		return fmt.Errorf("operation advance rows affected = %d, want 1", n)
	}

	// 7. Complete task lease using shared mutateTaskTx helper
	if _, err := s.mutateTaskTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	}, "completed", ""); err != nil {
		return fmt.Errorf("complete task lease: %w", err)
	}

	// 8. Append outbox event
	outboxEvt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{
		AggregateType:    "operation",
		AggregateID:      input.OperationID.String(),
		AggregateVersion: 2,
		EventType:        "image.deploy.succeeded",
		CreatedAt:        now,
		PayloadVersion:   "1.0",
	}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{
			"event_id":       id,
			"sequence":       cursor,
			"operation_id":   input.OperationID.String(),
			"application_id": appIDStr,
			"deployment_id":  input.DeploymentID.String(),
			"container_id":   input.ContainerID,
			"host_port":      input.HostPort,
			"occurred_at":    nowStr,
		})
	})
	if err != nil {
		return fmt.Errorf("append outbox event: %w", err)
	}

	// 9. Append audit log with trusted system actor and safe evidence refs (app, op, task, evt)
	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	auditDigest := "sha256:" + sha256Hex(fmt.Sprintf("%s:%s:%s", input.OperationID.String(), input.DeploymentID.String(), input.ContainerID))
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID: auditID.String(),
		Actor: appcontracts.AuditContext{
			ActorType: "system",
			ActorID:   "core-system",
			Reason:    "image.deploy",
		},
		Action:       "image.deploy.completed",
		InputDigest:  auditDigest,
		Result:       "succeeded",
		EvidenceRefs: []string{appIDStr, input.OperationID.String(), input.TaskID.String(), outboxEvt.ID},
		CreatedAt:    now,
	}); err != nil {
		return fmt.Errorf("append audit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit image execution result: %v", ErrOutcomeUnknown, err)
	}

	return nil
}

// FailImageExecution marks a failed deployment outcome under active lease fencing.
func (s *Store) FailImageExecution(ctx context.Context, input appcontracts.FailImageExecutionInput) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if input.TaskID.Empty() || input.OperationID.Empty() || input.Owner == "" {
		return domain.ValidationError("task, operation, and owner are required")
	}

	now := time.Now().UTC()
	if !input.Now.IsZero() {
		now = input.Now.UTC()
	}
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin fail tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Verify task lease and DB singleton using shared verifyTaskLeaseTx helper
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		return err
	}
	if task.OperationID != input.OperationID {
		return appcontracts.ErrLeaseLost
	}

	// Verify task kind is image.deploy
	var taskKind string
	if err := tx.QueryRowContext(ctx, `SELECT json_extract(payload, '$.kind') FROM task_leases WHERE task_id = ?`, input.TaskID.String()).Scan(&taskKind); err != nil || taskKind != "image.deploy" {
		return domain.NewError(domain.ErrForbidden, "task is not an image deployment task")
	}

	// Verify image deploy intent exists for this operation
	var intentExists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM image_deploy_intents WHERE operation_id = ?`, input.OperationID.String()).Scan(&intentExists); err != nil || intentExists == 0 {
		return domain.NewError(domain.ErrForbidden, "image deploy intent not found")
	}

	// 2. Deployment check if deployment ID is provided
	if !input.DeploymentID.Empty() {
		var depStatus string
		err := tx.QueryRowContext(ctx, `
			SELECT status
			  FROM image_deployments
			 WHERE id = ? AND operation_id = ? AND task_id = ?;
		`, input.DeploymentID.String(), input.OperationID.String(), input.TaskID.String()).Scan(&depStatus)
		if errors.Is(err, sql.ErrNoRows) {
			return domain.NewError(domain.ErrForbidden, "deployment record not found or mismatched")
		}
		if err != nil {
			return fmt.Errorf("query deployment for fail: %w", err)
		}
	}

	// 3. Operation check: must not override cancelled operation
	var opState, appIDStr string
	err = tx.QueryRowContext(ctx, `
		SELECT state, application_id
		  FROM operations
		 WHERE id = ?;
	`, input.OperationID.String()).Scan(&opState, &appIDStr)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query operation for fail: %w", err)
	}
	if opState == "cancelled" {
		return domain.NewError(domain.ErrConflict, "operation is already cancelled")
	}
	if opState != "pending" && opState != "running" && opState != "waiting" {
		return domain.NewError(domain.ErrConflict, fmt.Sprintf("operation is in terminal state %q, cannot fail", opState))
	}

	// 4. Mark task failed or ready for retry using shared mutateTaskTx helper
	nextState, err := s.mutateTaskTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	}, "retry", cleanLastErrorReason(input.Reason))
	if err != nil {
		return fmt.Errorf("mutate task lease on fail: %w", err)
	}

	// If terminal failure, update deployment and operation
	if nextState == appcontracts.TaskFailed {
		if !input.DeploymentID.Empty() {
			depRes, err := tx.ExecContext(ctx, `
				UPDATE image_deployments
				   SET status = 'failed', updated_at = ?
				 WHERE id = ?;
			`, nowStr, input.DeploymentID.String())
			if err != nil {
				return fmt.Errorf("update deployment on fail: %w", err)
			}
			if n, _ := depRes.RowsAffected(); n != 1 {
				return fmt.Errorf("deployment fail update rows affected = %d, want 1", n)
			}
		}
		opRes, err := tx.ExecContext(ctx, `
			UPDATE operations
			   SET state = 'failed', updated_at = ?
			 WHERE id = ? AND state IN ('pending', 'running', 'waiting');
		`, nowStr, input.OperationID.String())
		if err != nil {
			return fmt.Errorf("update operation on fail: %w", err)
		}
		if n, _ := opRes.RowsAffected(); n != 1 {
			return fmt.Errorf("operation fail update rows affected = %d, want 1", n)
		}
	}

	// 5. Outbox and audit entry
	outboxEvt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{
		AggregateType:    "operation",
		AggregateID:      input.OperationID.String(),
		AggregateVersion: 2,
		EventType:        "image.deploy.failed",
		CreatedAt:        now,
		PayloadVersion:   "1.0",
	}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{
			"event_id":     id,
			"sequence":     cursor,
			"operation_id": input.OperationID.String(),
			"reason":       input.Reason,
			"occurred_at":  nowStr,
		})
	})
	if err != nil {
		return fmt.Errorf("append outbox event on fail: %w", err)
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	auditDigest := "sha256:" + sha256Hex(fmt.Sprintf("%s:%s", input.OperationID.String(), input.Reason))
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID: auditID.String(),
		Actor: appcontracts.AuditContext{
			ActorType: "system",
			ActorID:   "core-system",
			Reason:    "image.deploy",
		},
		Action:       "image.deploy.failed",
		InputDigest:  auditDigest,
		Result:       "failed",
		EvidenceRefs: []string{appIDStr, input.OperationID.String(), input.TaskID.String(), outboxEvt.ID},
		CreatedAt:    now,
	}); err != nil {
		return fmt.Errorf("append audit on fail: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit fail image execution: %v", ErrOutcomeUnknown, err)
	}

	return nil
}

// RecordImageExecutionUnknown records an unknown deployment outcome under active lease fencing,
// marking operations.state = 'unknown' and leaving the task ready for reclaim without exhausting attempt budget.
func (s *Store) RecordImageExecutionUnknown(ctx context.Context, input appcontracts.RecordImageExecutionUnknownInput) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if input.TaskID.Empty() || input.OperationID.Empty() || input.Owner == "" {
		return domain.ValidationError("task, operation, and owner are required")
	}

	now := time.Now().UTC()
	if !input.Now.IsZero() {
		now = input.Now.UTC()
	}
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin record unknown tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Verify task lease and DB singleton using shared verifyTaskLeaseTx helper
	task, err := s.verifyTaskLeaseTx(ctx, tx, appcontracts.TaskMutationRequest{
		TaskID:          input.TaskID,
		Owner:           input.Owner,
		CoreGeneration:  input.CoreGeneration,
		LeaseGeneration: input.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		return err
	}
	if task.OperationID != input.OperationID {
		return appcontracts.ErrLeaseLost
	}

	// Verify task kind is image.deploy
	var taskKind string
	if err := tx.QueryRowContext(ctx, `SELECT json_extract(payload, '$.kind') FROM task_leases WHERE task_id = ?`, input.TaskID.String()).Scan(&taskKind); err != nil || taskKind != "image.deploy" {
		return domain.NewError(domain.ErrForbidden, "task is not an image deployment task")
	}

	// Verify image deploy intent exists for this operation
	var intentExists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM image_deploy_intents WHERE operation_id = ?`, input.OperationID.String()).Scan(&intentExists); err != nil || intentExists == 0 {
		return domain.NewError(domain.ErrForbidden, "image deploy intent not found")
	}

	// 2. Verify deployment exists
	if !input.DeploymentID.Empty() {
		var depStatus string
		err := tx.QueryRowContext(ctx, `
			SELECT status
			  FROM image_deployments
			 WHERE id = ? AND operation_id = ? AND task_id = ?;
		`, input.DeploymentID.String(), input.OperationID.String(), input.TaskID.String()).Scan(&depStatus)
		if errors.Is(err, sql.ErrNoRows) {
			return domain.NewError(domain.ErrForbidden, "deployment record not found or mismatched")
		}
		if err != nil {
			return fmt.Errorf("query deployment for unknown: %w", err)
		}
	}

	// 3. Update operations.state to waiting (conforming to 0005 schema constraint)
	var opState, appIDStr string
	err = tx.QueryRowContext(ctx, `
		SELECT state, application_id
		  FROM operations
		 WHERE id = ?;
	`, input.OperationID.String()).Scan(&opState, &appIDStr)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query operation for unknown: %w", err)
	}
	if opState == "cancelled" {
		return domain.NewError(domain.ErrConflict, "operation is already cancelled")
	}
	if opState != "pending" && opState != "running" && opState != "waiting" {
		return domain.NewError(domain.ErrConflict, fmt.Sprintf("operation is in terminal state %q", opState))
	}

	opRes, err := tx.ExecContext(ctx, `
		UPDATE operations
		   SET state = 'waiting', updated_at = ?
		 WHERE id = ? AND state IN ('pending', 'running', 'waiting');
	`, nowStr, input.OperationID.String())
	if err != nil {
		return fmt.Errorf("update operation to waiting: %w", err)
	}
	if n, _ := opRes.RowsAffected(); n != 1 {
		return fmt.Errorf("operation unknown rows affected = %d, want 1", n)
	}

	// 4. Release task lease back to ready, keeping attempt budget intact
	// (when task.Attempt >= task.MaxAttempts, ClaimTask attempt < min(max_attempts, ?) naturally blocks automatic reclaim)
	lastErr := cleanLastErrorReason(input.Reason)
	if task.Attempt >= task.MaxAttempts {
		lastErr = cleanLastErrorReason(fmt.Sprintf("needs_action: attempt budget %d exhausted; %s", task.MaxAttempts, input.Reason))
	}
	taskRes, err := tx.ExecContext(ctx, `
		UPDATE task_leases
		   SET state = 'ready',
		       lease_owner = NULL,
		       lease_until = NULL,
		       last_error = ?,
		       updated_at = ?
		 WHERE task_id = ? AND state = 'leased' AND lease_owner = ?;
	`, lastErr, nowStr, input.TaskID.String(), input.Owner)
	if err != nil {
		return fmt.Errorf("update task lease on unknown: %w", err)
	}
	if n, _ := taskRes.RowsAffected(); n != 1 {
		return fmt.Errorf("task lease update rows affected = %d, want 1", n)
	}

	// 5. Outbox and audit entry
	outboxEvt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{
		AggregateType:    "operation",
		AggregateID:      input.OperationID.String(),
		AggregateVersion: 2,
		EventType:        "image.deploy.unknown",
		CreatedAt:        now,
		PayloadVersion:   "1.0",
	}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{
			"event_id":     id,
			"sequence":     cursor,
			"operation_id": input.OperationID.String(),
			"reason":       input.Reason,
			"occurred_at":  nowStr,
		})
	})
	if err != nil {
		return fmt.Errorf("append outbox event on unknown: %w", err)
	}

	auditID, err := domain.NewID("audit")
	if err != nil {
		return err
	}
	auditDigest := "sha256:" + sha256Hex(fmt.Sprintf("%s:%s", input.OperationID.String(), input.Reason))
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID: auditID.String(),
		Actor: appcontracts.AuditContext{
			ActorType: "system",
			ActorID:   "core-system",
			Reason:    "image.deploy",
		},
		Action:       "image.deploy.unknown",
		InputDigest:  auditDigest,
		Result:       "unknown",
		EvidenceRefs: []string{appIDStr, input.OperationID.String(), input.TaskID.String(), outboxEvt.ID},
		CreatedAt:    now,
	}); err != nil {
		return fmt.Errorf("append audit on unknown: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit record unknown: %v", ErrOutcomeUnknown, err)
	}
	return nil
}

// ReadImageObservationBinding returns read-only authority facts linking an operation and deployment
// for observe recovery without requiring an active task lease.
func (s *Store) ReadImageObservationBinding(ctx context.Context, operationID, deploymentID domain.ID) (appcontracts.ImageObservationBinding, error) {
	if err := s.checkOpen(); err != nil {
		return appcontracts.ImageObservationBinding{}, err
	}
	if operationID.Empty() || deploymentID.Empty() {
		return appcontracts.ImageObservationBinding{}, domain.ValidationError("operation_id and deployment_id are required")
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return appcontracts.ImageObservationBinding{}, fmt.Errorf("begin read observe binding tx: %w", err)
	}
	defer tx.Rollback()

	var appIDStr, envIDStr, relIDStr, repo, digest string
	var approvedPort int
	var planDigest, opState, planOwner, canonicalRaw, provenanceRaw string
	var consistent bool

	err = tx.QueryRowContext(ctx, `
		SELECT d.application_id, d.environment_id, d.release_id, r.repository, r.digest,
		       json_extract(p.canonical_input, '$.port'), p.plan_digest, o.state,
		       p.admin_id, p.canonical_input, p.resolver_provenance,
		       COALESCE(d.application_id = o.application_id AND d.environment_id = o.environment_id
		         AND d.application_id = i.application_id AND d.environment_id = i.environment_id
		         AND r.application_id = d.application_id AND r.plan_id = i.plan_id
		         AND r.plan_digest = i.plan_digest AND i.plan_digest = p.plan_digest
		         AND r.repository = json_extract(p.resolved_image, '$.repository')
		         AND r.digest = json_extract(p.resolved_image, '$.digest'), 0)
		  FROM image_deployments d
		  JOIN operations o ON d.operation_id = o.id
		  JOIN image_releases r ON d.release_id = r.id
		  JOIN image_deploy_intents i ON o.id = i.operation_id
		  JOIN image_plans p ON i.plan_id = p.id
		 WHERE d.operation_id = ? AND d.id = ?;
	`, operationID.String(), deploymentID.String()).Scan(
		&appIDStr, &envIDStr, &relIDStr, &repo, &digest,
		&approvedPort, &planDigest, &opState, &planOwner, &canonicalRaw, &provenanceRaw, &consistent,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return appcontracts.ImageObservationBinding{}, ErrNotFound
	}
	if err != nil {
		return appcontracts.ImageObservationBinding{}, fmt.Errorf("query observe binding: %w", err)
	}
	if !consistent {
		return appcontracts.ImageObservationBinding{}, fmt.Errorf("%w: inconsistent image observation binding", ErrCorruptData)
	}
	var canonical appcontracts.CanonicalExecutionInput
	var provenance appcontracts.ResolverProvenance
	if json.Unmarshal([]byte(canonicalRaw), &canonical) != nil || json.Unmarshal([]byte(provenanceRaw), &provenance) != nil {
		return appcontracts.ImageObservationBinding{}, ErrCorruptData
	}
	plan := appcontracts.ImagePlan{AdminID: domain.ID(planOwner), CanonicalInput: canonical, ResolverProvenance: provenance, ResolvedImage: appcontracts.ResolvedImage{Repository: repo, Digest: digest}}
	sourceArtifact, err := s.sourceArtifactForImagePlanTx(ctx, tx, plan, domain.ID(appIDStr), domain.ID(envIDStr))
	if err != nil {
		return appcontracts.ImageObservationBinding{}, err
	}
	imageOrigin := "registryhttp"
	if sourceArtifact != nil {
		imageOrigin = "source-build"
	}

	return appcontracts.ImageObservationBinding{
		ApplicationID:  domain.ID(appIDStr),
		EnvironmentID:  domain.ID(envIDStr),
		ReleaseID:      domain.ID(relIDStr),
		Repository:     repo,
		Digest:         digest,
		ApprovedPort:   approvedPort,
		PlanDigest:     planDigest,
		OperationState: opState,
		ImageOrigin:    imageOrigin,
		SourceArtifact: sourceArtifact,
		CanonicalInput: &canonical,
	}, nil
}
