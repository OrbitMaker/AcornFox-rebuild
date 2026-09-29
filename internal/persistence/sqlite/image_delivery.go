package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	imageConfirmScope    = "image.confirm"
	imageDeployOpType    = "deploy_image"
	imageDeployTaskKind  = "image.deploy"
	imageDeployEventType = "image.deploy.created"
)

// CreateImagePlan persists a verified immutable image plan.
func (s *Store) CreateImagePlan(ctx context.Context, plan appcontracts.ImagePlan) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if err := appcontracts.ValidatePlanConsistency(plan); err != nil {
		return domain.ValidationError("plan consistency check failed: " + err.Error())
	}

	canonicalJSON, err := json.Marshal(plan.CanonicalInput)
	if err != nil {
		return fmt.Errorf("encode canonical input: %w", err)
	}
	resolvedJSON, err := json.Marshal(plan.ResolvedImage)
	if err != nil {
		return fmt.Errorf("encode resolved image: %w", err)
	}
	provenanceJSON, err := json.Marshal(plan.ResolverProvenance)
	if err != nil {
		return fmt.Errorf("encode resolver provenance: %w", err)
	}
	missingJSON, err := json.Marshal(plan.MissingInputs)
	if err != nil {
		return fmt.Errorf("encode missing inputs: %w", err)
	}

	createdAtStr := FormatTime(plan.CreatedAt.UTC())
	updatedAtStr := FormatTime(plan.UpdatedAt.UTC())

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO image_plans (
			id, admin_id, app_name, status, plan_digest,
			canonical_input, resolved_image, resolver_provenance, missing_inputs,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`, plan.ID.String(), plan.AdminID.String(), plan.AppName, string(plan.Status), plan.PlanDigest,
		string(canonicalJSON), string(resolvedJSON), string(provenanceJSON), string(missingJSON),
		createdAtStr, updatedAtStr)
	if err != nil {
		return fmt.Errorf("insert image plan: %w", err)
	}
	return nil
}

// GetImagePlan reads a stored image plan and enforces admin ownership and plan consistency.
func (s *Store) GetImagePlan(ctx context.Context, planID domain.ID, adminID domain.ID) (appcontracts.ImagePlan, error) {
	if err := s.checkOpen(); err != nil {
		return appcontracts.ImagePlan{}, err
	}
	if planID.Empty() {
		return appcontracts.ImagePlan{}, domain.ValidationError("plan id is required")
	}
	if adminID.Empty() {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnauthorized, "admin id is required")
	}

	var (
		idStr, storedAdminID, appName, statusStr, planDigest     string
		canonicalJSON, resolvedJSON, provenanceJSON, missingJSON string
		createdAtStr, updatedAtStr                               string
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT id, admin_id, app_name, status, plan_digest,
		       canonical_input, resolved_image, resolver_provenance, missing_inputs,
		       created_at, updated_at
		  FROM image_plans
		 WHERE id = ?;
	`, planID.String()).Scan(
		&idStr, &storedAdminID, &appName, &statusStr, &planDigest,
		&canonicalJSON, &resolvedJSON, &provenanceJSON, &missingJSON,
		&createdAtStr, &updatedAtStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return appcontracts.ImagePlan{}, ErrNotFound
	}
	if err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("query image plan: %w", err)
	}

	if storedAdminID != adminID.String() {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrForbidden, "image plan does not belong to administrator")
	}

	createdAt, err := ParseTime(createdAtStr)
	if err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: parse created_at: %v", ErrCorruptData, err)
	}
	updatedAt, err := ParseTime(updatedAtStr)
	if err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: parse updated_at: %v", ErrCorruptData, err)
	}

	var canonicalInput appcontracts.CanonicalExecutionInput
	if err := json.Unmarshal([]byte(canonicalJSON), &canonicalInput); err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: decode canonical input: %v", ErrCorruptData, err)
	}

	var resolvedImage appcontracts.ResolvedImage
	if err := json.Unmarshal([]byte(resolvedJSON), &resolvedImage); err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: decode resolved image: %v", ErrCorruptData, err)
	}

	var provenance appcontracts.ResolverProvenance
	if err := json.Unmarshal([]byte(provenanceJSON), &provenance); err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: decode resolver provenance: %v", ErrCorruptData, err)
	}

	var missingInputs []string
	if err := json.Unmarshal([]byte(missingJSON), &missingInputs); err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: decode missing inputs: %v", ErrCorruptData, err)
	}

	plan := appcontracts.ImagePlan{
		ID:                 domain.ID(idStr),
		AdminID:            domain.ID(storedAdminID),
		AppName:            appName,
		Status:             appcontracts.ImagePlanStatus(statusStr),
		PlanDigest:         planDigest,
		CanonicalInput:     canonicalInput,
		ResolvedImage:      resolvedImage,
		ResolverProvenance: provenance,
		MissingInputs:      missingInputs,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
	}

	if err := appcontracts.ValidatePlanConsistency(plan); err != nil {
		return appcontracts.ImagePlan{}, fmt.Errorf("%w: stored plan failed consistency check: %v", ErrCorruptData, err)
	}

	return plan, nil
}

// ConfirmImagePlan executes atomic intake in a single short SQLite transaction.
// Creates app, default env, image deploy operation/task, plan binding, outbox event, and audit entry.
func (s *Store) ConfirmImagePlan(ctx context.Context, adminID domain.ID, input appcontracts.ConfirmImagePlanInput) (appcontracts.ConfirmImagePlanResult, error) {
	if err := s.checkOpen(); err != nil {
		return appcontracts.ConfirmImagePlanResult{}, err
	}
	if adminID.Empty() {
		return appcontracts.ConfirmImagePlanResult{}, domain.NewError(domain.ErrUnauthorized, "admin id is required")
	}
	if input.PlanID.Empty() || strings.TrimSpace(input.PlanDigest) == "" || strings.TrimSpace(input.IdempotencyKey) == "" {
		return appcontracts.ConfirmImagePlanResult{}, domain.ValidationError("confirm input is incomplete")
	}

	key := strings.TrimSpace(input.IdempotencyKey)
	planDigest := strings.TrimSpace(input.PlanDigest)
	requestDigest := sha256Hex(fmt.Sprintf("%s:%s:%s", adminID.String(), input.PlanID.String(), planDigest))

	now := time.Now().UTC()
	nowStr := FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return appcontracts.ConfirmImagePlanResult{}, fmt.Errorf("begin confirm transaction: %w", err)
	}
	rollback := func(cause error) (appcontracts.ConfirmImagePlanResult, error) {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return appcontracts.ConfirmImagePlanResult{}, fmt.Errorf("%w (rollback: %v)", cause, rollbackErr)
		}
		return appcontracts.ConfirmImagePlanResult{}, cause
	}

	// 1. Idempotency reservation
	reservation, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_records
			(scope, idempotency_key, request_digest, status, created_at, updated_at)
		VALUES (?, ?, ?, 'in_progress', ?, ?)
		ON CONFLICT (scope, idempotency_key) DO NOTHING;
	`, imageConfirmScope, key, requestDigest, nowStr, nowStr)
	if err != nil {
		return rollback(fmt.Errorf("reserve confirm idempotency key: %w", err))
	}
	inserted, err := reservation.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("inspect confirm idempotency reservation: %w", err))
	}

	var storedDigest, storedStatus string
	var storedResponse sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT request_digest, status, response
		  FROM idempotency_records
		 WHERE scope = ? AND idempotency_key = ?;
	`, imageConfirmScope, key).Scan(&storedDigest, &storedStatus, &storedResponse); err != nil {
		return rollback(fmt.Errorf("read confirm idempotency record: %w", err))
	}

	if storedDigest != requestDigest {
		return rollback(ErrIdempotencyConflict)
	}

	if inserted == 0 {
		switch storedStatus {
		case "completed":
			if !storedResponse.Valid || len(storedResponse.String) == 0 {
				return rollback(ErrIdempotencyCorrupt)
			}
			var result appcontracts.ConfirmImagePlanResult
			if err := json.Unmarshal([]byte(storedResponse.String), &result); err != nil {
				return rollback(fmt.Errorf("%w: decode cached confirm response: %v", ErrIdempotencyCorrupt, err))
			}
			// Verify cached response integrity
			if result.ApplicationID.Empty() || result.EnvironmentID.Empty() || result.OperationID.Empty() || result.TaskID.Empty() || result.PlanID.Empty() || result.PlanDigest == "" || result.PlanID != input.PlanID || result.PlanDigest != planDigest || result.Status != "pending" || result.CreatedAt.IsZero() {
				return rollback(fmt.Errorf("%w: cached confirm response has corrupt fields", ErrIdempotencyCorrupt))
			}
			if err := tx.Commit(); err != nil {
				return appcontracts.ConfirmImagePlanResult{}, fmt.Errorf("%w: commit idempotent replay: %v", ErrOutcomeUnknown, err)
			}
			return result, nil
		case "in_progress":
			return rollback(ErrIdempotencyInProgress)
		default:
			return rollback(fmt.Errorf("%w: unsupported status %q", ErrIdempotencyCorrupt, storedStatus))
		}
	}

	// 2. Load stored plan and verify auth/ownership/digest/invariants
	var (
		idStr, planAdminID, appName, planStatus, storedPlanDigest string
		canonicalJSON, resolvedJSON, provenanceJSON, missingJSON  string
		planCreatedStr, planUpdatedStr                            string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, admin_id, app_name, status, plan_digest,
		       canonical_input, resolved_image, resolver_provenance, missing_inputs,
		       created_at, updated_at
		  FROM image_plans
		 WHERE id = ?;
	`, input.PlanID.String()).Scan(
		&idStr, &planAdminID, &appName, &planStatus, &storedPlanDigest,
		&canonicalJSON, &resolvedJSON, &provenanceJSON, &missingJSON,
		&planCreatedStr, &planUpdatedStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(fmt.Errorf("query image plan: %w", err))
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

	storedPlan := appcontracts.ImagePlan{
		ID:                 domain.ID(idStr),
		AdminID:            domain.ID(planAdminID),
		AppName:            appName,
		Status:             appcontracts.ImagePlanStatus(planStatus),
		PlanDigest:         storedPlanDigest,
		CanonicalInput:     canonicalInput,
		ResolvedImage:      resolvedImage,
		ResolverProvenance: provenance,
		MissingInputs:      missingInputs,
		CreatedAt:          planCreatedAt,
		UpdatedAt:          planUpdatedAt,
	}

	if err := appcontracts.ValidatePlanConsistency(storedPlan); err != nil {
		return rollback(fmt.Errorf("%w: stored plan failed consistency check: %v", ErrCorruptData, err))
	}

	if planAdminID != adminID.String() {
		return rollback(domain.NewError(domain.ErrForbidden, "image plan does not belong to administrator"))
	}
	if storedPlan.ResolverProvenance.Provider != "registryhttp" {
		return rollback(domain.NewError(domain.ErrConflict, "source-built plan requires original-application confirmation"))
	}
	if storedPlan.Status == appcontracts.ImagePlanStatusNeedsInput {
		return rollback(domain.NewError(domain.ErrConflict, "cannot confirm image plan that requires input"))
	}
	if storedPlanDigest != planDigest {
		return rollback(domain.NewError(domain.ErrConflict, "plan digest does not match stored plan"))
	}

	// 3. Generate IDs
	appID, err := domain.NewID("app")
	if err != nil {
		return rollback(fmt.Errorf("generate application id: %w", err))
	}
	envID, err := domain.NewID("env")
	if err != nil {
		return rollback(fmt.Errorf("generate environment id: %w", err))
	}
	opID, err := domain.NewID("op")
	if err != nil {
		return rollback(fmt.Errorf("generate operation id: %w", err))
	}
	taskID, err := domain.NewID("task")
	if err != nil {
		return rollback(fmt.Errorf("generate task id: %w", err))
	}

	// 4. Insert application and environment
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO applications (id, name, version, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?);
	`, appID.String(), appName, nowStr, nowStr); err != nil {
		return rollback(fmt.Errorf("insert application: %w", err))
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO environments (id, application_id, name, created_at)
		VALUES (?, ?, ?, ?);
	`, envID.String(), appID.String(), defaultEnvironmentName, nowStr); err != nil {
		return rollback(fmt.Errorf("insert default environment: %w", err))
	}

	// 5. Insert operation (deploy_image)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operations (
			id, application_id, environment_id, operation_type, idempotency_key,
			state, version, target_ref, target_kind, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, 'pending', 1, ?, 'application', ?, ?);
	`, opID.String(), appID.String(), envID.String(), imageDeployOpType, key, appID.String(), nowStr, nowStr); err != nil {
		return rollback(fmt.Errorf("insert image operation: %w", err))
	}

	// 6. Insert image deploy intent (plan binding)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO image_deploy_intents (
			operation_id, plan_id, application_id, environment_id, plan_digest, created_at
		) VALUES (?, ?, ?, ?, ?, ?);
	`, opID.String(), input.PlanID.String(), appID.String(), envID.String(), planDigest, nowStr); err != nil {
		return rollback(fmt.Errorf("insert image deploy intent: %w", err))
	}

	// 7. Insert task lease with approved immutable payload
	taskPayload, err := json.Marshal(map[string]any{
		"kind":            imageDeployTaskKind,
		"application_id":  appID.String(),
		"environment_id":  envID.String(),
		"operation_id":    opID.String(),
		"plan_id":         input.PlanID.String(),
		"plan_digest":     planDigest,
		"canonical_input": canonicalInput,
		"resolved_image":  resolvedImage,
	})
	if err != nil {
		return rollback(fmt.Errorf("encode task payload: %w", err))
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO task_leases (
			task_id, operation_id, lease_owner, lease_until, attempt, max_attempts,
			state, payload, created_at, updated_at
		) VALUES (?, ?, NULL, NULL, 0, ?, 'ready', ?, ?, ?);
	`, taskID.String(), opID.String(), defaultTaskMaxAttempts, string(taskPayload), nowStr, nowStr); err != nil {
		return rollback(fmt.Errorf("insert task lease: %w", err))
	}

	// 8. Append outbox event using existing appendOutboxTx helper
	outboxEvt, err := appendOutboxTx(ctx, tx, appcontracts.OutboxEvent{
		AggregateType:    "operation",
		AggregateID:      opID.String(),
		AggregateVersion: 1,
		EventType:        imageDeployEventType,
		CreatedAt:        now,
		PayloadVersion:   "1.0",
	}, func(id string, cursor int64) ([]byte, error) {
		return json.Marshal(map[string]any{
			"event_id":       id,
			"sequence":       cursor,
			"operation_id":   opID.String(),
			"application_id": appID.String(),
			"kind":           imageDeployEventType,
			"plan_id":        input.PlanID.String(),
			"plan_digest":    planDigest,
			"occurred_at":    nowStr,
		})
	})
	if err != nil {
		return rollback(fmt.Errorf("append outbox event: %w", err))
	}

	// 9. Append audit using existing appendAuditTx helper
	auditID, err := domain.NewID("audit")
	if err != nil {
		return rollback(err)
	}
	auditDigest := "sha256:" + requestDigest
	if _, err := appendAuditTx(ctx, tx, auditInput{
		ID:           auditID.String(),
		Actor:        auditContextFromAdmin(adminID),
		Action:       "image.deploy.accepted",
		InputDigest:  auditDigest,
		Result:       "accepted",
		EvidenceRefs: []string{appID.String(), opID.String(), taskID.String(), outboxEvt.ID},
		CreatedAt:    now,
	}); err != nil {
		return rollback(fmt.Errorf("append audit: %w", err))
	}

	// 10. Complete idempotency record
	result := appcontracts.ConfirmImagePlanResult{
		ApplicationID: appID,
		EnvironmentID: envID,
		OperationID:   opID,
		TaskID:        taskID,
		PlanID:        input.PlanID,
		PlanDigest:    planDigest,
		Status:        "pending",
		CreatedAt:     now,
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return rollback(fmt.Errorf("encode confirm result: %w", err))
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE idempotency_records
		   SET status = 'completed', response = ?, updated_at = ?
		 WHERE scope = ? AND idempotency_key = ? AND status = 'in_progress';
	`, string(resultJSON), nowStr, imageConfirmScope, key); err != nil {
		return rollback(fmt.Errorf("complete confirm idempotency: %w", err))
	}

	if err := tx.Commit(); err != nil {
		return appcontracts.ConfirmImagePlanResult{}, fmt.Errorf("%w: commit confirm: %v", ErrOutcomeUnknown, err)
	}

	return result, nil
}

// GetImageOperation reads an operation and its image deployment intent linkage, enforcing plan owner context.
func (s *Store) GetImageOperation(ctx context.Context, adminID domain.ID, operationID domain.ID) (appcontracts.ImageOperationDetailWithResult, error) {
	if err := s.checkOpen(); err != nil {
		return appcontracts.ImageOperationDetailWithResult{}, err
	}
	if adminID.Empty() {
		return appcontracts.ImageOperationDetailWithResult{}, domain.NewError(domain.ErrUnauthorized, "admin id is required")
	}
	if operationID.Empty() {
		return appcontracts.ImageOperationDetailWithResult{}, domain.ValidationError("operation id is required")
	}

	var (
		opIDStr, appIDStr, envIDStr, opType, state    string
		planIDStr, planDigest, taskIDStr, planAdminID string
		createdAtStr, updatedAtStr                    string
		taskState, lastError                          string
		attempt, maxAttempts                          int
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT o.id, o.application_id, o.environment_id, o.operation_type, o.state,
		       i.plan_id, i.plan_digest, COALESCE(t.task_id, ''), p.admin_id, o.created_at, o.updated_at,
		       COALESCE(t.state, ''), COALESCE(t.last_error, ''),
		       COALESCE(t.attempt, 0), COALESCE(t.max_attempts, 0)
		  FROM operations o
		  JOIN image_deploy_intents i ON o.id = i.operation_id
		  JOIN image_plans p ON i.plan_id = p.id
		  LEFT JOIN task_leases t ON o.id = t.operation_id
		 WHERE o.id = ?;
	`, operationID.String()).Scan(
		&opIDStr, &appIDStr, &envIDStr, &opType, &state,
		&planIDStr, &planDigest, &taskIDStr, &planAdminID, &createdAtStr, &updatedAtStr,
		&taskState, &lastError, &attempt, &maxAttempts,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// Distinguish between not found and unauthorized
		var exists int
		_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE id = ?;`, operationID.String()).Scan(&exists)
		if exists > 0 {
			return appcontracts.ImageOperationDetailWithResult{}, domain.NewError(domain.ErrForbidden, "image operation does not belong to administrator")
		}
		return appcontracts.ImageOperationDetailWithResult{}, ErrNotFound
	}
	if err != nil {
		return appcontracts.ImageOperationDetailWithResult{}, fmt.Errorf("query image operation: %w", err)
	}

	if planAdminID != adminID.String() {
		return appcontracts.ImageOperationDetailWithResult{}, domain.NewError(domain.ErrForbidden, "image operation does not belong to administrator")
	}

	createdAt, err := ParseTime(createdAtStr)
	if err != nil {
		return appcontracts.ImageOperationDetailWithResult{}, fmt.Errorf("%w: parse created_at: %v", ErrCorruptData, err)
	}
	updatedAt, err := ParseTime(updatedAtStr)
	if err != nil {
		return appcontracts.ImageOperationDetailWithResult{}, fmt.Errorf("%w: parse updated_at: %v", ErrCorruptData, err)
	}

	var result *appcontracts.ImageOperationExecutionResult
	var depID, relID, depStatus, containerID, imageID sql.NullString
	var hostIP sql.NullString
	var hostPort, containerPort sql.NullInt64
	depErr := s.db.QueryRowContext(ctx, `
		SELECT d.id, d.release_id, d.status, d.container_id, d.image_id,
		       e.host_ip, e.host_port, e.container_port
		  FROM image_deployments d
		  LEFT JOIN image_endpoints e ON d.id = e.deployment_id
		 WHERE d.operation_id = ?;
	`, operationID.String()).Scan(&depID, &relID, &depStatus, &containerID, &imageID, &hostIP, &hostPort, &containerPort)

	if depErr == nil && depID.Valid {
		endpoint := ""
		hp := int(hostPort.Int64)
		if hp > 0 {
			endpoint = fmt.Sprintf("http://127.0.0.1:%d", hp)
		}
		result = &appcontracts.ImageOperationExecutionResult{
			DeploymentID:  domain.ID(depID.String),
			ReleaseID:     domain.ID(relID.String),
			Status:        depStatus.String,
			ContainerID:   containerID.String,
			ImageID:       imageID.String,
			HostIP:        hostIP.String,
			HostPort:      hp,
			ContainerPort: int(containerPort.Int64),
			Endpoint:      endpoint,
		}
	}

	displayState := state
	if state == "waiting" {
		displayState = "unknown"
	}

	// Only current failure or unknown outcomes expose the persisted task diagnostic.
	reason := ""
	actionRequired := false
	if state == "failed" || state == "waiting" {
		if strings.TrimSpace(lastError) != "" {
			reason = cleanLastErrorReason(lastError)
		}
		actionRequired = maxAttempts > 0 && attempt >= maxAttempts &&
			((state == "waiting" && taskState == "ready") || (state == "failed" && taskState == "failed"))
	}

	return appcontracts.ImageOperationDetailWithResult{
		ImageOperationDetail: appcontracts.ImageOperationDetail{
			Reason:         reason,
			ActionRequired: actionRequired,
			OperationID:    domain.ID(opIDStr),
			ApplicationID:  domain.ID(appIDStr),
			EnvironmentID:  domain.ID(envIDStr),
			OperationType:  opType,
			State:          displayState,
			PlanID:         domain.ID(planIDStr),
			PlanDigest:     planDigest,
			TaskID:         domain.ID(taskIDStr),
			CreatedAt:      createdAt,
			UpdatedAt:      updatedAt,
		},
		Result: result,
	}, nil
}

func auditContextFromAdmin(adminID domain.ID) appcontracts.AuditContext {
	return appcontracts.AuditContext{
		ActorType: "admin",
		ActorID:   adminID.String(),
		Reason:    "deploy_image",
	}
}

// ListManagedImageApplications deliberately does not reuse unscoped
// ListApplications. Ownership comes from the original administrator-owned plan.
func (s *Store) ListManagedImageApplications(ctx context.Context, admin domain.ID, limit int) (appcontracts.ManagedImageApplicationList, error) {
	out := appcontracts.ManagedImageApplicationList{Items: []appcontracts.ManagedImageApplicationSummary{}}
	if err := s.checkOpen(); err != nil {
		return out, err
	}
	if admin.Empty() {
		return out, domain.NewError(domain.ErrUnauthorized, "administrator required")
	}
	if limit < 1 || limit > 100 {
		return out, domain.ValidationError("limit must be between 1 and 100")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE id=? AND disabled_at IS NULL`, admin.String()).Scan(&enabled); err != nil {
		return out, err
	}
	if enabled != 1 {
		return out, domain.NewError(domain.ErrUnauthorized, "administrator unavailable")
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.id,a.name,i.environment_id,p.id,p.plan_digest,o.id,o.state,COALESCE(d.id,''),COALESCE(d.status,''),max(a.updated_at,o.updated_at,COALESCE(d.updated_at,o.updated_at)),
 COALESCE((SELECT c.operation_id FROM image_lifecycle_commands c JOIN operations co ON co.id=c.operation_id WHERE c.deployment_id=d.id AND c.admin_id=p.admin_id AND co.application_id=a.id AND co.environment_id=i.environment_id AND co.state IN ('pending','leased','running','waiting','cancelling') ORDER BY co.created_at DESC,co.id DESC LIMIT 1),''),
 COALESCE((SELECT c.operation_id FROM image_lifecycle_commands c JOIN operations co ON co.id=c.operation_id WHERE c.deployment_id=d.id AND c.admin_id=p.admin_id AND co.application_id=a.id AND co.environment_id=i.environment_id ORDER BY co.created_at DESC,co.id DESC LIMIT 1),'')
 FROM image_deploy_intents i JOIN image_plans p ON p.id=i.plan_id AND p.plan_digest=i.plan_digest
 JOIN operations o ON o.id=i.operation_id AND o.application_id=i.application_id AND o.environment_id=i.environment_id
 JOIN applications a ON a.id=i.application_id JOIN environments e ON e.id=i.environment_id AND e.application_id=a.id
 LEFT JOIN image_deployments d ON d.operation_id=o.id AND d.application_id=a.id AND d.environment_id=e.id
 WHERE p.admin_id=? ORDER BY o.created_at DESC,o.id DESC LIMIT ?`, admin.String(), limit+1)
	if err != nil {
		return out, err
	}
	var activeIDs, lastIDs []string
	for rows.Next() {
		var item appcontracts.ManagedImageApplicationSummary
		var updated, active, last string
		if err := rows.Scan(&item.ApplicationID, &item.Name, &item.EnvironmentID, &item.PlanID, &item.PlanDigest, &item.DeployOperationID, &item.DeployState, &item.DeploymentID, &item.DeploymentState, &updated, &active, &last); err != nil {
			rows.Close()
			return out, err
		}
		item.UpdatedAt, err = ParseTime(updated)
		if err != nil {
			rows.Close()
			return out, ErrCorruptData
		}
		item.DeployState = publicManagedImageState(item.DeployState)
		if item.DeployState == "" || !validSha256Digest(item.PlanDigest) {
			rows.Close()
			return out, ErrCorruptData
		}
		out.Items = append(out.Items, item)
		activeIDs = append(activeIDs, active)
		lastIDs = append(lastIDs, last)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	if err := rows.Close(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Truncated = true
		out.Items = out.Items[:limit]
		activeIDs = activeIDs[:limit]
		lastIDs = lastIDs[:limit]
	}
	for index := range out.Items {
		item := &out.Items[index]
		for _, entry := range []struct {
			id     string
			target **appcontracts.ManagedImageCommandSummary
		}{{activeIDs[index], &item.ActiveCommand}, {lastIDs[index], &item.LastCommand}} {
			if entry.id == "" {
				continue
			}
			var summary appcontracts.ManagedImageCommandSummary
			err := tx.QueryRowContext(ctx, `SELECT c.operation_id,c.action,o.state FROM image_lifecycle_commands c JOIN operations o ON o.id=c.operation_id WHERE c.operation_id=? AND c.deployment_id=? AND c.admin_id=? AND o.application_id=? AND o.environment_id=?`, entry.id, item.DeploymentID.String(), admin.String(), item.ApplicationID.String(), item.EnvironmentID.String()).Scan(&summary.OperationID, &summary.Action, &summary.State)
			if err != nil {
				return out, ErrCorruptData
			}
			summary.State = publicManagedImageState(summary.State)
			if !validLifecycleAction(summary.Action) || summary.State == "" {
				return out, ErrCorruptData
			}
			*entry.target = &summary
		}
	}
	return out, nil
}
func publicManagedImageState(state string) string {
	switch state {
	case "waiting":
		return "unknown"
	case "leased", "cancelling":
		return "running"
	case "pending", "running", "unknown", "succeeded", "failed", "cancelled":
		return state
	}
	return ""
}
