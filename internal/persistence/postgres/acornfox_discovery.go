package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxDiscoveryCursor is an opaque HTTP-layer cursor's durable position.
// It deliberately contains no locator, workspace, task payload, or SQL key.
type AcornFoxDiscoveryCursor struct {
	CreatedAt time.Time
	ID        domain.ID
}

type AcornFoxSourceRevisionPage struct {
	Items      []domain.SourceRevision
	NextCursor *AcornFoxDiscoveryCursor
}

type AcornFoxDeploymentPage struct {
	Items      []domain.Deployment
	NextCursor *AcornFoxDiscoveryCursor
}

func validateAcornFoxDiscoveryCursor(cursor *AcornFoxDiscoveryCursor) error {
	if cursor == nil {
		return nil
	}
	if cursor.CreatedAt.IsZero() || domain.RequireID(cursor.ID, "AcornFox discovery cursor id") != nil {
		return domain.ValidationError("AcornFox discovery cursor is invalid")
	}
	return nil
}

func (s *Store) ensureAcornFoxDiscoveryApplication(ctx context.Context, applicationID domain.ID) error {
	if err := domain.RequireID(applicationID, "AcornFox discovery application id"); err != nil {
		return err
	}
	var value int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM applications WHERE id=$1`, applicationID.String()).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ListAcornFoxSourceRevisions returns immutable proven public Git or claimed upload facts.
// The raw locator remains inside persistence and is later hashed by the clean
// contract projection.
func (s *Store) ListAcornFoxSourceRevisions(ctx context.Context, applicationID domain.ID, after *AcornFoxDiscoveryCursor, limit int) (AcornFoxSourceRevisionPage, error) {
	if err := s.requireDB(); err != nil {
		return AcornFoxSourceRevisionPage{}, err
	}
	if err := validateAcornFoxDiscoveryCursor(after); err != nil {
		return AcornFoxSourceRevisionPage{}, err
	}
	if limit < 1 || limit > 100 {
		return AcornFoxSourceRevisionPage{}, domain.ValidationError("AcornFox discovery limit is invalid")
	}
	if err := s.ensureAcornFoxDiscoveryApplication(ctx, applicationID); err != nil {
		return AcornFoxSourceRevisionPage{}, err
	}
	scanLimit := acornFoxDiscoveryScanLimit(limit)
	statement := `
		SELECT id,application_id,source_kind,locator,COALESCE(source_ref,''),COALESCE(git_commit,''),content_digest,workspace_ref,created_at,immutable
		  FROM source_revisions
		 WHERE application_id=$1 AND immutable=true AND (source_kind='git_https' OR (source_kind='upload' AND provider='upload'))`
	args := []any{applicationID.String()}
	if after != nil {
		statement += ` AND (created_at,id)<($2,$3)`
		args = append(args, after.CreatedAt.UTC(), after.ID.String())
	}
	statement += ` ORDER BY created_at DESC,id DESC LIMIT $` + fmt.Sprint(len(args)+1)
	args = append(args, scanLimit)
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return AcornFoxSourceRevisionPage{}, fmt.Errorf("list AcornFox source revisions: %w", err)
	}
	defer rows.Close()
	raw := make([]domain.SourceRevision, 0, scanLimit)
	for rows.Next() {
		item, err := scanAcornFoxDiscoverySource(rows)
		if err != nil {
			return AcornFoxSourceRevisionPage{}, err
		}
		raw = append(raw, item)
	}
	if err := rows.Err(); err != nil {
		return AcornFoxSourceRevisionPage{}, err
	}
	proven, err := s.provenAcornFoxDiscoverySourceIDs(ctx, applicationID, raw)
	if err != nil {
		return AcornFoxSourceRevisionPage{}, err
	}
	page := AcornFoxSourceRevisionPage{Items: make([]domain.SourceRevision, 0, limit)}
	selectedRawIndex := -1
	for rawIndex, item := range raw {
		// Historical, private, malformed, or unclaimed facts remain internal history.
		if !isAcornFoxDiscoverableSource(item) || !proven[item.ID] {
			continue
		}
		page.Items = append(page.Items, item)
		if len(page.Items) == limit {
			selectedRawIndex = rawIndex
			break
		}
	}
	if len(page.Items) == limit {
		if selectedRawIndex < len(raw)-1 || len(raw) == scanLimit {
			last := page.Items[len(page.Items)-1]
			page.NextCursor = &AcornFoxDiscoveryCursor{CreatedAt: last.CreatedAt.UTC(), ID: last.ID}
		}
		return page, nil
	}
	if len(raw) == scanLimit {
		return AcornFoxSourceRevisionPage{}, errors.New("AcornFox discovery source scan exhausted")
	}
	return page, nil
}

func scanAcornFoxDiscoverySource(row interface{ Scan(...any) error }) (domain.SourceRevision, error) {
	var item domain.SourceRevision
	var kind string
	if err := row.Scan(&item.ID, &item.ApplicationID, &kind, &item.Locator, &item.Ref, &item.Commit, &item.ContentDigest, &item.WorkspaceRef, &item.CreatedAt, &item.Immutable); err != nil {
		return domain.SourceRevision{}, err
	}
	item.Kind, item.CreatedAt = domain.SourceKind(kind), item.CreatedAt.UTC()
	return item, nil
}

func acornFoxDiscoveryScanLimit(limit int) int {
	scanLimit := limit * 20
	if scanLimit < 100 {
		scanLimit = 100
	}
	if scanLimit > 900 {
		scanLimit = 900
	}
	return scanLimit
}

// provenAcornFoxPublicSourceIDs accepts the historical application.create
// proof and the explicit provenance written atomically by current public-Git
// imports. Both reads are bounded batches, never one query per revision.
func (s *Store) provenAcornFoxPublicSourceIDs(ctx context.Context, applicationID domain.ID, candidates []domain.SourceRevision) (map[domain.ID]bool, error) {
	proven := make(map[domain.ID]bool)
	if len(candidates) == 0 {
		return proven, nil
	}
	ids, args := acornFoxDiscoverySourceIDArguments(candidates)
	query := `SELECT task.payload,operation.application_id,operation.id FROM task_leases task JOIN operations operation ON operation.id=task.operation_id WHERE operation.application_id=$1 AND operation.operation_type=$2 AND operation.target_ref=operation.application_id AND task.payload->>'kind'='application.create' AND task.payload->>'source_revision_id' IN (` + ids + `) AND octet_length(task.payload::text)<=` + fmt.Sprint(acornFoxDiscoveryTaskPayloadMaximum) + ` ORDER BY task.created_at,task.task_id LIMIT $` + fmt.Sprint(len(args)+3)
	args = append([]any{applicationID.String(), createApplicationOpType}, args...)
	args = append(args, acornFoxDiscoveryTaskRowsMaximum)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list AcornFox source provenance tasks: %w", err)
	}
	items := make([]struct {
		payload                    json.RawMessage
		applicationID, operationID domain.ID
	}, 0, acornFoxDiscoveryTaskRowsMaximum)
	totalBytes := 0
	for rows.Next() {
		var item struct {
			payload                    json.RawMessage
			applicationID, operationID domain.ID
		}
		if err := rows.Scan(&item.payload, &item.applicationID, &item.operationID); err != nil {
			_ = rows.Close()
			return nil, err
		}
		totalBytes += len(item.payload)
		if totalBytes > acornFoxDiscoveryTaskPayloadTotalMaximum {
			_ = rows.Close()
			return nil, errors.New("AcornFox source provenance payload limit exceeded")
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, item := range items {
		var payload struct {
			Kind             string    `json:"kind"`
			ApplicationID    domain.ID `json:"application_id"`
			OperationID      domain.ID `json:"operation_id"`
			SourceRevisionID domain.ID `json:"source_revision_id"`
		}
		if json.Unmarshal(item.payload, &payload) == nil && payload.Kind == createApplicationTaskTag && payload.ApplicationID == applicationID && payload.ApplicationID == item.applicationID && payload.OperationID == item.operationID {
			proven[payload.SourceRevisionID] = true
		}
	}
	placeholders := make([]string, 0, len(candidates))
	metadataArgs := []any{applicationID.String()}
	for index, candidate := range candidates {
		placeholders = append(placeholders, "$"+fmt.Sprint(index+2))
		metadataArgs = append(metadataArgs, candidate.ID.String())
	}
	metadataRows, err := s.db.QueryContext(ctx, `
		SELECT source.id FROM source_revisions source
		JOIN acornfox_source_metadata metadata ON metadata.source_revision_id=source.id
		WHERE source.application_id=$1 AND source.source_kind='git_https'
		  AND source.immutable=true AND metadata.repository_url=source.locator
		  AND source.id IN (`+strings.Join(placeholders, ",")+`)`, metadataArgs...)
	if err != nil {
		return nil, fmt.Errorf("list AcornFox explicit source provenance: %w", err)
	}
	defer metadataRows.Close()
	for metadataRows.Next() {
		var id domain.ID
		if err := metadataRows.Scan(&id); err != nil {
			return nil, err
		}
		proven[id] = true
	}
	if err := metadataRows.Err(); err != nil {
		return nil, err
	}
	return proven, nil
}

func acornFoxDiscoverySourceIDArguments(items []domain.SourceRevision) (string, []any) {
	placeholders := make([]string, 0, len(items))
	args := make([]any, 0, len(items))
	for index, item := range items {
		placeholders = append(placeholders, "$"+fmt.Sprint(index+3))
		args = append(args, item.ID.String())
	}
	return strings.Join(placeholders, ","), args
}

// Each source family has its own proof; uploaded files never acquire public-Git provenance.
func (s *Store) provenAcornFoxDiscoverySourceIDs(ctx context.Context, applicationID domain.ID, candidates []domain.SourceRevision) (map[domain.ID]bool, error) {
	gitCandidates := make([]domain.SourceRevision, 0, len(candidates))
	uploadCandidates := make([]domain.SourceRevision, 0, len(candidates))
	for _, item := range candidates {
		if item.Kind == domain.SourceGitHTTPS {
			gitCandidates = append(gitCandidates, item)
		}
		if isAcornFoxUploadedSource(item) {
			uploadCandidates = append(uploadCandidates, item)
		}
	}
	proven, err := s.provenAcornFoxPublicSourceIDs(ctx, applicationID, gitCandidates)
	if err != nil {
		return nil, err
	}
	uploads, err := s.provenAcornFoxClaimedUploadSourceIDs(ctx, applicationID, uploadCandidates)
	if err != nil {
		return nil, err
	}
	for id := range uploads {
		proven[id] = true
	}
	return proven, nil
}

func isAcornFoxUploadedSource(item domain.SourceRevision) bool {
	return item.Kind == domain.SourceUpload && item.Immutable && item.Commit == "" &&
		item.Validate() == nil && domain.RequireID(domain.ID(item.Ref), "upload id") == nil &&
		item.Locator == "upload://"+item.Ref && contracts.IsSHA256Digest(item.ContentDigest)
}

func isAcornFoxDiscoverableSource(item domain.SourceRevision) bool {
	return item.Validate() == nil && (isAcornFoxPublicHTTPSGit(item) || isAcornFoxUploadedSource(item))
}

func (s *Store) provenAcornFoxClaimedUploadSourceIDs(ctx context.Context, applicationID domain.ID, candidates []domain.SourceRevision) (map[domain.ID]bool, error) {
	proven := make(map[domain.ID]bool)
	if len(candidates) == 0 {
		return proven, nil
	}
	if len(candidates) > acornFoxDiscoveryScanLimit(100) {
		return nil, domain.ValidationError("AcornFox upload discovery candidate bound exceeded")
	}
	args := []any{applicationID.String()}
	placeholders := make([]string, 0, len(candidates))
	for _, item := range candidates {
		if !isAcornFoxUploadedSource(item) || item.ApplicationID != applicationID {
			continue
		}
		args = append(args, item.ID.String())
		placeholders = append(placeholders, "$"+fmt.Sprint(len(args)))
	}
	if len(placeholders) == 0 {
		return proven, nil
	}
	// Upload bytes and the prepared tree have different digest semantics.
	// Bind through the accepted claim and prepared-workspace event, not digest equality.
	statement := `SELECT source.id
        FROM source_uploads AS upload
        JOIN source_revisions AS source
          ON upload.claimed_source_revision_id=source.id
         AND upload.claimed_application_id=source.application_id
        WHERE upload.status='claimed' AND source.application_id=$1
          AND source.source_kind='upload' AND source.provider='upload'
          AND source.immutable=true AND source.git_commit IS NULL
          AND upload.storage_ref=('upload://' || upload.id)
          AND source.locator=upload.storage_ref AND source.source_ref=upload.id
          AND upload.content_digest ~ '^sha256:[a-f0-9]{64}$'
          AND source.content_digest ~ '^sha256:[a-f0-9]{64}$'
          AND source.workspace_lifecycle='prepared'
          AND EXISTS (SELECT 1 FROM source_workspace_events AS event
                       WHERE event.source_revision_id=source.id AND event.sequence=1
                         AND event.workspace_ref=source.workspace_ref AND event.state='prepared')
          AND source.id IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("prove AcornFox upload source: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		proven[id] = true
	}
	return proven, rows.Err()
}

func isAcornFoxPublicHTTPSGit(item domain.SourceRevision) bool {
	if item.Kind != domain.SourceGitHTTPS || !item.Immutable {
		return false
	}
	parsed, err := url.Parse(item.Locator)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && !strings.ContainsRune(item.Locator, 0)
}

// GetAcornFoxSourceRevision returns a source only when it meets the same
// public-Git or claimed-upload provenance rule as discovery. An internal source is not a
// clean API resource merely because its opaque ID was guessed or retained.
func (s *Store) GetAcornFoxSourceRevision(ctx context.Context, applicationID, sourceID domain.ID) (domain.SourceRevision, error) {
	if err := s.requireDB(); err != nil {
		return domain.SourceRevision{}, err
	}
	if err := domain.RequireID(sourceID, "AcornFox source revision id"); err != nil {
		return domain.SourceRevision{}, err
	}
	if err := s.ensureAcornFoxDiscoveryApplication(ctx, applicationID); err != nil {
		return domain.SourceRevision{}, err
	}
	item, err := s.getAcornFoxDiscoverySource(ctx, applicationID, sourceID)
	if err != nil {
		return domain.SourceRevision{}, err
	}
	if !isAcornFoxDiscoverableSource(item) {
		return domain.SourceRevision{}, ErrNotFound
	}
	proven, err := s.provenAcornFoxDiscoverySourceIDs(ctx, applicationID, []domain.SourceRevision{item})
	if err != nil {
		return domain.SourceRevision{}, err
	}
	if !proven[item.ID] {
		return domain.SourceRevision{}, ErrNotFound
	}
	return item, nil
}

func (s *Store) getAcornFoxDiscoverySource(ctx context.Context, applicationID, sourceID domain.ID) (domain.SourceRevision, error) {
	item, err := scanAcornFoxDiscoverySource(s.db.QueryRowContext(ctx, `
		SELECT id,application_id,source_kind,locator,COALESCE(source_ref,''),COALESCE(git_commit,''),content_digest,workspace_ref,created_at,immutable
		  FROM source_revisions
		 WHERE id=$1 AND application_id=$2 AND immutable=true AND (source_kind='git_https' OR (source_kind='upload' AND provider='upload'))
	`, sourceID.String(), applicationID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SourceRevision{}, ErrNotFound
	}
	if err != nil {
		return domain.SourceRevision{}, fmt.Errorf("get AcornFox source revision: %w", err)
	}
	return item, nil
}

// ListAcornFoxDeployments returns only deployments whose persisted task has
// the strict AcornFox runtime marker and matching immutable runtime identity.
func (s *Store) ListAcornFoxDeployments(ctx context.Context, applicationID domain.ID, after *AcornFoxDiscoveryCursor, limit int) (AcornFoxDeploymentPage, error) {
	if err := s.requireDB(); err != nil {
		return AcornFoxDeploymentPage{}, err
	}
	if err := validateAcornFoxDiscoveryCursor(after); err != nil {
		return AcornFoxDeploymentPage{}, err
	}
	if limit < 1 || limit > 100 {
		return AcornFoxDeploymentPage{}, domain.ValidationError("AcornFox discovery limit is invalid")
	}
	if err := s.ensureAcornFoxDiscoveryApplication(ctx, applicationID); err != nil {
		return AcornFoxDeploymentPage{}, err
	}
	scanLimit := acornFoxDiscoveryScanLimit(limit)
	statement := `
		SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,COALESCE(d.failure_reason,''),d.version,d.created_at,d.updated_at
		  FROM deployments d JOIN environments e ON e.id=d.environment_id
		 WHERE e.application_id=$1`
	args := []any{applicationID.String()}
	if after != nil {
		statement += ` AND (d.created_at,d.id)<($2,$3)`
		args = append(args, after.CreatedAt.UTC(), after.ID.String())
	}
	statement += ` ORDER BY d.created_at DESC,d.id DESC LIMIT $` + fmt.Sprint(len(args)+1)
	args = append(args, scanLimit)
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return AcornFoxDeploymentPage{}, fmt.Errorf("list AcornFox deployments: %w", err)
	}
	defer rows.Close()
	raw := make([]domain.Deployment, 0, scanLimit)
	for rows.Next() {
		item, _, err := loadM1DeploymentQuery(rows)
		if err != nil {
			return AcornFoxDeploymentPage{}, err
		}
		raw = append(raw, item)
	}
	if err := rows.Err(); err != nil {
		return AcornFoxDeploymentPage{}, err
	}
	strict, err := s.strictAcornFoxDeploymentIDs(ctx, raw)
	if err != nil {
		return AcornFoxDeploymentPage{}, err
	}
	page := AcornFoxDeploymentPage{Items: make([]domain.Deployment, 0, limit)}
	selectedRawIndex := -1
	for rawIndex, item := range raw {
		if !strict[item.ID] {
			continue
		}
		page.Items = append(page.Items, item)
		if len(page.Items) == limit {
			selectedRawIndex = rawIndex
			break
		}
	}
	if len(page.Items) == limit {
		if selectedRawIndex < len(raw)-1 || len(raw) == scanLimit {
			last := page.Items[len(page.Items)-1]
			page.NextCursor = &AcornFoxDiscoveryCursor{CreatedAt: last.CreatedAt.UTC(), ID: last.ID}
		}
		return page, nil
	}
	if len(raw) == scanLimit {
		return AcornFoxDeploymentPage{}, errors.New("AcornFox discovery deployment scan exhausted")
	}
	return page, nil
}

// GetAcornFoxDeployment returns a deployment only when it has the same strict
// persisted runtime-task proof required by delivery discovery.
func (s *Store) GetAcornFoxDeployment(ctx context.Context, applicationID, deploymentID domain.ID) (domain.Deployment, error) {
	if err := s.requireDB(); err != nil {
		return domain.Deployment{}, err
	}
	if err := domain.RequireID(deploymentID, "AcornFox deployment id"); err != nil {
		return domain.Deployment{}, err
	}
	if err := s.ensureAcornFoxDiscoveryApplication(ctx, applicationID); err != nil {
		return domain.Deployment{}, err
	}
	deployment, _, err := loadM1DeploymentQuery(s.db.QueryRowContext(ctx, `
		SELECT d.id,e.application_id,d.environment_id,d.release_id,d.state,COALESCE(d.failure_reason,''),d.version,d.created_at,d.updated_at
		  FROM deployments d JOIN environments e ON e.id=d.environment_id
		 WHERE d.id=$1 AND e.application_id=$2
	`, deploymentID.String(), applicationID.String()))
	if err != nil {
		return domain.Deployment{}, err
	}
	strict, err := s.strictAcornFoxDeploymentIDs(ctx, []domain.Deployment{deployment})
	if err != nil {
		return domain.Deployment{}, err
	}
	if !strict[deployment.ID] {
		return domain.Deployment{}, ErrNotFound
	}
	return deployment, nil
}

const (
	acornFoxDiscoveryTaskRowsPerDeployment   = 16
	acornFoxDiscoveryTaskPayloadMaximum      = 64 << 10
	acornFoxDiscoveryTaskRowsMaximum         = 16384
	acornFoxDiscoveryTaskPayloadTotalMaximum = 1 << 20
)

// strictAcornFoxDeploymentIDs batches strict-marker evidence for a bounded
// candidate page. SQL enforces a deterministic per-deployment row ceiling;
// Go closes the cursor before decoding bounded payload copies.
func (s *Store) strictAcornFoxDeploymentIDs(ctx context.Context, candidates []domain.Deployment) (map[domain.ID]bool, error) {
	strict := make(map[domain.ID]bool)
	if len(candidates) == 0 {
		return strict, nil
	}
	if len(candidates)*(acornFoxDiscoveryTaskRowsPerDeployment+1) > acornFoxDiscoveryTaskRowsMaximum {
		return nil, errors.New("AcornFox deployment provenance candidate bound exceeded")
	}
	values := make([]string, 0, len(candidates))
	args := make([]any, 0, len(candidates)*4)
	for _, candidate := range candidates {
		base := len(args) + 1
		values = append(values, "($"+fmt.Sprint(base)+",$"+fmt.Sprint(base+1)+",$"+fmt.Sprint(base+2)+",$"+fmt.Sprint(base+3)+")")
		args = append(args, candidate.ID.String(), candidate.ApplicationID.String(), candidate.EnvironmentID.String(), candidate.ReleaseID.String())
	}
	totalLimit := len(candidates) * (acornFoxDiscoveryTaskRowsPerDeployment + 1)
	query := `WITH candidates(deployment_id,application_id,environment_id,release_id) AS (VALUES ` + strings.Join(values, ",") + `)
		SELECT candidate.deployment_id,candidate.application_id,candidate.environment_id,candidate.release_id,task.payload
		FROM candidates candidate
		JOIN LATERAL (
			SELECT lease.payload FROM task_leases lease JOIN operations operation ON operation.id=lease.operation_id
			WHERE operation.deployment_id=candidate.deployment_id
			  AND operation.operation_type IN ('deploy','redeploy')
			  AND lease.payload->>'kind'='deploy'
			  AND lease.payload->'parameters'->>'acornfox_payload_type' IN ('deploy','redeploy')
			  AND octet_length(lease.payload::text)<=` + fmt.Sprint(acornFoxDiscoveryTaskPayloadMaximum) + `
			ORDER BY lease.created_at,lease.task_id LIMIT ` + fmt.Sprint(acornFoxDiscoveryTaskRowsPerDeployment+1) + `
		) task ON true ORDER BY candidate.deployment_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list AcornFox deployment provenance tasks: %w", err)
	}
	type taskEvidence struct {
		deploymentID, applicationID, environmentID, releaseID domain.ID
		payload                                               json.RawMessage
	}
	evidence := make([]taskEvidence, 0, totalLimit)
	totalBytes := 0
	for rows.Next() {
		var item taskEvidence
		if err := rows.Scan(&item.deploymentID, &item.applicationID, &item.environmentID, &item.releaseID, &item.payload); err != nil {
			_ = rows.Close()
			return nil, err
		}
		totalBytes += len(item.payload)
		if totalBytes > acornFoxDiscoveryTaskPayloadTotalMaximum {
			_ = rows.Close()
			return nil, errors.New("AcornFox deployment provenance payload limit exceeded")
		}
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	perDeployment := make(map[domain.ID]int, len(candidates))
	for _, item := range evidence {
		perDeployment[item.deploymentID]++
		if perDeployment[item.deploymentID] > acornFoxDiscoveryTaskRowsPerDeployment {
			continue
		}
		request, ok, err := decodeAcornFoxRuntimeTask(item.payload)
		if err != nil || !ok {
			continue
		}
		expected, err := contracts.AcornFoxRuntimeDeploymentID(request.Fact)
		if err == nil && expected == item.deploymentID && request.Fact.ApplicationID == item.applicationID && request.Fact.EnvironmentID == item.environmentID && request.Fact.ReleaseID == item.releaseID {
			strict[item.deploymentID] = true
		}
	}
	for deploymentID, count := range perDeployment {
		if count > acornFoxDiscoveryTaskRowsPerDeployment && !strict[deploymentID] {
			return nil, errors.New("AcornFox deployment provenance task bound exhausted")
		}
	}
	return strict, nil
}
