package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// RecordAcornFoxPublicSourceProvenanceTx records the trusted public-git ingest
// claim in the same transaction that creates its immutable source revision.
// It deliberately accepts a transaction from the source-creation owner so a
// committed source can never be reported public after a separate write fails.
func (s *Store) RecordAcornFoxPublicSourceProvenanceTx(ctx context.Context, tx *sql.Tx, provenance contracts.AcornFoxPublicSourceProvenance) error {
	if tx == nil {
		return fmt.Errorf("source metadata transaction is required")
	}
	if err := provenance.Validate(); err != nil {
		return err
	}
	var sourceKind, locator string
	err := tx.QueryRowContext(ctx, `SELECT source_kind,locator FROM source_revisions WHERE id=$1 FOR SHARE`, provenance.SourceRevisionID.String()).Scan(&sourceKind, &locator)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("load accepted public source revision: %w", err)
	}
	if sourceKind != string(domain.SourceGitHTTPS) || locator != provenance.RepositoryURL {
		return domain.ValidationError("public source provenance does not match accepted HTTPS source")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO acornfox_source_metadata(source_revision_id,repository_url) VALUES($1,$2) ON CONFLICT(source_revision_id) DO NOTHING`, provenance.SourceRevisionID.String(), provenance.RepositoryURL)
	if err != nil {
		return fmt.Errorf("record public source provenance: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect public source provenance write: %w", err)
	}
	if inserted == 1 {
		return nil
	}
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT repository_url FROM acornfox_source_metadata WHERE source_revision_id=$1`, provenance.SourceRevisionID.String()).Scan(&existing); err != nil {
		return fmt.Errorf("read public source provenance replay: %w", err)
	}
	if existing != provenance.RepositoryURL {
		return ErrIdempotencyConflict
	}
	return nil
}

// GetAcornFoxSourceMetadata reads source metadata without selecting a source
// locator. An existing source with no trusted provenance is an expected,
// non-leaking unavailable result; a foreign source is not found.
func (s *Store) GetAcornFoxSourceMetadata(ctx context.Context, applicationID, sourceRevisionID domain.ID) (contracts.AcornFoxSourceMetadata, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxSourceMetadata{}, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return contracts.AcornFoxSourceMetadata{}, err
	}
	if err := domain.RequireID(sourceRevisionID, "source revision id"); err != nil {
		return contracts.AcornFoxSourceMetadata{}, err
	}
	var repositoryURL sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT metadata.repository_url
		  FROM source_revisions source
		  LEFT JOIN acornfox_source_metadata metadata ON metadata.source_revision_id=source.id
		 WHERE source.id=$1 AND source.application_id=$2 AND source.source_kind IS NOT NULL
	`, sourceRevisionID.String(), applicationID.String()).Scan(&repositoryURL)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AcornFoxSourceMetadata{}, ErrNotFound
	}
	if err != nil {
		return contracts.AcornFoxSourceMetadata{}, fmt.Errorf("get AcornFox source metadata: %w", err)
	}
	response := contracts.AcornFoxSourceMetadata{SourceRevisionID: sourceRevisionID, Availability: contracts.AcornFoxUnavailable}
	if !repositoryURL.Valid {
		return response, nil
	}
	canonical, err := contracts.CanonicalAcornFoxPublicRepositoryURL(repositoryURL.String)
	if err != nil || canonical != repositoryURL.String {
		return response, nil
	}
	response.Availability, response.RepositoryURL = contracts.AcornFoxAvailable, canonical
	return response, nil
}

// GetAcornFoxDeploymentSource follows the immutable deployment→release→
// definition→source relationship, and requires every release artifact's
// succeeded build plan to point to that same source. It never falls back to a
// newer application source when historical facts are absent or ambiguous.
func (s *Store) GetAcornFoxDeploymentSource(ctx context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxDeploymentSource, error) {
	if err := s.requireDB(); err != nil {
		return contracts.AcornFoxDeploymentSource{}, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return contracts.AcornFoxDeploymentSource{}, err
	}
	if err := domain.RequireID(deploymentID, "deployment id"); err != nil {
		return contracts.AcornFoxDeploymentSource{}, err
	}
	response := contracts.AcornFoxDeploymentSource{DeploymentID: deploymentID, Availability: contracts.AcornFoxUnavailable}
	var releaseID domain.ID
	err := s.db.QueryRowContext(ctx, `
		SELECT deployment.release_id
		  FROM deployments deployment
		  JOIN environments environment ON environment.id=deployment.environment_id
		 WHERE deployment.id=$1 AND environment.application_id=$2
	`, deploymentID.String(), applicationID.String()).Scan(&releaseID)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AcornFoxDeploymentSource{}, ErrNotFound
	}
	if err != nil {
		return contracts.AcornFoxDeploymentSource{}, fmt.Errorf("load AcornFox deployment owner: %w", err)
	}

	var sourceID, commit, ref string
	var repositoryURL sql.NullString
	err = s.db.QueryRowContext(ctx, `
		SELECT definition.source_revision_id, source.git_commit, COALESCE(source.source_ref,''), metadata.repository_url
		  FROM releases release
		  JOIN delivery_definitions definition ON definition.id=release.definition_id
		  JOIN source_revisions source ON source.id=definition.source_revision_id
		  LEFT JOIN acornfox_source_metadata metadata ON metadata.source_revision_id=source.id
		 WHERE release.id=$1
		   AND release.application_id=$2
		   AND definition.application_id=$2
		   AND source.application_id=$2
		   AND source.source_kind='git_https'
		   AND EXISTS (
		       SELECT 1
		         FROM release_artifacts release_artifact
		         JOIN artifacts artifact ON artifact.id=release_artifact.artifact_id
		         JOIN builds build ON build.id=artifact.build_id AND build.state='succeeded'
		         JOIN build_plans plan ON plan.id=build.plan_id
		        WHERE release_artifact.release_id=release.id
		          AND plan.source_revision_id=definition.source_revision_id
		   )
		   AND NOT EXISTS (
		       SELECT 1
		         FROM release_artifacts release_artifact
		         LEFT JOIN artifacts artifact ON artifact.id=release_artifact.artifact_id
		         LEFT JOIN builds build ON build.id=artifact.build_id
		         LEFT JOIN build_plans plan ON plan.id=build.plan_id
		        WHERE release_artifact.release_id=release.id
		          AND (build.state IS DISTINCT FROM 'succeeded'
		               OR build.artifact_id IS DISTINCT FROM artifact.id
		               OR plan.source_revision_id IS DISTINCT FROM definition.source_revision_id)
		   )
	`, releaseID.String(), applicationID.String()).Scan(&sourceID, &commit, &ref, &repositoryURL)
	if errors.Is(err, sql.ErrNoRows) {
		return response, nil
	}
	if err != nil {
		return contracts.AcornFoxDeploymentSource{}, fmt.Errorf("get AcornFox deployment source: %w", err)
	}
	if !repositoryURL.Valid {
		return response, nil
	}
	canonical, err := contracts.CanonicalAcornFoxPublicRepositoryURL(repositoryURL.String)
	if err != nil || canonical != repositoryURL.String {
		return response, nil
	}
	candidate := contracts.AcornFoxDeploymentSource{DeploymentID: deploymentID, Availability: contracts.AcornFoxAvailable, SourceRevisionID: domain.ID(sourceID), Commit: commit, Ref: ref, RepositoryURL: canonical}
	if err := candidate.Validate(); err != nil {
		return response, nil
	}
	return candidate, nil
}
