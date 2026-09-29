package sqlite

import (
	"context"
	"database/sql"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// ListActiveManagedImageMetricTargets enumerates only the one enabled admin's
// successfully deployed, still-owned Native image targets. The subsequent
// Container read rechecks each full plan/target binding; this query supplies no
// Docker identifier to the reader.
func (s *Store) ListActiveManagedImageMetricTargets(ctx context.Context, limit int) (appcontracts.ImageMetricsTargetSelection, error) {
	out := appcontracts.ImageMetricsTargetSelection{}
	if err := s.checkOpen(); err != nil {
		return out, err
	}
	if limit < 1 || limit > appcontracts.ImageMetricsHistoryObjects {
		return out, domain.ValidationError("invalid managed metrics target limit")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT a.id,d.id
 FROM admin_credentials a
 JOIN image_plans p ON p.admin_id=a.id
 JOIN image_releases r ON r.plan_id=p.id AND r.plan_digest=p.plan_digest
 JOIN image_deployments d ON d.release_id=r.id AND d.application_id=r.application_id AND d.status IN ('running','stopped')
 JOIN image_deploy_intents i ON i.operation_id=d.operation_id AND i.application_id=d.application_id AND i.environment_id=d.environment_id AND i.plan_id=p.id AND i.plan_digest=p.plan_digest
 JOIN operations o ON o.id=d.operation_id AND o.application_id=d.application_id AND o.environment_id=d.environment_id AND o.state='succeeded'
 WHERE a.disabled_at IS NULL AND length(a.id) BETWEEN 1 AND 128 AND length(d.id) BETWEEN 1 AND 128
   AND d.container_id IS NOT NULL AND d.container_id<>'' AND d.image_id IS NOT NULL AND d.image_id<>''
   AND EXISTS(SELECT 1 FROM image_endpoints e WHERE e.deployment_id=d.id AND e.application_id=d.application_id AND e.environment_id=d.environment_id)
   AND EXISTS(SELECT 1 FROM image_artifacts artifact WHERE artifact.release_id=r.id AND artifact.digest=r.digest AND artifact.image_id=d.image_id)
 ORDER BY d.updated_at DESC,d.id ASC LIMIT ?`, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Targets = make([]appcontracts.ImageMetricsRequest, 0, limit)
	for rows.Next() {
		var admin, deployment domain.ID
		if err := rows.Scan(&admin, &deployment); err != nil {
			return appcontracts.ImageMetricsTargetSelection{}, err
		}
		if len(out.Targets) == limit {
			out.Limited = true
			break
		}
		out.Targets = append(out.Targets, appcontracts.ImageMetricsRequest{AdminID: admin, DeploymentID: deployment})
	}
	if err := rows.Err(); err != nil {
		return appcontracts.ImageMetricsTargetSelection{}, err
	}
	if err := rows.Close(); err != nil {
		return appcontracts.ImageMetricsTargetSelection{}, err
	}
	if err := tx.Commit(); err != nil {
		return appcontracts.ImageMetricsTargetSelection{}, err
	}
	return out, nil
}
