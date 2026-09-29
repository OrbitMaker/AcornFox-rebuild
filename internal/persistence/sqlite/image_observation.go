package sqlite

import (
	"context"
	"database/sql"
	"errors"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func (s *Store) ReadManagedImageObservationBinding(ctx context.Context, admin, deployment domain.ID) (appcontracts.ManagedImageObservationBinding, error) {
	out := appcontracts.ManagedImageObservationBinding{}
	if err := s.checkOpen(); err != nil {
		return out, err
	}
	if admin.Empty() || deployment.Empty() {
		return out, domain.ValidationError("administrator and deployment required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var enabled int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_credentials WHERE id=? AND disabled_at IS NULL`, admin.String()).Scan(&enabled); err != nil {
		return out, err
	}
	if enabled != 1 {
		return out, domain.NewError(domain.ErrUnauthorized, "administrator unavailable")
	}
	var b appcontracts.ImageLifecycleBinding
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.release_id,d.application_id,d.environment_id,d.operation_id,p.id,p.plan_digest,r.digest,d.container_id,d.image_id,e.host_port,e.container_port
 FROM image_deployments d JOIN image_releases r ON r.id=d.release_id AND r.application_id=d.application_id
 JOIN image_deploy_intents i ON i.operation_id=d.operation_id AND i.application_id=d.application_id AND i.environment_id=d.environment_id AND i.plan_id=r.plan_id AND i.plan_digest=r.plan_digest
 JOIN image_plans p ON p.id=r.plan_id AND p.plan_digest=r.plan_digest AND p.admin_id=?
 JOIN operations o ON o.id=d.operation_id AND o.application_id=d.application_id AND o.environment_id=d.environment_id AND o.state='succeeded'
 JOIN image_endpoints e ON e.deployment_id=d.id AND e.application_id=d.application_id AND e.environment_id=d.environment_id
 WHERE d.id=? AND EXISTS(SELECT 1 FROM image_artifacts a WHERE a.release_id=r.id AND a.digest=r.digest AND a.image_id=d.image_id)`, admin.String(), deployment.String()).Scan(&b.DeploymentID, &b.ReleaseID, &b.ApplicationID, &b.EnvironmentID, &b.DeployOperationID, &b.PlanID, &b.PlanDigest, &b.ManifestDigest, &b.ContainerID, &b.ImageID, &b.HostPort, &b.ContainerPort)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	b.Plan, err = readLifecyclePlanTx(ctx, tx, b, admin)
	if err != nil {
		return out, err
	}
	if b.ContainerID == "" || !validSha256Digest(b.ImageID) || !validSha256Digest(b.ManifestDigest) || !validSha256Digest(b.PlanDigest) || b.HostPort <= 0 || b.ContainerPort <= 0 {
		return out, ErrCorruptData
	}
	out.AdminID = admin
	out.Runtime = b
	return out, nil
}
