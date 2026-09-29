package contracts

import (
	"context"
	"github.com/open-card/open-card/internal/packprotocol"
	"time"
)

type PackInstallIntent struct{ PackID, Version, OS, Arch, IdempotencyKey string }
type PlanPackInstallRecord struct {
	Intent    PackInstallIntent
	Selection packprotocol.VerifiedPackSelection
	Audit     AuditContext
}
type PlanPackInstallResult struct {
	PackID, Version, OperationID, TaskID, ManifestSHA256, ArtifactSHA256, PlanSHA256, State string
	CatalogSequence                                                                         int64
	Event                                                                                   PackEvent
}
type PackEvent struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	OperationID   string    `json:"operation_id"`
	PackID        string    `json:"pack_id"`
	Sequence      uint64    `json:"sequence"`
	OccurredAt    time.Time `json:"occurred_at"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
}
type PackRecord struct {
	PackID, DesiredVersion, ManifestSHA256, ArtifactSHA256, CatalogSHA256, State, InstallationBinding string
	CatalogSequence, Revision                                                                         int64
}
type PackIntentRecord struct{ OperationID, PackID, Version, PlanSHA256, Phase string }
type PackRepository interface {
	InstallationBinding(context.Context) (string, error)
	PreflightPackInstall(context.Context, PackInstallIntent) (PlanPackInstallResult, bool, error)
	PlanPackInstall(context.Context, PlanPackInstallRecord) (PlanPackInstallResult, error)
	GetPack(context.Context, string) (PackRecord, error)
	GetPackIntent(context.Context, string) (PackIntentRecord, error)
	PackLifecycleRepository
}
