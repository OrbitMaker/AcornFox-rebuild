package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/sourcebuildexecution"
)

// SourceBuildExecutionWorker consumes only Core-created prepare/build intents.
// Registering its PollOnce loop in Core and an authenticated Native RPC client
// remain explicit composition steps; cancel/release have no durable intent yet.
type SourceBuildExecutionWorkerConfig struct {
	WorkerID      string
	LeaseDuration time.Duration
	MaxAttempts   int
	Store         appcontracts.SourceBuildFactsStore
	TaskRepo      appcontracts.TaskRepository
	Client        appcontracts.SourceBuildExecutionClient
	Clock         func() time.Time
}
type SourceBuildExecutionWorker struct {
	cfg       SourceBuildExecutionWorkerConfig
	authority *CoreSourceBuildAuthority
}

func NewSourceBuildExecutionWorker(cfg SourceBuildExecutionWorkerConfig) (*SourceBuildExecutionWorker, error) {
	if cfg.WorkerID == "" || cfg.Store == nil || cfg.TaskRepo == nil || cfg.Client == nil {
		return nil, domain.ValidationError("source-build worker requires owner, durable store, tasks and authenticated client")
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = 2 * time.Minute
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	authority, err := NewCoreSourceBuildAuthority(cfg.Store)
	if err != nil {
		return nil, err
	}
	return &SourceBuildExecutionWorker{cfg: cfg, authority: authority}, nil
}
func (w *SourceBuildExecutionWorker) PollOnce(ctx context.Context) (bool, error) {
	task, ok, err := w.cfg.TaskRepo.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{"source.prepare", "source.build"}, Owner: w.cfg.WorkerID, Now: w.cfg.Clock().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: w.cfg.LeaseDuration, MaxAttempts: w.cfg.MaxAttempts}})
	if err != nil || !ok {
		return ok, err
	}
	var payload struct {
		Kind          string    `json:"kind"`
		ApplicationID domain.ID `json:"application_id"`
		IntentID      domain.ID `json:"intent_id"`
	}
	if err := json.Unmarshal(task.Payload, &payload); err != nil || payload.ApplicationID.Empty() || payload.IntentID.Empty() || task.CoreGeneration <= 0 || task.LeaseGeneration <= 0 {
		return true, domain.ValidationError("invalid persisted source-build task")
	}
	var stage appcontracts.SourceBuildStage
	switch payload.Kind {
	case "source.prepare":
		stage = appcontracts.SourceBuildPrepare
	case "source.build":
		stage = appcontracts.SourceBuildBuild
	default:
		return true, domain.ValidationError("unsupported source-build task")
	}
	binding := appcontracts.SourceBuildBinding{TaskID: task.ID, OperationID: task.OperationID, ApplicationID: payload.ApplicationID, Owner: w.cfg.WorkerID, CoreGeneration: uint64(task.CoreGeneration), LeaseGeneration: uint64(task.LeaseGeneration)}
	execCtx, finishLease := startTaskExecutionLease(ctx, task, w.cfg.TaskRepo, w.cfg.WorkerID, w.cfg.LeaseDuration, w.cfg.Clock)
	command, err := w.authority.ComposeSourceBuildStage(execCtx, appcontracts.BeginSourceBuildStageInput{Binding: binding, Stage: stage, Now: w.cfg.Clock().UTC()})
	if err != nil {
		_ = finishLease()
		return true, err
	} // includes durable unknown barrier: never redispatch.
	raw, err := json.Marshal(command)
	if err != nil {
		_ = finishLease()
		return true, err
	}
	sha, err := sourcebuildexecution.SourceBuildCommandDigest(command)
	if err != nil {
		_ = finishLease()
		return true, err
	}
	receipt, executeErr := w.cfg.Client.ExecuteSourceBuild(execCtx, raw)
	leaseErr := finishLease()
	if leaseErr != nil {
		return true, leaseErr
	} // stale worker cannot mutate Core facts.
	if executeErr != nil {
		return true, w.unknown(ctx, binding, stage, executeErr)
	}
	if receipt.Binding != binding || receipt.Stage != stage || receipt.CommandSHA256 != sha {
		return true, w.unknown(ctx, binding, stage, sourcebuildexecution.ErrBinding)
	}
	now := w.cfg.Clock().UTC()
	switch stage {
	case appcontracts.SourceBuildPrepare:
		if receipt.Prepared == nil || receipt.Built != nil || receipt.Prepared.Binding != binding || receipt.Prepared.CommandSHA256 != sha {
			return true, w.unknown(ctx, binding, stage, sourcebuildexecution.ErrBinding)
		}
		result := *receipt.Prepared
		result.Now = now
		err = w.cfg.Store.CommitPreparedSource(ctx, result)
	case appcontracts.SourceBuildBuild:
		if receipt.Built == nil || receipt.Prepared != nil || receipt.Built.Binding != binding || receipt.Built.CommandSHA256 != sha {
			return true, w.unknown(ctx, binding, stage, sourcebuildexecution.ErrBinding)
		}
		result := *receipt.Built
		result.Now = now
		err = w.cfg.Store.CommitSourceBuildOutput(ctx, result)
	}
	if err != nil && !errors.Is(err, appcontracts.ErrLeaseLost) {
		return true, w.unknown(ctx, binding, stage, err)
	}
	return true, err
}
func (w *SourceBuildExecutionWorker) unknown(ctx context.Context, binding appcontracts.SourceBuildBinding, stage appcontracts.SourceBuildStage, cause error) error {
	if err := w.cfg.Store.RecordSourceBuildUnknown(ctx, binding, stage, "source-build execution outcome requires reconciliation", w.cfg.Clock().UTC()); err != nil {
		return fmt.Errorf("persist source-build unknown: %w", err)
	}
	return fmt.Errorf("source-build execution outcome is unknown: %w", cause)
}
