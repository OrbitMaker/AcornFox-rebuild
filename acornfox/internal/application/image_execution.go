package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

// ImageExecutionWorkerConfig configures the image task execution worker.
type ImageExecutionWorkerConfig struct {
	WorkerID             string
	PollInterval         time.Duration
	LeaseDuration        time.Duration
	MaxAttempts          int
	Client               appcontracts.ContainerExecutionClient
	BuiltContainerClient appcontracts.SourceBuiltContainerClient
	OpenBuiltArchive     func(context.Context, appcontracts.SourceBuiltArtifactFact) (io.ReadCloser, error)
	LifecycleClient      appcontracts.ContainerLifecycleClient
	LifecycleStore       appcontracts.ImageLifecycleStore
	Store                appcontracts.ImageExecutionStore
	TaskRepo             appcontracts.TaskRepository
	Clock                func() time.Time
}

// ImageExecutionWorker polls for and executes image deployment tasks under lease fencing.
type ImageExecutionWorker struct {
	cfg     ImageExecutionWorkerConfig
	done    chan struct{}
	stopped chan struct{}
	mu      sync.Mutex
	running bool
}

// NewImageExecutionWorker constructs a new image execution worker.
func NewImageExecutionWorker(cfg ImageExecutionWorkerConfig) (*ImageExecutionWorker, error) {
	if cfg.WorkerID == "" {
		return nil, domain.ValidationError("worker id is required")
	}
	if cfg.Store == nil || cfg.TaskRepo == nil || cfg.Client == nil {
		return nil, domain.ValidationError("store, task repository, and execution client are required")
	}
	if (cfg.LifecycleClient == nil) != (cfg.LifecycleStore == nil) {
		return nil, domain.ValidationError("lifecycle store and client must be configured together")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
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

	return &ImageExecutionWorker{
		cfg:     cfg,
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}, nil
}

// Start begins the execution worker loop.
func (w *ImageExecutionWorker) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	go w.run(ctx)
}

// Done returns a channel that is closed when the worker loop stops.
func (w *ImageExecutionWorker) Done() <-chan struct{} {
	return w.done
}

func (w *ImageExecutionWorker) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pollAndExecute(ctx)
		}
	}
}

// PollOnce claims and executes one pending image deployment task if available.
func (w *ImageExecutionWorker) PollOnce(ctx context.Context) (bool, error) {
	now := w.cfg.Clock().UTC()
	kinds := []string{"image.deploy"}
	if w.cfg.LifecycleStore != nil {
		kinds = append(kinds, appcontracts.ImageLifecycleTaskKind)
	}
	claimedTask, ok, err := w.cfg.TaskRepo.ClaimTask(ctx, appcontracts.ClaimTaskRequest{
		Kinds: kinds,
		Owner: w.cfg.WorkerID,
		Now:   now,
		LeasePolicy: appcontracts.LeasePolicy{
			Duration:    w.cfg.LeaseDuration,
			MaxAttempts: w.cfg.MaxAttempts,
		},
	})
	if err != nil {
		return false, fmt.Errorf("claim image task: %w", err)
	}
	if !ok {
		return false, nil
	}

	var payload struct {
		Kind string `json:"kind"`
	}
	if w.cfg.LifecycleStore != nil {
		if err := json.Unmarshal(claimedTask.Payload, &payload); err != nil {
			return true, err
		}
	}
	var execErr error
	if payload.Kind == appcontracts.ImageLifecycleTaskKind {
		execErr = w.executeLifecycleTask(ctx, claimedTask)
	} else {
		execErr = w.executeClaimedTask(ctx, claimedTask)
	}
	if execErr != nil && errors.Is(execErr, appcontracts.ErrLeaseLost) {
		return true, nil
	}
	return true, execErr
}

func (w *ImageExecutionWorker) pollAndExecute(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			handled, err := w.PollOnce(ctx)
			if err != nil {
				log.Printf("image execution worker poll error: %v", err)
				return
			}
			if !handled {
				return
			}
		}
	}
}

func (w *ImageExecutionWorker) executeClaimedTask(ctx context.Context, task appcontracts.Task) error {
	now := w.cfg.Clock().UTC()

	// 1. Begin image execution transaction: binds verified plan, release, deployment
	binding, err := w.cfg.Store.BeginImageExecution(ctx, appcontracts.BeginImageExecutionInput{
		TaskID:          task.ID,
		OperationID:     task.OperationID,
		Owner:           w.cfg.WorkerID,
		CoreGeneration:  task.CoreGeneration,
		LeaseGeneration: task.LeaseGeneration,
		Now:             now,
	})
	if err != nil {
		log.Printf("begin image execution failed for task %s: %v", task.ID, err)
		if errors.Is(err, appcontracts.ErrLeaseLost) {
			return err
		}
		failErr := w.cfg.Store.FailImageExecution(ctx, appcontracts.FailImageExecutionInput{
			TaskID:          task.ID,
			OperationID:     task.OperationID,
			Owner:           w.cfg.WorkerID,
			CoreGeneration:  task.CoreGeneration,
			LeaseGeneration: task.LeaseGeneration,
			Reason:          err.Error(),
			Now:             w.cfg.Clock().UTC(),
		})
		if failErr != nil {
			return fmt.Errorf("fail image execution after begin error: %w (begin: %v)", failErr, err)
		}
		return err
	}

	execCtx, finishExec := w.startTaskLease(ctx, task)
	// 3. Dispatch to container role execution client using execCtx
	var commitInput appcontracts.CommitImageExecutionResultInput
	var execErr error
	if binding.SourceArtifact != nil {
		execErr = w.ensureBuiltOCI(execCtx, binding)
	}
	if execErr == nil {
		commitInput, execErr = w.cfg.Client.ExecuteDeployment(execCtx, binding)
	}

	if err := finishExec(); err != nil {
		return err
	}

	if execErr != nil {
		log.Printf("container role execute deployment failed for task %s: %v", task.ID, execErr)
		isUnknown := errors.Is(execErr, appcontracts.ErrOutcomeUnknown) ||
			contracts.IsProviderOutcomeUnknown(execErr) ||
			errors.Is(execErr, context.DeadlineExceeded)

		if isUnknown {
			// Do not fail immediately; attempt read-only Observe to reconcile
			obsCtx, obsCancel := context.WithTimeout(ctx, 10*time.Second)
			obsResult, obsErr := w.cfg.Client.ObserveDeployment(obsCtx, binding.DeploymentID, task.OperationID)
			obsCancel()

			sourceReceiptMatches := binding.SourceArtifact == nil || (obsResult.ManifestDigest == binding.SourceArtifact.Image.Digest && obsResult.Artifact.StorageRef == binding.SourceArtifact.StorageRef && obsResult.Artifact.ContentDigest == binding.SourceArtifact.ArchiveSHA256 && obsResult.Artifact.SizeBytes == binding.SourceArtifact.SizeBytes)
			if obsErr == nil && sourceReceiptMatches && obsResult.Running && !obsResult.ObservedAt.IsZero() && obsResult.HostPort > 0 && obsResult.ContainerID != "" && obsResult.ImageID != "" && obsResult.ManifestDigest != "" {
				commitErr := w.cfg.Store.CommitImageExecutionResult(ctx, appcontracts.CommitImageExecutionResultInput{
					TaskID:          task.ID,
					OperationID:     task.OperationID,
					DeploymentID:    binding.DeploymentID,
					ReleaseID:       binding.ReleaseID,
					Owner:           w.cfg.WorkerID,
					CoreGeneration:  task.CoreGeneration,
					LeaseGeneration: task.LeaseGeneration,
					Now:             w.cfg.Clock().UTC(),
					ContainerID:     obsResult.ContainerID,
					ContainerName:   obsResult.ContainerName,
					ImageID:         obsResult.ImageID,
					ManifestDigest:  obsResult.ManifestDigest,
					Artifact:        obsResult.Artifact,
					HostPort:        obsResult.HostPort,
					ContainerPort:   obsResult.ContainerPort,
					ObservedAt:      obsResult.ObservedAt,
				})
				if commitErr == nil {
					log.Printf("task %s successfully reconciled from unknown state", task.ID)
					return nil
				}
			}

			// If observation cannot confirm, record unknown state and leave task ready for reclaim
			recErr := w.cfg.Store.RecordImageExecutionUnknown(ctx, appcontracts.RecordImageExecutionUnknownInput{
				TaskID:          task.ID,
				OperationID:     task.OperationID,
				DeploymentID:    binding.DeploymentID,
				Owner:           w.cfg.WorkerID,
				CoreGeneration:  task.CoreGeneration,
				LeaseGeneration: task.LeaseGeneration,
				Reason:          execErr.Error(),
				Now:             w.cfg.Clock().UTC(),
			})
			if recErr != nil {
				return fmt.Errorf("record image execution unknown failed: %w", recErr)
			}
			return nil
		}

		failErr := w.cfg.Store.FailImageExecution(ctx, appcontracts.FailImageExecutionInput{
			TaskID:          task.ID,
			OperationID:     task.OperationID,
			DeploymentID:    binding.DeploymentID,
			Owner:           w.cfg.WorkerID,
			CoreGeneration:  task.CoreGeneration,
			LeaseGeneration: task.LeaseGeneration,
			Reason:          execErr.Error(),
			Now:             w.cfg.Clock().UTC(),
		})
		if failErr != nil {
			return fmt.Errorf("fail image execution failed: %w", failErr)
		}
		return nil
	}

	// 4. Atomically commit observed facts, endpoint, and complete task under fresh fencing
	commitInput.Now = w.cfg.Clock().UTC()
	if commitErr := w.cfg.Store.CommitImageExecutionResult(ctx, commitInput); commitErr != nil {
		log.Printf("commit image execution result failed for task %s: %v", task.ID, commitErr)
		return fmt.Errorf("commit image execution result: %w", commitErr)
	}
	return nil
}

// ensureBuiltOCI performs the only source-to-container transfer under the
// existing image.deploy lease. A missing destination may be imported; an
// unreadable or corrupt destination is never replaced or sent to a registry.
func (w *ImageExecutionWorker) ensureBuiltOCI(ctx context.Context, binding appcontracts.ImageExecutionBinding) error {
	if w.cfg.BuiltContainerClient == nil || w.cfg.OpenBuiltArchive == nil || binding.SourceArtifact == nil {
		return fmt.Errorf("%w: source archive handoff unavailable", appcontracts.ErrOutcomeUnknown)
	}
	transferCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	receipt, present, err := w.cfg.BuiltContainerClient.ProbeBuiltOCI(transferCtx, binding)
	if err != nil {
		return fmt.Errorf("%w: source archive probe could not be verified", appcontracts.ErrOutcomeUnknown)
	}
	if !present {
		archive, openErr := w.cfg.OpenBuiltArchive(transferCtx, *binding.SourceArtifact)
		if openErr != nil {
			return fmt.Errorf("%w: source archive unavailable", appcontracts.ErrOutcomeUnknown)
		}
		receipt, err = w.cfg.BuiltContainerClient.ImportBuiltOCI(transferCtx, binding, archive)
		closeErr := archive.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("%w: source archive import could not be verified", appcontracts.ErrOutcomeUnknown)
		}
	}
	if receipt.Image != binding.SourceArtifact.Image || receipt.StorageRef != binding.SourceArtifact.StorageRef || receipt.ArchiveSHA256 != binding.SourceArtifact.ArchiveSHA256 || receipt.SizeBytes != binding.SourceArtifact.SizeBytes || receipt.ManifestDigest != binding.SourceArtifact.Image.Digest || receipt.ConfigDigest == "" {
		return fmt.Errorf("%w: source archive receipt differs from Core facts", appcontracts.ErrOutcomeUnknown)
	}
	return nil
}

// startTaskLease is shared by deploy and the finite lifecycle task dispatch.
// Its completion cancels and joins the renewer before any result mutation.
func (w *ImageExecutionWorker) startTaskLease(ctx context.Context, task appcontracts.Task) (context.Context, func() error) {
	return startTaskExecutionLease(ctx, task, w.cfg.TaskRepo, w.cfg.WorkerID, w.cfg.LeaseDuration, w.cfg.Clock)
}
