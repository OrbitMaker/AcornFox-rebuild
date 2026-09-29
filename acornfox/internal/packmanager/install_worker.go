package packmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/packprotocol"
)

type WorkerStore interface {
	contracts.TaskRepository
	contracts.PackRepository
	contracts.PackExecutionRepository
}

type InstallWorkerConfig struct {
	WorkerID         string
	PollInterval     time.Duration
	LeaseDuration    time.Duration
	StagingDir       string
	PublishedDir     string
	StateDir         string
	RunDir           string
	CoreUID          uint32
	CoreGID          uint32
	CoreGeneration   int64
	HelperSocketPath string
	Policies         map[string]packprotocol.VerificationPolicy
}

type helperEffectClient interface {
	RegisterCore(ctx context.Context, req hosthelper.RegisterCoreRequest) (hosthelper.RegisterCoreResponse, error)
	PrepareDirs(ctx context.Context, req hosthelper.PrepareDirsRequest) (hosthelper.PrepareDirsResponse, error)
	PublishPack(ctx context.Context, req hosthelper.PublishPackRequest) (hosthelper.PublishPackResponse, error)
	StartPack(ctx context.Context, req hosthelper.StartPackRequest) (hosthelper.StartPackResponse, error)
	ObservePack(ctx context.Context, req hosthelper.ObservePackRequest) (hosthelper.ObservePackResponse, error)
	StopPending(ctx context.Context, req hosthelper.StopPendingRequest) (hosthelper.StopPendingResponse, error)
	AbortPending(ctx context.Context, req hosthelper.AbortPendingRequest) (hosthelper.AbortPendingResponse, error)
	SwitchCurrent(ctx context.Context, req hosthelper.SwitchCurrentRequest) (hosthelper.SwitchCurrentResponse, error)
}

type InstallWorker struct {
	store          WorkerStore
	helper         helperEffectClient
	dispatcher     *ProtocolDispatcher
	cfg            InstallWorkerConfig
	done           chan struct{}
	stopOnce       sync.Once
	ctx            context.Context
	cancel         context.CancelFunc
	registered     bool
	lastVerifiedAt time.Time
	regMu          sync.RWMutex
	observerCursor string
	wg             sync.WaitGroup
}

func NewInstallWorker(store WorkerStore, cfg InstallWorkerConfig) (*InstallWorker, error) {
	if cfg.WorkerID == "" {
		cfg.WorkerID = "core-install-worker"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 200 * time.Millisecond
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = 2 * time.Minute
	}
	if cfg.HelperSocketPath == "" {
		cfg.HelperSocketPath = hosthelper.DefaultHelperSocketPath
	}

	helperClient := hosthelper.NewClient(cfg.HelperSocketPath, 15*time.Second)
	dispatcher := NewProtocolDispatcher(10 * time.Second)

	return &InstallWorker{
		store:      store,
		helper:     helperClient,
		dispatcher: dispatcher,
		cfg:        cfg,
		done:       make(chan struct{}),
	}, nil
}

// newInstallWorkerWithHelper is a package-internal constructor for tests using a spy helper.
func newInstallWorkerWithHelper(store WorkerStore, cfg InstallWorkerConfig, helper helperEffectClient) (*InstallWorker, error) {
	w, err := NewInstallWorker(store, cfg)
	if err != nil {
		return nil, err
	}
	if helper != nil {
		w.helper = helper
	}
	w.setRegistered(true)
	return w, nil
}

func (w *InstallWorker) IsAvailable() bool {
	w.regMu.RLock()
	defer w.regMu.RUnlock()
	if !w.registered {
		return false
	}
	age := time.Since(w.lastVerifiedAt)
	if w.lastVerifiedAt.IsZero() || age < 0 || age > 30*time.Second {
		return false
	}
	return true
}

func (w *InstallWorker) setRegistered(reg bool) {
	w.regMu.Lock()
	defer w.regMu.Unlock()
	w.registered = reg
	if reg {
		w.lastVerifiedAt = time.Now().UTC()
	}
}

func (w *InstallWorker) updateVerifiedAt() {
	w.regMu.Lock()
	defer w.regMu.Unlock()
	w.lastVerifiedAt = time.Now().UTC()
}

func (w *InstallWorker) Start(parentCtx context.Context) {
	w.ctx, w.cancel = context.WithCancel(parentCtx)
	w.wg.Add(3)
	go w.regLoop()
	go w.claimLoop()
	go w.observerLoop()
	go func() {
		w.wg.Wait()
		close(w.done)
	}()
}

func (w *InstallWorker) Done() <-chan struct{} {
	return w.done
}

func (w *InstallWorker) Stop() {
	w.stopOnce.Do(func() {
		if w.cancel != nil {
			w.cancel()
		}
	})
}

func (w *InstallWorker) regLoop() {
	defer w.wg.Done()
	regTicker := time.NewTicker(2 * time.Second)
	defer regTicker.Stop()

	w.tryRegisterHelper()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-regTicker.C:
			w.tryRegisterHelper()
		}
	}
}

func (w *InstallWorker) claimLoop() {
	defer w.wg.Done()
	pollTicker := time.NewTicker(w.cfg.PollInterval)
	defer pollTicker.Stop()

	reconcileTicker := time.NewTicker(3 * time.Second)
	defer reconcileTicker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-reconcileTicker.C:
			w.tryReconcileWaitingOperation(w.ctx)
		case <-pollTicker.C:
			w.pollOnce()
		}
	}
}

func (w *InstallWorker) tryReconcileWaitingOperation(ctx context.Context) {
	if !w.IsAvailable() {
		return
	}
	waitOps, err := w.store.ListWaitingOperations(ctx, 4)
	if err != nil || len(waitOps) == 0 {
		return
	}

	binding, err := w.store.InstallationBinding(ctx)
	if err != nil {
		return
	}

	workerAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   w.cfg.WorkerID,
		Reason:    "waiting reconciliation",
	}

	for _, op := range waitOps {
		opID := op.OperationID

		mat, err := w.store.GetPackTrustMaterial(ctx, opID)
		if err != nil {
			continue
		}

		var env packprotocol.CatalogEnvelope
		if err := json.Unmarshal(mat.CatalogEnvelope, &env); err != nil {
			continue
		}
		rawPay, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
		if err != nil {
			continue
		}
		var catPay packprotocol.CatalogPayload
		if err := json.Unmarshal(rawPay, &catPay); err != nil {
			continue
		}

		policy, ok := w.cfg.Policies[catPay.Publisher]
		if !ok {
			continue
		}
		policy.Now = time.Now().UTC()
		policy.InstallationBinding = binding
		verifiedSelection, err := packprotocol.VerifySelection(mat.CatalogEnvelope, mat.ManifestBytes, policy)
		if err != nil {
			continue
		}

		var jnlRev int64 = 0
		var jnlPhase string = ""
		var artID string = ""
		jnl, jErr := w.store.GetActivationJournal(ctx, opID)
		if jErr == nil && jnl.JournalID != "" {
			jnlRev = jnl.Revision
			jnlPhase = jnl.Phase
			artID = jnl.ArtifactReceiptID
		}

		obsResp, err := w.helper.ObservePack(ctx, hosthelper.ObservePackRequest{
			PackID:      op.PackID,
			Version:     op.Version,
			OperationID: opID,
		})
		if err != nil || obsResp.CancellationSnapshot == nil {
			continue
		}
		snap := obsResp.CancellationSnapshot
		obsAge := time.Since(snap.ObservedAt)
		if snap.ObservedAt.IsZero() || obsAge < 0 || obsAge > time.Minute {
			continue
		}
		if snap.OperationID != opID || snap.PackID != op.PackID || snap.Version != op.Version {
			continue
		}

		var obsSnapshot *contracts.PackObservedSnapshot
		if jnlRev > 0 {
			obsSnapshot = &contracts.PackObservedSnapshot{
				OperationID:          snap.OperationID,
				PackID:               snap.PackID,
				Version:              snap.Version,
				MaxOperationSequence: snap.MaxOperationSequence,
				ObservedStopped:      snap.ObservedStopped,
				ObservedAt:           snap.ObservedAt,
				UID:                  snap.UID,
			}
			if snap.PublishEffect != nil {
				obsSnapshot.PublishEffect = &contracts.PackObservedEffect{
					ActionID:        snap.PublishEffect.ActionID,
					OperationID:     snap.PublishEffect.OperationID,
					PackID:          snap.PublishEffect.PackID,
					Version:         snap.PublishEffect.Version,
					Action:          snap.PublishEffect.Action,
					Status:          snap.PublishEffect.Status,
					CoreGeneration:  snap.PublishEffect.CoreGeneration,
					LeaseGeneration: snap.PublishEffect.LeaseGeneration,
					Sequence:        snap.PublishEffect.Sequence,
					RequestDigest:   snap.PublishEffect.RequestDigest,
					ExecutablePath:  snap.PublishEffect.ExecutablePath,
					ExecutableSHA:   snap.PublishEffect.ExecutableSHA,
				}
			}
			if snap.StartEffect != nil {
				obsSnapshot.StartEffect = &contracts.PackObservedEffect{
					ActionID:         snap.StartEffect.ActionID,
					OperationID:      snap.StartEffect.OperationID,
					PackID:           snap.StartEffect.PackID,
					Version:          snap.StartEffect.Version,
					Action:           snap.StartEffect.Action,
					Status:           snap.StartEffect.Status,
					CoreGeneration:   snap.StartEffect.CoreGeneration,
					LeaseGeneration:  snap.StartEffect.LeaseGeneration,
					Sequence:         snap.StartEffect.Sequence,
					RequestDigest:    snap.StartEffect.RequestDigest,
					InstanceID:       snap.StartEffect.InstanceID,
					MainPID:          snap.StartEffect.MainPID,
					ProcessStartTime: snap.StartEffect.ProcessStartTime,
					SocketPath:       snap.StartEffect.SocketPath,
					ExecutablePath:   snap.StartEffect.ExecutablePath,
					ExecutableSHA:    snap.StartEffect.ExecutableSHA,
				}
			}
			if snap.StopEffect != nil {
				obsSnapshot.StopEffect = &contracts.PackObservedEffect{
					ActionID:        snap.StopEffect.ActionID,
					OperationID:     snap.StopEffect.OperationID,
					PackID:          snap.StopEffect.PackID,
					Version:         snap.StopEffect.Version,
					Action:          snap.StopEffect.Action,
					Status:          snap.StopEffect.Status,
					CoreGeneration:  snap.StopEffect.CoreGeneration,
					LeaseGeneration: snap.StopEffect.LeaseGeneration,
					Sequence:        snap.StopEffect.Sequence,
					RequestDigest:   snap.StopEffect.RequestDigest,
				}
			}
			if snap.SwitchEffect != nil {
				obsSnapshot.SwitchEffect = &contracts.PackObservedEffect{
					ActionID:        snap.SwitchEffect.ActionID,
					OperationID:     snap.SwitchEffect.OperationID,
					PackID:          snap.SwitchEffect.PackID,
					Version:         snap.SwitchEffect.Version,
					Action:          snap.SwitchEffect.Action,
					Status:          snap.SwitchEffect.Status,
					CoreGeneration:  snap.SwitchEffect.CoreGeneration,
					LeaseGeneration: snap.SwitchEffect.LeaseGeneration,
					Sequence:        snap.SwitchEffect.Sequence,
					RequestDigest:   snap.SwitchEffect.RequestDigest,
					CurrentTarget:   snap.SwitchEffect.CurrentTarget,
				}
			}
			if snap.AbortEffect != nil {
				obsSnapshot.AbortEffect = &contracts.PackObservedEffect{
					ActionID:    snap.AbortEffect.ActionID,
					OperationID: snap.AbortEffect.OperationID,
					PackID:      snap.AbortEffect.PackID,
					Version:     snap.AbortEffect.Version,
					Status:      snap.AbortEffect.Status,
				}
			}
		}

		if rErr := w.store.ResumePackInstall(ctx, contracts.ResumePackInstallRequest{
			OperationID:                 opID,
			ExpectedOperationVersion:    op.OperationVersion,
			TaskID:                      op.TaskID,
			ExpectedTaskAttempt:         op.TaskAttempt,
			ExpectedTaskCoreGeneration:  op.TaskCoreGeneration,
			ExpectedTaskLeaseGeneration: op.TaskLeaseGeneration,
			PackID:                      op.PackID,
			Version:                     op.Version,
			PlanSHA256:                  op.PlanSHA256,
			Selection:                   verifiedSelection,
			ExpectedAuthoritySequence:   mat.AuthoritySequence,
			ArtifactReceiptID:           artID,
			ExpectedJournalRevision:     jnlRev,
			ExpectedPhase:               jnlPhase,
			ObservedEffects:             obsSnapshot,
			CoreGeneration:              w.cfg.CoreGeneration,
			Audit:                       workerAudit,
		}); rErr != nil {
			log.Printf("install worker: reconcile waiting operation %s skipped/held: %v", opID, rErr)
		} else {
			log.Printf("install worker: successfully reconciled and resumed waiting operation %s to pending", opID)
		}
	}
}

func (w *InstallWorker) observerLoop() {
	defer w.wg.Done()
	obsTicker := time.NewTicker(2 * time.Second)
	defer obsTicker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-obsTicker.C:
			w.observeActiveRuntimesOnce()
		}
	}
}

func (w *InstallWorker) tryRegisterHelper() {
	if w.ctx == nil {
		return
	}
	binding, err := w.store.InstallationBinding(w.ctx)
	if err != nil {
		return
	}
	regCtx, cancel := context.WithTimeout(w.ctx, 2*time.Second)
	defer cancel()

	resp, err := w.helper.RegisterCore(regCtx, hosthelper.RegisterCoreRequest{
		Registration: hosthelper.CoreRegistration{
			CorePID:             int32(os.Getpid()),
			CoreUID:             w.cfg.CoreUID,
			InstallationBinding: binding,
			CoreGeneration:      w.cfg.CoreGeneration,
		},
	})
	if err == nil && resp.Registered {
		w.setRegistered(true)
	} else {
		w.regMu.Lock()
		w.registered = false
		w.regMu.Unlock()
	}
}

func (w *InstallWorker) failInstall(
	ctx context.Context,
	task contracts.Task,
	opID string,
	expectedRevision int64,
	classification string,
	reason string,
	audit contracts.AuditContext,
) error {
	return w.store.FailPackInstall(ctx, contracts.FailPackInstallRecord{
		TaskID:                  task.ID.String(),
		OperationID:             opID,
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		ExpectedJournalRevision: expectedRevision,
		Classification:          classification,
		Reason:                  reason,
		Audit:                   audit,
	})
}

func (w *InstallWorker) pollOnce() {
	if !w.IsAvailable() {
		return
	}

	now := time.Now().UTC()
	claimedTask, claimed, err := w.store.ClaimTask(w.ctx, contracts.ClaimTaskRequest{
		Owner:                  w.cfg.WorkerID,
		Kinds:                  []string{"core.pack.install"},
		AllowedOperationStates: []string{"pending", "leased", "running", "cancelling"},
		Now:                    now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    w.cfg.LeaseDuration,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		return
	}

	if err := w.executeTask(w.ctx, claimedTask); err != nil {
		log.Printf("install worker: execution completed with error for task %s (op %s): %v",
			claimedTask.ID, claimedTask.OperationID, err)
	}
}

func (w *InstallWorker) checkAndRenewLease(ctx context.Context, task *contracts.Task) error {
	if task.LeaseUntil == nil {
		return errors.New("claimed task has nil lease deadline; rejected")
	}
	if time.Until(*task.LeaseUntil) < 30*time.Second {
		now := time.Now().UTC()
		renewReq := contracts.TaskMutationRequest{
			TaskID:          task.ID,
			CoreGeneration:  task.CoreGeneration,
			LeaseGeneration: task.LeaseGeneration,
			Owner:           task.LeaseOwner,
			Now:             now,
			LeasePolicy: contracts.LeasePolicy{
				Duration:    w.cfg.LeaseDuration,
				MaxAttempts: 3,
			},
		}
		if err := w.store.RenewTask(ctx, renewReq); err != nil {
			return fmt.Errorf("renew task lease failed: %w", err)
		}
		updated, err := w.store.GetTask(ctx, task.ID)
		if err != nil {
			return fmt.Errorf("get renewed task failed: %w", err)
		}
		if updated.State == contracts.TaskCancelled {
			return errors.New("task lease cancelled during renewal")
		}
		// Preserve original identity and caller tokens; only adopt updated lease deadline
		if updated.ID != task.ID || updated.OperationID != task.OperationID ||
			updated.CoreGeneration != task.CoreGeneration || updated.LeaseGeneration != task.LeaseGeneration ||
			updated.LeaseOwner != task.LeaseOwner {
			return errors.New("renewed task identity or caller tokens mismatch")
		}
		task.LeaseUntil = updated.LeaseUntil
	}
	return nil
}

func (w *InstallWorker) executeTask(ctx context.Context, task contracts.Task) error {
	if ctx == nil {
		if w.ctx != nil {
			ctx = w.ctx
		} else {
			ctx = context.Background()
		}
	}
	opID := task.OperationID.String()

	workerAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   w.cfg.WorkerID,
		Reason:    "pack activation execution",
	}

	// -1. Read immutable activation receipt first: if already committed, idempotent replay finishes cleanly
	existingActRcpt, actRcptErr := w.store.GetActivationReceipt(ctx, opID)
	if actRcptErr == nil && existingActRcpt.ReceiptID != "" {
		log.Printf("install worker: operation %s already has activation receipt %s; idempotent replay complete", opID, existingActRcpt.ReceiptID)
		return nil
	}
	if actRcptErr != nil && !errors.Is(actRcptErr, contracts.ErrNotFound) {
		failErr := w.failInstall(ctx, task, opID, 0, "waiting_reconcile", "get activation receipt unknown error: "+actRcptErr.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, actRcptErr)
		}
		return fmt.Errorf("get activation receipt: %w", actRcptErr)
	}

	// 0. Resolve persisted install intent early so cancellation is caught before any trust/manifest failure
	intent, intentErr := w.store.GetPackIntent(ctx, opID)
	if intentErr != nil {
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", "get pack install intent failed: "+intentErr.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, intentErr)
		}
		return fmt.Errorf("get pack install intent: %w", intentErr)
	}

	unitName := fmt.Sprintf("acornfox-pack-%s.service", intent.PackID)
	existingJnl, jnlErr := w.store.GetActivationJournal(ctx, opID)
	if jnlErr != nil && !errors.Is(jnlErr, contracts.ErrNotFound) {
		failErr := w.failInstall(ctx, task, opID, 0, "waiting_reconcile", "get activation journal unknown error: "+jnlErr.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, jnlErr)
		}
		return fmt.Errorf("get activation journal: %w", jnlErr)
	}
	hasJnl := (jnlErr == nil && existingJnl.JournalID != "")
	var jnlRev int64 = 0
	if hasJnl {
		jnlRev = existingJnl.Revision
	}

	// Pre-execution cancellation check before touching helper:
	// If operation is cancelling before any journal exists, handle NoJournal cancellation with zero helper calls
	_, authPreErr := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
		TaskID:                  task.ID.String(),
		OperationID:             opID,
		PackID:                  intent.PackID,
		Version:                 intent.Version,
		PlanSHA256:              intent.PlanSHA256,
		Action:                  "prepare",
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		ExpectedJournalRevision: jnlRev,
		Audit:                   workerAudit,
	})
	if authPreErr != nil {
		if strings.Contains(authPreErr.Error(), "cancelling") {
			return w.handleCancellationConvergence(ctx, task, intent.PackID, intent.Version, intent.PlanSHA256, unitName, "", jnlRev, 0, workerAudit)
		}
		if !hasJnl && strings.Contains(authPreErr.Error(), "requires existing activation journal") {
			// Expected for NoJournal stage pre-check; proceed
		} else {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_authorization", "pre-stage authorization failed: "+authPreErr.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on pre-stage rejection: %w (original: %v)", failErr, authPreErr)
			}
			return fmt.Errorf("pre-stage authorization failed: %w", authPreErr)
		}
	}

	var actionSeq int64 = 0
	var snapUID uint32 = 0
	var snap *hosthelper.OperationCancellationSnapshot
	obsResp, obsErr := w.helper.ObservePack(ctx, hosthelper.ObservePackRequest{
		PackID:      intent.PackID,
		Version:     intent.Version,
		OperationID: opID,
	})
	if obsErr == nil && obsResp.CancellationSnapshot != nil {
		snap = obsResp.CancellationSnapshot
		// Verify exact owned scope and fresh observation timestamp
		if snap.OperationID != opID || snap.PackID != intent.PackID || snap.Version != intent.Version {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "observe snapshot scope mismatch", workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on snapshot scope mismatch: %w", failErr)
			}
			return errors.New("observe snapshot scope mismatch")
		}
		obsAge := time.Since(snap.ObservedAt)
		if snap.ObservedAt.IsZero() || obsAge < 0 || obsAge > time.Minute {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "observe snapshot stale or invalid observed_at", workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on stale snapshot: %w", failErr)
			}
			return errors.New("observe snapshot stale or invalid observed_at")
		}

		if snap.MaxOperationSequence > actionSeq {
			actionSeq = snap.MaxOperationSequence
		}
		if snap.UID > 0 {
			snapUID = snap.UID
		}
	} else if obsErr != nil && !strings.Contains(obsErr.Error(), "404") && !strings.Contains(obsErr.Error(), "not found") {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "[unknown_observe] snapshot observe failed: "+obsErr.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on snapshot error: %w (original: %v)", failErr, obsErr)
		}
		return fmt.Errorf("observe snapshot: %w", obsErr)
	} else if hasJnl && (snap == nil || obsErr != nil) {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "[unknown_observe] existing journal requires verified helper snapshot", workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on missing snapshot with journal: %w", failErr)
		}
		return errors.New("existing journal requires verified helper snapshot")
	}

	// Ready-direct-commit recovery: verify fresh owned process, current pointer, and readiness, then adopt epochs and commit
	if hasJnl && existingJnl.Phase == "ready" {
		if snap == nil || snap.ObservedStopped || obsResp.MainPID <= 0 {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "ready journal recovery rejected: owned process stopped or unknown", workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on dead process: %w", failErr)
			}
			return errors.New("ready journal recovery rejected: owned process stopped or unknown")
		}
		if snap.StartEffect == nil || snap.StartEffect.InstanceID != existingJnl.InstanceID || snap.StartEffect.MainPID != existingJnl.MainPID {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "ready journal recovery rejected: start effect mismatch", workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on start effect mismatch: %w", failErr)
			}
			return errors.New("ready journal recovery rejected: start effect mismatch")
		}
		if snap.AbortEffect != nil && snap.AbortEffect.Status == hosthelper.StatusAborted {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "ready journal recovery rejected: abort effect exists", workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on aborted effect: %w", failErr)
			}
			return errors.New("ready journal recovery rejected: abort effect exists")
		}

		// Verify current pointer on filesystem directly
		currentLink, lErr := os.Readlink(filepath.Join(w.cfg.PublishedDir, intent.PackID, "current"))
		if lErr != nil || currentLink != intent.Version {
			errMsg := fmt.Sprintf("ready recovery current pointer mismatch: got %q want %q (err: %v)", currentLink, intent.Version, lErr)
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", errMsg, workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on current mismatch: %w", failErr)
			}
			return errors.New(errMsg)
		}

		// Fresh readiness and live peer identity check
		artRcptReady, aErr := w.store.GetArtifactReceipt(ctx, opID)
		if aErr != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "get artifact receipt on ready recovery failed: "+aErr.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on artifact receipt: %w", failErr)
			}
			return aErr
		}

		targetUID := snapUID
		if targetUID == 0 && snap.StartEffect != nil && snap.StartEffect.MainPID > 0 {
			targetUID = snap.UID
		}

		readyInst := contracts.PackProtocolInstance{
			InstanceID:       existingJnl.InstanceID,
			PackID:           intent.PackID,
			Version:          intent.Version,
			OperationID:      opID,
			ExecutablePath:   artRcptReady.ExecutablePath,
			ExecutableSHA256: artRcptReady.ExecutableSHA256,
			ProtocolVersion:  "1.0",
			Capabilities:     existingJnl.CandidateCapabilities,
			ExpectedUID:      targetUID,
			ExpectedPID:      existingJnl.MainPID,
			ProcessStartTime: existingJnl.ProcessStartIdentity,
			SocketPath:       existingJnl.SocketPath,
			CoreGeneration:   task.CoreGeneration,
		}

		_, hErr := w.dispatcher.CheckReadinessWithValidator(ctx, readyInst, existingJnl.CandidateCapabilities, func(pPID int32, pUID uint32) error {
			if pPID != existingJnl.MainPID || pUID != targetUID {
				return fmt.Errorf("peer identity mismatch on ready recovery probe: got (%d, %d), want (%d, %d)", pPID, pUID, existingJnl.MainPID, targetUID)
			}
			obs, err := w.helper.ObservePack(ctx, hosthelper.ObservePackRequest{
				PackID: intent.PackID,
				PeerAttest: &hosthelper.PeerAttestRequest{
					PID:                   pPID,
					UID:                   pUID,
					ExpectedPackID:        intent.PackID,
					ExpectedVersion:       intent.Version,
					ExpectedInstanceID:    existingJnl.InstanceID,
					ExpectedExecutableSHA: artRcptReady.ExecutableSHA256,
					ExpectedStartTime:     existingJnl.ProcessStartIdentity,
				},
			})
			if err != nil {
				return err
			}
			if obs.PeerAttestResult == nil || !obs.PeerAttestResult.Attested {
				return errors.New("peer attest rejected by host helper on ready recovery")
			}
			return nil
		})
		if hErr != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", fmt.Sprintf("fresh health check failed on ready recovery: %v", hErr), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on health check: %w", failErr)
			}
			return fmt.Errorf("fresh health check failed on ready recovery: %w", hErr)
		}

		authSwitch, sErr := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
			TaskID:                  task.ID.String(),
			OperationID:             opID,
			PackID:                  intent.PackID,
			Version:                 intent.Version,
			PlanSHA256:              intent.PlanSHA256,
			Action:                  "switch",
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if sErr != nil {
			if strings.Contains(sErr.Error(), "cancelling") {
				return w.handleCancellationConvergence(ctx, task, intent.PackID, intent.Version, intent.PlanSHA256, unitName, existingJnl.InstanceID, jnlRev, actionSeq, workerAudit)
			}
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_authorization", "authorize switch action on ready resume failed: "+sErr.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, sErr)
			}
			return fmt.Errorf("authorize switch action on ready resume: %w", sErr)
		}
		_ = authSwitch

		// Adopt current caller tokens along exact revision
		adoptedRev, jErr := w.store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
			OperationID:             opID,
			TaskID:                  task.ID.String(),
			PackID:                  intent.PackID,
			Version:                 intent.Version,
			PlanSHA256:              intent.PlanSHA256,
			ArtifactReceiptID:       existingJnl.ArtifactReceiptID,
			Phase:                   "ready",
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			PublishID:               existingJnl.PublishID,
			InstalledRoot:           existingJnl.InstalledRoot,
			UnitName:                existingJnl.UnitName,
			InstanceID:              existingJnl.InstanceID,
			MainPID:                 existingJnl.MainPID,
			SocketPath:              existingJnl.SocketPath,
			ProcessStartIdentity:    existingJnl.ProcessStartIdentity,
			CandidateCapabilities:   existingJnl.CandidateCapabilities,
			CurrentPointerEffect:    existingJnl.CurrentPointerEffect,
			ActivationGeneration:    existingJnl.ActivationGeneration,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if jErr != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "adopt caller tokens in ready journal failed: "+jErr.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on adopt tokens: %w", failErr)
			}
			return fmt.Errorf("adopt caller tokens in ready journal: %w", jErr)
		}

		actRcptID, _ := domain.NewID("actrcpt")
		actRcpt := contracts.PackActivationReceipt{
			ReceiptID:             actRcptID.String(),
			OperationID:           opID,
			PackID:                intent.PackID,
			Version:               intent.Version,
			PlanSHA256:            intent.PlanSHA256,
			ArtifactReceiptID:     existingJnl.ArtifactReceiptID,
			InstalledRoot:         existingJnl.InstalledRoot,
			RelativeCurrentTarget: intent.Version,
			UnitName:              existingJnl.UnitName,
			ServiceIdentity:       "systemd:" + existingJnl.UnitName,
			InstanceID:            existingJnl.InstanceID,
			MainPID:               existingJnl.MainPID,
			ProcessStartIdentity:  existingJnl.ProcessStartIdentity,
			SocketPath:            existingJnl.SocketPath,
			Capabilities:          existingJnl.CandidateCapabilities,
			ActivationGeneration:  existingJnl.ActivationGeneration,
			ActivatedAt:           time.Now().UTC(),
			CreatedAt:             time.Now().UTC(),
		}
		if actRcpt.ActivationGeneration <= 0 {
			actRcpt.ActivationGeneration = 1
		}

		commitRecord := contracts.CommitActivationRecord{
			TaskID:                  task.ID.String(),
			Receipt:                 actRcpt,
			ExpectedUID:             targetUID,
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			ExpectedJournalRevision: adoptedRev,
			Audit:                   workerAudit,
		}
		if err := w.store.CommitActivation(ctx, commitRecord); err != nil {
			failErr := w.failInstall(ctx, task, opID, adoptedRev, "waiting_reconcile", "commit activation on ready resume failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("commit activation on ready resume: %w", err)
		}
		log.Printf("install worker: successfully recovered and committed activation for operation %s", opID)
		return nil
	}

	// 1. Load Trust Materials
	mat, err := w.store.GetPackTrustMaterial(ctx, opID)
	if err != nil {
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", "load trust materials failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
		}
		return fmt.Errorf("load trust materials: %w", err)
	}

	// 2. Pre-effect check: prevent mutating host if pack already has another active version/operation
	activeRt, rtErr := w.store.GetActiveRuntime(ctx, mat.PackID)
	if rtErr == nil && activeRt.PackID == mat.PackID {
		if activeRt.OperationID != opID || activeRt.ActiveVersion != mat.Version {
			errMsg := fmt.Sprintf("pack %s already has active version %s (op %s); multi-version upgrade requires TP02C",
				mat.PackID, activeRt.ActiveVersion, activeRt.OperationID)
			failErr := w.failInstall(ctx, task, opID, 0, "known_failure", errMsg, workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on upgrade rejection: %w", failErr)
			}
			return errors.New(errMsg)
		}
	}

	manifestObj, err := packprotocol.ParseManifest(mat.ManifestBytes)
	if err != nil {
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", "invalid manifest: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w", failErr)
		}
		return fmt.Errorf("parse manifest from trust material: %w", err)
	}

	var adapterEntry *packprotocol.Entry
	for _, e := range manifestObj.Entries {
		if e.Role == "adapter" {
			adapterEntry = &e
			break
		}
	}
	if adapterEntry == nil {
		errMsg := "missing adapter entry in manifest"
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", errMsg, workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w", failErr)
		}
		return errors.New(errMsg)
	}

	// 3. Resolve explicit policy matching the trust material publisher
	var env packprotocol.CatalogEnvelope
	if err := json.Unmarshal(mat.CatalogEnvelope, &env); err != nil {
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", "unmarshal catalog envelope: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w", failErr)
		}
		return fmt.Errorf("unmarshal catalog envelope: %w", err)
	}
	rawPay, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", "decode catalog payload: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w", failErr)
		}
		return fmt.Errorf("decode catalog payload: %w", err)
	}
	var catPay packprotocol.CatalogPayload
	if err := json.Unmarshal(rawPay, &catPay); err != nil {
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", "unmarshal catalog payload: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w", failErr)
		}
		return fmt.Errorf("unmarshal catalog payload: %w", err)
	}

	policy, ok := w.cfg.Policies[catPay.Publisher]
	if !ok {
		errMsg := fmt.Sprintf("untrusted publisher %q in task trust material: no policy configured", catPay.Publisher)
		failErr := w.failInstall(ctx, task, opID, 0, "known_failure", errMsg, workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w", failErr)
		}
		return errors.New(errMsg)
	}
	policy.Now = time.Now().UTC()
	policy.InstallationBinding = mat.PlanSHA256

	// Check catalog authority expiration before proceeding to new mutation
	parsedExp, pErr := time.Parse(time.RFC3339Nano, catPay.ExpiresAt)
	if pErr == nil && time.Now().UTC().After(parsedExp) {
		errMsg := "catalog authority expired: authorization required"
		failErr := w.failInstall(ctx, task, opID, 0, "waiting_authorization", errMsg, workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on expired authority: %w", failErr)
		}
		return errors.New(errMsg)
	}

	stagerConfig := ArtifactStagingConfig{
		StagingRootDir:   w.cfg.StagingDir,
		Policy:           policy,
		MaxUnpackedBytes: 256 << 20,
		OwnerUID:         int(w.cfg.CoreUID),
		OwnerGID:         int(w.cfg.CoreGID),
		DownloadTimeout:  30 * time.Second,
	}
	stager, err := NewArtifactStager(w.store, stagerConfig)
	if err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "create artifact stager failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
		}
		return fmt.Errorf("create artifact stager: %w", err)
	}

	unitName = fmt.Sprintf("acornfox-pack-%s.service", mat.PackID)

	// 5. Stage Artifact or verify existing A receipt
	var artRcpt contracts.PackArtifactReceipt
	existingRcpt, err := w.store.GetArtifactReceipt(ctx, opID)
	if err == nil && existingRcpt.ReceiptID != "" {
		artRcpt = existingRcpt
		stagePath := filepath.Join(w.cfg.StagingDir, "staging", opID)
		policy.Now = time.Now().UTC()
		verifiedSelection, vErr := packprotocol.VerifySelection(mat.CatalogEnvelope, mat.ManifestBytes, policy)
		if vErr != nil {
			return fmt.Errorf("verify selection for staged readback failed: %w", vErr)
		}
		snap, _, ok := verifiedSelection.Snapshot()
		if !ok {
			return errors.New("failed to get snapshot from verified selection")
		}
		verified, err := ReadAndVerifyStagedInventory(stagePath, opID, snap, mat.PlanSHA256, mat.ManifestBytes, artRcpt.StageIdentity, int(w.cfg.CoreUID), int(w.cfg.CoreGID))
		if err != nil {
			errMsg := fmt.Sprintf("staged inventory readback verification failed: %v", err)
			failErr := w.failInstall(ctx, task, opID, 0, "known_failure", errMsg, workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w", failErr)
			}
			return errors.New(errMsg)
		}
		if verified == nil {
			return errors.New("readback verification returned nil receipt")
		}
	} else {
		if err := w.checkAndRenewLease(ctx, &task); err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "lease renew failed before stage: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on renew: %w (original: %v)", failErr, err)
			}
			return err
		}
		stageReq := StageArtifactRequest{
			OperationID:     opID,
			TaskID:          task.ID.String(),
			CoreGeneration:  task.CoreGeneration,
			LeaseGeneration: task.LeaseGeneration,
			OwnerID:         task.LeaseOwner,
			Audit:           workerAudit,
		}
		stageCtx, cancelStage := context.WithCancel(ctx)
		stopSupervisor := make(chan struct{})
		supervisorDone := make(chan struct{})
		var supervisorReason string
		var supervisorMu sync.Mutex
		setSupervisorReason := func(reason string) {
			supervisorMu.Lock()
			if supervisorReason == "" {
				supervisorReason = reason
			}
			supervisorMu.Unlock()
		}
		getSupervisorReason := func() string {
			supervisorMu.Lock()
			defer supervisorMu.Unlock()
			return supervisorReason
		}

		go func() {
			defer close(supervisorDone)
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopSupervisor:
					return
				case <-stageCtx.Done():
					return
				case <-ticker.C:
					if ctx.Err() != nil {
						setSupervisorReason("shutdown")
						cancelStage()
						return
					}
					if rErr := w.checkAndRenewLease(stageCtx, &task); rErr != nil {
						setSupervisorReason("lease_lost")
						cancelStage()
						return
					}
					// Authoritative check of operations.state: prepare rejects with "cancelling" if control plane requested cancel
					_, authCheckErr := w.store.AuthorizePackActivationAction(stageCtx, contracts.AuthorizePackActivationActionRequest{
						TaskID:                  task.ID.String(),
						OperationID:             opID,
						PackID:                  intent.PackID,
						Version:                 intent.Version,
						PlanSHA256:              intent.PlanSHA256,
						Action:                  "prepare",
						CoreGeneration:          task.CoreGeneration,
						LeaseGeneration:         task.LeaseGeneration,
						OwnerID:                 task.LeaseOwner,
						ExpectedJournalRevision: jnlRev,
						Audit:                   workerAudit,
					})
					if authCheckErr != nil {
						if strings.Contains(authCheckErr.Error(), "cancelling") {
							setSupervisorReason("user_cancel")
							cancelStage()
							return
						}
						// Requires existing journal is the legitimate NoJournal pre-check state; any other refusal must halt stage
						if !hasJnl && strings.Contains(authCheckErr.Error(), "requires existing activation journal") {
							// Expected pre-journal state
						} else {
							setSupervisorReason("auth_lost: " + authCheckErr.Error())
							cancelStage()
							return
						}
					}
				}
			}
		}()

		staged, err := stager.StageArtifact(stageCtx, stageReq)
		close(stopSupervisor)
		<-supervisorDone
		cancelStage()

		if err != nil {
			reason := getSupervisorReason()
			// Only if operations.state is verified cancelling do we converge to user cancellation
			if reason == "user_cancel" {
				return w.handleCancellationConvergence(ctx, task, intent.PackID, intent.Version, intent.PlanSHA256, unitName, "", jnlRev, 0, workerAudit)
			}
			// Verify if cancelled during staging via authoritative check
			if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "cancel") {
				_, postCheckErr := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
					TaskID:                  task.ID.String(),
					OperationID:             opID,
					PackID:                  intent.PackID,
					Version:                 intent.Version,
					PlanSHA256:              intent.PlanSHA256,
					Action:                  "prepare",
					CoreGeneration:          task.CoreGeneration,
					LeaseGeneration:         task.LeaseGeneration,
					OwnerID:                 task.LeaseOwner,
					ExpectedJournalRevision: jnlRev,
					Audit:                   workerAudit,
				})
				if postCheckErr != nil && strings.Contains(postCheckErr.Error(), "cancelling") {
					return w.handleCancellationConvergence(ctx, task, intent.PackID, intent.Version, intent.PlanSHA256, unitName, "", jnlRev, 0, workerAudit)
				}
				if ctx.Err() != nil {
					return fmt.Errorf("staging aborted on worker shutdown: %w", ctx.Err())
				}
			}

			classification := "known_failure"
			if strings.HasPrefix(reason, "auth_lost") || reason == "lease_lost" ||
				strings.Contains(err.Error(), "lease") || strings.Contains(err.Error(), "timeout") ||
				strings.Contains(err.Error(), "authority") || strings.Contains(err.Error(), "connection") ||
				strings.Contains(err.Error(), "unknown") {
				classification = "waiting_reconcile"
			}
			recordReason := err.Error()
			if strings.HasPrefix(reason, "auth_lost") {
				recordReason = reason + "; " + err.Error()
			}
			failErr := w.failInstall(ctx, task, opID, jnlRev, classification, recordReason, workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on stage error: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("stage artifact: %w", err)
		}
		artRcpt = *staged
	}

	if err := w.checkAndRenewLease(ctx, &task); err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "lease renew failed after stage: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on renew: %w (original: %v)", failErr, err)
		}
		return err
	}

	// 6. Check existing activation journal / receipts to resume safely without unconditional publishing reset
	if hasJnl && existingJnl.Phase == "active" {
		log.Printf("install worker: operation %s already active in journal; skipping execution", opID)
		return nil
	}

	pubDir := filepath.Join(w.cfg.PublishedDir, mat.PackID, mat.Version)
	socketPath := filepath.Join(w.cfg.RunDir, mat.PackID, "adapter.sock")

	// Form journal first before any host mutation (Rule: all host mutations require existing journal)
	if !hasJnl {
		// Initial activation journal: publishing (requires ExpectedJournalRevision == 0)
		rev, err := w.store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
			OperationID:             opID,
			TaskID:                  task.ID.String(),
			PackID:                  mat.PackID,
			Version:                 mat.Version,
			PlanSHA256:              mat.PlanSHA256,
			ArtifactReceiptID:       artRcpt.ReceiptID,
			Phase:                   "publishing",
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			PublishID:               "pub_" + opID,
			InstalledRoot:           pubDir,
			UnitName:                unitName,
			ExpectedJournalRevision: 0,
			Audit:                   workerAudit,
		})
		if err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "record initial activation journal failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("record activation journal publishing: %w", err)
		}
		jnlRev = rev
		hasJnl = true
	} else {
		jnlRev = existingJnl.Revision
	}

	permit := hosthelper.ActionPermit{
		OperationID:     opID,
		PackID:          mat.PackID,
		Version:         mat.Version,
		CoreGeneration:  task.CoreGeneration,
		LeaseGeneration: task.LeaseGeneration,
		OwnerID:         task.LeaseOwner,
	}

	var pubResp hosthelper.PublishPackResponse
	alreadyPublished := false
	if snap != nil && snap.PublishEffect != nil && snap.PublishEffect.OperationID == opID &&
		snap.PublishEffect.PackID == mat.PackID && snap.PublishEffect.Version == mat.Version &&
		snap.PublishEffect.Status == hosthelper.StatusSucceeded {
		if snap.UID == 0 || snap.PublishEffect.ExecutablePath != filepath.Join(pubDir, artRcpt.ExecutablePath) || snap.PublishEffect.ExecutableSHA != artRcpt.ExecutableSHA256 {
			proofErr := errors.New("published effect does not match the owned UID and frozen executable")
			if err := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", proofErr.Error(), workerAudit); err != nil {
				return fmt.Errorf("record unverified publish effect: %w", err)
			}
			return proofErr
		}
		pubResp = hosthelper.PublishPackResponse{
			PublishedRoot:  pubDir,
			ExecutablePath: snap.PublishEffect.ExecutablePath,
			ExecutableSHA:  snap.PublishEffect.ExecutableSHA,
		}
		alreadyPublished = true
		log.Printf("install worker: durable publish effect already present for op %s; skipping PrepareDirs and PublishPack", opID)
	}

	if !alreadyPublished {
		// 7. Action Authorize before host mutation: "prepare" (with positive journal revision)
		authPrep, err := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
			TaskID:                  task.ID.String(),
			OperationID:             opID,
			PackID:                  mat.PackID,
			Version:                 mat.Version,
			PlanSHA256:              mat.PlanSHA256,
			Action:                  "prepare",
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if err != nil {
			if strings.Contains(err.Error(), "cancelling") {
				return w.handleCancellationConvergence(ctx, task, mat.PackID, mat.Version, mat.PlanSHA256, unitName, "", jnlRev, actionSeq, workerAudit)
			}
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_authorization", "authorize prepare action failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("authorize prepare action failed: %w", err)
		}

		if actionSeq >= math.MaxInt64-2 {
			return errors.New("sequence overflow")
		}
		actionSeq++
		permit.Deadline = authPrep.Deadline
		permit.ActionID = fmt.Sprintf("act_prepare_%s_%d", opID, actionSeq)
		permit.Sequence = actionSeq

		// Call helper PrepareDirs
		prepResp, err := w.helper.PrepareDirs(ctx, hosthelper.PrepareDirsRequest{
			Permit: permit,
		})
		if err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "helper prepare dirs failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("helper prepare dirs: %w", err)
		}
		if snapUID == 0 && prepResp.PackUID > 0 {
			snapUID = prepResp.PackUID
		}

		if err := w.checkAndRenewLease(ctx, &task); err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "renew lease after prepare failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on renew: %w (original: %v)", failErr, err)
			}
			return err
		}

		// 8. Action Authorize before host mutation: "publish"
		authPub, err := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
			TaskID:                  task.ID.String(),
			OperationID:             opID,
			PackID:                  mat.PackID,
			Version:                 mat.Version,
			PlanSHA256:              mat.PlanSHA256,
			Action:                  "publish",
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if err != nil {
			if strings.Contains(err.Error(), "cancelling") {
				return w.handleCancellationConvergence(ctx, task, mat.PackID, mat.Version, mat.PlanSHA256, unitName, "", jnlRev, actionSeq, workerAudit)
			}
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_authorization", "authorize publish action failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("authorize publish action failed: %w", err)
		}

		actionSeq++
		permit.ActionID = fmt.Sprintf("act_publish_%s_%d", opID, actionSeq)
		permit.Sequence = actionSeq
		permit.Deadline = authPub.Deadline
		resp, err := w.helper.PublishPack(ctx, hosthelper.PublishPackRequest{
			Permit:                     permit,
			ArtifactReceiptID:          artRcpt.ReceiptID,
			PlanSHA256:                 mat.PlanSHA256,
			CatalogEnvelopeRaw:         mat.CatalogEnvelope,
			ManifestRaw:                mat.ManifestBytes,
			StageIdentity:              artRcpt.StageIdentity,
			ExpectedArchiveSHA:         artRcpt.ArchiveSHA256,
			ExpectedManifestSHA:        artRcpt.ManifestSHA256,
			ExpectedExecutablePath:     artRcpt.ExecutablePath,
			ExpectedExecutableSHA:      artRcpt.ExecutableSHA256,
			ExpectedMemberCount:        artRcpt.MemberCount,
			ExpectedUnpackedTotalBytes: artRcpt.UnpackedTotalBytes,
		})
		if err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "helper publish pack failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("helper publish pack: %w", err)
		}
		pubResp = resp

		if err := w.checkAndRenewLease(ctx, &task); err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "renew lease after publish failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on renew: %w (original: %v)", failErr, err)
			}
			return err
		}
	}

	// 9. Start Pack (with crash recovery observation check)
	var mainPID int32
	var startIdent string
	var instID string

	canAdopt := false
	if hasJnl && (existingJnl.Phase == "starting" || existingJnl.Phase == "started" || existingJnl.Phase == "ready") {
		if snap != nil && snap.StartEffect != nil {
			startEff := snap.StartEffect
			stopAfterStart := (snap.StopEffect != nil && snap.StopEffect.Sequence > startEff.Sequence)
			aborted := (snap.AbortEffect != nil && snap.AbortEffect.Status == hosthelper.StatusAborted)
			expectedExePath := filepath.Join(pubDir, artRcpt.ExecutablePath)
			if !stopAfterStart && !aborted &&
				startEff.OperationID == opID && startEff.PackID == mat.PackID && startEff.Version == mat.Version &&
				startEff.InstanceID == existingJnl.InstanceID && !snap.ObservedStopped &&
				obsResp.MainPID == startEff.MainPID && startEff.MainPID > 0 &&
				startEff.ExecutableSHA == artRcpt.ExecutableSHA256 &&
				startEff.ExecutablePath == expectedExePath &&
				startEff.SocketPath == socketPath {
				mainPID = startEff.MainPID
				startIdent = startEff.ProcessStartTime
				instID = startEff.InstanceID
				canAdopt = true
				log.Printf("install worker: successfully adopted live started process (PID %d, instance %s)", mainPID, instID)
			}
		}
	}

	if !canAdopt {
		// If unit is not cleanly inactive, stop it for recovery before restarting
		if obsResp.UnitStatus != "inactive" && obsResp.UnitStatus != "failed" {
			authStop, sErr := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
				TaskID:                  task.ID.String(),
				OperationID:             opID,
				PackID:                  mat.PackID,
				Version:                 mat.Version,
				PlanSHA256:              mat.PlanSHA256,
				Action:                  "stop",
				CoreGeneration:          task.CoreGeneration,
				LeaseGeneration:         task.LeaseGeneration,
				OwnerID:                 task.LeaseOwner,
				ExpectedJournalRevision: jnlRev,
				Audit:                   workerAudit,
			})
			if sErr != nil {
				if strings.Contains(sErr.Error(), "cancelling") {
					return w.handleCancellationConvergence(ctx, task, mat.PackID, mat.Version, mat.PlanSHA256, unitName, "", jnlRev, actionSeq, workerAudit)
				}
				failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "[unknown_stop] authorize stop for recovery failed: "+sErr.Error(), workerAudit)
				if failErr != nil {
					return fmt.Errorf("fail pack install on stop auth rejection: %w (original: %v)", failErr, sErr)
				}
				return fmt.Errorf("authorize stop for recovery failed: %w", sErr)
			}

			if actionSeq >= math.MaxInt64-2 {
				return errors.New("sequence overflow")
			}
			actionSeq++
			permit.ActionID = fmt.Sprintf("act_stop_%s_%d", opID, actionSeq)
			permit.Sequence = actionSeq
			permit.Deadline = authStop.Deadline
			stopResp, stopErr := w.helper.StopPending(ctx, hosthelper.StopPendingRequest{
				Permit: permit,
			})
			if stopErr != nil || !stopResp.Stopped {
				errMsg := "stop pending for recovery not confirmed"
				if stopErr != nil {
					errMsg = stopErr.Error()
				}
				failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "[unknown_stop] helper stop failed: "+errMsg, workerAudit)
				if failErr != nil {
					return fmt.Errorf("fail pack install on unconfirmed stop: %w (original: %s)", failErr, errMsg)
				}
				return fmt.Errorf("stop pending for recovery failed: %s", errMsg)
			}
		}

		// Authorize "start" action
		authStart, err := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
			TaskID:                  task.ID.String(),
			OperationID:             opID,
			PackID:                  mat.PackID,
			Version:                 mat.Version,
			PlanSHA256:              mat.PlanSHA256,
			Action:                  "start",
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if err != nil {
			if strings.Contains(err.Error(), "cancelling") {
				return w.handleCancellationConvergence(ctx, task, mat.PackID, mat.Version, mat.PlanSHA256, unitName, "", jnlRev, actionSeq, workerAudit)
			}
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_authorization", "authorize start action failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("authorize start action failed: %w", err)
		}
		if actionSeq >= math.MaxInt64-2 {
			return errors.New("sequence overflow")
		}
		actionSeq++
		permit.ActionID = fmt.Sprintf("act_start_%s_%d", opID, actionSeq)
		permit.Sequence = actionSeq
		permit.Deadline = authStart.Deadline

		startResp, err := w.helper.StartPack(ctx, hosthelper.StartPackRequest{
			Permit: permit,
		})
		if err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "helper start pack failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("helper start pack: %w", err)
		}
		mainPID = startResp.MainPID
		startIdent = startResp.ProcessStartIdentity
		instID = startResp.InstanceID
		if instID == "" {
			instID = fmt.Sprintf("inst_%s_%d", mat.Version, mainPID)
		}
		if startResp.UID > 0 && snapUID == 0 {
			snapUID = startResp.UID
		}
	}

	if canAdopt {
		targetPhase := existingJnl.Phase
		if targetPhase == "starting" {
			targetPhase = "started"
		}
		jnlRev, err = w.store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
			OperationID:             opID,
			TaskID:                  task.ID.String(),
			PackID:                  mat.PackID,
			Version:                 mat.Version,
			PlanSHA256:              mat.PlanSHA256,
			ArtifactReceiptID:       artRcpt.ReceiptID,
			Phase:                   targetPhase,
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			PublishID:               existingJnl.PublishID,
			InstalledRoot:           pubDir,
			UnitName:                unitName,
			InstanceID:              instID,
			MainPID:                 mainPID,
			SocketPath:              socketPath,
			ProcessStartIdentity:    startIdent,
			CandidateCapabilities:   manifestObj.Capabilities,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "adopt caller tokens in started journal failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on adopt: %w", failErr)
			}
			return fmt.Errorf("adopt caller tokens in started journal: %w", err)
		}
	} else {
		nextPhase := "starting"
		if existingJnl.Phase == "starting" || existingJnl.Phase == "started" {
			nextPhase = existingJnl.Phase
		}
		jnlRev, err = w.store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
			OperationID:             opID,
			TaskID:                  task.ID.String(),
			PackID:                  mat.PackID,
			Version:                 mat.Version,
			PlanSHA256:              mat.PlanSHA256,
			ArtifactReceiptID:       artRcpt.ReceiptID,
			Phase:                   nextPhase,
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			PublishID:               "pub_" + opID,
			InstalledRoot:           pubDir,
			UnitName:                unitName,
			InstanceID:              instID,
			MainPID:                 mainPID,
			SocketPath:              socketPath,
			ProcessStartIdentity:    startIdent,
			CandidateCapabilities:   manifestObj.Capabilities,
			ExpectedJournalRevision: jnlRev,
			Audit:                   workerAudit,
		})
		if err != nil {
			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "record activation journal starting failed: "+err.Error(), workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
			}
			return fmt.Errorf("record activation journal starting: %w", err)
		}
	}

	if err := w.checkAndRenewLease(ctx, &task); err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "renew lease after start failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on renew: %w (original: %v)", failErr, err)
		}
		return err
	}

	// 10. Readiness verification & Live process attestation bridge
	exePath := pubResp.ExecutablePath
	if exePath == "" {
		exePath = filepath.Join(pubDir, artRcpt.ExecutablePath)
	}
	expectedUID := snapUID

	inst := contracts.PackProtocolInstance{
		InstanceID:       instID,
		PackID:           mat.PackID,
		Version:          mat.Version,
		OperationID:      opID,
		ManifestSHA256:   mat.ManifestSHA256,
		ExecutableSHA256: artRcpt.ExecutableSHA256,
		ExecutablePath:   exePath,
		ProtocolVersion:  "1.0",
		Capabilities:     manifestObj.Capabilities,
		ExpectedUID:      expectedUID,
		ExpectedPID:      mainPID,
		ProcessStartTime: startIdent,
		SocketPath:       socketPath,
		CoreGeneration:   task.CoreGeneration,
	}

	customValidator := func(peerPID int32, peerUID uint32) error {
		obs, err := w.helper.ObservePack(ctx, hosthelper.ObservePackRequest{
			PackID: mat.PackID,
			PeerAttest: &hosthelper.PeerAttestRequest{
				PID:                   peerPID,
				UID:                   peerUID,
				ExpectedPackID:        mat.PackID,
				ExpectedVersion:       mat.Version,
				ExpectedInstanceID:    instID,
				ExpectedExecutableSHA: artRcpt.ExecutableSHA256,
				ExpectedStartTime:     startIdent,
			},
		})
		if err != nil {
			return fmt.Errorf("helper observe peer attest failed: %w", err)
		}
		if obs.PeerAttestResult == nil || !obs.PeerAttestResult.Attested {
			errStr := "attestation failed"
			if obs.PeerAttestResult != nil {
				errStr = obs.PeerAttestResult.Error
			}
			return fmt.Errorf("root helper rejected peer process identity: %s", errStr)
		}
		return nil
	}

	var health packprotocol.HealthResponse
	readinessDeadline := time.Now().Add(30 * time.Second)
	lastErr := errors.New("adapter readiness has not been observed")
	for time.Now().Before(readinessDeadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if _, err := os.Stat(socketPath); err == nil {
			health, lastErr = w.dispatcher.CheckReadinessWithValidator(ctx, inst, manifestObj.Capabilities, customValidator)
			if lastErr == nil {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}

	if lastErr != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", fmt.Sprintf("adapter readiness check failed: %v", lastErr), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, lastErr)
		}
		return fmt.Errorf("adapter readiness check failed: %v", lastErr)
	}

	// Filter and ensure readiness capabilities do not exceed declared manifest capabilities
	manifestCapMap := make(map[string]bool, len(manifestObj.Capabilities))
	for _, c := range manifestObj.Capabilities {
		manifestCapMap[c] = true
	}
	for _, c := range health.Capabilities {
		if !manifestCapMap[c] {
			errMsg := fmt.Sprintf("adapter readiness returned undeclared capability %q not authorized by manifest", c)
			// Live pending instance exists; stop it for recovery before recording failure
			authStop, sErr := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
				TaskID:                  task.ID.String(),
				OperationID:             opID,
				PackID:                  mat.PackID,
				Version:                 mat.Version,
				PlanSHA256:              mat.PlanSHA256,
				Action:                  "stop",
				CoreGeneration:          task.CoreGeneration,
				LeaseGeneration:         task.LeaseGeneration,
				OwnerID:                 task.LeaseOwner,
				ExpectedJournalRevision: jnlRev,
				Audit:                   workerAudit,
			})
			recordReason := errMsg
			if sErr != nil {
				if strings.Contains(sErr.Error(), "cancelling") {
					return w.handleCancellationConvergence(ctx, task, mat.PackID, mat.Version, mat.PlanSHA256, unitName, instID, jnlRev, actionSeq, workerAudit)
				}
				recordReason = fmt.Sprintf("%s; [unknown_stop] authorize stop failed: %v", errMsg, sErr)
			} else {
				if actionSeq >= math.MaxInt64-2 {
					return errors.New("sequence overflow")
				}
				actionSeq++
				permit.ActionID = fmt.Sprintf("act_stop_%s_%d", opID, actionSeq)
				permit.Sequence = actionSeq
				permit.Deadline = authStop.Deadline
				stopResp, stopErr := w.helper.StopPending(ctx, hosthelper.StopPendingRequest{
					Permit: permit,
					Reason: errMsg,
				})
				if stopErr != nil || !stopResp.Stopped {
					stopDetail := "stop unconfirmed"
					if stopErr != nil {
						stopDetail = stopErr.Error()
					}
					recordReason = fmt.Sprintf("%s; [unknown_stop] helper stop failed: %s", errMsg, stopDetail)
				}
			}

			failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", recordReason, workerAudit)
			if failErr != nil {
				return fmt.Errorf("fail pack install on undeclared capability stop: %w (original: %s)", failErr, recordReason)
			}
			return errors.New(recordReason)
		}
	}
	authorizedCaps := manifestObj.Capabilities

	if err := w.checkAndRenewLease(ctx, &task); err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "renew lease before switch failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on renew: %w (original: %v)", failErr, err)
		}
		return err
	}

	// 11. Action Authorize before host mutation: "switch"
	authSwitch, err := w.store.AuthorizePackActivationAction(ctx, contracts.AuthorizePackActivationActionRequest{
		TaskID:                  task.ID.String(),
		OperationID:             opID,
		PackID:                  mat.PackID,
		Version:                 mat.Version,
		PlanSHA256:              mat.PlanSHA256,
		Action:                  "switch",
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		ExpectedJournalRevision: jnlRev,
		Audit:                   workerAudit,
	})
	if err != nil {
		if strings.Contains(err.Error(), "cancelling") {
			return w.handleCancellationConvergence(ctx, task, mat.PackID, mat.Version, mat.PlanSHA256, unitName, instID, jnlRev, actionSeq, workerAudit)
		}
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_authorization", "authorize switch action failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
		}
		return fmt.Errorf("authorize switch action failed: %w", err)
	}

	if actionSeq >= math.MaxInt64-2 {
		return errors.New("sequence overflow")
	}
	actionSeq++
	permit.ActionID = fmt.Sprintf("act_switch_%s_%d", opID, actionSeq)
	permit.Sequence = actionSeq
	permit.Deadline = authSwitch.Deadline
	swResp, err := w.helper.SwitchCurrent(ctx, hosthelper.SwitchCurrentRequest{
		Permit:         permit,
		RelativeTarget: mat.Version,
	})
	if err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "helper switch current failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
		}
		return fmt.Errorf("helper switch current: %w", err)
	}

	// 12. Update activation journal: ready with current pointer effect
	jnlRev, err = w.store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             opID,
		TaskID:                  task.ID.String(),
		PackID:                  mat.PackID,
		Version:                 mat.Version,
		PlanSHA256:              mat.PlanSHA256,
		ArtifactReceiptID:       artRcpt.ReceiptID,
		Phase:                   "ready",
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		PublishID:               "pub_" + opID,
		InstalledRoot:           pubDir,
		UnitName:                unitName,
		InstanceID:              instID,
		MainPID:                 mainPID,
		SocketPath:              socketPath,
		ProcessStartIdentity:    startIdent,
		CandidateCapabilities:   authorizedCaps,
		CurrentPointerEffect:    swResp.Effect,
		ActivationGeneration:    1,
		ExpectedJournalRevision: jnlRev,
		Audit:                   workerAudit,
	})
	if err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "record activation journal ready failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install: %w (original: %v)", failErr, err)
		}
		return fmt.Errorf("record activation journal ready: %w", err)
	}

	// 13. Atomic CommitActivation in SQLite Store
	actRcptID, _ := domain.NewID("actrcpt")
	actRcpt := contracts.PackActivationReceipt{
		ReceiptID:             actRcptID.String(),
		OperationID:           opID,
		PackID:                mat.PackID,
		Version:               mat.Version,
		PlanSHA256:            mat.PlanSHA256,
		ArtifactReceiptID:     artRcpt.ReceiptID,
		InstalledRoot:         pubDir,
		RelativeCurrentTarget: mat.Version,
		UnitName:              unitName,
		ServiceIdentity:       "systemd:" + unitName,
		InstanceID:            instID,
		MainPID:               mainPID,
		ProcessStartIdentity:  startIdent,
		SocketPath:            socketPath,
		Capabilities:          authorizedCaps,
		ActivationGeneration:  1,
		ActivatedAt:           time.Now().UTC(),
		CreatedAt:             time.Now().UTC(),
	}

	commitRecord := contracts.CommitActivationRecord{
		TaskID:                  task.ID.String(),
		Receipt:                 actRcpt,
		ExpectedUID:             snapUID,
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		ExpectedJournalRevision: jnlRev,
		Audit:                   workerAudit,
	}

	if err := w.store.CommitActivation(ctx, commitRecord); err != nil {
		failErr := w.failInstall(ctx, task, opID, jnlRev, "waiting_reconcile", "commit activation failed: "+err.Error(), workerAudit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on commit: %w (original: %v)", failErr, err)
		}
		return fmt.Errorf("commit activation: %w", err)
	}

	log.Printf("install worker: successfully activated pack %s version %s (operation %s)",
		mat.PackID, mat.Version, opID)
	return nil
}

// handleCancellationConvergence handles graceful convergence when operation is cancelled:
// calls root helper AbortPending with an isolated bounded context, verifies process exit, and commits CancelActivation.
func (w *InstallWorker) handleCancellationConvergence(ctx context.Context, task contracts.Task, packID, version, planSHA256, unitName, instanceID string, jnlRev int64, actionSeq int64, audit contracts.AuditContext) error {
	if ctx == nil {
		if w.ctx != nil {
			ctx = w.ctx
		} else {
			ctx = context.Background()
		}
	}
	opID := task.OperationID.String()

	// If no journal exists (no host action was ever authorized/created), execute safe NoJournal cancel directly
	if jnlRev == 0 {
		cancelRecord := contracts.CancelActivationRecord{
			OperationID:       opID,
			TaskID:            task.ID.String(),
			CoreGeneration:    task.CoreGeneration,
			LeaseGeneration:   task.LeaseGeneration,
			OwnerID:           task.LeaseOwner,
			Reason:            "cancelled before journal creation",
			AbortReceiptID:    "", // no fake receipt
			ObservedStopped:   false,
			ObservedStoppedAt: time.Time{},
			Audit:             audit,
		}
		if err := w.store.CancelActivation(ctx, cancelRecord); err != nil {
			return fmt.Errorf("commit no-journal cancel activation failed: %w", err)
		}
		log.Printf("install worker: successfully cancelled un-started operation %s (NoJournal)", opID)
		return nil
	}

	// Use bounded sub-context inherited from passed live context for cleanup, fallback to background if parent already cancelled
	cleanupParent := ctx
	if cleanupParent.Err() != nil {
		cleanupParent = context.Background()
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(cleanupParent, 2*time.Second)
	defer cleanupCancel()

	// 1. Read internally consistent cancellation snapshot under host helper
	obsResp, obsErr := w.helper.ObservePack(cleanupCtx, hosthelper.ObservePackRequest{
		PackID:      packID,
		Version:     version,
		OperationID: opID,
	})
	if obsErr != nil || obsResp.CancellationSnapshot == nil {
		errMsg := "observe cancellation snapshot failed"
		if obsErr != nil {
			errMsg = obsErr.Error()
		}
		failErr := w.failInstall(cleanupCtx, task, opID, jnlRev, "waiting_reconcile", "[unknown_abort] snapshot observe failed: "+errMsg, audit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on snapshot error: %w (original: %s)", failErr, errMsg)
		}
		return fmt.Errorf("observe cancellation snapshot failed: %s", errMsg)
	}

	snap := obsResp.CancellationSnapshot

	// Verify exact owned scope of snapshot matches current frozen target
	if snap.OperationID != opID || snap.PackID != packID || snap.Version != version {
		errMsg := fmt.Sprintf("cancellation snapshot scope mismatch: got (%s, %s, %s), want (%s, %s, %s)",
			snap.OperationID, snap.PackID, snap.Version, opID, packID, version)
		failErr := w.failInstall(cleanupCtx, task, opID, jnlRev, "waiting_reconcile", "[unknown_abort] "+errMsg, audit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on snapshot scope mismatch: %w (original: %s)", failErr, errMsg)
		}
		return errors.New(errMsg)
	}

	// Verify freshness of observation timestamp
	observedAge := time.Since(snap.ObservedAt)
	if snap.ObservedAt.IsZero() || observedAge < 0 || observedAge > time.Minute {
		errMsg := "cancellation snapshot has invalid or stale observed_at timestamp"
		failErr := w.failInstall(cleanupCtx, task, opID, jnlRev, "waiting_reconcile", "[unknown_abort] "+errMsg, audit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on stale observation: %w (original: %s)", failErr, errMsg)
		}
		return errors.New(errMsg)
	}

	// If matching durable abort already exists and exact owned scope is currently stopped, converge immediately without re-aborting
	if snap.AbortEffect != nil && snap.AbortEffect.ActionID != "" &&
		snap.AbortEffect.OperationID == opID && snap.AbortEffect.PackID == packID && snap.AbortEffect.Version == version &&
		snap.AbortEffect.Status == hosthelper.StatusAborted && snap.ObservedStopped {
		savedUnit := unitName
		if snap.UnitName != "" {
			savedUnit = snap.UnitName
		}
		savedInst := instanceID
		if snap.InstanceID != "" {
			savedInst = snap.InstanceID
		}
		if snap.AbortEffect.InstanceID != "" {
			savedInst = snap.AbortEffect.InstanceID
		}
		cancelRecord := contracts.CancelActivationRecord{
			OperationID:             opID,
			TaskID:                  task.ID.String(),
			CoreGeneration:          task.CoreGeneration,
			LeaseGeneration:         task.LeaseGeneration,
			OwnerID:                 task.LeaseOwner,
			Reason:                  "cancelled by control plane request",
			AbortReceiptID:          snap.AbortEffect.ActionID,
			UnitName:                savedUnit,
			InstanceID:              savedInst,
			ObservedStopped:         true,
			ObservedStoppedAt:       snap.ObservedAt,
			ExpectedJournalRevision: jnlRev,
			Audit:                   audit,
		}
		if err := w.store.CancelActivation(cleanupCtx, cancelRecord); err != nil {
			return fmt.Errorf("commit cancel activation with existing abort effect failed: %w", err)
		}
		log.Printf("install worker: successfully converged cancellation for operation %s using existing durable abort %s", opID, snap.AbortEffect.ActionID)
		return nil
	}

	// 2. Derive stable sequence and actionID from known snapshot (checking integer overflow)
	if snap.MaxOperationSequence >= math.MaxInt64 {
		return errors.New("operation sequence overflow: cannot allocate abort sequence")
	}
	nextSeq := snap.MaxOperationSequence + 1
	actionID := fmt.Sprintf("act_abort_%s_%d", opID, nextSeq)

	// 3. Obtain original-caller abort authorization grant within live lease
	authAbort, authErr := w.store.AuthorizePackActivationAction(cleanupCtx, contracts.AuthorizePackActivationActionRequest{
		TaskID:                  task.ID.String(),
		OperationID:             opID,
		PackID:                  packID,
		Version:                 version,
		PlanSHA256:              planSHA256,
		Action:                  "abort",
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		ExpectedJournalRevision: jnlRev,
		Audit:                   audit,
	})
	if authErr != nil {
		failErr := w.failInstall(cleanupCtx, task, opID, jnlRev, "waiting_reconcile", "[unknown_abort] authorize abort failed: "+authErr.Error(), audit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on abort auth rejection: %w (original: %v)", failErr, authErr)
		}
		return fmt.Errorf("authorize abort action failed: %w", authErr)
	}

	abortPermit := hosthelper.ActionPermit{
		OperationID:     opID,
		PackID:          packID,
		Version:         version,
		CoreGeneration:  task.CoreGeneration,
		LeaseGeneration: task.LeaseGeneration,
		OwnerID:         task.LeaseOwner,
		Deadline:        authAbort.Deadline,
		ActionID:        actionID,
		Sequence:        nextSeq,
	}

	abortResp, err := w.helper.AbortPending(cleanupCtx, hosthelper.AbortPendingRequest{
		Permit: abortPermit,
		Reason: "cancelled by control plane request",
	})
	if err != nil || !abortResp.Aborted || abortResp.AbortReceiptID == "" {
		// Stop outcome unknown or failed: preserve cancelling state, do NOT claim stopped
		errMsg := "helper abort outcome unknown"
		if err != nil {
			errMsg = err.Error()
		}
		failErr := w.failInstall(cleanupCtx, task, opID, jnlRev, "waiting_reconcile", "[unknown_abort] "+errMsg, audit)
		if failErr != nil {
			return fmt.Errorf("fail pack install on unknown abort: %w (original abort error: %s)", failErr, errMsg)
		}
		return fmt.Errorf("helper abort pending not confirmed: %s", errMsg)
	}

	cancelRecord := contracts.CancelActivationRecord{
		OperationID:             opID,
		TaskID:                  task.ID.String(),
		CoreGeneration:          task.CoreGeneration,
		LeaseGeneration:         task.LeaseGeneration,
		OwnerID:                 task.LeaseOwner,
		Reason:                  "cancelled by control plane request",
		AbortReceiptID:          abortResp.AbortReceiptID,
		UnitName:                unitName,
		InstanceID:              instanceID,
		ObservedStopped:         abortResp.Aborted,
		ObservedStoppedAt:       time.Now().UTC(),
		ExpectedJournalRevision: jnlRev,
		Audit:                   audit,
	}

	if err := w.store.CancelActivation(cleanupCtx, cancelRecord); err != nil {
		return fmt.Errorf("commit cancel activation failed: %w", err)
	}

	log.Printf("install worker: successfully cancelled operation %s", opID)
	return nil
}

func (w *InstallWorker) observeActiveRuntimesOnce() {
	parent := w.ctx
	if parent == nil {
		return
	}
	roundCtx, roundCancel := context.WithTimeout(parent, 2*time.Second)
	defer roundCancel()

	runtimes, err := w.store.ListActiveRuntimes(roundCtx, w.observerCursor, 16)
	if err != nil {
		return
	}
	if len(runtimes) == 0 {
		w.observerCursor = ""
		return
	}

	for _, rt := range runtimes {
		select {
		case <-roundCtx.Done():
			return
		default:
		}

		w.observerCursor = rt.PackID

		probeCtx, probeCancel := context.WithTimeout(roundCtx, 500*time.Millisecond)
		targetStatus := w.probeActiveRuntime(probeCtx, rt)
		probeCancel()

		now := time.Now().UTC()
		if uErr := w.store.UpdateActiveRuntimeStatus(roundCtx, contracts.UpdateActiveRuntimeStatusRequest{
			PackID:              rt.PackID,
			ActivationReceiptID: rt.ActivationReceiptID,
			InstanceID:          rt.InstanceID,
			CoreGeneration:      w.cfg.CoreGeneration,
			RuntimeStatus:       targetStatus,
			ObservedAt:          now,
		}); uErr != nil {
			log.Printf("install worker: update active runtime status for %s failed: %v", rt.PackID, uErr)
		}
	}
}

func (w *InstallWorker) probeActiveRuntime(ctx context.Context, rt contracts.PackActiveRuntimeRecord) string {
	src, err := w.store.GetActivePackSource(ctx, rt.PackID)
	if err != nil || src.InstanceID != rt.InstanceID || src.ActivationReceiptID != rt.ActivationReceiptID {
		return "unknown"
	}

	inst := contracts.PackProtocolInstance{
		InstanceID:         src.InstanceID,
		PackID:             src.PackID,
		Version:            src.ActiveVersion,
		OperationID:        src.OperationID,
		ExecutableSHA256:   src.ExecutableSHA256,
		ExecutablePath:     src.ExecutablePath,
		ProtocolVersion:    "1.0",
		Capabilities:       src.Capabilities,
		ExpectedUID:        src.ExpectedUID,
		ExpectedPID:        src.ExpectedPID,
		ProcessStartTime:   src.ProcessStartIdentity,
		SocketPath:         src.SocketPath,
		CoreGeneration:     src.CoreGeneration,
		InstanceGeneration: src.InstanceGeneration,
	}

	// Single connection: CheckReadinessWithValidator dials the socket, and customValidator runs live PeerAttest on the exact same connection
	health, err := w.dispatcher.CheckReadinessWithValidator(ctx, inst, src.Capabilities, func(pPID int32, pUID uint32) error {
		if pPID != src.ExpectedPID || pUID != src.ExpectedUID {
			return fmt.Errorf("peer identity mismatch: got (%d, %d), want (%d, %d)", pPID, pUID, src.ExpectedPID, src.ExpectedUID)
		}
		obs, hErr := w.helper.ObservePack(ctx, hosthelper.ObservePackRequest{
			PackID: src.PackID,
			PeerAttest: &hosthelper.PeerAttestRequest{
				PID:                   pPID,
				UID:                   pUID,
				ExpectedPackID:        src.PackID,
				ExpectedVersion:       src.ActiveVersion,
				ExpectedInstanceID:    src.InstanceID,
				ExpectedExecutableSHA: src.ExecutableSHA256,
				ExpectedStartTime:     src.ProcessStartIdentity,
			},
		})
		if hErr != nil {
			return hErr
		}
		if obs.PeerAttestResult == nil || !obs.PeerAttestResult.Attested {
			errStr := "attestation failed"
			if obs.PeerAttestResult != nil && obs.PeerAttestResult.Error != "" {
				errStr = obs.PeerAttestResult.Error
			}
			return errors.New(errStr)
		}
		return nil
	})

	if err == nil {
		capMap := make(map[string]bool, len(src.Capabilities))
		for _, c := range src.Capabilities {
			capMap[c] = true
		}
		for _, c := range health.Capabilities {
			if !capMap[c] {
				return "unknown"
			}
		}
		return "ready"
	}

	// Only proved stopped can map to stopped; unknown stays unknown
	obs, hErr := w.helper.ObservePack(ctx, hosthelper.ObservePackRequest{
		PackID: src.PackID,
	})
	if hErr == nil {
		if obs.CancellationSnapshot != nil && obs.CancellationSnapshot.ObservedStopped {
			return "stopped"
		}
		if (obs.UnitStatus == "inactive" || obs.UnitStatus == "failed") && obs.MainPID == 0 {
			return "stopped"
		}
	}
	return "unknown"
}
