package packmanager

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/hosthelper"
	"github.com/open-card/open-card/internal/packprotocol"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type helperSpy struct {
	callCount       int
	mutationCalls   int
	abortCallCount  int
	abortResponse   hosthelper.AbortPendingResponse
	abortErr        error
	stopResponse    hosthelper.StopPendingResponse
	stopErr         error
	observeResponse *hosthelper.ObservePackResponse
}

func (s *helperSpy) RegisterCore(ctx context.Context, req hosthelper.RegisterCoreRequest) (hosthelper.RegisterCoreResponse, error) {
	s.callCount++
	return hosthelper.RegisterCoreResponse{Registered: true}, nil
}
func (s *helperSpy) PrepareDirs(ctx context.Context, req hosthelper.PrepareDirsRequest) (hosthelper.PrepareDirsResponse, error) {
	s.callCount++
	s.mutationCalls++
	return hosthelper.PrepareDirsResponse{}, nil
}
func (s *helperSpy) PublishPack(ctx context.Context, req hosthelper.PublishPackRequest) (hosthelper.PublishPackResponse, error) {
	s.callCount++
	s.mutationCalls++
	return hosthelper.PublishPackResponse{}, nil
}
func (s *helperSpy) StartPack(ctx context.Context, req hosthelper.StartPackRequest) (hosthelper.StartPackResponse, error) {
	s.callCount++
	s.mutationCalls++
	return hosthelper.StartPackResponse{}, nil
}
func (s *helperSpy) ObservePack(ctx context.Context, req hosthelper.ObservePackRequest) (hosthelper.ObservePackResponse, error) {
	s.callCount++
	if s.observeResponse != nil {
		resp := *s.observeResponse
		if req.PeerAttest != nil {
			resp.PeerAttestResult = &hosthelper.PeerAttestResponse{Attested: true}
		}
		return resp, nil
	}
	resp := hosthelper.ObservePackResponse{UnitStatus: "inactive"}
	if req.PeerAttest != nil {
		resp.PeerAttestResult = &hosthelper.PeerAttestResponse{Attested: true}
	}
	if req.OperationID != "" {
		resp.CancellationSnapshot = &hosthelper.OperationCancellationSnapshot{
			OperationID:          req.OperationID,
			PackID:               req.PackID,
			Version:              req.Version,
			MaxOperationSequence: 1,
			ObservedStopped:      true,
			ObservedAt:           time.Now().UTC(),
		}
	}
	return resp, nil
}
func (s *helperSpy) StopPending(ctx context.Context, req hosthelper.StopPendingRequest) (hosthelper.StopPendingResponse, error) {
	s.callCount++
	return s.stopResponse, s.stopErr
}
func (s *helperSpy) AbortPending(ctx context.Context, req hosthelper.AbortPendingRequest) (hosthelper.AbortPendingResponse, error) {
	s.callCount++
	s.abortCallCount++
	return s.abortResponse, s.abortErr
}
func (s *helperSpy) SwitchCurrent(ctx context.Context, req hosthelper.SwitchCurrentRequest) (hosthelper.SwitchCurrentResponse, error) {
	s.callCount++
	s.mutationCalls++
	return hosthelper.SwitchCurrentResponse{Effect: "created"}, nil
}

func TestInstallWorker_NoJournalCancellation_ZeroHelperCalls(t *testing.T) {
	store, _, _, stagingDir, serverHost, tempDir := setupTestStagingEnvironment(t)
	ctx := context.Background()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "plan no-journal cancel test",
	}

	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-worker-nj-cancel",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	workerID := "worker-nj-test"
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:                  workerID,
		Kinds:                  []string{sqlite.PackInstallTaskKind},
		AllowedOperationStates: []string{"pending", "leased", "running", "cancelling"},
		Now:                    now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    5 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: %v", err)
	}

	// Request cancellation on the operation before any activation journal is written
	err = store.RequestPackInstallCancellation(ctx, contracts.RequestPackInstallCancellationRecord{
		OperationID:              planRes.OperationID,
		ExpectedOperationVersion: 1,
		Reason:                   "user cancel before journal",
		Audit:                    audit,
	})
	if err != nil {
		t.Fatalf("request cancellation: %v", err)
	}

	spy := &helperSpy{}
	workerCfg := InstallWorkerConfig{
		WorkerID:         workerID,
		PollInterval:     time.Second,
		LeaseDuration:    5 * time.Minute,
		StagingDir:       stagingDir,
		PublishedDir:     filepath.Join(tempDir, "packs"),
		StateDir:         filepath.Join(tempDir, "state"),
		RunDir:           filepath.Join(tempDir, "run"),
		CoreUID:          uint32(os.Getuid()),
		CoreGID:          uint32(os.Getgid()),
		CoreGeneration:   store.CoreGeneration(),
		HelperSocketPath: filepath.Join(tempDir, "helper.sock"),
		Policies: map[string]packprotocol.VerificationPolicy{
			fixture.policy.Publisher: fixture.policy,
		},
	}

	worker, err := newInstallWorkerWithHelper(store, workerCfg, spy)
	if err != nil {
		t.Fatalf("new install worker: %v", err)
	}
	defer worker.Stop()

	// Execute task: since operation is cancelling before journal creation (NoJournal),
	// worker must converge to cancellation with ZERO helper calls and no network download!
	if err := worker.executeTask(ctx, claimedTask); err != nil {
		t.Fatalf("execute task under cancelling operation failed: %v", err)
	}

	// 1. Assert ZERO helper calls occurred
	if spy.callCount != 0 {
		t.Fatalf("expected 0 helper calls on NoJournal cancellation, got %d", spy.callCount)
	}

	// 2. Assert task lease was terminally cancelled in SQLite repository
	finalTask, err := store.GetTask(ctx, claimedTask.ID)
	if err != nil {
		t.Fatalf("get final task: %v", err)
	}
	if finalTask.State != contracts.TaskCancelled || finalTask.LeaseOwner != "" {
		t.Fatalf("expected task cancelled with cleared owner, got state=%s owner=%v", finalTask.State, finalTask.LeaseOwner)
	}

	// 3. Assert outbox contains cancellation event
	events, err := store.FetchOutboxAfter(ctx, 0, 10)
	if err != nil {
		t.Fatalf("fetch outbox: %v", err)
	}
	foundCancelEvent := false
	for _, e := range events {
		if e.AggregateID == planRes.OperationID && (e.EventType == "pack.activation.cancelled" || strings.Contains(e.EventType, "cancelled")) {
			foundCancelEvent = true
			break
		}
	}
	if !foundCancelEvent {
		t.Fatal("expected cancellation outbox event recorded")
	}
}

func TestInstallWorker_PendingJournal_UnconfirmedAbort_PreservesCancellingNonterminal(t *testing.T) {
	store, server, client, stagingDir, serverHost, tempDir := setupTestStagingEnvironment(t)
	ctx := context.Background()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	// Serve fixture archive bytes via test HTTP server
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture.archiveData)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "plan abort test",
	}

	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-unconfirmed-abort",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	workerID := "worker-unconf"
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:                  workerID,
		Kinds:                  []string{sqlite.PackInstallTaskKind},
		AllowedOperationStates: []string{"pending", "leased", "running", "cancelling"},
		Now:                    now,
		LeasePolicy:            contracts.LeasePolicy{Duration: 5 * time.Minute, MaxAttempts: 3},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: %v", err)
	}

	workerAudit := contracts.AuditContext{ActorType: "system", ActorID: workerID, Reason: "progress"}

	// Stage artifact with real fixture and obtain real A receipt
	stager, err := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})
	if err != nil {
		t.Fatalf("new artifact stager: %v", err)
	}
	realReceipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           workerAudit,
	})
	if err != nil {
		t.Fatalf("stage artifact: %v", err)
	}

	// Create real initial journal with ExpectedJournalRevision: 0 and real receipt ID
	_, err = store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  fixture.packID,
		Version:                 fixture.version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       realReceipt.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-1",
		InstalledRoot:           filepath.Join(tempDir, "packs", fixture.packID, fixture.version),
		UnitName:                "acornfox-pack-" + fixture.packID + ".service",
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("create real initial journal failed: %v", err)
	}

	// Request cancellation
	err = store.RequestPackInstallCancellation(ctx, contracts.RequestPackInstallCancellationRecord{
		OperationID:              planRes.OperationID,
		ExpectedOperationVersion: 1,
		Reason:                   "cancel with pending journal",
		Audit:                    audit,
	})
	if err != nil {
		t.Fatalf("request cancellation failed: %v", err)
	}

	// Spy simulates helper network timeout on AbortPending (unconfirmed abort outcome)
	spy := &helperSpy{
		abortErr: errors.New("helper network timeout"),
	}

	workerCfg := InstallWorkerConfig{
		WorkerID:         workerID,
		PollInterval:     time.Second,
		LeaseDuration:    5 * time.Minute,
		StagingDir:       stagingDir,
		PublishedDir:     filepath.Join(tempDir, "packs"),
		StateDir:         filepath.Join(tempDir, "state"),
		RunDir:           filepath.Join(tempDir, "run"),
		CoreUID:          uint32(os.Getuid()),
		CoreGID:          uint32(os.Getgid()),
		CoreGeneration:   store.CoreGeneration(),
		HelperSocketPath: filepath.Join(tempDir, "helper.sock"),
		Policies: map[string]packprotocol.VerificationPolicy{
			fixture.policy.Publisher: fixture.policy,
		},
	}

	worker, err := newInstallWorkerWithHelper(store, workerCfg, spy)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Stop()

	// Execute task: helper abort fails/times out, worker must return error
	execErr := worker.executeTask(ctx, claimedTask)
	if execErr == nil {
		t.Fatal("expected executeTask to return error on unconfirmed abort")
	}

	// 1. Helper was called specifically for abort
	if spy.abortCallCount != 1 {
		t.Fatalf("expected 1 helper abort call, got %d (total calls: %d)", spy.abortCallCount, spy.callCount)
	}

	// 2. Task must be released to 'ready' with cleared owner/deadline and unknown_abort error recorded
	taskPost, err := store.GetTask(ctx, claimedTask.ID)
	if err != nil {
		t.Fatalf("get post task failed: %v", err)
	}
	if taskPost.State != contracts.TaskReady || taskPost.LeaseOwner != "" || !strings.Contains(taskPost.LastError, "unknown_abort") {
		t.Fatalf("expected task released to ready with unknown_abort error, got state=%s owner=%v lastErr=%v", taskPost.State, taskPost.LeaseOwner, taskPost.LastError)
	}

	// 3. Journal failure reason must record unknown_abort and revision advanced
	jnlPost, err := store.GetActivationJournal(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get post journal failed: %v", err)
	}
	if !strings.Contains(jnlPost.FailureReason, "unknown_abort") || jnlPost.Revision < 2 {
		t.Fatalf("expected journal revision >= 2 with failure_reason unknown_abort, got rev=%d reason=%s", jnlPost.Revision, jnlPost.FailureReason)
	}

	// 4. Outbox events must NOT contain terminal pack.activation.cancelled (remains non-terminal / retryable!)
	events, err := store.FetchOutboxAfter(ctx, 0, 10)
	if err != nil {
		t.Fatalf("fetch outbox failed: %v", err)
	}
	for _, e := range events {
		if e.AggregateID == planRes.OperationID && e.EventType == "pack.activation.cancelled" {
			t.Fatal("expected nonterminal state on unconfirmed abort; terminal cancelled event must NOT be committed")
		}
	}
}

func TestInstallWorker_ReadyJournalRecovery_DirectCommitWithoutMutations(t *testing.T) {
	store, server, client, stagingDir, serverHost, tempDir := setupTestStagingEnvironment(t)
	ctx := context.Background()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	fixture := createTestFixturePack(t, "fixture-ready-recovery", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	// Serve fixture archive bytes via test HTTP server
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture.archiveData)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "plan ready recovery test",
	}

	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-ready-recovery",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	workerID := "worker-ready"
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:                  workerID,
		Kinds:                  []string{sqlite.PackInstallTaskKind},
		AllowedOperationStates: []string{"pending", "leased", "running", "cancelling"},
		Now:                    now,
		LeasePolicy:            contracts.LeasePolicy{Duration: 5 * time.Minute, MaxAttempts: 3},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: %v", err)
	}

	workerAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   workerID,
		Reason:    "worker progress",
	}

	// Stage artifact with real fixture and obtain real A receipt
	stager, err := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})
	if err != nil {
		t.Fatalf("new artifact stager: %v", err)
	}
	realReceipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           workerAudit,
	})
	if err != nil {
		t.Fatalf("stage artifact: %v", err)
	}

	// Progress journal legally: publishing -> starting -> ready
	installedRoot := filepath.Join(tempDir, "packs", fixture.packID, fixture.version)
	sockPath := filepath.Join(tempDir, "a.sock")
	pubRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  fixture.packID,
		Version:                 fixture.version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       realReceipt.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-ready",
		InstalledRoot:           installedRoot,
		UnitName:                "acornfox-pack-" + fixture.packID + ".service",
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record publishing journal: %v", err)
	}

	curPID := int32(os.Getpid())
	startRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  fixture.packID,
		Version:                 fixture.version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       realReceipt.ReceiptID,
		Phase:                   "starting",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-ready",
		InstalledRoot:           installedRoot,
		UnitName:                "acornfox-pack-" + fixture.packID + ".service",
		InstanceID:              "inst-ready-01",
		MainPID:                 curPID,
		SocketPath:              sockPath,
		ProcessStartIdentity:    "991122",
		CandidateCapabilities:   []string{"echo.run"},
		ExpectedJournalRevision: pubRev,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record starting journal: %v", err)
	}

	_, err = store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  fixture.packID,
		Version:                 fixture.version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       realReceipt.ReceiptID,
		Phase:                   "ready",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-ready",
		InstalledRoot:           installedRoot,
		UnitName:                "acornfox-pack-" + fixture.packID + ".service",
		InstanceID:              "inst-ready-01",
		MainPID:                 curPID,
		SocketPath:              sockPath,
		ProcessStartIdentity:    "991122",
		CandidateCapabilities:   []string{"echo.run"},
		CurrentPointerEffect:    "created",
		ActivationGeneration:    1,
		ExpectedJournalRevision: startRev,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record ready journal: %v", err)
	}

	// 1. Setup mock unix socket responding to readiness
	_ = os.MkdirAll(filepath.Dir(sockPath), 0755)
	_ = os.Remove(sockPath)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(packprotocol.HealthResponse{
				Schema:          packprotocol.ProtocolSchemaV1,
				ProtocolVersion: packprotocol.ProtocolVersion1,
				PackID:          fixture.packID,
				Version:         fixture.version,
				InstanceID:      "inst-ready-01",
				Status:          "serving",
				Capabilities:    []string{"echo.run"},
			})
		}),
	}
	go srv.Serve(l)
	defer srv.Close()

	// 2. Setup current symlink
	packPubDir := filepath.Join(tempDir, "packs", fixture.packID)
	_ = os.MkdirAll(filepath.Join(packPubDir, fixture.version), 0755)
	_ = os.Remove(filepath.Join(packPubDir, "current"))
	_ = os.Symlink(fixture.version, filepath.Join(packPubDir, "current"))

	// 3. Setup spy observe response with matching StartEffect and SwitchEffect
	spy := &helperSpy{
		observeResponse: &hosthelper.ObservePackResponse{
			Active:     true,
			UnitStatus: "active",
			MainPID:    curPID,
			CancellationSnapshot: &hosthelper.OperationCancellationSnapshot{
				OperationID:          planRes.OperationID,
				PackID:               fixture.packID,
				Version:              fixture.version,
				MaxOperationSequence: 2,
				ObservedStopped:      false,
				ObservedAt:           time.Now().UTC(),
				UID:                  uint32(os.Getuid()),
				StartEffect: &hosthelper.HelperEffectReceipt{
					ActionID:         "act_start_1",
					OperationID:      planRes.OperationID,
					PackID:           fixture.packID,
					Version:          fixture.version,
					Action:           hosthelper.ActionStart,
					Status:           hosthelper.StatusSucceeded,
					Sequence:         1,
					InstanceID:       "inst-ready-01",
					MainPID:          curPID,
					ProcessStartTime: "991122",
					SocketPath:       sockPath,
					ExecutablePath:   filepath.Join(installedRoot, "bin/adapter"),
					ExecutableSHA:    realReceipt.ExecutableSHA256,
				},
				SwitchEffect: &hosthelper.HelperEffectReceipt{
					ActionID:      "act_switch_2",
					OperationID:   planRes.OperationID,
					PackID:        fixture.packID,
					Version:       fixture.version,
					Action:        hosthelper.ActionSwitch,
					Status:        hosthelper.StatusSucceeded,
					Sequence:      2,
					CurrentTarget: fixture.version,
				},
			},
		},
	}
	workerCfg := InstallWorkerConfig{
		WorkerID:         workerID,
		PollInterval:     time.Second,
		LeaseDuration:    5 * time.Minute,
		StagingDir:       stagingDir,
		PublishedDir:     filepath.Join(tempDir, "packs"),
		StateDir:         filepath.Join(tempDir, "state"),
		RunDir:           filepath.Join(tempDir, "run"),
		CoreUID:          uint32(os.Getuid()),
		CoreGID:          uint32(os.Getgid()),
		CoreGeneration:   store.CoreGeneration(),
		HelperSocketPath: filepath.Join(tempDir, "helper.sock"),
		Policies: map[string]packprotocol.VerificationPolicy{
			fixture.policy.Publisher: fixture.policy,
		},
	}
	worker, err := newInstallWorkerWithHelper(store, workerCfg, spy)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Stop()

	// Execute task: worker must detect ready journal, skip prepare/publish/start mutations, and commit activation directly!
	mutationsBefore := spy.mutationCalls
	if err := worker.executeTask(ctx, claimedTask); err != nil {
		t.Fatalf("executeTask ready recovery failed: %v", err)
	}
	if spy.mutationCalls != mutationsBefore {
		t.Fatalf("expected zero mutation calls during ready recovery, got %d mutations", spy.mutationCalls-mutationsBefore)
	}

	// Verify activation receipt was committed
	actRcpt, err := store.GetActivationReceipt(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get activation receipt after ready recovery: %v", err)
	}
	if actRcpt.InstanceID != "inst-ready-01" || actRcpt.MainPID != curPID {
		t.Fatalf("unexpected activation receipt: %+v", actRcpt)
	}

	// Task lease must be completed
	taskPost, err := store.GetTask(ctx, claimedTask.ID)
	if err != nil {
		t.Fatalf("get task failed: %v", err)
	}
	if taskPost.State != contracts.TaskCompleted {
		t.Fatalf("expected task completed, got: %s", taskPost.State)
	}
}
