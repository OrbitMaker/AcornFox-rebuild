//go:build linux

package packmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/packprotocol"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
)

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func buildTestAdapter(t *testing.T, destPath string) string {
	t.Helper()
	cmd := exec.Command("/home/ubuntu/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.13.linux-amd64/bin/go", "build", "-o", destPath, "./testdata/protocol-adapter")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOTOOLCHAIN=local",
		"GOCACHE=/home/ubuntu/.cache/acornfox-container-execution-20260926/go-cache",
		"GOTMPDIR=/home/ubuntu/.cache/acornfox-container-execution-20260926/tmp",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build test adapter failed: %v, out: %s", err, string(out))
	}
	return destPath
}

func fixturePackSelectionWithAdapter(t *testing.T, s *sqlite.Store, packID string, adapterPath string, adapterSHA string) (packprotocol.VerifiedPackSelection, []byte) {
	t.Helper()
	binding, err := s.InstallationBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	manifestBytes, _ := json.Marshal(packprotocol.Manifest{
		Schema:          "acornfox-pack-manifest-v1",
		PackID:          packID,
		Version:         "1.0.0",
		OS:              "linux",
		Arch:            "amd64",
		MinCoreVersion:  "1.0.0",
		ProtocolVersion: "1.0",
		Capabilities:    []string{packprotocol.CapabilityDiagnosticObserve},
		Dependencies:    []packprotocol.Dependency{},
		Permissions:     []string{},
		Entries: []packprotocol.Entry{
			{Role: "adapter", Path: "bin/adapter"},
		},
		Files: []packprotocol.File{
			{Path: "bin/adapter", SHA256: adapterSHA, Size: 1024, Mode: 0755},
		},
	})

	h := sha256.Sum256(manifestBytes)
	manifestSHA := hex.EncodeToString(h[:])

	catalogPayload, _ := json.Marshal(packprotocol.CatalogPayload{
		Publisher:      "fixture-publisher",
		PackID:         packID,
		Version:        "1.0.0",
		OS:             "linux",
		Arch:           "amd64",
		Sequence:       1,
		ExpiresAt:      time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		ManifestSHA256: manifestSHA,
		ArtifactSHA256: strings.Repeat("b", 64),
		ArtifactSize:   2048,
		ArtifactURL:    "https://fixture-packs.invalid/archive.tgz",
	})
	sig := ed25519.Sign(priv, append([]byte(packprotocol.CatalogSignatureDomain), catalogPayload...))
	envelope, _ := json.Marshal(packprotocol.CatalogEnvelope{
		Schema:    "acornfox-pack-catalog-envelope-v1",
		Payload:   base64.StdEncoding.EncodeToString(catalogPayload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})

	policy := packprotocol.VerificationPolicy{
		Publisher:           "fixture-publisher",
		PublicKey:           pub,
		AllowedHosts:        []string{"fixture-packs.invalid"},
		CoreVersion:         "1.0.0",
		ProtocolVersion:     "1.0",
		OS:                  "linux",
		Arch:                "amd64",
		InstallationBinding: binding,
		Now:                 time.Now().UTC(),
	}

	selected, err := packprotocol.VerifySelection(envelope, manifestBytes, policy)
	if err != nil {
		t.Fatalf("VerifySelection failed: %v", err)
	}
	return selected, manifestBytes
}

func startTestAdapterProcess(t *testing.T, ctx context.Context, adapterBin, socketPath, packID, version, instanceID string) (*exec.Cmd, int32, uint32, string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, adapterBin, "-socket", socketPath, "-pack", packID, "-version", version, "-instance", instanceID)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start adapter: %v", err)
	}

	pid := int32(cmd.Process.Pid)
	uid := uint32(os.Getuid())

	// Wait for socket to become ready
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(socketPath); err != nil {
		_ = syscall.Kill(-int(pid), syscall.SIGKILL)
		t.Fatalf("adapter socket was not created in time: %v", err)
	}

	startTime, err := ReadProcessStartTime(pid)
	if err != nil {
		_ = syscall.Kill(-int(pid), syscall.SIGKILL)
		t.Fatalf("ReadProcessStartTime failed: %v", err)
	}

	return cmd, pid, uid, startTime
}

func TestProtocolProcessLinuxEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(tmpDir, "adapter.sock")
	adapterBin := filepath.Join(tmpDir, "adapter-bin")

	// 1. Build real independent adapter executable
	buildTestAdapter(t, adapterBin)
	adapterSHA, err := sha256File(adapterBin)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Start adapter child process for instance 1
	cmd1, pid1, uid1, startTime1 := startTestAdapterProcess(t, ctx, adapterBin, socketPath, "fixture-live-pack", "1.0.0", "inst-live-01")
	defer func() {
		if cmd1.Process != nil {
			_ = syscall.Kill(-cmd1.Process.Pid, syscall.SIGKILL)
			_ = cmd1.Wait()
		}
	}()

	// Attest process identity
	att, err := AttestLinuxProcess(pid1)
	if err != nil {
		t.Fatalf("AttestLinuxProcess failed: %v", err)
	}
	if att.UID != uid1 || att.ExecutableSHA256 != adapterSHA || att.StartTime != startTime1 {
		t.Fatalf("process attestation mismatch: got UID=%d, SHA=%s; want UID=%d, SHA=%s", att.UID, att.ExecutableSHA256, uid1, adapterSHA)
	}

	// 3. Setup SQLite Store and Plan Pack Install
	cfg := sqlite.Config{
		DataDirectory:       filepath.Join(tmpDir, "sqlite-data"),
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	}
	store, err := sqlite.Open(cfg)
	if err != nil {
		t.Fatalf("sqlite.Open failed: %v", err)
	}
	defer store.Close()

	selection, manifestBytes := fixturePackSelectionWithAdapter(t, store, "fixture-live-pack", adapterBin, adapterSHA)
	planReq := contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         "fixture-live-pack",
			Version:        "1.0.0",
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "plan-key-01",
		},
		Selection: selection,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "live-test",
			Reason:    "planning live test install",
		},
	}
	planRes, err := store.PlanPackInstall(ctx, planReq)
	if err != nil {
		t.Fatalf("PlanPackInstall failed: %v", err)
	}

	// 4. Register live attested instance
	inst, err := store.RegisterPackProtocolInstance(ctx, contracts.RegisterPackProtocolInstanceRequest{
		InstanceID:       "inst-live-01",
		PackID:           "fixture-live-pack",
		OperationID:      planRes.OperationID,
		ExecutablePath:   "bin/adapter",
		ExpectedUID:      uid1,
		ExpectedPID:      pid1,
		ProcessStartTime: startTime1,
		ExecutableSHA256: adapterSHA,
		SocketPath:       socketPath,
		ManifestRaw:      manifestBytes,
	})
	if err != nil {
		t.Fatalf("RegisterPackProtocolInstance failed: %v", err)
	}

	dispatcher := NewProtocolDispatcher(10 * time.Second)

	// Verify Health over Unix socket
	health, err := dispatcher.CheckHealth(ctx, inst)
	if err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
	if health.Status != "ok" || health.InstanceID != "inst-live-01" {
		t.Fatalf("unexpected health response: %+v", health)
	}

	// 5. Begin Diagnostic Check
	inputCtx := contracts.DiagnosticInputContext{
		Action: "observe",
		Target: "system.health",
		Param:  "{\"metrics\": [\"cpu\", \"mem\"]}",
	}

	chkRes, err := store.BeginPackProtocolCheck(ctx, contracts.BeginPackProtocolCheckRequest{
		PackID:         inst.PackID,
		OperationID:    inst.OperationID,
		InstanceID:     inst.InstanceID,
		IdempotencyKey: "chk-live-01",
		Kind:           packprotocol.KindDiagnosticObserve,
		Capability:     packprotocol.CapabilityDiagnosticObserve,
		InputContext:   inputCtx,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "dispatcher-test",
			Reason:    "live diagnostic check",
		},
	})
	if err != nil {
		t.Fatalf("BeginPackProtocolCheck failed: %v", err)
	}

	childTaskID := domain.ID(chkRes.TaskID)

	// Claim child task
	claimNow := time.Now().UTC()
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "live-worker-01",
		Now:   claimNow,
		Kinds: []string{packprotocol.KindDiagnosticObserve},
		LeasePolicy: contracts.LeasePolicy{
			Duration:    30 * time.Second,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed || claimedTask.ID != childTaskID {
		t.Fatalf("ClaimTask failed: claimed=%v, err=%v", claimed, err)
	}

	// 6. Roundtrip: Dispatch -> Compute -> Poll -> Commit -> ACK
	roundtripAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   "live-worker-01",
		Reason:    "execute diagnostic check",
	}
	receipt, err := dispatcher.ExecuteDiagnosticRoundtrip(
		ctx,
		store,
		inst,
		claimedTask,
		inputCtx,
		roundtripAudit,
	)
	if err != nil {
		t.Fatalf("ExecuteDiagnosticRoundtrip failed: %v", err)
	}
	if receipt.Sequence != 1 || receipt.Status != "persisted" {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}

	// 7. Verify GetPackProtocolCheck shows visible results
	checkState, err := store.GetPackProtocolCheck(ctx, childTaskID)
	if err != nil {
		t.Fatalf("GetPackProtocolCheck failed: %v", err)
	}
	if checkState.CancellationRequested {
		t.Fatalf("cancellation requested on normal task")
	}

	taskState, err := store.GetTask(ctx, childTaskID)
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}
	if taskState.State != contracts.TaskCompleted {
		t.Fatalf("expected completed task state, got %v", taskState.State)
	}

	// 8. Replay / redelivery test: resending the EXACT authorized commit request succeeds without duplicate outbox/audit
	eventsBefore, _ := store.FetchOutboxAfter(ctx, 0, 100)
	auditsBefore, _ := store.ListAuditEvidence(ctx, contracts.AuditFilter{})

	// Obtain event from adapter that was previously committed
	polledEvent, err := dispatcher.PollEvent(ctx, inst, childTaskID.String())
	if err != nil {
		t.Fatalf("poll original event: %v", err)
	}
	polledOccurredAt, _ := packprotocol.ParseCanonicalTime(polledEvent.OccurredAt)

	// Resend exact same authorized commit request
	dupReceipt, err := store.CommitPackProtocolEvent(ctx, contracts.CommitPackProtocolEventRequest{
		TaskID:             childTaskID,
		InstanceID:         inst.InstanceID,
		CoreGeneration:     claimedTask.CoreGeneration,
		LeaseGeneration:    claimedTask.LeaseGeneration,
		InstanceGeneration: inst.InstanceGeneration,
		Owner:              claimedTask.LeaseOwner,
		Sequence:           polledEvent.Sequence,
		InputDigest:        chkRes.InputDigest,
		EventDigest:        polledEvent.EventDigest,
		Kind:               packprotocol.KindDiagnosticObserve,
		Observation:        polledEvent.Observation,
		Terminal:           polledEvent.Terminal,
		TerminalStatus:     polledEvent.TerminalStatus,
		TerminalState:      contracts.TaskCompleted,
		OccurredAt:         polledOccurredAt,
		Audit:              roundtripAudit,
		Now:                time.Now().UTC(),
	})
	if err != nil || dupReceipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("replay failed or generated different receipt: %+v, err=%v", dupReceipt, err)
	}

	eventsAfter, _ := store.FetchOutboxAfter(ctx, 0, 100)
	auditsAfter, _ := store.ListAuditEvidence(ctx, contracts.AuditFilter{})
	if len(eventsAfter) != len(eventsBefore) || len(auditsAfter) != len(auditsBefore) {
		t.Fatalf("redelivery manufactured duplicate outbox (%d vs %d) or audit (%d vs %d)", len(eventsAfter), len(eventsBefore), len(auditsAfter), len(auditsBefore))
	}

	// 9. Process identity rejection: wrong PID fails
	wrongInst := inst
	wrongInst.ExpectedPID = pid1 + 9999
	if _, err := dispatcher.CheckHealth(ctx, wrongInst); err == nil {
		t.Fatalf("expected error when connecting with mismatched expected PID")
	}

	// 9b. Fencing verification: for an actively leased task, stale lease generation is rejected by AuthorizePackProtocolDispatch before dispatch
	fencingCheck, err := store.BeginPackProtocolCheck(ctx, contracts.BeginPackProtocolCheckRequest{
		PackID:         inst.PackID,
		OperationID:    inst.OperationID,
		InstanceID:     inst.InstanceID,
		IdempotencyKey: "chk-fencing-test",
		Kind:           packprotocol.KindDiagnosticObserve,
		Capability:     packprotocol.CapabilityDiagnosticObserve,
		InputContext:   inputCtx,
		Audit:          roundtripAudit,
	})
	if err != nil {
		t.Fatalf("fencing check creation failed: %v", err)
	}
	fencingTaskID := domain.ID(fencingCheck.TaskID)
	fencingClaimedTask, claimedFencing, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "live-worker-01",
		Now:   time.Now().UTC(),
		Kinds: []string{packprotocol.KindDiagnosticObserve},
		LeasePolicy: contracts.LeasePolicy{
			Duration:    30 * time.Second,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimedFencing || fencingClaimedTask.ID != fencingTaskID {
		t.Fatalf("claim fencing task failed: claimed=%v, err=%v", claimedFencing, err)
	}

	staleFencingTask := fencingClaimedTask
	staleFencingTask.LeaseGeneration = fencingClaimedTask.LeaseGeneration + 99
	_, err = dispatcher.ExecuteDiagnosticRoundtrip(
		ctx,
		store,
		inst,
		staleFencingTask,
		inputCtx,
		roundtripAudit,
	)
	if err == nil || !strings.Contains(err.Error(), "lease generation mismatch") {
		t.Fatalf("expected stale lease generation rejection before dispatch, got: %v", err)
	}

	// Cleanly terminalize the test fencing task so queue is clean
	if err := store.CancelTask(ctx, contracts.TaskMutationRequest{
		TaskID:          fencingTaskID,
		CoreGeneration:  fencingClaimedTask.CoreGeneration,
		LeaseGeneration: fencingClaimedTask.LeaseGeneration,
		Owner:           "live-worker-01",
		Now:             time.Now().UTC(),
	}); err != nil {
		t.Fatalf("cancel fencing task failed: %v", err)
	}

	// 10. Reopen store (Core generation increment) rejects old generation
	store.Close()
	store2, err := sqlite.Open(cfg)
	if err != nil {
		t.Fatalf("reopen store failed: %v", err)
	}
	defer store2.Close()

	// Attempting mutation with old core generation must fail at Core fencing guard
	staleOccurred := time.Now().UTC()
	staleOccurredStr := packprotocol.FormatCanonicalTime(staleOccurred)
	staleObs := contracts.DiagnosticObservation{
		CheckedAt:   staleOccurredStr,
		InputDigest: chkRes.InputDigest,
		Status:      "healthy",
		Summary:     "stale observation seq 2",
	}
	staleObsDigest, _, _ := packprotocol.DigestDiagnosticObservation(staleObs)
	staleEventDigest := packprotocol.ComputeEventDigest(
		childTaskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration, inst.InstanceGeneration,
		2, packprotocol.KindDiagnosticObserve, chkRes.InputDigest,
		true, "succeeded", staleOccurredStr, staleObsDigest,
	)

	staleCommit := contracts.CommitPackProtocolEventRequest{
		TaskID:             childTaskID,
		InstanceID:         inst.InstanceID,
		CoreGeneration:     claimedTask.CoreGeneration, // genuine old claimed generation 1
		LeaseGeneration:    claimedTask.LeaseGeneration,
		InstanceGeneration: inst.InstanceGeneration,
		Owner:              claimedTask.LeaseOwner,
		Sequence:           2,
		InputDigest:        chkRes.InputDigest,
		EventDigest:        staleEventDigest,
		Kind:               packprotocol.KindDiagnosticObserve,
		Observation:        staleObs,
		Terminal:           true,
		TerminalStatus:     "succeeded",
		TerminalState:      contracts.TaskCompleted,
		OccurredAt:         staleOccurred,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "stale-tester",
			Reason:    "stale test",
		},
		Now: time.Now().UTC(),
	}
	if _, err := store2.CommitPackProtocolEvent(ctx, staleCommit); err == nil || !strings.Contains(err.Error(), "core generation mismatch or stale instance") {
		t.Fatalf("expected old core generation rejection after restart, got: %v", err)
	}

	// Historical check remains readable
	historicalCheck, err := store2.GetPackProtocolCheck(ctx, childTaskID)
	if err != nil || historicalCheck.TaskID != childTaskID {
		t.Fatalf("historical check unreadable after restart: %v", err)
	}

	// 11. Real cancellation test with actual lease claim and sleep action
	// Stop first adapter cleanly before starting second adapter with inst-live-02 identity
	if cmd1.Process != nil {
		_ = syscall.Kill(-cmd1.Process.Pid, syscall.SIGKILL)
		_ = cmd1.Wait()
	}
	_ = os.Remove(socketPath)

	cmd2, pid2, uid2, startTime2 := startTestAdapterProcess(t, ctx, adapterBin, socketPath, "fixture-live-pack", "1.0.0", "inst-live-02")
	defer func() {
		if cmd2.Process != nil {
			_ = syscall.Kill(-cmd2.Process.Pid, syscall.SIGKILL)
			_ = cmd2.Wait()
		}
	}()

	// Register instance 2 with store2 (which is at core generation 2)
	inst2, err := store2.RegisterPackProtocolInstance(ctx, contracts.RegisterPackProtocolInstanceRequest{
		InstanceID:       "inst-live-02",
		PackID:           "fixture-live-pack",
		OperationID:      planRes.OperationID,
		ExecutablePath:   "bin/adapter",
		ExpectedUID:      uid2,
		ExpectedPID:      pid2,
		ProcessStartTime: startTime2,
		ExecutableSHA256: adapterSHA,
		SocketPath:       socketPath,
		ManifestRaw:      manifestBytes,
	})
	if err != nil {
		t.Fatalf("register instance 2 failed: %v", err)
	}

	// Check health of inst-live-02
	health2, err := dispatcher.CheckHealth(ctx, inst2)
	if err != nil || health2.InstanceID != "inst-live-02" {
		t.Fatalf("health check on inst2 failed: %v, health=%+v", err, health2)
	}

	cancelInputCtx := contracts.DiagnosticInputContext{
		Action: "observe.sleep",
		Target: "cancellable.job",
		Param:  "{\"delay_ms\": 500}",
	}

	chk2Res, err := store2.BeginPackProtocolCheck(ctx, contracts.BeginPackProtocolCheckRequest{
		PackID:         inst2.PackID,
		OperationID:    inst2.OperationID,
		InstanceID:     inst2.InstanceID,
		IdempotencyKey: "chk-cancel-live-02",
		Kind:           packprotocol.KindDiagnosticObserve,
		Capability:     packprotocol.CapabilityDiagnosticObserve,
		InputContext:   cancelInputCtx,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "cancel-tester",
			Reason:    "cancellation test",
		},
	})
	if err != nil {
		t.Fatalf("begin check 2 failed: %v", err)
	}

	task2ID := domain.ID(chk2Res.TaskID)

	// Claim task 2 with legitimate worker lease
	claim2Now := time.Now().UTC()
	claimedTask2, claimed2, err := store2.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "live-worker-02",
		Now:   claim2Now,
		Kinds: []string{packprotocol.KindDiagnosticObserve},
		LeasePolicy: contracts.LeasePolicy{
			Duration:    30 * time.Second,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed2 || claimedTask2.ID != task2ID {
		t.Fatalf("ClaimTask 2 failed: claimed=%v, err=%v", claimed2, err)
	}

	// Dispatch task 2 to adapter
	cancelInputDigest, _, _ := packprotocol.DigestDiagnosticInput(cancelInputCtx)
	err = dispatcher.DispatchTask(ctx, inst2, packprotocol.ObserveTaskRequest{
		Schema:             packprotocol.ProtocolSchemaV1,
		ProtocolVersion:    packprotocol.ProtocolVersion1,
		TaskID:             task2ID.String(),
		OperationID:        inst2.OperationID,
		PackID:             inst2.PackID,
		InstanceID:         inst2.InstanceID,
		InstanceGeneration: inst2.InstanceGeneration,
		CoreGeneration:     claimedTask2.CoreGeneration,
		LeaseGeneration:    claimedTask2.LeaseGeneration,
		Kind:               packprotocol.KindDiagnosticObserve,
		Capability:         packprotocol.CapabilityDiagnosticObserve,
		InputDigest:        cancelInputDigest,
		InputContext:       cancelInputCtx,
		Deadline:           packprotocol.FormatCanonicalTime(time.Now().Add(time.Minute)),
	})
	if err != nil {
		t.Fatalf("DispatchTask 2 failed: %v", err)
	}

	// Request cancellation in Core SQLite
	if err := store2.RequestPackProtocolCancellation(ctx, task2ID, "operator abort"); err != nil {
		t.Fatalf("RequestPackProtocolCancellation failed: %v", err)
	}

	// Forward cancel to adapter
	cancelResp, err := dispatcher.RequestCancel(ctx, inst2, packprotocol.CancelTaskRequest{
		Schema:      packprotocol.ProtocolSchemaV1,
		TaskID:      task2ID.String(),
		OperationID: inst2.OperationID,
		InstanceID:  inst2.InstanceID,
		Reason:      "operator abort",
	})
	if err != nil {
		t.Fatalf("RequestCancel failed: %v", err)
	}
	if cancelResp.Status != "cancelling" && cancelResp.Status != "cancelled" {
		t.Fatalf("adapter cancel response status: %s", cancelResp.Status)
	}

	// Repeat cancel request once to verify fixture duplicate cancellation is idempotent and does not panic
	repeatCancelResp, err := dispatcher.RequestCancel(ctx, inst2, packprotocol.CancelTaskRequest{
		Schema:      packprotocol.ProtocolSchemaV1,
		TaskID:      task2ID.String(),
		OperationID: inst2.OperationID,
		InstanceID:  inst2.InstanceID,
		Reason:      "operator abort repeated",
	})
	if err != nil {
		t.Fatalf("repeat RequestCancel failed: %v", err)
	}
	if repeatCancelResp.Status != "cancelling" && repeatCancelResp.Status != "cancelled" {
		t.Fatalf("repeat cancel response status: %s", repeatCancelResp.Status)
	}

	// Poll cancelled event from adapter
	var cancelEvent packprotocol.ObserveTaskEvent
	for i := 0; i < 20; i++ {
		cancelEvent, err = dispatcher.PollEvent(ctx, inst2, task2ID.String())
		if err == nil && cancelEvent.Terminal && cancelEvent.Observation.Status == "cancelled" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cancelEvent.Observation.Status != "cancelled" {
		t.Fatalf("expected cancelled observation event, got: %+v", cancelEvent)
	}

	cancelOccurredAt, err := packprotocol.ParseCanonicalTime(cancelEvent.OccurredAt)
	if err != nil {
		t.Fatalf("parse cancel occurredAt: %v", err)
	}

	// Core commits the cancelled terminal event
	cancelCommitAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   "live-worker-02",
		Reason:    "commit cancelled observation",
	}
	cancelReceipt, err := store2.CommitPackProtocolEvent(ctx, contracts.CommitPackProtocolEventRequest{
		TaskID:             task2ID,
		InstanceID:         inst2.InstanceID,
		CoreGeneration:     claimedTask2.CoreGeneration,
		LeaseGeneration:    claimedTask2.LeaseGeneration,
		InstanceGeneration: inst2.InstanceGeneration,
		Owner:              claimedTask2.LeaseOwner,
		Sequence:           cancelEvent.Sequence,
		InputDigest:        cancelInputDigest,
		EventDigest:        cancelEvent.EventDigest,
		Kind:               packprotocol.KindDiagnosticObserve,
		Observation:        cancelEvent.Observation,
		Terminal:           true,
		TerminalStatus:     "failed",
		TerminalState:      contracts.TaskCancelled,
		OccurredAt:         cancelOccurredAt,
		Audit:              cancelCommitAudit,
		Now:                time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("commit cancelled event failed: %v", err)
	}

	// Send ACK to adapter
	ackErr := dispatcher.AcknowledgeReceipt(ctx, inst2, packprotocol.ObserveTaskAck{
		Schema:      packprotocol.ProtocolSchemaV1,
		ReceiptID:   cancelReceipt.ReceiptID,
		TaskID:      task2ID.String(),
		InstanceID:  inst2.InstanceID,
		Sequence:    cancelEvent.Sequence,
		EventDigest: cancelReceipt.EventDigest,
		Status:      "persisted",
		CommittedAt: packprotocol.FormatCanonicalTime(cancelReceipt.CommittedAt),
	})
	if ackErr != nil {
		t.Fatalf("AcknowledgeReceipt failed: %v", ackErr)
	}

	// Verify task2 is truly TaskCancelled in SQLite
	task2State, err := store2.GetTask(ctx, task2ID)
	if err != nil {
		t.Fatalf("GetTask 2 failed: %v", err)
	}
	if task2State.State != contracts.TaskCancelled {
		t.Fatalf("expected task2 state TaskCancelled, got %v", task2State.State)
	}

	// 12. Invariant verification: original install task/operation/pack state untouched
	parentTaskID := domain.ID(planRes.TaskID)
	parentTask, err := store2.GetTask(ctx, parentTaskID)
	if err != nil || parentTask.State != contracts.TaskReady {
		t.Fatalf("parent install task altered: %+v", parentTask)
	}

	packRec, err := store2.GetPack(ctx, "fixture-live-pack")
	if err != nil || packRec.State != "planned" {
		t.Fatalf("pack record altered from planned: %+v", packRec)
	}

	packIntent, err := store2.GetPackIntent(ctx, planRes.OperationID)
	if err != nil || packIntent.Phase != "planned" {
		t.Fatalf("pack intent altered from planned: %+v", packIntent)
	}
}
