package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func TestPackActivationLifecycle(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DataDirectory:       tempDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	}
	store, err := Open(cfg)
	if err != nil {
		t.Fatalf("open store failed: %v", err)
	}
	defer store.Close()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatalf("installation binding failed: %v", err)
	}

	packID := "test-pack-activation"
	ver := "1.0.0"
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	selection, _, manBytes := makeTestVerifiedSelection(t, packID, ver, binding, now, 1, exp)

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install activation test",
	}

	intent := contracts.PackInstallIntent{
		PackID:         packID,
		Version:        ver,
		OS:             "linux",
		Arch:           "amd64",
		IdempotencyKey: "idem-activation-1",
	}
	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent:    intent,
		Selection: selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	workerID := "worker-1"
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: workerID,
		Kinds: []string{PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: %v", err)
	}

	workerAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   workerID,
		Reason:    "worker activation progress",
	}

	// 1. Stage and commit artifact receipt (TP02A)
	snap, _, _ := selection.Snapshot()
	stageIntent := contracts.StageArtifactIntent{
		OperationID:            planRes.OperationID,
		TaskID:                 claimedTask.ID.String(),
		PackID:                 planRes.PackID,
		Version:                planRes.Version,
		PlanSHA256:             planRes.PlanSHA256,
		CoreGeneration:         claimedTask.CoreGeneration,
		LeaseGeneration:        claimedTask.LeaseGeneration,
		OwnerID:                claimedTask.LeaseOwner,
		StageDirectory:         "staging/" + planRes.OperationID,
		AuthorityCatalogSHA256: snap.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  workerAudit,
	}
	rev, err := store.RecordStageIntent(ctx, stageIntent)
	if err != nil {
		t.Fatalf("record stage intent: %v", err)
	}

	rcptID, _ := domain.NewID("rcpt")
	artRcpt := contracts.PackArtifactReceipt{
		ReceiptID:          rcptID.String(),
		OperationID:        planRes.OperationID,
		PackID:             planRes.PackID,
		Version:            planRes.Version,
		PlanSHA256:         planRes.PlanSHA256,
		ArchiveSHA256:      snap.ArtifactSHA256,
		ManifestSHA256:     snap.ManifestSHA256,
		ExecutableSHA256:   strings.Repeat("a", 64),
		ExecutablePath:     "bin/adapter",
		CatalogSHA256:      snap.CatalogSHA256,
		CatalogSequence:    1,
		ArchiveSize:        snap.ArtifactSize,
		UnpackedTotalBytes: int64(len(manBytes)) + 42,
		RelativeStagePath:  "staging/" + planRes.OperationID,
		StageIdentity:      "stage-ident-1",
		MemberCount:        2,
		VerifiedAt:         now,
		CreatedAt:          now,
	}
	if err := store.CommitArtifactReceipt(ctx, contracts.CommitArtifactReceiptRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 artRcpt,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: rev,
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("commit artifact receipt: %v", err)
	}

	// 2. Fencing: cannot commit activation before journal is in ready phase
	actRcptID, _ := domain.NewID("actrcpt")
	actRcpt := contracts.PackActivationReceipt{
		ReceiptID:             actRcptID.String(),
		OperationID:           planRes.OperationID,
		PackID:                planRes.PackID,
		Version:               planRes.Version,
		PlanSHA256:            planRes.PlanSHA256,
		ArtifactReceiptID:     artRcpt.ReceiptID,
		InstalledRoot:         "/opt/acornfox/packs/" + packID + "/" + ver,
		RelativeCurrentTarget: ver,
		UnitName:              "acornfox-pack-" + packID + ".service",
		ServiceIdentity:       "systemd:acornfox-pack-" + packID + ".service",
		InstanceID:            "inst-001",
		MainPID:               12345,
		ProcessStartIdentity:  "558222",
		SocketPath:            "/run/acornfox/packs/" + packID + "/adapter.sock",
		Capabilities:          []string{"echo.run"},
		ActivationGeneration:  1,
		ActivatedAt:           now,
		CreatedAt:             now,
	}
	badPrematureCommit := contracts.CommitActivationRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 actRcpt,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: 1,
		Audit:                   workerAudit,
	}
	if err := store.CommitActivation(ctx, badPrematureCommit); err == nil || !strings.Contains(err.Error(), "ready activation journal") {
		t.Fatalf("expected error on premature commit without ready journal, got %v", err)
	}

	// 3. Activation Journal progression: publishing -> starting -> ready
	// Step A: publishing (must have ExpectedJournalRevision == 0)
	actIntent1 := contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  planRes.PackID,
		Version:                 planRes.Version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       artRcpt.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub_" + planRes.OperationID,
		InstalledRoot:           actRcpt.InstalledRoot,
		UnitName:                actRcpt.UnitName,
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	}
	actRev1, err := store.RecordActivationJournal(ctx, actIntent1)
	if err != nil {
		t.Fatalf("record activation journal publishing: %v", err)
	}
	if actRev1 != 1 {
		t.Fatalf("expected journal rev 1, got %d", actRev1)
	}

	// Step B: starting
	actIntent2 := actIntent1
	actIntent2.Phase = "starting"
	actIntent2.ExpectedJournalRevision = actRev1
	actIntent2.InstanceID = actRcpt.InstanceID
	actIntent2.MainPID = actRcpt.MainPID
	actIntent2.SocketPath = actRcpt.SocketPath
	actIntent2.ProcessStartIdentity = actRcpt.ProcessStartIdentity
	actIntent2.CandidateCapabilities = []string{"echo.run"}
	actRev2, err := store.RecordActivationJournal(ctx, actIntent2)
	if err != nil {
		t.Fatalf("record activation journal starting: %v", err)
	}
	if actRev2 != 2 {
		t.Fatalf("expected journal rev 2, got %d", actRev2)
	}

	// Step C: ready
	actIntent3 := actIntent2
	actIntent3.Phase = "ready"
	actIntent3.CurrentPointerEffect = "created"
	actIntent3.ActivationGeneration = 1
	actIntent3.ExpectedJournalRevision = actRev2
	actRev3, err := store.RecordActivationJournal(ctx, actIntent3)
	if err != nil {
		t.Fatalf("record activation journal ready: %v", err)
	}
	if actRev3 != 3 {
		t.Fatalf("expected journal rev 3, got %d", actRev3)
	}

	// Verify journal is ready
	jnl, err := store.GetActivationJournal(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get activation journal: %v", err)
	}
	if jnl.Phase != "ready" || jnl.Revision != 3 {
		t.Fatalf("unexpected journal contents: %+v", jnl)
	}

	// 4. Fencing checks on CommitActivation
	// 4a. Wrong lease gen
	badCommit := contracts.CommitActivationRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 actRcpt,
		ExpectedUID:             1000,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration + 1,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: actRev3,
		Audit:                   workerAudit,
	}
	if err := store.CommitActivation(ctx, badCommit); err == nil || !strings.Contains(err.Error(), "lease generation mismatch") {
		t.Fatalf("expected lease generation mismatch, got %v", err)
	}

	// 4b. Wrong expected revision
	badCommitRev := contracts.CommitActivationRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 actRcpt,
		ExpectedUID:             1000,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: actRev3 + 99,
		Audit:                   workerAudit,
	}
	if err := store.CommitActivation(ctx, badCommitRev); err == nil || !strings.Contains(err.Error(), "revision conflict") {
		t.Fatalf("expected journal revision conflict, got %v", err)
	}

	// 4c. Missing ExpectedUID must be rejected (no fallback to Core UID!)
	badCommitUID := contracts.CommitActivationRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 actRcpt,
		ExpectedUID:             0,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: actRev3,
		Audit:                   workerAudit,
	}
	if err := store.CommitActivation(ctx, badCommitUID); err == nil || !strings.Contains(err.Error(), "expected UID must be non-zero") {
		t.Fatalf("expected zero UID rejection, got %v", err)
	}

	// 5. Valid CommitActivation
	validCommit := contracts.CommitActivationRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 actRcpt,
		ExpectedUID:             1000,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: actRev3,
		Audit:                   workerAudit,
	}
	if err := store.CommitActivation(ctx, validCommit); err != nil {
		t.Fatalf("commit activation: %v", err)
	}

	// 6. Verify terminal lease semantics: lease_owner and leased_until must be NULL
	var leaseOwner, leaseUntil sql.NullString
	var leaseState string
	err = store.db.QueryRowContext(ctx, `SELECT state, lease_owner, lease_until FROM task_leases WHERE task_id=?`, claimedTask.ID.String()).Scan(&leaseState, &leaseOwner, &leaseUntil)
	if err != nil {
		t.Fatalf("query completed task lease: %v", err)
	}
	if leaseState != "completed" || leaseOwner.Valid || leaseUntil.Valid {
		t.Fatalf("expected completed task lease with cleared owner/until, got state=%s owner=%v until=%v", leaseState, leaseOwner, leaseUntil)
	}

	// 7. Verify activation receipt and active runtime
	savedRcpt, err := store.GetActivationReceipt(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get activation receipt: %v", err)
	}
	if savedRcpt.ReceiptID != actRcpt.ReceiptID || savedRcpt.Version != ver {
		t.Fatalf("unexpected activation receipt: %+v", savedRcpt)
	}

	runtime, err := store.GetActiveRuntime(ctx, packID)
	if err != nil {
		t.Fatalf("get active runtime: %v", err)
	}
	if runtime.ActiveVersion != ver || runtime.RuntimeStatus != "ready" || runtime.InstanceID != "inst-001" || runtime.CoreGeneration != claimedTask.CoreGeneration {
		t.Fatalf("unexpected active runtime: %+v", runtime)
	}

	// 8. Verify Unified Pack Status
	status, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("get unified status: %v", err)
	}
	if status.IntentPhase != "planned" || status.ArtifactStatus != "artifact_verified" ||
		status.InstalledVersion != ver || !status.RuntimeReady || status.RuntimeStatus != "ready" {
		t.Fatalf("unexpected unified status: %+v", status)
	}

	// 9. Verify triggers: activation receipt is immutable
	_, err = store.db.ExecContext(ctx, `UPDATE pack_activation_receipts SET version='2.0.0' WHERE receipt_id=?`, actRcpt.ReceiptID)
	if err == nil {
		t.Fatal("expected update on pack_activation_receipts to fail")
	}
	_, err = store.db.ExecContext(ctx, `DELETE FROM pack_activation_receipts WHERE receipt_id=?`, actRcpt.ReceiptID)
	if err == nil {
		t.Fatal("expected delete on pack_activation_receipts to fail")
	}

	// 10. UpdateActiveRuntimeStatus guards: wrong CoreGeneration is rejected
	obsTime := time.Now().UTC()
	badUpdateCore := contracts.UpdateActiveRuntimeStatusRequest{
		PackID:              packID,
		ActivationReceiptID: actRcpt.ReceiptID,
		InstanceID:          "inst-001",
		CoreGeneration:      claimedTask.CoreGeneration + 1, // mismatch with store.coreGeneration
		RuntimeStatus:       "stopped",
		ObservedAt:          obsTime,
	}
	if err := store.UpdateActiveRuntimeStatus(ctx, badUpdateCore); err == nil || !strings.Contains(err.Error(), "core generation mismatch") {
		t.Fatalf("expected core generation mismatch, got %v", err)
	}

	// Valid UpdateActiveRuntimeStatus to stopped
	validUpdate := contracts.UpdateActiveRuntimeStatusRequest{
		PackID:              packID,
		ActivationReceiptID: actRcpt.ReceiptID,
		InstanceID:          "inst-001",
		CoreGeneration:      store.coreGeneration,
		RuntimeStatus:       "stopped",
		ObservedAt:          obsTime,
	}
	if err := store.UpdateActiveRuntimeStatus(ctx, validUpdate); err != nil {
		t.Fatalf("valid update active runtime status: %v", err)
	}
	statusStopped, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("get unified status after stop: %v", err)
	}
	if statusStopped.RuntimeReady || statusStopped.RuntimeStatus != "stopped" {
		t.Fatalf("expected runtime not ready and status stopped, got: %+v", statusStopped)
	}

	// 11. B cannot overwrite active pack with a different version (must require TP02C)
	ver2 := "2.0.0"
	selection2, _, manBytes2 := makeTestVerifiedSelection(t, packID, ver2, binding, now, 2, exp)
	planRes2, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         packID,
			Version:        ver2,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-activation-2",
		},
		Selection: selection2,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install ver2: %v", err)
	}

	claim2, claimed2, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: workerID,
		Kinds: []string{PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed2 {
		t.Fatalf("claim task for ver2: %v", err)
	}

	snap2, _, _ := selection2.Snapshot()
	stageRev2, err := store.RecordStageIntent(ctx, contracts.StageArtifactIntent{
		OperationID:            planRes2.OperationID,
		TaskID:                 claim2.ID.String(),
		PackID:                 planRes2.PackID,
		Version:                planRes2.Version,
		PlanSHA256:             planRes2.PlanSHA256,
		CoreGeneration:         claim2.CoreGeneration,
		LeaseGeneration:        claim2.LeaseGeneration,
		OwnerID:                claim2.LeaseOwner,
		StageDirectory:         "staging/" + planRes2.OperationID,
		AuthorityCatalogSHA256: snap2.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  workerAudit,
	})
	if err != nil {
		t.Fatalf("record stage intent ver2: %v", err)
	}

	rcptID2, _ := domain.NewID("rcpt")
	artRcpt2 := contracts.PackArtifactReceipt{
		ReceiptID:          rcptID2.String(),
		OperationID:        planRes2.OperationID,
		PackID:             planRes2.PackID,
		Version:            planRes2.Version,
		PlanSHA256:         planRes2.PlanSHA256,
		ArchiveSHA256:      snap2.ArtifactSHA256,
		ManifestSHA256:     snap2.ManifestSHA256,
		ExecutableSHA256:   strings.Repeat("a", 64),
		ExecutablePath:     "bin/adapter",
		CatalogSHA256:      snap2.CatalogSHA256,
		CatalogSequence:    2,
		ArchiveSize:        snap2.ArtifactSize,
		UnpackedTotalBytes: int64(len(manBytes2)) + 42,
		RelativeStagePath:  "staging/" + planRes2.OperationID,
		StageIdentity:      "stage-ident-2",
		MemberCount:        2,
		VerifiedAt:         now,
		CreatedAt:          now,
	}
	if err := store.CommitArtifactReceipt(ctx, contracts.CommitArtifactReceiptRecord{
		TaskID:                  claim2.ID.String(),
		Receipt:                 artRcpt2,
		CoreGeneration:          claim2.CoreGeneration,
		LeaseGeneration:         claim2.LeaseGeneration,
		OwnerID:                 claim2.LeaseOwner,
		ExpectedJournalRevision: stageRev2,
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("commit artifact receipt ver2: %v", err)
	}

	// Progress ver2 journal to ready
	actRev2_1, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes2.OperationID,
		TaskID:                  claim2.ID.String(),
		PackID:                  planRes2.PackID,
		Version:                 planRes2.Version,
		PlanSHA256:              planRes2.PlanSHA256,
		ArtifactReceiptID:       artRcpt2.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          claim2.CoreGeneration,
		LeaseGeneration:         claim2.LeaseGeneration,
		OwnerID:                 claim2.LeaseOwner,
		PublishID:               "pub_" + planRes2.OperationID,
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver2,
		UnitName:                "acornfox-pack-" + packID + ".service",
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record journal ver2 publishing: %v", err)
	}

	actRev2_2, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes2.OperationID,
		TaskID:                  claim2.ID.String(),
		PackID:                  planRes2.PackID,
		Version:                 planRes2.Version,
		PlanSHA256:              planRes2.PlanSHA256,
		ArtifactReceiptID:       artRcpt2.ReceiptID,
		Phase:                   "starting",
		CoreGeneration:          claim2.CoreGeneration,
		LeaseGeneration:         claim2.LeaseGeneration,
		OwnerID:                 claim2.LeaseOwner,
		PublishID:               "pub_" + planRes2.OperationID,
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver2,
		UnitName:                "acornfox-pack-" + packID + ".service",
		InstanceID:              "inst-002",
		MainPID:                 12346,
		SocketPath:              "/run/acornfox/packs/" + packID + "/adapter.sock",
		ProcessStartIdentity:    "558223",
		CandidateCapabilities:   []string{"echo.run"},
		ExpectedJournalRevision: actRev2_1,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record journal ver2 starting: %v", err)
	}

	actRev2_3, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes2.OperationID,
		TaskID:                  claim2.ID.String(),
		PackID:                  planRes2.PackID,
		Version:                 planRes2.Version,
		PlanSHA256:              planRes2.PlanSHA256,
		ArtifactReceiptID:       artRcpt2.ReceiptID,
		Phase:                   "ready",
		CoreGeneration:          claim2.CoreGeneration,
		LeaseGeneration:         claim2.LeaseGeneration,
		OwnerID:                 claim2.LeaseOwner,
		PublishID:               "pub_" + planRes2.OperationID,
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver2,
		UnitName:                "acornfox-pack-" + packID + ".service",
		InstanceID:              "inst-002",
		MainPID:                 12346,
		SocketPath:              "/run/acornfox/packs/" + packID + "/adapter.sock",
		ProcessStartIdentity:    "558223",
		CandidateCapabilities:   []string{"echo.run"},
		CurrentPointerEffect:    "created",
		ActivationGeneration:    2,
		ExpectedJournalRevision: actRev2_2,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record journal ver2 ready: %v", err)
	}

	actRcptID2, _ := domain.NewID("actrcpt")
	diffVerCommit := contracts.CommitActivationRecord{
		TaskID: claim2.ID.String(),
		Receipt: contracts.PackActivationReceipt{
			ReceiptID:             actRcptID2.String(),
			OperationID:           planRes2.OperationID,
			PackID:                planRes2.PackID,
			Version:               ver2,
			PlanSHA256:            planRes2.PlanSHA256,
			ArtifactReceiptID:     artRcpt2.ReceiptID,
			InstalledRoot:         "/opt/acornfox/packs/" + packID + "/" + ver2,
			RelativeCurrentTarget: ver2,
			UnitName:              "acornfox-pack-" + packID + ".service",
			ServiceIdentity:       "systemd:acornfox-pack-" + packID + ".service",
			InstanceID:            "inst-002",
			MainPID:               12346,
			ProcessStartIdentity:  "558223",
			SocketPath:            "/run/acornfox/packs/" + packID + "/adapter.sock",
			Capabilities:          []string{"echo.run"},
			ActivationGeneration:  2,
			ActivatedAt:           now,
			CreatedAt:             now,
		},
		CoreGeneration:          claim2.CoreGeneration,
		LeaseGeneration:         claim2.LeaseGeneration,
		OwnerID:                 claim2.LeaseOwner,
		ExpectedJournalRevision: actRev2_3,
		ExpectedUID:             1000,
		Audit:                   workerAudit,
	}
	if err := store.CommitActivation(ctx, diffVerCommit); err == nil || !strings.Contains(err.Error(), "requires TP02C") {
		t.Fatalf("expected error rejecting multi-version upgrade in TP02B, got %v", err)
	}

	// 12. Test ListActiveRuntimes keyset pagination
	runtimes, err := store.ListActiveRuntimes(ctx, "", 16)
	if err != nil {
		t.Fatalf("list active runtimes failed: %v", err)
	}
	if len(runtimes) != 1 || runtimes[0].PackID != packID {
		t.Fatalf("expected 1 active runtime for %s, got %v", packID, runtimes)
	}

	// 13. CancelActivation guards on operation 2
	// 13a. Fails if ObservedStopped is false
	badCancel := contracts.CancelActivationRecord{
		OperationID:             planRes2.OperationID,
		TaskID:                  claim2.ID.String(),
		CoreGeneration:          claim2.CoreGeneration,
		LeaseGeneration:         claim2.LeaseGeneration,
		OwnerID:                 claim2.LeaseOwner,
		Reason:                  "operator cancel",
		AbortReceiptID:          "abort-123",
		UnitName:                "acornfox-pack-" + packID + ".service",
		InstanceID:              "inst-002",
		ObservedStopped:         false, // not verified stopped!
		ExpectedJournalRevision: actRev2_3,
		Audit:                   workerAudit,
	}
	if err := store.CancelActivation(ctx, badCancel); err == nil || !strings.Contains(err.Error(), "without verified stop confirmation") {
		t.Fatalf("expected rejection when not verified stopped, got %v", err)
	}

	// 13b. Fails on unit name mismatch
	badCancelUnit := badCancel
	badCancelUnit.ObservedStopped = true
	badCancelUnit.ObservedStoppedAt = time.Now().UTC()
	badCancelUnit.UnitName = "wrong-unit.service"
	if err := store.CancelActivation(ctx, badCancelUnit); err == nil || !strings.Contains(err.Error(), "unit name mismatch") {
		t.Fatalf("expected rejection on unit name mismatch, got %v", err)
	}

	// 13c. Valid cancel
	validCancel := badCancel
	validCancel.ObservedStopped = true
	validCancel.ObservedStoppedAt = time.Now().UTC()
	if err := store.CancelActivation(ctx, validCancel); err != nil {
		t.Fatalf("valid cancel activation failed: %v", err)
	}
}

func TestPackActivationW2AuthorityAndFencing(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DataDirectory:       tempDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	}
	store, err := Open(cfg)
	if err != nil {
		t.Fatalf("open store failed: %v", err)
	}
	defer store.Close()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatalf("installation binding failed: %v", err)
	}

	packID := "test-pack-w2"
	ver := "1.0.0"
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	selection, _, manBytes := makeTestVerifiedSelection(t, packID, ver, binding, now, 1, exp)

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "plan w2 authority test",
	}

	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         packID,
			Version:        ver,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-w2-auth",
		},
		Selection: selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	workerID := "worker-w2"
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: workerID,
		Kinds: []string{PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: %v", err)
	}

	workerAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   workerID,
		Reason:    "worker progress",
	}

	// 1. AuthorizePackActivationAction: Test action before journal exists
	// "publish" without journal must fail
	authReq := contracts.AuthorizePackActivationActionRequest{
		TaskID:                  claimedTask.ID.String(),
		OperationID:             planRes.OperationID,
		PackID:                  packID,
		Version:                 ver,
		PlanSHA256:              planRes.PlanSHA256,
		Action:                  "publish",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	}
	_, err = store.AuthorizePackActivationAction(ctx, authReq)
	if err == nil || !strings.Contains(err.Error(), "requires existing activation journal") {
		t.Fatalf("expected error for publish without journal, got %v", err)
	}

	// 1. AuthorizePackActivationAction: All host mutations (including prepare) require an existing journal
	authReq.Action = "prepare"
	authRes, err := store.AuthorizePackActivationAction(ctx, authReq)
	if err == nil || authRes.Authorized || !strings.Contains(err.Error(), "requires existing activation journal") {
		t.Fatalf("expected prepare without journal to be rejected, got res=%+v, err=%v", authRes, err)
	}

	// Stage and commit artifact receipt (TP02A requirement for activation journal)
	snap, _, _ := selection.Snapshot()
	stageIntent := contracts.StageArtifactIntent{
		OperationID:            planRes.OperationID,
		TaskID:                 claimedTask.ID.String(),
		PackID:                 planRes.PackID,
		Version:                planRes.Version,
		PlanSHA256:             planRes.PlanSHA256,
		CoreGeneration:         claimedTask.CoreGeneration,
		LeaseGeneration:        claimedTask.LeaseGeneration,
		OwnerID:                claimedTask.LeaseOwner,
		StageDirectory:         "staging/" + planRes.OperationID,
		AuthorityCatalogSHA256: snap.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  workerAudit,
	}
	stgRev, err := store.RecordStageIntent(ctx, stageIntent)
	if err != nil {
		t.Fatalf("record stage intent: %v", err)
	}

	rcptID, _ := domain.NewID("rcpt")
	artRcpt := contracts.PackArtifactReceipt{
		ReceiptID:          rcptID.String(),
		OperationID:        planRes.OperationID,
		PackID:             planRes.PackID,
		Version:            planRes.Version,
		PlanSHA256:         planRes.PlanSHA256,
		ArchiveSHA256:      snap.ArtifactSHA256,
		ManifestSHA256:     snap.ManifestSHA256,
		ExecutableSHA256:   strings.Repeat("a", 64),
		ExecutablePath:     "bin/adapter",
		CatalogSHA256:      snap.CatalogSHA256,
		CatalogSequence:    1,
		ArchiveSize:        snap.ArtifactSize,
		UnpackedTotalBytes: int64(len(manBytes)) + 42,
		RelativeStagePath:  "staging/" + planRes.OperationID,
		StageIdentity:      "stage-ident-w2",
		MemberCount:        2,
		VerifiedAt:         now,
		CreatedAt:          now,
	}
	if err := store.CommitArtifactReceipt(ctx, contracts.CommitArtifactReceiptRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 artRcpt,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: stgRev,
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("commit artifact receipt: %v", err)
	}

	// Create initial publishing journal (revision 1)
	jnlRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  packID,
		Version:                 ver,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       artRcpt.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-1",
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver,
		UnitName:                "acornfox-pack-" + packID + ".service",
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	})
	if err != nil || jnlRev != 1 {
		t.Fatalf("initial journal failed: rev=%d, err=%v", jnlRev, err)
	}

	// Now with existing journal and exact expected revision 1, "prepare" authorization succeeds
	authReq.Action = "prepare"
	authReq.ExpectedJournalRevision = 1
	authPrep, err := store.AuthorizePackActivationAction(ctx, authReq)
	if err != nil || !authPrep.Authorized {
		t.Fatalf("expected prepare authorized with journal, got res=%+v, err=%v", authPrep, err)
	}

	// 2. Risk Check 1: Pre-authorization cancellation blocks mutation actions, but allows stop/abort
	err = store.RequestPackInstallCancellation(ctx, contracts.RequestPackInstallCancellationRecord{
		OperationID:              planRes.OperationID,
		ExpectedOperationVersion: 1,
		Reason:                   "user requested stop",
		Audit:                    audit,
	})
	if err != nil {
		t.Fatalf("request cancellation failed: %v", err)
	}

	// Now mutating action ("publish") must be rejected because operation is cancelling
	authReq.Action = "publish"
	authReq.ExpectedJournalRevision = 1
	_, err = store.AuthorizePackActivationAction(ctx, authReq)
	if err == nil || !strings.Contains(err.Error(), "operation is cancelling") {
		t.Fatalf("expected rejection for publish during cancelling, got %v", err)
	}

	// But cleanup action ("abort") must be permitted during cancelling to allow convergence!
	authReq.Action = "abort"
	authAbort, err := store.AuthorizePackActivationAction(ctx, authReq)
	if err != nil || !authAbort.Authorized {
		t.Fatalf("expected abort permitted during cancelling, got res=%+v, err=%v", authAbort, err)
	}

	// 3. Risk Check 2: Audit rejection within-transaction rollback test on FailPackInstall & CancelActivation
	// Install package-private test trigger on audit_evidence table to simulate audit failure inside the active transaction
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER test_reject_audit BEFORE INSERT ON audit_evidence BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	// Capture pre-failure baseline state
	jnlBefore, err := store.GetActivationJournal(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get jnlBefore: %v", err)
	}
	taskBefore, err := store.GetTask(ctx, claimedTask.ID)
	if err != nil {
		t.Fatalf("get taskBefore: %v", err)
	}
	var opStateBefore, opReasonBefore string
	var opVerBefore int64
	_ = store.db.QueryRowContext(ctx, `SELECT state, failure_reason, version FROM operations WHERE id=?`, planRes.OperationID).Scan(&opStateBefore, &opReasonBefore, &opVerBefore)
	var auditCountBefore, outboxCountBefore int
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence`).Scan(&auditCountBefore)
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=?`, planRes.OperationID).Scan(&outboxCountBefore)

	// Valid FailPackInstall within transaction must abort when audit trigger fires, rolling back all modifications
	failReq := contracts.FailPackInstallRecord{
		TaskID:                  claimedTask.ID.String(),
		OperationID:             planRes.OperationID,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: jnlBefore.Revision,
		Classification:          "known_failure",
		Reason:                  "something broke",
		Audit:                   workerAudit,
	}
	failErr := store.FailPackInstall(ctx, failReq)
	if failErr == nil || !strings.Contains(failErr.Error(), "injected audit failure") {
		t.Fatalf("expected FailPackInstall to fail with injected audit failure, got %v", failErr)
	}

	// Assert journal, task, operation, audit, outbox are completely unchanged (atomic rollback, no half-facts!)
	jnlAfterFail, _ := store.GetActivationJournal(ctx, planRes.OperationID)
	if jnlAfterFail.Revision != jnlBefore.Revision || jnlAfterFail.Phase != jnlBefore.Phase || jnlAfterFail.FailureReason != jnlBefore.FailureReason {
		t.Fatalf("journal altered after rollback: %+v vs %+v", jnlAfterFail, jnlBefore)
	}
	taskAfterFail, _ := store.GetTask(ctx, claimedTask.ID)
	if taskAfterFail.State != taskBefore.State || taskAfterFail.LeaseOwner != taskBefore.LeaseOwner || taskAfterFail.LastError != taskBefore.LastError {
		t.Fatalf("task altered after rollback: %+v vs %+v", taskAfterFail, taskBefore)
	}
	var opStateAfterFail, opReasonAfterFail string
	var opVerAfterFail int64
	_ = store.db.QueryRowContext(ctx, `SELECT state, failure_reason, version FROM operations WHERE id=?`, planRes.OperationID).Scan(&opStateAfterFail, &opReasonAfterFail, &opVerAfterFail)
	if opStateAfterFail != opStateBefore || opReasonAfterFail != opReasonBefore || opVerAfterFail != opVerBefore {
		t.Fatalf("op altered after rollback: state=%s, ver=%d, reason=%s", opStateAfterFail, opVerAfterFail, opReasonAfterFail)
	}

	// Also verify CancelActivation rollback under audit trigger
	cancelReq := contracts.CancelActivationRecord{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		Reason:                  "test cancel audit rollback",
		AbortReceiptID:          "dummy_abort_rcpt",
		UnitName:                "acornfox-pack-" + packID + ".service",
		ObservedStopped:         true,
		ObservedStoppedAt:       time.Now().UTC(),
		ExpectedJournalRevision: jnlBefore.Revision,
		Audit:                   workerAudit,
	}
	cancelErr := store.CancelActivation(ctx, cancelReq)
	if cancelErr == nil || !strings.Contains(cancelErr.Error(), "injected audit failure") {
		t.Fatalf("expected CancelActivation to fail with injected audit failure, got %v", cancelErr)
	}

	// Verify no partial facts after cancel rollback
	var auditCountAfterRollback, outboxCountAfterRollback int
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence`).Scan(&auditCountAfterRollback)
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=?`, planRes.OperationID).Scan(&outboxCountAfterRollback)
	if auditCountAfterRollback != auditCountBefore || outboxCountAfterRollback != outboxCountBefore {
		t.Fatalf("audit or outbox leaked after rollback: audit=%d/%d, outbox=%d/%d", auditCountAfterRollback, auditCountBefore, outboxCountAfterRollback, outboxCountBefore)
	}

	// Drop test trigger before continuing
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER test_reject_audit;`); err != nil {
		t.Fatalf("drop test trigger: %v", err)
	}

	// 4. Risk Check 2 (part b): Unknown abort outcome while cancelling preserves 'cancelling' state!
	// It must NOT replace cancelling with a generic waiting state that loses the user request!
	waitReq := contracts.FailPackInstallRecord{
		TaskID:                  claimedTask.ID.String(),
		OperationID:             planRes.OperationID,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: 1,
		Classification:          "waiting_reconcile",
		Reason:                  "helper network timeout",
		Audit:                   workerAudit,
	}
	if err := store.FailPackInstall(ctx, waitReq); err != nil {
		t.Fatalf("fail pack install waiting_reconcile failed: %v", err)
	}

	// Comprehensive assertion of waiting success on cancelling operation:
	// a. Journal revision advances from 1 to 2, and failure_reason records waiting_reconcile
	jnlWait, err := store.GetActivationJournal(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get jnlWait: %v", err)
	}
	if jnlWait.Revision != 2 || !strings.Contains(jnlWait.FailureReason, "waiting_reconcile") {
		t.Fatalf("expected journal revision 2 with waiting_reconcile, got rev=%d, reason=%s", jnlWait.Revision, jnlWait.FailureReason)
	}

	// b. Task is released to 'ready' with cleared owner/deadline and last_error records waiting_reconcile
	taskWait, err := store.GetTask(ctx, claimedTask.ID)
	if err != nil {
		t.Fatalf("get taskWait: %v", err)
	}
	if taskWait.State != contracts.TaskReady || taskWait.LeaseOwner != "" || taskWait.LeaseUntil != nil || !strings.Contains(taskWait.LastError, "waiting_reconcile") {
		t.Fatalf("expected task released to ready with cleared lease and waiting_reconcile last_error, got state=%s, owner=%s, until=%v, lastErr=%s",
			taskWait.State, taskWait.LeaseOwner, taskWait.LeaseUntil, taskWait.LastError)
	}

	// c. Operation preserves 'cancelling' state with unknown reason preserved
	var curState, curReason string
	_ = store.db.QueryRowContext(ctx, `SELECT state, failure_reason FROM operations WHERE id=?`, planRes.OperationID).Scan(&curState, &curReason)
	if curState != "cancelling" || !strings.Contains(curReason, "waiting_reconcile") {
		t.Fatalf("cancellation intent must survive uncertainty: expected cancelling, got state=%s, reason=%s", curState, curReason)
	}

	// d. Exactly 1 new audit record and 1 new outbox event added
	var auditCountWait, outboxCountWait int
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence`).Scan(&auditCountWait)
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=?`, planRes.OperationID).Scan(&outboxCountWait)
	if auditCountWait != auditCountBefore+1 || outboxCountWait != outboxCountBefore+1 {
		t.Fatalf("expected +1 audit and +1 outbox event, got audit=%d (was %d), outbox=%d (was %d)", auditCountWait, auditCountBefore, outboxCountWait, outboxCountBefore)
	}

	// 5. Risk Check 3: waiting tasks are excluded from ClaimTask with AllowedOperationStates,
	// while cancelling tasks CAN be claimed for convergence!
	// In another operation, set state to 'waiting'
	packID3 := "pack-waiting-test"
	selection3, _, _ := makeTestVerifiedSelection(t, packID3, ver, binding, now, 1, exp)
	planRes3, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         packID3,
			Version:        ver,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-waiting-test",
		},
		Selection: selection3,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install 3 failed: %v", err)
	}
	claim3, claimed3, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:                  "worker-temp",
		Kinds:                  []string{PackInstallTaskKind},
		AllowedOperationStates: []string{"pending"},
		Now:                    now,
		LeasePolicy:            contracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3},
	})
	if err != nil || !claimed3 {
		t.Fatalf("claim task 3 failed: %v", err)
	}
	if claim3.ID.String() != planRes3.TaskID {
		t.Fatalf("claim3 task ID mismatch: got %s want %s", claim3.ID.String(), planRes3.TaskID)
	}
	// Put operation 3 into waiting
	if err := store.FailPackInstall(ctx, contracts.FailPackInstallRecord{
		TaskID:          claim3.ID.String(),
		OperationID:     planRes3.OperationID,
		CoreGeneration:  claim3.CoreGeneration,
		LeaseGeneration: claim3.LeaseGeneration,
		OwnerID:         claim3.LeaseOwner,
		Classification:  "waiting_authorization",
		Reason:          "need catalog refresh",
		Audit:           workerAudit,
	}); err != nil {
		t.Fatalf("fail pack install operation 3 to waiting failed: %v", err)
	}

	// Query initial attempt count of task 3
	var initialAttempt int
	_ = store.db.QueryRowContext(ctx, `SELECT attempt FROM task_leases WHERE task_id=?`, claim3.ID.String()).Scan(&initialAttempt)

	// Repeatedly claim with AllowedOperationStates: []string{"pending","leased","running","cancelling"}
	// It must NOT claim task 3 because its operation is 'waiting', and its attempt count must NOT increase!
	filterClaimReq := contracts.ClaimTaskRequest{
		Owner:                  "worker-filter",
		Kinds:                  []string{PackInstallTaskKind},
		AllowedOperationStates: []string{"pending", "leased", "running", "cancelling"},
		Now:                    now.Add(time.Minute),
		LeasePolicy:            contracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3},
	}

	// Operation 1 (which is 'cancelling') CAN be claimed for convergence!
	cancellingClaim, didClaimCancelling, err := store.ClaimTask(ctx, filterClaimReq)
	if err != nil || !didClaimCancelling || cancellingClaim.ID != claimedTask.ID {
		t.Fatalf("cancelling task should be claimable for convergence, got didClaim=%v, task=%+v, err=%v", didClaimCancelling, cancellingClaim, err)
	}

	// Repeatedly claim with AllowedOperationStates: []string{"pending","leased","running","cancelling"}
	// It must NOT claim task 3 because its operation is 'waiting', and its attempt count must NOT increase!
	for i := 0; i < 3; i++ {
		claimedTask, didClaim, _ := store.ClaimTask(ctx, filterClaimReq)
		if didClaim && claimedTask.ID == claim3.ID {
			t.Fatalf("task in waiting operation should not be claimed with filter on iteration %d", i)
		}
	}
	var finalAttempt int
	_ = store.db.QueryRowContext(ctx, `SELECT attempt FROM task_leases WHERE task_id=?`, claim3.ID.String()).Scan(&finalAttempt)
	if finalAttempt != initialAttempt {
		t.Fatalf("attempt count should not increase for waiting tasks: was %d, now %d", initialAttempt, finalAttempt)
	}
}

func TestPackActivationW3SourceBridgeAndResumeAndFreshness(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		DataDirectory:       tempDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	}
	store, err := Open(cfg)
	if err != nil {
		t.Fatalf("open store failed: %v", err)
	}
	defer store.Close()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatalf("installation binding failed: %v", err)
	}

	packID := "test-pack-w3"
	ver := "1.0.0"
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	selection, _, manBytes := makeTestVerifiedSelection(t, packID, ver, binding, now, 1, exp)

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-w3",
		Reason:    "w3 source bridge test",
	}

	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         packID,
			Version:        ver,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-w3-test",
		},
		Selection: selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	workerID := "worker-w3"
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: workerID,
		Kinds: []string{PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: %v", err)
	}

	workerAudit := contracts.AuditContext{
		ActorType: "system",
		ActorID:   workerID,
		Reason:    "worker progress",
	}

	// 1. Prior to CommitActivation, GetActivePackSource must return ErrNotFound
	_, err = store.GetActivePackSource(ctx, packID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for active pack source before commit, got %v", err)
	}

	// 2. Stage and commit artifact receipt
	snap, _, _ := selection.Snapshot()
	stageIntent := contracts.StageArtifactIntent{
		OperationID:            planRes.OperationID,
		TaskID:                 claimedTask.ID.String(),
		PackID:                 planRes.PackID,
		Version:                planRes.Version,
		PlanSHA256:             planRes.PlanSHA256,
		CoreGeneration:         claimedTask.CoreGeneration,
		LeaseGeneration:        claimedTask.LeaseGeneration,
		OwnerID:                claimedTask.LeaseOwner,
		StageDirectory:         "staging/" + planRes.OperationID,
		AuthorityCatalogSHA256: snap.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  workerAudit,
	}
	stageRev, err := store.RecordStageIntent(ctx, stageIntent)
	if err != nil {
		t.Fatalf("record stage intent: %v", err)
	}
	artRcpt := contracts.PackArtifactReceipt{
		ReceiptID:          "art-rcpt-w3",
		OperationID:        planRes.OperationID,
		PackID:             planRes.PackID,
		Version:            planRes.Version,
		PlanSHA256:         planRes.PlanSHA256,
		ArchiveSHA256:      snap.ArtifactSHA256,
		ManifestSHA256:     snap.ManifestSHA256,
		ExecutableSHA256:   strings.Repeat("a", 64),
		ExecutablePath:     "bin/adapter",
		CatalogSHA256:      snap.CatalogSHA256,
		CatalogSequence:    1,
		ArchiveSize:        snap.ArtifactSize,
		UnpackedTotalBytes: int64(len(manBytes)) + 42,
		RelativeStagePath:  "staging/" + planRes.OperationID,
		StageIdentity:      "stage-ident-w3",
		MemberCount:        2,
		VerifiedAt:         now,
		CreatedAt:          now,
	}
	if err := store.CommitArtifactReceipt(ctx, contracts.CommitArtifactReceiptRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 artRcpt,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: stageRev,
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("commit artifact receipt: %v", err)
	}

	// 3. Record publishing -> starting -> ready journal
	pubRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  planRes.PackID,
		Version:                 planRes.Version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       artRcpt.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-w3",
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver,
		UnitName:                "acornfox-pack-" + packID + ".service",
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record initial publishing journal: %v", err)
	}

	startRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  planRes.PackID,
		Version:                 planRes.Version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       artRcpt.ReceiptID,
		Phase:                   "starting",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-w3",
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver,
		UnitName:                "acornfox-pack-" + packID + ".service",
		InstanceID:              "inst-w3-001",
		MainPID:                 23456,
		SocketPath:              "/run/acornfox/packs/" + packID + "/socket",
		ProcessStartIdentity:    "991122",
		CandidateCapabilities:   []string{"diagnostic.observe"},
		ExpectedJournalRevision: pubRev,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record starting journal: %v", err)
	}

	jnlRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes.OperationID,
		TaskID:                  claimedTask.ID.String(),
		PackID:                  planRes.PackID,
		Version:                 planRes.Version,
		PlanSHA256:              planRes.PlanSHA256,
		ArtifactReceiptID:       artRcpt.ReceiptID,
		Phase:                   "ready",
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		PublishID:               "pub-w3",
		InstalledRoot:           "/opt/acornfox/packs/" + packID + "/" + ver,
		UnitName:                "acornfox-pack-" + packID + ".service",
		InstanceID:              "inst-w3-001",
		MainPID:                 23456,
		SocketPath:              "/run/acornfox/packs/" + packID + "/socket",
		ProcessStartIdentity:    "991122",
		CandidateCapabilities:   []string{"diagnostic.observe"},
		CurrentPointerEffect:    "created",
		ActivationGeneration:    1,
		ExpectedJournalRevision: startRev,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record ready journal: %v", err)
	}

	// 4. CommitActivation writes 0006 pack_protocol_instances and active runtime
	actRcpt := contracts.PackActivationReceipt{
		ReceiptID:             "act-rcpt-w3",
		OperationID:           planRes.OperationID,
		PackID:                planRes.PackID,
		Version:               planRes.Version,
		PlanSHA256:            planRes.PlanSHA256,
		ArtifactReceiptID:     artRcpt.ReceiptID,
		InstalledRoot:         "/opt/acornfox/packs/" + packID + "/" + ver,
		RelativeCurrentTarget: ver,
		UnitName:              "acornfox-pack-" + packID + ".service",
		ServiceIdentity:       "systemd:acornfox-pack-" + packID + ".service",
		InstanceID:            "inst-w3-001",
		MainPID:               23456,
		ProcessStartIdentity:  "991122",
		SocketPath:            "/run/acornfox/packs/" + packID + "/socket",
		Capabilities:          []string{"diagnostic.observe"},
		ActivationGeneration:  1,
		ActivatedAt:           now,
		CreatedAt:             now,
	}
	if err := store.CommitActivation(ctx, contracts.CommitActivationRecord{
		TaskID:                  claimedTask.ID.String(),
		Receipt:                 actRcpt,
		ExpectedUID:             1005,
		CoreGeneration:          claimedTask.CoreGeneration,
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: jnlRev,
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("commit activation w3 failed: %v", err)
	}

	// 5. Verify 0006 pack_protocol_instances record
	var instID, instOp, instBinding, instExecPath string
	var instUID uint32
	var instPID int32
	var retiredAt sql.NullString
	err = store.db.QueryRowContext(ctx, `
		SELECT instance_id, operation_id, installation_binding, executable_path, expected_uid, expected_pid, retired_at
		  FROM pack_protocol_instances
		 WHERE instance_id='inst-w3-001'
	`).Scan(&instID, &instOp, &instBinding, &instExecPath, &instUID, &instPID, &retiredAt)
	if err != nil {
		t.Fatalf("query pack_protocol_instances failed: %v", err)
	}
	if instID != "inst-w3-001" || instOp != planRes.OperationID || instUID != 1005 || instPID != 23456 || retiredAt.Valid {
		t.Fatalf("unexpected pack_protocol_instances row: id=%s op=%s uid=%d pid=%d retired=%v", instID, instOp, instUID, instPID, retiredAt)
	}

	// 6. Verify GetActivePackSource
	src, err := store.GetActivePackSource(ctx, packID)
	if err != nil {
		t.Fatalf("get active pack source failed: %v", err)
	}
	if src.PackID != packID || src.ActiveVersion != ver || src.InstanceID != "inst-w3-001" || src.ExpectedUID != 1005 || src.ExpectedPID != 23456 || src.SocketPath != "/run/acornfox/packs/"+packID+"/socket" {
		t.Fatalf("unexpected active pack source: %+v", src)
	}

	// 7. Verify 30s freshness in GetPackUnifiedStatus
	st, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("get pack unified status failed: %v", err)
	}
	if !st.RuntimeReady || st.RuntimeStatus != "ready" {
		t.Fatalf("expected fresh status ready, got: %+v", st)
	}

	// Set LastObservedAt to 45 seconds ago -> must project unknown!
	staleTime := FormatTime(time.Now().UTC().Add(-45 * time.Second))
	if _, err := store.db.ExecContext(ctx, `UPDATE pack_active_runtimes SET last_observed_at=? WHERE pack_id=?`, staleTime, packID); err != nil {
		t.Fatalf("update stale last_observed_at failed: %v", err)
	}
	stStale, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("get stale unified status failed: %v", err)
	}
	if stStale.RuntimeReady || stStale.RuntimeStatus != "unknown" {
		t.Fatalf("expected stale observation to project runtime_ready=false and unknown status, got: %+v", stStale)
	}

	// Set LastObservedAt to future (+1 minute) -> must project unknown!
	futureTime := FormatTime(time.Now().UTC().Add(time.Minute))
	if _, err := store.db.ExecContext(ctx, `UPDATE pack_active_runtimes SET last_observed_at=? WHERE pack_id=?`, futureTime, packID); err != nil {
		t.Fatalf("update future last_observed_at failed: %v", err)
	}
	stFuture, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("get future unified status failed: %v", err)
	}
	if stFuture.RuntimeReady || stFuture.RuntimeStatus != "unknown" {
		t.Fatalf("expected future observation to project runtime_ready=false and unknown status, got: %+v", stFuture)
	}

	// Reset to fresh -> ready again
	freshTime := FormatTime(time.Now().UTC())
	if _, err := store.db.ExecContext(ctx, `UPDATE pack_active_runtimes SET last_observed_at=? WHERE pack_id=?`, freshTime, packID); err != nil {
		t.Fatalf("reset fresh last_observed_at failed: %v", err)
	}
	stFresh, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("get fresh unified status failed: %v", err)
	}
	if !stFresh.RuntimeReady || stFresh.RuntimeStatus != "ready" {
		t.Fatalf("expected fresh observation to project ready, got: %+v", stFresh)
	}

	// 8. Test ResumePackInstall CAS semantics
	// Setup a new operation in 'waiting' state
	packID4 := "test-pack-resume"
	selection4, _, _ := makeTestVerifiedSelection(t, packID4, ver, binding, now, 1, exp)
	planRes4, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         packID4,
			Version:        ver,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-resume-test",
		},
		Selection: selection4,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install 4: %v", err)
	}

	claim4, claimed4, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:       "worker-r",
		Kinds:       []string{PackInstallTaskKind},
		Now:         now,
		LeasePolicy: contracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3},
	})
	if err != nil || !claimed4 {
		t.Fatalf("claim task 4: %v", err)
	}

	// Put into waiting
	if err := store.FailPackInstall(ctx, contracts.FailPackInstallRecord{
		TaskID:          claim4.ID.String(),
		OperationID:     planRes4.OperationID,
		CoreGeneration:  claim4.CoreGeneration,
		LeaseGeneration: claim4.LeaseGeneration,
		OwnerID:         claim4.LeaseOwner,
		Classification:  "waiting_reconcile",
		Reason:          "temporary failure",
		Audit:           workerAudit,
	}); err != nil {
		t.Fatalf("fail pack install 4: %v", err)
	}

	// 8a. Rejection on missing or unverified evidence
	// Wrong TaskID
	badTaskReq := contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    2,
		TaskID:                      "wrong-task-id",
		ExpectedTaskAttempt:         claim4.Attempt,
		ExpectedTaskCoreGeneration:  claim4.CoreGeneration,
		ExpectedTaskLeaseGeneration: claim4.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ExpectedJournalRevision:     0,
		ExpectedPhase:               "",
		CoreGeneration:              store.coreGeneration,
		Audit:                       audit,
	}
	if err := store.ResumePackInstall(ctx, badTaskReq); err == nil || !strings.Contains(err.Error(), "task lease not found") {
		t.Fatalf("expected wrong task rejection, got: %v", err)
	}

	// Wrong Attempt snapshot
	badAttemptReq := contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    2,
		TaskID:                      claim4.ID.String(),
		ExpectedTaskAttempt:         claim4.Attempt + 5,
		ExpectedTaskCoreGeneration:  claim4.CoreGeneration,
		ExpectedTaskLeaseGeneration: claim4.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ExpectedJournalRevision:     0,
		ExpectedPhase:               "",
		CoreGeneration:              store.coreGeneration,
		Audit:                       audit,
	}
	if err := store.ResumePackInstall(ctx, badAttemptReq); err == nil || !strings.Contains(err.Error(), "attempt snapshot mismatch") {
		t.Fatalf("expected attempt mismatch rejection, got: %v", err)
	}

	// Version conflict rejection
	err = store.ResumePackInstall(ctx, contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    999, // wrong version
		TaskID:                      claim4.ID.String(),
		ExpectedTaskAttempt:         claim4.Attempt,
		ExpectedTaskCoreGeneration:  claim4.CoreGeneration,
		ExpectedTaskLeaseGeneration: claim4.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ExpectedJournalRevision:     0,
		ExpectedPhase:               "",
		CoreGeneration:              store.coreGeneration,
		Audit:                       audit,
	})
	if err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("expected version conflict on resume, got: %v", err)
	}

	// Valid resume with verified evidence tuple
	validResumeReq := contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    2, // 1 (plan) + 1 (fail) = 2
		TaskID:                      claim4.ID.String(),
		ExpectedTaskAttempt:         claim4.Attempt,
		ExpectedTaskCoreGeneration:  claim4.CoreGeneration,
		ExpectedTaskLeaseGeneration: claim4.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ExpectedJournalRevision:     0,
		ExpectedPhase:               "",
		CoreGeneration:              store.coreGeneration,
		Audit:                       audit,
	}
	if err := store.ResumePackInstall(ctx, validResumeReq); err != nil {
		t.Fatalf("valid resume failed: %v", err)
	}

	// Verify operation state is pending and version is 3
	var op4State string
	var op4Ver int64
	_ = store.db.QueryRowContext(ctx, `SELECT state, version FROM operations WHERE id=?`, planRes4.OperationID).Scan(&op4State, &op4Ver)
	if op4State != "pending" || op4Ver != 3 {
		t.Fatalf("expected resumed operation state=pending, ver=3; got state=%s, ver=%d", op4State, op4Ver)
	}

	// Claiming again can claim the resumed task!
	reclaim, didReclaim, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:       "worker-r2",
		Kinds:       []string{PackInstallTaskKind},
		Now:         now.Add(time.Second),
		LeasePolicy: contracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3},
	})
	if err != nil || !didReclaim || reclaim.ID != claim4.ID {
		t.Fatalf("expected resumed task to be claimable, got didReclaim=%v, task=%+v, err=%v", didReclaim, reclaim, err)
	}

	// Calling resume on non-waiting operation (currently leased/running) must be rejected
	err = store.ResumePackInstall(ctx, contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    3,
		TaskID:                      claim4.ID.String(),
		ExpectedTaskAttempt:         claim4.Attempt,
		ExpectedTaskCoreGeneration:  claim4.CoreGeneration,
		ExpectedTaskLeaseGeneration: claim4.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ExpectedJournalRevision:     0,
		ExpectedPhase:               "",
		CoreGeneration:              store.coreGeneration,
		Audit:                       audit,
	})
	if err == nil || !strings.Contains(err.Error(), "only waiting operations can be resumed") {
		t.Fatalf("expected rejection resuming non-waiting operation, got: %v", err)
	}

	// 8b. Operation with existing journal requires verified observed effects
	// Re-claim task 4 and put into waiting with existing starting journal
	reclaimTask := reclaim
	snap4, manBytes4, _ := selection4.Snapshot()
	sRev4, err := store.RecordStageIntent(ctx, contracts.StageArtifactIntent{
		OperationID:            planRes4.OperationID,
		TaskID:                 reclaimTask.ID.String(),
		PackID:                 planRes4.PackID,
		Version:                planRes4.Version,
		PlanSHA256:             planRes4.PlanSHA256,
		CoreGeneration:         reclaimTask.CoreGeneration,
		LeaseGeneration:        reclaimTask.LeaseGeneration,
		OwnerID:                reclaimTask.LeaseOwner,
		StageDirectory:         "staging/" + planRes4.OperationID,
		AuthorityCatalogSHA256: snap4.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  workerAudit,
	})
	if err != nil {
		t.Fatalf("record stage intent for op4: %v", err)
	}
	artRcpt4 := contracts.PackArtifactReceipt{
		ReceiptID:          "art-rcpt-op4",
		OperationID:        planRes4.OperationID,
		PackID:             packID4,
		Version:            ver,
		PlanSHA256:         planRes4.PlanSHA256,
		ArchiveSHA256:      snap4.ArtifactSHA256,
		ManifestSHA256:     snap4.ManifestSHA256,
		ExecutableSHA256:   strings.Repeat("a", 64),
		ExecutablePath:     "bin/adapter",
		CatalogSHA256:      snap4.CatalogSHA256,
		CatalogSequence:    1,
		ArchiveSize:        snap4.ArtifactSize,
		UnpackedTotalBytes: int64(len(manBytes4)) + 42,
		RelativeStagePath:  "staging/" + planRes4.OperationID,
		StageIdentity:      "stage-ident-op4",
		MemberCount:        2,
		VerifiedAt:         now,
		CreatedAt:          now,
	}
	if err := store.CommitArtifactReceipt(ctx, contracts.CommitArtifactReceiptRecord{
		TaskID:                  reclaimTask.ID.String(),
		Receipt:                 artRcpt4,
		CoreGeneration:          reclaimTask.CoreGeneration,
		LeaseGeneration:         reclaimTask.LeaseGeneration,
		OwnerID:                 reclaimTask.LeaseOwner,
		ExpectedJournalRevision: sRev4,
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("commit artifact receipt for op4: %v", err)
	}

	jnlStartRev, err := store.RecordActivationJournal(ctx, contracts.RecordActivationJournalIntent{
		OperationID:             planRes4.OperationID,
		TaskID:                  reclaimTask.ID.String(),
		PackID:                  packID4,
		Version:                 ver,
		PlanSHA256:              planRes4.PlanSHA256,
		ArtifactReceiptID:       artRcpt4.ReceiptID,
		Phase:                   "publishing",
		CoreGeneration:          reclaimTask.CoreGeneration,
		LeaseGeneration:         reclaimTask.LeaseGeneration,
		OwnerID:                 reclaimTask.LeaseOwner,
		PublishID:               "pub-r4",
		InstalledRoot:           "/opt/acornfox/packs/" + packID4 + "/" + ver,
		UnitName:                "acornfox-pack-" + packID4 + ".service",
		ExpectedJournalRevision: 0,
		Audit:                   workerAudit,
	})
	if err != nil {
		t.Fatalf("record publishing journal for op4: %v", err)
	}

	// Transition to waiting
	if err := store.FailPackInstall(ctx, contracts.FailPackInstallRecord{
		TaskID:                  reclaimTask.ID.String(),
		OperationID:             planRes4.OperationID,
		CoreGeneration:          reclaimTask.CoreGeneration,
		LeaseGeneration:         reclaimTask.LeaseGeneration,
		OwnerID:                 reclaimTask.LeaseOwner,
		ExpectedJournalRevision: jnlStartRev,
		Classification:          "waiting_reconcile",
		Reason:                  "waiting after publishing",
		Audit:                   workerAudit,
	}); err != nil {
		t.Fatalf("fail pack install to waiting with journal: %v", err)
	}

	// Resuming with existing journal but ObservedEffects=nil must be rejected!
	err = store.ResumePackInstall(ctx, contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    4, // 3 -> 4 on fail
		TaskID:                      reclaimTask.ID.String(),
		ExpectedTaskAttempt:         reclaimTask.Attempt,
		ExpectedTaskCoreGeneration:  reclaimTask.CoreGeneration,
		ExpectedTaskLeaseGeneration: reclaimTask.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ArtifactReceiptID:           artRcpt4.ReceiptID,
		ExpectedJournalRevision:     2,
		ExpectedPhase:               "publishing",
		ObservedEffects:             nil, // MISSING!
		CoreGeneration:              store.coreGeneration,
		Audit:                       audit,
	})
	if err == nil || !strings.Contains(err.Error(), "observed effects snapshot required") {
		t.Fatalf("expected missing observed effects rejection, got: %v", err)
	}

	// Resuming with aborted effect must be rejected!
	err = store.ResumePackInstall(ctx, contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    4,
		TaskID:                      reclaimTask.ID.String(),
		ExpectedTaskAttempt:         reclaimTask.Attempt,
		ExpectedTaskCoreGeneration:  reclaimTask.CoreGeneration,
		ExpectedTaskLeaseGeneration: reclaimTask.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ArtifactReceiptID:           artRcpt4.ReceiptID,
		ExpectedJournalRevision:     2,
		ExpectedPhase:               "publishing",
		ObservedEffects: &contracts.PackObservedSnapshot{
			OperationID: planRes4.OperationID,
			PackID:      packID4,
			Version:     ver,
			ObservedAt:  time.Now().UTC(),
			AbortEffect: &contracts.PackObservedEffect{
				Status: "aborted",
			},
		},
		CoreGeneration: store.coreGeneration,
		Audit:          audit,
	})
	if err == nil || !strings.Contains(err.Error(), "helper reports aborted effect") {
		t.Fatalf("expected aborted effect rejection, got: %v", err)
	}

	// Valid resume with verified exact owned effects for publishing journal
	validOwnedResume := contracts.ResumePackInstallRequest{
		OperationID:                 planRes4.OperationID,
		ExpectedOperationVersion:    4,
		TaskID:                      reclaimTask.ID.String(),
		ExpectedTaskAttempt:         reclaimTask.Attempt,
		ExpectedTaskCoreGeneration:  reclaimTask.CoreGeneration,
		ExpectedTaskLeaseGeneration: reclaimTask.LeaseGeneration,
		PackID:                      packID4,
		Version:                     ver,
		PlanSHA256:                  planRes4.PlanSHA256,
		Selection:                   selection4,
		ExpectedAuthoritySequence:   1,
		ArtifactReceiptID:           artRcpt4.ReceiptID,
		ExpectedJournalRevision:     2,
		ExpectedPhase:               "publishing",
		ObservedEffects: &contracts.PackObservedSnapshot{
			OperationID:          planRes4.OperationID,
			PackID:               packID4,
			Version:              ver,
			MaxOperationSequence: 1,
			ObservedStopped:      true,
			ObservedAt:           time.Now().UTC(),
			UID:                  1005,
			PublishEffect: &contracts.PackObservedEffect{
				ActionID:        "act_pub_1",
				OperationID:     planRes4.OperationID,
				PackID:          packID4,
				Version:         ver,
				Action:          "publish",
				Status:          "succeeded",
				CoreGeneration:  1,
				LeaseGeneration: 1,
				Sequence:        1,
				RequestDigest:   strings.Repeat("a", 64),
				ExecutableSHA:   artRcpt4.ExecutableSHA256,
				ExecutablePath:  "/opt/acornfox/packs/" + packID4 + "/" + ver + "/" + artRcpt4.ExecutablePath,
			},
		},
		CoreGeneration: store.coreGeneration,
		Audit:          audit,
	}
	if err := store.ResumePackInstall(ctx, validOwnedResume); err != nil {
		t.Fatalf("valid owned resume failed: %v", err)
	}

	// Verify operation advanced to pending with version 5
	var op4StateFinal string
	var op4VerFinal int64
	_ = store.db.QueryRowContext(ctx, `SELECT state, version FROM operations WHERE id=?`, planRes4.OperationID).Scan(&op4StateFinal, &op4VerFinal)
	if op4StateFinal != "pending" || op4VerFinal != 5 {
		t.Fatalf("expected resumed op4 state=pending, ver=5; got state=%s ver=%d", op4StateFinal, op4VerFinal)
	}

	// Re-claimed task again succeeds
	reclaimFinal, didReclaimFinal, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:       "worker-r3",
		Kinds:       []string{PackInstallTaskKind},
		Now:         now.Add(2 * time.Second),
		LeasePolicy: contracts.LeasePolicy{Duration: time.Minute, MaxAttempts: 3},
	})
	if err != nil || !didReclaimFinal || reclaimFinal.ID != reclaimTask.ID {
		t.Fatalf("expected final reclaim to succeed, got didReclaim=%v, task=%+v, err=%v", didReclaimFinal, reclaimFinal, err)
	}
}
