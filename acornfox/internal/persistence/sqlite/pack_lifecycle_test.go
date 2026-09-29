package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/packprotocol"
)

func makeTestVerifiedSelection(t *testing.T, packID, version string, binding string, now time.Time, seq uint64, exp time.Time) (packprotocol.VerifiedPackSelection, []byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := packprotocol.Manifest{
		Schema:          "acornfox-pack-manifest-v1",
		PackID:          packID,
		Version:         version,
		OS:              "linux",
		Arch:            "amd64",
		MinCoreVersion:  "1.0.0",
		ProtocolVersion: "1.0",
		Capabilities:    []string{"echo.run"},
		Dependencies:    []packprotocol.Dependency{},
		Permissions:     []string{"state.private"},
		Entries:         []packprotocol.Entry{{Role: "adapter", Path: "bin/adapter"}},
		Files:           []packprotocol.File{{Path: "bin/adapter", SHA256: strings.Repeat("a", 64), Size: 42, Mode: 0755}},
	}
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	manSum := packprotocolDigest(manifestBytes)
	c := packprotocol.CatalogPayload{
		Publisher:      "test-publisher",
		PackID:         packID,
		Version:        version,
		OS:             "linux",
		Arch:           "amd64",
		Sequence:       seq,
		ExpiresAt:      exp.Format(time.RFC3339Nano),
		ManifestSHA256: manSum,
		ArtifactSHA256: strings.Repeat("b", 64),
		ArtifactSize:   100,
		ArtifactURL:    "https://test-packs.invalid/archive.tar.gz",
	}
	payBytes, _ := json.Marshal(c)
	sig := ed25519.Sign(priv, append([]byte(packprotocol.CatalogSignatureDomain), payBytes...))
	envelopeBytes, _ := json.Marshal(packprotocol.CatalogEnvelope{
		Schema:    "acornfox-pack-catalog-envelope-v1",
		Payload:   base64.StdEncoding.EncodeToString(payBytes),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})

	policy := packprotocol.VerificationPolicy{
		Publisher:           c.Publisher,
		PublicKey:           pub,
		AllowedHosts:        []string{"test-packs.invalid"},
		CoreVersion:         "1.0.0",
		ProtocolVersion:     "1.0",
		OS:                  "linux",
		Arch:                "amd64",
		InstallationBinding: binding,
		Now:                 now,
	}

	verified, err := packprotocol.VerifySelection(envelopeBytes, manifestBytes, policy)
	if err != nil {
		t.Fatalf("verify selection failed: %v", err)
	}
	return verified, envelopeBytes, manifestBytes
}

func packprotocolDigest(b []byte) string {
	sum := sha256Hex(string(b))
	return sum
}

func TestPackLifecyclePersistence(t *testing.T) {
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

	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	selection, origEnv, origMan := makeTestVerifiedSelection(t, "fixture-echo", "1.0.0", binding, now, 10, exp)

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	// 1. PlanPackInstall should store trust materials
	intent := contracts.PackInstallIntent{
		PackID:         "fixture-echo",
		Version:        "1.0.0",
		OS:             "linux",
		Arch:           "amd64",
		IdempotencyKey: "idem-plan-1",
	}
	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent:    intent,
		Selection: selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install failed: %v", err)
	}

	// 2. Trust material was saved and can be retrieved
	mat, err := store.GetPackTrustMaterial(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get pack trust material: %v", err)
	}
	if mat.OperationID != planRes.OperationID || mat.PackID != "fixture-echo" || mat.Version != "1.0.0" {
		t.Fatalf("unexpected trust material record: %+v", mat)
	}
	if string(mat.CatalogEnvelope) != string(origEnv) || string(mat.ManifestBytes) != string(origMan) {
		t.Fatalf("trust material bytes mismatch")
	}

	// 3. Immutability of pack_trust_materials
	_, err = store.db.ExecContext(ctx, `UPDATE pack_trust_materials SET version='2.0.0' WHERE material_id=?`, mat.MaterialID)
	if err == nil {
		t.Fatal("expected update of pack_trust_materials to fail via trigger")
	}
	_, err = store.db.ExecContext(ctx, `DELETE FROM pack_trust_materials WHERE material_id=?`, mat.MaterialID)
	if err == nil {
		t.Fatal("expected delete of pack_trust_materials to fail via trigger")
	}

	// 4. Initial Pack status is "planned"
	st, rcpt, err := store.GetPackStatus(ctx, "fixture-echo")
	if err != nil {
		t.Fatalf("get pack status: %v", err)
	}
	if st != "planned" || rcpt != nil {
		t.Fatalf("expected status planned, got %s, rcpt=%v", st, rcpt)
	}

	// 5. Genuine task claim to obtain positive caller tokens
	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		t.Fatalf("claim task failed: claimed=%v, err=%v", claimed, err)
	}
	if claimedTask.OperationID.String() != planRes.OperationID || claimedTask.CoreGeneration <= 0 || claimedTask.LeaseGeneration <= 0 {
		t.Fatalf("unexpected claimed task: %+v", claimedTask)
	}

	snap, _, _ := selection.Snapshot()

	// 6. Fencing on RecordStageIntent: wrong core gen
	badStageIntent := contracts.StageArtifactIntent{
		OperationID:            planRes.OperationID,
		TaskID:                 claimedTask.ID.String(),
		PackID:                 planRes.PackID,
		Version:                planRes.Version,
		PlanSHA256:             planRes.PlanSHA256,
		CoreGeneration:         claimedTask.CoreGeneration + 1, // mismatch
		LeaseGeneration:        claimedTask.LeaseGeneration,
		OwnerID:                claimedTask.LeaseOwner,
		StageDirectory:         "staging/" + planRes.OperationID,
		AuthorityCatalogSHA256: snap.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  audit,
	}
	if _, err := store.RecordStageIntent(ctx, badStageIntent); err == nil || !strings.Contains(err.Error(), "core generation mismatch") {
		t.Fatalf("expected core generation mismatch, got %v", err)
	}

	// Fencing on RecordStageIntent: wrong lease gen
	badStageIntent.CoreGeneration = claimedTask.CoreGeneration
	badStageIntent.LeaseGeneration = claimedTask.LeaseGeneration + 1 // mismatch
	if _, err := store.RecordStageIntent(ctx, badStageIntent); err == nil || !strings.Contains(err.Error(), "lease generation mismatch") {
		t.Fatalf("expected lease generation mismatch, got %v", err)
	}

	// Fencing on RecordStageIntent: wrong owner
	badStageIntent.LeaseGeneration = claimedTask.LeaseGeneration
	badStageIntent.OwnerID = "other-worker"
	if _, err := store.RecordStageIntent(ctx, badStageIntent); err == nil || !strings.Contains(err.Error(), "lease generation mismatch") {
		t.Fatalf("expected owner mismatch, got %v", err)
	}

	// 7. Valid RecordStageIntent creates journal with phase "staging" and revision 1
	validStageIntent := contracts.StageArtifactIntent{
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
		Audit:                  audit,
	}
	rev, err := store.RecordStageIntent(ctx, validStageIntent)
	if err != nil {
		t.Fatalf("record stage intent: %v", err)
	}
	if rev != 1 {
		t.Fatalf("expected revision 1, got %d", rev)
	}

	jnl, err := store.GetPackLifecycleJournal(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get journal: %v", err)
	}
	if jnl.Phase != "staging" || jnl.Revision != 1 {
		t.Fatalf("unexpected journal: %+v", jnl)
	}

	// 8. Immutability/Check on pack_lifecycle_journal: cannot delete or decrement revision
	_, err = store.db.ExecContext(ctx, `DELETE FROM pack_lifecycle_journal WHERE operation_id=?`, planRes.OperationID)
	if err == nil {
		t.Fatal("expected delete of pack_lifecycle_journal to fail")
	}
	_, err = store.db.ExecContext(ctx, `UPDATE pack_lifecycle_journal SET revision=0 WHERE operation_id=?`, planRes.OperationID)
	if err == nil {
		t.Fatal("expected revision non-increasing update to fail")
	}

	// 9. CommitArtifactReceipt: Fencing test - wrong core generation
	rcptID, _ := domain.NewID("rcpt")
	commitRec := contracts.CommitArtifactReceiptRecord{
		TaskID: claimedTask.ID.String(),
		Receipt: contracts.PackArtifactReceipt{
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
			CatalogSequence:    snap.CatalogSequence,
			ArchiveSize:        snap.ArtifactSize,
			UnpackedTotalBytes: int64(len(origMan)) + 42,
			RelativeStagePath:  "staging/" + planRes.OperationID,
			StageIdentity:      "token-1234",
			MemberCount:        2,
			VerifiedAt:         now,
		},
		CoreGeneration:          claimedTask.CoreGeneration + 1, // mismatch
		LeaseGeneration:         claimedTask.LeaseGeneration,
		OwnerID:                 claimedTask.LeaseOwner,
		ExpectedJournalRevision: 1,
		Audit:                   audit,
	}
	err = store.CommitArtifactReceipt(ctx, commitRec)
	if err == nil || !strings.Contains(err.Error(), "core generation mismatch") {
		t.Fatalf("expected core generation mismatch, got %v", err)
	}

	// 10. CommitArtifactReceipt: Revision conflict
	commitRec.CoreGeneration = claimedTask.CoreGeneration
	commitRec.ExpectedJournalRevision = 999
	err = store.CommitArtifactReceipt(ctx, commitRec)
	if err == nil || !strings.Contains(err.Error(), "revision conflict") {
		t.Fatalf("expected revision conflict, got %v", err)
	}

	// 11. Valid CommitArtifactReceipt succeeds
	commitRec.ExpectedJournalRevision = 1
	err = store.CommitArtifactReceipt(ctx, commitRec)
	if err != nil {
		t.Fatalf("valid commit receipt failed: %v", err)
	}

	// 12. Verify receipt on disk in SQLite
	savedRcpt, err := store.GetArtifactReceipt(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get artifact receipt failed: %v", err)
	}
	if savedRcpt.ReceiptID != rcptID.String() || savedRcpt.PackID != "fixture-echo" {
		t.Fatalf("unexpected receipt: %+v", savedRcpt)
	}

	// 13. Immutability of pack_artifact_receipts
	_, err = store.db.ExecContext(ctx, `UPDATE pack_artifact_receipts SET version='2.0.0' WHERE receipt_id=?`, rcptID.String())
	if err == nil {
		t.Fatal("expected update of pack_artifact_receipts to fail")
	}
	_, err = store.db.ExecContext(ctx, `DELETE FROM pack_artifact_receipts WHERE receipt_id=?`, rcptID.String())
	if err == nil {
		t.Fatal("expected delete of pack_artifact_receipts to fail")
	}

	// 14. Check pack status is now "artifact_verified"
	st, statusRcpt, err := store.GetPackStatus(ctx, "fixture-echo")
	if err != nil {
		t.Fatalf("get pack status: %v", err)
	}
	if st != "artifact_verified" || statusRcpt == nil || statusRcpt.ReceiptID != rcptID.String() {
		t.Fatalf("expected artifact_verified, got %s, rcpt=%v", st, statusRcpt)
	}

	// 15. pack_records.state and operations.state remain planned/pending (nonterminal)
	packRec, err := store.GetPack(ctx, "fixture-echo")
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	if packRec.State != "planned" {
		t.Fatalf("pack state should remain planned, got %s", packRec.State)
	}

	var opState string
	err = store.db.QueryRowContext(ctx, `SELECT state FROM operations WHERE id=?`, planRes.OperationID).Scan(&opState)
	if err != nil {
		t.Fatalf("query op state: %v", err)
	}
	if opState != "pending" {
		t.Fatalf("operation state should remain pending, got %s", opState)
	}

	// 16. Cannot transition verified journal to failed
	failRec := contracts.LifecycleFailureRecord{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Reason:          "should fail",
		Audit:           audit,
	}
	err = store.RecordLifecycleFailure(ctx, failRec)
	if err == nil || !strings.Contains(err.Error(), "cannot transition verified journal to failed") {
		t.Fatalf("expected rejection of verified -> failed transition, got %v", err)
	}

	// 17. Resupply renewed catalog material
	renewedSel, _, _ := makeTestVerifiedSelection(t, "fixture-echo", "1.0.0", binding, now.Add(time.Minute), 11, now.Add(2*time.Hour))
	err = store.ResupplyPackTrustMaterial(ctx, planRes.OperationID, renewedSel, "renewed_catalog")
	if err != nil {
		t.Fatalf("resupply renewed catalog: %v", err)
	}
	matLatest, err := store.GetPackTrustMaterial(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get latest material: %v", err)
	}
	if matLatest.AuthoritySequence != 2 || matLatest.AuthorityKind != "renewed_catalog" {
		t.Fatalf("unexpected latest material: %+v", matLatest)
	}

	// 18. Storage Regression 1: After accepting renewal seq 11, original-plan resupply stays idempotent and head remains 11
	err = store.ResupplyPackTrustMaterial(ctx, planRes.OperationID, selection, "original_plan")
	if err != nil {
		t.Fatalf("idempotent original_plan resupply failed: %v", err)
	}
	matHead, err := store.GetPackTrustMaterial(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("get pack trust material head: %v", err)
	}
	if matHead.CatalogSequence != 11 || matHead.AuthorityKind != "renewed_catalog" {
		t.Fatalf("authority head regressed behind renewal floor: expected seq 11 renewed_catalog, got seq %d %s", matHead.CatalogSequence, matHead.AuthorityKind)
	}

	// 19. Staging older still-valid material cannot bypass the accepted floor
	badOlderStageIntent := contracts.StageArtifactIntent{
		OperationID:            planRes.OperationID,
		TaskID:                 claimedTask.ID.String(),
		PackID:                 planRes.PackID,
		Version:                planRes.Version,
		PlanSHA256:             planRes.PlanSHA256,
		CoreGeneration:         claimedTask.CoreGeneration,
		LeaseGeneration:        claimedTask.LeaseGeneration,
		OwnerID:                claimedTask.LeaseOwner,
		StageDirectory:         "staging/" + planRes.OperationID,
		AuthorityCatalogSHA256: snap.CatalogSHA256, // older seq 10 authority
		AuthoritySequence:      1,                  // older sequence 1
		AuthorityExpiresAt:     exp,
		Audit:                  audit,
	}
	_, err = store.RecordStageIntent(ctx, badOlderStageIntent)
	if err == nil || !strings.Contains(err.Error(), "below accepted floor") {
		t.Fatalf("expected rejection of superseded authority sequence, got %v", err)
	}

	// 20. Storage Regression 2: Stage material1 then accept material2, attempt material2 receipt without restaging:
	// must reject the journal/material mix and leave no receipt/phase advancement from the rejected call.
	op2Selection, _, origMan2 := makeTestVerifiedSelection(t, "fixture-echo-mix", "1.0.0", binding, now, 12, exp)
	planRes2, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         "fixture-echo-mix",
			Version:        "1.0.0",
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-plan-mix",
		},
		Selection: op2Selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan2 failed: %v", err)
	}
	claimedTask2, claimed2, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner:       "worker-2",
		Kinds:       []string{PackInstallTaskKind},
		Now:         now,
		LeasePolicy: contracts.LeasePolicy{Duration: 10 * time.Minute, MaxAttempts: 3},
	})
	if err != nil || !claimed2 || claimedTask2.ID.String() != planRes2.TaskID {
		t.Fatalf("claim task2 failed: claimed=%v, err=%v, id=%s vs %s", claimed2, err, claimedTask2.ID, planRes2.TaskID)
	}

	snap2, _, _ := op2Selection.Snapshot()
	stageIntent2 := contracts.StageArtifactIntent{
		OperationID:            planRes2.OperationID,
		TaskID:                 claimedTask2.ID.String(),
		PackID:                 planRes2.PackID,
		Version:                planRes2.Version,
		PlanSHA256:             planRes2.PlanSHA256,
		CoreGeneration:         claimedTask2.CoreGeneration,
		LeaseGeneration:        claimedTask2.LeaseGeneration,
		OwnerID:                claimedTask2.LeaseOwner,
		StageDirectory:         "staging/" + planRes2.OperationID,
		AuthorityCatalogSHA256: snap2.CatalogSHA256,
		AuthoritySequence:      1,
		AuthorityExpiresAt:     exp,
		Audit:                  audit,
	}
	rev2, err := store.RecordStageIntent(ctx, stageIntent2)
	if err != nil || rev2 != 1 {
		t.Fatalf("record stage intent2: %v", err)
	}

	// Accept material 2 (renewal seq 13)
	renewedSel2, _, _ := makeTestVerifiedSelection(t, "fixture-echo-mix", "1.0.0", binding, now.Add(time.Minute), 13, now.Add(2*time.Hour))
	snapRenewed2, _, _ := renewedSel2.Snapshot()
	err = store.ResupplyPackTrustMaterial(ctx, planRes2.OperationID, renewedSel2, "renewed_catalog")
	if err != nil {
		t.Fatalf("resupply material 2: %v", err)
	}

	// Attempt to commit receipt for material 2 (seq 13) directly without re-staging:
	rcptID2, _ := domain.NewID("rcpt")
	mismatchedCommitRec := contracts.CommitArtifactReceiptRecord{
		TaskID: claimedTask2.ID.String(),
		Receipt: contracts.PackArtifactReceipt{
			ReceiptID:          rcptID2.String(),
			OperationID:        planRes2.OperationID,
			PackID:             planRes2.PackID,
			Version:            planRes2.Version,
			PlanSHA256:         planRes2.PlanSHA256,
			ArchiveSHA256:      snapRenewed2.ArtifactSHA256,
			ManifestSHA256:     snapRenewed2.ManifestSHA256,
			ExecutableSHA256:   strings.Repeat("a", 64),
			ExecutablePath:     "bin/adapter",
			CatalogSHA256:      snapRenewed2.CatalogSHA256,
			CatalogSequence:    snapRenewed2.CatalogSequence,
			ArchiveSize:        snapRenewed2.ArtifactSize,
			UnpackedTotalBytes: int64(len(origMan2)) + 42,
			RelativeStagePath:  "staging/" + planRes2.OperationID,
			StageIdentity:      "token-mix",
			MemberCount:        2,
			VerifiedAt:         now,
		},
		CoreGeneration:          claimedTask2.CoreGeneration,
		LeaseGeneration:         claimedTask2.LeaseGeneration,
		OwnerID:                 claimedTask2.LeaseOwner,
		ExpectedJournalRevision: 1,
		Audit:                   audit,
	}
	err = store.CommitArtifactReceipt(ctx, mismatchedCommitRec)
	if err == nil || !strings.Contains(err.Error(), "does not match journal staged authority material") {
		t.Fatalf("expected rejection of un-restaged authority receipt, got %v", err)
	}

	// Verify no receipt was written and journal remained in staging at revision 1
	if _, err := store.GetArtifactReceipt(ctx, planRes2.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after rejected commit, got %v", err)
	}
	jnl2, err := store.GetPackLifecycleJournal(ctx, planRes2.OperationID)
	if err != nil || jnl2.Phase != "staging" || jnl2.Revision != 1 {
		t.Fatalf("journal should remain in staging revision 1: %+v, err=%v", jnl2, err)
	}

	// Re-stage under authority 2
	stageIntent2.AuthorityCatalogSHA256 = snapRenewed2.CatalogSHA256
	stageIntent2.AuthoritySequence = 2
	stageIntent2.AuthorityExpiresAt = snapRenewed2.ExpiresAt
	rev2Updated, err := store.RecordStageIntent(ctx, stageIntent2)
	if err != nil || rev2Updated != 2 {
		t.Fatalf("re-stage under authority 2 failed: rev=%d err=%v", rev2Updated, err)
	}

	// Now commit receipt for material 2 succeeds
	mismatchedCommitRec.ExpectedJournalRevision = 2
	err = store.CommitArtifactReceipt(ctx, mismatchedCommitRec)
	if err != nil {
		t.Fatalf("commit receipt after re-staging under authority 2 failed: %v", err)
	}

	// 21. Reopen store with standard Open(cfg) to verify migration 0007 reopen
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopenedStore, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen store failed: %v", err)
	}
	defer reopenedStore.Close()

	reopenedStatus, reopenedRcpt, err := reopenedStore.GetPackStatus(ctx, "fixture-echo")
	if err != nil {
		t.Fatalf("reopened get pack status: %v", err)
	}
	if reopenedStatus != "artifact_verified" || reopenedRcpt == nil || reopenedRcpt.ReceiptID != rcptID.String() {
		t.Fatalf("reopened status mismatch: status=%s, rcpt=%v", reopenedStatus, reopenedRcpt)
	}
}
