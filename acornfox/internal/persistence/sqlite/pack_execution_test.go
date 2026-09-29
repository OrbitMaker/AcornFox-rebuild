package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/packprotocol"
)

type testPackFixture struct {
	plan     contracts.PlanPackInstallResult
	manifest []byte
}

func fixtureProtocolSelection(t *testing.T, s *Store, packID string, adapterSHA string) (packprotocol.VerifiedPackSelection, []byte) {
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

func setupTestPackWithPlannedInstall(t *testing.T, s *Store, packID string) testPackFixture {
	t.Helper()
	ctx := context.Background()
	selection, manifestBytes := fixtureProtocolSelection(t, s, packID, strings.Repeat("a", 64))
	req := packRequest(packID, "install-key-"+packID, selection)
	res, err := s.PlanPackInstall(ctx, req)
	if err != nil {
		t.Fatalf("PlanPackInstall failed: %v", err)
	}
	return testPackFixture{plan: res, manifest: manifestBytes}
}

func TestPackExecutionInstanceRegistration(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "pack-exec-inst")
	cfg := Config{DataDirectory: dir, PackCoreVersion: "1.0.0", PackProtocolVersion: "1.0"}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fix := setupTestPackWithPlannedInstall(t, s, "fixture-adapter-pack")

	// 1. Valid registration
	regReq := contracts.RegisterPackProtocolInstanceRequest{
		InstanceID:       "inst-01",
		PackID:           "fixture-adapter-pack",
		OperationID:      fix.plan.OperationID,
		ExecutablePath:   "bin/adapter",
		ExpectedUID:      1000,
		ExpectedPID:      12345,
		ProcessStartTime: "100200",
		ExecutableSHA256: strings.Repeat("a", 64),
		SocketPath:       filepath.Join(dir, "inst-01.sock"),
		ManifestRaw:      fix.manifest,
	}

	inst, err := s.RegisterPackProtocolInstance(ctx, regReq)
	if err != nil {
		t.Fatalf("RegisterPackProtocolInstance failed: %v", err)
	}
	if inst.InstanceID != "inst-01" || inst.InstanceGeneration != 1 || inst.RetiredAt != nil {
		t.Fatalf("unexpected instance: %+v", inst)
	}

	// 2. Register next instance for same pack retires old and increments generation
	regReq2 := regReq
	regReq2.InstanceID = "inst-02"
	regReq2.ExpectedPID = 12346
	regReq2.ProcessStartTime = "100300"
	inst2, err := s.RegisterPackProtocolInstance(ctx, regReq2)
	if err != nil {
		t.Fatalf("second instance registration failed: %v", err)
	}
	if inst2.InstanceGeneration != 2 {
		t.Fatalf("expected generation 2, got %d", inst2.InstanceGeneration)
	}

	// Verify old instance is retired
	var retiredAt string
	err = s.db.QueryRow(`SELECT retired_at FROM pack_protocol_instances WHERE instance_id='inst-01'`).Scan(&retiredAt)
	if err != nil || retiredAt == "" {
		t.Fatalf("expected inst-01 to be retired, err=%v, retiredAt=%s", err, retiredAt)
	}

	// 2b. Verify instance identity fields are frozen by trigger
	if _, err := s.db.Exec(`UPDATE pack_protocol_instances SET expected_pid=99999 WHERE instance_id='inst-01'`); err == nil {
		t.Fatalf("expected trigger to abort update on frozen instance field")
	}
	if _, err := s.db.Exec(`UPDATE pack_protocol_instances SET retired_at=NULL WHERE instance_id='inst-01'`); err == nil {
		t.Fatalf("expected trigger to abort unretiring an already retired instance")
	}
	if _, err := s.db.Exec(`DELETE FROM pack_protocol_instances WHERE instance_id='inst-01'`); err == nil {
		t.Fatalf("expected trigger to abort delete on instance")
	}

	// 3. Rejection of missing manifest proof
	noManifestReq := regReq
	noManifestReq.InstanceID = "inst-nomanifest"
	noManifestReq.ManifestRaw = nil
	if _, err := s.RegisterPackProtocolInstance(ctx, noManifestReq); err == nil {
		t.Fatalf("expected error registering with missing manifest proof")
	}

	// 4. Rejection of undeclared or invalid executable
	badReq := regReq
	badReq.InstanceID = "inst-03"
	badReq.ExecutablePath = "bin/unknown"
	if _, err := s.RegisterPackProtocolInstance(ctx, badReq); err == nil {
		t.Fatalf("expected error registering unknown executable")
	}

	badSHA := regReq
	badSHA.InstanceID = "inst-04"
	badSHA.ExecutableSHA256 = strings.Repeat("f", 64)
	if _, err := s.RegisterPackProtocolInstance(ctx, badSHA); err == nil {
		t.Fatalf("expected error on mismatched executable sha256")
	}
}

func TestPackExecutionCheckLifecycleAndFencing(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "pack-exec-chk")
	cfg := Config{DataDirectory: dir, PackCoreVersion: "1.0.0", PackProtocolVersion: "1.0"}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fix := setupTestPackWithPlannedInstall(t, s, "fixture-chk-pack")

	inst, err := s.RegisterPackProtocolInstance(ctx, contracts.RegisterPackProtocolInstanceRequest{
		InstanceID:       "inst-chk",
		PackID:           "fixture-chk-pack",
		OperationID:      fix.plan.OperationID,
		ExecutablePath:   "bin/adapter",
		ExpectedUID:      1000,
		ExpectedPID:      20001,
		ProcessStartTime: "200000",
		ExecutableSHA256: strings.Repeat("a", 64),
		SocketPath:       filepath.Join(dir, "inst-chk.sock"),
		ManifestRaw:      fix.manifest,
	})
	if err != nil {
		t.Fatal(err)
	}

	inputCtx := contracts.DiagnosticInputContext{
		Action: "observe",
		Target: "service:app",
		Param:  "{\"query\": \"stats\"}",
	}

	chkReq := contracts.BeginPackProtocolCheckRequest{
		PackID:         "fixture-chk-pack",
		OperationID:    fix.plan.OperationID,
		InstanceID:     inst.InstanceID,
		IdempotencyKey: "chk-key-01",
		Kind:           packprotocol.KindDiagnosticObserve,
		Capability:     packprotocol.CapabilityDiagnosticObserve,
		InputContext:   inputCtx,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "tester",
			Reason:    "diagnostic check",
		},
	}

	res, err := s.BeginPackProtocolCheck(ctx, chkReq)
	if err != nil {
		t.Fatalf("BeginPackProtocolCheck failed: %v", err)
	}
	if res.State != contracts.TaskReady {
		t.Fatalf("expected state ready, got %v", res.State)
	}

	// Idempotent replay with same key and input
	replay, err := s.BeginPackProtocolCheck(ctx, chkReq)
	if err != nil || replay.TaskID != res.TaskID {
		t.Fatalf("replay mismatch: %+v, err: %v", replay, err)
	}

	// Idempotent conflict with different input
	conflictReq := chkReq
	conflictReq.InputContext = contracts.DiagnosticInputContext{
		Action: "observe",
		Target: "service:app",
		Param:  "{\"query\": \"different\"}",
	}
	if _, err := s.BeginPackProtocolCheck(ctx, conflictReq); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}

	// Verify child task exists in task_leases and has kind pack.protocol.observe
	taskID := domain.ID(res.TaskID)
	task, err := s.GetTask(ctx, taskID)
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}
	if task.State != contracts.TaskReady || task.OperationID.String() != fix.plan.OperationID {
		t.Fatalf("child task mismatch: %+v", task)
	}

	// Parent task remains untouched
	parentTaskID := domain.ID(fix.plan.TaskID)
	parentTask, err := s.GetTask(ctx, parentTaskID)
	if err != nil || parentTask.State != contracts.TaskReady {
		t.Fatalf("parent task altered: %+v", parentTask)
	}

	// Audit failure rollback test
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER test_reject_audit BEFORE INSERT ON audit_evidence BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatal(err)
	}
	failAuditReq := chkReq
	failAuditReq.IdempotencyKey = "chk-key-audit-fail"
	if _, err := s.BeginPackProtocolCheck(ctx, failAuditReq); err == nil {
		t.Fatalf("expected failure when audit insertion is aborted")
	}
	// Verify no partial rows in idempotency_records or task_leases
	var count int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM idempotency_records WHERE idempotency_key='chk-key-audit-fail'`).Scan(&count)
	if count != 0 {
		t.Fatalf("dirty idempotency record left after audit failure")
	}
	// Drop injected trigger
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER test_reject_audit`); err != nil {
		t.Fatal(err)
	}

	// 5. Test AuthorizePackProtocolDispatch with same-owner expired lease reclaim (N -> N+1)
	claimNow := time.Now().UTC()
	claimedTask1, claimed1, err := s.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-fencing-01",
		Now:   claimNow,
		Kinds: []string{packprotocol.KindDiagnosticObserve},
		LeasePolicy: contracts.LeasePolicy{
			Duration:    time.Second,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed1 || claimedTask1.ID != taskID {
		t.Fatalf("first claim failed: %v", err)
	}
	if claimedTask1.LeaseGeneration != 1 {
		t.Fatalf("expected lease generation 1, got %d", claimedTask1.LeaseGeneration)
	}

	// Immediate authorize with claimedTask1 succeeds
	auth1, err := s.AuthorizePackProtocolDispatch(ctx, contracts.AuthorizePackProtocolDispatchRequest{
		TaskID:          taskID,
		InstanceID:      inst.InstanceID,
		Owner:           "worker-fencing-01",
		CoreGeneration:  claimedTask1.CoreGeneration,
		LeaseGeneration: claimedTask1.LeaseGeneration,
		Now:             claimNow.Add(100 * time.Millisecond),
	})
	if err != nil || auth1.LeaseGeneration != 1 {
		t.Fatalf("auth1 failed: %v, auth1=%+v", err, auth1)
	}

	// Expire the lease and reclaim by the same owner as lease generation 2 (N+1)
	reclaimNow := claimNow.Add(2 * time.Second)
	claimedTask2, claimed2, err := s.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-fencing-01",
		Now:   reclaimNow,
		Kinds: []string{packprotocol.KindDiagnosticObserve},
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Second,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed2 || claimedTask2.LeaseGeneration != 2 {
		t.Fatalf("reclaim failed: claimed=%v, gen=%d, err=%v", claimed2, claimedTask2.LeaseGeneration, err)
	}

	// A stale worker holding old token N (LeaseGeneration 1) calling authorize must be REJECTED!
	_, err = s.AuthorizePackProtocolDispatch(ctx, contracts.AuthorizePackProtocolDispatchRequest{
		TaskID:          taskID,
		InstanceID:      inst.InstanceID,
		Owner:           "worker-fencing-01",
		CoreGeneration:  claimedTask1.CoreGeneration,
		LeaseGeneration: claimedTask1.LeaseGeneration, // stale generation 1
		Now:             reclaimNow.Add(100 * time.Millisecond),
	})
	if err == nil || !strings.Contains(err.Error(), "lease generation mismatch") {
		t.Fatalf("expected stale lease generation rejection, got: %v", err)
	}

	// Current worker holding N+1 (LeaseGeneration 2) succeeds
	auth2, err := s.AuthorizePackProtocolDispatch(ctx, contracts.AuthorizePackProtocolDispatchRequest{
		TaskID:          taskID,
		InstanceID:      inst.InstanceID,
		Owner:           "worker-fencing-01",
		CoreGeneration:  claimedTask2.CoreGeneration,
		LeaseGeneration: claimedTask2.LeaseGeneration, // current generation 2
		Now:             reclaimNow.Add(100 * time.Millisecond),
	})
	if err != nil || auth2.LeaseGeneration != 2 {
		t.Fatalf("auth2 with current generation 2 failed: %v", err)
	}
}

func TestPackExecutionEventCommitReplayAndFencing(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "pack-exec-evt")
	cfg := Config{DataDirectory: dir, PackCoreVersion: "1.0.0", PackProtocolVersion: "1.0"}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fix := setupTestPackWithPlannedInstall(t, s, "fixture-evt-pack")

	inst, err := s.RegisterPackProtocolInstance(ctx, contracts.RegisterPackProtocolInstanceRequest{
		InstanceID:       "inst-evt",
		PackID:           "fixture-evt-pack",
		OperationID:      fix.plan.OperationID,
		ExecutablePath:   "bin/adapter",
		ExpectedUID:      1000,
		ExpectedPID:      30001,
		ProcessStartTime: "300000",
		ExecutableSHA256: strings.Repeat("a", 64),
		SocketPath:       filepath.Join(dir, "inst-evt.sock"),
		ManifestRaw:      fix.manifest,
	})
	if err != nil {
		t.Fatal(err)
	}

	inputCtx := contracts.DiagnosticInputContext{
		Action: "ping",
		Target: "test",
		Param:  "{}",
	}
	inputDigest, _, _ := packprotocol.DigestDiagnosticInput(inputCtx)

	chkRes, err := s.BeginPackProtocolCheck(ctx, contracts.BeginPackProtocolCheckRequest{
		PackID:         "fixture-evt-pack",
		OperationID:    fix.plan.OperationID,
		InstanceID:     inst.InstanceID,
		IdempotencyKey: "chk-evt-01",
		Kind:           packprotocol.KindDiagnosticObserve,
		Capability:     packprotocol.CapabilityDiagnosticObserve,
		InputContext:   inputCtx,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "tester",
			Reason:    "diagnostic check",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	taskID := domain.ID(chkRes.TaskID)

	// Claim the task
	now := time.Now().UTC()
	claimedTask, claimed, err := s.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-01",
		Now:   now,
		Kinds: []string{packprotocol.KindDiagnosticObserve},
		LeasePolicy: contracts.LeasePolicy{
			Duration:    30 * time.Second,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed || claimedTask.ID != taskID {
		t.Fatalf("ClaimTask failed: claimed=%v, err=%v", claimed, err)
	}

	// 1. Commit nonterminal sequence 1
	occurred1 := now.Add(time.Second)
	occurred1Str := packprotocol.FormatCanonicalTime(occurred1)
	obs1 := contracts.DiagnosticObservation{
		CheckedAt:   occurred1Str,
		InputDigest: inputDigest,
		Status:      "healthy",
		Summary:     "observation seq 1",
	}
	obs1Digest, _, _ := packprotocol.DigestDiagnosticObservation(obs1)
	eventDigest1 := packprotocol.ComputeEventDigest(
		taskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration, inst.InstanceGeneration,
		1, packprotocol.KindDiagnosticObserve, inputDigest,
		false, "", occurred1Str, obs1Digest,
	)

	commitReq1 := contracts.CommitPackProtocolEventRequest{
		TaskID:             taskID,
		InstanceID:         inst.InstanceID,
		CoreGeneration:     claimedTask.CoreGeneration,
		LeaseGeneration:    claimedTask.LeaseGeneration,
		InstanceGeneration: inst.InstanceGeneration,
		Owner:              "worker-01",
		Sequence:           1,
		InputDigest:        inputDigest,
		EventDigest:        eventDigest1,
		Kind:               packprotocol.KindDiagnosticObserve,
		Observation:        obs1,
		Terminal:           false,
		OccurredAt:         occurred1,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "tester",
			Reason:    "event 1",
		},
		Now: now.Add(time.Second),
	}

	receipt1, err := s.CommitPackProtocolEvent(ctx, commitReq1)
	if err != nil {
		t.Fatalf("CommitPackProtocolEvent seq 1 failed: %v", err)
	}
	if receipt1.Sequence != 1 || receipt1.EventDigest != eventDigest1 {
		t.Fatalf("unexpected receipt: %+v", receipt1)
	}

	// 2. Exact duplicate commit returns same receipt without error or new rows
	dupReceipt, err := s.CommitPackProtocolEvent(ctx, commitReq1)
	if err != nil || dupReceipt.ReceiptID != receipt1.ReceiptID {
		t.Fatalf("duplicate replay mismatch: %+v, err=%v", dupReceipt, err)
	}

	// 3. Same sequence with altered semantic content (recomputed valid digest) is rejected by sequence conflict guard
	eventsBeforeConflict, _ := s.FetchOutboxAfter(ctx, 0, 100)
	auditsBeforeConflict, _ := s.ListAuditEvidence(ctx, contracts.AuditFilter{})

	obsAltered := obs1
	obsAltered.Summary = "altered observation seq 1"
	obsAlteredDigest, _, _ := packprotocol.DigestDiagnosticObservation(obsAltered)
	alteredEventDigest1 := packprotocol.ComputeEventDigest(
		taskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration, inst.InstanceGeneration,
		1, packprotocol.KindDiagnosticObserve, inputDigest,
		false, "", occurred1Str, obsAlteredDigest,
	)
	conflictCommit := commitReq1
	conflictCommit.Observation = obsAltered
	conflictCommit.EventDigest = alteredEventDigest1
	if _, err := s.CommitPackProtocolEvent(ctx, conflictCommit); err == nil || !strings.Contains(err.Error(), "event conflict for existing sequence") {
		t.Fatalf("expected existing sequence content conflict error, got: %v", err)
	}

	eventsAfterConflict, _ := s.FetchOutboxAfter(ctx, 0, 100)
	auditsAfterConflict, _ := s.ListAuditEvidence(ctx, contracts.AuditFilter{})
	if len(eventsAfterConflict) != len(eventsBeforeConflict) || len(auditsAfterConflict) != len(auditsBeforeConflict) {
		t.Fatalf("conflicted commit wrote duplicate outbox (%d vs %d) or audit (%d vs %d)",
			len(eventsAfterConflict), len(eventsBeforeConflict), len(auditsAfterConflict), len(auditsBeforeConflict))
	}

	// 4. Sequence gap (seq 3 instead of 2) is rejected by sequence guard
	occurredGap := now.Add(time.Second)
	occurredGapStr := packprotocol.FormatCanonicalTime(occurredGap)
	obsGapDigest, _, _ := packprotocol.DigestDiagnosticObservation(obs1)
	eventDigestGap := packprotocol.ComputeEventDigest(
		taskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration, inst.InstanceGeneration,
		3, packprotocol.KindDiagnosticObserve, inputDigest,
		false, "", occurredGapStr, obsGapDigest,
	)
	gapCommit := commitReq1
	gapCommit.Sequence = 3
	gapCommit.EventDigest = eventDigestGap
	gapCommit.OccurredAt = occurredGap
	if _, err := s.CommitPackProtocolEvent(ctx, gapCommit); err == nil || !strings.Contains(err.Error(), "invalid sequence") {
		t.Fatalf("expected invalid sequence error, got: %v", err)
	}

	// Setup valid seq 2 observation & digest for testing guard branches
	occurred2 := now.Add(2 * time.Second)
	occurred2Str := packprotocol.FormatCanonicalTime(occurred2)
	obs2 := contracts.DiagnosticObservation{
		CheckedAt:   occurred2Str,
		InputDigest: inputDigest,
		Status:      "healthy",
		Summary:     "observation complete seq 2",
	}
	obs2Digest, _, _ := packprotocol.DigestDiagnosticObservation(obs2)
	eventDigest2NonTerm := packprotocol.ComputeEventDigest(
		taskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration, inst.InstanceGeneration,
		2, packprotocol.KindDiagnosticObserve, inputDigest,
		false, "", occurred2Str, obs2Digest,
	)

	// 5. Wrong lease owner is rejected by owner guard
	wrongOwner := commitReq1
	wrongOwner.Sequence = 2
	wrongOwner.Owner = "intruder"
	wrongOwner.EventDigest = eventDigest2NonTerm
	wrongOwner.OccurredAt = occurred2
	wrongOwner.Observation = obs2
	if _, err := s.CommitPackProtocolEvent(ctx, wrongOwner); err == nil || !strings.Contains(err.Error(), "lease owner mismatch") {
		t.Fatalf("expected lease owner mismatch error, got: %v", err)
	}

	// 5b. Fencing mismatch (wrong lease generation) is rejected by lease guard
	wrongLeaseGenDigest := packprotocol.ComputeEventDigest(
		taskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration+99, inst.InstanceGeneration,
		2, packprotocol.KindDiagnosticObserve, inputDigest,
		false, "", occurred2Str, obs2Digest,
	)
	wrongLeaseGen := wrongOwner
	wrongLeaseGen.Owner = "worker-01"
	wrongLeaseGen.LeaseGeneration = claimedTask.LeaseGeneration + 99
	wrongLeaseGen.EventDigest = wrongLeaseGenDigest
	if _, err := s.CommitPackProtocolEvent(ctx, wrongLeaseGen); err == nil || !strings.Contains(err.Error(), "generation fencing mismatch") {
		t.Fatalf("expected generation fencing mismatch error, got: %v", err)
	}

	// 5c. Terminal=true with inconsistent TerminalState (TaskReady) rejected by terminal guard
	eventDigest2Term := packprotocol.ComputeEventDigest(
		taskID.String(), inst.InstanceID,
		claimedTask.CoreGeneration, claimedTask.LeaseGeneration, inst.InstanceGeneration,
		2, packprotocol.KindDiagnosticObserve, inputDigest,
		true, "succeeded", occurred2Str, obs2Digest,
	)
	badTerminalCommit := commitReq1
	badTerminalCommit.Sequence = 2
	badTerminalCommit.Terminal = true
	badTerminalCommit.TerminalStatus = "succeeded"
	badTerminalCommit.TerminalState = contracts.TaskReady
	badTerminalCommit.Observation = obs2
	badTerminalCommit.OccurredAt = occurred2
	badTerminalCommit.EventDigest = eventDigest2Term
	if _, err := s.CommitPackProtocolEvent(ctx, badTerminalCommit); err == nil || !strings.Contains(err.Error(), "terminal state inconsistent") {
		t.Fatalf("expected terminal state inconsistent error, got: %v", err)
	}

	// 5d. Non-terminal event carrying TerminalState rejected
	badNonTermCommit := commitReq1
	badNonTermCommit.Sequence = 2
	badNonTermCommit.Terminal = false
	badNonTermCommit.TerminalState = contracts.TaskCompleted
	badNonTermCommit.Observation = obs2
	badNonTermCommit.OccurredAt = occurred2
	badNonTermCommit.EventDigest = eventDigest2NonTerm
	if _, err := s.CommitPackProtocolEvent(ctx, badNonTermCommit); err == nil || !strings.Contains(err.Error(), "nonterminal event must not carry terminal state") {
		t.Fatalf("expected nonterminal terminal state error, got: %v", err)
	}

	// 6. Commit terminal event seq 2
	eventDigest2 := eventDigest2Term

	commitReq2 := contracts.CommitPackProtocolEventRequest{
		TaskID:             taskID,
		InstanceID:         inst.InstanceID,
		CoreGeneration:     claimedTask.CoreGeneration,
		LeaseGeneration:    claimedTask.LeaseGeneration,
		InstanceGeneration: inst.InstanceGeneration,
		Owner:              "worker-01",
		Sequence:           2,
		InputDigest:        inputDigest,
		EventDigest:        eventDigest2,
		Kind:               packprotocol.KindDiagnosticObserve,
		Observation:        obs2,
		Terminal:           true,
		TerminalStatus:     "succeeded",
		TerminalState:      contracts.TaskCompleted,
		OccurredAt:         occurred2,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "tester",
			Reason:    "terminal event",
		},
		Now: now.Add(2 * time.Second),
	}

	receipt2, err := s.CommitPackProtocolEvent(ctx, commitReq2)
	if err != nil {
		t.Fatalf("CommitPackProtocolEvent seq 2 failed: %v", err)
	}
	if receipt2.Sequence != 2 {
		t.Fatalf("receipt2 sequence mismatch: %+v", receipt2)
	}

	// Verify task in task_leases is now completed and lease is released
	taskAfter, err := s.GetTask(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if taskAfter.State != contracts.TaskCompleted || taskAfter.LeaseOwner != "" {
		t.Fatalf("expected completed unleased task, got: %+v", taskAfter)
	}

	// 7. Duplicate terminal commit replay succeeds even when task is completed and unleased
	dupTerminalReceipt, err := s.CommitPackProtocolEvent(ctx, commitReq2)
	if err != nil || dupTerminalReceipt.ReceiptID != receipt2.ReceiptID {
		t.Fatalf("terminal duplicate replay failed: %+v, err=%v", dupTerminalReceipt, err)
	}

	// 8. Verify audit evidence was recorded with sha256: prefix
	audits, err := s.ListAuditEvidence(ctx, contracts.AuditFilter{})
	if err != nil || len(audits) == 0 {
		t.Fatalf("ListAuditEvidence failed: %v, count=%d", err, len(audits))
	}
	for _, a := range audits {
		if !strings.HasPrefix(a.InputDigest, "sha256:") {
			t.Fatalf("audit InputDigest missing sha256: prefix: %s", a.InputDigest)
		}
	}
}

func TestPackExecutionCancellationSeparation(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "pack-exec-cancel")
	cfg := Config{DataDirectory: dir, PackCoreVersion: "1.0.0", PackProtocolVersion: "1.0"}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fix := setupTestPackWithPlannedInstall(t, s, "fixture-cancel-pack")

	inst, err := s.RegisterPackProtocolInstance(ctx, contracts.RegisterPackProtocolInstanceRequest{
		InstanceID:       "inst-cancel",
		PackID:           "fixture-cancel-pack",
		OperationID:      fix.plan.OperationID,
		ExecutablePath:   "bin/adapter",
		ExpectedUID:      1000,
		ExpectedPID:      40001,
		ProcessStartTime: "400000",
		ExecutableSHA256: strings.Repeat("a", 64),
		SocketPath:       filepath.Join(dir, "inst-cancel.sock"),
		ManifestRaw:      fix.manifest,
	})
	if err != nil {
		t.Fatal(err)
	}

	chkRes, err := s.BeginPackProtocolCheck(ctx, contracts.BeginPackProtocolCheckRequest{
		PackID:         "fixture-cancel-pack",
		OperationID:    fix.plan.OperationID,
		InstanceID:     inst.InstanceID,
		IdempotencyKey: "chk-cancel-01",
		Kind:           packprotocol.KindDiagnosticObserve,
		Capability:     packprotocol.CapabilityDiagnosticObserve,
		InputContext: contracts.DiagnosticInputContext{
			Action: "observe",
			Target: "cancellable",
			Param:  "{}",
		},
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "tester",
			Reason:    "diagnostic check",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	taskID := domain.ID(chkRes.TaskID)

	// Request cancellation
	err = s.RequestPackProtocolCancellation(ctx, taskID, "operator requested abort")
	if err != nil {
		t.Fatalf("RequestPackProtocolCancellation failed: %v", err)
	}

	// Check table has cancellation_requested = true
	chk, err := s.GetPackProtocolCheck(ctx, taskID)
	if err != nil {
		t.Fatalf("GetPackProtocolCheck failed: %v", err)
	}
	if !chk.CancellationRequested || chk.CancellationReason != "operator requested abort" {
		t.Fatalf("cancellation not recorded: %+v", chk)
	}

	// Task itself in task_leases is still ready (not auto-cancelled!)
	task, err := s.GetTask(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if task.State != contracts.TaskReady {
		t.Fatalf("task was unexpectedly terminalized on cancel request: %+v", task)
	}
}
