//go:build linux

package hosthelper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/packprotocol"
)

func dummyVerifier(stagePath string, opID string, snap packprotocol.Selection, planSHA string, rawManifest []byte, expectedStageIdentity string, ownerUID int, ownerGID int) (*contracts.PackArtifactReceipt, error) {
	return &contracts.PackArtifactReceipt{
		ReceiptID:          "rcpt-test-1",
		OperationID:        opID,
		PackID:             snap.PackID,
		Version:            snap.Version,
		PlanSHA256:         planSHA,
		ArchiveSHA256:      snap.ArtifactSHA256,
		ManifestSHA256:     snap.ManifestSHA256,
		ExecutableSHA256:   "dummy_adapter_sha",
		ExecutablePath:     "bin/adapter",
		StageIdentity:      expectedStageIdentity,
		MemberCount:        2,
		UnpackedTotalBytes: 100,
	}, nil
}

func testVerificationPolicies() map[string]packprotocol.VerificationPolicy {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return map[string]packprotocol.VerificationPolicy{
		"test-publisher": {
			Publisher:           "test-publisher",
			PublicKey:           pub,
			AllowedHosts:        []string{"test.invalid"},
			CoreVersion:         "1.0.0",
			ProtocolVersion:     "1.0",
			InstallationBinding: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
}

func TestHelperServerFailClosedConfiguration(t *testing.T) {
	tempDir := t.TempDir()

	baseCfg := ServerConfig{
		SocketPath:               filepath.Join(tempDir, "helper.sock"),
		StateDir:                 filepath.Join(tempDir, "state"),
		TrustedCoreUID:           1000,
		TrustedCoreExecutableSHA: "abc123",
		InstallationBinding:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Policies:                 testVerificationPolicies(),
		VerifyStagedInventory:    dummyVerifier,
	}

	// 1. Missing TrustedCoreUID fails closed
	cfg1 := baseCfg
	cfg1.TrustedCoreUID = 0
	if _, err := NewServer(cfg1); err == nil {
		t.Fatal("expected NewServer to fail with zero TrustedCoreUID")
	}

	// 2. Missing TrustedCoreExecutableSHA fails closed
	cfg2 := baseCfg
	cfg2.TrustedCoreExecutableSHA = ""
	if _, err := NewServer(cfg2); err == nil {
		t.Fatal("expected NewServer to fail with empty TrustedCoreExecutableSHA")
	}

	// 3. Missing InstallationBinding fails closed
	cfg3 := baseCfg
	cfg3.InstallationBinding = ""
	if _, err := NewServer(cfg3); err == nil {
		t.Fatal("expected NewServer to fail with empty InstallationBinding")
	}

	// 4. Missing VerifyStagedInventory fails closed
	cfg4 := baseCfg
	cfg4.VerifyStagedInventory = nil
	if _, err := NewServer(cfg4); err == nil {
		t.Fatal("expected NewServer to fail with nil VerifyStagedInventory")
	}

	// 5. Missing Policies fails closed
	cfg5 := baseCfg
	cfg5.Policies = nil
	if _, err := NewServer(cfg5); err == nil {
		t.Fatal("expected NewServer to fail with nil Policies")
	}

	// Valid config succeeds
	server, err := NewServer(baseCfg)
	if err != nil {
		t.Fatalf("NewServer failed on valid config: %v", err)
	}
	defer server.Close()
}

func TestHelperSocketGroupIsSeparateFromCorePrimaryGroup(t *testing.T) {
	legacy := &Server{config: ServerConfig{CoreGID: 981}}
	if legacy.socketGroup() != 981 {
		t.Fatal("legacy socket group no longer defaults to CoreGID")
	}
	separate := &Server{config: ServerConfig{CoreGID: 981, SocketGID: 1901}}
	if separate.socketGroup() != 1901 || separate.config.CoreGID != 981 {
		t.Fatal("socket group changed the Core primary-group authority fact")
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	server, err := NewServer(ServerConfig{SocketPath: path, RuntimeBindingPath: "/unused-protected-binding", ReadOnlyPeerOnly: true, CoreGID: uint32(os.Getgid()), SocketGID: uint32(os.Getgid() + 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil {
		server.Close()
		t.Fatal("unpublished helper parent was silently chowned into the IPC group")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed helper parent validation created a socket")
	}
}

func TestHelperServerFloorAndReceiptDurablePersistence(t *testing.T) {
	tempDir := t.TempDir()
	cfg := ServerConfig{
		SocketPath:               filepath.Join(tempDir, "helper.sock"),
		StateDir:                 filepath.Join(tempDir, "state"),
		TrustedCoreUID:           uint32(os.Getuid()),
		TrustedCoreExecutableSHA: "dummy_exe_sha",
		InstallationBinding:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Policies:                 testVerificationPolicies(),
		VerifyStagedInventory:    dummyVerifier,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// 1. Initial floor is 0
	if server.coreEpochFloor != 0 {
		t.Fatalf("expected initial floor 0, got %d", server.coreEpochFloor)
	}

	// 2. Save floor 5
	if err := server.saveFloor(5); err != nil {
		t.Fatalf("saveFloor failed: %v", err)
	}

	// 3. Re-open server and check floor loaded
	server2, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server2.Close()
	if server2.coreEpochFloor != 5 {
		t.Fatalf("expected reloaded floor 5, got %d", server2.coreEpochFloor)
	}

	// 4. Persist receipt and check replay
	packID := "test-pack-persist"
	opID := "op-test-123"

	// Fake currentCore to match permit
	server.currentCore = &CoreRegistration{
		CorePID:             int32(os.Getpid()),
		CoreUID:             uint32(os.Getuid()),
		CoreGeneration:      1,
		InstallationBinding: cfg.InstallationBinding,
	}

	permit1 := ActionPermit{
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		CoreGeneration:  1,
		LeaseGeneration: 1,
		OwnerID:         "owner-1",
		Deadline:        time.Now().UTC().Add(time.Hour),
		ActionID:        "act-prep-1",
		Sequence:        1,
	}

	digest1 := server.computeRequestDigest(ActionPrepare, permit1, nil)
	rcpt1 := HelperEffectReceipt{
		ActionID:        "act-prep-1",
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		Action:          ActionPrepare,
		Status:          StatusSucceeded,
		CoreGeneration:  1,
		LeaseGeneration: 1,
		Sequence:        1,
		RequestDigest:   digest1,
		RecordedAt:      time.Now().UTC(),
	}
	if err := server.persistReceipt(rcpt1); err != nil {
		t.Fatalf("persist receipt 1: %v", err)
	}

	// Replay exact same actionID, sequence, and digest: must return isReplay=true
	isReplay, saved, err := server.validatePermitAndCheckReplayLocked(permit1, ActionPrepare, digest1)
	if err != nil || !isReplay || saved == nil {
		t.Fatalf("expected valid replay, got isReplay=%v, saved=%v, err=%v", isReplay, saved, err)
	}

	// Replay with changed digest (different input) under reused action ID: must be rejected
	differentDigest := server.computeRequestDigest(ActionPrepare, permit1, []byte("changed_input"))
	_, _, err = server.validatePermitAndCheckReplayLocked(permit1, ActionPrepare, differentDigest)
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflict on changed inputs under reused sequence, got %v", err)
	}

	// Non-monotonic sequence (jump from 1 to 3) rejected
	permitJump := permit1
	permitJump.Sequence = 3
	permitJump.ActionID = "act-jump"
	digestJump := server.computeRequestDigest(ActionPublish, permitJump, nil)
	_, _, err = server.validatePermitAndCheckReplayLocked(permitJump, ActionPublish, digestJump)
	if err == nil {
		t.Fatal("expected non-monotonic sequence to be rejected")
	}

	// Sequence 2: valid ActionAbort
	permitAbort := permit1
	permitAbort.Sequence = 2
	permitAbort.ActionID = "act-abort-2"
	digestAbort := server.computeRequestDigest(ActionAbort, permitAbort, []byte("user_cancelled"))
	rcpt2 := HelperEffectReceipt{
		ActionID:        "act-abort-2",
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		Action:          ActionAbort,
		Status:          StatusAborted,
		CoreGeneration:  1,
		LeaseGeneration: 1,
		Sequence:        2,
		RequestDigest:   digestAbort,
		RecordedAt:      time.Now().UTC(),
	}
	if err := server.persistReceipt(rcpt2); err != nil {
		t.Fatalf("persist abort receipt: %v", err)
	}

	// Subsequent mutating action on aborted operation must be rejected
	permitPostAbort := permit1
	permitPostAbort.Sequence = 3
	permitPostAbort.ActionID = "act-post-abort"
	digestPost := server.computeRequestDigest(ActionStart, permitPostAbort, nil)
	_, _, err = server.validatePermitAndCheckReplayLocked(permitPostAbort, ActionStart, digestPost)
	if err == nil || !strings.Contains(err.Error(), "already been aborted") {
		t.Fatalf("expected rejected mutation on aborted operation, got %v", err)
	}
}

func TestHelperServerCallerAuthentication(t *testing.T) {
	tempDir := t.TempDir()
	cfg := ServerConfig{
		SocketPath:               filepath.Join(tempDir, "helper.sock"),
		StateDir:                 filepath.Join(tempDir, "state"),
		TrustedCoreUID:           99999, // Intentional mismatch with current UID
		TrustedCoreExecutableSHA: "dummy_exe_sha",
		InstallationBinding:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Policies:                 testVerificationPolicies(),
		VerifyStagedInventory:    dummyVerifier,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client := newClientWithExpectedServerUID(cfg.SocketPath, uint32(os.Getuid()), time.Second)
	ctx := context.Background()

	// Calling with untrusted UID must receive 403 Forbidden
	_, err = client.RegisterCore(ctx, RegisterCoreRequest{
		Registration: CoreRegistration{
			CorePID:             int32(os.Getpid()),
			CoreUID:             uint32(os.Getuid()),
			InstallationBinding: cfg.InstallationBinding,
			CoreGeneration:      1,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 forbidden for untrusted UID, got %v", err)
	}
}

func TestHelperServerSetgidRunDirectoryMode(t *testing.T) {
	tempDir := t.TempDir()
	runDir := filepath.Join(tempDir, "run_test")
	if err := os.MkdirAll(runDir, 0770); err != nil {
		t.Fatal(err)
	}

	// Must set mode using Go os.ModeSetgid
	if err := os.Chmod(runDir, os.ModeSetgid|0770); err != nil {
		t.Fatalf("chmod with ModeSetgid failed: %v", err)
	}

	info, err := os.Stat(runDir)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0770 {
		t.Fatalf("expected Perm() == 0770, got %o", info.Mode().Perm())
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("expected ModeSetgid bit set in Mode(), got %v", info.Mode())
	}
}

func TestHelperServerReplayOlderLeaseRejection(t *testing.T) {
	tempDir := t.TempDir()
	cfg := ServerConfig{
		SocketPath:               filepath.Join(tempDir, "helper.sock"),
		StateDir:                 filepath.Join(tempDir, "state"),
		TrustedCoreUID:           uint32(os.Getuid()),
		TrustedCoreExecutableSHA: "dummy_exe_sha",
		InstallationBinding:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Policies:                 testVerificationPolicies(),
		VerifyStagedInventory:    dummyVerifier,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	server.currentCore = &CoreRegistration{
		CorePID:             int32(os.Getpid()),
		CoreUID:             uint32(os.Getuid()),
		CoreGeneration:      1,
		InstallationBinding: cfg.InstallationBinding,
	}

	packID := "test-pack-lease"
	opID := "op-test-lease"

	// 1. Record prepare at sequence 1, lease 1
	permit1 := ActionPermit{
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		CoreGeneration:  1,
		LeaseGeneration: 1,
		OwnerID:         "owner-1",
		Deadline:        time.Now().UTC().Add(time.Hour),
		ActionID:        "act-prep-1",
		Sequence:        1,
	}
	digest1 := server.computeRequestDigest(ActionPrepare, permit1, nil)
	rcpt1 := HelperEffectReceipt{
		ActionID:        "act-prep-1",
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		Action:          ActionPrepare,
		Status:          StatusSucceeded,
		CoreGeneration:  1,
		LeaseGeneration: 1,
		Sequence:        1,
		RequestDigest:   digest1,
		RecordedAt:      time.Now().UTC(),
	}
	if err := server.persistReceipt(rcpt1); err != nil {
		t.Fatalf("persist receipt 1: %v", err)
	}

	// 2. Advance to lease 2, sequence 2 (publish)
	permit2 := ActionPermit{
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		CoreGeneration:  1,
		LeaseGeneration: 2,
		OwnerID:         "owner-1",
		Deadline:        time.Now().UTC().Add(time.Hour),
		ActionID:        "act-pub-2",
		Sequence:        2,
	}
	digest2 := server.computeRequestDigest(ActionPublish, permit2, nil)
	rcpt2 := HelperEffectReceipt{
		ActionID:        "act-pub-2",
		OperationID:     opID,
		PackID:          packID,
		Version:         "1.0.0",
		Action:          ActionPublish,
		Status:          StatusSucceeded,
		CoreGeneration:  1,
		LeaseGeneration: 2,
		Sequence:        2,
		RequestDigest:   digest2,
		RecordedAt:      time.Now().UTC(),
	}
	if err := server.persistReceipt(rcpt2); err != nil {
		t.Fatalf("persist receipt 2: %v", err)
	}

	// 3. Attempting to replay prepare with older lease generation 1 MUST be rejected,
	// even if the prepare receipt is scanned first in the directory
	_, _, err = server.validatePermitAndCheckReplayLocked(permit1, ActionPrepare, digest1)
	if err == nil || !strings.Contains(err.Error(), "older than recorded floor") {
		t.Fatalf("expected older lease generation rejection, got %v", err)
	}
}

func TestHelperServerObserveCancellationSnapshot(t *testing.T) {
	tempDir := t.TempDir()
	cfg := ServerConfig{
		SocketPath:               filepath.Join(tempDir, "helper.sock"),
		StateDir:                 filepath.Join(tempDir, "state"),
		TrustedCoreUID:           uint32(os.Getuid()),
		TrustedCoreExecutableSHA: "dummy_exe_sha",
		InstallationBinding:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Policies:                 testVerificationPolicies(),
		VerifyStagedInventory:    dummyVerifier,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	packID := "test-pack-obs"
	opID := "op-test-obs-snap"

	// 1. Record publish, start, stop_for_recovery, abort, switch
	rcpts := []HelperEffectReceipt{
		{
			ActionID:        "act-pub-1",
			OperationID:     opID,
			PackID:          packID,
			Version:         "1.0.0",
			Action:          ActionPublish,
			Status:          StatusSucceeded,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			Sequence:        1,
			RequestDigest:   "sha256:pub",
			RecordedAt:      time.Now().UTC(),
		},
		{
			ActionID:        "act-start-2",
			OperationID:     opID,
			PackID:          packID,
			Version:         "1.0.0",
			Action:          ActionStart,
			Status:          StatusSucceeded,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			Sequence:        2,
			InstanceID:      "inst-obs-01",
			MainPID:         1234,
			RequestDigest:   "sha256:start",
			RecordedAt:      time.Now().UTC(),
		},
		{
			ActionID:        "act-stop-3",
			OperationID:     opID,
			PackID:          packID,
			Version:         "1.0.0",
			Action:          ActionStopForRecovery,
			Status:          StatusStoppedForRecovery,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			Sequence:        3,
			RequestDigest:   "sha256:stop",
			RecordedAt:      time.Now().UTC(),
		},
		{
			ActionID:        "act-abort-4",
			OperationID:     opID,
			PackID:          packID,
			Version:         "1.0.0",
			Action:          ActionAbort,
			Status:          StatusAborted,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			Sequence:        4,
			RequestDigest:   "sha256:abort",
			RecordedAt:      time.Now().UTC(),
		},
		{
			ActionID:        "act-switch-5",
			OperationID:     opID,
			PackID:          packID,
			Version:         "1.0.0",
			Action:          ActionSwitch,
			Status:          StatusSucceeded,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			Sequence:        5,
			CurrentTarget:   "1.0.0",
			RequestDigest:   "sha256:switch",
			RecordedAt:      time.Now().UTC(),
		},
	}
	for _, r := range rcpts {
		if err := server.persistReceipt(r); err != nil {
			t.Fatalf("persist receipt %s: %v", r.ActionID, err)
		}
	}

	// 2. Query cancellation snapshot via read-only inspection under pack lock
	lock := server.getPackLock(packID)
	lock.Lock()
	dir := filepath.Join(server.config.StateDir, packID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		lock.Unlock()
		t.Fatalf("read dir: %v", err)
	}

	var maxOpSeq int64 = 0
	var pubRcpt, startRcpt, stopRcpt, abortRcpt, switchRcpt *HelperEffectReceipt
	for _, e := range entries {
		if strings.Contains(e.Name(), "_"+opID+"_") && strings.HasSuffix(e.Name(), ".json") {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err == nil {
				var rcpt HelperEffectReceipt
				if json.Unmarshal(data, &rcpt) == nil && rcpt.OperationID == opID {
					if rcpt.Sequence > maxOpSeq {
						maxOpSeq = rcpt.Sequence
					}
					if rcpt.Action == ActionPublish && rcpt.Status == StatusSucceeded {
						if pubRcpt == nil || rcpt.Sequence > pubRcpt.Sequence {
							c := rcpt
							pubRcpt = &c
						}
					}
					if rcpt.Action == ActionStart && rcpt.Status == StatusSucceeded {
						if startRcpt == nil || rcpt.Sequence > startRcpt.Sequence {
							c := rcpt
							startRcpt = &c
						}
					}
					if rcpt.Action == ActionStopForRecovery && rcpt.Status == StatusStoppedForRecovery {
						if stopRcpt == nil || rcpt.Sequence > stopRcpt.Sequence {
							c := rcpt
							stopRcpt = &c
						}
					}
					if rcpt.Action == ActionAbort && rcpt.Status == StatusAborted {
						if abortRcpt == nil || rcpt.Sequence > abortRcpt.Sequence {
							c := rcpt
							abortRcpt = &c
						}
					}
					if rcpt.Action == ActionSwitch && rcpt.Status == StatusSucceeded {
						if switchRcpt == nil || rcpt.Sequence > switchRcpt.Sequence {
							c := rcpt
							switchRcpt = &c
						}
					}
				}
			}
		}
	}
	lock.Unlock()

	if maxOpSeq != 5 {
		t.Fatalf("expected MaxOperationSequence 5, got %d", maxOpSeq)
	}
	if pubRcpt == nil || pubRcpt.ActionID != "act-pub-1" {
		t.Fatalf("expected pubRcpt act-pub-1, got %+v", pubRcpt)
	}
	if startRcpt == nil || startRcpt.ActionID != "act-start-2" {
		t.Fatalf("expected startRcpt act-start-2, got %+v", startRcpt)
	}
	if stopRcpt == nil || stopRcpt.ActionID != "act-stop-3" {
		t.Fatalf("expected stopRcpt act-stop-3, got %+v", stopRcpt)
	}
	if abortRcpt == nil || abortRcpt.ActionID != "act-abort-4" {
		t.Fatalf("expected abortRcpt act-abort-4, got %+v", abortRcpt)
	}
	if switchRcpt == nil || switchRcpt.ActionID != "act-switch-5" {
		t.Fatalf("expected switchRcpt act-switch-5, got %+v", switchRcpt)
	}
}

func TestRuntimePeerTargetAllowsOnlyFixedSourceBuildPair(t *testing.T) {
	b := &localpeer.RuntimePeerBinding{CorePID: 10, CoreUID: 1000, ContainerPID: 11, ContainerUID: 1001, SourceBuildPID: 12, SourceBuildUID: 1002}
	for _, pair := range [][2]string{{"core", "container"}, {"container", "core"}, {"core", "source-build"}, {"source-build", "core"}} {
		pid, uid, _, _, ok := runtimePeerTarget(b, pair[0], pair[1])
		if !ok || pid <= 0 || uid == 0 {
			t.Fatal("fixed counterpart rejected")
		}
	}
	for _, pair := range [][2]string{{"container", "source-build"}, {"source-build", "container"}, {"core", "arbitrary"}, {"arbitrary", "core"}, {"source-build", "source-build"}} {
		if _, _, _, _, ok := runtimePeerTarget(b, pair[0], pair[1]); ok {
			t.Fatal("untrusted runtime role pair allowed")
		}
	}
	b.SourceBuildPID = 0
	b.SourceBuildUID = 0
	if _, _, _, _, ok := runtimePeerTarget(b, "core", "source-build"); ok {
		t.Fatal("unconfigured source role accepted")
	}
}

func TestRuntimePeerTargetAllowsOnlyCoreGatewayPair(t *testing.T) {
	b := &localpeer.RuntimePeerBinding{CorePID: 10, CoreUID: 1000, ContainerPID: 11, ContainerUID: 1001, SourceBuildPID: 12, SourceBuildUID: 1002, GatewayPID: 13, GatewayUID: 1003}
	for _, pair := range [][2]string{{"core", "gateway"}, {"gateway", "core"}} {
		pid, uid, _, _, ok := runtimePeerTarget(b, pair[0], pair[1])
		if !ok || pid <= 0 || uid == 0 {
			t.Fatalf("approved Gateway pair rejected: %v", pair)
		}
	}
	for _, pair := range [][2]string{{"gateway", "container"}, {"container", "gateway"}, {"gateway", "source-build"}, {"source-build", "gateway"}, {"gateway", "gateway"}} {
		if _, _, _, _, ok := runtimePeerTarget(b, pair[0], pair[1]); ok {
			t.Fatalf("extra Gateway authority accepted: %v", pair)
		}
	}
	b.GatewayPID = 0
	b.GatewayUID = 0
	if _, _, _, _, ok := runtimePeerTarget(b, "core", "gateway"); ok {
		t.Fatal("absent Gateway role accepted")
	}
}
