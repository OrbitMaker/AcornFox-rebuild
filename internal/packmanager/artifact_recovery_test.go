package packmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/packprotocol"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

func TestHelperCrashSubprocess(t *testing.T) {
	if os.Getenv("ACORNFOX_TEST_SUBPROCESS_CRASH") != "1" {
		return
	}

	ctx := context.Background()
	dbDir := os.Getenv("ACORNFOX_TEST_DB_DIR")
	stagingDir := os.Getenv("ACORNFOX_TEST_STAGING_DIR")
	serverURL := os.Getenv("ACORNFOX_TEST_SERVER_URL")
	opID := os.Getenv("ACORNFOX_TEST_OP_ID")
	pubKeyB64 := os.Getenv("ACORNFOX_TEST_PUB_KEY")
	certB64 := os.Getenv("ACORNFOX_TEST_CERT_B64")

	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subprocess decode pubkey: %v\n", err)
		os.Exit(97)
	}

	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subprocess decode cert: %v\n", err)
		os.Exit(97)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subprocess parse cert: %v\n", err)
		os.Exit(97)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)

	cfg := sqlite.Config{
		DataDirectory:       dbDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	}
	store, err := sqlite.Open(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subprocess open sqlite: %v\n", err)
		os.Exit(99)
	}
	defer store.Close()

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subprocess installation binding: %v\n", err)
		os.Exit(97)
	}
	now := time.Now().UTC()

	policy := packprotocol.VerificationPolicy{
		Publisher:           "test-publisher",
		PublicKey:           ed25519.PublicKey(pubBytes),
		AllowedHosts:        []string{"example.com"},
		CoreVersion:         "1.0.0",
		ProtocolVersion:     "1.0",
		OS:                  "linux",
		Arch:                "amd64",
		InstallationBinding: binding,
		Now:                 now,
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawURL := strings.TrimPrefix(serverURL, "https://")
			return (&net.Dialer{}).DialContext(ctx, network, rawURL)
		},
		TLSClientConfig: &tls.Config{
			ServerName: "example.com",
			RootCAs:    rootPool,
		},
	}
	client := &http.Client{Transport: tr}

	stager, err := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          policy,
		HTTPClient:      client,
		DownloadTimeout: 10 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "subprocess new stager: %v\n", err)
		os.Exit(98)
	}
	stager.setPreCommitHookForTest(func(stageDir string) error {
		// Controlled exit after file/directory sync, before DB receipt
		os.Exit(42)
		return nil
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	claimedTask, claimed, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		fmt.Fprintf(os.Stderr, "subprocess claim task: %v, claimed=%v\n", err, claimed)
		os.Exit(95)
	}

	_, stageErr := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     opID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if stageErr != nil {
		fmt.Fprintf(os.Stderr, "subprocess stage error: %v\n", stageErr)
		os.Exit(96)
	}
}

func TestArtifactStaging_CrashAfterFsyncBeforeDB(t *testing.T) {
	ctx := context.Background()
	store, server, client, stagingDir, serverHost, dbDir := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatalf("installation binding: %v", err)
	}
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture.archiveData)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-fsync-crash",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install: %v", err)
	}

	// Close store before launching subprocess so subprocess can open sqlite
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Run controlled crash in subprocess
	serverAddr := server.Listener.Addr().String()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperCrashSubprocess")
	cmd.Env = append(os.Environ(),
		"ACORNFOX_TEST_SUBPROCESS_CRASH=1",
		"ACORNFOX_TEST_DB_DIR="+dbDir,
		"ACORNFOX_TEST_STAGING_DIR="+stagingDir,
		"ACORNFOX_TEST_SERVER_URL=https://"+serverAddr,
		"ACORNFOX_TEST_OP_ID="+planRes.OperationID,
		"ACORNFOX_TEST_PUB_KEY="+base64.StdEncoding.EncodeToString(fixture.policy.PublicKey),
		"ACORNFOX_TEST_CERT_B64="+base64.StdEncoding.EncodeToString(server.Certificate().Raw),
	)

	// Subprocess should exit with status 42 (crash after fsync, before DB commit)
	output, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 42 {
		t.Fatalf("expected crash exit code 42, got %v, output: %s", err, string(output))
	}

	// Verify files are indeed on disk and fsynced
	opStageDir := filepath.Join(stagingDir, "staging", planRes.OperationID)
	if _, err := os.Stat(filepath.Join(opStageDir, "artifact.tar.gz")); err != nil {
		t.Fatalf("artifact.tar.gz not created before crash: %v", err)
	}
	if _, err := os.Stat(filepath.Join(opStageDir, "pack", "manifest.json")); err != nil {
		t.Fatalf("pack/manifest.json not created before crash: %v", err)
	}

	// Reopen store to test recovery across process lifetime
	reopenedStore, err := sqlite.Open(sqlite.Config{
		DataDirectory:       dbDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopenedStore.Close()

	// Reclaim task with advanced lease
	reclaimedTask, claimed, err := reopenedStore.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now.Add(time.Minute),
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})
	if err != nil || !claimed {
		t.Fatalf("reclaim task failed: claimed=%v, err=%v", claimed, err)
	}

	stager, err := NewArtifactStager(reopenedStore, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})
	if err != nil {
		t.Fatalf("new stager: %v", err)
	}

	// Next stage run should detect intact files, adopt them, and commit receipt
	receipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          reclaimedTask.ID.String(),
		CoreGeneration:  reclaimedTask.CoreGeneration,
		LeaseGeneration: reclaimedTask.LeaseGeneration,
		OwnerID:         reclaimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err != nil {
		t.Fatalf("adoption after crash failed: %v", err)
	}

	status, _, err := reopenedStore.GetPackStatus(ctx, fixture.packID)
	if err != nil || status != "artifact_verified" {
		t.Fatalf("expected artifact_verified after adoption, got %s, err: %v", status, err)
	}
	if receipt.ArchiveSHA256 != fixture.archiveSHA {
		t.Fatalf("adopted archive sha mismatch: %s", receipt.ArchiveSHA256)
	}
}

func TestArtifactStaging_AdoptionRejectsMissingExecutable(t *testing.T) {
	ctx := context.Background()
	store, _, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, _ := store.InstallationBinding(ctx)
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	planRes, _ := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-missing-exe",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})

	claimedTask, _, _ := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})

	// Pre-populate stage directory with valid archive and manifest, but MISSING adapter binary
	stagingSubdir := filepath.Join(stagingDir, "staging")
	_ = os.MkdirAll(stagingSubdir, 0700)
	_ = os.Chmod(stagingSubdir, 0700)
	opStageDir := filepath.Join(stagingSubdir, planRes.OperationID)
	_ = os.MkdirAll(filepath.Join(opStageDir, "pack"), 0755)
	_ = os.Chmod(opStageDir, 0700)
	_ = os.Chmod(filepath.Join(opStageDir, "pack"), 0755)
	_ = os.WriteFile(filepath.Join(opStageDir, "artifact.tar.gz"), fixture.archiveData, 0644)
	_ = os.WriteFile(filepath.Join(opStageDir, "pack", "manifest.json"), fixture.manifestData, 0644)

	stager, _ := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})

	// Staging must reject adoption and NOT commit receipt
	_, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err == nil || (!strings.Contains(err.Error(), "declared file") && !strings.Contains(err.Error(), "adapter") && !strings.Contains(err.Error(), "tampered") && !strings.Contains(err.Error(), "inventory")) {
		t.Fatalf("expected missing declared file error on adoption, got %v", err)
	}

	// Verify disk files were NOT deleted
	if _, err := os.Stat(filepath.Join(opStageDir, "artifact.tar.gz")); err != nil {
		t.Fatalf("archive should not be deleted on adoption failure: %v", err)
	}
}

func TestArtifactStaging_AdoptionRejectsForeignSentinelInPack(t *testing.T) {
	ctx := context.Background()
	store, _, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, _ := store.InstallationBinding(ctx)
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	planRes, _ := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-foreign-pack",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})

	claimedTask, _, _ := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})

	// Pre-populate stage directory with valid files PLUS a foreign sentinel inside pack/
	stagingSubdir := filepath.Join(stagingDir, "staging")
	_ = os.MkdirAll(stagingSubdir, 0700)
	_ = os.Chmod(stagingSubdir, 0700)
	opStageDir := filepath.Join(stagingSubdir, planRes.OperationID)
	_ = os.MkdirAll(filepath.Join(opStageDir, "pack", "bin"), 0755)
	_ = os.Chmod(opStageDir, 0700)
	_ = os.Chmod(filepath.Join(opStageDir, "pack"), 0755)
	_ = os.Chmod(filepath.Join(opStageDir, "pack", "bin"), 0755)
	_ = os.WriteFile(filepath.Join(opStageDir, "artifact.tar.gz"), fixture.archiveData, 0644)
	_ = os.WriteFile(filepath.Join(opStageDir, "pack", "manifest.json"), fixture.manifestData, 0644)
	_ = os.WriteFile(filepath.Join(opStageDir, "pack", "bin", "adapter"), []byte("#!/bin/sh\necho fixture-adapter-run\n"), 0755)
	sentinelPath := filepath.Join(opStageDir, "pack", "foreign_sentinel.txt")
	_ = os.WriteFile(sentinelPath, []byte("foreign sentinel data"), 0600)

	stager, _ := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})

	_, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err == nil || (!strings.Contains(err.Error(), "foreign") && !strings.Contains(err.Error(), "tampered") && !strings.Contains(err.Error(), "inventory")) {
		t.Fatalf("expected foreign file rejection, got %v", err)
	}

	// Verify foreign sentinel was preserved and NOT deleted
	data, readErr := os.ReadFile(sentinelPath)
	if readErr != nil || string(data) != "foreign sentinel data" {
		t.Fatalf("foreign sentinel was modified or deleted: %v", readErr)
	}
}

func TestArtifactStaging_PartAfterCrash(t *testing.T) {
	ctx := context.Background()
	store, server, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, _ := store.InstallationBinding(ctx)
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture.archiveData)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	planRes, _ := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-part-crash",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})

	claimedTask, _, _ := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})

	// Inject a partial .part file from an earlier crashed download (regular file, owned by us)
	stagingSubdir := filepath.Join(stagingDir, "staging")
	_ = os.MkdirAll(stagingSubdir, 0700)
	_ = os.Chmod(stagingSubdir, 0700)
	opStageDir := filepath.Join(stagingSubdir, planRes.OperationID)
	_ = os.MkdirAll(opStageDir, 0700)
	_ = os.Chmod(opStageDir, 0700)
	partPath := filepath.Join(opStageDir, "artifact.tar.gz.part")
	_ = os.WriteFile(partPath, []byte("truncated partial download"), 0600)

	stager, _ := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})

	receipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err != nil {
		t.Fatalf("stage artifact recovery failed: %v", err)
	}

	// Verify part file is replaced by complete final artifact
	if _, err := os.Stat(partPath); !os.IsNotExist(err) {
		t.Fatalf("part file should no longer exist, err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(opStageDir, "artifact.tar.gz")); err != nil {
		t.Fatalf("final artifact missing: %v", err)
	}
	if receipt.ArchiveSHA256 != fixture.archiveSHA {
		t.Fatalf("archive sha mismatch: %s vs %s", receipt.ArchiveSHA256, fixture.archiveSHA)
	}
}

func TestArtifactStaging_BytesTamperedAfterReceipt(t *testing.T) {
	ctx := context.Background()
	store, server, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, _ := store.InstallationBinding(ctx)
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture.archiveData)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	planRes, _ := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-tamper",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})

	claimedTask, _, _ := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})

	stager, _ := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})

	receipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err != nil {
		t.Fatalf("initial staging failed: %v", err)
	}

	// 1. Idempotent replay before tampering
	replayReceipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err != nil || replayReceipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("replay failed: %v, rcpt=%v", err, replayReceipt)
	}

	// 2. Tamper with adapter binary on disk
	adapterFile := filepath.Join(stagingDir, receipt.RelativeStagePath, "pack", "bin", "adapter")
	_ = os.WriteFile(adapterFile, []byte("tampered malicious bytes"), 0755)

	_, err = stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err == nil || !errors.Is(err, ErrStagedArtifactTampered) {
		t.Fatalf("expected ErrStagedArtifactTampered, got %v", err)
	}
}

func TestArtifactStaging_CatalogExpiryAndRenewedAuthority(t *testing.T) {
	ctx := context.Background()
	store, server, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, _ := store.InstallationBinding(ctx)

	// Fixture catalog expires in 5 seconds
	shortExp := now.Add(5 * time.Second)
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, shortExp)

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture.archiveData)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	planRes, _ := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-expired",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})

	claimedTask, _, _ := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
		Owner: "worker-1",
		Kinds: []string{sqlite.PackInstallTaskKind},
		Now:   now,
		LeasePolicy: contracts.LeasePolicy{
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
		},
	})

	// Advance clock past expiry
	futureNow := now.Add(10 * time.Second)
	stagerClock := futureNow

	stager, _ := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 5 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
		Clock:           func() time.Time { return stagerClock },
	})

	// 1. Without renewed authority: fails with ErrPackAuthorizationRequired
	_, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err == nil || !errors.Is(err, ErrPackAuthorizationRequired) {
		t.Fatalf("expected ErrPackAuthorizationRequired, got %v", err)
	}

	// Verify journal recorded authorization_required
	jnl, err := store.GetPackLifecycleJournal(ctx, planRes.OperationID)
	if err != nil || jnl.Phase != "authorization_required" {
		t.Fatalf("expected journal phase authorization_required, got %s, err: %v", jnl.Phase, err)
	}

	// 2. Supply fresh renewed authority for the SAME pinned artifact (same key, same deterministic archive bytes)
	freshExp := futureNow.Add(time.Hour)
	renewedFixture := createRenewedFixturePack(t, fixture, 2, freshExp, futureNow)

	// Verify pinned hashes are identical
	if renewedFixture.archiveSHA != fixture.archiveSHA || renewedFixture.manifestSHA != fixture.manifestSHA {
		t.Fatalf("renewed fixture must pin the exact same artifact digests")
	}

	receipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:      planRes.OperationID,
		TaskID:           claimedTask.ID.String(),
		CoreGeneration:   claimedTask.CoreGeneration,
		LeaseGeneration:  claimedTask.LeaseGeneration,
		OwnerID:          claimedTask.LeaseOwner,
		RenewedAuthority: &renewedFixture.selection,
		Audit:            audit,
	})
	if err != nil {
		t.Fatalf("staging with renewed authority failed: %v", err)
	}

	if receipt.CatalogSequence != 2 {
		t.Fatalf("receipt should record renewed sequence 2, got %d", receipt.CatalogSequence)
	}

	status, statusRcpt, err := store.GetPackStatus(ctx, fixture.packID)
	if err != nil || status != "artifact_verified" || statusRcpt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("expected artifact_verified, got %s, err: %v", status, err)
	}
}
