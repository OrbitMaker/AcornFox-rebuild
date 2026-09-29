package packmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packprotocol"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type SeedHandoff struct {
	PackID              string   `json:"pack_id"`
	Version             string   `json:"version"`
	Publisher           string   `json:"publisher"`
	PublisherPublicKey  string   `json:"publisher_public_key"`
	AllowedHosts        []string `json:"allowed_hosts"`
	InstallationBinding string   `json:"installation_binding"`
	OperationID         string   `json:"operation_id"`
	TaskID              string   `json:"task_id"`
	TaskKind            string   `json:"task_kind"`
	PlanSHA256          string   `json:"plan_sha256"`
	ArchiveURL          string   `json:"archive_url"`
	ArchivePath         string   `json:"archive_path"`
	ArchiveSHA256       string   `json:"archive_sha256"`
	ArchiveSize         int64    `json:"archive_size"`
	ManifestSHA256      string   `json:"manifest_sha256"`
	AdapterSHA256       string   `json:"adapter_sha256"`
	AdapterPath         string   `json:"adapter_path"`
	CatalogSHA256       string   `json:"catalog_sha256"`
	CatalogSequence     int64    `json:"catalog_sequence"`
	CatalogExpiresAt    string   `json:"catalog_expires_at"`
	Capabilities        []string `json:"capabilities"`
}

func TestRuntimeSeed(t *testing.T) {
	dataDir := strings.TrimSpace(os.Getenv("ACORNFOX_SEED_DATA_DIR"))
	handoffDir := strings.TrimSpace(os.Getenv("ACORNFOX_SEED_HANDOFF_DIR"))
	if handoffDir == "" {
		handoffDir = strings.TrimSpace(os.Getenv("ACORNFOX_SEED_OUTPUT_DIR"))
	}
	adapterPath := strings.TrimSpace(os.Getenv("ACORNFOX_SEED_ADAPTER_PATH"))
	archiveURL := strings.TrimSpace(os.Getenv("ACORNFOX_SEED_ARCHIVE_URL"))

	if dataDir == "" || handoffDir == "" || adapterPath == "" {
		t.Skip("skipping opt-in runtime seed test: ACORNFOX_SEED_DATA_DIR, ACORNFOX_SEED_HANDOFF_DIR, and ACORNFOX_SEED_ADAPTER_PATH must be set")
	}

	if !filepath.IsAbs(dataDir) {
		t.Fatalf("ACORNFOX_SEED_DATA_DIR must be absolute: %s", dataDir)
	}
	if !filepath.IsAbs(handoffDir) {
		t.Fatalf("ACORNFOX_SEED_HANDOFF_DIR must be absolute: %s", handoffDir)
	}
	if !filepath.IsAbs(adapterPath) {
		t.Fatalf("ACORNFOX_SEED_ADAPTER_PATH must be absolute: %s", adapterPath)
	}

	adapterBytes, err := os.ReadFile(adapterPath)
	if err != nil {
		t.Fatalf("read adapter binary from %s: %v", adapterPath, err)
	}
	if len(adapterBytes) == 0 {
		t.Fatalf("adapter binary %s is empty", adapterPath)
	}

	if archiveURL == "" {
		archiveURL = "https://127.0.0.1/fixture-live-pack-1.0.0.tar.gz"
	}
	u, err := url.Parse(archiveURL)
	if err != nil {
		t.Fatalf("parse archive URL %s: %v", archiveURL, err)
	}
	if u.Scheme != "https" {
		t.Fatalf("archive URL scheme must be https: %s", archiveURL)
	}
	if u.Port() != "" {
		t.Fatalf("archive URL must be portless (got port %s): %s", u.Port(), archiveURL)
	}
	host := u.Hostname()
	if host == "" {
		t.Fatalf("archive URL missing host: %s", archiveURL)
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir dataDir: %v", err)
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		t.Fatalf("chmod dataDir 0700: %v", err)
	}
	if err := os.MkdirAll(handoffDir, 0755); err != nil {
		t.Fatalf("mkdir handoffDir: %v", err)
	}

	ctx := context.Background()

	store, err := sqlite.Open(sqlite.Config{
		DataDirectory:       dataDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	})
	if err != nil {
		t.Fatalf("sqlite.Open failed: %v", err)
	}

	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		_ = store.Close()
		t.Fatalf("store.InstallationBinding failed: %v", err)
	}

	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	packID := "fixture-live-pack"
	version := "1.0.0"
	publisher := "fixture-publisher"
	capabilities := []string{packprotocol.CapabilityDiagnosticObserve}

	fixture := createCustomFixturePack(
		t,
		packID,
		version,
		binding,
		host,
		now,
		1,
		exp,
		fixturePackParams{
			AdapterBytes: adapterBytes,
			Capabilities: capabilities,
			Publisher:    publisher,
			ArtifactURL:  archiveURL,
		},
	)

	planReq := contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         packID,
			Version:        version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: fmt.Sprintf("seed-%s-%s-%d", packID, version, now.UnixNano()),
		},
		Selection: fixture.selection,
		Audit: contracts.AuditContext{
			ActorType: "system",
			ActorID:   "fixture-seed",
			Reason:    "runtime fixture initial plan seeding",
		},
	}
	planRes, err := store.PlanPackInstall(ctx, planReq)
	if err != nil {
		_ = store.Close()
		t.Fatalf("store.PlanPackInstall failed: %v", err)
	}

	if planRes.State != "planned" {
		_ = store.Close()
		t.Fatalf("expected plan state 'planned', got %s", planRes.State)
	}
	if planRes.OperationID == "" || planRes.TaskID == "" {
		_ = store.Close()
		t.Fatalf("plan missing OperationID (%s) or TaskID (%s)", planRes.OperationID, planRes.TaskID)
	}

	taskID := domain.ID(planRes.TaskID)
	task, err := store.GetTask(ctx, taskID)
	if err != nil {
		_ = store.Close()
		t.Fatalf("store.GetTask failed: %v", err)
	}
	if task.State != contracts.TaskReady {
		_ = store.Close()
		t.Fatalf("expected task state 'ready', got %s", task.State)
	}
	if task.OperationID.String() != planRes.OperationID {
		_ = store.Close()
		t.Fatalf("task operation ID mismatch: got %s, want %s", task.OperationID.String(), planRes.OperationID)
	}

	var taskPayload struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(task.Payload, &taskPayload); err != nil {
		_ = store.Close()
		t.Fatalf("unmarshal task payload: %v", err)
	}
	if taskPayload.Kind != "core.pack.install" {
		_ = store.Close()
		t.Fatalf("expected task kind 'core.pack.install', got %s", taskPayload.Kind)
	}

	// Verify zero staged/active facts on store
	unified, err := store.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		_ = store.Close()
		t.Fatalf("store.GetPackUnifiedStatus failed: %v", err)
	}
	if unified.IntentPhase != "planned" {
		_ = store.Close()
		t.Fatalf("expected intent phase 'planned', got %s", unified.IntentPhase)
	}
	if unified.ArtifactStatus != "none" {
		_ = store.Close()
		t.Fatalf("expected artifact status 'none', got %s", unified.ArtifactStatus)
	}
	if unified.ArtifactReceipt != nil {
		_ = store.Close()
		t.Fatalf("expected nil ArtifactReceipt, got %+v", unified.ArtifactReceipt)
	}
	if unified.ActivationReceipt != nil {
		_ = store.Close()
		t.Fatalf("expected nil ActivationReceipt, got %+v", unified.ActivationReceipt)
	}
	if unified.ActiveRuntime != nil {
		_ = store.Close()
		t.Fatalf("expected nil ActiveRuntime, got %+v", unified.ActiveRuntime)
	}
	if unified.InstalledVersion != "" {
		_ = store.Close()
		t.Fatalf("expected empty InstalledVersion, got %s", unified.InstalledVersion)
	}
	if unified.RuntimeReady {
		_ = store.Close()
		t.Fatalf("expected RuntimeReady false, got true")
	}

	if _, err := store.GetArtifactReceipt(ctx, planRes.OperationID); !errors.Is(err, contracts.ErrNotFound) {
		_ = store.Close()
		t.Fatalf("expected ErrNotFound for GetArtifactReceipt, got %v", err)
	}
	if _, err := store.GetActivationReceipt(ctx, planRes.OperationID); !errors.Is(err, contracts.ErrNotFound) {
		_ = store.Close()
		t.Fatalf("expected ErrNotFound for GetActivationReceipt, got %v", err)
	}
	if _, err := store.GetActiveRuntime(ctx, packID); !errors.Is(err, contracts.ErrNotFound) {
		_ = store.Close()
		t.Fatalf("expected ErrNotFound for GetActiveRuntime, got %v", err)
	}

	// Close store before handoff
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	// Write archive to handoff directory
	archiveFileName := filepath.Base(u.Path)
	if archiveFileName == "" || archiveFileName == "/" || archiveFileName == "." {
		archiveFileName = "fixture-live-pack-1.0.0.tar.gz"
	}
	archiveDestPath := filepath.Join(handoffDir, archiveFileName)
	if err := os.WriteFile(archiveDestPath, fixture.archiveData, 0644); err != nil {
		t.Fatalf("write archive to %s: %v", archiveDestPath, err)
	}

	snap, _, _ := fixture.selection.Snapshot()
	pubKeyB64 := base64.StdEncoding.EncodeToString(fixture.policy.PublicKey)

	handoff := SeedHandoff{
		PackID:              packID,
		Version:             version,
		Publisher:           publisher,
		PublisherPublicKey:  pubKeyB64,
		AllowedHosts:        []string{host},
		InstallationBinding: binding,
		OperationID:         planRes.OperationID,
		TaskID:              planRes.TaskID,
		TaskKind:            "core.pack.install",
		PlanSHA256:          planRes.PlanSHA256,
		ArchiveURL:          archiveURL,
		ArchivePath:         archiveDestPath,
		ArchiveSHA256:       fixture.archiveSHA,
		ArchiveSize:         fixture.archiveSize,
		ManifestSHA256:      fixture.manifestSHA,
		AdapterSHA256:       fixture.adapterSHA,
		AdapterPath:         "bin/adapter",
		CatalogSHA256:       snap.CatalogSHA256,
		CatalogSequence:     snap.CatalogSequence,
		CatalogExpiresAt:    exp.Format(time.RFC3339Nano),
		Capabilities:        capabilities,
	}

	hBytes, err := json.MarshalIndent(handoff, "", "  ")
	if err != nil {
		t.Fatalf("marshal handoff JSON: %v", err)
	}
	handoffPath := filepath.Join(handoffDir, "fixture-seed-handoff.json")
	if err := os.WriteFile(handoffPath, hBytes, 0644); err != nil {
		t.Fatalf("write handoff JSON to %s: %v", handoffPath, err)
	}

	// Verify reopened DB state
	reopenStore, err := sqlite.Open(sqlite.Config{
		DataDirectory:       dataDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	})
	if err != nil {
		t.Fatalf("reopen store failed: %v", err)
	}
	defer reopenStore.Close()

	pRec, err := reopenStore.GetPack(ctx, packID)
	if err != nil {
		t.Fatalf("reopen GetPack failed: %v", err)
	}
	if pRec.State != "planned" || pRec.DesiredVersion != version {
		t.Fatalf("reopen pack mismatch: state=%s, version=%s", pRec.State, pRec.DesiredVersion)
	}

	pIntent, err := reopenStore.GetPackIntent(ctx, planRes.OperationID)
	if err != nil {
		t.Fatalf("reopen GetPackIntent failed: %v", err)
	}
	if pIntent.Phase != "planned" || pIntent.PackID != packID {
		t.Fatalf("reopen intent mismatch: phase=%s, packID=%s", pIntent.Phase, pIntent.PackID)
	}

	reTask, err := reopenStore.GetTask(ctx, taskID)
	if err != nil {
		t.Fatalf("reopen GetTask failed: %v", err)
	}
	if reTask.State != contracts.TaskReady {
		t.Fatalf("reopen task state mismatch: %s", reTask.State)
	}

	reUnified, err := reopenStore.GetPackUnifiedStatus(ctx, packID)
	if err != nil {
		t.Fatalf("reopen GetPackUnifiedStatus failed: %v", err)
	}
	if reUnified.ArtifactStatus != "none" || reUnified.ArtifactReceipt != nil || reUnified.ActivationReceipt != nil || reUnified.ActiveRuntime != nil {
		t.Fatalf("reopen non-zero staged/active facts: %+v", reUnified)
	}

	t.Logf("Runtime seed successful: op=%s task=%s binding=%s", planRes.OperationID, planRes.TaskID, binding)
}
