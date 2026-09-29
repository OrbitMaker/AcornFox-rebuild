package packmanager

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/packprotocol"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

type testFixturePack struct {
	packID       string
	version      string
	manifestData []byte
	archiveData  []byte
	archiveSize  int64
	archiveSHA   string
	manifestSHA  string
	adapterSHA   string
	configSHA    string
	envelopeData []byte
	selection    packprotocol.VerifiedPackSelection
	policy       packprotocol.VerificationPolicy
	priv         ed25519.PrivateKey
}

func buildTestArchive(t *testing.T, files map[string][]byte, modes map[string]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		content := files[name]
		mode := int64(0644)
		if m, ok := modes[name]; ok {
			mode = m
		}
		hdr := &tar.Header{
			Name:     name,
			Mode:     mode,
			Size:     int64(len(content)),
			Format:   tar.FormatUSTAR,
			Typeflag: tar.TypeReg,
			Uid:      0,
			Gid:      0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type fixturePackParams struct {
	AdapterBytes []byte
	Capabilities []string
	Publisher    string
	ArtifactURL  string
}

func createCustomFixturePack(
	t *testing.T,
	packID, version string,
	binding string,
	host string,
	now time.Time,
	seq uint64,
	exp time.Time,
	params fixturePackParams,
) *testFixturePack {
	t.Helper()
	adapterBytes := params.AdapterBytes
	if len(adapterBytes) == 0 {
		adapterBytes = []byte("#!/bin/sh\necho fixture-adapter-run\n")
	}
	adapterSum := sha256.Sum256(adapterBytes)
	adapterSHA := hex.EncodeToString(adapterSum[:])

	capabilities := params.Capabilities
	if len(capabilities) == 0 {
		capabilities = []string{"echo.run"}
	}

	publisher := params.Publisher
	if publisher == "" {
		publisher = "test-publisher"
	}

	configBytes := []byte(`{"enabled":true,"name":"fixture"}` + "\n")
	configSum := sha256.Sum256(configBytes)
	configSHA := hex.EncodeToString(configSum[:])

	m := packprotocol.Manifest{
		Schema:          "acornfox-pack-manifest-v1",
		PackID:          packID,
		Version:         version,
		OS:              "linux",
		Arch:            "amd64",
		MinCoreVersion:  "1.0.0",
		ProtocolVersion: "1.0",
		Capabilities:    capabilities,
		Dependencies:    []packprotocol.Dependency{},
		Permissions:     []string{"state.private"},
		Entries:         []packprotocol.Entry{{Role: "adapter", Path: "bin/adapter"}},
		Files: []packprotocol.File{
			{Path: "assets/config/settings.json", SHA256: configSHA, Size: int64(len(configBytes)), Mode: 0644},
			{Path: "bin/adapter", SHA256: adapterSHA, Size: int64(len(adapterBytes)), Mode: 0755},
		},
	}
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manSum := sha256.Sum256(manifestBytes)
	manifestSHA := hex.EncodeToString(manSum[:])

	files := map[string][]byte{
		"pack/manifest.json":               manifestBytes,
		"pack/assets/config/settings.json": configBytes,
		"pack/bin/adapter":                 adapterBytes,
	}
	modes := map[string]int64{
		"pack/manifest.json":               0644,
		"pack/assets/config/settings.json": 0644,
		"pack/bin/adapter":                 0755,
	}
	archiveBytes := buildTestArchive(t, files, modes)
	archSum := sha256.Sum256(archiveBytes)
	archiveSHA := hex.EncodeToString(archSum[:])

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	artifactURL := params.ArtifactURL
	if artifactURL == "" {
		artifactURL = "https://" + host + "/archive.tar.gz"
	}

	c := packprotocol.CatalogPayload{
		Publisher:      publisher,
		PackID:         packID,
		Version:        version,
		OS:             "linux",
		Arch:           "amd64",
		Sequence:       seq,
		ExpiresAt:      exp.Format(time.RFC3339Nano),
		ManifestSHA256: manifestSHA,
		ArtifactSHA256: archiveSHA,
		ArtifactSize:   int64(len(archiveBytes)),
		ArtifactURL:    artifactURL,
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
		AllowedHosts:        []string{host},
		CoreVersion:         "1.0.0",
		ProtocolVersion:     "1.0",
		OS:                  "linux",
		Arch:                "amd64",
		InstallationBinding: binding,
		Now:                 now,
	}

	verified, err := packprotocol.VerifySelection(envelopeBytes, manifestBytes, policy)
	if err != nil {
		t.Fatalf("verify fixture selection: %v", err)
	}

	return &testFixturePack{
		packID:       packID,
		version:      version,
		manifestData: manifestBytes,
		archiveData:  archiveBytes,
		archiveSize:  int64(len(archiveBytes)),
		archiveSHA:   archiveSHA,
		manifestSHA:  manifestSHA,
		adapterSHA:   adapterSHA,
		configSHA:    configSHA,
		envelopeData: envelopeBytes,
		selection:    verified,
		policy:       policy,
		priv:         priv,
	}
}

func createTestFixturePack(t *testing.T, packID, version string, binding string, host string, now time.Time, seq uint64, exp time.Time) *testFixturePack {
	t.Helper()
	return createCustomFixturePack(t, packID, version, binding, host, now, seq, exp, fixturePackParams{})
}

func createRenewedFixturePack(t *testing.T, orig *testFixturePack, seq uint64, exp time.Time, now time.Time) *testFixturePack {
	t.Helper()
	c := packprotocol.CatalogPayload{
		Publisher:      orig.policy.Publisher,
		PackID:         orig.packID,
		Version:        orig.version,
		OS:             orig.policy.OS,
		Arch:           orig.policy.Arch,
		Sequence:       seq,
		ExpiresAt:      exp.Format(time.RFC3339Nano),
		ManifestSHA256: orig.manifestSHA,
		ArtifactSHA256: orig.archiveSHA,
		ArtifactSize:   orig.archiveSize,
		ArtifactURL:    "https://" + orig.policy.AllowedHosts[0] + "/archive.tar.gz",
	}
	payBytes, _ := json.Marshal(c)
	sig := ed25519.Sign(orig.priv, append([]byte(packprotocol.CatalogSignatureDomain), payBytes...))
	envelopeBytes, _ := json.Marshal(packprotocol.CatalogEnvelope{
		Schema:    "acornfox-pack-catalog-envelope-v1",
		Payload:   base64.StdEncoding.EncodeToString(payBytes),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})

	policy := orig.policy
	policy.Now = now

	verified, err := packprotocol.VerifySelection(envelopeBytes, orig.manifestData, policy)
	if err != nil {
		t.Fatalf("verify renewed fixture selection: %v", err)
	}

	return &testFixturePack{
		packID:       orig.packID,
		version:      orig.version,
		manifestData: orig.manifestData,
		archiveData:  orig.archiveData,
		archiveSize:  orig.archiveSize,
		archiveSHA:   orig.archiveSHA,
		manifestSHA:  orig.manifestSHA,
		adapterSHA:   orig.adapterSHA,
		configSHA:    orig.configSHA,
		envelopeData: envelopeBytes,
		selection:    verified,
		policy:       policy,
		priv:         orig.priv,
	}
}

func setupTestStagingEnvironment(t *testing.T) (*sqlite.Store, *httptest.Server, *http.Client, string, string, string) {
	t.Helper()
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := sqlite.Config{
		DataDirectory:       tempDir,
		PackCoreVersion:     "1.0.0",
		PackProtocolVersion: "1.0",
	}
	store, err := sqlite.Open(cfg)
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	stagingDir := filepath.Join(tempDir, "pack-staging")
	if err := os.Mkdir(stagingDir, 0700); err != nil {
		t.Fatal(err)
	}

	const serverHost = "example.com"
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(func() { server.Close() })

	tr := server.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	tr.TLSClientConfig.ServerName = serverHost
	httpClient := &http.Client{Transport: tr}

	return store, server, httpClient, stagingDir, serverHost, tempDir
}

func TestArtifactStaging_EndToEndSuccess(t *testing.T) {
	ctx := context.Background()
	store, server, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, err := store.InstallationBinding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	// Register artifact route
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/archive.tar.gz" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(fixture.archiveData)
			return
		}
		http.NotFound(w, r)
	})

	audit := contracts.AuditContext{
		ActorType: "admin",
		ActorID:   "admin-1",
		Reason:    "install pack",
	}

	// 1. Plan pack install
	planRes, err := store.PlanPackInstall(ctx, contracts.PlanPackInstallRecord{
		Intent: contracts.PackInstallIntent{
			PackID:         fixture.packID,
			Version:        fixture.version,
			OS:             "linux",
			Arch:           "amd64",
			IdempotencyKey: "idem-e2e-1",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})
	if err != nil {
		t.Fatalf("plan pack install failed: %v", err)
	}

	// 2. Claim task to get genuine caller tokens
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
		t.Fatalf("claim task failed: %v", err)
	}

	// 3. Stage artifact
	stager, err := NewArtifactStager(store, ArtifactStagingConfig{
		StagingRootDir:  stagingDir,
		Policy:          fixture.policy,
		HTTPClient:      client,
		DownloadTimeout: 10 * time.Second,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
	})
	if err != nil {
		t.Fatalf("new artifact stager: %v", err)
	}

	receipt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err != nil {
		t.Fatalf("stage artifact failed: %v", err)
	}

	if receipt.PackID != fixture.packID || receipt.Version != fixture.version ||
		receipt.ArchiveSHA256 != fixture.archiveSHA || receipt.ManifestSHA256 != fixture.manifestSHA ||
		receipt.ExecutableSHA256 != fixture.adapterSHA {
		t.Fatalf("receipt content mismatch: %+v", receipt)
	}

	// 4. Verify SQLite state: pack status is artifact_verified, pack_records.state is planned
	status, statusRcpt, err := store.GetPackStatus(ctx, fixture.packID)
	if err != nil {
		t.Fatalf("get pack status: %v", err)
	}
	if status != "artifact_verified" || statusRcpt == nil || statusRcpt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("unexpected pack status: %s", status)
	}

	packRec, err := store.GetPack(ctx, fixture.packID)
	if err != nil {
		t.Fatalf("get pack: %v", err)
	}
	if packRec.State != "planned" {
		t.Fatalf("pack state must remain planned, got %s", packRec.State)
	}

	// 5. Verify filesystem: check files on disk
	stagedArchive := filepath.Join(stagingDir, receipt.RelativeStagePath, "artifact.tar.gz")
	if _, err := os.Stat(stagedArchive); err != nil {
		t.Fatalf("staged archive missing: %v", err)
	}
	stagedAdapter := filepath.Join(stagingDir, receipt.RelativeStagePath, "pack", "bin", "adapter")
	info, err := os.Stat(stagedAdapter)
	if err != nil {
		t.Fatalf("staged adapter missing: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatalf("staged adapter not executable: %o", info.Mode())
	}

	stagedConfig := filepath.Join(stagingDir, receipt.RelativeStagePath, "pack", "assets", "config", "settings.json")
	cfgInfo, err := os.Stat(stagedConfig)
	if err != nil {
		t.Fatalf("staged config missing: %v", err)
	}
	if cfgInfo.Mode().Perm() != 0644 {
		t.Fatalf("staged config mode expected 0644, got %o", cfgInfo.Mode().Perm())
	}
}

func TestArtifactStaging_NegativeScenarios(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name          string
		mutateArchive func(fixture *testFixturePack) []byte
		handler       func(fixture *testFixturePack) http.HandlerFunc
		mutateReq     func(req *StageArtifactRequest, task contracts.Task)
		setupDisk     func(stageDir, opID string)
		wantErr       string
	}{
		{
			name: "wrong bytes (archive digest mismatch)",
			handler: func(fixture *testFixturePack) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/octet-stream")
					corrupt := append([]byte(nil), fixture.archiveData...)
					corrupt[len(corrupt)/2] ^= 1
					_, _ = w.Write(corrupt)
				}
			},
			wantErr: "sha256 mismatch",
		},
		{
			name: "redirect beyond allowed hosts",
			handler: func(fixture *testFixturePack) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "https://disallowed.invalid/archive.tar.gz", http.StatusFound)
				}
			},
			wantErr: "url not allowed",
		},
		{
			name: "foreign sentinel in staging directory preserved and staging refused",
			handler: func(fixture *testFixturePack) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write(fixture.archiveData)
				}
			},
			setupDisk: func(stageDir, opID string) {
				stagingSubdir := filepath.Join(stageDir, "staging")
				_ = os.MkdirAll(stagingSubdir, 0700)
				_ = os.Chmod(stagingSubdir, 0700)
				target := filepath.Join(stagingSubdir, opID)
				_ = os.MkdirAll(target, 0700)
				_ = os.Chmod(target, 0700)
				_ = os.WriteFile(filepath.Join(target, "foreign_sentinel.txt"), []byte("preserved"), 0600)
			},
			wantErr: "foreign or unknown files present",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, server, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)
			now := time.Now().UTC()
			binding, _ := store.InstallationBinding(ctx)
			fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

			server.Config.Handler = tc.handler(fixture)

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
					IdempotencyKey: "idem-" + tc.name,
				},
				Selection: fixture.selection,
				Audit:     audit,
			})
			if err != nil {
				t.Fatalf("plan pack install: %v", err)
			}

			claimedTask, _, err := store.ClaimTask(ctx, contracts.ClaimTaskRequest{
				Owner: "worker-1",
				Kinds: []string{sqlite.PackInstallTaskKind},
				Now:   now,
				LeasePolicy: contracts.LeasePolicy{
					Duration:    10 * time.Minute,
					MaxAttempts: 3,
				},
			})
			if err != nil {
				t.Fatalf("claim task: %v", err)
			}

			if tc.setupDisk != nil {
				tc.setupDisk(stagingDir, planRes.OperationID)
			}

			stager, err := NewArtifactStager(store, ArtifactStagingConfig{
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

			req := StageArtifactRequest{
				OperationID:     planRes.OperationID,
				TaskID:          claimedTask.ID.String(),
				CoreGeneration:  claimedTask.CoreGeneration,
				LeaseGeneration: claimedTask.LeaseGeneration,
				OwnerID:         claimedTask.LeaseOwner,
				Audit:           audit,
			}
			if tc.mutateReq != nil {
				tc.mutateReq(&req, claimedTask)
			}

			_, err = stager.StageArtifact(ctx, req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}

			// If foreign sentinel was placed, verify it was NOT deleted
			if tc.setupDisk != nil {
				sentinelPath := filepath.Join(stagingDir, "staging", planRes.OperationID, "foreign_sentinel.txt")
				content, readErr := os.ReadFile(sentinelPath)
				if readErr != nil || string(content) != "preserved" {
					t.Fatalf("foreign sentinel was modified or deleted: %v", readErr)
				}
			}
		})
	}
}

func TestArtifactStaging_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store, server, client, stagingDir, serverHost, _ := setupTestStagingEnvironment(t)

	now := time.Now().UTC()
	binding, _ := store.InstallationBinding(ctx)
	fixture := createTestFixturePack(t, "fixture-echo", "1.0.0", binding, serverHost, now, 1, now.Add(time.Hour))

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel() // Cancel context during download
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
			IdempotencyKey: "idem-cancel",
		},
		Selection: fixture.selection,
		Audit:     audit,
	})

	claimedTask, _, _ := store.ClaimTask(context.Background(), contracts.ClaimTaskRequest{
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

	_, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err == nil || (!errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled")) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}

func TestArtifactStaging_StaleClaimCausesZeroDiskMutation(t *testing.T) {
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
			IdempotencyKey: "idem-stale-zero-mutation",
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

	// Invoke with stale lease generation
	_, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration + 1, // stale!
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err == nil || !strings.Contains(err.Error(), "lease generation mismatch") {
		t.Fatalf("expected lease generation mismatch, got %v", err)
	}

	// Assert ZERO filesystem mutation: operation staging dir must NOT exist
	opStagePath := filepath.Join(stagingDir, "staging", planRes.OperationID)
	if _, err := os.Stat(opStagePath); !os.IsNotExist(err) {
		t.Fatalf("expected stage dir to NOT exist after stale claim rejection, err=%v", err)
	}
}

func TestArtifactStaging_ForeignSentinelInPackPreserved(t *testing.T) {
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
			IdempotencyKey: "idem-sentinel-in-pack",
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

	// Pre-create pack/ directory with a foreign file inside staging/<op_id>
	opStageDir := filepath.Join(stagingDir, "staging", planRes.OperationID)
	_ = os.MkdirAll(filepath.Join(opStageDir, "pack"), 0700)
	sentinelPath := filepath.Join(opStageDir, "pack", "foreign_inside_pack.txt")
	_ = os.WriteFile(sentinelPath, []byte("sentinel-inside-pack"), 0600)

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
	if err == nil || (!errors.Is(err, ErrForeignFilesPresent) && !strings.Contains(err.Error(), "foreign")) {
		t.Fatalf("expected foreign files error, got %v", err)
	}

	// Verify foreign sentinel was NOT deleted
	data, readErr := os.ReadFile(sentinelPath)
	if readErr != nil || string(data) != "sentinel-inside-pack" {
		t.Fatalf("foreign sentinel in pack was modified or deleted: %v", readErr)
	}
}

func TestReadAndVerifyStagedInventory_ReplacedPhysicalIdentityRejected(t *testing.T) {
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
			IdempotencyKey: "idem-phys-identity",
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

	rcpt, err := stager.StageArtifact(ctx, StageArtifactRequest{
		OperationID:     planRes.OperationID,
		TaskID:          claimedTask.ID.String(),
		CoreGeneration:  claimedTask.CoreGeneration,
		LeaseGeneration: claimedTask.LeaseGeneration,
		OwnerID:         claimedTask.LeaseOwner,
		Audit:           audit,
	})
	if err != nil {
		t.Fatalf("stage artifact failed: %v", err)
	}

	stagePath := filepath.Join(stagingDir, "staging", planRes.OperationID)
	snap, _, _ := fixture.selection.Snapshot()

	// 1. Legitimate readback with exact stage identity passes
	verifiedRcpt, err := ReadAndVerifyStagedInventory(stagePath, planRes.OperationID, snap, planRes.PlanSHA256, fixture.manifestData, rcpt.StageIdentity, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("legitimate readback failed: %v", err)
	}
	if verifiedRcpt.StageIdentity != rcpt.StageIdentity {
		t.Fatalf("expected stage identity %s, got %s", rcpt.StageIdentity, verifiedRcpt.StageIdentity)
	}

	// 2. Readback with mismatched physical stage identity (e.g. replaced directory with new inode) must be rejected
	tamperedIdentity := "dev:99999:ino:88888"
	_, err = ReadAndVerifyStagedInventory(stagePath, planRes.OperationID, snap, planRes.PlanSHA256, fixture.manifestData, tamperedIdentity, os.Getuid(), os.Getgid())
	if err == nil || (!errors.Is(err, ErrStagedArtifactTampered) && !strings.Contains(err.Error(), "physical stage directory identity changed")) {
		t.Fatalf("expected ErrStagedArtifactTampered on replaced physical stage identity, got %v", err)
	}
}
