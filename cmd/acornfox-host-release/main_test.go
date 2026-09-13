package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

var (
	binaryCache     = make(map[string][]byte)
	binaryCacheLock sync.Mutex
)

func getTestBinary(t *testing.T, goos, goarch string) []byte {
	t.Helper()
	key := goos + "/" + goarch
	binaryCacheLock.Lock()
	defer binaryCacheLock.Unlock()

	if b, ok := binaryCache[key]; ok {
		return b
	}

	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcFile, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	binFile := filepath.Join(srcDir, "binary")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", binFile, srcFile)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build (%s/%s) failed: %v\n%s", goos, goarch, err, out)
	}
	data, err := os.ReadFile(binFile)
	if err != nil {
		t.Fatal(err)
	}
	binaryCache[key] = data
	return data
}

func generateTestKeyPEM(t *testing.T, dir string) (string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	keyPath := filepath.Join(dir, fmt.Sprintf("test-key-%d.pem", time.Now().UnixNano()))
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}
	return keyPath, priv, pub
}

func setupPayloadDir(t *testing.T, parentDir, osName, archName string, executable []byte) string {
	t.Helper()
	payload := filepath.Join(parentDir, "payload")
	if err := os.MkdirAll(filepath.Join(payload, "launcher"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(payload, "controller"), 0755); err != nil {
		t.Fatal(err)
	}

	launcherName := "acornfox"
	if osName == "darwin" {
		launcherName = "AcornFox"
	}
	launcherPath := filepath.Join(payload, "launcher", launcherName)
	controllerPath := filepath.Join(payload, "controller", "acornfox-host-update")

	if err := os.WriteFile(launcherPath, executable, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controllerPath, executable, 0755); err != nil {
		t.Fatal(err)
	}

	return payload
}

func createBackendCandidateFiles(t *testing.T, payloadDir, version, arch, fromBinding string) (string, string) {
	t.Helper()
	candDir := filepath.Join(payloadDir, "backend", "candidate")
	if err := os.MkdirAll(candDir, 0755); err != nil {
		t.Fatal(err)
	}
	helperBytes := []byte("bin/acornfox-upgrade fixture executable")
	helperSHA := hex.EncodeToString(sha256Sum(helperBytes))

	prodArchiveBytes := []byte("production tar gz fixture bytes")
	prodArchiveSHA := hex.EncodeToString(sha256Sum(prodArchiveBytes))
	archiveName := fmt.Sprintf("acornfox-%s-production.tar.gz", version)
	if err := os.WriteFile(filepath.Join(candDir, archiveName), prodArchiveBytes, 0644); err != nil {
		t.Fatal(err)
	}

	bundleManifestBytes := []byte("bundle manifest sha256 fixture")
	bundleSHA := hex.EncodeToString(sha256Sum(bundleManifestBytes))
	if err := os.WriteFile(filepath.Join(candDir, "bundle-manifest.sha256"), bundleManifestBytes, 0644); err != nil {
		t.Fatal(err)
	}

	buildRecordBytes := []byte(`{"schema_version":1}`)
	if err := os.WriteFile(filepath.Join(candDir, "build-record.json"), buildRecordBytes, 0644); err != nil {
		t.Fatal(err)
	}

	relManifest := map[string]any{
		"product":       "acornfox",
		"version":       version,
		"release_id":    "release-" + version,
		"source_commit": strings.Repeat("1", 40),
		"architecture":  arch,
		"files": []map[string]any{
			{
				"path":   "bin/acornfox-upgrade",
				"sha256": helperSHA,
				"mode":   0755,
			},
		},
	}
	relManifestRaw, _ := json.Marshal(relManifest)
	manifestSHA := hex.EncodeToString(sha256Sum(relManifestRaw))
	if err := os.WriteFile(filepath.Join(candDir, "release-manifest.json"), relManifestRaw, 0644); err != nil {
		t.Fatal(err)
	}

	candBinding := map[string]any{
		"schema_version":         1,
		"product":                "acornfox",
		"version":                version,
		"release_id":             "release-" + version,
		"source_commit":          strings.Repeat("1", 40),
		"architecture":           arch,
		"migration_version":      "0040",
		"archive_sha256":         prodArchiveSHA,
		"manifest_sha256":        manifestSHA,
		"bundle_manifest_sha256": bundleSHA,
		"n_minus_one": map[string]string{
			"binding_sha256": fromBinding,
		},
	}
	candBindingRaw, _ := json.Marshal(candBinding)
	toBinding := hex.EncodeToString(sha256Sum(candBindingRaw))
	if err := os.WriteFile(filepath.Join(candDir, "candidate-binding.json"), candBindingRaw, 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(candDir, "candidate-binding.sha256"), []byte(toBinding+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	return toBinding, helperSHA
}

func TestHostRelease_Roundtrip_DarwinArm64_Unchanged(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("a", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.2.0",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifactPath := filepath.Join(tmpDir, "acornfox-1.2.0-darwin-arm64.tar.gz")
	var buildOut bytes.Buffer
	receipt, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifactPath,
	}, &buildOut)
	if err != nil {
		t.Fatalf("buildHostArtifact failed: %v", err)
	}
	if !receipt.Verified {
		t.Fatal("expected artifact to be verified")
	}

	// Sign index
	keyDir := t.TempDir()
	keyFile, _, pubKey := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.2.0",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/v1.2.0/acornfox-1.2.0-darwin-arm64.tar.gz",
				SHA256:         receipt.SHA256,
				Size:           receipt.Size,
				BackendBinding: binding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	if err := os.WriteFile(indexSpecPath, indexSpecRaw, 0644); err != nil {
		t.Fatal(err)
	}

	indexEnvPath := filepath.Join(tmpDir, "index.json")
	var signOut bytes.Buffer
	signReceipt, err := signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:   indexSpecPath,
		KeyFilePath:     keyFile,
		OutputPath:      indexEnvPath,
		AllowedChannel:  "stable",
		AllowedHosts:    []string{"downloads.acornfox.com"},
		PayloadRoots:    []string{payload},
		BundleFiles:     []string{artifactPath},
		CurrentSequence: 5,
		CurrentVersion:  "1.1.0",
	}, &signOut)
	if err != nil {
		t.Fatalf("signIndex failed: %v", err)
	}
	if signReceipt.Sequence != 10 {
		t.Fatalf("expected sequence 10, got %d", signReceipt.Sequence)
	}
	if len(signReceipt.VerifiedBundles) != 1 || !signReceipt.VerifiedBundles[0].Verified {
		t.Fatal("expected 1 verified bundle in receipt")
	}

	// Verify using VerifyHostBundle API directly
	envelopeBytes, err := os.ReadFile(indexEnvPath)
	if err != nil {
		t.Fatal(err)
	}
	checkOpts := desktopupdate.CheckUpdateOptions{
		PublicKey:       pubKey,
		TargetOS:        "darwin",
		TargetArch:      "arm64",
		AllowedChannel:  "stable",
		CurrentSequence: 5,
		CurrentVersion:  "1.1.0",
		CurrentTime:     time.Now().UTC(),
		AllowedHosts:    []string{"downloads.acornfox.com"},
	}
	bundle, err := desktopupdate.VerifyHostBundle(context.Background(), artifactPath, envelopeBytes, checkOpts)
	if err != nil {
		t.Fatalf("VerifyHostBundle failed: %v", err)
	}
	defer bundle.Close()

	if bundle.SHA256() != receipt.SHA256 {
		t.Fatalf("bundle SHA mismatch: %s != %s", bundle.SHA256(), receipt.SHA256)
	}
	manifest := bundle.Manifest()
	if manifest.Launcher != "launcher/AcornFox" {
		t.Fatalf("manifest launcher mismatch: %s", manifest.Launcher)
	}

	// Verify using verify-bundle command
	var verifyOut bytes.Buffer
	vReceipt, err := verifyBundle(context.Background(), VerifyBundleOptions{
		BundlePath:      artifactPath,
		EnvelopePath:    indexEnvPath,
		PublicKeyHex:    signReceipt.PublicKeyHex,
		TargetOS:        "darwin",
		TargetArch:      "arm64",
		AllowedChannel:  "stable",
		AllowedHosts:    []string{"downloads.acornfox.com"},
		CurrentSequence: 5,
		CurrentVersion:  "1.1.0",
	}, &verifyOut)
	if err != nil {
		t.Fatalf("verifyBundle failed: %v", err)
	}
	if !vReceipt.Verified {
		t.Fatal("expected verifyBundle receipt to be verified")
	}
}

func TestHostRelease_Roundtrip_LinuxAmd64_Candidate(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	fromBinding := strings.Repeat("a", 64)
	toBinding, helperSHA := createBackendCandidateFiles(t, payload, "1.2.0", "amd64", fromBinding)

	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.2.0",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:         "candidate",
			FromBinding:  fromBinding,
			ToBinding:    toBinding,
			HelperSHA256: helperSHA,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifactPath := filepath.Join(tmpDir, "acornfox-1.2.0-linux-amd64.tar.gz")
	var buildOut bytes.Buffer
	receipt, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifactPath,
	}, &buildOut)
	if err != nil {
		t.Fatalf("buildHostArtifact failed: %v", err)
	}
	if receipt.BackendMode != "candidate" {
		t.Fatalf("expected candidate backend mode, got %s", receipt.BackendMode)
	}

	// Sign index
	keyDir := t.TempDir()
	keyFile, _, pubKey := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.2.0",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "linux",
				Arch:           "amd64",
				URL:            "https://downloads.acornfox.com/v1.2.0/acornfox-1.2.0-linux-amd64.tar.gz",
				SHA256:         receipt.SHA256,
				Size:           receipt.Size,
				BackendBinding: toBinding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	if err := os.WriteFile(indexSpecPath, indexSpecRaw, 0644); err != nil {
		t.Fatal(err)
	}

	indexEnvPath := filepath.Join(tmpDir, "index.json")
	var signOut bytes.Buffer
	_, err = signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     indexEnvPath,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{payload},
		BundleFiles:    []string{artifactPath},
	}, &signOut)
	if err != nil {
		t.Fatalf("signIndex failed: %v", err)
	}

	// Verify using VerifyHostBundle
	envelopeBytes, err := os.ReadFile(indexEnvPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := desktopupdate.VerifyHostBundle(context.Background(), artifactPath, envelopeBytes, desktopupdate.CheckUpdateOptions{
		PublicKey:       pubKey,
		TargetOS:        "linux",
		TargetArch:      "amd64",
		AllowedChannel:  "stable",
		CurrentSequence: 0,
		CurrentVersion:  "",
		CurrentTime:     time.Now().UTC(),
		AllowedHosts:    []string{"downloads.acornfox.com"},
	})
	if err != nil {
		t.Fatalf("VerifyHostBundle failed: %v", err)
	}
	defer bundle.Close()

	// Read launcher from bundle
	var launcherBytes bytes.Buffer
	if err := bundle.ReadFile("launcher/acornfox", &launcherBytes); err != nil {
		t.Fatalf("ReadFile launcher failed: %v", err)
	}
	if !bytes.Equal(launcherBytes.Bytes(), bin) {
		t.Fatal("launcher bytes mismatch")
	}

	// Read backend candidate file from bundle
	var bindingBytes bytes.Buffer
	if err := bundle.ReadFile("backend/candidate/candidate-binding.json", &bindingBytes); err != nil {
		t.Fatalf("ReadFile candidate-binding.json failed: %v", err)
	}
	if hex.EncodeToString(sha256Sum(bindingBytes.Bytes())) != toBinding {
		t.Fatal("candidate-binding hash mismatch")
	}
}

func TestHostRelease_Roundtrip_LinuxArm64_Unchanged(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "arm64")
	payload := setupPayloadDir(t, tmpDir, "linux", "arm64", bin)

	binding := strings.Repeat("b", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "arm64",
		Version:       "1.2.0",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifactPath := filepath.Join(tmpDir, "acornfox-1.2.0-linux-arm64.tar.gz")
	receipt, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifactPath,
	}, nil)
	if err != nil {
		t.Fatalf("buildHostArtifact failed: %v", err)
	}

	// Sign index
	keyDir := t.TempDir()
	keyFile, _, pubKey := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.2.0",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "linux",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/v1.2.0/acornfox-1.2.0-linux-arm64.tar.gz",
				SHA256:         receipt.SHA256,
				Size:           receipt.Size,
				BackendBinding: binding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	if err := os.WriteFile(indexSpecPath, indexSpecRaw, 0644); err != nil {
		t.Fatal(err)
	}

	indexEnvPath := filepath.Join(tmpDir, "index.json")
	_, err = signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     indexEnvPath,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{payload},
		BundleFiles:    []string{artifactPath},
	}, nil)
	if err != nil {
		t.Fatalf("signIndex failed: %v", err)
	}

	envelopeBytes, err := os.ReadFile(indexEnvPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := desktopupdate.VerifyHostBundle(context.Background(), artifactPath, envelopeBytes, desktopupdate.CheckUpdateOptions{
		PublicKey:       pubKey,
		TargetOS:        "linux",
		TargetArch:      "arm64",
		AllowedChannel:  "stable",
		CurrentSequence: 0,
		CurrentVersion:  "",
		CurrentTime:     time.Now().UTC(),
		AllowedHosts:    []string{"downloads.acornfox.com"},
	})
	if err != nil {
		t.Fatalf("VerifyHostBundle failed: %v", err)
	}
	bundle.Close()
}

func TestHostRelease_DeterministicBuild(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("c", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.3.0",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifact1 := filepath.Join(tmpDir, "bundle1.tar.gz")
	receipt1, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact1,
	}, nil)
	if err != nil {
		t.Fatalf("first build failed: %v", err)
	}

	artifact2 := filepath.Join(tmpDir, "bundle2.tar.gz")
	receipt2, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact2,
	}, nil)
	if err != nil {
		t.Fatalf("second build failed: %v", err)
	}

	if receipt1.SHA256 != receipt2.SHA256 {
		t.Fatalf("build is not deterministic: %s != %s", receipt1.SHA256, receipt2.SHA256)
	}
	if receipt1.Size != receipt2.Size {
		t.Fatalf("size mismatch: %d != %d", receipt1.Size, receipt2.Size)
	}

	data1, _ := os.ReadFile(artifact1)
	data2, _ := os.ReadFile(artifact2)
	if !bytes.Equal(data1, data2) {
		t.Fatal("byte comparison failed: artifacts are not bit-for-bit identical")
	}
}

func TestHostRelease_InvalidInventory(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	binding := strings.Repeat("d", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
		Files: []desktopupdate.HostBundleFile{
			{
				Path:   "controller/acornfox-host-update",
				SHA256: strings.Repeat("0", 64), // wrong SHA256
				Size:   int64(len(bin)),
				Mode:   0755,
			},
			{
				Path:   "launcher/acornfox",
				SHA256: hex.EncodeToString(sha256Sum(bin)),
				Size:   int64(len(bin)),
				Mode:   0755,
			},
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join(tmpDir, "out.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected error due to SHA256 mismatch in inventory, got nil")
	}
	if !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("expected SHA256 mismatch error, got: %v", err)
	}
}

func TestHostRelease_ExtraUnexpectedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	// Add an extra file to payload
	extraFile := filepath.Join(payload, "launcher", "extra.txt")
	if err := os.WriteFile(extraFile, []byte("unexpected"), 0644); err != nil {
		t.Fatal(err)
	}

	binding := strings.Repeat("e", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
		Files: []desktopupdate.HostBundleFile{
			{
				Path:   "controller/acornfox-host-update",
				SHA256: hex.EncodeToString(sha256Sum(bin)),
				Size:   int64(len(bin)),
				Mode:   0755,
			},
			{
				Path:   "launcher/acornfox",
				SHA256: hex.EncodeToString(sha256Sum(bin)),
				Size:   int64(len(bin)),
				Mode:   0755,
			},
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join(tmpDir, "out.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected error due to unexpected extra file, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected extra file") {
		t.Fatalf("expected extra file error, got: %v", err)
	}
}

func TestHostRelease_SymlinkRejection(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	// Add symlink
	symlinkPath := filepath.Join(payload, "launcher", "link-acornfox")
	if err := os.Symlink(filepath.Join(payload, "launcher", "acornfox"), symlinkPath); err != nil {
		t.Fatal(err)
	}

	binding := strings.Repeat("f", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join(tmpDir, "out.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected error due to symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection error, got: %v", err)
	}
}

func TestHostRelease_HardlinkRejection(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	// Add hard link
	targetPath := filepath.Join(payload, "launcher", "hardlink-target")
	if err := os.Link(filepath.Join(payload, "launcher", "acornfox"), targetPath); err != nil {
		t.Skip("hard link creation not supported in this environment")
	}

	binding := strings.Repeat("1", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0644); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join(tmpDir, "out.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected error due to hard link, got nil")
	}
	if !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("expected hardlink rejection error, got: %v", err)
	}
}

func TestHostRelease_PathSwap_AncestorSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	// Create outside secret file
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("outside secret"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a subdirectory inside payload and make an ancestor symlink pointing outside
	ancestorDir := filepath.Join(payload, "launcher", "nested")
	if err := os.Symlink(outsideDir, ancestorDir); err != nil {
		t.Fatal(err)
	}

	binding := strings.Repeat("e", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "out-pathswap.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected build to fail when ancestor symlink points outside payload")
	}
}

func TestHostRelease_InsecureOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	// Create insecure output directory with 0777 (world writable) permissions
	insecureDir := filepath.Join(tmpDir, "insecure-output")
	if err := os.Mkdir(insecureDir, 0777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(insecureDir, 0777)

	binding := strings.Repeat("f", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(insecureDir, "bundle.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected build to fail when output parent is world-writable")
	}
	if !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("expected permission error, got: %v", err)
	}
}

func TestHostRelease_SwapRoot_Detected(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)
	subDir := t.TempDir()
	substitutePayload := setupPayloadDir(t, subDir, "linux", "amd64", bin)

	binding := strings.Repeat("a", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "out-swap.tar.gz")

	testPreOpenPayloadRootHook = func(p string) error {
		renamed := p + ".orig"
		if err := os.Rename(p, renamed); err != nil {
			return err
		}
		if err := os.Rename(substitutePayload, p); err != nil {
			return err
		}
		return nil
	}
	defer func() { testPreOpenPayloadRootHook = nil }()

	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected build to fail when payload root is swapped between lstat and open")
	}
	if !strings.Contains(err.Error(), "swapped or replaced") {
		t.Fatalf("expected swap rejection error, got: %v", err)
	}
}

func TestHostRelease_InsecureParentDirChain(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")
	payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)

	insecureAncestor := filepath.Join(tmpDir, "ancestor")
	nestedDir := filepath.Join(insecureAncestor, "nested")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(insecureAncestor, 0777)

	binding := strings.Repeat("d", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "linux",
		Architecture:  "amd64",
		Version:       "1.0.1",
		Launcher:      "launcher/acornfox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(nestedDir, "bundle.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected build to fail when an ancestor in output chain is insecure")
	}
}

func TestHostRelease_InvalidMode(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "linux", "amd64")

	t.Run("unchanged_mode_with_backend_files", func(t *testing.T) {
		payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)
		candDir := filepath.Join(payload, "backend", "candidate")
		os.MkdirAll(candDir, 0755)
		os.WriteFile(filepath.Join(candDir, "test.json"), []byte("{}"), 0644)

		binding := strings.Repeat("2", 64)
		spec := ReleaseSpec{
			SchemaVersion: 1,
			Product:       "acornfox",
			Kind:          "host-update-v1",
			OS:            "linux",
			Architecture:  "amd64",
			Version:       "1.0.1",
			Launcher:      "launcher/acornfox",
			Backend: BackendSpec{
				Mode:    "unchanged",
				Binding: binding,
			},
		}
		specRaw, _ := json.Marshal(spec)
		specPath := filepath.Join(tmpDir, "spec1.json")
		os.WriteFile(specPath, specRaw, 0644)

		artifact := filepath.Join(tmpDir, "out1.tar.gz")
		_, err := buildHostArtifact(context.Background(), BuildOptions{
			SpecPath:   specPath,
			PayloadDir: payload,
			OutputPath: artifact,
		}, nil)
		if err == nil {
			t.Fatal("expected error for backend files in unchanged mode")
		}
	})

	t.Run("candidate_mode_missing_files", func(t *testing.T) {
		payload := setupPayloadDir(t, tmpDir, "linux", "amd64", bin)
		fromBinding := strings.Repeat("3", 64)
		toBinding, helperSHA := createBackendCandidateFiles(t, payload, "1.0.1", "amd64", fromBinding)

		// Remove one of the candidate files
		os.Remove(filepath.Join(payload, "backend", "candidate", "build-record.json"))

		spec := ReleaseSpec{
			SchemaVersion: 1,
			Product:       "acornfox",
			Kind:          "host-update-v1",
			OS:            "linux",
			Architecture:  "amd64",
			Version:       "1.0.1",
			Launcher:      "launcher/acornfox",
			Backend: BackendSpec{
				Mode:         "candidate",
				FromBinding:  fromBinding,
				ToBinding:    toBinding,
				HelperSHA256: helperSHA,
			},
		}
		specRaw, _ := json.Marshal(spec)
		specPath := filepath.Join(tmpDir, "spec2.json")
		os.WriteFile(specPath, specRaw, 0644)

		artifact := filepath.Join(tmpDir, "out2.tar.gz")
		_, err := buildHostArtifact(context.Background(), BuildOptions{
			SpecPath:   specPath,
			PayloadDir: payload,
			OutputPath: artifact,
		}, nil)
		if err == nil {
			t.Fatal("expected error for candidate mode missing files")
		}
	})
}

func TestHostRelease_Cancellation(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("4", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	artifact := filepath.Join(tmpDir, "out-cancel.tar.gz")
	_, err := buildHostArtifact(ctx, BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected cancellation error")
	}

	// Verify destination was not created
	if _, err := os.Lstat(artifact); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected destination to not exist after cancellation")
	}
}

func TestHostRelease_NonClobber(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("5", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "existing.tar.gz")
	originalContent := []byte("do not overwrite")
	if err := os.WriteFile(artifact, originalContent, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected no-clobber error when destination already exists")
	}
	if !strings.Contains(err.Error(), "already exists (no-clobber)") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify original file was preserved
	content, _ := os.ReadFile(artifact)
	if !bytes.Equal(content, originalContent) {
		t.Fatal("original content was corrupted")
	}
}

func TestHostRelease_KeySecrecy(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	// Generate key before build
	keyDir := t.TempDir()
	keyFile, privKey, _ := generateTestKeyPEM(t, keyDir)
	privKeyBytes := []byte(privKey)
	privKeyHex := hex.EncodeToString(privKeyBytes)

	binding := strings.Repeat("6", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "secret-test.tar.gz")
	receipt, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         receipt.SHA256,
				Size:           receipt.Size,
				BackendBinding: binding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	indexEnvPath := filepath.Join(tmpDir, "index.json")
	var stdout bytes.Buffer
	signReceipt, err := signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     indexEnvPath,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{payload},
		BundleFiles:    []string{artifact},
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Verify receipt stdout does not contain private key or seed
	stdoutStr := stdout.String()
	if strings.Contains(stdoutStr, privKeyHex) {
		t.Fatal("private key hex leaked in stdout receipt")
	}
	if strings.Contains(stdoutStr, "PRIVATE KEY") {
		t.Fatal("PEM private key marker leaked in stdout receipt")
	}

	// 2. Verify produced envelope does not contain private key
	envData, _ := os.ReadFile(indexEnvPath)
	if bytes.Contains(envData, privKeyBytes) || strings.Contains(string(envData), privKeyHex) {
		t.Fatal("private key leaked into envelope file")
	}

	// 3. Verify produced bundle does not contain private key
	bundleData, _ := os.ReadFile(artifact)
	if bytes.Contains(bundleData, privKeyBytes) {
		t.Fatal("private key leaked into bundle artifact")
	}

	// 4. Verify only public key fingerprint and hex are in signReceipt
	if signReceipt.PublicKeyHex == "" || signReceipt.PublicKeyFingerprint == "" {
		t.Fatal("expected public key hex and fingerprint in receipt")
	}
}

func TestHostRelease_KeyFilePermissionsAndLocation(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := t.TempDir()
	keyFile, _, _ := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         strings.Repeat("7", 64),
				Size:           1024,
				BackendBinding: strings.Repeat("8", 64),
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	t.Run("insecure_permissions_rejected", func(t *testing.T) {
		insecureKey := filepath.Join(keyDir, "insecure.pem")
		data, _ := os.ReadFile(keyFile)
		os.WriteFile(insecureKey, data, 0644) // 0644 instead of 0600

		out := filepath.Join(tmpDir, "out-insecure.json")
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    insecureKey,
			OutputPath:     out,
			AllowedChannel: "stable",
			AllowedHosts:   []string{"downloads.acornfox.com"},
			PayloadRoots:   []string{tmpDir},
			BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
		}, nil)
		if err == nil {
			t.Fatal("expected error due to 0644 key file permissions")
		}
		if !strings.Contains(err.Error(), "0600") {
			t.Fatalf("expected 0600 error, got: %v", err)
		}
	})

	t.Run("key_inside_output_tree_rejected", func(t *testing.T) {
		outDir := filepath.Join(tmpDir, "output-tree")
		os.MkdirAll(outDir, 0700)
		insideKey := filepath.Join(outDir, "key.pem")
		data, _ := os.ReadFile(keyFile)
		os.WriteFile(insideKey, data, 0600)

		out := filepath.Join(outDir, "index.json")
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    insideKey,
			OutputPath:     out,
			AllowedChannel: "stable",
			AllowedHosts:   []string{"downloads.acornfox.com"},
			PayloadRoots:   []string{tmpDir},
			BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
		}, nil)
		if err == nil {
			t.Fatal("expected error due to key file inside output tree")
		}
		if !strings.Contains(err.Error(), "must be outside") {
			t.Fatalf("expected outside error, got: %v", err)
		}
	})

	t.Run("key_inside_payload_tree_rejected", func(t *testing.T) {
		payloadDir := filepath.Join(tmpDir, "payload-with-key")
		os.MkdirAll(payloadDir, 0700)
		insidePayloadKey := filepath.Join(payloadDir, "signing-key.pem")
		data, _ := os.ReadFile(keyFile)
		os.WriteFile(insidePayloadKey, data, 0600)

		out := filepath.Join(tmpDir, "index-outside.json")
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    insidePayloadKey,
			OutputPath:     out,
			AllowedChannel: "stable",
			AllowedHosts:   []string{"downloads.acornfox.com"},
			PayloadRoots:   []string{payloadDir},
			BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
		}, nil)
		if err == nil {
			t.Fatal("expected error due to key inside payload root")
		}
		if !strings.Contains(err.Error(), "must be outside directory") {
			t.Fatalf("expected outside directory error, got: %v", err)
		}
	})
}

func TestHostRelease_PayloadContainingKey_BuildRejected(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	// Add a private key PEM inside payload/launcher
	_, privKey, _ := generateTestKeyPEM(t, t.TempDir())
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(privKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	keyInsidePayload := filepath.Join(payload, "launcher", "leaked-key.pem")
	if err := os.WriteFile(keyInsidePayload, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}

	binding := strings.Repeat("7", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "out-key-leak.tar.gz")
	_, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected build to reject payload containing private key")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Fatalf("expected private key rejection error, got: %v", err)
	}
}

func TestHostRelease_SignPolicy_ExplicitRequired(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := t.TempDir()
	keyFile, _, _ := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         strings.Repeat("7", 64),
				Size:           1024,
				BackendBinding: strings.Repeat("8", 64),
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	out := filepath.Join(tmpDir, "index.json")

	t.Run("missing_allowed_channel", func(t *testing.T) {
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    keyFile,
			OutputPath:     out,
			AllowedChannel: "", // missing
			AllowedHosts:   []string{"downloads.acornfox.com"},
			PayloadRoots:   []string{tmpDir},
			BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "--allowed-channel is required") {
			t.Fatalf("expected missing channel error, got: %v", err)
		}
	})

	t.Run("missing_allowed_hosts", func(t *testing.T) {
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    keyFile,
			OutputPath:     out,
			AllowedChannel: "stable",
			AllowedHosts:   nil, // missing
			PayloadRoots:   []string{tmpDir},
			BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "--allowed-hosts is required") {
			t.Fatalf("expected missing allowed hosts error, got: %v", err)
		}
	})

	t.Run("missing_payload_roots", func(t *testing.T) {
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    keyFile,
			OutputPath:     out,
			AllowedChannel: "stable",
			AllowedHosts:   []string{"downloads.acornfox.com"},
			PayloadRoots:   nil, // missing
			BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "--payload-roots is required") {
			t.Fatalf("expected missing payload roots error, got: %v", err)
		}
	})

	t.Run("missing_bundles", func(t *testing.T) {
		_, err := signIndex(context.Background(), SignIndexOptions{
			IndexSpecPath:  indexSpecPath,
			KeyFilePath:    keyFile,
			OutputPath:     out,
			AllowedChannel: "stable",
			AllowedHosts:   []string{"downloads.acornfox.com"},
			PayloadRoots:   []string{tmpDir},
			BundleFiles:    nil, // missing
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "--bundles is required") {
			t.Fatalf("expected missing bundles error, got: %v", err)
		}
	})
}

func TestHostRelease_TamperAndVerification(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("9", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "tamper-test.tar.gz")
	receipt, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	keyDir := t.TempDir()
	keyFile, _, pubKey := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         receipt.SHA256,
				Size:           receipt.Size,
				BackendBinding: binding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	indexEnvPath := filepath.Join(tmpDir, "index.json")
	_, err = signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     indexEnvPath,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{payload},
		BundleFiles:    []string{artifact},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	envelopeBytes, _ := os.ReadFile(indexEnvPath)

	t.Run("tampered_artifact_payload_rejected", func(t *testing.T) {
		tamperedArtifact := filepath.Join(tmpDir, "tampered-artifact.tar.gz")
		artData, _ := os.ReadFile(artifact)
		artData[len(artData)-1] ^= 0xFF // corrupt byte
		os.WriteFile(tamperedArtifact, artData, 0600)

		checkOpts := desktopupdate.CheckUpdateOptions{
			PublicKey:       pubKey,
			TargetOS:        "darwin",
			TargetArch:      "arm64",
			AllowedChannel:  "stable",
			CurrentSequence: 0,
			CurrentVersion:  "",
			CurrentTime:     time.Now().UTC(),
			AllowedHosts:    []string{"downloads.acornfox.com"},
		}
		_, err := desktopupdate.VerifyHostBundle(context.Background(), tamperedArtifact, envelopeBytes, checkOpts)
		if err == nil {
			t.Fatal("expected VerifyHostBundle to fail on tampered payload")
		}
	})

	t.Run("wrong_public_key_rejected", func(t *testing.T) {
		wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
		checkOpts := desktopupdate.CheckUpdateOptions{
			PublicKey:       wrongPub,
			TargetOS:        "darwin",
			TargetArch:      "arm64",
			AllowedChannel:  "stable",
			CurrentSequence: 0,
			CurrentVersion:  "",
			CurrentTime:     time.Now().UTC(),
			AllowedHosts:    []string{"downloads.acornfox.com"},
		}
		_, err := desktopupdate.VerifyHostBundle(context.Background(), artifact, envelopeBytes, checkOpts)
		if err == nil {
			t.Fatal("expected VerifyHostBundle to fail on wrong public key")
		}
	})
}

func TestHostRelease_CLI_Run(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("0", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "2.0.0",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "cli-artifact.tar.gz")

	// Test CLI build
	var buildOut, buildErr bytes.Buffer
	buildArgs := []string{
		"build",
		"--spec", specPath,
		"--payload-dir", payload,
		"--output", artifact,
	}
	if err := run(context.Background(), buildArgs, &buildOut, &buildErr); err != nil {
		t.Fatalf("CLI build failed: %v\nstderr: %s", err, buildErr.String())
	}

	var bReceipt BuildReceipt
	if err := json.Unmarshal(buildOut.Bytes(), &bReceipt); err != nil {
		t.Fatalf("failed to unmarshal build receipt: %v\nstdout: %s", err, buildOut.String())
	}
	if !bReceipt.Verified {
		t.Fatal("expected build receipt verified to be true")
	}

	// Test CLI sign-index
	keyDir := t.TempDir()
	keyFile, _, _ := generateTestKeyPEM(t, keyDir)

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "2.0.0",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/cli-artifact.tar.gz",
				SHA256:         bReceipt.SHA256,
				Size:           bReceipt.Size,
				BackendBinding: binding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	indexEnvPath := filepath.Join(tmpDir, "index.json")
	var signOut, signErr bytes.Buffer
	signArgs := []string{
		"sign-index",
		"--index-spec", indexSpecPath,
		"--key-file", keyFile,
		"--output", indexEnvPath,
		"--allowed-channel", "stable",
		"--allowed-hosts", "downloads.acornfox.com",
		"--bundles", artifact,
		"--payload-roots", payload,
	}
	if err := run(context.Background(), signArgs, &signOut, &signErr); err != nil {
		t.Fatalf("CLI sign-index failed: %v\nstderr: %s", err, signErr.String())
	}

	var sReceipt SignReceipt
	if err := json.Unmarshal(signOut.Bytes(), &sReceipt); err != nil {
		t.Fatalf("failed to unmarshal sign receipt: %v\nstdout: %s", err, signOut.String())
	}
	if len(sReceipt.VerifiedBundles) != 1 || !sReceipt.VerifiedBundles[0].Verified {
		t.Fatal("expected 1 verified bundle in CLI receipt")
	}

	// Test CLI verify-bundle
	var verifyOut, verifyErr bytes.Buffer
	verifyArgs := []string{
		"verify-bundle",
		"--bundle", artifact,
		"--envelope", indexEnvPath,
		"--public-key-hex", sReceipt.PublicKeyHex,
		"--os", "darwin",
		"--arch", "arm64",
		"--channel", "stable",
		"--allowed-hosts", "downloads.acornfox.com",
	}
	if err := run(context.Background(), verifyArgs, &verifyOut, &verifyErr); err != nil {
		t.Fatalf("CLI verify-bundle failed: %v\nstderr: %s", err, verifyErr.String())
	}

	var vReceipt VerifyReceipt
	if err := json.Unmarshal(verifyOut.Bytes(), &vReceipt); err != nil {
		t.Fatalf("failed to unmarshal verify receipt: %v\nstdout: %s", err, verifyOut.String())
	}
	if !vReceipt.Verified {
		t.Fatal("expected CLI verify-bundle verified to be true")
	}
}

func TestHostRelease_SignMissingBackendBinding(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := t.TempDir()
	keyFile, _, _ := generateTestKeyPEM(t, keyDir)

	// Artifact with missing backend_binding
	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         strings.Repeat("a", 64),
				Size:           1024,
				BackendBinding: "", // empty!
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	out := filepath.Join(tmpDir, "index.json")
	_, err := signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     out,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{tmpDir},
		BundleFiles:    []string{filepath.Join(tmpDir, "dummy.tar.gz")},
	}, nil)
	if err == nil {
		t.Fatal("expected error due to missing backend_binding")
	}
	if !strings.Contains(err.Error(), "backend_binding") {
		t.Fatalf("expected backend_binding error, got: %v", err)
	}
}

func TestHostRelease_SignMismatchedBundle(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("b", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	artifact := filepath.Join(tmpDir, "real.tar.gz")
	receipt, err := buildHostArtifact(context.Background(), BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	keyDir := t.TempDir()
	keyFile, _, _ := generateTestKeyPEM(t, keyDir)

	// Index spec with a different SHA256 than the real bundle
	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         strings.Repeat("f", 64), // mismatched SHA256!
				Size:           receipt.Size,
				BackendBinding: binding,
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	out := filepath.Join(tmpDir, "index.json")
	_, err = signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     out,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{payload},
		BundleFiles:    []string{artifact},
	}, nil)
	if err == nil {
		t.Fatal("expected signIndex to reject mismatched bundle")
	}
	if !strings.Contains(err.Error(), "no valid bundle verified") && !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("expected bundle verification mismatch error, got: %v", err)
	}
}

func TestHostRelease_CancellationMidStream(t *testing.T) {
	tmpDir := t.TempDir()
	bin := getTestBinary(t, "darwin", "arm64")
	payload := setupPayloadDir(t, tmpDir, "darwin", "arm64", bin)

	binding := strings.Repeat("c", 64)
	spec := ReleaseSpec{
		SchemaVersion: 1,
		Product:       "acornfox",
		Kind:          "host-update-v1",
		OS:            "darwin",
		Architecture:  "arm64",
		Version:       "1.0.1",
		Launcher:      "launcher/AcornFox",
		Backend: BackendSpec{
			Mode:    "unchanged",
			Binding: binding,
		},
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(tmpDir, "spec.json")
	os.WriteFile(specPath, specRaw, 0644)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // ensure expired

	artifact := filepath.Join(tmpDir, "out-midstream-cancel.tar.gz")
	_, err := buildHostArtifact(ctx, BuildOptions{
		SpecPath:   specPath,
		PayloadDir: payload,
		OutputPath: artifact,
	}, nil)
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}

	// Verify temp file was cleaned up and destination was not created
	if _, err := os.Lstat(artifact); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected destination to not exist after cancellation")
	}
}

func TestHostRelease_SignBundleDisappears_NoPanic(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := t.TempDir()
	keyFile, _, _ := generateTestKeyPEM(t, keyDir)

	missingBundle := filepath.Join(tmpDir, "vanished.tar.gz")

	indexSpec := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.0.1",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             "darwin",
				Arch:           "arm64",
				URL:            "https://downloads.acornfox.com/bundle.tar.gz",
				SHA256:         strings.Repeat("a", 64),
				Size:           1024,
				BackendBinding: strings.Repeat("b", 64),
			},
		},
	}
	indexSpecRaw, _ := json.Marshal(indexSpec)
	indexSpecPath := filepath.Join(tmpDir, "index-spec.json")
	os.WriteFile(indexSpecPath, indexSpecRaw, 0644)

	out := filepath.Join(tmpDir, "index.json")
	_, err := signIndex(context.Background(), SignIndexOptions{
		IndexSpecPath:  indexSpecPath,
		KeyFilePath:    keyFile,
		OutputPath:     out,
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.acornfox.com"},
		PayloadRoots:   []string{tmpDir},
		BundleFiles:    []string{missingBundle},
	}, nil)
	if err == nil {
		t.Fatal("expected error when bundle does not exist")
	}
	if !strings.Contains(err.Error(), "no valid bundle verified") {
		t.Fatalf("expected bundle verification error, got: %v", err)
	}

	// Verify no output envelope was written
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("output index must not exist when bundle verification fails")
	}
}
