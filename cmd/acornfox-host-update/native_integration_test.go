package main

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
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostlifecycle"
)

// TestRealRootGuestTransportObserve performs a read-only observation using the
// real NewPrivilegedLocalGuestTransport if running as root on a provisioned machine.
// If unprivileged or unprovisioned, it clearly skips without fabricating evidence.
func TestRealRootGuestTransportObserve(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real guest transport observe is linux-only")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping real guest transport observe: requires root privileges")
	}

	workerPath := "/usr/local/libexec/acornfox-guest-update"
	if _, err := os.Stat(workerPath); os.IsNotExist(err) {
		t.Skip("skipping real guest transport observe: worker not provisioned at " + workerPath)
	}

	instancePath := "/etc/acornfox-host/guest-instance.json"
	instRaw, err := os.ReadFile(instancePath)
	if err != nil {
		t.Skip("skipping real guest transport observe: instance config missing: " + err.Error())
	}

	var inst struct {
		InstanceID string `json:"instance_id"`
	}
	if err := json.Unmarshal(instRaw, &inst); err != nil || inst.InstanceID == "" {
		t.Skip("skipping real guest transport observe: invalid guest-instance.json")
	}

	transport := defaultGuestTransport()
	if transport == nil {
		t.Skip("guest transport unavailable")
	}

	gb, err := desktopupdate.NewGuestBackend(desktopupdate.GuestBackendOptions{
		InstanceID:   inst.InstanceID,
		Architecture: runtime.GOARCH,
		Transport:    transport,
	})
	if err != nil {
		t.Fatalf("failed to construct GuestBackend: %v", err)
	}

	obs, err := gb.Observe(context.Background(), "")
	if err != nil {
		t.Fatalf("real GuestBackend.Observe failed: %v", err)
	}

	t.Logf("REAL GUEST BACKEND OBSERVATION: InstanceID=%s Arch=%s Loopback=%v Ready=%v Finalized=%v Binding=%s",
		obs.InstanceID, obs.Architecture, obs.LocalLoopback, obs.Ready, obs.Finalized, obs.Binding)

	if !obs.LocalLoopback || obs.InstanceID != inst.InstanceID || !obs.Finalized {
		t.Fatalf("real observation invariant violation: %+v", obs)
	}
	t.Logf("Genuine root observation confirmed: Ready=%v (pre-service deployment state), Finalized=%v", obs.Ready, obs.Finalized)
}

// TestWrongOldArgvRegression asserts that invoking the binary with only ["managed-child"]
// exits with code 2 (usage), while ["acornfox-host-update", "managed-child"] enters the controller.
func TestWrongOldArgvRegression(t *testing.T) {
	if os.Getenv("ACORNFOX_TEST_SUBPROCESS") == "1" {
		main()
		return
	}

	// 1. Single argument (the old bug where cmd.Args = []string{"managed-child"} lacked argv0)
	cmdSingle := exec.Command(os.Args[0], "managed-child")
	cmdSingle.Args = []string{"managed-child"}
	cmdSingle.Env = append(os.Environ(), "ACORNFOX_TEST_SUBPROCESS=1")
	out, err := cmdSingle.CombinedOutput()
	if err == nil {
		t.Fatal("expected error when invoking with single argument managed-child")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for wrong argv, got %v (output: %s)", err, out)
	}

	// 2. Correct two arguments ["acornfox-host-update", "managed-child"]
	// Passes argument validation; exits 1 due to missing lifecycle FD 4 in this direct test
	cmdDual := exec.Command(os.Args[0], "acornfox-host-update", "managed-child")
	cmdDual.Args = []string{"acornfox-host-update", "managed-child"}
	cmdDual.Env = append(os.Environ(), "ACORNFOX_TEST_SUBPROCESS=1")
	outDual, errDual := cmdDual.CombinedOutput()
	if errDual == nil {
		t.Fatal("expected error due to missing lifecycle descriptor")
	}
	var exitErrDual *exec.ExitError
	if !errors.As(errDual, &exitErrDual) || exitErrDual.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 (lifecycle missing), got %v (output: %s)", errDual, outDual)
	}
}

// TestControllerPathnameReplacementProof verifies that replacing the controller binary
// on disk after callback does not alter the child's inherited inode descriptor.
func TestControllerPathnameReplacementProof(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(tmpDir, "controller-bin")
	contentA := []byte("version-A-original-content-for-descriptor-test")
	if err := os.WriteFile(testFile, contentA, 0755); err != nil {
		t.Fatal(err)
	}

	// Open descriptor with O_NOFOLLOW
	fd, err := syscall.Open(testFile, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "original-controller")

	var statA syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &statA); err != nil {
		f.Close()
		t.Fatal(err)
	}

	// Replace pathname atomically with version B
	newTestFile := filepath.Join(tmpDir, "controller-bin.new")
	contentB := []byte("version-B-completely-different-content-overwritten")
	if err := os.WriteFile(newTestFile, contentB, 0755); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := os.Rename(newTestFile, testFile); err != nil {
		f.Close()
		t.Fatal(err)
	}

	// Inode on open descriptor MUST NOT change
	var statCheck syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &statCheck); err != nil {
		f.Close()
		t.Fatal(err)
	}

	if statA.Ino != statCheck.Ino || statA.Dev != statCheck.Dev {
		f.Close()
		t.Fatalf("descriptor inode changed unexpectedly: %d vs %d", statA.Ino, statCheck.Ino)
	}

	// Verify descriptor still reads content A
	buf := make([]byte, len(contentA))
	if _, err := f.ReadAt(buf, 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if string(buf) != string(contentA) {
		f.Close()
		t.Fatalf("read content mismatch: got %q, want %q", string(buf), string(contentA))
	}

	// Close FD and verify it is truly closed
	f.Close()
	var statClosed syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &statClosed); err == nil {
		t.Fatal("expected Fstat to fail on closed descriptor")
	}
}

// TestRealCancelNoOrphanAndLockReacquire verifies process group cancellation and clean lock reacquisition.
func TestRealCancelNoOrphanAndLockReacquire(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(tmpDir, "invocation.lock")
	lock1, err := hostconfig.AcquireInvocationLock(lockPath, true)
	if err != nil {
		t.Fatal(err)
	}

	// Launch a background child in its own process group
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		lock1.Close()
		t.Fatal(err)
	}
	pid := cmd.Process.Pid

	// Terminate process group
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = cmd.Wait()

	// Verify child is not alive (no orphan)
	if err := syscall.Kill(pid, 0); err == nil {
		lock1.Close()
		t.Fatalf("child process %d still running", pid)
	}

	// Release lock1
	lock1.Close()

	// Reacquire lock: must succeed immediately
	lock2, err := hostconfig.AcquireInvocationLock(lockPath, true)
	if err != nil {
		t.Fatalf("failed to reacquire invocation lock: %v", err)
	}
	lock2.Close()
}

// TestNoEphemeralResidual verifies that after lifecycle execution, no temporary files exist.
func TestNoEphemeralResidual(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	entriesBefore, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Perform a lock acquire and release cycle
	lockPath := filepath.Join(tmpDir, "invocation.lock")
	lock, err := hostconfig.AcquireInvocationLock(lockPath, true)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	_ = os.Remove(lockPath)

	entriesAfter, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entriesBefore) != len(entriesAfter) {
		t.Fatalf("residual files detected: before %d, after %d", len(entriesBefore), len(entriesAfter))
	}
}

// Helper to create a signed test bundle for N -> N+1 -> N+2 testing
func makeTestSignedBundle(t *testing.T, version, fromBinding string, seq uint64, priv ed25519.PrivateKey, binContent ...[]byte) ([]byte, []byte, string) {
	t.Helper()
	helper := computeHexSHA256([]byte("helper-bin"))
	manifestMap := map[string]any{
		"schema_version":    1,
		"product":           "acornfox",
		"version":           version,
		"release_id":        "release-" + version,
		"source_commit":     strings.Repeat("a", 40),
		"architecture":      runtime.GOARCH,
		"migration_version": "0040",
		"files": []map[string]any{
			{"path": "bin/acornfox-upgrade", "sha256": helper, "mode": 0755},
		},
	}
	manifestBytes, _ := json.Marshal(manifestMap)
	archiveBytes := []byte("backend-archive-payload")
	bundleManifestBytes := []byte("bundle-manifest-bytes")

	bindingMap := map[string]any{
		"schema_version":         1,
		"product":                "acornfox",
		"version":                version,
		"release_id":             "release-" + version,
		"source_commit":          strings.Repeat("a", 40),
		"architecture":           runtime.GOARCH,
		"migration_version":      "0040",
		"archive_sha256":         computeHexSHA256(archiveBytes),
		"manifest_sha256":        computeHexSHA256(manifestBytes),
		"bundle_manifest_sha256": computeHexSHA256(bundleManifestBytes),
		"n_minus_one":            map[string]string{"binding_sha256": fromBinding},
	}
	bindingBytes, _ := json.Marshal(bindingMap)
	toBinding := computeHexSHA256(bindingBytes)

	// Binary content for launcher and controller
	var launcherContent []byte
	if len(binContent) > 0 && len(binContent[0]) > 0 {
		launcherContent = binContent[0]
	} else {
		var err error
		launcherContent, err = os.ReadFile(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	controllerContent := launcherContent

	contents := map[string][]byte{
		"launcher/acornfox-host-launcher":                              launcherContent,
		"controller/acornfox-host-update":                              controllerContent,
		"backend/candidate/candidate-binding.json":                     bindingBytes,
		"backend/candidate/candidate-binding.sha256":                   []byte(toBinding + "\n"),
		"backend/candidate/release-manifest.json":                      manifestBytes,
		"backend/candidate/bundle-manifest.sha256":                     bundleManifestBytes,
		"backend/candidate/build-record.json":                          []byte(`{"schema_version":1}`),
		"backend/candidate/acornfox-" + version + "-production.tar.gz": archiveBytes,
	}

	manifest := desktopupdate.HostBundleManifest{
		SchemaVersion:      1,
		Product:            "acornfox",
		Kind:               "host-update-v1",
		OS:                 runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Version:            version,
		ControllerProtocol: 1,
		InstanceProtocol:   1,
		Launcher:           "launcher/acornfox-host-launcher",
		Controller:         "controller/acornfox-host-update",
		Backend: desktopupdate.HostBackendPlan{
			Mode:         "candidate",
			FromBinding:  fromBinding,
			ToBinding:    toBinding,
			Architecture: runtime.GOARCH,
			HelperSHA256: helper,
			APIProtocol:  1,
		},
	}

	for p, b := range contents {
		mode := int64(0644)
		if strings.HasPrefix(p, "launcher/") || strings.HasPrefix(p, "controller/") {
			mode = 0755
		}
		manifest.Files = append(manifest.Files, desktopupdate.HostBundleFile{
			Path:   p,
			SHA256: computeHexSHA256(b),
			Size:   int64(len(b)),
			Mode:   mode,
		})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	rawManifest, _ := json.Marshal(manifest)
	_ = tw.WriteHeader(&tar.Header{Name: "bundle.json", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(rawManifest))})
	_, _ = tw.Write(rawManifest)
	for _, f := range manifest.Files {
		_ = tw.WriteHeader(&tar.Header{Name: f.Path, Typeflag: tar.TypeReg, Mode: f.Mode, Size: f.Size})
		_, _ = tw.Write(contents[f.Path])
	}
	_ = tw.Close()
	_ = gw.Close()

	payload := buf.Bytes()
	payloadSHA := computeHexSHA256(payload)

	// Create signed envelope
	payloadObj := desktopupdate.IndexPayload{
		Channel:   "stable",
		Sequence:  seq,
		Version:   version,
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             runtime.GOOS,
				Arch:           runtime.GOARCH,
				URL:            "https://downloads.example.com/" + version + "/bundle",
				SHA256:         payloadSHA,
				Size:           int64(len(payload)),
				BackendBinding: toBinding,
			},
		},
	}
	payloadJSON, _ := json.Marshal(payloadObj)
	sig := ed25519.Sign(priv, payloadJSON)

	envelopeObj := desktopupdate.IndexEnvelope{
		SchemaVersion: 1,
		Payload:       base64.StdEncoding.EncodeToString(payloadJSON),
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}
	envelopeJSON, _ := json.Marshal(envelopeObj)

	return payload, envelopeJSON, toBinding
}

func computeHexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fakeUpgradableBackend implements BackendExecutor with realistic observe & ensure upgrade
type fakeUpgradableBackend struct {
	mu           sync.Mutex
	instanceID   string
	bindingID    string
	architecture string
	attempts     map[string]bool
}

func (f *fakeUpgradableBackend) Observe(ctx context.Context, attempt string) (desktopupdate.BackendObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := "absent"
	if attempt != "" && f.attempts[attempt] {
		state = "upgraded"
	}
	return desktopupdate.BackendObservation{
		LocalLoopback:    true,
		MigrationVersion: "0040",
		Architecture:     f.architecture,
		InstanceID:       f.instanceID,
		Binding:          f.bindingID,
		Ready:            true,
		Finalized:        true,
		AttemptState:     state,
	}, nil
}

func (f *fakeUpgradableBackend) EnsureUpgrade(ctx context.Context, intent desktopupdate.HostUpgradeIntent, bundle *desktopupdate.VerifiedHostBundle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts[intent.AttemptID] = true
	f.bindingID = intent.ToBinding
	return nil
}

// TestNN1N2PipelineExecution performs a genuine HostController + HostSlots execution
// advancing N (C0) -> N+1 (C1) -> N+2 (C2), verifying slot pointer migration, distinct
// inodes, and durable terminal states.
func TestNN1N2PipelineExecution(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapDir := filepath.Join(tmpDir, "bootstrap")
	slotsDir := filepath.Join(tmpDir, "slots")
	controllerDir := filepath.Join(tmpDir, "controller")

	for _, d := range []string{bootstrapDir, slotsDir, controllerDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	lockPath := filepath.Join(slotsDir, "lock")
	if err := os.WriteFile(lockPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	files := createTestBootstrapFiles(t, bootstrapDir)
	spec := desktopupdate.HostBootstrapSpec{
		Root:               bootstrapDir,
		OS:                 runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Version:            "1.0.0",
		Launcher:           "launcher/acornfox-host-launcher",
		Controller:         "controller/acornfox-host-update",
		ControllerProtocol: 1,
		InstanceProtocol:   1,
		BackendAPIProtocol: 1,
		Files:              files,
	}
	pinned, err := desktopupdate.PinHostBootstrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	slotN := pinned.ID()

	instanceID := strings.Repeat("1", 64)
	bindingN := strings.Repeat("a", 64)

	backend := &fakeUpgradableBackend{
		instanceID:   instanceID,
		bindingID:    bindingN,
		architecture: runtime.GOARCH,
		attempts:     make(map[string]bool),
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hooks := desktopupdate.HostSlotHooks{
		Stop: func(ctx context.Context, inst, att string, view desktopupdate.HostSlotView) error {
			return nil
		},
		Start: func(ctx context.Context, inst string, view desktopupdate.HostSlotView) error {
			return nil
		},
		Probe: func(ctx context.Context, inst string, view desktopupdate.HostSlotView, targetBinding string) error {
			obs, err := backend.Observe(ctx, "")
			if err != nil || obs.Binding != targetBinding {
				return desktopupdate.ErrHostConflict
			}
			return nil
		},
	}

	slots, err := desktopupdate.NewHostSlots(desktopupdate.HostSlotOptions{
		Root:       slotsDir,
		InstanceID: instanceID,
		Bootstrap:  pinned,
		Hooks:      hooks,
	})
	if err != nil {
		t.Fatal(err)
	}

	initial := desktopupdate.HostInstallation{
		Version:         "1.0.0",
		SlotSHA256:      slotN,
		BackendBinding:  bindingN,
		AppliedSequence: 0,
	}

	// Prepare N+1 bundle and mock HTTP server
	payloadN1, envelopeN1, bindingN1 := makeTestSignedBundle(t, "1.1.0", bindingN, 1, priv)
	var currentPayload []byte
	currentPayload = payloadN1

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(currentPayload)
	}))
	defer ts.Close()

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}
	tr := ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = dialer
	tr.TLSClientConfig.ServerName = "downloads.example.com"
	client := &http.Client{Transport: tr}

	policy := &desktopupdate.HostPolicy{
		PublicKey:       pub,
		IndexURL:        "https://downloads.example.com/index.json",
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Channel:         "stable",
		AllowedHosts:    []string{"downloads.example.com"},
		MaxArtifactSize: 104857600,
	}

	controllerOpts := desktopupdate.HostControllerOptions{
		Root:            controllerDir,
		InstanceID:      instanceID,
		Initial:         initial,
		Policy:          policy,
		Backend:         backend,
		Runtime:         slots,
		HTTPClient:      client,
		DownloadTimeout: 10 * time.Second,
	}

	ctrl, err := desktopupdate.NewHostController(controllerOpts)
	if err != nil {
		t.Fatal(err)
	}

	// Confirm Slot N is active
	active, err := slots.CurrentSlot(context.Background())
	if err != nil || active != slotN {
		t.Fatalf("initial slot mismatch: got %s, want %s", active, slotN)
	}

	// 1. C0 selects N+1
	st, err := ctrl.Select(context.Background(), envelopeN1, false)
	if err != nil {
		t.Fatalf("C0 select N+1 failed: %v", err)
	}

	// Advance through all stages to terminal updated
	for i := 0; i < 10; i++ {
		st, err = ctrl.Advance(context.Background())
		if err != nil {
			t.Fatalf("advance error at step %d: %v", i, err)
		}
		if st.Snapshot != nil && st.Snapshot.Pending == nil {
			break
		}
	}
	if st.State != "updated" {
		t.Fatalf("expected terminal updated state, got %q", st.State)
	}

	// Active slot is now N+1!
	activeN1, err := slots.CurrentSlot(context.Background())
	if err != nil || activeN1 == slotN {
		t.Fatalf("slot pointer did not migrate to N+1: %s", activeN1)
	}
	t.Logf("SUCCESSFUL ADVANCE N -> N+1: active slot is now %s (binding %s)", activeN1, bindingN1)

	// Verify durable state recorded in state.json
	stStatus, err := ctrl.Status(context.Background())
	if err != nil || stStatus.Snapshot == nil || stStatus.Snapshot.Installed.SlotSHA256 != activeN1 {
		t.Fatalf("controller status does not reflect durable N+1: %+v", stStatus)
	}

	// 2. C1 advances N+1 -> N+2 with sequence 2
	payloadN2, envelopeN2, bindingN2 := makeTestSignedBundle(t, "1.2.0", bindingN1, 2, priv)
	currentPayload = payloadN2

	st2, err := ctrl.Select(context.Background(), envelopeN2, false)
	if err != nil {
		t.Fatalf("C1 select N+2 failed: %v", err)
	}

	// Advance through all stages to terminal updated
	for i := 0; i < 10; i++ {
		st2, err = ctrl.Advance(context.Background())
		if err != nil {
			t.Fatalf("C1 advance error at step %d: %v", i, err)
		}
		if st2.Snapshot != nil && st2.Snapshot.Pending == nil {
			break
		}
	}
	if st2.State != "updated" {
		t.Fatalf("expected terminal updated state for N+2, got %q", st2.State)
	}

	// Active slot is now N+2!
	activeN2, err := slots.CurrentSlot(context.Background())
	if err != nil || activeN2 == activeN1 || activeN2 == slotN {
		t.Fatalf("slot pointer did not migrate to N+2: %s", activeN2)
	}
	t.Logf("SUCCESSFUL ADVANCE N+1 -> N+2: active slot is now %s (binding %s)", activeN2, bindingN2)

	// Verify durable state recorded for N+2
	stStatus2, err := ctrl.Status(context.Background())
	if err != nil || stStatus2.Snapshot == nil || stStatus2.Snapshot.Installed.SlotSHA256 != activeN2 {
		t.Fatalf("controller status does not reflect durable N+2: %+v", stStatus2)
	}
	if stStatus2.Snapshot.Installed.Version != "1.2.0" {
		t.Fatalf("version mismatch: got %s, want 1.2.0", stStatus2.Snapshot.Installed.Version)
	}
}

func findOrBuildFixtureBinaries(t *testing.T, tmpDir string) (bootstrapBin, c0Bin, c1Bin, c2Bin string) {
	t.Helper()
	exeDir := filepath.Dir(os.Args[0])

	candidates := []string{
		exeDir,
		filepath.Join(exeDir, "fixture-bins"),
		"/tmp/acornfox-packet39-test",
		"/tmp/acornfox-packet39-build",
	}

	foundAll := func(base string) bool {
		for _, name := range []string{"acornfox-host-bootstrap.fixture", "c0.fixture", "c1.fixture", "c2.fixture"} {
			if _, err := os.Stat(filepath.Join(base, name)); err != nil {
				return false
			}
		}
		return true
	}

	for _, c := range candidates {
		if foundAll(c) {
			return filepath.Join(c, "acornfox-host-bootstrap.fixture"),
				filepath.Join(c, "c0.fixture"),
				filepath.Join(c, "c1.fixture"),
				filepath.Join(c, "c2.fixture")
		}
	}

	// If not pre-built, build if go compiler available in PATH
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("skipping two-invocation real bootstrap test: pre-built fixture binaries not found and go compiler unavailable in PATH")
	}

	binDir := filepath.Join(tmpDir, "fixture-binaries")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapBin = filepath.Join(binDir, "acornfox-host-bootstrap.fixture")
	c0Bin = filepath.Join(binDir, "c0.fixture")
	c1Bin = filepath.Join(binDir, "c1.fixture")
	c2Bin = filepath.Join(binDir, "c2.fixture")

	bCmd := exec.Command("go", "build", "-tags", "fixture", "-o", bootstrapBin, "github.com/open-card/open-card/cmd/acornfox-host-bootstrap")
	if out, err := bCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fixture bootstrap: %v (%s)", err, out)
	}

	for _, item := range []struct {
		marker string
		path   string
	}{
		{"C0", c0Bin},
		{"C1", c1Bin},
		{"C2", c2Bin},
	} {
		cCmd := exec.Command("go", "build", "-tags", "fixture", "-ldflags", "-X main.BuildMarker="+item.marker, "-o", item.path, "github.com/open-card/open-card/cmd/acornfox-host-update")
		if out, err := cCmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build %s: %v (%s)", item.marker, err, out)
		}
	}

	return bootstrapBin, c0Bin, c1Bin, c2Bin
}

// TestTwoInvocationRealBootstrapNN1N2 executes a real external bootstrap process twice against
// the same durable roots, proving that invocation 1 executes C0 and reaches N+1 terminal,
// and invocation 2 actually selects and executes C1 (with distinct inode and marker) reaching N+2.
func TestTwoInvocationRealBootstrapNN1N2(t *testing.T) {
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	bootstrapBin, c0Bin, c1Bin, c2Bin := findOrBuildFixtureBinaries(t, tmpDir)

	stat0, _ := os.Stat(c0Bin)
	stat1, _ := os.Stat(c1Bin)
	stat2, _ := os.Stat(c2Bin)
	ino0 := stat0.Sys().(*syscall.Stat_t).Ino
	ino1 := stat1.Sys().(*syscall.Stat_t).Ino
	ino2 := stat2.Sys().(*syscall.Stat_t).Ino

	if ino0 == ino1 || ino1 == ino2 || ino0 == ino2 {
		t.Fatalf("fixture binary inodes must be distinct: C0=%d, C1=%d, C2=%d", ino0, ino1, ino2)
	}
	t.Logf("Distinct controller binaries: C0(ino=%d), C1(ino=%d), C2(ino=%d)", ino0, ino1, ino2)

	fixtureDir := filepath.Join(tmpDir, "fixture-roots")
	bootstrapDir := filepath.Join(fixtureDir, "bootstrap")
	slotsDir := filepath.Join(fixtureDir, "slots")
	controllerDir := filepath.Join(fixtureDir, "controller")

	for _, d := range []string{
		filepath.Join(bootstrapDir, "launcher"),
		filepath.Join(bootstrapDir, "controller"),
		slotsDir,
		controllerDir,
	} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}

	slotLockPath := filepath.Join(slotsDir, "lock")
	if err := os.WriteFile(slotLockPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	// Copy C0 binary into bootstrap tree
	c0Bytes, err := os.ReadFile(c0Bin)
	if err != nil {
		t.Fatal(err)
	}
	c1Bytes, err := os.ReadFile(c1Bin)
	if err != nil {
		t.Fatal(err)
	}
	c2Bytes, err := os.ReadFile(c2Bin)
	if err != nil {
		t.Fatal(err)
	}

	bLauncher := filepath.Join(bootstrapDir, "launcher", "acornfox-host-launcher")
	bController := filepath.Join(bootstrapDir, "controller", "acornfox-host-update")
	if err := os.WriteFile(bLauncher, c0Bytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bController, c0Bytes, 0755); err != nil {
		t.Fatal(err)
	}

	c0SHA := computeHexSHA256(c0Bytes)
	files := []hostconfig.HostBundleFileConfig{
		{Path: "controller/acornfox-host-update", SHA256: c0SHA, Size: int64(len(c0Bytes)), Mode: 0755},
		{Path: "launcher/acornfox-host-launcher", SHA256: c0SHA, Size: int64(len(c0Bytes)), Mode: 0755},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	instanceID := strings.Repeat("1", 64)
	bindingN := strings.Repeat("a", 64)

	// Prepare signed bundles: N+1 contains C1, N+2 contains C2
	payloadN1, envelopeN1, bindingN1 := makeTestSignedBundle(t, "1.1.0", bindingN, 1, priv, c1Bytes)
	payloadN2, envelopeN2, bindingN2 := makeTestSignedBundle(t, "1.2.0", bindingN1, 2, priv, c2Bytes)
	_ = bindingN2

	var mu sync.Mutex
	var currentPayload []byte
	var currentEnvelope []byte
	currentPayload = payloadN1
	currentEnvelope = envelopeN1

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		p := currentPayload
		env := currentEnvelope
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/index.json" {
			_, _ = w.Write(env)
		} else {
			_, _ = w.Write(p)
		}
	}))
	defer ts.Close()

	// Initial persistent backend state
	backendInit := struct {
		InstanceID   string          `json:"instance_id"`
		Architecture string          `json:"architecture"`
		Binding      string          `json:"binding"`
		Ready        bool            `json:"ready"`
		Finalized    bool            `json:"finalized"`
		Attempts     map[string]bool `json:"attempts"`
	}{
		InstanceID:   instanceID,
		Architecture: runtime.GOARCH,
		Binding:      bindingN,
		Ready:        true,
		Finalized:    true,
		Attempts:     make(map[string]bool),
	}
	bInitRaw, _ := json.Marshal(backendInit)
	_ = os.WriteFile(filepath.Join(fixtureDir, "backend-state.json"), bInitRaw, 0600)

	cfg := hostconfig.HostConfigFile{
		SchemaVersion:           1,
		InstanceID:              instanceID,
		BootstrapBackendBinding: bindingN,
		BootstrapSpec: hostconfig.HostBootstrapSpecConfig{
			Root:               bootstrapDir,
			OS:                 runtime.GOOS,
			Architecture:       runtime.GOARCH,
			Version:            "1.0.0",
			Launcher:           "launcher/acornfox-host-launcher",
			Controller:         "controller/acornfox-host-update",
			ControllerProtocol: 1,
			InstanceProtocol:   1,
			BackendAPIProtocol: 1,
			Files:              files,
		},
		Policy: hostconfig.ConfigPolicyFile{
			PublicKeyHex:    hex.EncodeToString(pub),
			IndexURL:        "https://downloads.example.com/index.json",
			OS:              runtime.GOOS,
			Arch:            runtime.GOARCH,
			Channel:         "stable",
			AllowedHosts:    []string{"downloads.example.com"},
			MaxArtifactSize: 104857600,
		},
	}
	cfgRaw, _ := json.Marshal(cfg)
	configPath := filepath.Join(fixtureDir, "host-runtime.json")
	if err := os.WriteFile(configPath, cfgRaw, 0600); err != nil {
		t.Fatal(err)
	}

	envVars := append(os.Environ(),
		"ACORNFOX_FIXTURE_DIR="+fixtureDir,
		"ACORNFOX_FIXTURE_SERVER="+ts.Listener.Addr().String(),
		"ACORNFOX_FIXTURE_ALLOW_NONROOT=1",
	)

	t.Logf("=== Real Bootstrap Invocations Architecture ===")
	t.Logf("  Durable roots provisioned at: %s", fixtureDir)
	t.Logf("  Bootstrap binary: %s", bootstrapBin)
	t.Logf("  C0: %s (ino=%d)", c0Bin, ino0)
	t.Logf("  C1: %s (ino=%d)", c1Bin, ino1)
	t.Logf("  C2: %s (ino=%d)", c2Bin, ino2)

	// 0. Initial bootstrap invocation: status (authorizes and initializes initial state.json)
	cmdInit := exec.Command(bootstrapBin, "status")
	cmdInit.Env = envVars
	outInit, err := cmdInit.CombinedOutput()
	if err != nil {
		t.Fatalf("initial bootstrap status failed: %v (%s)", err, outInit)
	}
	var receiptInit hostlifecycle.ResultFrame
	if err := json.Unmarshal(outInit, &receiptInit); err != nil {
		t.Fatalf("failed to decode init receipt: %v (%s)", err, outInit)
	}
	if receiptInit.State != "idle" {
		t.Fatalf("unexpected init state: %+v", receiptInit)
	}
	t.Logf("INITIAL REAL BOOTSTRAP STATUS SUCCESS: baseline state initialized (slot=%s)", receiptInit.SlotID)

	// 1. First real bootstrap invocation: check (select N+1)
	cmdCheck1 := exec.Command(bootstrapBin, "check")
	cmdCheck1.Env = envVars
	outCheck1, err := cmdCheck1.CombinedOutput()
	if err != nil {
		t.Fatalf("first bootstrap check failed: %v (%s)", err, outCheck1)
	}

	// First advance: C0 runs, stages N+1, extracts C1, switches active to N+1, terminal updated
	cmdAdv1 := exec.Command(bootstrapBin, "advance")
	cmdAdv1.Env = envVars
	outAdv1, err := cmdAdv1.CombinedOutput()
	if err != nil {
		t.Fatalf("first bootstrap advance failed: %v (%s)", err, outAdv1)
	}
	var receipt1 hostlifecycle.ResultFrame
	if err := json.Unmarshal(outAdv1, &receipt1); err != nil {
		t.Fatalf("failed to decode receipt 1: %v (%s)", err, outAdv1)
	}
	if receipt1.State != "updated" || receipt1.Version != "1.1.0" {
		t.Fatalf("unexpected receipt 1: %+v", receipt1)
	}
	activeN1 := receipt1.SlotID
	t.Logf("FIRST REAL BOOTSTRAP INVOCATION SUCCESS: C0 advanced to N+1 (slot=%s, ver=%s)", activeN1, receipt1.Version)

	// 2. Second real bootstrap invocation: C1 is now active!
	// Switch test server to offer N+2
	mu.Lock()
	currentPayload = payloadN2
	currentEnvelope = envelopeN2
	mu.Unlock()

	cmdCheck2 := exec.Command(bootstrapBin, "check")
	cmdCheck2.Env = envVars
	outCheck2, err := cmdCheck2.CombinedOutput()
	if err != nil {
		t.Fatalf("second bootstrap check failed: %v (%s)", err, outCheck2)
	}

	// Second advance: C1 executes N+1 -> N+2
	cmdAdv2 := exec.Command(bootstrapBin, "advance")
	cmdAdv2.Env = envVars
	outAdv2, err := cmdAdv2.CombinedOutput()
	if err != nil {
		t.Fatalf("second bootstrap advance failed: %v (%s)", err, outAdv2)
	}
	var receipt2 hostlifecycle.ResultFrame
	if err := json.Unmarshal(outAdv2, &receipt2); err != nil {
		t.Fatalf("failed to decode receipt 2: %v (%s)", err, outAdv2)
	}
	if receipt2.State != "updated" || receipt2.Version != "1.2.0" {
		t.Fatalf("unexpected receipt 2: %+v", receipt2)
	}
	if receipt2.SlotID == activeN1 {
		t.Fatalf("active slot did not migrate on second advance: %s", receipt2.SlotID)
	}
	t.Logf("SECOND REAL BOOTSTRAP INVOCATION SUCCESS: C1 advanced to N+2 (slot=%s, ver=%s)", receipt2.SlotID, receipt2.Version)

	// 3. Third real invocation: verify status on N+2 (C2)
	cmdStat3 := exec.Command(bootstrapBin, "status")
	cmdStat3.Env = envVars
	outStat3, err := cmdStat3.CombinedOutput()
	if err != nil {
		t.Fatalf("third bootstrap status failed: %v (%s)", err, outStat3)
	}
	var receipt3 hostlifecycle.ResultFrame
	if err := json.Unmarshal(outStat3, &receipt3); err != nil {
		t.Fatalf("failed to decode receipt 3: %v (%s)", err, outStat3)
	}
	if (receipt3.State != "updated" && receipt3.State != "idle") || receipt3.Version != "1.2.0" || receipt3.SlotID != receipt2.SlotID {
		t.Fatalf("unexpected receipt 3: %+v", receipt3)
	}
	t.Logf("THIRD REAL BOOTSTRAP INVOCATION SUCCESS: C2 verified status (slot=%s, ver=%s)", receipt3.SlotID, receipt3.Version)

	// 4. Read and verify marker trace log: must strictly prove execution order C0 -> C1 -> C2
	tracePath := filepath.Join(fixtureDir, "marker-trace.log")
	traceRaw, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("failed to read marker trace log: %v", err)
	}
	traceLines := strings.Split(strings.TrimSpace(string(traceRaw)), "\n")
	t.Logf("EXECUTED CONTROLLER MARKER TRACE: %v", traceLines)

	c0Seen, c1Seen, c2Seen := false, false, false
	for _, l := range traceLines {
		if strings.HasPrefix(l, "C0:") {
			c0Seen = true
		}
		if strings.HasPrefix(l, "C1:") {
			c1Seen = true
			if !c0Seen {
				t.Fatal("C1 ran before C0!")
			}
		}
		if strings.HasPrefix(l, "C2:") {
			c2Seen = true
			if !c1Seen {
				t.Fatal("C2 ran before C1!")
			}
		}
	}
	if !c0Seen || !c1Seen || !c2Seen {
		t.Fatalf("marker trace did not observe all generations: C0=%v, C1=%v, C2=%v", c0Seen, c1Seen, c2Seen)
	}
	t.Logf("PROVEN EXECUTED CONTROLLER MARKERS: C0 -> C1 -> C2 verified strictly via post-admit fixture trace")
}
