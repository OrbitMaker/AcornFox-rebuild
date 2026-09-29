package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostlifecycle"
)

// fakeBackendState implements mock observation responses for tests.
type fakeBackendState struct {
	mu           sync.Mutex
	instanceID   string
	bindingID    string
	architecture string
	ready        bool
	finalized    bool
}

func (f *fakeBackendState) transport() desktopupdate.GuestTransport {
	return func(ctx context.Context, command desktopupdate.GuestCommand, stdin io.Reader, stdout io.Writer) (int, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		args := command.Arguments()
		if len(args) > 0 && args[0] == "observe" {
			obs := desktopupdate.BackendObservation{
				LocalLoopback:    true,
				MigrationVersion: "0040",
				Architecture:     f.architecture,
				InstanceID:       f.instanceID,
				Binding:          f.bindingID,
				Ready:            f.ready,
				Finalized:        f.finalized,
				AttemptState:     "absent",
			}
			obsRaw, _ := json.Marshal(obs)
			reply := struct {
				OK     bool            `json:"ok"`
				Code   string          `json:"code"`
				Result json.RawMessage `json:"result,omitempty"`
			}{
				OK:     true,
				Code:   "ok",
				Result: json.RawMessage(obsRaw),
			}
			raw, _ := json.Marshal(reply)
			stdout.Write(raw)
			return 0, nil
		}
		return 0, nil
	}
}

func createTestBootstrapFiles(t *testing.T, bootstrapDir string) []desktopupdate.HostBundleFile {
	t.Helper()
	launcherDir := filepath.Join(bootstrapDir, "launcher")
	controllerDir := filepath.Join(bootstrapDir, "controller")
	if err := os.MkdirAll(launcherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(controllerDir, 0700); err != nil {
		t.Fatal(err)
	}

	launcherPath := filepath.Join(launcherDir, "acornfox-host-launcher")
	controllerPath := filepath.Join(controllerDir, "acornfox-host-update")

	content, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcherPath, content, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controllerPath, content, 0755); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(content)
	contentSHA := hex.EncodeToString(h[:])

	files := []desktopupdate.HostBundleFile{
		{
			Path:   "controller/acornfox-host-update",
			SHA256: contentSHA,
			Size:   int64(len(content)),
			Mode:   0755,
		},
		{
			Path:   "launcher/acornfox-host-launcher",
			SHA256: contentSHA,
			Size:   int64(len(content)),
			Mode:   0755,
		},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func createTestEnvironment(t *testing.T) (configPath string, bootstrapDir, slotsDir, controllerDir string, instanceID, bindingID string, pubKey ed25519.PublicKey) {
	t.Helper()
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}
	bootstrapDir = filepath.Join(tmpDir, "bootstrap")
	slotsDir = filepath.Join(tmpDir, "slots")
	controllerDir = filepath.Join(tmpDir, "controller")

	for _, d := range []string{bootstrapDir, slotsDir, controllerDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}

	// Create slot lockfile
	lockPath := filepath.Join(slotsDir, "lock")
	if err := os.WriteFile(lockPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	files := createTestBootstrapFiles(t, bootstrapDir)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	instanceID = strings.Repeat("1", 64)
	bindingID = strings.Repeat("2", 64)

	specFiles := make([]hostconfig.HostBundleFileConfig, len(files))
	for i, f := range files {
		specFiles[i] = hostconfig.HostBundleFileConfig{
			Path:   f.Path,
			SHA256: f.SHA256,
			Size:   f.Size,
			Mode:   f.Mode,
		}
	}

	cfg := hostconfig.HostConfigFile{
		SchemaVersion:           1,
		InstanceID:              instanceID,
		BootstrapBackendBinding: bindingID,
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
			Files:              specFiles,
		},
		Policy: hostconfig.ConfigPolicyFile{
			PublicKeyHex:    hex.EncodeToString(pub),
			IndexURL:        "https://example.com/index.json",
			OS:              runtime.GOOS,
			Arch:            runtime.GOARCH,
			Channel:         "stable",
			AllowedHosts:    []string{"example.com"},
			MaxArtifactSize: 104857600,
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	configPath = filepath.Join(tmpDir, "host-runtime.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	return configPath, bootstrapDir, slotsDir, controllerDir, instanceID, bindingID, pub
}

func TestManagedChildHandshakeAndStatus(t *testing.T) {
	configPath, bootstrapDir, slotsDir, controllerDir, instanceID, bindingID, _ := createTestEnvironment(t)

	// Memory pipe for lifecycle connection
	parentConn, childConn := net.Pipe()
	defer parentConn.Close()
	defer childConn.Close()

	backend := &fakeBackendState{
		instanceID:   instanceID,
		bindingID:    bindingID,
		architecture: runtime.GOARCH,
		ready:        true,
		finalized:    true,
	}

	opts := ControllerOptions{
		ConfigPath:     configPath,
		SlotsRoot:      slotsDir,
		ControllerRoot: controllerDir,
		BootstrapRoot:  bootstrapDir,
		AllowNonRoot:   true,
		GuestTransport: backend.transport(),
	}

	childErrCh := make(chan error, 1)
	go func() {
		defer childConn.Close()
		childErrCh <- RunManagedChild(context.Background(), childConn, opts)
	}()

	// 1. Parent reads Hello
	helloRaw, err := hostlifecycle.ReadFrame(parentConn)
	if err != nil {
		t.Fatalf("parent failed to read hello: %v", err)
	}
	hello, err := hostlifecycle.DecodeHello(helloRaw)
	if err != nil {
		t.Fatalf("failed to decode hello: %v", err)
	}
	if hello.Type != hostlifecycle.FrameTypeHello || hello.SchemaVersion != 1 {
		t.Fatalf("unexpected hello frame: %+v", hello)
	}

	// Calculate bootstrap slot ID
	pinned, err := desktopupdate.PinHostBootstrap(context.Background(), desktopupdate.HostBootstrapSpec{
		Root:               bootstrapDir,
		OS:                 runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Version:            "1.0.0",
		Launcher:           "launcher/acornfox-host-launcher",
		Controller:         "controller/acornfox-host-update",
		ControllerProtocol: 1,
		InstanceProtocol:   1,
		BackendAPIProtocol: 1,
		Files:              createTestBootstrapFiles(t, bootstrapDir),
	})
	if err != nil {
		t.Fatal(err)
	}
	slotID := pinned.ID()
	pinned.Close()

	// 2. Parent sends Admit
	admit := &hostlifecycle.AdmitFrame{
		Type:          hostlifecycle.FrameTypeAdmit,
		SchemaVersion: 1,
		Operation:     hostlifecycle.OpStatus,
		Role:          hostlifecycle.RoleNormal,
		SlotID:        slotID,
		InstanceID:    instanceID,
		Nonce:         strings.Repeat("f", 64),
	}
	admitBytes, err := hostlifecycle.EncodeAdmit(admit)
	if err != nil {
		t.Fatal(err)
	}
	if err := hostlifecycle.WriteFrame(parentConn, admitBytes); err != nil {
		t.Fatal(err)
	}

	// 3. Parent reads Result
	resRaw, err := hostlifecycle.ReadFrame(parentConn)
	if err != nil {
		childErr := <-childErrCh
		t.Fatalf("parent failed to read result: %v (childErr: %v)", err, childErr)
	}
	result, err := hostlifecycle.DecodeResult(resRaw)
	if err != nil {
		t.Fatalf("failed to decode result: %v", err)
	}
	if result.Operation != hostlifecycle.OpStatus || result.State != "idle" || result.ReasonCode != "ok" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Nonce != admit.Nonce {
		t.Fatalf("nonce mismatch: got %q, want %q", result.Nonce, admit.Nonce)
	}

	if err := <-childErrCh; err != nil {
		t.Fatalf("child failed with: %v", err)
	}
}

func TestDebugStatus(t *testing.T) {
	configPath, bootstrapDir, slotsDir, controllerDir, instanceID, bindingID, pub := createTestEnvironment(t)
	_ = configPath

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
		t.Fatalf("PinHostBootstrap: %v", err)
	}

	backend := &fakeBackendState{
		instanceID:   instanceID,
		bindingID:    bindingID,
		architecture: runtime.GOARCH,
		ready:        true,
		finalized:    true,
	}

	gb, err := desktopupdate.NewGuestBackend(desktopupdate.GuestBackendOptions{
		InstanceID:   instanceID,
		Architecture: runtime.GOARCH,
		Transport:    backend.transport(),
	})
	if err != nil {
		t.Fatalf("NewGuestBackend: %v", err)
	}

	obs, err := gb.Observe(context.Background(), "")
	t.Logf("Observe result: %+v, err: %v", obs, err)

	hooks := desktopupdate.HostSlotHooks{
		Stop:  func(context.Context, string, string, desktopupdate.HostSlotView) error { return nil },
		Start: func(context.Context, string, desktopupdate.HostSlotView) error { return nil },
		Probe: func(context.Context, string, desktopupdate.HostSlotView, string) error { return nil },
	}

	slots, err := desktopupdate.NewHostSlots(desktopupdate.HostSlotOptions{
		Root:       slotsDir,
		InstanceID: instanceID,
		Bootstrap:  pinned,
		Hooks:      hooks,
	})
	if err != nil {
		t.Fatalf("NewHostSlots: %v", err)
	}

	currSlot, err := slots.CurrentSlot(context.Background())
	t.Logf("CurrentSlot: %q, err: %v", currSlot, err)

	policy := &desktopupdate.HostPolicy{
		PublicKey:       pub,
		IndexURL:        "https://example.com/index.json",
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Channel:         "stable",
		AllowedHosts:    []string{"example.com"},
		MaxArtifactSize: 104857600,
	}
	initial := desktopupdate.HostInstallation{
		Version:         "1.0.0",
		SlotSHA256:      pinned.ID(),
		BackendBinding:  bindingID,
		AppliedSequence: 0,
	}
	ctrl, err := desktopupdate.NewHostController(desktopupdate.HostControllerOptions{
		Root:       controllerDir,
		InstanceID: instanceID,
		Initial:    initial,
		Policy:     policy,
		Backend:    gb,
		Runtime:    slots,
	})
	if err != nil {
		t.Fatalf("NewHostController: %v", err)
	}

	st, err := ctrl.Status(context.Background())
	t.Logf("Status: %+v, err: %v", st, err)
	if err != nil {
		t.Fatalf("ctrl.Status failed: %v", err)
	}
}

func TestLauncherRequiredUnitsExclusion(t *testing.T) {
	// Verify that RequiredApplicationUnits and OptionalApplicationUnits NEVER contain docker, postgresql, or upgrade-safe.target
	for _, u := range RequiredApplicationUnits {
		if strings.Contains(u, "docker") || strings.Contains(u, "postgres") || strings.Contains(u, "upgrade-safe") {
			t.Fatalf("RequiredApplicationUnits must not contain docker, postgresql, or upgrade-safe, found: %s", u)
		}
	}
	for _, u := range OptionalApplicationUnits {
		if strings.Contains(u, "docker") || strings.Contains(u, "postgres") || strings.Contains(u, "upgrade-safe") {
			t.Fatalf("OptionalApplicationUnits must not contain docker, postgresql, or upgrade-safe, found: %s", u)
		}
	}
}

func TestLauncherStopAndStartMock(t *testing.T) {
	var stoppedUnits []string
	var startedUnits []string
	var mu sync.Mutex

	origCommandRunner := unitCommandRunner
	origActiveRunner := unitActiveRunner
	origEnabledRunner := unitEnabledRunner
	origPort := portReleasedRunner
	defer func() {
		unitCommandRunner = origCommandRunner
		unitActiveRunner = origActiveRunner
		unitEnabledRunner = origEnabledRunner
		portReleasedRunner = origPort
	}()

	unitActiveRunner = func(ctx context.Context, unit string) (bool, error) {
		return false, nil // All inactive after stop
	}

	unitEnabledRunner = func(ctx context.Context, unit string) (bool, error) {
		if unit == "acornfox-edge.service" {
			return true, nil // Profile preserved: edge was enabled
		}
		return false, nil
	}

	unitCommandRunner = func(ctx context.Context, action string, unit string) error {
		mu.Lock()
		defer mu.Unlock()
		if action == "stop" {
			stoppedUnits = append(stoppedUnits, unit)
		} else if action == "start" {
			startedUnits = append(startedUnits, unit)
		}
		return nil
	}

	portReleasedRunner = func(ctx context.Context, addr string, timeout time.Duration) error {
		return nil
	}

	if err := RunSlotStop(context.Background()); err != nil {
		t.Fatalf("RunSlotStop failed: %v", err)
	}

	mu.Lock()
	if len(stoppedUnits) == 0 {
		t.Fatal("no units stopped")
	}
	mu.Unlock()

	if err := RunSlotStart(context.Background()); err != nil {
		t.Fatalf("RunSlotStart failed: %v", err)
	}

	mu.Lock()
	if len(startedUnits) == 0 {
		t.Fatal("no units started")
	}
	edgeStarted := false
	for _, u := range startedUnits {
		if u == "acornfox-edge.service" {
			edgeStarted = true
		}
	}
	if !edgeStarted {
		t.Fatal("enabled optional profile for acornfox-edge.service was not restored on start")
	}
	mu.Unlock()

	// Injected required stop failure must block stop and fail closed
	unitCommandRunner = func(ctx context.Context, action string, unit string) error {
		if action == "stop" && unit == "acornfox-server.service" {
			return errors.New("injected stop failure")
		}
		return nil
	}
	if err := RunSlotStop(context.Background()); err == nil {
		t.Fatal("expected error on injected required unit stop failure")
	}

	// Injected optional stop failure must block stop and fail closed
	unitActiveRunner = func(ctx context.Context, unit string) (bool, error) {
		if unit == "acornfox-edge.service" {
			return true, nil
		}
		return false, nil
	}
	unitCommandRunner = func(ctx context.Context, action string, unit string) error {
		if action == "stop" && unit == "acornfox-edge.service" {
			return errors.New("injected optional stop failure")
		}
		return nil
	}
	if err := RunSlotStop(context.Background()); err == nil {
		t.Fatal("expected error on injected optional unit stop failure")
	}

	// Injected optional unit remains active after stop must block activation
	unitCommandRunner = func(ctx context.Context, action string, unit string) error {
		return nil
	}
	unitActiveRunner = func(ctx context.Context, unit string) (bool, error) {
		if unit == "acornfox-edge.service" {
			return true, nil // edge still active!
		}
		return false, nil
	}
	if err := RunSlotStop(context.Background()); err == nil || !errors.Is(err, ErrLauncherUnitActive) {
		t.Fatalf("expected ErrLauncherUnitActive when optional unit remains active, got: %v", err)
	}

	// Stateful test: optional unit false on initial query, but true on final barrier query
	// (e.g. unit activated concurrently or spawned by timer during stop)
	edgeQueryCount := 0
	unitActiveRunner = func(ctx context.Context, unit string) (bool, error) {
		if unit == "acornfox-edge.service" {
			edgeQueryCount++
			if edgeQueryCount == 1 {
				return false, nil // Inactive on initial query (not stopped in pass 1)
			}
			return true, nil // Active on final barrier query!
		}
		return false, nil
	}
	if err := RunSlotStop(context.Background()); err == nil || !errors.Is(err, ErrLauncherUnitActive) {
		t.Fatalf("expected ErrLauncherUnitActive when optional unit becomes active at barrier, got: %v", err)
	}
}
