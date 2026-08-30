package install

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeServiceRunner struct {
	active      map[string]bool
	enabled     map[string]bool
	argv        [][]string
	fail        map[string]error
	inactiveErr error
	disabledErr error
}

type fixedResultServiceRunner struct{ result CommandResult }

func (r fixedResultServiceRunner) Run(context.Context, ...string) CommandResult { return r.result }

func TestProductionServiceRunnerDoesNotInheritAmbientEnvironment(t *testing.T) {
	for key, value := range map[string]string{
		"OPEN_CARD_DATABASE_URL": "postgresql://ambient:secret@example.invalid/open_card",
		"DATABASE_URL":           "postgresql://ambient:secret@example.invalid/open_card",
		"PGPASSWORD":             "ambient-secret",
		"TENCENT_SECRET_ID":      "cloud-secret",
		"AWS_SECRET_ACCESS_KEY":  "cloud-secret",
		"HTTP_PROXY":             "http://proxy.invalid",
		"ACCESS_TOKEN":           "token-secret",
	} {
		t.Setenv(key, value)
	}
	var captured *exec.Cmd
	runner := productionServiceRunner{command: func(ctx context.Context, path string, args ...string) *exec.Cmd {
		if path != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"daemon-reload"}) {
			t.Fatalf("command = %q %q", path, args)
		}
		captured = exec.CommandContext(ctx, "/usr/bin/true")
		return captured
	}}
	if result := runner.Run(context.Background(), "systemctl", "daemon-reload"); result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("result = %#v", result)
	}
	if captured == nil || !reflect.DeepEqual(captured.Env, productionSubprocessBaseEnv) {
		t.Fatalf("child env = %#v", captured)
	}
	for _, entry := range captured.Env {
		if strings.Contains(entry, "secret") || strings.Contains(entry, "proxy") || strings.Contains(entry, "token") {
			t.Fatalf("ambient value leaked into child env: %q", entry)
		}
	}
}

type fakeEdgeConfigRunner struct {
	commands []EdgeConfigCommand
	run      func(context.Context, EdgeConfigCommand) CommandResult
}

func (r *fakeEdgeConfigRunner) RunEdgeConfig(ctx context.Context, command EdgeConfigCommand) CommandResult {
	r.commands = append(r.commands, EdgeConfigCommand{Executable: command.Executable, Arguments: append([]string(nil), command.Arguments...), User: command.User, UID: command.UID, GID: command.GID, Environment: append([]string(nil), command.Environment...)})
	if r.run != nil {
		return r.run(ctx, command)
	}
	return CommandResult{}
}

func TestProductionEdgeConfigRunnerUsesFixedPrivilegeBoundaryAndEnvironment(t *testing.T) {
	for key, value := range map[string]string{
		"OPEN_CARD_DATABASE_URL": "postgresql://ambient:secret@example.invalid/open_card",
		"PGPASSWORD":             "ambient-secret",
		"HTTP_PROXY":             "http://proxy.invalid",
		"TENCENT_SECRET_ID":      "cloud-secret",
		"ACCESS_TOKEN":           "token-secret",
	} {
		t.Setenv(key, value)
	}
	var captured *exec.Cmd
	runner := productionEdgeConfigRunner{verify: func(path string) (os.FileInfo, error) {
		if path != productionCaddyPrivilegeDropPath {
			t.Fatalf("verified path = %q", path)
		}
		return serverUnitFileInfo{mode: 0o755, uid: 0, gid: 0}, nil
	}, command: func(ctx context.Context, path string, args ...string) *exec.Cmd {
		if path != productionCaddyPrivilegeDropPath {
			t.Fatalf("privilege path = %q", path)
		}
		want := []string{"--reuid=123", "--regid=456", "--clear-groups", "--", "/opt/open-card/releases/release-new/bin/caddy", "validate", "--config", "/var/lib/open-card/upgrade-artifacts/txn-1/open-card-edge.Caddyfile", "--adapter", "caddyfile"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("privilege argv = %#v, want %#v", args, want)
		}
		captured = exec.CommandContext(ctx, "/usr/bin/true")
		return captured
	}}
	result := runner.RunEdgeConfig(context.Background(), EdgeConfigCommand{Executable: "/opt/open-card/releases/release-new/bin/caddy", Arguments: []string{"validate", "--config", "/var/lib/open-card/upgrade-artifacts/txn-1/open-card-edge.Caddyfile", "--adapter", "caddyfile"}, User: productionCaddyUser, UID: 123, GID: 456, Environment: productionEdgeRuntimePaths.environment()})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("runner result = %#v", result)
	}
	if captured == nil || !reflect.DeepEqual(captured.Env, productionEdgeRuntimePaths.environment()) {
		t.Fatalf("child env = %#v", captured)
	}
	for _, entry := range captured.Env {
		if strings.Contains(entry, "secret") || strings.Contains(entry, "proxy") || strings.Contains(entry, "token") || strings.Contains(entry, "postgres") {
			t.Fatalf("ambient value leaked into child env: %q", entry)
		}
	}
	if unsafe := runner.RunEdgeConfig(context.Background(), EdgeConfigCommand{Executable: "/opt/open-card/releases/release-new/bin/caddy", Arguments: []string{"validate"}, User: productionCaddyUser, UID: 123, GID: 456, Environment: append(productionSubprocessBaseEnv, "OPEN_CARD_DATABASE_URL=postgresql://secret@invalid")}); unsafe.Err == nil {
		t.Fatal("production runner accepted a caller-selected environment")
	}
}

func TestSafeProductionExecutableRequiresSecureAncestorsAndRereadsLeaf(t *testing.T) {
	const executable = "/secure/root/bin/tool"
	entries := map[string]os.FileInfo{
		"/":                serverUnitFileInfo{mode: os.ModeDir | 0o755, uid: 0, gid: 0, directory: true},
		"/secure":          serverUnitFileInfo{mode: os.ModeDir | 0o755, uid: 0, gid: 0, directory: true},
		"/secure/root":     serverUnitFileInfo{mode: os.ModeDir | 0o755, uid: 0, gid: 0, directory: true},
		"/secure/root/bin": serverUnitFileInfo{mode: os.ModeDir | 0o755, uid: 0, gid: 0, directory: true},
		executable:         serverUnitFileInfo{mode: 0o755, uid: 0, gid: 0},
	}
	lstat := func(path string) (os.FileInfo, error) {
		info, ok := entries[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	if _, err := safeExecutablePath(executable, 0, 0, lstat); err != nil {
		t.Fatalf("safe path rejected: %v", err)
	}
	for name, replace := range map[string]os.FileInfo{
		"writable ancestor": serverUnitFileInfo{mode: os.ModeDir | 0o775, uid: 0, gid: 0, directory: true},
		"symlink ancestor":  serverUnitFileInfo{mode: os.ModeSymlink | 0o777, uid: 0, gid: 0},
		"nonroot ancestor":  serverUnitFileInfo{mode: os.ModeDir | 0o755, uid: 1, gid: 0, directory: true},
	} {
		t.Run(name, func(t *testing.T) {
			original := entries["/secure/root"]
			entries["/secure/root"] = replace
			t.Cleanup(func() { entries["/secure/root"] = original })
			if _, err := safeExecutablePath(executable, 0, 0, lstat); err == nil {
				t.Fatal("unsafe ancestor accepted")
			}
		})
	}
	// Rechecking at use time rejects a leaf replacement after a prior success.
	entries[executable] = serverUnitFileInfo{mode: 0o777, uid: 0, gid: 0}
	if _, err := safeExecutablePath(executable, 0, 0, lstat); err == nil {
		t.Fatal("replaced executable leaf accepted")
	}
}

func TestEdgeConfigValidatorFixedInputsAndEvidence(t *testing.T) {
	validator, input, roots := edgeValidatorFixture(t)
	runner := validator.runner.(*fakeEdgeConfigRunner)
	result, err := validator.validate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ConfigSHA256 != input.ConfigSHA256 || result.CandidateCaddySHA256 != input.Transition.CandidateCaddySHA256 || result.EvidenceSHA256 != edgeConfigEvidenceSHA256(input) {
		t.Fatalf("validation result = %#v", result)
	}
	want := []EdgeConfigCommand{
		{Executable: filepath.Join(roots.active, "releases", input.Transition.CandidateReleaseID, "bin/caddy"), Arguments: []string{"validate", "--config", filepath.Join(roots.data, "upgrade-artifacts", input.Transition.TransactionID, edgeConfigArtifactName), "--adapter", "caddyfile"}, User: productionCaddyUser, UID: os.Getuid(), GID: os.Getgid(), Environment: validator.runtime.environment()},
		{Executable: filepath.Join(roots.active, "releases", input.Transition.CandidateReleaseID, "bin/caddy"), Arguments: []string{"adapt", "--config", filepath.Join(roots.data, "upgrade-artifacts", input.Transition.TransactionID, edgeConfigArtifactName), "--adapter", "caddyfile", "--validate"}, User: productionCaddyUser, UID: os.Getuid(), GID: os.Getgid(), Environment: validator.runtime.environment()},
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("edge commands = %#v, want %#v", runner.commands, want)
	}
}

func TestEdgeConfigValidatorRejectsUnsafeInputsAndUnknownOutcomes(t *testing.T) {
	t.Run("symlink config", func(t *testing.T) {
		validator, input, roots := edgeValidatorFixture(t)
		config := filepath.Join(roots.data, "upgrade-artifacts", input.Transition.TransactionID, edgeConfigArtifactName)
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(config); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, config); err != nil {
			t.Fatal(err)
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("symlink error = %v", err)
		}
		if len(validator.runner.(*fakeEdgeConfigRunner).commands) != 0 {
			t.Fatal("symlink config reached caddy runner")
		}
	})
	t.Run("unsafe caddy mode", func(t *testing.T) {
		validator, input, roots := edgeValidatorFixture(t)
		if err := os.Chmod(filepath.Join(roots.active, "releases", input.Transition.CandidateReleaseID, edgeCaddyRelativePath), 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("mode error = %v", err)
		}
	})
	t.Run("unsafe config mode", func(t *testing.T) {
		validator, input, roots := edgeValidatorFixture(t)
		if err := os.Chmod(filepath.Join(roots.data, "upgrade-artifacts", input.Transition.TransactionID, edgeConfigArtifactName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("config mode error = %v", err)
		}
	})
	t.Run("edge service env rejects path mode owner and grammar drift", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*testing.T, *EdgeConfigValidator, edgeConfigValidationInput, edgeValidatorRoots)
		}{
			{"symlink", func(t *testing.T, validator *EdgeConfigValidator, _ edgeConfigValidationInput, roots edgeValidatorRoots) {
				path := filepath.Join(roots.data, "open-card-edge.env")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(roots.data, "missing.env"), path); err != nil {
					t.Fatal(err)
				}
			}},
			{"mode", func(t *testing.T, _ *EdgeConfigValidator, _ edgeConfigValidationInput, roots edgeValidatorRoots) {
				if err := os.Chmod(filepath.Join(roots.data, "open-card-edge.env"), 0o644); err != nil {
					t.Fatal(err)
				}
			}},
			{"owner", func(t *testing.T, validator *EdgeConfigValidator, _ edgeConfigValidationInput, _ edgeValidatorRoots) {
				validator.edgeGID++
			}},
			{"extra", func(t *testing.T, validator *EdgeConfigValidator, _ edgeConfigValidationInput, roots edgeValidatorRoots) {
				writeEdgeEnvFixture(t, validator, filepath.Join(roots.data, "open-card-edge.env"), "UNRELATED=value\n")
			}},
			{"duplicate", func(t *testing.T, validator *EdgeConfigValidator, _ edgeConfigValidationInput, roots edgeValidatorRoots) {
				writeEdgeEnvFixture(t, validator, filepath.Join(roots.data, "open-card-edge.env"), "HOME="+validator.runtime.home+"\n")
			}},
			{"comment", func(t *testing.T, validator *EdgeConfigValidator, _ edgeConfigValidationInput, roots edgeValidatorRoots) {
				writeEdgeEnvFixture(t, validator, filepath.Join(roots.data, "open-card-edge.env"), edgeEnvCanonicalComment+"\n")
			}},
			{"runtime-dir", func(t *testing.T, validator *EdgeConfigValidator, _ edgeConfigValidationInput, _ edgeValidatorRoots) {
				if err := os.Chmod(validator.runtime.log, 0o777); err != nil {
					t.Fatal(err)
				}
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				validator, input, roots := edgeValidatorFixture(t)
				test.mutate(t, validator, input, roots)
				if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
					t.Fatalf("%s error = %v", test.name, err)
				}
				if len(validator.runner.(*fakeEdgeConfigRunner).commands) != 0 {
					t.Fatalf("%s reached caddy runner", test.name)
				}
			})
		}
	})
	t.Run("runner output is never surfaced", func(t *testing.T) {
		validator, input, _ := edgeValidatorFixture(t)
		validator.runner.(*fakeEdgeConfigRunner).run = func(context.Context, EdgeConfigCommand) CommandResult {
			return CommandResult{ExitCode: 1, Output: "postgresql://secret@invalid", Err: errors.New("token-secret")}
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres") {
			t.Fatalf("runner error = %v", err)
		}
	})
	t.Run("timeout is unknown", func(t *testing.T) {
		validator, input, _ := edgeValidatorFixture(t)
		validator.timeout = 10 * time.Millisecond
		validator.runner.(*fakeEdgeConfigRunner).run = func(ctx context.Context, _ EdgeConfigCommand) CommandResult {
			return CommandResult{ExitCode: -1, Output: "secret", Err: ctx.Err()}
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("timeout error = %v", err)
		}
	})
	t.Run("post command drift is rejected", func(t *testing.T) {
		validator, input, roots := edgeValidatorFixture(t)
		calls := 0
		validator.runner.(*fakeEdgeConfigRunner).run = func(context.Context, EdgeConfigCommand) CommandResult {
			calls++
			if calls == 1 {
				_ = os.WriteFile(filepath.Join(roots.data, "upgrade-artifacts", input.Transition.TransactionID, edgeConfigArtifactName), []byte("changed"), 0o644)
			}
			return CommandResult{}
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("post-command drift error = %v", err)
		}
	})
	t.Run("service environment drift is rejected after command", func(t *testing.T) {
		validator, input, roots := edgeValidatorFixture(t)
		calls := 0
		validator.runner.(*fakeEdgeConfigRunner).run = func(context.Context, EdgeConfigCommand) CommandResult {
			calls++
			if calls == 1 {
				writeEdgeEnvFixture(t, validator, filepath.Join(roots.data, "open-card-edge.env"), "# changed\n")
			}
			return CommandResult{}
		}
		if _, err := validator.validate(context.Background(), input); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("service environment drift error = %v", err)
		}
	})
}

type edgeValidatorRoots struct{ active, data string }

func edgeValidatorFixture(t *testing.T) (*EdgeConfigValidator, edgeConfigValidationInput, edgeValidatorRoots) {
	t.Helper()
	base := t.TempDir()
	roots := edgeValidatorRoots{active: filepath.Join(base, "active"), data: filepath.Join(base, "data")}
	if err := os.Mkdir(roots.active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(roots.data, 0o711); err != nil {
		t.Fatal(err)
	}
	tx, releaseID := "txn-edge-1", "release-edge-1"
	release := filepath.Join(roots.active, "releases", releaseID)
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]struct {
		raw  []byte
		mode os.FileMode
	}{
		edgeCaddyRelativePath:                                     {[]byte("caddy-binary\n"), 0o755},
		edgeTemplateRelativePath:                                  {[]byte("edge template\n"), 0o644},
		"bin/open-card-admin":                                     {[]byte("admin\n"), 0o755},
		"bin/open-card-upgrade":                                   {[]byte("upgrade\n"), 0o755},
		"systemd/open-card-edge.service":                          {[]byte("edge\n"), 0o644},
		"systemd/open-card-upgrade-recover.service":               {ProductionUpgradeRecoveryUnitBytes(), 0o644},
		"systemd/open-card-upgrade-safe.target":                   {ProductionUpgradeSafeBootTargetBytes(), 0o644},
		"systemd/open-card-upgrade-finalize.service":              {ProductionUpgradeFinalizeUnitBytes(), 0o644},
		"systemd/open-card-edge.service.d/10-upgrade-marker.conf": {ProductionUpgradeEdgeMarkerDropInBytes(), 0o644},
		"migrations/control-plane/0024_dns_change_ledger.sql":     {[]byte("-- migration\n"), 0o644},
		"web/dist/index.html":                                     {[]byte("web\n"), 0o644},
		"docs/licenses/licenses-manifest.json":                    {[]byte("{}\n"), 0o644},
		"sbom.spdx.json":                                          {[]byte("{}\n"), 0o644},
		"source-manifest.sha256":                                  {[]byte("source\n"), 0o644},
	}
	manifestFiles := make([]FileDigest, 0, len(files))
	for path, file := range files {
		full := filepath.Join(release, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, file.raw, file.mode); err != nil {
			t.Fatal(err)
		}
		manifestFiles = append(manifestFiles, FileDigest{Path: path, SHA256: sha256Bytes(file.raw), Mode: uint32(file.mode)})
	}
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: ProductionCandidateVersion, ReleaseID: releaseID, Architecture: "amd64", MigrationVersion: CurrentMigrationVersion, SourceCommit: strings.Repeat("a", 40), NMinusOne: &NMinusOne{Version: ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: RC0ReleaseManifestSHA256, ArchiveSHA256: RC0ArchiveSHA256, BundleManifestSHA256: RC0BundleManifestSHA256}, Protocol: AgentProtocolVersion, ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir, Compatibility: Compatibility{MinDataVersion: 23, MaxDataVersion: 24, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion}, Files: manifestFiles}
	if err := SaveManifest(filepath.Join(release, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(roots.data, "upgrade-artifacts", tx)
	if err := os.MkdirAll(artifactDir, 0o711); err != nil {
		t.Fatal(err)
	}
	config := []byte("example.test {\n respond \"ok\"\n}\n")
	if err := os.WriteFile(filepath.Join(artifactDir, edgeConfigArtifactName), config, 0o640); err != nil {
		t.Fatal(err)
	}
	input := edgeConfigValidationInput{Transition: EdgeConfigTransitionV1{SchemaVersion: 1, TransactionID: tx, SourceReleaseID: "release-old", CandidateReleaseID: releaseID, ConsoleHostname: "console.example.test", SourceTemplateSHA256: strings.Repeat("1", 64), CandidateTemplateSHA256: sha256Bytes(files[edgeTemplateRelativePath].raw), InstalledBeforeSHA256: strings.Repeat("2", 64), InstalledAfterSHA256: sha256Bytes(config), CandidateCaddySHA256: sha256Bytes(files[edgeCaddyRelativePath].raw)}, ConfigSHA256: sha256Bytes(config)}
	runner := &fakeEdgeConfigRunner{}
	validator, err := TaskEdgeConfigValidator(roots.active, roots.data, os.Getuid(), os.Getgid(), os.Getuid(), os.Getgid(), runner)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{validator.runtime.home, validator.runtime.data, validator.runtime.config, validator.runtime.log} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeEdgeEnvFixture(t, validator, filepath.Join(roots.data, "open-card-edge.env"), "")
	return validator, input, roots
}

func writeEdgeEnvFixture(t *testing.T, validator *EdgeConfigValidator, path, suffix string) {
	t.Helper()
	env := edgeEnvCanonicalComment + "\n" + strings.Join([]string{
		"HOME=" + validator.runtime.home,
		"XDG_DATA_HOME=" + validator.runtime.data,
		"XDG_CONFIG_HOME=" + validator.runtime.config,
		"OPEN_CARD_EDGE_LOG_DIR=" + validator.runtime.log,
	}, "\n") + "\n" + suffix
	if err := os.WriteFile(path, []byte(env), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestServiceControllerAndAdapterCloseAreIdempotent(t *testing.T) {
	writerOps := &serviceCloseOps{err: errors.New("unit writer close")}
	controller := &ServiceController{unitWriter: &DurableWriter{ops: writerOps}}
	if err := controller.Close(); !errors.Is(err, ErrServiceOutcomeUnknown) || writerOps.calls != 1 {
		t.Fatalf("controller close=%v calls=%d", err, writerOps.calls)
	}
	if err := controller.Close(); err != nil || writerOps.calls != 1 {
		t.Fatalf("second controller close=%v calls=%d", err, writerOps.calls)
	}
	adapter := &UpgradeServiceAdapter{controller: &ServiceController{unitWriter: &DurableWriter{ops: writerOps}}}
	if err := adapter.Close(); !errors.Is(err, ErrServiceOutcomeUnknown) || writerOps.calls != 2 {
		t.Fatalf("adapter close=%v calls=%d", err, writerOps.calls)
	}
	if err := adapter.Close(); err != nil || writerOps.calls != 2 {
		t.Fatalf("second adapter close=%v calls=%d", err, writerOps.calls)
	}
}

type serviceCloseOps struct {
	durableOps
	calls int
	err   error
}

func (o *serviceCloseOps) Close() error { o.calls++; return o.err }

func newFakeServiceRunner() *fakeServiceRunner {
	return &fakeServiceRunner{active: map[string]bool{}, enabled: map[string]bool{}, fail: map[string]error{}, inactiveErr: testExitError(3), disabledErr: testExitError(1)}
}

func testExitError(code int) error {
	err := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	if _, ok := err.(*exec.ExitError); !ok {
		panic("test command did not return exec.ExitError")
	}
	return err
}
func (f *fakeServiceRunner) Run(_ context.Context, argv ...string) CommandResult {
	f.argv = append(f.argv, append([]string(nil), argv...))
	key := strings.Join(argv, " ")
	if err := f.fail[key]; err != nil {
		return CommandResult{ExitCode: -1, Output: "sensitive output", Err: err}
	}
	if len(argv) == 2 && argv[1] == "daemon-reload" {
		return CommandResult{}
	}
	unit := argv[len(argv)-1]
	switch argv[1] {
	case "is-active":
		if f.active[unit] {
			return CommandResult{}
		}
		return CommandResult{ExitCode: 3, Err: f.inactiveErr}
	case "is-enabled":
		if f.enabled[unit] {
			return CommandResult{}
		}
		return CommandResult{ExitCode: 1, Err: f.disabledErr}
	case "start":
		f.active[unit] = true
	case "stop":
		f.active[unit] = false
	case "enable":
		f.enabled[unit] = true
	case "disable":
		f.enabled[unit] = false
	}
	return CommandResult{}
}

func taskController(t *testing.T, runner *fakeServiceRunner, marker func() (bool, error)) *ServiceController {
	t.Helper()
	controller, err := TaskServiceController(runner, marker, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestServiceControlOrdersQuiesceStartAndSnapshotWithoutRawOutput(t *testing.T) {
	runner := newFakeServiceRunner()
	for _, unit := range serviceUnits {
		runner.active[serviceName(unit)] = true
		runner.enabled[serviceName(unit)] = true
	}
	controller := taskController(t, runner, func() (bool, error) { return false, nil })
	snapshot, err := controller.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot[ServiceEdge].Active || !snapshot[ServiceEdge].Enabled {
		t.Fatal("snapshot lost service booleans")
	}
	if err := controller.Quiesce(context.Background(), false, false); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer} {
		if runner.active[serviceName(unit)] {
			t.Fatalf("%s remained active", unit)
		}
	}
	if err := controller.StartInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := controller.StartEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(func() []string {
		values := []string{}
		for _, argv := range runner.argv {
			values = append(values, strings.Join(argv, " "))
		}
		return values
	}(), "\n")
	for _, want := range []string{"systemctl stop open-card-edge.service", "systemctl stop open-card-agent.service", "systemctl stop open-card-server.service", "systemctl start open-card-buildkit.service", "systemctl start open-card-caddy.service", "systemctl start open-card-server.service", "systemctl start open-card-agent.service", "systemctl start open-card-edge.service"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing fixed command %q", want)
		}
	}
}

func TestServiceControlAcceptsDocumentedInactiveAndDisabledExitErrors(t *testing.T) {
	runner := newFakeServiceRunner()
	controller := taskController(t, runner, func() (bool, error) { return false, nil })
	snapshot, err := controller.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range serviceUnits {
		if snapshot[unit].Active || snapshot[unit].Enabled {
			t.Fatalf("unexpected active/enabled state for %s: %#v", unit, snapshot[unit])
		}
	}
	if err := controller.Quiesce(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}
}

func TestServiceControlRejectsUnprovenStatusOutcomes(t *testing.T) {
	exit3, exit1, exit4 := testExitError(3), testExitError(1), testExitError(4)
	tests := []struct {
		name   string
		action string
		result CommandResult
	}{
		{"inactive nil error", "is-active", CommandResult{ExitCode: 3}},
		{"disabled nil error", "is-enabled", CommandResult{ExitCode: 1}},
		{"inactive generic error", "is-active", CommandResult{ExitCode: 3, Err: errors.New("generic")}},
		{"disabled generic error", "is-enabled", CommandResult{ExitCode: 1, Err: context.Canceled}},
		{"active zero status generic error", "is-active", CommandResult{Err: errors.New("generic")}},
		{"enabled zero status generic error", "is-enabled", CommandResult{Err: context.Canceled}},
		{"swapped active code", "is-active", CommandResult{ExitCode: 1, Err: exit1}},
		{"swapped enabled code", "is-enabled", CommandResult{ExitCode: 3, Err: exit3}},
		{"mismatched exit error", "is-active", CommandResult{ExitCode: 3, Err: exit4}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &ServiceController{runner: fixedResultServiceRunner{result: test.result}}
			if _, err := controller.state(context.Background(), ServiceEdge, test.action); !errors.Is(err, ErrServiceOutcomeUnknown) {
				t.Fatalf("state error=%v", err)
			}
		})
	}
}

func TestServiceControlUnknownRollbackAndMarkerAreFailClosed(t *testing.T) {
	runner := newFakeServiceRunner()
	runner.active[serviceName(ServiceEdge)] = true
	controller := taskController(t, runner, func() (bool, error) { return true, nil })
	if err := controller.StartEdge(context.Background()); !errors.Is(err, ErrEdgeMarkerPresent) {
		t.Fatalf("marker error=%v", err)
	}
	runner.fail["systemctl stop open-card-edge.service"] = errors.New("untrusted output")
	if err := controller.Quiesce(context.Background(), true, true); !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("stop error=%v", err)
	}
	delete(runner.fail, "systemctl stop open-card-edge.service")
	if err := controller.RestoreSnapshot(context.Background(), ServiceSnapshot{}); !errors.Is(err, ErrServiceOutcomeUnknown) {
		t.Fatalf("restore error=%v", err)
	}
}

func TestHealthProbeOnlyUsesLoopbackApprovedEndpoints(t *testing.T) {
	runner := newFakeServiceRunner()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/config/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	controller := taskController(t, runner, func() (bool, error) { return false, nil })
	if _, err := controller.ProbeHealth(context.Background(), server.URL+"/healthz"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ProbeHealth(context.Background(), server.URL+"/config/"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://example.com:8080/healthz", "http://127.0.0.1:8080/nope", "http://127.0.0.1:8080/healthz?secret=value"} {
		result, err := controller.ProbeHealth(context.Background(), raw)
		if err == nil || result.Code != "invalid_target" {
			t.Fatalf("accepted %q: %#v %v", raw, result, err)
		}
	}
	deadline, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := controller.ProbeHealth(deadline, "http://127.0.0.1:1/readyz")
	if err == nil || result.Code != "unhealthy" {
		t.Fatalf("timeout/cancel result=%#v err=%v", result, err)
	}
}

type serverUnitReloadRunner struct {
	argv    [][]string
	shows   []CommandResult
	reload  CommandResult
	invalid CommandResult
}

func (r *serverUnitReloadRunner) Run(_ context.Context, argv ...string) CommandResult {
	r.argv = append(r.argv, append([]string(nil), argv...))
	if reflect.DeepEqual(argv, []string{"systemctl", "show", "open-card-server.service", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload"}) {
		if len(r.shows) == 0 {
			return CommandResult{ExitCode: -1, Err: errors.New("unexpected show")}
		}
		result := r.shows[0]
		r.shows = r.shows[1:]
		return result
	}
	if reflect.DeepEqual(argv, []string{"systemctl", "daemon-reload"}) {
		return r.reload
	}
	return r.invalid
}

type serverUnitFileInfo struct {
	mode      os.FileMode
	uid, gid  uint32
	directory bool
}

func (i serverUnitFileInfo) Name() string       { return "open-card-server.service" }
func (i serverUnitFileInfo) Size() int64        { return 1 }
func (i serverUnitFileInfo) Mode() os.FileMode  { return i.mode }
func (i serverUnitFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (i serverUnitFileInfo) IsDir() bool        { return i.directory }
func (i serverUnitFileInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

type serverUnitReadResult struct {
	raw  []byte
	info os.FileInfo
	err  error
}

type serverUnitReaderFixture struct {
	results []serverUnitReadResult
	paths   []string
}

func (r *serverUnitReaderFixture) Read(path string) ([]byte, os.FileInfo, error) {
	r.paths = append(r.paths, path)
	if len(r.results) == 0 {
		return nil, nil, errors.New("unexpected read")
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result.raw, result.info, result.err
}

type serverUnitDescriptorFixture struct {
	reader *strings.Reader
	info   os.FileInfo
	err    error
}

func (d *serverUnitDescriptorFixture) Read(raw []byte) (int, error) { return d.reader.Read(raw) }
func (d *serverUnitDescriptorFixture) Stat() (os.FileInfo, error)   { return d.info, d.err }
func (d *serverUnitDescriptorFixture) Close() error                 { return nil }

type serverUnitDescriptorResult struct {
	raw  []byte
	info os.FileInfo
	err  error
}

type serverUnitDescriptorOpenerFixture struct {
	results []serverUnitDescriptorResult
	opens   int
}

func (o *serverUnitDescriptorOpenerFixture) Open() (ServiceUnitDescriptor, error) {
	o.opens++
	if len(o.results) == 0 {
		return nil, errors.New("unexpected descriptor open")
	}
	result := o.results[0]
	o.results = o.results[1:]
	if result.err != nil {
		return nil, result.err
	}
	return &serverUnitDescriptorFixture{reader: strings.NewReader(string(result.raw)), info: result.info}, nil
}

func serverUnitShow(fragment, dropIns, need string) CommandResult {
	return CommandResult{Output: "FragmentPath=" + fragment + "\nDropInPaths=" + dropIns + "\nNeedDaemonReload=" + need + "\n"}
}

func serverUnitHash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("%x", digest)
}

func reloadServerController(t *testing.T, runner *serverUnitReloadRunner, path string, reader *serverUnitReaderFixture) *ServiceController {
	t.Helper()
	controller, err := TaskServiceControllerWithServerUnit(runner, func() (bool, error) { return false, nil }, nil, path, reader.Read)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func safeServerUnitInfoFixture() os.FileInfo {
	return serverUnitFileInfo{mode: 0o644, uid: 0, gid: 0}
}

func reloadServerDescriptorController(t *testing.T, runner *serverUnitReloadRunner, opener *serverUnitDescriptorOpenerFixture) *ServiceController {
	t.Helper()
	controller, err := TaskServiceControllerWithServerUnitDescriptor(runner, func() (bool, error) { return false, nil }, nil, productionServerUnitPath, opener.Open)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestReloadServerUnitUsesOnlyFixedCommandsAndVerifiesAfterReload(t *testing.T) {
	raw := []byte("[Service]\nExecStart=/opt/open-card/current/bin/open-card-server\n")
	reader := &serverUnitReaderFixture{results: []serverUnitReadResult{{raw: raw, info: safeServerUnitInfoFixture()}, {raw: raw, info: safeServerUnitInfoFixture()}}}
	runner := &serverUnitReloadRunner{shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "yes"), serverUnitShow(productionServerUnitPath, "", "no")}}
	controller := reloadServerController(t, runner, productionServerUnitPath, reader)
	if err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw)); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "show", "open-card-server.service", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "show", "open-card-server.service", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload"},
	}
	if !reflect.DeepEqual(runner.argv, want) {
		t.Fatalf("commands = %v, want %v", runner.argv, want)
	}
	if wantPaths := []string{productionServerUnitPath, productionServerUnitPath}; !reflect.DeepEqual(reader.paths, wantPaths) {
		t.Fatalf("read paths = %v, want %v", reader.paths, wantPaths)
	}
}

func TestReloadServerUnitRejectsPinnedRootReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	raw := []byte("[Service]\nExecStart=/opt/open-card/current/bin/open-card-server\n")
	if err := os.WriteFile(filepath.Join(root, systemdServerUnitName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &serverUnitReloadRunner{shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}}
	controller, err := TaskServiceControllerWithPinnedUnitRoot(runner, func() (bool, error) { return false, nil }, nil, root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw)); !errors.Is(err, ErrServiceOutcomeUnknown) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.argv) != 0 {
		t.Fatalf("unit reload ran after root replacement: %v", runner.argv)
	}
}

func TestReloadServerUnitRejectsUnsafeInputsAndSystemdState(t *testing.T) {
	raw := []byte("unit")
	valid := safeServerUnitInfoFixture()
	tests := []struct {
		name      string
		path      string
		shows     []CommandResult
		reads     []serverUnitReadResult
		expected  string
		reloadRun bool
	}{
		{name: "wrong hash", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}, reads: []serverUnitReadResult{{raw: raw, info: valid}}, expected: serverUnitHash([]byte("other"))},
		{name: "wrong mode", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}, reads: []serverUnitReadResult{{raw: raw, info: serverUnitFileInfo{mode: 0o600, uid: 0}}}, expected: serverUnitHash(raw)},
		{name: "symlink", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}, reads: []serverUnitReadResult{{raw: raw, info: serverUnitFileInfo{mode: os.ModeSymlink | 0o777, uid: 0}}}, expected: serverUnitHash(raw)},
		{name: "non root owner", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}, reads: []serverUnitReadResult{{raw: raw, info: serverUnitFileInfo{mode: 0o644, uid: 501}}}, expected: serverUnitHash(raw)},
		{name: "non root group", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}, reads: []serverUnitReadResult{{raw: raw, info: serverUnitFileInfo{mode: 0o644, uid: 0, gid: 501}}}, expected: serverUnitHash(raw)},
		{name: "wrong task path", path: "/tmp/open-card-server.service", expected: serverUnitHash(raw)},
		{name: "wrong fragment path", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow("/usr/lib/systemd/system/open-card-server.service", "", "no")}, expected: serverUnitHash(raw)},
		{name: "drop ins", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "/etc/systemd/system/open-card-server.service.d/override.conf", "no")}, expected: serverUnitHash(raw)},
		{name: "need remains yes", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "yes"), serverUnitShow(productionServerUnitPath, "", "yes")}, reads: []serverUnitReadResult{{raw: raw, info: valid}, {raw: raw, info: valid}}, expected: serverUnitHash(raw), reloadRun: true},
		{name: "unit hash changed", path: productionServerUnitPath, shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no"), serverUnitShow(productionServerUnitPath, "", "no")}, reads: []serverUnitReadResult{{raw: raw, info: valid}, {raw: []byte("changed"), info: valid}}, expected: serverUnitHash(raw), reloadRun: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &serverUnitReaderFixture{results: test.reads}
			runner := &serverUnitReloadRunner{shows: test.shows}
			controller := reloadServerController(t, runner, test.path, reader)
			if err := controller.ReloadServerUnit(context.Background(), test.expected); !errors.Is(err, ErrServiceOutcomeUnknown) {
				t.Fatalf("error = %v", err)
			}
			reloaded := false
			for _, command := range runner.argv {
				if reflect.DeepEqual(command, []string{"systemctl", "daemon-reload"}) {
					reloaded = true
				}
			}
			if reloaded != test.reloadRun {
				t.Fatalf("daemon-reload called = %t, want %t", reloaded, test.reloadRun)
			}
		})
	}
}

func TestReloadServerUnitRedactsFailuresAndIsRepeatable(t *testing.T) {
	raw := []byte("unit")
	t.Run("reload failure is redacted", func(t *testing.T) {
		reader := &serverUnitReaderFixture{results: []serverUnitReadResult{{raw: raw, info: safeServerUnitInfoFixture()}}}
		runner := &serverUnitReloadRunner{shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "yes")}, reload: CommandResult{ExitCode: -1, Output: "secret output", Err: errors.New("secret error")}}
		controller := reloadServerController(t, runner, productionServerUnitPath, reader)
		err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw))
		if !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("reload error = %v", err)
		}
	})
	t.Run("malformed show is redacted", func(t *testing.T) {
		runner := &serverUnitReloadRunner{shows: []CommandResult{{Output: "FragmentPath=/secret/path\n"}}}
		controller := reloadServerController(t, runner, productionServerUnitPath, &serverUnitReaderFixture{})
		err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw))
		if !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("show error = %v", err)
		}
	})
	t.Run("repeatable", func(t *testing.T) {
		reader := &serverUnitReaderFixture{results: []serverUnitReadResult{{raw: raw, info: safeServerUnitInfoFixture()}, {raw: raw, info: safeServerUnitInfoFixture()}, {raw: raw, info: safeServerUnitInfoFixture()}, {raw: raw, info: safeServerUnitInfoFixture()}}}
		runner := &serverUnitReloadRunner{shows: []CommandResult{
			serverUnitShow(productionServerUnitPath, "", "yes"), serverUnitShow(productionServerUnitPath, "", "no"),
			serverUnitShow(productionServerUnitPath, "", "no"), serverUnitShow(productionServerUnitPath, "", "no"),
		}}
		controller := reloadServerController(t, runner, productionServerUnitPath, reader)
		for range 2 {
			if err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw)); err != nil {
				t.Fatal(err)
			}
		}
		if got := len(runner.argv); got != 6 {
			t.Fatalf("command count = %d, want 6", got)
		}
	})
}

func TestReloadServerUnitDescriptorRejectsUnsafeMetadataAndSwap(t *testing.T) {
	raw := []byte("unit-before")
	for _, test := range []struct {
		name string
		info os.FileInfo
	}{
		{name: "symlink", info: serverUnitFileInfo{mode: os.ModeSymlink | 0o777, uid: 0, gid: 0}},
		{name: "owner", info: serverUnitFileInfo{mode: 0o644, uid: 501, gid: 0}},
		{name: "group", info: serverUnitFileInfo{mode: 0o644, uid: 0, gid: 501}},
		{name: "mode", info: serverUnitFileInfo{mode: 0o664, uid: 0, gid: 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			opener := &serverUnitDescriptorOpenerFixture{results: []serverUnitDescriptorResult{{raw: raw, info: test.info}}}
			runner := &serverUnitReloadRunner{shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "no")}}
			controller := reloadServerDescriptorController(t, runner, opener)
			if err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw)); !errors.Is(err, ErrServiceOutcomeUnknown) {
				t.Fatalf("error = %v", err)
			}
			if len(runner.argv) != 1 || opener.opens != 1 {
				t.Fatalf("unsafe descriptor advanced reload: commands=%v opens=%d", runner.argv, opener.opens)
			}
		})
	}

	t.Run("post-reload descriptor swap is detected", func(t *testing.T) {
		opener := &serverUnitDescriptorOpenerFixture{results: []serverUnitDescriptorResult{
			{raw: raw, info: safeServerUnitInfoFixture()},
			{raw: []byte("unit-after-swap"), info: safeServerUnitInfoFixture()},
		}}
		runner := &serverUnitReloadRunner{shows: []CommandResult{
			serverUnitShow(productionServerUnitPath, "", "yes"),
			serverUnitShow(productionServerUnitPath, "", "no"),
		}}
		controller := reloadServerDescriptorController(t, runner, opener)
		if err := controller.ReloadServerUnit(context.Background(), serverUnitHash(raw)); !errors.Is(err, ErrServiceOutcomeUnknown) {
			t.Fatalf("swap error = %v", err)
		}
		if opener.opens != 2 {
			t.Fatalf("descriptor opens = %d, want 2", opener.opens)
		}
	})
}

func TestSafeServerUnitDirectoryInfoRequiresSecureRootParent(t *testing.T) {
	if !safeServerUnitDirectoryInfo(serverUnitFileInfo{directory: true, mode: 0o755, uid: 0, gid: 0}) {
		t.Fatal("rejected secure root parent")
	}
	for _, info := range []os.FileInfo{
		serverUnitFileInfo{directory: true, mode: os.ModeSymlink | 0o755, uid: 0, gid: 0},
		serverUnitFileInfo{directory: true, mode: 0o775, uid: 0, gid: 0},
		serverUnitFileInfo{directory: true, mode: 0o755, uid: 501, gid: 0},
		serverUnitFileInfo{directory: true, mode: 0o755, uid: 0, gid: 501},
	} {
		if safeServerUnitDirectoryInfo(info) {
			t.Fatalf("accepted unsafe parent: %#v", info)
		}
	}
}
