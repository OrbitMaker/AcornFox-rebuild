package install

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeServiceRunner struct {
	active  map[string]bool
	enabled map[string]bool
	argv    [][]string
	fail    map[string]error
}

func newFakeServiceRunner() *fakeServiceRunner {
	return &fakeServiceRunner{active: map[string]bool{}, enabled: map[string]bool{}, fail: map[string]error{}}
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
		return CommandResult{ExitCode: 3}
	case "is-enabled":
		if f.enabled[unit] {
			return CommandResult{}
		}
		return CommandResult{ExitCode: 1}
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
		if r.URL.Path == "/healthz" {
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
