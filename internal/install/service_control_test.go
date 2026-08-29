package install

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
