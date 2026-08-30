package install

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func bootstrapServiceFixture(t *testing.T, marker *bool) (*BootstrapServiceAdapter, *fakeServiceRunner, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	runner := newFakeServiceRunner()
	upgrade := adapterForTest(t, runner, func() (bool, error) { return *marker, nil }, adapterProbeConfig(server.URL))
	adapter, err := TaskBootstrapServiceAdapter(upgrade)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return adapter, runner, func() {
		_ = adapter.Close()
		server.Close()
	}
}

func TestBootstrapServiceAdapterEnablesStartsAndProvesFixedUnits(t *testing.T) {
	marker := true
	adapter, runner, cleanup := bootstrapServiceFixture(t, &marker)
	defer cleanup()
	if err := adapter.GuardEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnableInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.StartInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.HealthInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	internal, err := adapter.Capture(context.Background())
	if err != nil || !bootstrapInternalSnapshot(internal) {
		t.Fatalf("internal=%+v err=%v", internal, err)
	}
	if err := adapter.StartEdge(context.Background()); !errors.Is(err, ErrEdgeMarkerPresent) {
		t.Fatalf("marker did not block edge: %v", err)
	}
	marker = false
	if err := adapter.EnableEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.StartEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.HealthEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	final, err := adapter.Capture(context.Background())
	if err != nil || !bootstrapFinalSnapshot(final) {
		t.Fatalf("final=%+v err=%v", final, err)
	}
	wantActions := []string{
		"enable open-card-buildkit.service",
		"enable open-card-caddy.service",
		"enable open-card-server.service",
		"enable open-card-agent.service",
		"start open-card-buildkit.service",
		"start open-card-caddy.service",
		"start open-card-server.service",
		"start open-card-agent.service",
		"enable open-card-edge.service",
		"start open-card-edge.service",
	}
	if len(runner.argv) == 0 || !reflect.DeepEqual(runner.argv[0], []string{"systemctl", "is-active", "--quiet", "open-card-edge.service"}) {
		t.Fatalf("guard did not begin with fixed edge state query: %v", runner.argv)
	}
	daemonReloads := 0
	for _, command := range runner.argv {
		if reflect.DeepEqual(command, []string{"systemctl", "daemon-reload"}) {
			daemonReloads++
		}
	}
	if daemonReloads != 1 {
		t.Fatalf("daemon reload count=%d", daemonReloads)
	}
	if got := serviceActions(runner.argv); !reflect.DeepEqual(got, wantActions) {
		t.Fatalf("actions=%v", got)
	}
	if err := adapter.EnableInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, action := range serviceActions(runner.argv)[len(wantActions):] {
		if strings.HasPrefix(action, "enable ") {
			t.Fatalf("idempotent enable repeated mutation %q", action)
		}
	}
}

func TestBootstrapServiceAdapterFailsClosedWithoutLeakingRunnerOutput(t *testing.T) {
	marker := true
	adapter, runner, cleanup := bootstrapServiceFixture(t, &marker)
	defer cleanup()
	runner.fail["systemctl daemon-reload"] = errors.New("password=service-secret")
	if err := adapter.EnableInternal(context.Background()); !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "service-secret") {
		t.Fatalf("daemon reload error=%v", err)
	}
	delete(runner.fail, "systemctl daemon-reload")
	runner.fail["systemctl enable open-card-buildkit.service"] = errors.New("token=service-secret")
	if err := adapter.EnableInternal(context.Background()); !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "service-secret") {
		t.Fatalf("enable error=%v", err)
	}
}

func TestBootstrapServiceAdapterHasNoCallerSelectedUnitSurface(t *testing.T) {
	raw, err := os.ReadFile("bootstrap_service.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"unit string", "exec.command", "/bin/sh", "projectlegacy", "drop database"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("bootstrap service exposes forbidden surface %q", forbidden)
		}
	}
}
