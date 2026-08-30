package install

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func adapterForTest(t *testing.T, runner *fakeServiceRunner, marker func() (bool, error), probes UpgradeServiceProbeConfig) *UpgradeServiceAdapter {
	t.Helper()
	adapter, err := TaskUpgradeServiceAdapter(taskController(t, runner, marker), probes)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func adapterProbeConfig(serverURL string) UpgradeServiceProbeConfig {
	return UpgradeServiceProbeConfig{
		ServerHealth:      serverURL + "/healthz",
		ServerReady:       serverURL + "/readyz",
		EdgeHealth:        serverURL + "/healthz",
		RestoredEdgeReady: serverURL + "/config/",
	}
}

func serviceActions(argv [][]string) []string {
	actions := make([]string, 0, len(argv))
	for _, command := range argv {
		if len(command) >= 3 && command[0] == "systemctl" && command[1] != "is-active" && command[1] != "is-enabled" {
			actions = append(actions, strings.Join(command[1:], " "))
		}
	}
	return actions
}

func TestUpgradeServiceAdapterCaptureQuiesceAndGuardEdge(t *testing.T) {
	runner := newFakeServiceRunner()
	states := map[ServiceUnit]ServiceState{
		ServiceEdge:     {Active: true, Enabled: false},
		ServiceAgent:    {Active: false, Enabled: true},
		ServiceServer:   {Active: true, Enabled: true},
		ServiceCaddy:    {Active: false, Enabled: false},
		ServiceBuildKit: {Active: true, Enabled: false},
	}
	for unit, state := range states {
		runner.active[serviceName(unit)] = state.Active
		runner.enabled[serviceName(unit)] = state.Enabled
	}
	adapter := adapterForTest(t, runner, func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{})

	snapshot, err := adapter.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := ServiceSnapshotV1{Edge: unitSnapshot(states[ServiceEdge]), Agent: unitSnapshot(states[ServiceAgent]), Server: unitSnapshot(states[ServiceServer]), Caddy: unitSnapshot(states[ServiceCaddy]), BuildKit: unitSnapshot(states[ServiceBuildKit])}
	if !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("snapshot = %#v, want %#v", snapshot, want)
	}
	if err := adapter.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer} {
		if runner.active[serviceName(unit)] {
			t.Fatalf("%s remained active after quiesce", unit)
		}
	}
	if runner.active[serviceName(ServiceCaddy)] != states[ServiceCaddy].Active || runner.active[serviceName(ServiceBuildKit)] != states[ServiceBuildKit].Active {
		t.Fatal("quiesce changed a retained internal service")
	}
	if err := adapter.GuardEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, action := range serviceActions(runner.argv) {
		if strings.Contains(action, "open-card-caddy.service") || strings.Contains(action, "open-card-buildkit.service") {
			t.Fatalf("quiesce unexpectedly acted on retained service: %q", action)
		}
	}
}

func TestUpgradeServiceAdapterHealthTargetsAndSafeFailures(t *testing.T) {
	serverPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverPaths = append(serverPaths, r.URL.Path)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	edgePaths := []string{}
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		edgePaths = append(edgePaths, r.URL.Path)
		if r.URL.Path == "/healthz" || r.URL.Path == "/config/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer edge.Close()
	runner := newFakeServiceRunner()
	probes := adapterProbeConfig(server.URL)
	probes.EdgeHealth = edge.URL + "/healthz"
	probes.RestoredEdgeReady = edge.URL + "/config/"
	adapter := adapterForTest(t, runner, func() (bool, error) { return false, nil }, probes)
	if err := adapter.HealthInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.HealthEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.HealthRestoredEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	adapter.restoredInternal.Server.Active = true
	if err := adapter.HealthLegacyRestoredInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/healthz", "/readyz", "/healthz"}; !reflect.DeepEqual(serverPaths, want) {
		t.Fatalf("server health targets = %v, want %v", serverPaths, want)
	}
	if want := []string{"/healthz", "/config/"}; !reflect.DeepEqual(edgePaths, want) {
		t.Fatalf("edge health targets = %v, want %v", edgePaths, want)
	}
	if productionEdgeHealthURL != "http://127.0.0.1:18482/healthz" || strings.Contains(productionEdgeHealthURL, ":443") {
		t.Fatalf("production edge health target = %q", productionEdgeHealthURL)
	}
	if productionRestoredEdgeReadyURL != "http://127.0.0.1:2020/config/" {
		t.Fatalf("production restored edge readiness target = %q", productionRestoredEdgeReadyURL)
	}

	unsafe, err := TaskUpgradeServiceAdapter(taskController(t, runner, func() (bool, error) { return false, nil }), UpgradeServiceProbeConfig{ServerHealth: "http://127.0.0.1:8080/healthz?secret=raw-url", ServerReady: server.URL + "/readyz"})
	if err != nil {
		t.Fatal(err)
	}
	err = unsafe.HealthInternal(context.Background())
	if err == nil || strings.Contains(err.Error(), "raw-url") || strings.Contains(err.Error(), "127.0.0.1:8080") {
		t.Fatalf("health error leaked target: %v", err)
	}
	nonLoopback, err := TaskUpgradeServiceAdapter(taskController(t, runner, func() (bool, error) { return false, nil }), UpgradeServiceProbeConfig{EdgeHealth: "http://192.0.2.10:18482/healthz"})
	if err != nil {
		t.Fatal(err)
	}
	err = nonLoopback.HealthEdge(context.Background())
	if err == nil || strings.Contains(err.Error(), "192.0.2.10") {
		t.Fatalf("non-loopback edge error leaked target: %v", err)
	}
	wrongPath, err := TaskUpgradeServiceAdapter(taskController(t, runner, func() (bool, error) { return false, nil }), UpgradeServiceProbeConfig{EdgeHealth: edge.URL + "/not-health"})
	if err != nil {
		t.Fatal(err)
	}
	err = wrongPath.HealthEdge(context.Background())
	if err == nil || strings.Contains(err.Error(), "not-health") {
		t.Fatalf("wrong edge path leaked target: %v", err)
	}

	runner.fail["systemctl is-active --quiet open-card-edge.service"] = errors.New("sensitive command output")
	_, err = adapter.Capture(context.Background())
	if !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("capture error = %v", err)
	}
}

func TestUpgradeServiceAdapterRetriesStartupHealthWithinBoundedBudget(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/healthz" && requests < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	runner := newFakeServiceRunner()
	adapter := adapterForTest(t, runner, func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{ServerHealth: server.URL + "/healthz", ServerReady: server.URL + "/readyz"})
	adapter.healthTimeout = 250 * time.Millisecond
	adapter.healthInterval = time.Millisecond
	if err := adapter.HealthInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests < 4 {
		t.Fatalf("health requests=%d", requests)
	}
}

func TestUpgradeServiceAdapterSharesOneInternalHealthBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			time.Sleep(60 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	adapter := adapterForTest(t, newFakeServiceRunner(), func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{ServerHealth: server.URL + "/healthz", ServerReady: server.URL + "/readyz"})
	adapter.healthTimeout = 90 * time.Millisecond
	adapter.healthInterval = time.Millisecond
	started := time.Now()
	err := adapter.HealthInternal(context.Background())
	if elapsed := time.Since(started); !errors.Is(err, ErrServiceOutcomeUnknown) || elapsed > 140*time.Millisecond {
		t.Fatalf("elapsed=%s err=%v", elapsed, err)
	}
}

func TestUpgradeServiceAdapterHealthRetryHonorsCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	adapter := adapterForTest(t, newFakeServiceRunner(), func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{ServerHealth: server.URL + "/healthz", ServerReady: server.URL + "/readyz"})
	adapter.healthTimeout = time.Second
	adapter.healthInterval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := adapter.HealthInternal(ctx)
	if !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("cancelled health error=%v", err)
	}
}

func TestUpgradeServiceAdapterStartEdgePreservesEnabledPolicy(t *testing.T) {
	runner := newFakeServiceRunner()
	runner.enabled[serviceName(ServiceEdge)] = false
	adapter := adapterForTest(t, runner, func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{})
	if err := adapter.StartEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.enabled[serviceName(ServiceEdge)] {
		t.Fatal("committed edge start changed enabled policy")
	}
	if got, want := serviceActions(runner.argv), []string{"start open-card-edge.service"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("committed edge actions = %v, want %v", got, want)
	}
}

func TestUpgradeServiceAdapterValidatesOnlyPreparedCandidateEdgeConfig(t *testing.T) {
	validator, input, _ := edgeValidatorFixture(t)
	adapter, err := TaskUpgradeServiceAdapterWithEdgeConfigValidator(taskController(t, newFakeServiceRunner(), func() (bool, error) { return false, nil }), UpgradeServiceProbeConfig{}, validator)
	if err != nil {
		t.Fatal(err)
	}
	artifact := ArtifactV1{Path: edgeConfigPreparedArtifactPath(input.Transition.TransactionID), SHA256: input.ConfigSHA256, Size: 1}
	validation, err := adapter.ValidateEdgeConfig(context.Background(), input.Transition, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ConfigSHA256 != input.Transition.InstalledAfterSHA256 || validation.CaddySHA256 != input.Transition.CandidateCaddySHA256 || !validSHA(validation.EvidenceSHA256) {
		t.Fatalf("validation = %#v", validation)
	}
	artifact.Path = "/tmp/caller-selected.Caddyfile"
	if _, err := adapter.ValidateEdgeConfig(context.Background(), input.Transition, artifact); !errors.Is(err, ErrServiceOutcomeUnknown) {
		t.Fatalf("unsafe artifact path error = %v", err)
	}
	withoutValidator := adapterForTest(t, newFakeServiceRunner(), func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{})
	if _, err := withoutValidator.ValidateEdgeConfig(context.Background(), input.Transition, ArtifactV1{}); !errors.Is(err, ErrServiceOutcomeUnknown) {
		t.Fatalf("missing validator error = %v", err)
	}
}

func TestUpgradeServiceAdapterReloadServerUnitForwardsOnlyFixedControllerOperation(t *testing.T) {
	raw := []byte("[Service]\nExecStart=/opt/open-card/current/bin/open-card-server\n")
	reader := &serverUnitReaderFixture{results: []serverUnitReadResult{{raw: raw, info: safeServerUnitInfoFixture()}, {raw: raw, info: safeServerUnitInfoFixture()}}}
	runner := &serverUnitReloadRunner{shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "yes"), serverUnitShow(productionServerUnitPath, "", "no")}}
	controller, err := TaskServiceControllerWithServerUnit(runner, func() (bool, error) { return false, nil }, nil, productionServerUnitPath, reader.Read)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := TaskUpgradeServiceAdapter(controller, UpgradeServiceProbeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.ReloadServerUnit(context.Background(), serverUnitHash(raw)); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "show", "open-card-server.service", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "show", "open-card-server.service", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload"},
	}
	if !reflect.DeepEqual(runner.argv, want) {
		t.Fatalf("adapter reload commands = %v, want %v", runner.argv, want)
	}

	reader = &serverUnitReaderFixture{results: []serverUnitReadResult{{raw: raw, info: safeServerUnitInfoFixture()}}}
	runner = &serverUnitReloadRunner{shows: []CommandResult{serverUnitShow(productionServerUnitPath, "", "yes")}, reload: CommandResult{ExitCode: -1, Output: "secret output", Err: errors.New("secret error")}}
	controller, err = TaskServiceControllerWithServerUnit(runner, func() (bool, error) { return false, nil }, nil, productionServerUnitPath, reader.Read)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err = TaskUpgradeServiceAdapter(controller, UpgradeServiceProbeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.ReloadServerUnit(context.Background(), serverUnitHash(raw))
	if !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("adapter reload error = %v", err)
	}
}

func TestUpgradeServiceAdapterRestoreInternalPolicyOrderAndHealth(t *testing.T) {
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	runner := newFakeServiceRunner()
	for _, unit := range serviceUnits {
		runner.active[serviceName(unit)] = false
		runner.enabled[serviceName(unit)] = false
	}
	runner.active[serviceName(ServiceEdge)] = true
	runner.enabled[serviceName(ServiceEdge)] = true
	adapter := adapterForTest(t, runner, func() (bool, error) { return false, nil }, adapterProbeConfig(server.URL))
	snapshot := ServiceSnapshotV1{
		Edge:     UnitSnapshotV1{Active: false, Enabled: false},
		BuildKit: UnitSnapshotV1{Active: true, Enabled: true},
		Caddy:    UnitSnapshotV1{Active: true, Enabled: true},
		Server:   UnitSnapshotV1{Active: true, Enabled: false},
		Agent:    UnitSnapshotV1{Active: true, Enabled: true},
	}
	if err := adapter.RestoreSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	for _, unit := range restoreInternalStartOrder {
		state := snapshotUnit(snapshot, unit)
		if runner.active[serviceName(unit)] != state.Active || runner.enabled[serviceName(unit)] != state.Enabled {
			t.Fatalf("%s = active:%t enabled:%t, want active:%t enabled:%t", unit, runner.active[serviceName(unit)], runner.enabled[serviceName(unit)], state.Active, state.Enabled)
		}
	}
	if !runner.active[serviceName(ServiceEdge)] || !runner.enabled[serviceName(ServiceEdge)] {
		t.Fatal("internal restore changed edge policy")
	}
	if got, want := serviceActions(runner.argv), []string{
		"enable open-card-buildkit.service", "enable open-card-caddy.service", "enable open-card-agent.service",
		"start open-card-buildkit.service", "start open-card-caddy.service", "start open-card-server.service", "start open-card-agent.service",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("restore actions = %v, want %v", got, want)
	}
	if err := adapter.HealthRestoredInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/healthz", "/readyz"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("restored health paths = %v, want %v", paths, want)
	}

	paths = nil
	snapshot.Server.Active = false
	if err := adapter.RestoreSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := adapter.HealthRestoredInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.HealthLegacyRestoredInternal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("inactive server was probed: %v", paths)
	}
}

func TestUpgradeServiceAdapterRestoreEdgePolicyMarkerAndIdempotence(t *testing.T) {
	for _, desired := range []UnitSnapshotV1{{}, {Enabled: true}, {Active: true}, {Active: true, Enabled: true}} {
		t.Run("active="+boolText(desired.Active)+"/enabled="+boolText(desired.Enabled), func(t *testing.T) {
			runner := newFakeServiceRunner()
			runner.active[serviceName(ServiceEdge)] = !desired.Active
			runner.enabled[serviceName(ServiceEdge)] = !desired.Enabled
			adapter := adapterForTest(t, runner, func() (bool, error) { return false, nil }, UpgradeServiceProbeConfig{})
			snapshot := ServiceSnapshotV1{Edge: desired}
			if err := adapter.RestoreEdge(context.Background(), snapshot); err != nil {
				t.Fatal(err)
			}
			if runner.active[serviceName(ServiceEdge)] != desired.Active || runner.enabled[serviceName(ServiceEdge)] != desired.Enabled {
				t.Fatalf("edge = active:%t enabled:%t, want active:%t enabled:%t", runner.active[serviceName(ServiceEdge)], runner.enabled[serviceName(ServiceEdge)], desired.Active, desired.Enabled)
			}
			actions := append([]string(nil), serviceActions(runner.argv)...)
			if len(actions) != 2 || (actions[0] != "enable open-card-edge.service" && actions[0] != "disable open-card-edge.service") || (actions[1] != "start open-card-edge.service" && actions[1] != "stop open-card-edge.service") {
				t.Fatalf("edge policy actions = %v, want enablement then active policy", actions)
			}
			if err := adapter.RestoreEdge(context.Background(), snapshot); err != nil {
				t.Fatal(err)
			}
			if got := serviceActions(runner.argv); !reflect.DeepEqual(got, actions) {
				t.Fatalf("duplicate edge action: first %v, then %v", actions, got)
			}
		})
	}

	runner := newFakeServiceRunner()
	adapter := adapterForTest(t, runner, func() (bool, error) { return true, nil }, UpgradeServiceProbeConfig{})
	if err := adapter.RestoreEdge(context.Background(), ServiceSnapshotV1{Edge: UnitSnapshotV1{Active: true}}); !errors.Is(err, ErrEdgeMarkerPresent) {
		t.Fatalf("marker error = %v", err)
	}
	runner.fail["systemctl enable open-card-edge.service"] = errors.New("sensitive body")
	err := adapter.RestoreEdge(context.Background(), ServiceSnapshotV1{Edge: UnitSnapshotV1{Enabled: true}})
	if !errors.Is(err, ErrServiceOutcomeUnknown) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("edge error = %v", err)
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
