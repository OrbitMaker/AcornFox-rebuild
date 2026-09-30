package reconcile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// seedAddon records an add-on the way the API server does: pinned image and
// port from the runner spec, fresh credentials, fixed volume name.
func seedAddon(t *testing.T, s *fakeStore, app, kind string) state.AddonCredentials {
	t.Helper()
	spec, ok := runner.AddonSpecFor(kind)
	if !ok {
		t.Fatalf("no spec for %s", kind)
	}
	c, err := state.NewAddonCredentials(app, kind, runner.AddonContainerName(app, kind), spec.Port)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s.putAddon(state.Addon{App: app, Kind: kind, Image: spec.Image,
		VolumeName: runner.AddonVolumeName(app, kind), Credentials: raw, EnvVar: state.AddonEnvVar(kind)})
	return c
}

func (f *fakeRunner) requestsFor(deploymentID string) []runner.EnsureContainerRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runner.EnsureContainerRequest
	for _, r := range f.ensureReqs {
		if r.DeploymentID == deploymentID {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeRunner) hasVolume(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.volumes[name]
}

// Every add-on kind the state layer accepts must have a runner spec, and the
// other way round, or AddAddon could record something the runner refuses.
func TestAddonKindsMatchRunnerSpecs(t *testing.T) {
	for _, k := range runner.AddonKinds() {
		if !state.ValidAddonKind(k) {
			t.Fatalf("runner kind %q is not a state kind", k)
		}
	}
	for _, k := range []string{state.AddonPostgres, state.AddonMySQL, state.AddonRedis} {
		if _, ok := runner.AddonSpecFor(k); !ok {
			t.Fatalf("state kind %q has no runner spec", k)
		}
	}
}

func TestAddonStartsBeforeAppAndURLIsInjected(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("shop"))
	pg := seedAddon(t, h.store, "shop", state.AddonPostgres)
	h.store.putDeployment(queued("shop", "aaaaaaaaaaaa", 1))

	d := h.driveToTerminal(t, "shop", "aaaaaaaaaaaa", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("want live, got %s (%+v)", d.Status, d.Diagnosis)
	}

	// The add-on container was requested first, with the pinned spec.
	if len(h.runner.ensureReqs) < 2 || h.runner.ensureReqs[0].Role != runner.RoleAddon {
		t.Fatalf("add-on must be ensured before the app: %+v", h.runner.ensureReqs)
	}
	reqs := h.runner.requestsFor("addon-postgres")
	if len(reqs) != 1 {
		t.Fatalf("want one add-on ensure (then skipped while running), got %d", len(reqs))
	}
	ar := reqs[0]
	spec, _ := runner.AddonSpecFor(state.AddonPostgres)
	if ar.Image != "postgres:16-alpine" || ar.Port != 5432 || ar.MemoryMB != 512 ||
		len(ar.Mounts) != 1 || ar.Mounts[0].Volume != "af-shop-addon-postgres-data" || ar.Mounts[0].Path != spec.DataPath {
		t.Fatalf("add-on request = %+v", ar)
	}
	if ar.Env["POSTGRES_PASSWORD"] != pg.Password || ar.Env["POSTGRES_USER"] != "acornfox_shop" || ar.Env["POSTGRES_DB"] != "acornfox_shop" {
		t.Fatalf("add-on env = %v", ar.Env)
	}
	if !h.runner.hasContainer("af-shop-addon-postgres") || !h.runner.hasVolume("af-shop-addon-postgres-data") {
		t.Fatal("add-on container or volume missing")
	}

	// The app container got DATABASE_URL pointing at the add-on by name.
	app := h.runner.requestsFor("aaaaaaaaaaaa")
	if len(app) == 0 {
		t.Fatal("app container never ensured")
	}
	want := "postgresql://acornfox_shop:" + pg.Password + "@af-shop-addon-postgres:5432/acornfox_shop"
	if got := app[0].Env["DATABASE_URL"]; got != want {
		t.Fatalf("DATABASE_URL = %q, want %q", got, want)
	}
	// Converge must leave the add-on container alone.
	if h.runner.containerCount(runner.RoleAddon) != 1 || h.runner.containerCount(runner.RoleApp) != 1 {
		t.Fatalf("containers: addon=%d app=%d", h.runner.containerCount(runner.RoleAddon), h.runner.containerCount(runner.RoleApp))
	}
}

func TestAddonURLOverridesUserEnvAndIsRedacted(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("shop"))
	h.store.env["shop"] = []state.EnvVar{{App: "shop", Key: "REDIS_URL", Value: "redis://old"}, {App: "shop", Key: "MODE", Value: "prod"}}
	rc := seedAddon(t, h.store, "shop", state.AddonRedis)

	env, err := h.rec.appEnv(context.Background(), "shop", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]state.EnvVar{}
	for _, e := range env {
		if _, dup := got[e.Key]; dup {
			t.Fatalf("duplicate key %s", e.Key)
		}
		got[e.Key] = e
	}
	if got["REDIS_URL"].Value != rc.URL || !got["REDIS_URL"].Secret || got["MODE"].Value != "prod" {
		t.Fatalf("merged env = %+v", env)
	}
	if out := h.rec.redactString("connect "+rc.URL+" failed", env); strings.Contains(out, rc.Password) {
		t.Fatalf("add-on URL not redacted: %q", out)
	}
}

func TestRemovedAddonContainerIsCleanedAndVolumeKept(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("shop"))
	seedAddon(t, h.store, "shop", state.AddonRedis)
	ctx := context.Background()

	h.rec.round(ctx, "shop")
	if !h.runner.hasContainer("af-shop-addon-redis") {
		t.Fatal("add-on container not created")
	}
	// The redis entrypoint gets the password through env, never argv.
	r := h.runner.requestsFor("addon-redis")[0]
	if r.Env["REDIS_PASSWORD"] == "" || r.MemoryMB != 256 {
		t.Fatalf("redis request = %+v", r)
	}

	h.store.clearAddons("shop")
	h.rec.round(ctx, "shop")
	if h.runner.hasContainer("af-shop-addon-redis") {
		t.Fatal("orphan add-on container not removed")
	}
	if !h.runner.hasVolume("af-shop-addon-redis-data") {
		t.Fatal("data volume must be kept when an add-on is removed")
	}
}

func TestStoppedAddonIsRestarted(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("shop"))
	seedAddon(t, h.store, "shop", state.AddonMySQL)
	ctx := context.Background()

	h.rec.round(ctx, "shop")
	name := "af-shop-addon-mysql"
	_ = h.runner.StopContainer(ctx, "shop", name)
	h.runner.mu.Lock()
	delete(h.runner.containers, name) // simulate a crashed/removed container
	h.runner.mu.Unlock()

	h.rec.round(ctx, "shop")
	if !h.runner.hasContainer(name) {
		t.Fatal("missing add-on container was not recreated")
	}
	r := h.runner.requestsFor("addon-mysql")[0]
	if r.Env["MYSQL_ROOT_PASSWORD"] == "" || r.Env["MYSQL_ROOT_PASSWORD"] == r.Env["MYSQL_PASSWORD"] {
		t.Fatalf("mysql root and user passwords must be set and differ: %v", r.Env)
	}
}

// ADR-0006: an add-on that never accepts connections fails the deployment at
// stage "addon" before any app container is created, with redacted logs.
func TestAddonNotReadyFailsDeploymentAtAddonStage(t *testing.T) {
	h := newHarness(t)
	h.rec.addonPoll = time.Millisecond
	h.store.putApp(baseApp("shop"))
	pg := seedAddon(t, h.store, "shop", state.AddonPostgres)
	h.runner.addonHealth = map[string]string{"af-shop-addon-postgres": "starting"}
	h.runner.logs["af-shop-addon-postgres"] = []string{"initdb: user acornfox_shop password " + pg.Password}
	h.runner.onList = func() { h.clock.Advance(30 * time.Second) }
	h.store.putDeployment(queued("shop", "aaaaaaaaaaaa", 1))

	d := h.driveToTerminal(t, "shop", "aaaaaaaaaaaa", 5)
	if d.Status != state.StatusFailed || d.Diagnosis == nil || d.Diagnosis.Stage != "addon" || d.Diagnosis.Code != "not_ready" {
		t.Fatalf("want failed addon/not_ready, got %s %+v", d.Status, d.Diagnosis)
	}
	diag := d.Diagnosis
	if !strings.Contains(diag.Message, "postgres") || !strings.Contains(diag.Message, "应用尚未上线") {
		t.Fatalf("message = %q", diag.Message)
	}
	if !strings.Contains(diag.Hint, "af-shop-addon-postgres-data") || !strings.Contains(diag.Hint, "未被改动") {
		t.Fatalf("hint = %q", diag.Hint)
	}
	if !strings.Contains(diag.LogExcerpt, "initdb") || strings.Contains(diag.LogExcerpt, pg.Password) {
		t.Fatalf("log excerpt must come from the add-on and be redacted: %q", diag.LogExcerpt)
	}
	if len(h.runner.requestsFor("aaaaaaaaaaaa")) != 0 {
		t.Fatal("the app container must not be created while the add-on is not ready")
	}
}
func TestAddonPullFailureFailsDeployment(t *testing.T) {
	h := newHarness(t)
	h.rec.addonPoll = time.Millisecond
	h.store.putApp(baseApp("shop"))
	seedAddon(t, h.store, "shop", state.AddonMySQL)
	h.runner.ensureErr["addon-mysql"] = &runner.RemoteError{Status: 502,
		ErrorResponse: runner.ErrorResponse{Code: "pull_failed", Message: "mysql:8.4: TLS handshake timeout"}}
	h.store.putDeployment(queued("shop", "aaaaaaaaaaaa", 1))

	d := h.driveToTerminal(t, "shop", "aaaaaaaaaaaa", 5)
	if d.Status != state.StatusFailed || d.Diagnosis == nil || d.Diagnosis.Stage != "addon" || d.Diagnosis.Code != "pull_failed" {
		t.Fatalf("want failed addon/pull_failed, got %s %+v", d.Status, d.Diagnosis)
	}
	if !strings.Contains(d.Diagnosis.Message, "镜像拉取失败") || d.Diagnosis.LogExcerpt == "" {
		t.Fatalf("diagnosis = %+v", d.Diagnosis)
	}
}

// A runner outage is not an add-on failure: the deployment waits in starting
// and goes live once the runner is back (ADR-0006).
func TestRunnerOutageKeepsDeploymentStarting(t *testing.T) {
	h := newHarness(t)
	h.rec.addonPoll = time.Millisecond
	h.store.putApp(baseApp("shop"))
	seedAddon(t, h.store, "shop", state.AddonRedis)
	h.runner.ensureErr["addon-redis"] = runner.ErrUnavailable
	h.store.putDeployment(queued("shop", "aaaaaaaaaaaa", 1))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		h.rec.round(ctx, "shop")
	}
	if d := h.store.getDeployment("aaaaaaaaaaaa"); d.Status != state.StatusStarting || d.Diagnosis != nil {
		t.Fatalf("want starting without diagnosis, got %s %+v", d.Status, d.Diagnosis)
	}
	h.runner.mu.Lock()
	delete(h.runner.ensureErr, "addon-redis")
	h.runner.mu.Unlock()
	if d := h.driveToTerminal(t, "shop", "aaaaaaaaaaaa", 5); d.Status != state.StatusLive {
		t.Fatalf("want live after the runner recovers, got %s %+v", d.Status, d.Diagnosis)
	}
}

// Container-level failures are reported at once, not after the 120s budget.
func TestAddonContainerFailuresAreClassified(t *testing.T) {
	cases := []struct {
		name string
		c    runner.ContainerInfo
		code string
	}{
		{"oom", runner.ContainerInfo{Running: true, OOMKilled: true, Health: "starting", State: "running"}, "out_of_memory"},
		{"restarting", runner.ContainerInfo{Restarting: true, State: "restarting", ExitCode: 1}, "exited"},
		{"unhealthy", runner.ContainerInfo{Running: true, Health: "unhealthy", State: "running"}, "not_ready"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.rec.addonPoll = time.Millisecond
			h.runner.onList = func() { h.clock.Advance(30 * time.Second) } // guarantees termination
			h.store.putApp(baseApp("shop"))
			seedAddon(t, h.store, "shop", state.AddonPostgres)
			c := tc.c
			c.Name, c.App, c.Role, c.DeploymentID = "af-shop-addon-postgres", "shop", runner.RoleAddon, "addon-postgres"
			h.runner.containers[c.Name] = c
			h.store.putDeployment(queued("shop", "aaaaaaaaaaaa", 1))

			d := h.driveToTerminal(t, "shop", "aaaaaaaaaaaa", 5)
			if d.Status != state.StatusFailed || d.Diagnosis == nil || d.Diagnosis.Stage != "addon" || d.Diagnosis.Code != tc.code {
				t.Fatalf("want failed addon/%s, got %s %+v", tc.code, d.Status, d.Diagnosis)
			}
		})
	}
}

func TestAddonDiagnosisWhenAppIsLive(t *testing.T) {
	h := newHarness(t)
	app := baseApp("shop")
	app.CurrentDeployment = "bbbbbbbbbbbb"
	d := h.rec.addonDiagnosis(context.Background(), app, &addonProblem{kind: "redis", code: "out_of_memory"}, nil)
	if d.Stage != "addon" || d.Code != "out_of_memory" || !strings.Contains(d.Message, "原版本继续运行") ||
		!strings.Contains(d.Hint, "af-shop-addon-redis-data") {
		t.Fatalf("diagnosis = %+v", d)
	}
}
