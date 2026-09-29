package reconcile

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/caddyroute"
	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// ---------------------------------------------------------------------------
// fake clock
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------------------------------------------------------------------------
// fake Store
// ---------------------------------------------------------------------------

type fakeStore struct {
	mu          sync.Mutex
	apps        map[string]*state.App
	deployments map[string]*state.Deployment
	env         map[string][]state.EnvVar
	volumes     map[string][]state.Volume
	events      []state.Event
	domains     map[string]*state.Domain // key: app+"/"+name
}

func newStore() *fakeStore {
	return &fakeStore{
		apps:        map[string]*state.App{},
		deployments: map[string]*state.Deployment{},
		env:         map[string][]state.EnvVar{},
		volumes:     map[string][]state.Volume{},
		domains:     map[string]*state.Domain{},
	}
}

func (s *fakeStore) GetApp(_ context.Context, name string) (state.App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[name]
	if !ok {
		return state.App{}, state.ErrNotFound
	}
	return *a, nil
}

func (s *fakeStore) ListApps(_ context.Context) ([]state.App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]state.App, 0, len(s.apps))
	for _, a := range s.apps {
		out = append(out, *a)
	}
	return out, nil
}

func (s *fakeStore) SetCurrentDeployment(_ context.Context, app, deploymentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[app]
	if !ok {
		return state.ErrNotFound
	}
	// previous live -> retired
	if a.CurrentDeployment != "" {
		if prev, ok := s.deployments[a.CurrentDeployment]; ok && prev.Status == state.StatusLive {
			prev.Status = state.StatusRetired
		}
	}
	d, ok := s.deployments[deploymentID]
	if !ok {
		return state.ErrNotFound
	}
	d.Status = state.StatusLive
	a.CurrentDeployment = deploymentID
	return nil
}

func (s *fakeStore) PendingDeployments(_ context.Context, app string) ([]state.Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []state.Deployment
	for _, d := range s.deployments {
		if d.App == app && state.IsPending(d.Status) {
			out = append(out, *d)
		}
	}
	// oldest first by Seq
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Seq < out[i].Seq {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

func (s *fakeStore) GetDeployment(_ context.Context, id string) (state.Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deployments[id]
	if !ok {
		return state.Deployment{}, state.ErrNotFound
	}
	return *d, nil
}

func (s *fakeStore) UpdateDeployment(_ context.Context, id string, fn func(*state.Deployment) error) (state.Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deployments[id]
	if !ok {
		return state.Deployment{}, state.ErrNotFound
	}
	cp := *d
	if err := fn(&cp); err != nil {
		return state.Deployment{}, err
	}
	*d = cp
	return *d, nil
}

func (s *fakeStore) KeptImageDeployments(_ context.Context, app string) ([]state.Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// live + newest KeepVersions retired with ImageID
	var live *state.Deployment
	var retired []state.Deployment
	for _, d := range s.deployments {
		if d.App != app {
			continue
		}
		if d.Status == state.StatusLive {
			cp := *d
			live = &cp
		} else if d.Status == state.StatusRetired && d.ImageID != "" {
			retired = append(retired, *d)
		}
	}
	// newest first by Seq
	for i := 0; i < len(retired); i++ {
		for j := i + 1; j < len(retired); j++ {
			if retired[j].Seq > retired[i].Seq {
				retired[i], retired[j] = retired[j], retired[i]
			}
		}
	}
	if len(retired) > state.KeepVersions {
		retired = retired[:state.KeepVersions]
	}
	var out []state.Deployment
	if live != nil {
		out = append(out, *live)
	}
	out = append(out, retired...)
	return out, nil
}

func (s *fakeStore) AddVolume(_ context.Context, app, path string, auto bool) (state.Volume, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.volumes[app] {
		if v.Path == path {
			return v, false, nil
		}
	}
	n := len(s.volumes[app]) + 1
	v := state.Volume{App: app, Path: path, VolumeName: fmt.Sprintf("af-%s-%d", app, n), Auto: auto}
	s.volumes[app] = append(s.volumes[app], v)
	return v, true, nil
}

func (s *fakeStore) ListEnv(_ context.Context, app string) ([]state.EnvVar, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]state.EnvVar(nil), s.env[app]...), nil
}

func (s *fakeStore) ListVolumes(_ context.Context, app string) ([]state.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]state.Volume(nil), s.volumes[app]...), nil
}

func (s *fakeStore) AddEvent(_ context.Context, e state.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = int64(len(s.events) + 1)
	s.events = append(s.events, e)
	return nil
}

func (s *fakeStore) ListDomains(_ context.Context, app string) ([]state.Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []state.Domain
	for _, d := range s.domains {
		if app == "" || d.App == app {
			out = append(out, *d)
		}
	}
	// deterministic order by name
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Name < out[i].Name {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

func (s *fakeStore) SetDomainStatus(_ context.Context, app, name, status string, diag *state.Diagnosis) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.domains[app+"/"+name]
	if !ok {
		return state.ErrNotFound
	}
	d.Status = status
	d.Diagnosis = diag
	now := time.Unix(1_700_000_000, 0)
	d.CheckedAt = &now
	return nil
}

// helpers
func (s *fakeStore) putApp(a state.App) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := a
	s.apps[a.Name] = &cp
}
func (s *fakeStore) putDeployment(d state.Deployment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := d
	s.deployments[d.ID] = &cp
}
func (s *fakeStore) getDeployment(id string) state.Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.deployments[id]
}
func (s *fakeStore) getApp(name string) state.App {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.apps[name]
}
func (s *fakeStore) putDomain(d state.Domain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := d
	s.domains[d.App+"/"+d.Name] = &cp
}
func (s *fakeStore) getDomain(app, name string) state.Domain {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.domains[app+"/"+name]
}
func (s *fakeStore) eventMessages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, e.Message)
	}
	return out
}

// ---------------------------------------------------------------------------
// fake runner.API
// ---------------------------------------------------------------------------

type fakeRunner struct {
	mu sync.Mutex

	pingErr error

	// containers by name
	containers map[string]runner.ContainerInfo
	// images by ID
	images map[string]runner.ImageInfo
	// volumes by name
	volumes map[string]bool

	// build behaviour keyed by deployment ID; default: success creating image
	buildResp    map[string]runner.BuildResponse
	buildErr     map[string]error
	imageVolumes []string
	exposedPorts []int

	// pull behaviour keyed by deployment ID; default: success creating image
	pullResp map[string]runner.PullResponse
	pullErr  map[string]error
	pullReqs []runner.PullRequest

	// health simulation: name -> ContainerInfo overrides during checking
	logs map[string][]string
	diff map[string][]string

	// build concurrency tracking (semaphore invariant)
	buildActive int32
	buildMax    int32
	buildCount  int32

	// which deployments EnsureContainer should fail for
	ensureErr map[string]error
}

func newRunner() *fakeRunner {
	return &fakeRunner{
		containers: map[string]runner.ContainerInfo{},
		images:     map[string]runner.ImageInfo{},
		volumes:    map[string]bool{},
		buildResp:  map[string]runner.BuildResponse{},
		buildErr:   map[string]error{},
		pullResp:   map[string]runner.PullResponse{},
		pullErr:    map[string]error{},
		logs:       map[string][]string{},
		diff:       map[string][]string{},
		ensureErr:  map[string]error{},
	}
}

func (f *fakeRunner) Ping(_ context.Context) (runner.PingResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pingErr != nil {
		return runner.PingResponse{}, f.pingErr
	}
	return runner.PingResponse{ServerVersion: "test", DockerAPIVersion: "1.56"}, nil
}

func (f *fakeRunner) Build(_ context.Context, req runner.BuildRequest) (runner.BuildResponse, error) {
	// track concurrency
	n := atomic.AddInt32(&f.buildActive, 1)
	for {
		old := atomic.LoadInt32(&f.buildMax)
		if n <= old || atomic.CompareAndSwapInt32(&f.buildMax, old, n) {
			break
		}
	}
	atomic.AddInt32(&f.buildCount, 1)
	time.Sleep(2 * time.Millisecond) // widen the window for the race detector
	defer atomic.AddInt32(&f.buildActive, -1)

	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.buildErr[req.DeploymentID]; err != nil {
		return runner.BuildResponse{}, err
	}
	if resp, ok := f.buildResp[req.DeploymentID]; ok {
		if resp.OK && resp.Image == nil {
			img := f.makeImageLocked(req.App, req.DeploymentID)
			resp.Image = &img
		}
		return resp, nil
	}
	// default success
	img := f.makeImageLocked(req.App, req.DeploymentID)
	return runner.BuildResponse{OK: true, Image: &img}, nil
}

func (f *fakeRunner) makeImageLocked(app, id string) runner.ImageInfo {
	imgID := "sha256:" + app + "-" + id
	info := runner.ImageInfo{
		ID:           imgID,
		Tags:         []string{runner.ImageTag(app, id)},
		App:          app,
		DeploymentID: id,
		ExposedPorts: f.exposedPorts,
		Volumes:      f.imageVolumes,
	}
	f.images[imgID] = info
	return info
}

func (f *fakeRunner) PullImage(_ context.Context, app, deploymentID, ref string) (runner.PullResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pullReqs = append(f.pullReqs, runner.PullRequest{App: app, DeploymentID: deploymentID, Ref: ref})
	if err := f.pullErr[deploymentID]; err != nil {
		return runner.PullResponse{}, err
	}
	if resp, ok := f.pullResp[deploymentID]; ok {
		if resp.OK && resp.Image == nil {
			img := f.makeImageLocked(app, deploymentID)
			resp.Image = &img
		}
		return resp, nil
	}
	// default success
	img := f.makeImageLocked(app, deploymentID)
	return runner.PullResponse{OK: true, Image: &img}, nil
}

func (f *fakeRunner) ImageInspect(_ context.Context, app, ref string) (runner.ImageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if info, ok := f.images[ref]; ok {
		return info, nil
	}
	// also match by tag
	for _, info := range f.images {
		for _, t := range info.Tags {
			if t == ref {
				return info, nil
			}
		}
	}
	return runner.ImageInfo{}, runner.ErrNotFound
}

func (f *fakeRunner) ListImages(_ context.Context, app string) ([]runner.ImageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runner.ImageInfo
	for _, info := range f.images {
		if info.App == app {
			out = append(out, info)
		}
	}
	return out, nil
}

func (f *fakeRunner) RemoveImage(_ context.Context, app, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.images, ref)
	return nil
}

func (f *fakeRunner) EnsureContainer(_ context.Context, req runner.EnsureContainerRequest) (runner.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := runner.ContainerName(req.App, req.DeploymentID)
	if err := f.ensureErr[req.DeploymentID]; err != nil {
		return runner.ContainerInfo{}, err
	}
	if c, ok := f.containers[name]; ok {
		return c, nil
	}
	c := runner.ContainerInfo{
		ID:           "c-" + name,
		Name:         name,
		App:          req.App,
		DeploymentID: req.DeploymentID,
		Role:         runner.RoleApp,
		Image:        req.Image,
		State:        "running",
		Running:      true,
		HostPort:     40000 + len(f.containers),
	}
	f.containers[name] = c
	return c, nil
}

func (f *fakeRunner) ListContainers(_ context.Context, app string) ([]runner.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runner.ContainerInfo
	for _, c := range f.containers {
		if app == "" || c.App == app {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeRunner) StopContainer(_ context.Context, app, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.containers[name]; ok {
		c.Running = false
		c.State = "exited"
		f.containers[name] = c
	}
	return nil
}

func (f *fakeRunner) StartContainer(_ context.Context, app, name string) (runner.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.containers[name]
	if !ok {
		return runner.ContainerInfo{}, runner.ErrNotFound
	}
	c.Running = true
	c.State = "running"
	f.containers[name] = c
	return c, nil
}

func (f *fakeRunner) RemoveContainer(_ context.Context, app, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.containers, name)
	return nil
}

func (f *fakeRunner) Logs(_ context.Context, app, name string, tail int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logs[name], nil
}

func (f *fakeRunner) Diff(_ context.Context, app, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.diff[name], nil
}

func (f *fakeRunner) EnsureVolume(_ context.Context, app, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.volumes[name] = true
	return nil
}

func (f *fakeRunner) ListVolumes(_ context.Context, app string) ([]runner.VolumeInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runner.VolumeInfo
	for n := range f.volumes {
		out = append(out, runner.VolumeInfo{Name: n, App: app})
	}
	return out, nil
}

// helpers to mutate container state for health simulation
func (f *fakeRunner) setContainer(name string, mut func(*runner.ContainerInfo)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.containers[name]
	mut(&c)
	f.containers[name] = c
}
func (f *fakeRunner) containerCount(role string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.containers {
		if role == "" || c.Role == role {
			n++
		}
	}
	return n
}
func (f *fakeRunner) hasContainer(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.containers[name]
	return ok
}

// ---------------------------------------------------------------------------
// fake Router
// ---------------------------------------------------------------------------

type fakeRouter struct {
	mu      sync.Mutex
	routes  map[string]caddyroute.Route
	syncErr error
	syncs   int
}

func newRouter() *fakeRouter { return &fakeRouter{routes: map[string]caddyroute.Route{}} }

func (r *fakeRouter) Sync(_ context.Context, routes []caddyroute.Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.syncErr != nil {
		return r.syncErr
	}
	r.syncs++
	r.routes = map[string]caddyroute.Route{}
	for _, rt := range routes {
		r.routes[rt.App] = rt
	}
	return nil
}

func (r *fakeRouter) Current(_ context.Context) (map[string]caddyroute.Route, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]caddyroute.Route{}
	for k, v := range r.routes {
		out[k] = v
	}
	return out, nil
}
func (r *fakeRouter) hasRoute(app string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.routes[app]
	return ok
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type harness struct {
	store  *fakeStore
	runner *fakeRunner
	router *fakeRouter
	clock  *fakeClock
	rec    *Reconciler
	probe  func(ctx context.Context, hostport, path string) error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		store:  newStore(),
		runner: newRunner(),
		router: newRouter(),
		clock:  newClock(),
	}
	h.probe = func(context.Context, string, string) error { return nil } // healthy by default
	h.rec = New(Config{
		Store:         h.store,
		Runner:        h.runner,
		Router:        h.router,
		Probe:         func(ctx context.Context, hp, p string) error { return h.probe(ctx, hp, p) },
		UploadDir:     t.TempDir(),
		PublicHost:    "192.168.0.1",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tick:          time.Hour,
		HealthTimeout: 3 * time.Second,
		Now:           h.clock.Now,
	})
	return h
}

// driveToTerminal runs rounds until the deployment reaches live/failed/superseded
// or maxRounds is hit. Returns the final deployment.
func (h *harness) driveToTerminal(t *testing.T, app, id string, maxRounds int) state.Deployment {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < maxRounds; i++ {
		h.rec.round(ctx, app)
		d := h.store.getDeployment(id)
		if !state.IsPending(d.Status) {
			return d
		}
	}
	return h.store.getDeployment(id)
}

func baseApp(name string) state.App {
	return state.App{
		Name:       name,
		Desired:    state.DesiredRunning,
		HealthPath: "/",
		PublicPort: 18810,
		MemoryMB:   512,
		CPUMilli:   1000,
	}
}

func queued(app, id string, seq int) state.Deployment {
	return state.Deployment{
		ID:         id,
		App:        app,
		Seq:        seq,
		SourceKind: state.SourceUpload,
		SourceRef:  "/nonexistent/" + id + ".tar.gz",
		Status:     state.StatusQueued,
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestHappyPathToLive(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(queued("web", "aaaaaaaaaaaa", 1))

	d := h.driveToTerminal(t, "web", "aaaaaaaaaaaa", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("want live, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
	if !h.router.hasRoute("web") {
		t.Fatalf("expected route for web")
	}
	if h.runner.containerCount(runner.RoleApp) != 1 {
		t.Fatalf("want 1 app container, got %d", h.runner.containerCount(runner.RoleApp))
	}
	app := h.store.getApp("web")
	if app.CurrentDeployment != "aaaaaaaaaaaa" {
		t.Fatalf("current deployment not set: %q", app.CurrentDeployment)
	}
}

// A single kick must carry a deployment all the way to live; waiting for the
// periodic tick between stages made real deploys take a minute or more.
func TestSingleRoundReachesLive(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(queued("web", "aaaaaaaaaaaa", 1))
	d := h.driveToTerminal(t, "web", "aaaaaaaaaaaa", 1)
	if d.Status != state.StatusLive {
		t.Fatalf("want live after one round, got %s", d.Status)
	}
}

func TestBuildFailureKeepsPreviousLive(t *testing.T) {
	h := newHarness(t)
	app := baseApp("web")
	app.CurrentDeployment = "old000000001"
	h.store.putApp(app)
	// old live deployment + its container
	h.store.putDeployment(state.Deployment{ID: "old000000001", App: "web", Seq: 1, SourceKind: state.SourceUpload, Status: state.StatusLive, ImageID: "sha256:web-old000000001"})
	h.runner.images["sha256:web-old000000001"] = runner.ImageInfo{ID: "sha256:web-old000000001", App: "web", DeploymentID: "old000000001", ExposedPorts: []int{8080}}
	h.runner.containers[runner.ContainerName("web", "old000000001")] = runner.ContainerInfo{
		ID: "c-old", Name: runner.ContainerName("web", "old000000001"), App: "web", DeploymentID: "old000000001",
		Role: runner.RoleApp, State: "running", Running: true, HostPort: 41000,
	}

	// new deployment that fails to build
	h.store.putDeployment(queued("web", "new000000002", 2))
	h.runner.buildResp["new000000002"] = runner.BuildResponse{OK: false, Failure: &runner.Failure{Stage: "build", Code: "build_failed", Message: "boom"}}

	d := h.driveToTerminal(t, "web", "new000000002", 10)
	if d.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", d.Status)
	}
	// old still live and its container present
	old := h.store.getDeployment("old000000001")
	if old.Status != state.StatusLive {
		t.Fatalf("old should stay live, got %s", old.Status)
	}
	if !h.runner.hasContainer(runner.ContainerName("web", "old000000001")) {
		t.Fatalf("old live container removed")
	}
	if h.runner.hasContainer(runner.ContainerName("web", "new000000002")) {
		t.Fatalf("failed container should not exist")
	}
}

func TestSupersedeOfThreeBuildsOnlyLast(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(queued("web", "d00000000001", 1))
	h.store.putDeployment(queued("web", "d00000000002", 2))
	h.store.putDeployment(queued("web", "d00000000003", 3))

	d := h.driveToTerminal(t, "web", "d00000000003", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("want newest live, got %s", d.Status)
	}
	if s := h.store.getDeployment("d00000000001").Status; s != state.StatusSuperseded {
		t.Fatalf("d1 want superseded, got %s", s)
	}
	if s := h.store.getDeployment("d00000000002").Status; s != state.StatusSuperseded {
		t.Fatalf("d2 want superseded, got %s", s)
	}
	if got := atomic.LoadInt32(&h.runner.buildCount); got != 1 {
		t.Fatalf("want exactly 1 build, got %d", got)
	}
}

func TestCrashResumeFromEachStatus(t *testing.T) {
	statuses := []string{
		state.StatusQueued,
		state.StatusBuilding,
		state.StatusStarting,
		state.StatusChecking,
		state.StatusRouting,
	}
	for _, startStatus := range statuses {
		t.Run(startStatus, func(t *testing.T) {
			h := newHarness(t)
			h.store.putApp(baseApp("web"))
			d := queued("web", "resume000001", 1)
			d.Status = startStatus
			// construct mid-way state
			switch startStatus {
			case state.StatusBuilding:
				d.Attempts = 1
			case state.StatusStarting:
				d.ImageID = "sha256:web-resume000001"
				h.runner.images["sha256:web-resume000001"] = runner.ImageInfo{ID: "sha256:web-resume000001", App: "web", DeploymentID: "resume000001", ExposedPorts: []int{8080}}
			case state.StatusChecking:
				d.ImageID = "sha256:web-resume000001"
				name := runner.ContainerName("web", "resume000001")
				h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "resume000001", Role: runner.RoleApp, State: "running", Running: true, HostPort: 42000}
			case state.StatusRouting:
				d.ImageID = "sha256:web-resume000001"
				name := runner.ContainerName("web", "resume000001")
				h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "resume000001", Role: runner.RoleApp, State: "running", Running: true, HostPort: 42000}
			}
			h.store.putDeployment(d)

			final := h.driveToTerminal(t, "web", "resume000001", 12)
			if final.Status != state.StatusLive {
				t.Fatalf("resume from %s: want live, got %s (diag=%+v)", startStatus, final.Status, final.Diagnosis)
			}
			if h.runner.containerCount(runner.RoleApp) != 1 {
				t.Fatalf("resume from %s: want exactly 1 container, got %d", startStatus, h.runner.containerCount(runner.RoleApp))
			}
			if !h.router.hasRoute("web") {
				t.Fatalf("resume from %s: expected route", startStatus)
			}
		})
	}
}

func TestBuildingWithMaxAttemptsFailsInterrupted(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	d := queued("web", "interrupt0001", 1)
	d.Status = state.StatusBuilding
	d.Attempts = state.MaxBuildAttempts
	h.store.putDeployment(d)

	final := h.driveToTerminal(t, "web", "interrupt0001", 5)
	if final.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", final.Status)
	}
	if final.Diagnosis == nil || final.Diagnosis.Code != "interrupted" {
		t.Fatalf("want interrupted diagnosis, got %+v", final.Diagnosis)
	}
	if h.runner.containerCount(runner.RoleApp) != 0 {
		t.Fatalf("no container expected")
	}
}

func TestRestartLoopContainerExited(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	d := queued("web", "restart00001", 1)
	d.Status = state.StatusChecking
	d.ImageID = "sha256:web-restart00001"
	name := runner.ContainerName("web", "restart00001")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "restart00001", Role: runner.RoleApp, State: "restarting", Restarting: true, RestartCount: 3, HostPort: 42000}
	h.store.putDeployment(d)

	final := h.driveToTerminal(t, "web", "restart00001", 5)
	if final.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", final.Status)
	}
	if final.Diagnosis.Code != "container_exited" {
		t.Fatalf("want container_exited, got %s", final.Diagnosis.Code)
	}
	if h.runner.hasContainer(name) {
		t.Fatalf("container should be removed")
	}
}

func TestOOMKilled(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	d := queued("web", "oom000000001", 1)
	d.Status = state.StatusChecking
	d.ImageID = "sha256:web-oom000000001"
	name := runner.ContainerName("web", "oom000000001")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "oom000000001", Role: runner.RoleApp, State: "exited", OOMKilled: true, RestartCount: 1, HostPort: 42000}
	h.store.putDeployment(d)

	final := h.driveToTerminal(t, "web", "oom000000001", 5)
	if final.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", final.Status)
	}
	if final.Diagnosis.Code != "out_of_memory" {
		t.Fatalf("want out_of_memory, got %s", final.Diagnosis.Code)
	}
}

func TestStoppedAppHasNoRoute(t *testing.T) {
	h := newHarness(t)
	app := baseApp("web")
	app.Desired = state.DesiredStopped
	app.CurrentDeployment = "live00000001"
	h.store.putApp(app)
	h.store.putDeployment(state.Deployment{ID: "live00000001", App: "web", Seq: 1, SourceKind: state.SourceUpload, Status: state.StatusLive, ImageID: "sha256:web-live00000001"})
	name := runner.ContainerName("web", "live00000001")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "live00000001", Role: runner.RoleApp, State: "running", Running: true, HostPort: 43000}

	h.rec.round(context.Background(), "web")

	if h.router.hasRoute("web") {
		t.Fatalf("stopped app must not have a route")
	}
	// container should be stopped
	c := h.runner.containers[name]
	if c.Running {
		t.Fatalf("stopped app container should be stopped")
	}
}

func TestOrphanCleanup(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	// orphan container belongs to unknown app
	orphan := runner.ContainerName("ghost", "orphan000001")
	h.runner.containers[orphan] = runner.ContainerInfo{ID: "o", Name: orphan, App: "ghost", DeploymentID: "orphan000001", Role: runner.RoleApp, State: "running", Running: true}

	h.rec.globalGC(context.Background(), []string{"web"})

	if h.runner.hasContainer(orphan) {
		t.Fatalf("orphan container should be removed")
	}
}

// A runner that drops mid-build (killed, restarted) is a transient failure and
// must not use up the crash-retry budget: after several blips the build still
// completes instead of failing as build/interrupted.
func TestTransientBuildErrorsDoNotCountAsInterruptions(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(queued("web", "blip00000001", 1))
	h.runner.mu.Lock()
	h.runner.buildErr["blip00000001"] = runner.ErrUnavailable
	h.runner.mu.Unlock()
	for i := 0; i < 3; i++ {
		h.rec.round(context.Background(), "web")
		d := h.store.getDeployment("blip00000001")
		if d.Status != state.StatusBuilding {
			t.Fatalf("round %d: want building, got %s (diag=%+v)", i, d.Status, d.Diagnosis)
		}
	}
	h.runner.mu.Lock()
	delete(h.runner.buildErr, "blip00000001")
	h.runner.mu.Unlock()
	if d := h.driveToTerminal(t, "web", "blip00000001", 3); d.Status != state.StatusLive {
		t.Fatalf("want live after runner recovers, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
}

func TestRunnerUnavailableLeavesPendingThenContinues(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(queued("web", "unavail00001", 1))

	// runner down
	h.runner.mu.Lock()
	h.runner.pingErr = runner.ErrUnavailable
	h.runner.mu.Unlock()

	h.rec.round(context.Background(), "web")
	if s := h.store.getDeployment("unavail00001").Status; s != state.StatusQueued {
		t.Fatalf("want still queued while runner down, got %s", s)
	}
	// one event only; a second immediate round should not add a duplicate
	h.rec.round(context.Background(), "web")
	n := 0
	for _, m := range h.store.eventMessages() {
		if m == "runner 暂不可用，稍后重试" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 runner/unavailable event within throttle, got %d", n)
	}

	// runner recovers
	h.runner.mu.Lock()
	h.runner.pingErr = nil
	h.runner.mu.Unlock()

	final := h.driveToTerminal(t, "web", "unavail00001", 10)
	if final.Status != state.StatusLive {
		t.Fatalf("want live after recovery, got %s", final.Status)
	}
}

func TestImageGCKeepsKeptVersions(t *testing.T) {
	h := newHarness(t)
	app := baseApp("web")
	app.CurrentDeployment = "live00000005"
	h.store.putApp(app)

	// live + 3 retired (kept) + 1 old retired (should be GC'd)
	mk := func(id string, seq int, status string) {
		imgID := "sha256:web-" + id
		h.store.putDeployment(state.Deployment{ID: id, App: "web", Seq: seq, SourceKind: state.SourceUpload, Status: status, ImageID: imgID})
		h.runner.images[imgID] = runner.ImageInfo{ID: imgID, App: "web", DeploymentID: id}
	}
	mk("live00000005", 5, state.StatusLive)
	mk("ret000000004", 4, state.StatusRetired)
	mk("ret000000003", 3, state.StatusRetired)
	mk("ret000000002", 2, state.StatusRetired)
	mk("ret000000001", 1, state.StatusRetired) // oldest -> should be removed
	// live container present so converge doesn't try to recreate
	name := runner.ContainerName("web", "live00000005")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "live00000005", Role: runner.RoleApp, State: "running", Running: true, HostPort: 44000}

	h.rec.appGC(context.Background(), "web", nil)

	if _, ok := h.runner.images["sha256:web-ret000000001"]; ok {
		t.Fatalf("oldest image should be GC'd")
	}
	for _, keep := range []string{"live00000005", "ret000000004", "ret000000003", "ret000000002"} {
		if _, ok := h.runner.images["sha256:web-"+keep]; !ok {
			t.Fatalf("kept image %s was removed", keep)
		}
	}
}

func TestBuildSemaphoreNeverExceedsOne(t *testing.T) {
	h := newHarness(t)
	// several apps, each with a queued deployment, kicked concurrently via Run
	apps := []string{"appa", "appb", "appc", "appd"}
	for i, a := range apps {
		app := baseApp(a)
		app.PublicPort = 18810 + i
		h.store.putApp(app)
		id := fmt.Sprintf("sem00000000%d", i)
		h.store.putDeployment(queued(a, id, 1))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// run each app's worker loop concurrently by kicking; drive via goroutines
	var wg sync.WaitGroup
	for _, a := range apps {
		wg.Add(1)
		go func(app string) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				h.rec.round(ctx, app)
			}
		}(a)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&h.runner.buildMax); got > 1 {
		t.Fatalf("build semaphore exceeded 1: max concurrent = %d", got)
	}
	for i, a := range apps {
		id := fmt.Sprintf("sem00000000%d", i)
		if s := h.store.getDeployment(id).Status; s != state.StatusLive {
			t.Fatalf("app %s deployment want live, got %s", a, s)
		}
	}
}

func TestSecretsRedactedInDiagnosis(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.env["web"] = []state.EnvVar{
		{App: "web", Key: "DB_PASSWORD", Value: "supersecret", Secret: true},
		{App: "web", Key: "PUBLIC", Value: "plainvalue", Secret: false},
	}
	// checking with a failing container whose logs contain the secret
	d := queued("web", "secret000001", 1)
	d.Status = state.StatusChecking
	d.ImageID = "sha256:web-secret000001"
	name := runner.ContainerName("web", "secret000001")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "secret000001", Role: runner.RoleApp, State: "exited", RestartCount: 1, HostPort: 42000}
	h.runner.logs[name] = []string{"connecting with password supersecret", "and public plainvalue"}
	h.store.putDeployment(d)

	final := h.driveToTerminal(t, "web", "secret000001", 5)
	if final.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", final.Status)
	}
	if final.Diagnosis == nil {
		t.Fatalf("want diagnosis")
	}
	if strings.Contains(final.Diagnosis.LogExcerpt, "supersecret") {
		t.Fatalf("secret not redacted: %q", final.Diagnosis.LogExcerpt)
	}
	if !strings.Contains(final.Diagnosis.LogExcerpt, redactMask) {
		t.Fatalf("expected redaction mask in log excerpt: %q", final.Diagnosis.LogExcerpt)
	}
	if !strings.Contains(final.Diagnosis.LogExcerpt, "plainvalue") {
		t.Fatalf("non-secret value should remain: %q", final.Diagnosis.LogExcerpt)
	}
}

func TestUnpersistedDatabaseWarning(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	d := queued("web", "warn00000001", 1)
	d.Status = state.StatusChecking
	d.ImageID = "sha256:web-warn00000001"
	name := runner.ContainerName("web", "warn00000001")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "warn00000001", Role: runner.RoleApp, State: "running", Running: true, HostPort: 42000}
	h.runner.diff[name] = []string{"/app/data.db"}
	h.store.putDeployment(d)

	final := h.driveToTerminal(t, "web", "warn00000001", 6)
	if final.Status != state.StatusLive {
		t.Fatalf("warning must not block go-live, got %s", final.Status)
	}
	if len(final.Warnings) == 0 || final.Warnings[0].Code != "unpersisted_database" {
		t.Fatalf("want unpersisted_database warning, got %+v", final.Warnings)
	}
}

func TestRouteFailureBudget(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	d := queued("web", "route0000001", 1)
	d.Status = state.StatusRouting
	d.ImageID = "sha256:web-route0000001"
	name := runner.ContainerName("web", "route0000001")
	h.runner.containers[name] = runner.ContainerInfo{ID: "c", Name: name, App: "web", DeploymentID: "route0000001", Role: runner.RoleApp, State: "running", Running: true, HostPort: 42000}
	h.store.putDeployment(d)

	h.router.mu.Lock()
	h.router.syncErr = fmt.Errorf("caddy down")
	h.router.mu.Unlock()

	// first round: stays routing
	h.rec.round(context.Background(), "web")
	if s := h.store.getDeployment("route0000001").Status; s != state.StatusRouting {
		t.Fatalf("want routing after first failure, got %s", s)
	}
	// advance past 5 minutes
	h.clock.Advance(6 * time.Minute)
	h.rec.round(context.Background(), "web")
	final := h.store.getDeployment("route0000001")
	if final.Status != state.StatusFailed || final.Diagnosis.Code != "route_failed" {
		t.Fatalf("want route_failed, got %s / %+v", final.Status, final.Diagnosis)
	}
	if h.runner.hasContainer(name) {
		t.Fatalf("routing-failed container should be removed")
	}
}

func TestScheduleViaKick(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(queued("web", "kick00000001", 1))

	// Kick creates a worker goroutine; poll for terminal.
	h.rec.Kick("web")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s := h.store.getDeployment("kick00000001").Status; !state.IsPending(s) {
			break
		}
		// re-kick to drive subsequent rounds (coalesced if pending)
		h.rec.Kick("web")
		time.Sleep(5 * time.Millisecond)
	}
	if s := h.store.getDeployment("kick00000001").Status; s != state.StatusLive {
		t.Fatalf("want live via Kick scheduling, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// git / image source tests
// ---------------------------------------------------------------------------

// fakeGit is an injectable Git for tests: it records calls and either writes a
// working tree or returns a classified failure output.
type fakeGit struct {
	mu          sync.Mutex
	cloneCalls  []string // "url ref dst"
	checkout    []string // "dir ref"
	cloneOutput string
	cloneErr    error
	writeFiles  map[string]string // files to create in dst on a successful clone
	checkoutErr error
	checkoutOut string
}

func (g *fakeGit) Clone(_ context.Context, url, ref, dst string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cloneCalls = append(g.cloneCalls, url+" "+ref+" "+dst)
	if g.cloneErr != nil {
		return g.cloneOutput, g.cloneErr
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	files := g.writeFiles
	if files == nil {
		files = map[string]string{"Dockerfile": "FROM scratch\n"}
	}
	for name, body := range files {
		full := filepath.Join(dst, name)
		if derr := os.MkdirAll(filepath.Dir(full), 0o755); derr != nil {
			return "", derr
		}
		if werr := os.WriteFile(full, []byte(body), 0o644); werr != nil {
			return "", werr
		}
	}
	return g.cloneOutput, nil
}

func (g *fakeGit) Checkout(_ context.Context, dir, ref string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.checkout = append(g.checkout, dir+" "+ref)
	return g.checkoutOut, g.checkoutErr
}

func gitDeployment(app, id string, seq int, sourceRef string) state.Deployment {
	return state.Deployment{
		ID:         id,
		App:        app,
		Seq:        seq,
		SourceKind: state.SourceGit,
		SourceRef:  sourceRef,
		Status:     state.StatusQueued,
	}
}

func imageDeployment(app, id string, seq int, ref string) state.Deployment {
	return state.Deployment{
		ID:         id,
		App:        app,
		Seq:        seq,
		SourceKind: state.SourceImage,
		SourceRef:  ref,
		Status:     state.StatusQueued,
	}
}

func TestGitSourceReachesLive(t *testing.T) {
	h := newHarness(t)
	h.rec.cfg.Git = &fakeGit{}
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(gitDeployment("web", "gitaaaaaaaa1", 1, "https://example.com/repo.git#main"))

	d := h.driveToTerminal(t, "web", "gitaaaaaaaa1", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("git deploy want live, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
	// The build must have been driven from a tarball placed in UploadDir.
	fg := h.rec.cfg.Git.(*fakeGit)
	if len(fg.cloneCalls) == 0 {
		t.Fatalf("expected a clone call")
	}
}

func TestGitCloneTimeoutDiagnosis(t *testing.T) {
	h := newHarness(t)
	h.rec.cfg.Git = &fakeGit{cloneErr: fmt.Errorf("boom"), cloneOutput: "fatal: unable to access: Connection timed out"}
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(gitDeployment("web", "gittimeout01", 1, "https://github.com/x/y.git#main"))

	d := h.driveToTerminal(t, "web", "gittimeout01", 5)
	if d.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", d.Status)
	}
	if d.Diagnosis == nil || d.Diagnosis.Stage != "source" || d.Diagnosis.Code != "clone_timeout" {
		t.Fatalf("want source/clone_timeout, got %+v", d.Diagnosis)
	}
}

func TestGitRepoNotFoundDiagnosis(t *testing.T) {
	h := newHarness(t)
	h.rec.cfg.Git = &fakeGit{cloneErr: fmt.Errorf("exit 128"), cloneOutput: "remote: Repository not found.\nfatal: repository not found"}
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(gitDeployment("web", "gitnotfound1", 1, "https://github.com/x/missing.git"))

	d := h.driveToTerminal(t, "web", "gitnotfound1", 5)
	if d.Diagnosis == nil || d.Diagnosis.Code != "repo_not_found" {
		t.Fatalf("want repo_not_found, got %+v", d.Diagnosis)
	}
}

func TestGitCommitHashCheckedOut(t *testing.T) {
	h := newHarness(t)
	fg := &fakeGit{}
	h.rec.cfg.Git = fg
	h.store.putApp(baseApp("web"))
	commit := "0123456789abcdef0123456789abcdef01234567"
	h.store.putDeployment(gitDeployment("web", "gitcommit001", 1, "https://example.com/repo.git#"+commit))

	d := h.driveToTerminal(t, "web", "gitcommit001", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("want live, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
	if len(fg.checkout) == 0 {
		t.Fatalf("expected a checkout for a commit hash ref")
	}
	// Clone must not have used --branch for a commit hash (ref recorded empty
	// slot is fine; verify checkout carried the commit).
	if !strings.Contains(fg.checkout[0], commit) {
		t.Fatalf("checkout did not target the commit: %v", fg.checkout)
	}
}

func TestImageSourcePullReachesLive(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	// External ref not present locally -> ImageInspect NotFound -> PullImage.
	h.store.putDeployment(imageDeployment("web", "img000000001", 1, "nginx:1.27-alpine"))
	h.runner.exposedPorts = []int{80}

	d := h.driveToTerminal(t, "web", "img000000001", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("image deploy want live, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
	h.runner.mu.Lock()
	pulls := len(h.runner.pullReqs)
	h.runner.mu.Unlock()
	if pulls == 0 {
		t.Fatalf("expected a PullImage call for an external image ref")
	}
}

func TestImageSourcePullFailureDiagnosis(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(imageDeployment("web", "imgfail00001", 1, "nope:doesnotexist"))
	h.runner.mu.Lock()
	h.runner.pullResp["imgfail00001"] = runner.PullResponse{OK: false, Failure: &runner.Failure{Stage: "image", Code: "image_not_found", Message: "no such image"}}
	h.runner.mu.Unlock()

	d := h.driveToTerminal(t, "web", "imgfail00001", 5)
	if d.Status != state.StatusFailed {
		t.Fatalf("want failed, got %s", d.Status)
	}
	if d.Diagnosis == nil || d.Diagnosis.Stage != "image" || d.Diagnosis.Code != "image_not_found" {
		t.Fatalf("want image/image_not_found, got %+v", d.Diagnosis)
	}
}

func TestRollbackImageInspectStillWorks(t *testing.T) {
	h := newHarness(t)
	h.store.putApp(baseApp("web"))
	// A rollback deployment references a local image ID that ImageInspect finds.
	imgID := "sha256:web-rollbackimg"
	h.runner.images[imgID] = runner.ImageInfo{ID: imgID, App: "web", DeploymentID: "prevdeploy01", ExposedPorts: []int{8080}}
	d := imageDeployment("web", "rollback0001", 1, imgID)
	h.store.putDeployment(d)

	final := h.driveToTerminal(t, "web", "rollback0001", 10)
	if final.Status != state.StatusLive {
		t.Fatalf("rollback want live, got %s (diag=%+v)", final.Status, final.Diagnosis)
	}
	// No pull should have happened for a locally-present image.
	h.runner.mu.Lock()
	pulls := len(h.runner.pullReqs)
	h.runner.mu.Unlock()
	if pulls != 0 {
		t.Fatalf("rollback must not pull, got %d pulls", pulls)
	}
}

// TestRealGitCloneLocalBareRepo clones a real bare repository created in the
// test's temp dir with the git binary. It is skipped when git is missing.
func TestRealGitCloneLocalBareRepo(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not available")
	}
	_ = gitBin

	ctx := context.Background()
	tmp := t.TempDir()

	// Create a work tree, commit a Dockerfile, then clone it bare.
	work := filepath.Join(tmp, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	runInDir := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_TERMINAL_PROMPT=0",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, cerr := cmd.CombinedOutput(); cerr != nil {
			t.Fatalf("git %v: %v\n%s", args, cerr, out)
		}
	}
	runInDir(work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "app.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInDir(work, "add", ".")
	runInDir(work, "commit", "-q", "-m", "init")

	bare := filepath.Join(tmp, "repo.git")
	runInDir(tmp, "clone", "-q", "--bare", work, bare)

	// Drive a git deployment through the real DefaultGit clone into a tarball,
	// then a fake Build.
	h := newHarness(t)
	h.rec.cfg.Git = DefaultGit()
	h.store.putApp(baseApp("web"))
	h.store.putDeployment(gitDeployment("web", "realgit00001", 1, "file://"+bare+"#main"))

	d := h.driveToTerminal(t, "web", "realgit00001", 10)
	if d.Status != state.StatusLive {
		t.Fatalf("real git clone deploy want live, got %s (diag=%+v)", d.Status, d.Diagnosis)
	}
}
