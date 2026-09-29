package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/acornfox/acornfox/internal/caddyroute"
	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// Store is the subset of *state.Store the reconciler depends on. It is
// declared here (rather than importing a concrete type) so the store can be
// implemented concurrently and faked in tests. Signatures match the method
// set documented in internal/state/types.go.
type Store interface {
	// Apps
	GetApp(ctx context.Context, name string) (state.App, error)
	ListApps(ctx context.Context) ([]state.App, error)
	SetCurrentDeployment(ctx context.Context, app, deploymentID string) error

	// Deployments
	GetDeployment(ctx context.Context, id string) (state.Deployment, error)
	PendingDeployments(ctx context.Context, app string) ([]state.Deployment, error)
	UpdateDeployment(ctx context.Context, id string, fn func(*state.Deployment) error) (state.Deployment, error)
	KeptImageDeployments(ctx context.Context, app string) ([]state.Deployment, error)

	// Env, volumes
	AddVolume(ctx context.Context, app, path string, auto bool) (state.Volume, bool, error)
	ListEnv(ctx context.Context, app string) ([]state.EnvVar, error)
	ListVolumes(ctx context.Context, app string) ([]state.Volume, error)

	// Events
	AddEvent(ctx context.Context, e state.Event) error
}

// Config configures a Reconciler. Store, Runner and Router are required.
type Config struct {
	Store         Store
	Runner        runner.API
	Router        caddyroute.Router
	Probe         func(ctx context.Context, hostport, path string) error
	UploadDir     string
	PublicHost    string
	Logger        *slog.Logger
	Tick          time.Duration
	HealthTimeout time.Duration
	Now           func() time.Time
	// Git performs server-side clones for git-source deployments. Nil uses the
	// system git binary (DefaultGit); tests inject a fake.
	Git Git
}

// Default configuration values.
const (
	DefaultTick          = 30 * time.Second
	DefaultHealthTimeout = 60 * time.Second
	routeFailureBudget   = 5 * time.Minute
	staleUploadAge       = 1 * time.Hour
	pingThrottle         = 1 * time.Minute
	redactMinLen         = 4
	redactMask           = "******"
)

// Reconciler drives every app toward its desired state.
type Reconciler struct {
	cfg Config
	log *slog.Logger

	// per-app scheduling
	mu       sync.Mutex
	workers  map[string]*worker
	firstRun bool // true until the first global round completes (forces a route Sync)

	// runner/unavailable event throttle: app -> last time an event was written
	pingMu      sync.Mutex
	lastPingEvt map[string]time.Time

	// global build semaphore (capacity 1)
	buildSem chan struct{}

	// routing failure tracking: deployment ID -> first failure time
	routeFailMu    sync.Mutex
	routeFailSince map[string]time.Time
}

// worker owns one app's serial reconcile goroutine.
type worker struct {
	app  string
	kick chan struct{} // buffered size 1; coalesces triggers
}

// New builds a Reconciler, filling defaults.
func New(cfg Config) *Reconciler {
	if cfg.Tick <= 0 {
		cfg.Tick = DefaultTick
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = DefaultHealthTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Probe == nil {
		cfg.Probe = DefaultProbe
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Reconciler{
		cfg:            cfg,
		log:            cfg.Logger,
		workers:        make(map[string]*worker),
		firstRun:       true,
		lastPingEvt:    make(map[string]time.Time),
		buildSem:       make(chan struct{}, 1),
		routeFailSince: make(map[string]time.Time),
	}
}

// Run blocks until ctx is cancelled. On start and every Tick it kicks all
// known apps and runs a global orphan sweep.
func (r *Reconciler) Run(ctx context.Context) error {
	// initial round
	r.globalRound(ctx)

	t := time.NewTicker(r.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.shutdown()
			return ctx.Err()
		case <-t.C:
			r.globalRound(ctx)
		}
	}
}

// globalRound kicks every known app and performs the global GC sweep.
func (r *Reconciler) globalRound(ctx context.Context) {
	apps, err := r.cfg.Store.ListApps(ctx)
	if err != nil {
		r.log.Error("list apps", "err", err)
		return
	}
	names := make([]string, 0, len(apps))
	for _, a := range apps {
		names = append(names, a.Name)
		r.Kick(a.Name)
	}
	r.globalGC(ctx, names)

	r.mu.Lock()
	r.firstRun = false
	r.mu.Unlock()
}

// shutdown closes all worker kick channels.
func (r *Reconciler) shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.workers {
		close(w.kick)
	}
	r.workers = make(map[string]*worker)
}

// Kick triggers one reconcile round for app; duplicate kicks are coalesced.
// It lazily creates the app's serial goroutine on first use.
func (r *Reconciler) Kick(app string) {
	r.mu.Lock()
	w, ok := r.workers[app]
	if !ok {
		w = &worker{app: app, kick: make(chan struct{}, 1)}
		r.workers[app] = w
		go r.workerLoop(w)
	}
	r.mu.Unlock()

	select {
	case w.kick <- struct{}{}:
	default: // already pending; coalesce
	}
}

// workerLoop runs one app's rounds strictly serially.
func (r *Reconciler) workerLoop(w *worker) {
	for range w.kick {
		ctx := context.Background()
		r.round(ctx, w.app)
	}
}

// round performs one full reconcile pass for a single app.
func (r *Reconciler) round(ctx context.Context, app string) {
	// runner ping gating
	if _, err := r.cfg.Runner.Ping(ctx); err != nil {
		r.throttledPingEvent(ctx, app)
		return
	}

	st := r.cfg.Store
	appRec, err := st.GetApp(ctx, app)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return
		}
		r.log.Error("get app", "app", app, "err", err)
		return
	}
	pending, err := st.PendingDeployments(ctx, app)
	if err != nil {
		r.log.Error("pending deployments", "app", app, "err", err)
		return
	}
	env, err := st.ListEnv(ctx, app)
	if err != nil {
		r.log.Error("list env", "app", app, "err", err)
		return
	}
	volumes, err := st.ListVolumes(ctx, app)
	if err != nil {
		r.log.Error("list volumes", "app", app, "err", err)
		return
	}

	// 2.2.2 supersede: keep only the newest pending deployment.
	pending = r.supersede(ctx, app, pending)

	// 2.2.3 advance the single pending deployment.
	if len(pending) == 1 {
		d := &pending[0]
		// Drive the deployment through as many stages as possible in this
		// round. Stop when it is terminal, or when a step made no progress
		// (runner unavailable, route retry): the next kick or tick resumes it.
		for step := 0; step < 8; step++ {
			before := d.Status
			r.advance(ctx, appRec, d, env, volumes)
			cur, err := st.GetDeployment(ctx, d.ID)
			if err != nil {
				break
			}
			*d = cur
			if !state.IsPending(d.Status) || d.Status == before {
				break
			}
			if v, err := st.ListVolumes(ctx, app); err == nil {
				volumes = v // the build step may have added image VOLUME paths
			}
		}
		// re-read app since SetCurrentDeployment may have changed it
		if a2, err := st.GetApp(ctx, app); err == nil {
			appRec = a2
		}
	}

	// re-read observed containers after advancing
	containers, err := r.cfg.Runner.ListContainers(ctx, app)
	if err != nil {
		r.log.Error("list containers", "app", app, "err", err)
		return
	}

	// 2.4 converge actual state.
	r.converge(ctx, appRec, containers)

	// route sync on change (always on first round)
	r.syncRoutesIfChanged(ctx)

	// 2.5 per-app GC.
	r.appGC(ctx, app, pending)
}

// supersede marks all but the newest pending deployment as superseded, removing
// their containers and uploads. Returns the surviving pending slice (0 or 1).
func (r *Reconciler) supersede(ctx context.Context, app string, pending []state.Deployment) []state.Deployment {
	if len(pending) <= 1 {
		return pending
	}
	// PendingDeployments is oldest first; the last is the newest.
	newest := pending[len(pending)-1]
	for i := 0; i < len(pending)-1; i++ {
		r.markSuperseded(ctx, app, pending[i])
	}
	return []state.Deployment{newest}
}

func (r *Reconciler) markSuperseded(ctx context.Context, app string, d state.Deployment) {
	_, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Status = state.StatusSuperseded
		return nil
	})
	if err != nil {
		r.log.Error("supersede", "deployment", d.ID, "err", err)
		return
	}
	r.event(ctx, app, d.ID, "deploy", "被更新的提交取代")
	// remove any container this deployment created
	name := runner.ContainerName(app, d.ID)
	_ = r.cfg.Runner.RemoveContainer(ctx, app, name)
	r.removeUpload(d)
}

// advance drives one pending deployment forward one step per round. Each status
// transition is written to the store before the side effect so a crash can
// resume from the persisted status.
func (r *Reconciler) advance(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar, volumes []state.Volume) {
	switch d.Status {
	case state.StatusQueued:
		r.doBuild(ctx, app, d, env)
	case state.StatusBuilding:
		r.resumeBuild(ctx, app, d, env)
	case state.StatusStarting:
		r.doStart(ctx, app, d, env, volumes)
	case state.StatusChecking:
		r.doCheck(ctx, app, d, env)
	case state.StatusRouting:
		r.doRoute(ctx, app, d)
	}
}

// doBuild: queued -> building (+Attempts) -> build.
func (r *Reconciler) doBuild(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar) {
	updated, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Status = state.StatusBuilding
		dep.Attempts++
		return nil
	})
	if err != nil {
		r.log.Error("to building", "deployment", d.ID, "err", err)
		return
	}
	*d = updated
	r.event(ctx, app.Name, d.ID, "build", buildStartMessage(d.SourceKind))
	r.build(ctx, app, d, env)
}

// resumeBuild handles a deployment found in building after a restart.
func (r *Reconciler) resumeBuild(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar) {
	if d.Attempts >= state.MaxBuildAttempts {
		r.fail(ctx, app, d, env, &state.Diagnosis{
			Stage:   "build",
			Code:    "interrupted",
			Message: "构建被中断两次",
			Hint:    "请重新提交部署",
		})
		return
	}
	updated, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Attempts++
		return nil
	})
	if err != nil {
		r.log.Error("resume build attempts", "deployment", d.ID, "err", err)
		return
	}
	*d = updated
	// The runner returns an existing image without rebuilding, so a completed
	// build is not redone.
	r.build(ctx, app, d, env)
}

// build performs the source-kind specific build/resolve, then moves to starting.
func (r *Reconciler) build(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar) {
	var imageID string
	var imageVolumes []string

	switch d.SourceKind {
	case state.SourceUpload:
		// global build semaphore, cancellable via ctx
		select {
		case r.buildSem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		resp, err := r.cfg.Runner.Build(ctx, runner.BuildRequest{
			App:          app.Name,
			DeploymentID: d.ID,
			ContextPath:  d.SourceRef,
		})
		<-r.buildSem
		if err != nil {
			r.log.Error("build", "deployment", d.ID, "err", err)
			// Transient runner/transport failure: stay in building and retry on a
			// later round. Attempts only count builds interrupted by a server
			// crash, so give this attempt back.
			if u, uerr := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
				if dep.Attempts > 0 {
					dep.Attempts--
				}
				return nil
			}); uerr == nil {
				*d = u
			}
			return
		}
		if !resp.OK {
			diag := &state.Diagnosis{Stage: "build", Code: "build_failed", Message: "构建失败"}
			if resp.Failure != nil {
				diag.Stage = resp.Failure.Stage
				diag.Code = resp.Failure.Code
				diag.Message = resp.Failure.Message
				diag.LogExcerpt = resp.Failure.LogExcerpt
				diag.Hint = resp.Failure.Hint
			}
			r.fail(ctx, app, d, env, diag)
			return
		}
		if resp.Image != nil {
			imageID = resp.Image.ID
			imageVolumes = resp.Image.Volumes
		}
	case state.SourceGit:
		// Clone the repo into a tar.gz, then build it like an upload. The clone
		// itself is network I/O and is not gated by the build semaphore; the
		// build is.
		tarball, diag, gerr := r.buildGitTarball(ctx, d)
		if gerr != nil {
			// Transient/internal failure: stay in building, retry next round and
			// hand the crash-retry attempt back.
			r.log.Error("git clone", "deployment", d.ID, "err", gerr)
			if u, uerr := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
				if dep.Attempts > 0 {
					dep.Attempts--
				}
				return nil
			}); uerr == nil {
				*d = u
			}
			return
		}
		if diag != nil {
			r.fail(ctx, app, d, env, diag)
			return
		}
		select {
		case r.buildSem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		resp, err := r.cfg.Runner.Build(ctx, runner.BuildRequest{
			App:          app.Name,
			DeploymentID: d.ID,
			ContextPath:  tarball,
		})
		<-r.buildSem
		if err != nil {
			r.log.Error("build (git)", "deployment", d.ID, "err", err)
			if u, uerr := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
				if dep.Attempts > 0 {
					dep.Attempts--
				}
				return nil
			}); uerr == nil {
				*d = u
			}
			return
		}
		if !resp.OK {
			bdiag := &state.Diagnosis{Stage: "build", Code: "build_failed", Message: "构建失败"}
			if resp.Failure != nil {
				bdiag.Stage = resp.Failure.Stage
				bdiag.Code = resp.Failure.Code
				bdiag.Message = resp.Failure.Message
				bdiag.LogExcerpt = resp.Failure.LogExcerpt
				bdiag.Hint = resp.Failure.Hint
			}
			r.fail(ctx, app, d, env, bdiag)
			return
		}
		if resp.Image != nil {
			imageID = resp.Image.ID
			imageVolumes = resp.Image.Volumes
		}
	case state.SourceImage:
		// Rollback and already-resolved deployments reference an image present
		// locally: inspect it. A fresh `deploy --image` references an external
		// image that must be pulled first (stage=image).
		info, err := r.cfg.Runner.ImageInspect(ctx, app.Name, d.SourceRef)
		if err == nil {
			imageID = info.ID
			imageVolumes = info.Volumes
			break
		}
		if !errors.Is(err, runner.ErrNotFound) {
			r.log.Error("image inspect", "deployment", d.ID, "err", err)
			return
		}
		resp, perr := r.cfg.Runner.PullImage(ctx, app.Name, d.ID, d.SourceRef)
		if perr != nil {
			r.log.Error("image pull", "deployment", d.ID, "err", perr)
			return // transient: retry next round
		}
		if !resp.OK {
			diag := &state.Diagnosis{Stage: "image", Code: "pull_failed", Message: "拉取镜像失败"}
			if resp.Failure != nil {
				diag.Stage = resp.Failure.Stage
				diag.Code = resp.Failure.Code
				diag.Message = resp.Failure.Message
				diag.LogExcerpt = resp.Failure.LogExcerpt
				diag.Hint = resp.Failure.Hint
			}
			r.fail(ctx, app, d, env, diag)
			return
		}
		if resp.Image != nil {
			imageID = resp.Image.ID
			imageVolumes = resp.Image.Volumes
		}
	default:
		r.log.Error("unknown source kind", "deployment", d.ID, "kind", d.SourceKind)
		return
	}

	// auto-save each image VOLUME path
	for _, p := range imageVolumes {
		_, created, err := r.cfg.Store.AddVolume(ctx, app.Name, p, true)
		if err != nil {
			r.log.Error("add auto volume", "app", app.Name, "path", p, "err", err)
			continue
		}
		if created {
			r.event(ctx, app.Name, d.ID, "build", "自动保存数据目录 "+p)
		}
	}

	// persist ImageID and move to starting
	updated, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.ImageID = imageID
		dep.Status = state.StatusStarting
		return nil
	})
	if err != nil {
		r.log.Error("to starting", "deployment", d.ID, "err", err)
		return
	}
	*d = updated
	r.event(ctx, app.Name, d.ID, "build", "镜像就绪，启动容器")
}

// doStart creates and starts the container, then moves to checking.
func (r *Reconciler) doStart(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar, volumes []state.Volume) {
	// resolve port
	port, declared := r.containerPort(ctx, app, d.ImageID)
	if !declared {
		r.event(ctx, app.Name, d.ID, "start", "未声明 EXPOSE，按 8080 处理")
	}

	// ensure volumes
	mounts := make([]runner.Mount, 0, len(volumes))
	for _, v := range volumes {
		if err := r.cfg.Runner.EnsureVolume(ctx, app.Name, v.VolumeName); err != nil {
			r.log.Error("ensure volume", "app", app.Name, "volume", v.VolumeName, "err", err)
			return // transient; retry next round in starting
		}
		mounts = append(mounts, runner.Mount{Volume: v.VolumeName, Path: v.Path})
	}

	envMap := make(map[string]string, len(env))
	for _, e := range env {
		envMap[e.Key] = e.Value
	}

	image := d.ImageID
	if image == "" {
		image = runner.ImageTag(app.Name, d.ID)
	}

	memMB := app.MemoryMB
	if memMB <= 0 {
		memMB = state.DefaultMemoryMB
	}
	cpu := app.CPUMilli
	if cpu <= 0 {
		cpu = state.DefaultCPUMilli
	}

	_, err := r.cfg.Runner.EnsureContainer(ctx, runner.EnsureContainerRequest{
		App:          app.Name,
		DeploymentID: d.ID,
		Image:        image,
		Port:         port,
		Env:          envMap,
		Mounts:       mounts,
		MemoryMB:     memMB,
		CPUMilli:     cpu,
	})
	if err != nil {
		name := runner.ContainerName(app.Name, d.ID)
		logs := r.tailLogs(ctx, app.Name, name, env)
		r.fail(ctx, app, d, env, &state.Diagnosis{
			Stage:      "start",
			Code:       "start_failed",
			Message:    "容器启动失败",
			LogExcerpt: logs,
		})
		_ = r.cfg.Runner.RemoveContainer(ctx, app.Name, name)
		return
	}

	updated, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Status = state.StatusChecking
		return nil
	})
	if err != nil {
		r.log.Error("to checking", "deployment", d.ID, "err", err)
		return
	}
	*d = updated
	r.event(ctx, app.Name, d.ID, "start", "容器已启动，等待应用响应")
}

// containerPort is the app's container port: explicit, else the image's first
// EXPOSE, else 8080. declared is false only in the 8080 fallback case.
func (r *Reconciler) containerPort(ctx context.Context, app state.App, imageID string) (port int, declared bool) {
	if app.Port != 0 {
		return app.Port, true
	}
	if info, err := r.cfg.Runner.ImageInspect(ctx, app.Name, imageID); err == nil && len(info.ExposedPorts) > 0 {
		return info.ExposedPorts[0], true
	}
	return 8080, false
}

// doCheck runs the health check loop, then moves to routing (or fails).
func (r *Reconciler) doCheck(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar) {
	name := runner.ContainerName(app.Name, d.ID)
	healthPath := app.HealthPath
	if healthPath == "" {
		healthPath = state.DefaultHealthPath
	}

	containerPort, _ := r.containerPort(ctx, app, d.ImageID)
	deadline := r.cfg.Now().Add(r.cfg.HealthTimeout)
	for {
		ci, ok := r.findContainer(ctx, app.Name, name)
		if ok {
			// container-level failure detection
			if ci.OOMKilled {
				logs := r.tailLogs(ctx, app.Name, name, env)
				r.fail(ctx, app, d, env, &state.Diagnosis{
					Stage:      "health",
					Code:       "out_of_memory",
					Message:    "容器因内存超限被杀死",
					LogExcerpt: logs,
					Hint:       "请调高内存上限（acornfox app set --memory）",
				})
				_ = r.cfg.Runner.RemoveContainer(ctx, app.Name, name)
				return
			}
			if ci.RestartCount > 0 || ci.Restarting || (ci.State != "" && ci.State != "running") {
				logs := r.tailLogs(ctx, app.Name, name, env)
				r.fail(ctx, app, d, env, &state.Diagnosis{
					Stage:      "health",
					Code:       "container_exited",
					Message:    "容器启动后退出或反复重启",
					LogExcerpt: logs,
					Hint:       "请检查启动命令与日志",
				})
				_ = r.cfg.Runner.RemoveContainer(ctx, app.Name, name)
				return
			}
			if ci.HostPort > 0 {
				hostport := fmt.Sprintf("127.0.0.1:%d", ci.HostPort)
				if err := r.cfg.Probe(ctx, hostport, healthPath); err == nil {
					goto healthy
				}
			}
		}
		if !r.cfg.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	// timed out
	{
		logs := r.tailLogs(ctx, app.Name, name, env)
		r.fail(ctx, app, d, env, &state.Diagnosis{
			Stage:      "health",
			Code:       "port_not_listening",
			Message:    "健康检查超时，端口未监听",
			LogExcerpt: logs,
			Hint:       fmt.Sprintf("请确认应用在容器内监听 0.0.0.0:%d（可用 EXPOSE 声明端口）", containerPort),
		})
		_ = r.cfg.Runner.RemoveContainer(ctx, app.Name, name)
		return
	}

healthy:
	// unpersisted database warning (non-fatal)
	if files, err := r.cfg.Runner.Diff(ctx, app.Name, name); err == nil && len(files) > 0 {
		dir := filepath.Dir(files[0])
		warn := state.Diagnosis{
			Stage:   "data",
			Code:    "unpersisted_database",
			Message: "检测到未持久化的数据库文件：" + strings.Join(files, ", "),
			Hint:    "acornfox volume add " + dir,
		}
		_, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
			dep.Warnings = append(dep.Warnings, warn)
			return nil
		})
		if err != nil {
			r.log.Error("append warning", "deployment", d.ID, "err", err)
		}
		r.event(ctx, app.Name, d.ID, "data", warn.Message)
	}

	updated, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Status = state.StatusRouting
		return nil
	})
	if err != nil {
		r.log.Error("to routing", "deployment", d.ID, "err", err)
		return
	}
	*d = updated
	r.event(ctx, app.Name, d.ID, "health", "健康检查通过，切换流量")
}

// doRoute switches Caddy to the new container, with retry and a 5-minute budget.
func (r *Reconciler) doRoute(ctx context.Context, app state.App, d *state.Deployment) {
	routes, err := r.desiredRoutes(ctx, app.Name, d)
	if err != nil {
		r.log.Error("compute routes", "app", app.Name, "err", err)
		return
	}
	if err := r.cfg.Router.Sync(ctx, routes); err != nil {
		r.log.Error("route sync", "app", app.Name, "deployment", d.ID, "err", err)
		r.event(ctx, app.Name, d.ID, "route", "路由同步失败，稍后重试："+err.Error())
		r.routeFailMu.Lock()
		first, ok := r.routeFailSince[d.ID]
		if !ok {
			first = r.cfg.Now()
			r.routeFailSince[d.ID] = first
		}
		expired := r.cfg.Now().Sub(first) > routeFailureBudget
		r.routeFailMu.Unlock()

		if expired {
			r.routeFailMu.Lock()
			delete(r.routeFailSince, d.ID)
			r.routeFailMu.Unlock()
			r.fail(ctx, app, d, nil, &state.Diagnosis{
				Stage:   "route",
				Code:    "route_failed",
				Message: "路由持续同步失败超过 5 分钟",
				Hint:    "请检查 Caddy admin 是否可用",
			})
			_ = r.cfg.Runner.RemoveContainer(ctx, app.Name, runner.ContainerName(app.Name, d.ID))
		}
		return // stay in routing, retry next round
	}
	r.routeFailMu.Lock()
	delete(r.routeFailSince, d.ID)
	r.routeFailMu.Unlock()

	if err := r.cfg.Store.SetCurrentDeployment(ctx, app.Name, d.ID); err != nil {
		r.log.Error("set current deployment", "deployment", d.ID, "err", err)
		return
	}
	r.removeUpload(*d)
	r.event(ctx, app.Name, d.ID, "deploy", fmt.Sprintf("已上线 http://%s:%d", r.cfg.PublicHost, app.PublicPort))
}

// fail marks a deployment failed with a redacted diagnosis and removes upload.
func (r *Reconciler) fail(ctx context.Context, app state.App, d *state.Deployment, env []state.EnvVar, diag *state.Diagnosis) {
	if env == nil {
		env, _ = r.cfg.Store.ListEnv(ctx, app.Name)
	}
	r.redactDiagnosis(diag, env)
	updated, err := r.cfg.Store.UpdateDeployment(ctx, d.ID, func(dep *state.Deployment) error {
		dep.Status = state.StatusFailed
		dep.Diagnosis = diag
		return nil
	})
	if err != nil {
		r.log.Error("to failed", "deployment", d.ID, "err", err)
		return
	}
	*d = updated
	r.event(ctx, app.Name, d.ID, diag.Stage, diag.Message)
	r.removeUpload(*d)
}

// converge makes actual containers match the expected set for one app (2.4).
func (r *Reconciler) converge(ctx context.Context, app state.App, containers []runner.ContainerInfo) {
	// determine live deployment container name (if any)
	liveName := ""
	if app.CurrentDeployment != "" {
		liveName = runner.ContainerName(app.Name, app.CurrentDeployment)
	}

	// pending deployment currently occupying a container (starting/checking/routing)
	pendingNames := map[string]struct{}{}
	pending, _ := r.cfg.Store.PendingDeployments(ctx, app.Name)
	for _, d := range pending {
		switch d.Status {
		case state.StatusStarting, state.StatusChecking, state.StatusRouting:
			pendingNames[runner.ContainerName(app.Name, d.ID)] = struct{}{}
		}
	}

	// remove unexpected app-role containers
	var liveContainer *runner.ContainerInfo
	for i := range containers {
		c := containers[i]
		if c.Role != runner.RoleApp {
			continue
		}
		expected := (liveName != "" && c.Name == liveName)
		if _, ok := pendingNames[c.Name]; ok {
			expected = true
		}
		if !expected {
			_ = r.cfg.Runner.RemoveContainer(ctx, app.Name, c.Name)
			r.event(ctx, app.Name, "", "converge", "清理旧容器 "+c.Name)
			continue
		}
		if c.Name == liveName {
			liveContainer = &containers[i]
		}
	}

	if liveName == "" {
		return // no live deployment; nothing to keep running
	}

	switch app.Desired {
	case state.DesiredRunning:
		if liveContainer == nil {
			// live container missing: recreate from live deployment's ImageID
			r.recreateLive(ctx, app)
		} else if !liveContainer.Running {
			if _, err := r.cfg.Runner.StartContainer(ctx, app.Name, liveName); err != nil {
				r.log.Error("start live", "app", app.Name, "err", err)
			}
		}
	case state.DesiredStopped:
		if liveContainer != nil && liveContainer.Running {
			if err := r.cfg.Runner.StopContainer(ctx, app.Name, liveName); err != nil {
				r.log.Error("stop live", "app", app.Name, "err", err)
			}
		}
	}
}

// recreateLive re-ensures the live container after it went missing.
func (r *Reconciler) recreateLive(ctx context.Context, app state.App) {
	kept, err := r.cfg.Store.KeptImageDeployments(ctx, app.Name)
	if err != nil {
		r.log.Error("kept deployments", "app", app.Name, "err", err)
		return
	}
	var live *state.Deployment
	for i := range kept {
		if kept[i].ID == app.CurrentDeployment {
			live = &kept[i]
			break
		}
	}
	if live == nil || live.ImageID == "" {
		return
	}
	port, _ := r.containerPort(ctx, app, live.ImageID)
	env, _ := r.cfg.Store.ListEnv(ctx, app.Name)
	envMap := make(map[string]string, len(env))
	for _, e := range env {
		envMap[e.Key] = e.Value
	}
	volumes, _ := r.cfg.Store.ListVolumes(ctx, app.Name)
	mounts := make([]runner.Mount, 0, len(volumes))
	for _, v := range volumes {
		_ = r.cfg.Runner.EnsureVolume(ctx, app.Name, v.VolumeName)
		mounts = append(mounts, runner.Mount{Volume: v.VolumeName, Path: v.Path})
	}
	memMB := app.MemoryMB
	if memMB <= 0 {
		memMB = state.DefaultMemoryMB
	}
	cpu := app.CPUMilli
	if cpu <= 0 {
		cpu = state.DefaultCPUMilli
	}
	if _, err := r.cfg.Runner.EnsureContainer(ctx, runner.EnsureContainerRequest{
		App:          app.Name,
		DeploymentID: live.ID,
		Image:        live.ImageID,
		Port:         port,
		Env:          envMap,
		Mounts:       mounts,
		MemoryMB:     memMB,
		CPUMilli:     cpu,
	}); err != nil {
		r.log.Error("recreate live", "app", app.Name, "err", err)
		return
	}
	r.event(ctx, app.Name, live.ID, "converge", "容器缺失，已重建")
}

// appGC removes images outside the kept set for one app (2.5 per-app part).
func (r *Reconciler) appGC(ctx context.Context, app string, pending []state.Deployment) {
	kept, err := r.cfg.Store.KeptImageDeployments(ctx, app)
	if err != nil {
		r.log.Error("kept deployments", "app", app, "err", err)
		return
	}
	keepIDs := map[string]struct{}{}
	for _, d := range kept {
		keepIDs[d.ID] = struct{}{}
	}
	for _, d := range pending {
		keepIDs[d.ID] = struct{}{}
	}

	images, err := r.cfg.Runner.ListImages(ctx, app)
	if err != nil {
		r.log.Error("list images", "app", app, "err", err)
		return
	}
	for _, img := range images {
		if _, ok := keepIDs[img.DeploymentID]; ok {
			continue
		}
		if err := r.cfg.Runner.RemoveImage(ctx, app, img.ID); err != nil {
			// ignore "image still in use" errors
			r.log.Debug("remove image", "app", app, "image", img.ID, "err", err)
		}
	}
}

// globalGC runs once per Tick: orphan containers and stale uploads (2.5 global).
func (r *Reconciler) globalGC(ctx context.Context, appNames []string) {
	known := map[string]struct{}{}
	for _, n := range appNames {
		known[n] = struct{}{}
	}

	// orphan containers: acornfox.app not in ListApps
	all, err := r.cfg.Runner.ListContainers(ctx, "")
	if err != nil {
		r.log.Error("list all containers", "err", err)
	} else {
		for _, c := range all {
			if _, ok := known[c.App]; !ok {
				_ = r.cfg.Runner.RemoveContainer(ctx, c.App, c.Name)
			}
		}
	}

	// stale uploads: not belonging to any pending deployment, mtime > 1h
	r.gcUploads(ctx, appNames)
}

// gcUploads removes upload files older than 1h that no pending deployment references.
func (r *Reconciler) gcUploads(ctx context.Context, appNames []string) {
	if r.cfg.UploadDir == "" {
		return
	}
	entries, err := os.ReadDir(r.cfg.UploadDir)
	if err != nil {
		return
	}
	// collect referenced upload paths
	referenced := map[string]struct{}{}
	for _, app := range appNames {
		pending, err := r.cfg.Store.PendingDeployments(ctx, app)
		if err != nil {
			continue
		}
		for _, d := range pending {
			if d.SourceKind == state.SourceUpload && d.SourceRef != "" {
				referenced[filepath.Clean(d.SourceRef)] = struct{}{}
			}
		}
	}
	cutoff := r.cfg.Now().Add(-staleUploadAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(r.cfg.UploadDir, e.Name())
		if _, ok := referenced[filepath.Clean(full)]; ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(full)
		}
	}
}

// desiredRoutes computes the full expected route set, substituting the given
// pending deployment's container as this app's upstream when non-nil.
func (r *Reconciler) desiredRoutes(ctx context.Context, thisApp string, override *state.Deployment) ([]caddyroute.Route, error) {
	apps, err := r.cfg.Store.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	var routes []caddyroute.Route
	for _, a := range apps {
		if a.Desired == state.DesiredStopped {
			continue
		}
		var containerName string
		if a.Name == thisApp && override != nil {
			containerName = runner.ContainerName(a.Name, override.ID)
		} else if a.CurrentDeployment != "" {
			containerName = runner.ContainerName(a.Name, a.CurrentDeployment)
		} else {
			continue // no live deployment, no route
		}
		hostPort := r.observedHostPort(ctx, a.Name, containerName)
		if hostPort == 0 {
			continue
		}
		routes = append(routes, caddyroute.Route{
			App:        a.Name,
			PublicPort: a.PublicPort,
			Upstream:   fmt.Sprintf("127.0.0.1:%d", hostPort),
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].App < routes[j].App })
	return routes, nil
}

// syncRoutesIfChanged computes routes from observed live containers and syncs
// only when different from Caddy's current view (or always on the first round).
func (r *Reconciler) syncRoutesIfChanged(ctx context.Context) {
	routes, err := r.observedRoutes(ctx)
	if err != nil {
		r.log.Error("observed routes", "err", err)
		return
	}
	r.mu.Lock()
	first := r.firstRun
	r.mu.Unlock()

	if !first {
		current, err := r.cfg.Router.Current(ctx)
		if err == nil && routesEqual(current, routes) {
			return
		}
	}
	if err := r.cfg.Router.Sync(ctx, routes); err != nil {
		r.log.Error("route sync", "err", err)
	}
}

// observedRoutes builds routes from live containers of running apps.
func (r *Reconciler) observedRoutes(ctx context.Context) ([]caddyroute.Route, error) {
	apps, err := r.cfg.Store.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	var routes []caddyroute.Route
	for _, a := range apps {
		if a.Desired == state.DesiredStopped || a.CurrentDeployment == "" {
			continue
		}
		name := runner.ContainerName(a.Name, a.CurrentDeployment)
		hostPort := r.observedHostPort(ctx, a.Name, name)
		if hostPort == 0 {
			continue
		}
		routes = append(routes, caddyroute.Route{
			App:        a.Name,
			PublicPort: a.PublicPort,
			Upstream:   fmt.Sprintf("127.0.0.1:%d", hostPort),
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].App < routes[j].App })
	return routes, nil
}

func (r *Reconciler) observedHostPort(ctx context.Context, app, name string) int {
	if ci, ok := r.findContainer(ctx, app, name); ok {
		return ci.HostPort
	}
	return 0
}

func (r *Reconciler) findContainer(ctx context.Context, app, name string) (runner.ContainerInfo, bool) {
	cs, err := r.cfg.Runner.ListContainers(ctx, app)
	if err != nil {
		return runner.ContainerInfo{}, false
	}
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return runner.ContainerInfo{}, false
}

// tailLogs fetches the last 40 lines of a container's logs, redacted.
func (r *Reconciler) tailLogs(ctx context.Context, app, name string, env []state.EnvVar) string {
	lines, err := r.cfg.Runner.Logs(ctx, app, name, runner.MaxLogExcerptLine)
	if err != nil || len(lines) == 0 {
		return ""
	}
	joined := strings.Join(lines, "\n")
	return r.redactString(joined, env)
}

// throttledPingEvent writes a runner/unavailable event at most once per minute per app.
func (r *Reconciler) throttledPingEvent(ctx context.Context, app string) {
	r.pingMu.Lock()
	last, ok := r.lastPingEvt[app]
	now := r.cfg.Now()
	if ok && now.Sub(last) < pingThrottle {
		r.pingMu.Unlock()
		return
	}
	r.lastPingEvt[app] = now
	r.pingMu.Unlock()
	r.event(ctx, app, "", "runner", "runner 暂不可用，稍后重试")
}

func (r *Reconciler) event(ctx context.Context, app, deploymentID, stage, message string) {
	err := r.cfg.Store.AddEvent(ctx, state.Event{
		App:          app,
		DeploymentID: deploymentID,
		At:           r.cfg.Now(),
		Stage:        stage,
		Message:      message,
	})
	if err != nil {
		r.log.Error("add event", "app", app, "err", err)
	}
}

func (r *Reconciler) removeUpload(d state.Deployment) {
	if d.SourceKind != state.SourceUpload || d.SourceRef == "" {
		return
	}
	_ = os.Remove(d.SourceRef)
}

// redactDiagnosis masks any secret env values (len >= 4) in message/log/hint.
func (r *Reconciler) redactDiagnosis(diag *state.Diagnosis, env []state.EnvVar) {
	if diag == nil {
		return
	}
	diag.Message = r.redactString(diag.Message, env)
	diag.LogExcerpt = r.redactString(diag.LogExcerpt, env)
	diag.Hint = r.redactString(diag.Hint, env)
}

func (r *Reconciler) redactString(s string, env []state.EnvVar) string {
	if s == "" {
		return s
	}
	for _, e := range env {
		if e.Secret && len(e.Value) >= redactMinLen {
			s = strings.ReplaceAll(s, e.Value, redactMask)
		}
	}
	return s
}

func routesEqual(current map[string]caddyroute.Route, want []caddyroute.Route) bool {
	if len(current) != len(want) {
		return false
	}
	for _, rt := range want {
		c, ok := current[rt.App]
		if !ok || c != rt {
			return false
		}
	}
	return true
}

// DefaultProbe performs an HTTP GET with a 2s timeout, no redirects; any
// response with status < 500 is considered healthy (section 2.6).
func DefaultProbe(ctx context.Context, hostport, path string) error {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := "http://" + hostport + path
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("probe: status %d", resp.StatusCode)
	}
	return nil
}

func buildStartMessage(kind string) string {
	switch kind {
	case state.SourceGit:
		return "拉取 Git 仓库并构建镜像"
	case state.SourceImage:
		return "准备镜像"
	default:
		return "开始构建镜像"
	}
}
