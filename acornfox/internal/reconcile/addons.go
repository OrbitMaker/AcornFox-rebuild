package reconcile

// N4.2 add-ons [addon-agent]: add-on containers, env injection and the
// deployment readiness gate of ADR-0006.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// appEnv returns the app's stored env plus one secret entry per add-on
// (EnvVar = connection URL, e.g. DATABASE_URL). An add-on value overrides a
// user variable of the same key: adding the add-on is the more specific
// intent. addons may be nil, in which case they are read from the store.
func (r *Reconciler) appEnv(ctx context.Context, app string, addons []state.Addon) ([]state.EnvVar, error) {
	env, err := r.cfg.Store.ListEnv(ctx, app)
	if err != nil {
		return nil, err
	}
	if addons == nil {
		if addons, err = r.cfg.Store.ListAddons(ctx, app); err != nil {
			r.log.Error("list addons", "app", app, "err", err)
			return env, nil
		}
	}
	return mergeAddonEnv(env, addons, r.log), nil
}

// mergeAddonEnv overlays add-on connection URLs onto env as secrets.
func mergeAddonEnv(env []state.EnvVar, addons []state.Addon, log *slog.Logger) []state.EnvVar {
	if len(addons) == 0 {
		return env
	}
	provided := map[string]string{}
	for _, a := range addons {
		c, err := a.DecodeCredentials()
		if err != nil || c.URL == "" {
			log.Error("addon credentials", "app", a.App, "kind", a.Kind, "err", err)
			continue
		}
		provided[a.EnvVar] = c.URL
	}
	out := make([]state.EnvVar, 0, len(env)+len(provided))
	for _, e := range env {
		if _, ok := provided[e.Key]; !ok {
			out = append(out, e)
		}
	}
	keys := make([]string, 0, len(provided))
	for k := range provided {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, state.EnvVar{App: addons[0].App, Key: k, Value: provided[k], Secret: true})
	}
	return out
}

// reconcileAddons converges the add-on containers of one app: every recorded
// add-on gets a running container on the app network, and add-on containers
// without a record (removed add-ons) are deleted. Data volumes are never
// deleted here. Add-ons keep running while the app itself is stopped. Errors
// are only logged; a pending deployment reports them through the readiness
// gate in doStart.
func (r *Reconciler) reconcileAddons(ctx context.Context, app state.App, addons []state.Addon) {
	containers, err := r.cfg.Runner.ListContainers(ctx, app.Name)
	if err != nil {
		r.log.Error("list containers for addons", "app", app.Name, "err", err)
		return
	}
	observed := map[string]runner.ContainerInfo{}
	for _, c := range containers {
		if c.Role == runner.RoleAddon {
			observed[c.Name] = c
		}
	}
	wanted := map[string]bool{}
	for _, a := range addons {
		name := runner.AddonContainerName(app.Name, a.Kind)
		wanted[name] = true
		c, exists := observed[name]
		if exists && (c.Running || c.Restarting) {
			continue
		}
		if err := r.ensureAddonContainer(ctx, app, a); err != nil {
			r.log.Error("ensure addon", "app", app.Name, "kind", a.Kind, "err", err)
			continue
		}
		if !exists {
			r.event(ctx, app.Name, "", "addon", "附加服务 "+a.Kind+" 已启动")
		}
	}
	for name := range observed {
		if wanted[name] {
			continue
		}
		if err := r.cfg.Runner.RemoveContainer(ctx, app.Name, name); err != nil {
			r.log.Error("remove addon container", "app", app.Name, "name", name, "err", err)
			continue
		}
		r.event(ctx, app.Name, "", "addon", "清理已删除的附加服务容器 "+name+"（数据卷保留）")
	}
}

// errAddonConfig marks a stored add-on that cannot be run as recorded (unknown
// kind, unreadable credentials); it is a start failure, not a transient error.
var errAddonConfig = errors.New("addon record unusable")

// ensureAddonContainer creates (or starts) the container of one add-on from
// the runner's pinned spec and the add-on's stored credentials.
func (r *Reconciler) ensureAddonContainer(ctx context.Context, app state.App, a state.Addon) error {
	spec, ok := runner.AddonSpecFor(a.Kind)
	if !ok {
		return fmt.Errorf("%w: unsupported kind %q", errAddonConfig, a.Kind)
	}
	creds, err := a.DecodeCredentials()
	if err != nil {
		return fmt.Errorf("%w: %v", errAddonConfig, err)
	}
	if err := r.cfg.Runner.EnsureVolume(ctx, app.Name, a.VolumeName); err != nil {
		return fmt.Errorf("ensure volume %s: %w", a.VolumeName, err)
	}
	_, err = r.cfg.Runner.EnsureContainer(ctx, runner.EnsureContainerRequest{
		App:          app.Name,
		DeploymentID: runner.AddonDeploymentID(a.Kind),
		Image:        a.Image, // pinned at add time; the runner refuses anything but its spec
		Port:         spec.Port,
		Env:          addonContainerEnv(a.Kind, creds),
		Mounts:       []runner.Mount{{Volume: a.VolumeName, Path: spec.DataPath}},
		MemoryMB:     spec.MemoryMB,
		CPUMilli:     spec.CPUMilli,
		Role:         runner.RoleAddon,
	})
	return err
}

// addonContainerEnv is the environment the official image reads to create
// its user, password and database on first start.
func addonContainerEnv(kind string, c state.AddonCredentials) map[string]string {
	switch kind {
	case state.AddonPostgres:
		return map[string]string{"POSTGRES_USER": c.Username, "POSTGRES_PASSWORD": c.Password, "POSTGRES_DB": c.Database}
	case state.AddonMySQL:
		return map[string]string{"MYSQL_ROOT_PASSWORD": c.RootPassword, "MYSQL_USER": c.Username, "MYSQL_PASSWORD": c.Password, "MYSQL_DATABASE": c.Database}
	case state.AddonRedis:
		return map[string]string{"REDIS_PASSWORD": c.Password} // read by the runner's redis entrypoint
	}
	return nil
}

// addonReadyTimeout bounds how long a deployment waits for its add-ons to
// accept connections before it fails with stage "addon" (ADR-0006).
const addonReadyTimeout = 120 * time.Second

// addonProblem is a terminal add-on failure found by the readiness gate.
type addonProblem struct {
	kind, code, detail string
	logs               bool // include the add-on container's log tail
}

// classifyEnsure turns an ensureAddonContainer error into a problem. It
// returns nil for a transient runner outage, which is retried, not a failure.
func classifyEnsure(kind string, err error) *addonProblem {
	switch {
	case errors.Is(err, errAddonConfig):
		return &addonProblem{kind: kind, code: "start_failed", detail: err.Error()}
	case runner.IsPullFailed(err):
		return &addonProblem{kind: kind, code: "pull_failed", detail: err.Error()}
	case errors.As(err, new(*runner.RemoteError)):
		return &addonProblem{kind: kind, code: "start_failed", detail: err.Error(), logs: true}
	}
	return nil
}

// waitAddonsReady blocks until every add-on of app reports Docker-healthy
// (accepting TCP connections), for at most addonReadyTimeout. ok=false with a
// nil problem means "not decided": the runner is unavailable or ctx ended, so
// the deployment stays in starting and is retried next round.
func (r *Reconciler) waitAddonsReady(ctx context.Context, app state.App, addons []state.Addon) (bool, *addonProblem) {
	deadline := r.cfg.Now().Add(addonReadyTimeout)
	baseRestarts := map[string]int{}
	for {
		containers, err := r.cfg.Runner.ListContainers(ctx, app.Name)
		if err != nil {
			return false, nil
		}
		byName := map[string]runner.ContainerInfo{}
		for _, c := range containers {
			if c.Role == runner.RoleAddon {
				byName[c.Name] = c
			}
		}
		var notReady string
		for _, a := range addons {
			name := runner.AddonContainerName(app.Name, a.Kind)
			c, exists := byName[name]
			if !exists || (!c.Running && !c.Restarting) {
				if err := r.ensureAddonContainer(ctx, app, a); err != nil {
					if p := classifyEnsure(a.Kind, err); p != nil {
						return false, p
					}
					return false, nil
				}
				if notReady == "" {
					notReady = a.Kind
				}
				continue
			}
			base, seen := baseRestarts[name]
			if !seen {
				baseRestarts[name], base = c.RestartCount, c.RestartCount
			}
			switch {
			case c.Health == "healthy" && c.Running:
			case c.OOMKilled:
				return false, &addonProblem{kind: a.Kind, code: "out_of_memory", logs: true}
			case c.Restarting || c.RestartCount > base:
				return false, &addonProblem{kind: a.Kind, code: "exited", detail: fmt.Sprintf("exit code %d", c.ExitCode), logs: true}
			case c.Health == "unhealthy":
				return false, &addonProblem{kind: a.Kind, code: "not_ready", logs: true}
			default:
				if notReady == "" {
					notReady = a.Kind
				}
			}
		}
		if notReady == "" {
			return true, nil
		}
		if !r.cfg.Now().Before(deadline) {
			return false, &addonProblem{kind: notReady, code: "not_ready", logs: true}
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(r.addonPoll):
		}
	}
}

// addonSecrets returns env plus the raw add-on passwords as secrets, so that
// add-on logs are redacted even where a password appears outside its URL.
func addonSecrets(env []state.EnvVar, addons []state.Addon) []state.EnvVar {
	out := append([]state.EnvVar(nil), env...)
	for _, a := range addons {
		if c, err := a.DecodeCredentials(); err == nil {
			for _, p := range []string{c.Password, c.RootPassword} {
				if p != "" {
					out = append(out, state.EnvVar{Key: "_addon_" + a.Kind, Value: p, Secret: true})
				}
			}
		}
	}
	return out
}

// addonDiagnosis builds the stage "addon" diagnosis of ADR-0006: which
// add-on, what happened, the effect on the app, add-on logs, and a next step
// that states the data volume was not touched.
func (r *Reconciler) addonDiagnosis(ctx context.Context, app state.App, p *addonProblem, secrets []state.EnvVar) *state.Diagnosis {
	effect := "新版本未启动，原版本继续运行。"
	if app.CurrentDeployment == "" {
		effect = "应用尚未上线。"
	}
	var what, hint string
	switch p.code {
	case "pull_failed":
		what = "附加服务 " + p.kind + " 的镜像拉取失败"
		hint = "检查服务器能否访问镜像仓库（或配置镜像加速）后重新部署"
	case "start_failed":
		what = "附加服务 " + p.kind + " 的容器无法启动"
		hint = "查看日志摘录，修复后重新部署"
	case "exited":
		what = "附加服务 " + p.kind + " 启动后退出或反复重启"
		hint = "查看数据库日志摘录；常见原因是数据卷里有不兼容的旧数据"
	case "out_of_memory":
		what = "附加服务 " + p.kind + " 因内存超限被杀死"
		hint = "减少数据库负载或连接数后重新部署"
	default: // not_ready
		what = fmt.Sprintf("附加服务 %s 在 %d 秒内没有就绪（不能接受连接）", p.kind, int(addonReadyTimeout/time.Second))
		hint = "查看数据库日志摘录；首次初始化较慢时可直接重新部署"
	}
	d := &state.Diagnosis{
		Stage:   "addon",
		Code:    p.code,
		Message: what + "，" + effect,
		Hint:    hint + "。数据卷 " + runner.AddonVolumeName(app.Name, p.kind) + " 未被改动。",
	}
	if p.logs {
		d.LogExcerpt = r.tailLogs(ctx, app.Name, runner.AddonContainerName(app.Name, p.kind), secrets)
	}
	if d.LogExcerpt == "" && p.detail != "" {
		d.LogExcerpt = p.detail
	}
	r.redactDiagnosis(d, secrets)
	return d
}
