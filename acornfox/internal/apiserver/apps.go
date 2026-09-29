package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// envKeyPattern mirrors the store's accepted env key form.
var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// listApps implements GET /v1/apps.
func (s *server) listApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	views := make([]appView, 0, len(apps))
	for _, a := range apps {
		views = append(views, s.buildAppView(ctx, a, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": views})
}

// getApp implements GET /v1/apps/{app}.
func (s *server) getApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("app")
	if !state.ValidAppName(name) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	app, err := s.store.GetApp(ctx, name)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.buildAppView(ctx, app, true))
}

// buildAppView assembles the view for one app. When detail is true it also
// includes env keys, volumes and the live deployment. Container state is
// observed best-effort: any runner error degrades to ObservedState="unavailable".
func (s *server) buildAppView(ctx context.Context, a state.App, detail bool) appView {
	v := appView{
		Name:              a.Name,
		Desired:           a.Desired,
		Port:              a.Port,
		HealthPath:        a.HealthPath,
		PublicPort:        a.PublicPort,
		CurrentDeployment: a.CurrentDeployment,
		MemoryMB:          a.MemoryMB,
		CPUMilli:          a.CPUMilli,
		URL:               appURL(s.publicHost, a.PublicPort),
	}

	// Observed container state (best-effort).
	v.ObservedState = s.observeApp(ctx, a, &v)

	if !detail {
		return v
	}

	if a.CurrentDeployment != "" {
		if live, err := s.store.GetDeployment(ctx, a.CurrentDeployment); err == nil {
			v.Live = &live
		}
	}
	if vars, err := s.store.ListEnv(ctx, a.Name); err == nil {
		v.Env = makeEnvView(vars)
	}
	if vols, err := s.store.ListVolumes(ctx, a.Name); err == nil {
		v.Volumes = vols
	}
	return v
}

// observeApp reads the live container for an app and fills v.Observed. It
// returns the observed-state label. Runner errors are swallowed into
// "unavailable" so a broken runner never fails an API read.
func (s *server) observeApp(ctx context.Context, a state.App, v *appView) string {
	containers, err := s.runner.ListContainers(ctx, a.Name)
	if err != nil {
		return "unavailable"
	}
	var live *runner.ContainerInfo
	for i := range containers {
		c := containers[i]
		if c.Role != runner.RoleApp {
			continue
		}
		if a.CurrentDeployment != "" && c.DeploymentID == a.CurrentDeployment {
			live = &containers[i]
			break
		}
	}
	if live == nil {
		return "missing"
	}
	obs := makeObserved(*live)
	v.Observed = &obs
	if live.Running {
		return "running"
	}
	return "stopped"
}

// envRequest is the PUT env body.
type envRequest struct {
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
}

// putEnv implements PUT /v1/apps/{app}/env/{key}.
func (s *server) putEnv(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	key := r.PathValue("key")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if !envKeyPattern.MatchString(key) {
		writeError(w, http.StatusBadRequest, "invalid_env_key", "环境变量名不合法：需匹配 ^[A-Za-z_][A-Za-z0-9_]{0,127}$")
		return
	}
	var body envRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "请求体不是合法 JSON")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	if err := s.store.SetEnv(ctx, state.EnvVar{App: app, Key: key, Value: body.Value, Secret: body.Secret}); err != nil {
		s.mapStoreError(w, err)
		return
	}
	// Value is never echoed back; only the key and secret flag, plus a note
	// that the change applies on the next deployment.
	writeJSON(w, http.StatusOK, map[string]any{
		"key":     key,
		"secret":  body.Secret,
		"applied": false,
		"note":    "已保存到期望状态，下次部署生效",
	})
}

// deleteEnv implements DELETE /v1/apps/{app}/env/{key}.
func (s *server) deleteEnv(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	key := r.PathValue("key")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	if err := s.store.DeleteEnv(ctx, app, key); err != nil {
		s.mapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":     key,
		"deleted": true,
		"note":    "已从期望状态删除，下次部署生效",
	})
}

// volumeRequest is the POST volumes body.
type volumeRequest struct {
	Path string `json:"path"`
}

// addVolume implements POST /v1/apps/{app}/volumes.
func (s *server) addVolume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	var body volumeRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "请求体不是合法 JSON")
		return
	}
	if body.Path == "" || !filepath.IsAbs(body.Path) {
		writeError(w, http.StatusBadRequest, "invalid_path", "数据卷路径必须是绝对路径")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	vol, created, err := s.store.AddVolume(ctx, app, filepath.Clean(body.Path), false)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"volume":  vol,
		"created": created,
		"note":    "已保存到期望状态，下次部署生效",
	})
}

// stopApp implements POST /v1/apps/{app}/stop.
func (s *server) stopApp(w http.ResponseWriter, r *http.Request) {
	s.setDesired(w, r, state.DesiredStopped)
}

// startApp implements POST /v1/apps/{app}/start.
func (s *server) startApp(w http.ResponseWriter, r *http.Request) {
	s.setDesired(w, r, state.DesiredRunning)
}

func (s *server) setDesired(w http.ResponseWriter, r *http.Request, desired string) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	updated, err := s.store.UpdateApp(ctx, app, func(a *state.App) error {
		a.Desired = desired
		return nil
	})
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	s.kicker.Kick(app)
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    updated.Name,
		"desired": updated.Desired,
	})
}

// patchAppRequest is the PATCH /v1/apps/{app} body; nil fields are unchanged.
type patchAppRequest struct {
	MemoryMB   *int    `json:"memory_mb,omitempty"`
	CPUMilli   *int    `json:"cpu_milli,omitempty"`
	Port       *int    `json:"port,omitempty"`
	HealthPath *string `json:"health_path,omitempty"`
}

// patchApp implements PATCH /v1/apps/{app}: update app settings within bounds.
// Changes take effect on the next deployment.
func (s *server) patchApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	var body patchAppRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "请求体不是合法 JSON")
		return
	}
	// Validate bounds before touching the store so a bad value has no effect.
	if body.MemoryMB != nil && (*body.MemoryMB < minMemoryMB || *body.MemoryMB > maxMemoryMB) {
		writeError(w, http.StatusBadRequest, "invalid_memory", "内存需在 64..16384 MB 之间")
		return
	}
	if body.CPUMilli != nil && (*body.CPUMilli < minCPUMilli || *body.CPUMilli > maxCPUMilli) {
		writeError(w, http.StatusBadRequest, "invalid_cpu", "CPU 需在 100..16000 (毫核) 之间")
		return
	}
	if body.Port != nil && (*body.Port < 1 || *body.Port > 65535) {
		writeError(w, http.StatusBadRequest, "invalid_port", "port 必须在 1..65535 之间")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	updated, err := s.store.UpdateApp(ctx, app, func(a *state.App) error {
		if body.MemoryMB != nil {
			a.MemoryMB = *body.MemoryMB
		}
		if body.CPUMilli != nil {
			a.CPUMilli = *body.CPUMilli
		}
		if body.Port != nil {
			a.Port = *body.Port
		}
		if body.HealthPath != nil {
			a.HealthPath = *body.HealthPath
		}
		return nil
	})
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.buildAppView(ctx, updated, true))
}

// appLogs implements GET /v1/apps/{app}/logs?tail=N: the last N lines of the
// live container, secrets redacted. It returns 404 no_live_deployment when
// there is no live container.
func (s *server) appLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	tail := 100
	if raw := r.URL.Query().Get("tail"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			writeError(w, http.StatusBadRequest, "invalid_tail", "tail 必须是正整数")
			return
		}
		if v > 1000 {
			v = 1000
		}
		tail = v
	}

	a, err := s.store.GetApp(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if a.CurrentDeployment == "" {
		writeError(w, http.StatusNotFound, "no_live_deployment", "该应用没有正在运行的版本")
		return
	}
	name := runner.ContainerName(app, a.CurrentDeployment)
	lines, err := s.runner.Logs(ctx, app, name, tail)
	if err != nil {
		if errors.Is(err, runner.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no_live_deployment", "该应用没有正在运行的容器")
			return
		}
		s.log.Error("app logs", "app", app, "err", err)
		writeError(w, http.StatusServiceUnavailable, "runner_unavailable", "无法读取容器日志")
		return
	}
	// Redact secret env values (length >= 4) from the returned lines.
	lines = s.redactLogLines(ctx, app, lines)
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

// redactLogLines masks any secret env value (length >= 4) appearing in lines.
func (s *server) redactLogLines(ctx context.Context, app string, lines []string) []string {
	vars, err := s.store.ListEnv(ctx, app)
	if err != nil {
		return lines
	}
	var secrets []string
	for _, v := range vars {
		if v.Secret && len(v.Value) >= 4 {
			secrets = append(secrets, v.Value)
		}
	}
	if len(secrets) == 0 {
		return lines
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		for _, sv := range secrets {
			l = strings.ReplaceAll(l, sv, "******")
		}
		out[i] = l
	}
	return out
}

// status implements GET /v1/status.
func (s *server) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	runnerState := "ok"
	dockerVersion := ""
	if ping, err := s.runner.Ping(ctx); err != nil {
		runnerState = "unavailable"
	} else {
		dockerVersion = ping.ServerVersion
	}

	appCount := 0
	if apps, err := s.store.ListApps(ctx); err == nil {
		appCount = len(apps)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"api_version":    apiVersion,
		"runner":         runnerState,
		"docker_version": dockerVersion,
		"apps":           appCount,
	})
}

// decodeJSON decodes an optional JSON body. An empty body is treated as an
// empty object so callers may omit it.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}
