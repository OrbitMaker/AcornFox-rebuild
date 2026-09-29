package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"regexp"

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
