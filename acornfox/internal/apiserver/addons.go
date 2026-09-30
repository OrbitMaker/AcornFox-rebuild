package apiserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// addonView is the wire form of one add-on. Credentials and the connection
// URL are never included; the app receives them only as environment.
type addonView struct {
	Kind          string    `json:"kind"`
	Image         string    `json:"image"`
	EnvVar        string    `json:"env_var"`
	Host          string    `json:"host"` // in-network DNS name, e.g. af-shop-addon-postgres
	Port          int       `json:"port"` // in-network port; never published on the host
	VolumeName    string    `json:"volume_name"`
	ObservedState string    `json:"observed_state"` // running | starting | unhealthy | stopped | missing | unavailable
	CreatedAt     time.Time `json:"created_at"`
}

// addonApplyNote explains when the injected variable reaches the app: a new
// container is created only by a new deployment. A restart keeps the old env,
// and re-deploying an unchanged upload is deduplicated by source digest.
const addonApplyNote = "附加服务容器会立即启动；环境变量在下次部署新版本时注入应用（源码未变的重复部署会被去重，不会重建容器）"

func makeAddonView(a state.Addon, containers map[string]runner.ContainerInfo, observed bool) addonView {
	v := addonView{
		Kind:       a.Kind,
		Image:      a.Image,
		EnvVar:     a.EnvVar,
		Host:       runner.AddonContainerName(a.App, a.Kind),
		VolumeName: a.VolumeName,
		CreatedAt:  a.CreatedAt,
	}
	if spec, ok := runner.AddonSpecFor(a.Kind); ok {
		v.Port = spec.Port
	}
	switch c, ok := containers[v.Host]; {
	case !observed:
		v.ObservedState = "unavailable"
	case !ok:
		v.ObservedState = "missing"
	case c.Running && (c.Health == "starting" || c.Health == "unhealthy"):
		v.ObservedState = c.Health // not yet (or no longer) accepting connections
	case c.Running:
		v.ObservedState = "running"
	default:
		v.ObservedState = "stopped"
	}
	return v
}

// addonViews lists an app's add-ons with their observed container state.
// Runner errors degrade to observed_state="unavailable".
func (s *server) addonViews(ctx context.Context, app string) ([]addonView, error) {
	addons, err := s.store.ListAddons(ctx, app)
	if err != nil || len(addons) == 0 {
		return nil, err
	}
	containers := map[string]runner.ContainerInfo{}
	list, lerr := s.runner.ListContainers(ctx, app)
	for _, c := range list {
		if c.Role == runner.RoleAddon {
			containers[c.Name] = c
		}
	}
	out := make([]addonView, 0, len(addons))
	for _, a := range addons {
		out = append(out, makeAddonView(a, containers, lerr == nil))
	}
	return out, nil
}

// listAddons implements GET /v1/apps/{app}/addons.
func (s *server) listAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	views, err := s.addonViews(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if views == nil {
		views = []addonView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"addons": views})
}

// addAddon implements POST /v1/apps/{app}/addons {"kind": "postgres"|"mysql"|"redis"}.
// It records the add-on with fresh credentials and kicks the reconciler,
// which pulls the pinned image and starts the container on the app network.
func (s *server) addAddonLocked(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	var body struct {
		Kind string `json:"kind"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "请求体不是合法 JSON")
		return
	}
	spec, ok := runner.AddonSpecFor(body.Kind)
	if !ok || !state.ValidAddonKind(body.Kind) {
		writeError(w, http.StatusBadRequest, "invalid_addon_kind", "附加服务类型不合法：可选 postgres、mysql、redis")
		return
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}

	// Pre-check for a clear message; AddAddon re-checks in its transaction.
	envVar := state.AddonEnvVar(body.Kind)
	if existing, err := s.store.ListAddons(ctx, app); err == nil {
		for _, a := range existing {
			if a.Kind == body.Kind {
				writeError(w, http.StatusConflict, "addon_exists", "应用已有附加服务 "+a.Kind)
				return
			}
			if a.EnvVar == envVar {
				writeError(w, http.StatusConflict, "addon_env_conflict",
					"附加服务 "+a.Kind+" 已提供 "+envVar+"，同一应用只能有一个；请先删除它")
				return
			}
		}
	}

	retained, err := s.store.ListRemovedAddons(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	canRestore := false
	for _, a := range retained {
		if a.Kind == body.Kind {
			canRestore = true
		}
	}
	if !canRestore {
		volumes, err := s.runner.ListVolumes(ctx, app)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "runner_unavailable", "无法检查保留的数据卷，附加服务尚未添加，请稍后重试")
			return
		}
		for _, v := range volumes {
			if v.Name == runner.AddonVolumeName(app, body.Kind) {
				writeError(w, http.StatusConflict, "addon_data_orphaned", "检测到保留的数据卷 "+v.Name+"，但旧凭据记录缺失；不会生成新密码覆盖旧连接，请先恢复原 AcornFox 状态记录或人工恢复数据库访问")
				return
			}
		}
	}

	creds, err := state.NewAddonCredentials(app, body.Kind, runner.AddonContainerName(app, body.Kind), spec.Port)
	if err != nil {
		s.log.Error("addon credentials", "app", app, "kind", body.Kind, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "生成凭据失败")
		return
	}
	raw, err := creds.Marshal()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "生成凭据失败")
		return
	}
	addon := state.Addon{
		App:         app,
		Kind:        body.Kind,
		Image:       spec.Image,
		VolumeName:  runner.AddonVolumeName(app, body.Kind),
		Credentials: raw,
		EnvVar:      envVar,
	}
	reused, err := s.store.AddAddon(ctx, addon)
	if err != nil {
		if errors.Is(err, state.ErrConflict) {
			writeError(w, http.StatusConflict, "addon_exists", "应用已有同类附加服务或 "+envVar)
			return
		}
		s.mapStoreError(w, err)
		return
	}
	s.kicker.Kick(app)

	// Re-read for the stored CreatedAt; the container is not up yet.
	view := makeAddonView(addon, nil, true)
	if list, err := s.store.ListAddons(ctx, app); err == nil {
		for _, a := range list {
			if a.Kind == body.Kind {
				view = makeAddonView(a, nil, true)
			}
		}
	}

	deploymentID, err := s.redeployLive(ctx, app, r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "redeploy_failed", "附加服务已添加，但重新部署未提交；请运行 acornfox redeploy，勿重复添加附加服务")
		return
	}
	note := "已触发重新部署以注入连接变量"
	if deploymentID == "" {
		if reused {
			note = "已恢复附加服务，沿用保留的凭据和数据"
		} else {
			note = "首次部署时会自动注入连接变量"
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"addon":         view,
		"deployment_id": deploymentID,
		"reused":        reused,
		"note":          note,
	})
}

// removeAddon implements DELETE /v1/apps/{app}/addons/{kind}[?volumes=true].
// The record is deleted and the container removed; the data volume is kept
// unless volumes=true. It is idempotent: repeating it (for example after a
// volume removal failed) still cleans up the fixed container/volume names.
func (s *server) removeAddonLocked(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	kind := r.PathValue("kind")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if !state.ValidAddonKind(kind) {
		writeError(w, http.StatusBadRequest, "invalid_addon_kind", "附加服务类型不合法：可选 postgres、mysql、redis")
		return
	}
	raw := r.URL.Query().Get("volumes")
	if raw != "" && raw != "true" && raw != "false" {
		writeError(w, http.StatusBadRequest, "invalid_volumes", "volumes 必须为 true 或 false，默认保留数据卷")
		return
	}
	deleteVolume := raw == "true"
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}

	// Stop reconciliation from recreating the container, but retain credentials
	// until Docker confirms the volume has actually been deleted.
	removed := true
	if err := s.store.RemoveAddon(ctx, app, kind, false); err != nil {
		if !errors.Is(err, state.ErrNotFound) {
			s.mapStoreError(w, err)
			return
		}
		removed = false
		if !deleteVolume {
			writeError(w, http.StatusNotFound, "not_found", "应用没有附加服务 "+kind)
			return
		}
	}
	s.kicker.Kick(app)

	if deleteVolume {
		// The volume can only go once the container is gone.
		if err := s.runner.RemoveContainer(ctx, app, runner.AddonContainerName(app, kind)); err != nil {
			s.log.Error("remove addon container", "app", app, "kind", kind, "err", err)
			writeError(w, http.StatusServiceUnavailable, "runner_unavailable", "附加服务已删除，但数据卷未删除：执行器不可用，请稍后重试")
			return
		}
		if err := s.runner.RemoveVolume(ctx, app, runner.AddonVolumeName(app, kind)); err != nil {
			s.log.Error("remove addon volume", "app", app, "kind", kind, "err", err)
			writeError(w, http.StatusServiceUnavailable, "volume_remove_failed", "附加服务已停用，但数据卷未删除，凭据仍保留，请稍后重试")
			return
		}
		if err := s.store.RemoveAddon(ctx, app, kind, true); err != nil && !errors.Is(err, state.ErrNotFound) {
			s.mapStoreError(w, err)
			return
		}
	}

	var deploymentID string
	if removed || deleteVolume {
		var err error
		deploymentID, err = s.redeployLive(ctx, app, r.Header.Get("Idempotency-Key"))
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "redeploy_failed", "附加服务已移除，但重新部署未提交；请运行 acornfox redeploy 使连接变量变更生效")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kind":           kind,
		"removed":        removed,
		"deployment_id":  deploymentID,
		"volume_deleted": deleteVolume,
		"volume_name":    runner.AddonVolumeName(app, kind),
	})
}
