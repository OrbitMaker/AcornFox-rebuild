package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/acornfox/acornfox/internal/state"
)

// maxErrorReadTail bounds how much of an over-size upload body we drain before
// closing; we do not need to read the whole thing to return 413.
const eventsPageLimit = 500

// createDeployment implements POST /v1/apps/{app}/deployments.
//
// Flow: validate app name -> EnsureApp -> optionally UpdateApp from query
// params -> stream body to a temp file (0640) computing sha256 ->
// CreateDeployment -> on new deployment rename temp file to <id>.tar.gz, on a
// duplicate delete the temp file -> Kick -> 202 (new) or 200 (duplicate).
func (s *server) createDeployment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法：需匹配 ^[a-z][a-z0-9-]{0,38}[a-z0-9]$")
		return
	}

	// A JSON body selects an image or git source; the default is a tar.gz upload.
	if isJSONDeploy(r) {
		s.createDeploymentJSON(w, r, app)
		return
	}

	// Parse optional port / health_path before touching the store so a bad
	// value fails fast without side effects.
	port, hasPort, perr := parsePort(r.URL.Query().Get("port"))
	if perr != nil {
		writeError(w, http.StatusBadRequest, "invalid_port", perr.Error())
		return
	}
	healthPath := r.URL.Query().Get("health_path")

	if _, _, err := s.store.EnsureApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}

	if hasPort || healthPath != "" {
		if _, err := s.store.UpdateApp(ctx, app, func(a *state.App) error {
			if hasPort {
				a.Port = port
			}
			if healthPath != "" {
				a.HealthPath = healthPath
			}
			return nil
		}); err != nil {
			s.mapStoreError(w, err)
			return
		}
	}

	// Stream to a temp file with a size cap and running sha256.
	tmp, err := os.CreateTemp(s.uploadDir, "upload-*.part")
	if err != nil {
		s.log.Error("create temp upload", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "无法创建上传临时文件")
		return
	}
	tmpName := tmp.Name()
	// Ensure cleanup on every error path; success paths set done=true.
	done := false
	defer func() {
		_ = tmp.Close()
		if !done {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o640); err != nil {
		s.log.Error("chmod temp upload", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "无法设置上传文件权限")
		return
	}

	hasher := sha256.New()
	limited := io.LimitReader(r.Body, s.maxUploadBytes+1)
	written, err := io.Copy(io.MultiWriter(tmp, hasher), limited)
	if err != nil {
		s.log.Error("stream upload", "err", err)
		writeError(w, http.StatusBadRequest, "upload_read_failed", "读取上传内容失败")
		return
	}
	if written > s.maxUploadBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "upload_too_large",
			"上传超过大小上限 "+strconv.FormatInt(s.maxUploadBytes, 10)+" 字节")
		return
	}
	if err := tmp.Sync(); err != nil {
		s.log.Error("sync upload", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "无法写入上传文件")
		return
	}
	digest := hex.EncodeToString(hasher.Sum(nil))

	dep, created, err := s.store.CreateDeployment(ctx, state.NewDeployment{
		App:          app,
		SourceKind:   state.SourceUpload,
		SourceRef:    tmpName, // provisional; rewritten below on the new-deployment path
		SourceDigest: digest,
		RequestKey:   r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.mapStoreError(w, err)
		return
	}

	if !created {
		// Duplicate submission: drop the temp file, return the existing row.
		done = true
		_ = os.Remove(tmpName)
		writeJSON(w, http.StatusOK, deploymentView(dep))
		return
	}

	// New deployment: give the upload its stable name <id>.tar.gz.
	finalName := filepath.Join(s.uploadDir, dep.ID+".tar.gz")
	if err := os.Rename(tmpName, finalName); err != nil {
		s.log.Error("rename upload", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "无法保存上传文件")
		return
	}
	done = true

	// Record the final path so the reconciler reads the right file.
	updated, err := s.store.UpdateDeployment(ctx, dep.ID, func(d *state.Deployment) error {
		d.SourceRef = finalName
		return nil
	})
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	dep = updated

	s.kicker.Kick(app)
	writeJSON(w, http.StatusAccepted, deploymentView(dep))
}

// rollback implements POST /v1/apps/{app}/rollback: create a new image-source
// deployment from the most recent retired deployment that still has an ImageID.
func (s *server) rollback(w http.ResponseWriter, r *http.Request) {
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

	deps, err := s.store.ListDeployments(ctx, app, 100)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	var target *state.Deployment
	for i := range deps {
		d := deps[i]
		if d.Status == state.StatusRetired && d.ImageID != "" {
			target = &deps[i]
			break // newest first, so the first match is the most recent
		}
	}
	if target == nil {
		writeError(w, http.StatusConflict, "no_rollback_target", "没有可回退的历史版本")
		return
	}

	dep, _, err := s.store.CreateDeployment(ctx, state.NewDeployment{
		App:          app,
		SourceKind:   state.SourceImage,
		SourceRef:    target.ImageID,
		SourceDigest: target.ImageID,
	})
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	s.kicker.Kick(app)
	writeJSON(w, http.StatusAccepted, deploymentView(dep))
}

// getDeployment implements GET /v1/deployments/{id}: the deployment plus its
// events, optionally filtered by ?after=<event id>.
func (s *server) getDeployment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	dep, err := s.store.GetDeployment(ctx, id)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}

	var after int64
	if raw := r.URL.Query().Get("after"); raw != "" {
		v, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "invalid_after", "after 必须是非负整数")
			return
		}
		after = v
	}

	events, err := s.store.ListEvents(ctx, dep.App, dep.ID, after, eventsPageLimit)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if events == nil {
		events = []state.Event{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"deployment": deploymentView(dep),
		"events":     events,
	})
}

// listDeployments implements GET /v1/apps/{app}/deployments?limit=N: the
// version history, newest first. limit is clamped to 1..100 (default 20).
func (s *server) listDeployments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 100 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit 必须在 1..100 之间")
			return
		}
		limit = v
	}
	if _, err := s.store.GetApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}
	deps, err := s.store.ListDeployments(ctx, app, limit)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if deps == nil {
		deps = []state.Deployment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deployments": deps})
}

// parsePort validates the optional ?port= query parameter.
func parsePort(raw string) (port int, ok bool, err error) {
	if raw == "" {
		return 0, false, nil
	}
	v, cerr := strconv.Atoi(raw)
	if cerr != nil {
		return 0, false, errors.New("port 必须是整数")
	}
	if v < 1 || v > 65535 {
		return 0, false, errors.New("port 必须在 1..65535 之间")
	}
	return v, true, nil
}
