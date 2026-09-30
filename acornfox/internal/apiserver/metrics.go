package apiserver

import (
	"errors"
	"net/http"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

func (s *server) getHostMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.hostMetrics.Host(r.Context()))
}

func (s *server) getAppMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, 400, "invalid_app", "应用名不合法")
		return
	}
	a, err := s.store.GetApp(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if a.CurrentDeployment == "" {
		writeJSON(w, 200, map[string]any{"app": app, "available": false, "observed_state": "missing"})
		return
	}
	name := runner.ContainerName(app, a.CurrentDeployment)
	containers, err := s.runner.ListContainers(ctx, app)
	if err != nil {
		writeError(w, 503, "runner_unavailable", "无法读取容器指标，请稍后重试")
		return
	}
	observed := "missing"
	running := false
	for _, c := range containers {
		if c.Name == name && c.App == app && c.Role == runner.RoleApp {
			observed = c.State
			running = c.Running && !c.Restarting
			break
		}
	}
	if !running {
		writeJSON(w, 200, map[string]any{"app": app, "available": false, "observed_state": observed})
		return
	}
	stats, err := s.runner.ContainerStats(ctx, app, name)
	if errors.Is(err, runner.ErrStopped) || errors.Is(err, runner.ErrNotFound) {
		writeJSON(w, 200, map[string]any{"app": app, "available": false, "observed_state": "stopped"})
		return
	}
	if err != nil {
		writeError(w, 503, "runner_unavailable", "无法读取容器指标，请稍后重试")
		return
	}
	writeJSON(w, 200, map[string]any{
		"app": app, "available": true, "observed_state": "running",
		"cpu_percent": stats.CPUPercent, "cpu_available": stats.CPUAvailable,
		"memory_usage_mb": stats.MemoryUsageMB, "memory_limit_mb": stats.MemoryLimitMB,
		"network_rx_mb": stats.NetworkRxMB, "network_tx_mb": stats.NetworkTxMB, "pids": stats.PIDs,
	})
}
