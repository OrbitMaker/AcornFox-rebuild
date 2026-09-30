package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

type metricRunner struct {
	*fakeRunner
	stats    runner.StatsResponse
	statsErr error
	calls    int
}

func (r *metricRunner) ContainerStats(context.Context, string, string) (runner.StatsResponse, error) {
	r.calls++
	return r.stats, r.statsErr
}

func metricServer(t *testing.T) (http.Handler, *fakeStore, *metricRunner) {
	t.Helper()
	store := newFakeStore()
	_, _, _ = store.EnsureApp(context.Background(), "shop")
	_, _ = store.UpdateApp(context.Background(), "shop", func(a *state.App) error { a.CurrentDeployment = "0123456789ab"; return nil })
	run := &metricRunner{fakeRunner: newFakeRunner(), stats: runner.StatsResponse{CPUAvailable: true, CPUPercent: 12.5, MemoryUsageMB: 64, MemoryLimitMB: 0}}
	run.containers["shop"] = []runner.ContainerInfo{{App: "shop", Name: runner.ContainerName("shop", "0123456789ab"), Role: runner.RoleApp, Running: true, State: "running"}}
	return New(Config{Store: store, Kicker: &fakeKicker{}, Runner: run, UploadDir: t.TempDir()}), store, run
}

func TestMetricsRunningAndUnlimitedMemory(t *testing.T) {
	h, _, run := metricServer(t)
	w := do(t, h, "GET", "/v1/metrics/apps/shop", nil, nil)
	var view map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || run.calls != 1 || view["available"] != true || view["cpu_available"] != true || view["cpu_percent"] != 12.5 || view["memory_limit_mb"] != float64(0) {
		t.Fatalf("status=%d view=%v calls=%d", w.Code, view, run.calls)
	}
}

func TestMetricsStoppedMissingAndUnavailable(t *testing.T) {
	h, _, run := metricServer(t)
	run.containers["shop"][0].Running = false
	run.containers["shop"][0].State = "exited"
	w := do(t, h, "GET", "/v1/metrics/apps/shop", nil, nil)
	if w.Code != 200 || run.calls != 0 || !strings.Contains(w.Body.String(), `"available":false`) || strings.Contains(w.Body.String(), "cpu_percent") {
		t.Fatalf("stopped=%d %s calls=%d", w.Code, w.Body, run.calls)
	}
	run.containers["shop"] = nil
	w = do(t, h, "GET", "/v1/metrics/apps/shop", nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"observed_state":"missing"`) {
		t.Fatalf("missing=%d %s", w.Code, w.Body)
	}
	run.listErr = errors.New("runner down")
	w = do(t, h, "GET", "/v1/metrics/apps/shop", nil, nil)
	if w.Code != 503 || strings.Contains(w.Body.String(), "cpu_percent") {
		t.Fatalf("unavailable=%d %s", w.Code, w.Body)
	}
}

func TestMetricsStopRaceDoesNotReturnMadeUpValues(t *testing.T) {
	h, _, run := metricServer(t)
	run.statsErr = runner.ErrStopped
	w := do(t, h, "GET", "/v1/metrics/apps/shop", nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) || strings.Contains(w.Body.String(), "cpu_percent") {
		t.Fatalf("race=%d %s", w.Code, w.Body)
	}
}
