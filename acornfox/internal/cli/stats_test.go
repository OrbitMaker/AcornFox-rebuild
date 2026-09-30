package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/client"
)

func TestStatsHostHumanOutput(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	cpu, used, total := 45.2, uint64(2<<30), uint64(8<<30)
	h.api.hostMetricsFn = func(ctx context.Context) (client.HostMetrics, error) {
		return client.HostMetrics{Available: true, CPUPercent: &cpu, MemoryUsed: &used, MemoryTotal: &total}, nil
	}
	code, out, errOut := h.run("stats")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"CPU 使用率：45.20%", "内存使用：2.00 GB / 8.00 GB (25.0%)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestStatsHostUnavailable(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	code, out, _ := h.run("stats")
	if code != exitOK || !strings.Contains(out, "主机指标不可用") {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

// The positional app name must win over the app resolved from .acornfox.
func TestStatsAppUsesPositionalName(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	var gotApp string
	h.api.appMetricsFn = func(ctx context.Context, app string) (client.AppMetrics, error) {
		gotApp = app
		return client.AppMetrics{App: app, CPUPercent: 1.5, MemoryUsageMB: 128, MemoryLimitMB: 512}, nil
	}
	code, out, errOut := h.run("stats", "shop")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if gotApp != "shop" {
		t.Fatalf("queried app %q, want shop", gotApp)
	}
	if !strings.Contains(out, "内存使用：128.00 MB / 512.00 MB (25.0%)") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

// A zero memory limit must not divide by zero.
func TestStatsAppNoMemoryLimit(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.api.appMetricsFn = func(ctx context.Context, app string) (client.AppMetrics, error) {
		return client.AppMetrics{App: app, MemoryUsageMB: 64}, nil
	}
	_, out, _ := h.run("stats", "shop")
	if !strings.Contains(out, "（无限制）") || strings.Contains(out, "NaN") || strings.Contains(out, "Inf") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestStatsAppJSON(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.api.appMetricsFn = func(ctx context.Context, app string) (client.AppMetrics, error) {
		return client.AppMetrics{App: app, CPUPercent: 12.3, MemoryUsageMB: 256, MemoryLimitMB: 512, PIDs: 7}, nil
	}
	code, out, _ := h.run("--json", "stats", "shop")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid json %q: %v", out, err)
	}
	if got["app"] != "shop" || got["cpu_percent"] != 12.3 || got["memory_limit_mb"] != 512.0 {
		t.Fatalf("unexpected json: %v", got)
	}
}

func TestStatsRejectsExtraArgs(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if code, _, _ := h.run("stats", "a", "b"); code != exitUsage {
		t.Fatalf("exit %d, want usage error", code)
	}
}
