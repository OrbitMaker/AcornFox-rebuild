package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/client"
)

func shortStopWait(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldInterval, oldTimeout := stopPollInterval, stopWaitTimeout
	stopPollInterval, stopWaitTimeout = time.Millisecond, timeout
	t.Cleanup(func() { stopPollInterval, stopWaitTimeout = oldInterval, oldTimeout })
}

// `stop` must not report success until the container is observed stopped.
func TestStopWaitsForObservedStopped(t *testing.T) {
	shortStopWait(t, time.Second)
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	stopped := false
	h.api.stopFn = func(ctx context.Context, app string) error { stopped = true; return nil }
	polls := 0
	h.api.appFn = func(ctx context.Context, app string) (client.App, error) {
		polls++
		state := "running"
		if stopped && polls >= 3 {
			state = "stopped"
		}
		return client.App{Name: app, ObservedState: state}, nil
	}
	code, out, errOut := h.run("--app", "shop", "stop")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if polls < 3 || !strings.Contains(out, "已停止应用 shop") {
		t.Fatalf("polls %d, output %q", polls, out)
	}
}

func TestStopTimeoutSaysStillStopping(t *testing.T) {
	shortStopWait(t, 20*time.Millisecond)
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	h.api.appFn = func(ctx context.Context, app string) (client.App, error) {
		return client.App{Name: app, ObservedState: "running"}, nil
	}
	code, out, errOut := h.run("--app", "shop", "stop")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if strings.Contains(out, "已停止应用") || !strings.Contains(out, "仍在停止中（当前状态：running）") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestHelpPrintsUsage(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		h := newHarness(t)
		code, out, _ := h.run(arg)
		if code != exitOK || !strings.Contains(out, "用法：acornfox") || !strings.Contains(out, "public-console") {
			t.Fatalf("%s: exit %d, output %q", arg, code, out)
		}
	}
}
