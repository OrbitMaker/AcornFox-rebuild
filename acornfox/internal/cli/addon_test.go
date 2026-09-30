package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/client"
)

func addonHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	return h
}

func TestAddAddonWithAppFlag(t *testing.T) {
	h := addonHarness(t)
	var gotApp, gotKind string
	h.api.addAddonFn = func(_ context.Context, app, kind string) (client.AddonResult, error) {
		gotApp, gotKind = app, kind
		return client.AddonResult{
			Addon: client.Addon{Kind: kind, Image: "postgres:16-alpine", EnvVar: "DATABASE_URL",
				Host: "af-shop-addon-postgres", Port: 5432},
			Note: "首次部署时会自动注入连接变量",
		}, nil
	}
	code, out, errOut := h.run("add", "postgres", "--app", "shop")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if gotApp != "shop" || gotKind != "postgres" {
		t.Fatalf("called with %q %q", gotApp, gotKind)
	}
	if !strings.Contains(out, "DATABASE_URL") || (!strings.Contains(out, "下次部署") && !strings.Contains(out, "首次部署")) {
		t.Fatalf("output must name the env var and when it applies: %s", out)
	}
}

func TestAddAddonRejectsUnknownKind(t *testing.T) {
	h := addonHarness(t)
	called := false
	h.api.addAddonFn = func(context.Context, string, string) (client.AddonResult, error) {
		called = true
		return client.AddonResult{}, nil
	}
	if code, _, _ := h.run("add", "mongo", "--app", "shop"); code != exitUsage {
		t.Fatalf("exit = %d", code)
	}
	if code, _, _ := h.run("add", "--app", "shop"); code != exitUsage {
		t.Fatalf("missing kind: exit = %d", code)
	}
	if called {
		t.Fatal("API must not be called for a usage error")
	}
}

func TestRemoveAddonKeepsVolumeUnlessFlag(t *testing.T) {
	h := addonHarness(t)
	var gotDelete []bool
	h.api.removeAddonFn = func(_ context.Context, app, kind string, del bool) (client.AddonRemoval, error) {
		gotDelete = append(gotDelete, del)
		return client.AddonRemoval{Kind: kind, Removed: true, VolumeDeleted: del, VolumeName: "af-shop-addon-redis-data"}, nil
	}
	code, out, _ := h.run("remove", "redis", "--app", "shop")
	if code != exitOK || !strings.Contains(out, "已保留") {
		t.Fatalf("default remove: %d %s", code, out)
	}
	// --volumes after the positional kind must still be honoured.
	code, out, _ = h.run("remove", "redis", "--volumes", "--app", "shop")
	if code != exitOK || !strings.Contains(out, "数据卷") || strings.Contains(out, "已保留") {
		t.Fatalf("remove --volumes: %d %s", code, out)
	}
	if len(gotDelete) != 2 || gotDelete[0] || !gotDelete[1] {
		t.Fatalf("deleteVolume flags = %v", gotDelete)
	}
}

func TestAddonsListJSON(t *testing.T) {
	h := addonHarness(t)
	h.api.addonsFn = func(context.Context, string) ([]client.Addon, error) {
		return []client.Addon{{Kind: "redis", EnvVar: "REDIS_URL", ObservedState: "running"}}, nil
	}
	code, out, _ := h.run("--json", "addons", "--app", "shop")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	m := decodeJSON(t, out)
	list, ok := m["addons"].([]any)
	if !ok || len(list) != 1 || list[0].(map[string]any)["observed_state"] != "running" {
		t.Fatalf("json = %v", m)
	}
}
