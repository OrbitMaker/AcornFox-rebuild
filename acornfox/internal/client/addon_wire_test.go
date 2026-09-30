package client_test

// End-to-end wire test for N4.2 add-ons: the real client against the real API
// server backed by the real SQLite store, so request paths, bodies and reply
// shapes cannot drift apart between packages.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/apiserver"
	"github.com/acornfox/acornfox/internal/client"
	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

type nopKicker struct{}

func (nopKicker) Kick(string) {}

// wireRunner records the add-on cleanup calls; every other method is inert.
type wireRunner struct {
	removedVolumes []string
}

func (*wireRunner) Ping(context.Context) (runner.PingResponse, error) {
	return runner.PingResponse{}, nil
}
func (*wireRunner) ListContainers(context.Context, string) ([]runner.ContainerInfo, error) {
	return nil, nil
}
func (*wireRunner) ListVolumes(context.Context, string) ([]runner.VolumeInfo, error) {
	return nil, nil
}
func (*wireRunner) Logs(context.Context, string, string, int) ([]string, error) { return nil, nil }
func (*wireRunner) ContainerStats(context.Context, string, string) (runner.StatsResponse, error) {
	return runner.StatsResponse{}, nil
}
func (*wireRunner) StopContainer(context.Context, string, string) error { return nil }
func (*wireRunner) StartContainer(context.Context, string, string) (runner.ContainerInfo, error) {
	return runner.ContainerInfo{}, nil
}
func (*wireRunner) RemoveContainer(context.Context, string, string) error { return nil }
func (*wireRunner) RemoveNetwork(context.Context, string) error           { return nil }
func (w *wireRunner) RemoveVolume(_ context.Context, _, name string) error {
	w.removedVolumes = append(w.removedVolumes, name)
	return nil
}

func TestAddonWireEndToEnd(t *testing.T) {
	ctx := context.Background()
	st, err := state.Open(state.Config{Path: filepath.Join(t.TempDir(), "af.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, _, err := st.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	rn := &wireRunner{}
	ts := httptest.NewServer(apiserver.New(apiserver.Config{
		Store: st, Kicker: nopKicker{}, Runner: rn, UploadDir: t.TempDir(), PublicHost: "127.0.0.1",
	}))
	defer ts.Close()
	c, err := client.Connect(ctx, client.Target{URL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	res, err := c.AddAddon(ctx, "shop", "postgres")
	if err != nil {
		t.Fatalf("AddAddon: %v", err)
	}
	if res.Addon.Kind != "postgres" || res.Addon.EnvVar != "DATABASE_URL" || res.Addon.Host != "af-shop-addon-postgres" ||
		res.Addon.Port != 5432 || res.Addon.Image != "postgres:16-alpine" || res.Note == "" {
		t.Fatalf("AddAddon result = %+v", res)
	}

	// Second DATABASE_URL provider is refused with a server error the CLI can show.
	_, err = c.AddAddon(ctx, "shop", "mysql")
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != http.StatusConflict {
		t.Fatalf("mysql after postgres: %v", err)
	}

	if _, err := c.AddAddon(ctx, "shop", "redis"); err != nil {
		t.Fatalf("AddAddon redis: %v", err)
	}
	list, err := c.Addons(ctx, "shop")
	if err != nil || len(list) != 2 || list[0].Kind != "postgres" || list[1].Kind != "redis" || list[1].EnvVar != "REDIS_URL" {
		t.Fatalf("Addons = %+v, %v", list, err)
	}
	if list[0].ObservedState != "missing" { // the fake runner reports no containers
		t.Fatalf("observed state = %q", list[0].ObservedState)
	}

	// The stored credentials hold the documented URL shape.
	stored, _ := st.ListAddons(ctx, "shop")
	cr, err := stored[0].DecodeCredentials()
	if err != nil || !strings.HasPrefix(cr.URL, "postgresql://acornfox_shop:") || !strings.HasSuffix(cr.URL, "@af-shop-addon-postgres:5432/acornfox_shop") {
		t.Fatalf("stored url = %q (%v)", cr.URL, err)
	}

	rm, err := c.RemoveAddon(ctx, "shop", "redis", false)
	if err != nil || !rm.Removed || rm.VolumeDeleted || rm.VolumeName != "af-shop-addon-redis-data" {
		t.Fatalf("RemoveAddon keep = %+v, %v", rm, err)
	}
	if len(rn.removedVolumes) != 0 {
		t.Fatalf("volume removed without --volumes: %v", rn.removedVolumes)
	}
	rm, err = c.RemoveAddon(ctx, "shop", "postgres", true)
	if err != nil || !rm.VolumeDeleted || len(rn.removedVolumes) != 1 || rn.removedVolumes[0] != "af-shop-addon-postgres-data" {
		t.Fatalf("RemoveAddon --volumes = %+v, %v, %v", rm, err, rn.removedVolumes)
	}
	if list, _ := c.Addons(ctx, "shop"); len(list) != 0 {
		t.Fatalf("addons left: %+v", list)
	}
}
