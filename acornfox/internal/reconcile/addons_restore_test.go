package reconcile

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

func TestSoftDeletedAddonConvergesWithRealStore(t *testing.T) {
	ctx := context.Background()
	s, err := state.Open(state.Config{Path: filepath.Join(t.TempDir(), "af.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	app, _, err := s.EnsureApp(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := runner.AddonSpecFor(state.AddonPostgres)
	creds, err := state.NewAddonCredentials(app.Name, state.AddonPostgres, runner.AddonContainerName(app.Name, state.AddonPostgres), spec.Port)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := creds.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a := state.Addon{App: app.Name, Kind: state.AddonPostgres, Image: spec.Image,
		VolumeName: runner.AddonVolumeName(app.Name, state.AddonPostgres), Credentials: raw, EnvVar: state.AddonEnvVar(state.AddonPostgres)}
	if _, err := s.AddAddon(ctx, a); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.rec.cfg.Store = s
	converge := func() {
		t.Helper()
		addons, err := s.ListAddons(ctx, app.Name)
		if err != nil {
			t.Fatal(err)
		}
		h.rec.reconcileAddons(ctx, app, addons)
	}
	name := runner.AddonContainerName(app.Name, state.AddonPostgres)
	converge()
	if !h.runner.hasContainer(name) || !h.runner.hasVolume(a.VolumeName) {
		t.Fatal("initial convergence did not create the add-on and data volume")
	}
	if err := s.RemoveAddon(ctx, app.Name, state.AddonPostgres, false); err != nil {
		t.Fatal(err)
	}
	converge()
	if h.runner.hasContainer(name) || !h.runner.hasVolume(a.VolumeName) {
		t.Fatal("soft deletion must remove the container and retain the data volume")
	}
	if reused, err := s.AddAddon(ctx, a); err != nil || !reused {
		t.Fatalf("restore: reused=%v err=%v", reused, err)
	}
	converge()
	if !h.runner.hasContainer(name) || !h.runner.hasVolume(a.VolumeName) {
		t.Fatal("restoration must recreate the container on its existing volume")
	}
	reqs := h.runner.requestsFor(runner.AddonDeploymentID(state.AddonPostgres))
	if len(reqs) != 2 || reqs[0].Env["POSTGRES_PASSWORD"] != reqs[1].Env["POSTGRES_PASSWORD"] {
		t.Fatal("restoration changed the database password")
	}
}
