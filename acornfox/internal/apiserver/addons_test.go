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

func addonTestServer(t *testing.T) (http.Handler, *fakeStore, *fakeKicker, *fakeRunner) {
	t.Helper()
	h, st, k, rn, _ := newTestServer(t)
	if _, _, err := st.EnsureApp(context.Background(), "shop"); err != nil {
		t.Fatal(err)
	}
	return h, st, k, rn
}

func TestAddAddonCreatesRecordWithPinnedSpec(t *testing.T) {
	h, st, k, _ := addonTestServer(t)
	w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	var resp struct {
		Addon   addonView `json:"addon"`
		Applied bool      `json:"applied"`
		Note    string    `json:"note"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	a := resp.Addon
	if a.Kind != "postgres" || a.Image != "postgres:16-alpine" || a.EnvVar != "DATABASE_URL" ||
		a.Host != "af-shop-addon-postgres" || a.Port != 5432 || a.VolumeName != "af-shop-addon-postgres-data" {
		t.Fatalf("addon view = %+v", a)
	}
	if resp.Applied || resp.Note == "" {
		t.Fatalf("response must say the env applies on next deploy: %s", body)
	}
	if len(k.kicks) == 0 || k.kicks[len(k.kicks)-1] != "shop" {
		t.Fatalf("reconciler not kicked: %v", k.kicks)
	}

	stored, _ := st.ListAddons(context.Background(), "shop")
	if len(stored) != 1 {
		t.Fatalf("stored = %+v", stored)
	}
	creds, err := stored[0].DecodeCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(creds.URL, "postgresql://acornfox_shop:") || !strings.Contains(creds.URL, "@af-shop-addon-postgres:5432/acornfox_shop") {
		t.Fatalf("url = %q", creds.URL)
	}
	// Secrets never leave the server.
	if strings.Contains(body, creds.Password) || strings.Contains(body, "postgresql://") {
		t.Fatalf("response leaks credentials: %s", body)
	}
}

func TestAddAddonRejectsBadKindAndConflicts(t *testing.T) {
	h, _, _, _ := addonTestServer(t)

	if w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"mongo"}`), nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad kind: %d %s", w.Code, w.Body)
	}
	if w := do(t, h, http.MethodPost, "/v1/apps/ghost/addons", []byte(`{"kind":"redis"}`), nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing app: %d %s", w.Code, w.Body)
	}
	if w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil); w.Code != http.StatusCreated {
		t.Fatalf("first add: %d %s", w.Code, w.Body)
	}
	w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "addon_exists") {
		t.Fatalf("duplicate: %d %s", w.Code, w.Body)
	}
	w = do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"mysql"}`), nil)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "addon_env_conflict") {
		t.Fatalf("second DATABASE_URL: %d %s", w.Code, w.Body)
	}
	if w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"redis"}`), nil); w.Code != http.StatusCreated {
		t.Fatalf("redis alongside postgres: %d %s", w.Code, w.Body)
	}
}

func TestListAddonsShowsObservedState(t *testing.T) {
	h, _, _, rn := addonTestServer(t)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"redis"}`), nil)
	rn.containers["shop"] = []runner.ContainerInfo{
		{Name: "af-shop-addon-postgres", App: "shop", Role: runner.RoleAddon, Running: true},
	}

	w := do(t, h, http.MethodGet, "/v1/apps/shop/addons", nil, nil)
	var resp struct {
		Addons []addonView `json:"addons"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.Addons) != 2 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	states := map[string]string{}
	for _, a := range resp.Addons {
		states[a.Kind] = a.ObservedState
	}
	if states["postgres"] != "running" || states["redis"] != "missing" {
		t.Fatalf("states = %v", states)
	}

	// App detail includes the same views; runner failure degrades to unavailable.
	rn.listErr = errRunnerDown
	w = do(t, h, http.MethodGet, "/v1/apps/shop", nil, nil)
	var app struct {
		Addons []addonView `json:"addons"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &app); err != nil || len(app.Addons) != 2 || app.Addons[0].ObservedState != "unavailable" {
		t.Fatalf("detail addons: %s", w.Body)
	}
}

func TestRemoveAddonKeepsVolumeByDefault(t *testing.T) {
	h, st, k, rn := addonTestServer(t)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"redis"}`), nil)
	kicks := len(k.kicks)

	w := do(t, h, http.MethodDelete, "/v1/apps/shop/addons/redis", nil, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"volume_deleted":false`) {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	if list, _ := st.ListAddons(context.Background(), "shop"); len(list) != 0 {
		t.Fatalf("record not removed: %+v", list)
	}
	if len(rn.removedVolumes) != 0 || len(rn.removedContainers) != 0 {
		t.Fatalf("default remove must leave Docker cleanup to the reconciler and keep the volume: %+v %+v", rn.removedContainers, rn.removedVolumes)
	}
	if len(k.kicks) != kicks+1 {
		t.Fatal("reconciler not kicked")
	}
	if w := do(t, h, http.MethodDelete, "/v1/apps/shop/addons/redis", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("second remove: %d %s", w.Code, w.Body)
	}
	if w := do(t, h, http.MethodDelete, "/v1/apps/shop/addons/mongo", nil, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad kind: %d %s", w.Code, w.Body)
	}
}

func TestRemoveAddonWithVolumes(t *testing.T) {
	h, _, _, rn := addonTestServer(t)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)

	w := do(t, h, http.MethodDelete, "/v1/apps/shop/addons/postgres?volumes=true", nil, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"volume_deleted":true`) {
		t.Fatalf("remove with volumes: %d %s", w.Code, w.Body)
	}
	if len(rn.removedContainers) != 1 || rn.removedContainers[0] != "af-shop-addon-postgres" ||
		len(rn.removedVolumes) != 1 || rn.removedVolumes[0] != "af-shop-addon-postgres-data" {
		t.Fatalf("docker cleanup: %+v %+v", rn.removedContainers, rn.removedVolumes)
	}

	// A failed volume removal is reported, and retrying still works although
	// the record is already gone.
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	rn.removeVolumeErr = errors.New("volume in use")
	if w := do(t, h, http.MethodDelete, "/v1/apps/shop/addons/postgres?volumes=true", nil, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed volume removal: %d %s", w.Code, w.Body)
	}
	rn.removeVolumeErr = nil
	w = do(t, h, http.MethodDelete, "/v1/apps/shop/addons/postgres?volumes=true", nil, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"removed":false`) {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
}

func TestAddonObservedStateReflectsHealth(t *testing.T) {
	h, _, _, rn := addonTestServer(t)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	for _, health := range []string{"starting", "unhealthy", "healthy"} {
		rn.containers["shop"] = []runner.ContainerInfo{
			{Name: "af-shop-addon-postgres", App: "shop", Role: runner.RoleAddon, Running: true, Health: health},
		}
		w := do(t, h, http.MethodGet, "/v1/apps/shop/addons", nil, nil)
		var resp struct {
			Addons []addonView `json:"addons"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Addons) != 1 {
			t.Fatalf("list: %s", w.Body)
		}
		want := health
		if health == "healthy" {
			want = "running"
		}
		if resp.Addons[0].ObservedState != want {
			t.Fatalf("health %s: observed_state = %q, want %q", health, resp.Addons[0].ObservedState, want)
		}
	}
}

// Guard against the kinds drifting apart between the API and the store.
func TestAddonKindsAccepted(t *testing.T) {
	for _, k := range runner.AddonKinds() {
		if !state.ValidAddonKind(k) {
			t.Fatalf("runner kind %q rejected by state", k)
		}
	}
}
