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

func TestDeleteAppKeepsDockerVolumesByDefault(t *testing.T) {
	h, st, _, rn := addonTestServer(t)
	rn.containers["shop"] = []runner.ContainerInfo{{Name: "af-shop-0123456789ab", App: "shop", Role: runner.RoleApp}}
	w := do(t, h, http.MethodDelete, "/v1/apps/shop", nil, nil)
	if w.Code != http.StatusOK || len(rn.removedContainers) != 1 || len(rn.removedVolumes) != 0 {
		t.Fatalf("delete status=%d containers=%v volumes=%v", w.Code, rn.removedContainers, rn.removedVolumes)
	}
	if _, err := st.GetApp(context.Background(), "shop"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("app must be removed: %v", err)
	}
}

func TestDeleteAppIncludesRetainedAndOrphanVolumes(t *testing.T) {
	h, st, _, rn := addonTestServer(t)
	if w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil); w.Code != http.StatusCreated {
		t.Fatalf("add: %s", w.Body)
	}
	if err := st.RemoveAddon(context.Background(), "shop", "postgres", false); err != nil {
		t.Fatal(err)
	}
	st.volumes["shop"] = []state.Volume{{App: "shop", VolumeName: "af-shop-1", Path: "/data"}}
	rn.volumes = map[string][]runner.VolumeInfo{"shop": {{App: "shop", Name: "af-shop-orphan"}}}
	w := do(t, h, http.MethodDelete, "/v1/apps/shop?volumes=true", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	got := map[string]bool{}
	for _, name := range rn.removedVolumes {
		got[name] = true
	}
	if len(got) != 3 || !got["af-shop-1"] || !got["af-shop-addon-postgres-data"] || !got["af-shop-orphan"] {
		t.Fatalf("removed volumes = %v", got)
	}
}

func TestDeleteAppFailureKeepsRecordForRetry(t *testing.T) {
	for _, failure := range []string{"list", "container", "volume", "volume-list"} {
		t.Run(failure, func(t *testing.T) {
			h, st, _, rn := addonTestServer(t)
			st.volumes["shop"] = []state.Volume{{App: "shop", VolumeName: "af-shop-1", Path: "/data"}}
			rn.containers["shop"] = []runner.ContainerInfo{{Name: "af-shop-0123456789ab", App: "shop"}}
			switch failure {
			case "list":
				rn.listErr = errRunnerDown
			case "container":
				rn.removeContainerErr = errRunnerDown
			case "volume":
				rn.removeVolumeErr = errors.New("in use")
			case "volume-list":
				rn.volumeListErr = errRunnerDown
			}
			w := do(t, h, http.MethodDelete, "/v1/apps/shop?volumes=true", nil, nil)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("delete status=%d body=%s", w.Code, w.Body)
			}
			if _, err := st.GetApp(context.Background(), "shop"); err != nil {
				t.Fatalf("failed delete must keep record: %v", err)
			}
			rn.listErr, rn.removeContainerErr, rn.removeVolumeErr, rn.volumeListErr = nil, nil, nil, nil
			w = do(t, h, http.MethodDelete, "/v1/apps/shop?volumes=true", nil, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("retry status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}

func TestAddonRestoresCredentialsButRejectsOrphanData(t *testing.T) {
	h, st, _, rn := addonTestServer(t)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	original := string(st.addons["shop/postgres"].Credentials)
	do(t, h, http.MethodDelete, "/v1/apps/shop/addons/postgres", nil, nil)
	rn.volumes = map[string][]runner.VolumeInfo{"shop": {{Name: "af-shop-addon-postgres-data", App: "shop"}}}
	w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"reused":true`) || string(st.addons["shop/postgres"].Credentials) != original {
		t.Fatalf("restore failed: %d %s", w.Code, w.Body)
	}
	delete(st.addons, "shop/postgres")
	w = do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "addon_data_orphaned") {
		t.Fatalf("orphan must not get new credentials: %d %s", w.Code, w.Body)
	}
}

func TestAddonFailedVolumeDeletionRetainsCredentials(t *testing.T) {
	h, st, _, rn := addonTestServer(t)
	do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	original := string(st.addons["shop/postgres"].Credentials)
	rn.removeVolumeErr = errors.New("in use")
	w := do(t, h, http.MethodDelete, "/v1/apps/shop/addons/postgres?volumes=true", nil, nil)
	if w.Code != http.StatusServiceUnavailable || string(st.removedAddons["shop/postgres"].Credentials) != original {
		t.Fatalf("failed deletion lost retained credentials: %d %s", w.Code, w.Body)
	}
}

func TestAddonAutomaticallyRedeploysLiveVersion(t *testing.T) {
	h, st, _, _ := addonTestServer(t)
	ctx := context.Background()
	live, _, err := st.CreateDeployment(ctx, state.NewDeployment{App: "shop", SourceKind: state.SourceImage, SourceRef: "sha256:test", SourceDigest: "sha256:test"})
	if err != nil {
		t.Fatal(err)
	}
	st.deployments[live.ID].ImageID, st.deployments[live.ID].Status = "sha256:test", state.StatusLive
	a := st.apps["shop"]
	a.CurrentDeployment = live.ID
	st.apps["shop"] = a
	w := do(t, h, http.MethodPost, "/v1/apps/shop/addons", []byte(`{"kind":"postgres"}`), nil)
	var result struct {
		DeploymentID string `json:"deployment_id"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.DeploymentID == "" || result.DeploymentID == live.ID {
		t.Fatalf("add must create a new deployment even for the same image: %d %s", w.Code, w.Body)
	}
	w = do(t, h, http.MethodDelete, "/v1/apps/shop/addons/postgres", nil, nil)
	var removal struct {
		DeploymentID string `json:"deployment_id"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &removal) != nil || removal.DeploymentID == "" || removal.DeploymentID == result.DeploymentID {
		t.Fatalf("remove must create a new deployment: %d %s", w.Code, w.Body)
	}
}
