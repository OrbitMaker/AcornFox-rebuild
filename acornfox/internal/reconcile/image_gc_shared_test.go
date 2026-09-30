package reconcile

import (
	"context"
	"fmt"
	"testing"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

func TestImageGCKeepsSharedImageReferencedByLiveRollbackOrPending(t *testing.T) {
	for _, reference := range []string{"live", "rollback", "pending"} {
		t.Run(reference, func(t *testing.T) {
			h := newHarness(t)
			app := baseApp("web")
			app.CurrentDeployment = "000000000006"
			h.store.putApp(app)
			shared := "sha256:shared-content"
			for seq := 1; seq <= 6; seq++ {
				id := fmt.Sprintf("%012x", seq)
				status := state.StatusRetired
				image := fmt.Sprintf("sha256:image-%d", seq)
				if seq == 6 {
					status = state.StatusLive
				}
				if seq == 1 || reference == "live" && seq == 6 || reference == "rollback" && seq == 3 {
					image = shared
				}
				h.store.putDeployment(state.Deployment{ID: id, App: "web", Seq: seq, Status: status, ImageID: image})
			}
			// Reusing an image does not change the original Docker deployment label.
			h.runner.images[shared] = runner.ImageInfo{ID: shared, App: "web", DeploymentID: "000000000001"}
			h.runner.images["sha256:unreferenced"] = runner.ImageInfo{ID: "sha256:unreferenced", App: "web", DeploymentID: "000000000002"}
			var pending []state.Deployment
			if reference == "pending" {
				pending = []state.Deployment{{ID: "000000000007", App: "web", Seq: 7, Status: state.StatusChecking, ImageID: shared}}
			}
			h.rec.appGC(context.Background(), "web", pending)
			if _, ok := h.runner.images[shared]; !ok {
				t.Fatalf("shared image referenced by %s was removed because of its old label", reference)
			}
			if _, ok := h.runner.images["sha256:unreferenced"]; ok {
				t.Fatal("unreferenced old image must still be collected")
			}
		})
	}
}
