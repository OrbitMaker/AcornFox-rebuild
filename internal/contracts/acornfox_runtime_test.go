package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestProjectAcornFoxRuntimeReleaseFactBindsExactlyOneImmutableService(t *testing.T) {
	image := domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}
	release, err := domain.NewRelease("app_1", "sg_1", 1, "sha256:"+strings.Repeat("b", 64), map[string]domain.ImageDigest{"web": image}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	resources := AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 128 << 20, DiskReservationBytes: 256 << 20, PIDs: 64}
	first, err := ProjectAcornFoxRuntimeReleaseFact(*release, "env_1", resources, 8080, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProjectAcornFoxRuntimeReleaseFact(*release, "env_1", resources, 8080, time.Unix(2, 0).UTC())
	if err != nil || first != second {
		t.Fatalf("immutable fact was not deterministic: first=%#v second=%#v err=%v", first, second, err)
	}
	deploymentID, err := AcornFoxRuntimeDeploymentID(first)
	if err != nil || deploymentID.Empty() {
		t.Fatalf("deterministic deployment identity failed: %q %v", deploymentID, err)
	}
	operationID, err := AcornFoxRuntimeOperationID(first, "deploy", "deploy-1")
	if err != nil || operationID == "" {
		t.Fatalf("deterministic operation identity failed: %q %v", operationID, err)
	}
	if repeated, err := AcornFoxRuntimeOperationID(first, "deploy", "deploy-1"); err != nil || repeated != operationID {
		t.Fatalf("same fact action and caller key were not stable: %q %v", repeated, err)
	}
	for _, candidate := range []struct {
		action string
		key    string
		fact   AcornFoxRuntimeReleaseFact
	}{
		{action: "redeploy", key: "deploy-1", fact: first},
		{action: "deploy", key: "deploy-2", fact: first},
		{action: "deploy", key: "deploy-1", fact: AcornFoxRuntimeReleaseFact{ApplicationID: first.ApplicationID, EnvironmentID: first.EnvironmentID, ReleaseID: first.ReleaseID, ServiceName: first.ServiceName, Image: first.Image, Resources: first.Resources, ContainerPort: 0, AcceptedAt: first.AcceptedAt, Immutable: first.Immutable}},
	} {
		value, err := AcornFoxRuntimeOperationID(candidate.fact, candidate.action, candidate.key)
		if err != nil || value == operationID {
			t.Fatalf("different fact, action, or caller key collided: %q %v", value, err)
		}
	}
	raw, err := json.Marshal(AcornFoxRuntimeDeployRequest{Fact: first, IdempotencyKey: "deploy-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "volume", "public", "caddy", "dns", "host", "rollback", "scale", "rolling", "required", "optional", "group", "timeout", "concurrency"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("narrow AcornFox request leaked %q: %s", forbidden, raw)
		}
	}
}

func TestProjectAcornFoxRuntimeReleaseFactRejectsMultiServiceAndInvalidLimits(t *testing.T) {
	image := domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}
	release, err := domain.NewRelease("app_1", "sg_1", 1, "sha256:"+strings.Repeat("b", 64), map[string]domain.ImageDigest{"web": image, "worker": image}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectAcornFoxRuntimeReleaseFact(*release, "env_1", AcornFoxRuntimeRequestedResources{CPUMillis: 1, MemoryBytes: 1, DiskReservationBytes: 1, PIDs: 1}, 0, time.Unix(2, 0).UTC()); err == nil {
		t.Fatal("multi-service release became one AcornFox fact")
	}
	single, err := domain.NewRelease("app_1", "sg_1", 1, "sha256:"+strings.Repeat("c", 64), map[string]domain.ImageDigest{"web": image}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectAcornFoxRuntimeReleaseFact(*single, "env_1", AcornFoxRuntimeRequestedResources{CPUMillis: 1, MemoryBytes: 1, DiskReservationBytes: 1}, 0, time.Unix(2, 0).UTC()); err == nil {
		t.Fatal("zero PID limit was accepted")
	}
	if _, err := ProjectAcornFoxRuntimeReleaseFact(*single, "env_1", AcornFoxRuntimeRequestedResources{CPUMillis: 1, MemoryBytes: 1, DiskReservationBytes: 1, PIDs: 1}, 65536, time.Unix(2, 0).UTC()); err == nil {
		t.Fatal("second container port was accepted")
	}
}

func TestSharedRuntimeObservationWireShapeHasNoAcornFoxReadbackField(t *testing.T) {
	raw, err := json.Marshal(RuntimeObservation{DeploymentID: "dep_1", Limits: ResourceLimits{CPUMillis: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "observed_limits") {
		t.Fatalf("shared runtime observation wire shape widened: %s", raw)
	}
}
