package standalone

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/acornfox/acornfox/internal/contracts"
	volumeprovider "github.com/acornfox/acornfox/internal/providers/volume"
	"io"
	"os"
	"strings"
	"testing"
)

type configuredVolumeFixture struct {
	contracts.VolumeProvider
	volumes map[string]volumeprovider.VolumeFacts
	creates int
}

func (v *configuredVolumeFixture) Create(_ context.Context, r contracts.VolumeRequest) (contracts.VolumeSpec, contracts.Evidence, error) {
	if _, exists := v.volumes[r.Volume.Name]; !exists {
		v.creates++
		v.volumes[r.Volume.Name] = volumeprovider.VolumeFacts{Name: r.Volume.Name, Driver: "local", Labels: map[string]string{"open-card.managed": "true", "open-card.task-prefix": "opencard-m1", "open-card.volume-logical-name": r.Volume.Name, "open-card.volume-mount-path": r.Volume.MountPath, "open-card.volume-size-bytes": fmt.Sprint(r.Volume.SizeBytes), "open-card.retention": "retain"}}
	}
	return r.Volume, contracts.Evidence{}, nil
}
func (v *configuredVolumeFixture) InspectFacts(_ context.Context, r contracts.VolumeRequest) (volumeprovider.VolumeFacts, error) {
	f, ok := v.volumes[r.Volume.Name]
	if !ok {
		return f, &contracts.ProviderError{Code: contracts.ErrNotFound, Message: "volume absent"}
	}
	return f, nil
}

func configureDockerFixture(t *testing.T, d *replacementDocker) {
	t.Helper()
	original := d.runner.run
	d.runner.run = func(args []string, out io.Writer) error {
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			_, err := io.WriteString(out, testDigest+`|{"Entrypoint":["/image-default"],"Cmd":["default"],"Volumes":{"/data":{}}}`)
			return err
		}
		if args[0] == "restart" {
			d.facts.State.Running = true
			d.facts.State.StartedAt = "2026-09-16T00:00:00Z"
			return nil
		}
		if err := original(args, out); err != nil {
			return err
		}
		if args[0] == "run" {
			imageIndex := -1
			for i, a := range args {
				if a == testDigest {
					imageIndex = i
					break
				}
			}
			if imageIndex < 0 {
				t.Fatal("image absent")
			}
			d.facts.Config.Entrypoint = []string{"/image-default"}
			d.facts.Config.Cmd = []string{"default"}
			d.facts.Config.Volumes = map[string]any{"/data": map[string]any{}}
			for i := 1; i < imageIndex; i++ {
				if args[i] == "--entrypoint" {
					d.facts.Config.Entrypoint = []string{args[i+1]}
					d.facts.Config.Cmd = nil
				}
				if args[i] == "--env" {
					d.facts.Config.Env = append(d.facts.Config.Env, args[i+1])
				}
				if args[i] == "--mount" {
					m := map[string]string{}
					for _, entry := range strings.Split(args[i+1], ",") {
						k, v, _ := strings.Cut(entry, "=")
						m[k] = v
					}
					var mounts []struct {
						Type        string `json:"Type"`
						Name        string `json:"Name"`
						Destination string `json:"Destination"`
						RW          bool   `json:"RW"`
					}
					_, readonly := m["readonly"]
					mounts = append(mounts, struct {
						Type        string `json:"Type"`
						Name        string `json:"Name"`
						Destination string `json:"Destination"`
						RW          bool   `json:"RW"`
					}{"volume", m["source"], m["target"], !readonly})
					d.facts.Mounts = append(d.facts.Mounts, mounts...)
				}
			}
			if imageIndex+1 < len(args) {
				d.facts.Config.Cmd = append([]string(nil), args[imageIndex+1:]...)
			}
		}
		return nil
	}
}
func configuredRuntimeRequest(t *testing.T) contracts.DeployRequest {
	t.Helper()
	req := testRequest("configured-runtime")
	req.Spec.Configuration = &contracts.AcornFoxRuntimeConfiguration{Entrypoint: []string{"/app", "--quiet"}, Command: []string{"serve"}, Environment: []contracts.RuntimeEnvironmentVariable{{Name: "MODE", Kind: contracts.RuntimeEnvironmentLiteral, Value: "production"}}, Volumes: []contracts.AcornFoxRuntimeVolume{{Name: "data", MountPath: "/data", SizeBytes: 1 << 20}}}
	var err error
	req.Spec.ConfigDigest, err = contracts.CanonicalAcornFoxRuntimeConfigDigest(*req.Spec.Configuration, contracts.AcornFoxRuntimeRequestedResources{CPUMillis: req.Spec.Resources.CPUMillis, MemoryBytes: req.Spec.Resources.MemoryBytes, PIDs: req.Spec.Resources.PIDs, DiskReservationBytes: req.Spec.Resources.DiskBytes}, req.Spec.Port)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
func TestAcornFoxConfiguredRuntimeRetainsVolumeAcrossRestartRecreateAndRecovery(t *testing.T) {
	root := t.TempDir()
	docker := newReplacementDocker(t)
	configureDockerFixture(t, docker)
	ports := &fixedPorts{port: 39124}
	volumes := &configuredVolumeFixture{volumes: map[string]volumeprovider.VolumeFacts{}}
	provider := stableReplacementProvider(t, root, docker, ports)
	provider.config.Volumes = volumes
	req := configuredRuntimeRequest(t)
	if _, err := provider.Deploy(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	firstID := docker.facts.ID
	physical := docker.facts.Mounts[0].Name
	snapshot := mustDurableSnapshot(t, provider, req.DeploymentID)
	if snapshot.SchemaVersion != "2" || snapshot.Spec.ConfigDigest != req.Spec.ConfigDigest || snapshot.Spec.Configuration.Command[0] != "serve" {
		t.Fatal("configuration lost in durable state")
	}
	if err := provider.Restart(context.Background(), contracts.RestartRequest{DeploymentID: req.DeploymentID, ServiceName: "web", Operation: contracts.OperationContext{IdempotencyKey: "configured-restart"}}); err != nil {
		t.Fatal(err)
	}
	if docker.facts.ID != firstID {
		t.Fatal("restart replaced container")
	}
	req.Operation.IdempotencyKey = "configured-recreate"
	if _, err := provider.Recreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if docker.facts.ID == firstID || docker.facts.Mounts[0].Name != physical || volumes.creates != 1 {
		t.Fatal("recreate changed retained volume")
	}
	lastRun := docker.runner.callsFor("run")
	args := lastRun[len(lastRun)-1]
	for i, a := range args {
		if a == testDigest {
			if strings.Join(args[i+1:], " ") != "--quiet serve" {
				t.Fatal("replacement label leaked into application argv")
			}
			break
		}
	}
	fresh := stableReplacementProvider(t, root, docker, ports)
	fresh.config.Volumes = volumes
	if err := fresh.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Observe(context.Background(), contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "configured-observe"}}); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Destroy(context.Background(), contracts.DestroyRequest{DeploymentID: req.DeploymentID, Operation: contracts.OperationContext{IdempotencyKey: "configured-destroy"}}); err != nil {
		t.Fatal(err)
	}
	if len(volumes.volumes) != 1 || volumes.creates != 1 {
		t.Fatal("container destroy removed retained data volume")
	}
}
func TestAcornFoxConfiguredRuntimeRejectsDriftAndMissingData(t *testing.T) {
	for _, kind := range []string{"command", "environment", "volume mount", "volume ownership", "volume missing"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			docker := newReplacementDocker(t)
			configureDockerFixture(t, docker)
			ports := &fixedPorts{port: 39124}
			volumes := &configuredVolumeFixture{volumes: map[string]volumeprovider.VolumeFacts{}}
			provider := stableReplacementProvider(t, root, docker, ports)
			provider.config.Volumes = volumes
			req := configuredRuntimeRequest(t)
			if _, err := provider.Deploy(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "command":
				docker.facts.Config.Cmd = []string{"drift"}
			case "environment":
				docker.facts.Config.Env = []string{"MODE=drift"}
			case "volume mount":
				docker.facts.Mounts[0].Name = "foreign"
			case "volume ownership":
				for _, v := range volumes.volumes {
					v.Labels["open-card.task-prefix"] = "foreign"
				}
			case "volume missing":
				clear(volumes.volumes)
			}
			fresh := stableReplacementProvider(t, root, docker, ports)
			fresh.config.Volumes = volumes
			if err := fresh.Reconcile(context.Background()); err == nil {
				t.Fatal("drift accepted during recovery")
			}
			if volumes.creates != 1 || len(docker.runner.callsFor("rm")) != 0 {
				t.Fatal("recovery modified missing or foreign data")
			}
		})
	}
}
func TestAcornFoxRuntimeVolumeIdentityIsApplicationScoped(t *testing.T) {
	req := configuredRuntimeRequest(t)
	first := runtimeVolumeName("opencard-m1", req.Spec, "data")
	other := req.Spec
	other.ReleaseID = "rel_other"
	if runtimeVolumeName("opencard-m1", other, "data") != first {
		t.Fatal("release changed data identity")
	}
	other.ApplicationID = "app_other"
	if runtimeVolumeName("opencard-m1", other, "data") == first {
		t.Fatal("applications share data volume")
	}
	raw, _ := json.Marshal(req.Spec)
	if strings.Contains(string(raw), "/var/lib/docker") {
		t.Fatal("host path leaked")
	}
}

func TestAcornFoxRuntimeVolumeReceiptCrashRecovery(t *testing.T) {
	for _, mode := range []string{"before create", "after create", "unrecorded existing", "accepted missing", "unsafe receipt"} {
		t.Run(mode, func(t *testing.T) {
			docker := newReplacementDocker(t)
			ports := &fixedPorts{port: 39124}
			provider := stableReplacementProvider(t, t.TempDir(), docker, ports)
			volumes := &configuredVolumeFixture{volumes: map[string]volumeprovider.VolumeFacts{}}
			provider.config.Volumes = volumes
			req := configuredRuntimeRequest(t)
			claim := runtimeVolumeClaimFor(provider.config.TaskPrefix, req.Spec, req.Spec.Configuration.Volumes[0])
			if mode != "unrecorded existing" {
				if err := provider.persistRuntimeVolumeReceipt(claim, "pending"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "after create" || mode == "unrecorded existing" {
				if _, _, err := volumes.Create(context.Background(), contracts.VolumeRequest{Volume: claim.Volume}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "accepted missing" {
				if err := provider.persistRuntimeVolumeReceipt(claim, "accepted"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unsafe receipt" {
				if err := os.Chmod(provider.runtimeVolumeReceiptPath(claim), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := provider.prepareRuntimeVolumes(context.Background(), req.Spec, req.Operation)
			if mode == "before create" || mode == "after create" {
				if err != nil {
					t.Fatal(err)
				}
				state, err := provider.readRuntimeVolumeReceipt(claim)
				if err != nil || state != "accepted" || volumes.creates != 1 {
					t.Fatal("pending volume did not recover exactly once")
				}
			} else if err == nil {
				t.Fatal("unsafe or missing accepted volume was adopted")
			}
			if mode == "accepted missing" && volumes.creates != 0 {
				t.Fatal("lost data replaced with empty volume")
			}
		})
	}
}
func TestAcornFoxRuntimeVolumeConcurrentDefinitionsConflict(t *testing.T) {
	docker := newReplacementDocker(t)
	provider := stableReplacementProvider(t, t.TempDir(), docker, &fixedPorts{port: 39124})
	volumes := &configuredVolumeFixture{volumes: map[string]volumeprovider.VolumeFacts{}}
	provider.config.Volumes = volumes
	first := configuredRuntimeRequest(t)
	second := first
	second.Spec.Configuration = copyRuntimeConfiguration(first.Spec.Configuration)
	second.Spec.Configuration.Volumes[0].SizeBytes++
	second.Spec.ConfigDigest, _ = contracts.CanonicalAcornFoxRuntimeConfigDigest(*second.Spec.Configuration, contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 128 << 20, PIDs: 64, DiskReservationBytes: 256 << 20}, 8080)
	done := make(chan error, 2)
	for _, req := range []contracts.DeployRequest{first, second} {
		go func(req contracts.DeployRequest) {
			done <- provider.prepareRuntimeVolumes(context.Background(), req.Spec, req.Operation)
		}(req)
	}
	successes := 0
	for range 2 {
		if <-done == nil {
			successes++
		}
	}
	if successes != 1 || volumes.creates != 1 {
		t.Fatal("conflicting definitions created or accepted twice")
	}
}
func TestAcornFoxRuntimeRefusesUnlabelledVolumeAfterDockerRun(t *testing.T) {
	docker := newReplacementDocker(t)
	configureDockerFixture(t, docker)
	provider := stableReplacementProvider(t, t.TempDir(), docker, &fixedPorts{port: 39124})
	volumes := &configuredVolumeFixture{volumes: map[string]volumeprovider.VolumeFacts{}}
	provider.config.Volumes = volumes
	docker.hook = func(event string) {
		if event == "after run" {
			for name, v := range volumes.volumes {
				v.Labels = nil
				volumes.volumes[name] = v
			}
		}
	}
	if _, err := provider.Deploy(context.Background(), configuredRuntimeRequest(t)); err == nil {
		t.Fatal("Docker auto-created unlabelled volume reported ready")
	}
}
