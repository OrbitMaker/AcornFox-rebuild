//go:build integration

package standalone

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	capacityprovider "github.com/open-card/open-card/internal/providers/capacity"
	volumeprovider "github.com/open-card/open-card/internal/providers/volume"
)

func TestAcornFoxLifecycleRealDockerIntegration(t *testing.T) {
	if os.Getenv("ACORNFOX_MANAGEMENT_REAL_DOCKER") != "1" {
		t.Skip("explicit isolated Docker integration required (set ACORNFOX_MANAGEMENT_REAL_DOCKER=1)")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("Linux integration only")
	}

	const prefix = "acornfox-management-20260921-r1"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	root := t.TempDir()

	// Register isolated cleanup for resources owned strictly by this test task.
	t.Cleanup(func() {
		cleanCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, kind := range []string{"container", "volume", "network"} {
			args := []string{kind, "ls", "--quiet", "--filter", "label=open-card.task-prefix=" + prefix}
			if kind == "container" {
				args = append(args, "--all")
			}
			raw, err := runtimeDockerCommand(cleanCtx, args...)
			if err != nil {
				continue
			}
			for _, id := range strings.Fields(string(raw)) {
				// Verify task ownership label before deletion to prevent touching other containers
				inspectRaw, err := runtimeDockerCommand(cleanCtx, kind, "inspect", id)
				if err != nil {
					continue
				}
				var rows []struct {
					Labels map[string]string
					Config struct{ Labels map[string]string }
				}
				if json.Unmarshal(inspectRaw, &rows) != nil || len(rows) != 1 {
					continue
				}
				labels := rows[0].Labels
				if kind == "container" {
					labels = rows[0].Config.Labels
				}
				if labels["open-card.task-prefix"] != prefix {
					continue
				}
				remove := []string{kind, "rm"}
				if kind == "container" {
					remove = append(remove, "--force")
				}
				remove = append(remove, id)
				_, _ = runtimeDockerCommand(cleanCtx, remove...)
			}
		}
	})

	// Use pre-existing local alpine:3.20 image (already cached on devbox)
	cachedImage := os.Getenv("ACORNFOX_RUNTIME_INTEGRATION_IMAGE")
	if cachedImage == "" {
		cachedImage = "alpine:3.20"
	}
	raw, err := runtimeDockerCommand(ctx, "image", "inspect", "--format", "{{.Id}}", cachedImage)
	if err != nil {
		t.Fatalf("cached image %s unavailable: %s", cachedImage, raw)
	}
	imageID := strings.TrimSpace(string(raw))
	if !validImageID(imageID) {
		t.Fatalf("invalid cached image ID: %s", imageID)
	}

	imageDigest := domain.ImageDigest{Repository: "acornfox.test/lifecycle-app", Digest: imageID}
	archive := filepath.Join(root, "cached-image.tar")
	archiveFile, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	save := exec.CommandContext(ctx, "docker", "image", "save", imageID)
	save.Stdout = archiveFile
	var saveError strings.Builder
	save.Stderr = &saveError
	saveErr := save.Run()
	closeErr := archiveFile.Close()
	if saveErr != nil || closeErr != nil {
		t.Fatalf("save cached image: %v %v %s", saveErr, closeErr, saveError.String())
	}

	runner := runtimeIntegrationDocker{}
	volumes, err := volumeprovider.New(volumeprovider.Config{TaskPrefix: prefix, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}

	network := prefix + "-network"
	validateNetwork := func(raw []byte) error {
		var networks []struct {
			Name, Driver string
			Internal     bool
			Labels       map[string]string
		}
		if json.Unmarshal(raw, &networks) != nil || len(networks) != 1 || networks[0].Name != network || networks[0].Driver != "bridge" || networks[0].Internal || networks[0].Labels["open-card.task-prefix"] != prefix {
			return fmt.Errorf("integration network identity changed")
		}
		return nil
	}

	// Pre-create task network with valid installed labels
	netRaw, err := runtimeDockerCommand(ctx, "network", "create", "--driver", "bridge", "--label", "open-card.managed=true", "--label", "open-card.task-prefix="+prefix, network)
	if err != nil {
		t.Fatalf("pre-create network: %v output=%s", err, netRaw)
	}

	// Create managed persistent volume
	volumeSpec, _, err := volumes.Create(ctx, contracts.VolumeRequest{
		Volume:    contracts.VolumeSpec{Name: "data", MountPath: "/data"},
		Operation: contracts.OperationContext{IdempotencyKey: "r1-create-volume"},
	})
	if err != nil {
		t.Fatalf("create managed volume: %v", err)
	}

	resources := contracts.AcornFoxRuntimeRequestedResources{
		CPUMillis:            500,
		MemoryBytes:          128 << 20,
		DiskReservationBytes: 256 << 20,
		PIDs:                 64,
	}

	configuration := contracts.AcornFoxRuntimeConfiguration{
		Entrypoint: []string{"/bin/sh", "-c"},
		Command:    []string{"echo 'preserved-data-r1-20260921' > /data/marker.txt && nc -lk -p 8080 -e echo -e 'HTTP/1.1 200 OK\\r\\n\\r\\nOK'"},
		Volumes: []contracts.AcornFoxRuntimeVolume{{
			Name:      "data",
			MountPath: "/data",
			SizeBytes: 16 << 20,
		}},
	}

	configDigest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(configuration, resources, 8080)
	if err != nil {
		t.Fatal(err)
	}

	release, err := domain.NewRelease("app_r1", "sg_r1", 1, configDigest, map[string]domain.ImageDigest{"web": imageDigest}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	fact, err := contracts.ProjectAcornFoxConfiguredRuntimeReleaseFact(*release, "env_r1", resources, 8080, time.Now().UTC(), configuration)
	if err != nil {
		t.Fatal(err)
	}

	newRuntime := func(restore bool) (*Provider, contracts.AcornFoxRuntimeDriver, *capacityprovider.Provider) {
		capacity, err := capacityprovider.New(capacityprovider.Config{DiskPath: root})
		if err != nil {
			t.Fatal(err)
		}
		p, err := New(Config{
			TaskPrefix:               prefix,
			WorkRoot:                 root,
			Network:                  network,
			Runner:                   runner,
			Capacity:                 capacity,
			ImageStore:               runtimeIntegrationArchive{file: archive, image: imageDigest},
			Volumes:                  volumes,
			WorkerNetworkIsolated:    true,
			ExistingNetworkValidator: validateNetwork,
			RestoreActiveGuard: func(ctx context.Context) error {
				raw, err := runtimeDockerCommand(ctx, "network", "inspect", network)
				if err != nil {
					return err
				}
				return validateNetwork(raw)
			},
			Timeout: 30 * time.Second,
			Clock:   time.Now().UTC,
		})
		if err != nil {
			t.Fatal(err)
		}
		svc, err := application.NewAcornFoxRuntimeService(p)
		if err != nil {
			t.Fatal(err)
		}
		return p, svc, capacity
	}

	provider1, service1, capacity1 := newRuntime(false)

	// 1. Initial Deploy
	t.Log("===> Step 1: Deploy initial container workload")
	dep, err := service1.Deploy(ctx, contracts.AcornFoxRuntimeDeployRequest{
		Fact:           fact,
		IdempotencyKey: "r1-deploy-initial",
	})
	if err != nil {
		t.Fatalf("Deploy initial container: %v", err)
	}
	if dep.RuntimeState != string(domain.DeploymentRuntimeReady) {
		t.Fatalf("expected state %s, got %s", domain.DeploymentRuntimeReady, dep.RuntimeState)
	}

	obs1, err := service1.Observe(ctx, contracts.AcornFoxRuntimeReference{Fact: fact})
	if err != nil {
		t.Fatalf("Observe initial: %v", err)
	}
	initialContainerID := obs1.ContainerID
	initialAddress := obs1.InternalAddress
	if initialContainerID == "" || initialAddress == "" {
		t.Fatalf("missing container ID or address: id=%s addr=%s", initialContainerID, initialAddress)
	}
	t.Logf("Initial deployment running: ID=%s Addr=%s", initialContainerID, initialAddress)

	// Wait briefly for marker file write
	time.Sleep(500 * time.Millisecond)

	// Verify marker was written inside volume
	markerRaw, err := runtimeDockerCommand(ctx, "exec", initialContainerID, "cat", "/data/marker.txt")
	if err != nil || !strings.Contains(string(markerRaw), "preserved-data-r1-20260921") {
		t.Fatalf("verify marker file: %v output=%s", err, markerRaw)
	}
	t.Log("Data successfully verified in volume before stop")

	// 2. Stop container
	t.Log("===> Step 2: Stop container (paused)")
	lifecycle1, ok := service1.(contracts.AcornFoxLifecycleDriver)
	if !ok {
		t.Fatal("expected service1 to implement AcornFoxLifecycleDriver")
	}
	stopErr := lifecycle1.Stop(ctx, contracts.AcornFoxRuntimeActionRequest{
		Fact:           fact,
		IdempotencyKey: "r1-stop-1",
	})
	if stopErr != nil {
		t.Fatalf("Stop container: %v", stopErr)
	}

	// Verify container status via Docker inspect
	inspectRaw, err := runtimeDockerCommand(ctx, "container", "inspect", "--format", "{{.State.Status}}|{{.State.Running}}|{{.Id}}", initialContainerID)
	if err != nil {
		t.Fatalf("inspect stopped container: %v", err)
	}
	inspectParts := strings.Split(strings.TrimSpace(string(inspectRaw)), "|")
	if len(inspectParts) != 3 || inspectParts[0] != "exited" || inspectParts[1] != "false" || inspectParts[2] != initialContainerID {
		t.Fatalf("stopped container fact mismatch: %s", inspectRaw)
	}
	t.Log("Docker inspect confirmed container is exited and ID is unchanged")

	// Verify durable state schema 3 and paused phase
	state1, found, err := provider1.readDurableState(dep.DeploymentID)
	if err != nil || !found {
		t.Fatalf("read durable state: found=%t err=%v", found, err)
	}
	if state1.Phase != "paused" || state1.Deployment.Status != domain.DeploymentPaused {
		t.Fatalf("expected paused state: phase=%s status=%s", state1.Phase, state1.Deployment.Status)
	}
	if state1.SchemaVersion != "3" {
		t.Fatalf("expected schema version 3, got %s", state1.SchemaVersion)
	}
	// Capacity lease must be retained (ActiveLeaseCount == 1)
	if capacity1.ActiveLeaseCount() != 1 {
		t.Fatalf("capacity lease was not retained on stop: count=%d", capacity1.ActiveLeaseCount())
	}
	t.Log("Durable state verified as Schema 3 / DeploymentPaused, capacity retained")

	// 3. Fresh Provider Reconcile (Reboot simulation)
	t.Log("===> Step 3: Fresh provider reboot and reconcile")
	provider2, service2, capacity2 := newRuntime(true)

	if err := provider2.Reconcile(ctx); err != nil {
		t.Fatalf("fresh provider Reconcile: %v", err)
	}

	// Verify container is STILL stopped and NOT started by Reconcile
	reconcileInspect, err := runtimeDockerCommand(ctx, "container", "inspect", "--format", "{{.State.Status}}|{{.State.Running}}", initialContainerID)
	if err != nil {
		t.Fatalf("inspect container after reconcile: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(reconcileInspect)), "exited|false") {
		t.Fatalf("VIOLATION: Reconcile started paused container: %s", reconcileInspect)
	}
	// Verify fresh capacity accounted the retained lease
	if capacity2.ActiveLeaseCount() != 1 {
		t.Fatalf("fresh provider did not account retained capacity: %d", capacity2.ActiveLeaseCount())
	}
	t.Log("Fresh provider Reconcile confirmed container remains stopped and capacity accounted")

	// 4. Start container
	t.Log("===> Step 4: Start container back to running")
	lifecycle2, ok := service2.(contracts.AcornFoxLifecycleDriver)
	if !ok {
		t.Fatal("expected service2 to implement AcornFoxLifecycleDriver")
	}
	startErr := lifecycle2.Start(ctx, contracts.AcornFoxRuntimeActionRequest{
		Fact:           fact,
		IdempotencyKey: "r1-start-1",
	})
	if startErr != nil {
		t.Fatalf("Start container: %v", startErr)
	}

	// Verify container is running, same container ID, same address
	obs2, err := service2.Observe(ctx, contracts.AcornFoxRuntimeReference{Fact: fact})
	if err != nil {
		t.Fatalf("Observe after start: %v", err)
	}
	if obs2.ContainerID != initialContainerID {
		t.Fatalf("VIOLATION: container ID changed after start: initial=%s current=%s", initialContainerID, obs2.ContainerID)
	}
	if obs2.InternalAddress != initialAddress {
		t.Fatalf("VIOLATION: container port/address changed after start: initial=%s current=%s", initialAddress, obs2.InternalAddress)
	}

	// Verify marker data intact across stop/start
	markerRawAfter, err := runtimeDockerCommand(ctx, "exec", initialContainerID, "cat", "/data/marker.txt")
	if err != nil || !strings.Contains(string(markerRawAfter), "preserved-data-r1-20260921") {
		t.Fatalf("marker data corrupted or lost across stop/start: %v output=%s", err, markerRawAfter)
	}
	t.Log("Volume marker data intact after start! Container ID and host port preserved")

	// 5. Anti-undo test: replaying old Stop key must NOT stop running container
	t.Log("===> Step 5: Test anti-undo (replay old Stop key)")
	if err := lifecycle2.Stop(ctx, contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "r1-stop-1"}); err != nil {
		t.Fatalf("replay old stop key should succeed idempotently: %v", err)
	}
	runningCheck, _ := runtimeDockerCommand(ctx, "container", "inspect", "--format", "{{.State.Running}}", initialContainerID)
	if strings.TrimSpace(string(runningCheck)) != "true" {
		t.Fatal("P1-1 VIOLATION: replaying old Stop key stopped the running container!")
	}
	t.Log("Anti-undo verified: old Stop key did not undo active container")

	// 6. Destroy container and verify volume retention
	t.Log("===> Step 6: Destroy container and verify volume retention")
	destroyErr := service2.Destroy(ctx, contracts.AcornFoxRuntimeActionRequest{
		Fact:           fact,
		IdempotencyKey: "r1-destroy-1",
	})
	if destroyErr != nil {
		t.Fatalf("Destroy container: %v", destroyErr)
	}

	// Verify container is removed
	_, inspectAfterDestroy := runtimeDockerCommand(ctx, "container", "inspect", initialContainerID)
	if inspectAfterDestroy == nil {
		t.Fatalf("container %s still exists after destroy", initialContainerID)
	}

	// Verify volume STILL EXISTS (managed volume must not be deleted by container destroy)
	volumeInspectRaw, volErr := runtimeDockerCommand(ctx, "volume", "inspect", volumeSpec.Name)
	if volErr != nil {
		t.Fatalf("VIOLATION: managed volume %s was deleted by Destroy: %v", volumeSpec.Name, volErr)
	}
	t.Logf("Managed volume %s strictly retained after container Destroy: %s", volumeSpec.Name, strings.TrimSpace(string(volumeInspectRaw)))

	t.Log("===> All Real Docker Acceptance Criteria Passed for R1!")
}
