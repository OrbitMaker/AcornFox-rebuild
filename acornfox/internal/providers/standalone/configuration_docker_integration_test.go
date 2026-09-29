//go:build integration

package standalone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
	volumeprovider "github.com/acornfox/acornfox/internal/providers/volume"
)

type runtimeIntegrationDocker struct{}

func (runtimeIntegrationDocker) Run(ctx context.Context, command string, args []string, out, stderr io.Writer) error {
	if command != "docker" {
		return fmt.Errorf("unexpected integration executable")
	}
	cmd := exec.CommandContext(ctx, "sudo", append([]string{"-n", "docker"}, args...)...)
	cmd.Stdout = out
	cmd.Stderr = stderr
	return cmd.Run()
}
func runtimeDockerCommand(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "sudo", append([]string{"-n", "docker"}, args...)...).CombinedOutput()
}

type runtimeIntegrationArchive struct {
	contracts.ImageStore
	file  string
	image domain.ImageDigest
}

func (s runtimeIntegrationArchive) OpenOCI(_ context.Context, image domain.ImageDigest, _ contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	if image != s.image {
		return nil, contracts.StoreOCIResult{}, fmt.Errorf("unexpected image")
	}
	file, err := os.Open(s.file)
	if err != nil {
		return nil, contracts.StoreOCIResult{}, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, contracts.StoreOCIResult{}, err
	}
	return file, contracts.StoreOCIResult{Image: image, StorageRef: "oci://integration/configured-runtime", SizeBytes: info.Size()}, nil
}
func TestAcornFoxConfiguredRuntimeRealDocker(t *testing.T) {
	if os.Getenv("ACORNFOX_RUNTIME_DOCKER_INTEGRATION") != "1" {
		t.Skip("explicit isolated Docker integration required")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("Linux integration only")
	}
	prefix := os.Getenv("ACORNFOX_RUNTIME_INTEGRATION_PREFIX")
	if !strings.HasPrefix(prefix, "acornfox-lsd-") || !safeName.MatchString(prefix) {
		t.Fatal("task-owned resource prefix is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
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
				t.Errorf("list own %s: %s", kind, raw)
				continue
			}
			for _, id := range strings.Fields(string(raw)) {
				raw, err := runtimeDockerCommand(cleanCtx, kind, "inspect", id)
				if err != nil {
					t.Errorf("inspect own %s: %s", kind, raw)
					continue
				}
				var rows []struct {
					Labels map[string]string
					Config struct{ Labels map[string]string }
				}
				if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
					t.Errorf("invalid cleanup receipt")
					continue
				}
				labels := rows[0].Labels
				if kind == "container" {
					labels = rows[0].Config.Labels
				}
				if labels["open-card.task-prefix"] != prefix {
					t.Errorf("refusing non-task cleanup")
					continue
				}
				remove := []string{kind, "rm"}
				if kind == "container" {
					remove = append(remove, "--force")
				}
				remove = append(remove, id)
				if output, err := runtimeDockerCommand(cleanCtx, remove...); err != nil {
					t.Errorf("remove own %s: %s", kind, output)
				}
			}
		}
	})
	cached := os.Getenv("ACORNFOX_RUNTIME_INTEGRATION_IMAGE")
	if cached == "" {
		t.Fatal("pre-existing image must be selected explicitly")
	}
	raw, err := runtimeDockerCommand(ctx, "image", "inspect", "--format", "{{.Id}}", cached)
	if err != nil {
		t.Fatalf("cached image unavailable: %s", raw)
	}
	imageID := strings.TrimSpace(string(raw))
	if !validImageID(imageID) {
		t.Fatal("invalid cached image ID")
	}
	image := domain.ImageDigest{Repository: "acornfox.test/runtime-config", Digest: imageID}
	archive := filepath.Join(root, "cached-image.tar")
	archiveFile, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	save := exec.CommandContext(ctx, "sudo", "-n", "docker", "image", "save", imageID)
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
	configureRestore := func(p *Provider) {
		p.config.ExistingNetworkValidator = validateNetwork
		p.config.RestoreActiveGuard = func(ctx context.Context) error {
			raw, err := runtimeDockerCommand(ctx, "network", "inspect", network)
			if err != nil {
				return err
			}
			return validateNetwork(raw)
		}
	}
	newRuntime := func(restore bool) (*Provider, contracts.AcornFoxRuntimeDriver) {
		capacity, err := capacityprovider.New(capacityprovider.Config{DiskPath: root})
		if err != nil {
			t.Fatal(err)
		}
		provider, err := New(Config{TaskPrefix: prefix, WorkRoot: root, Network: network, ImageStore: runtimeIntegrationArchive{file: archive, image: image}, Capacity: capacity, Volumes: volumes, Runner: runner, WorkerNetworkIsolated: true, Timeout: 30 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if restore {
			configureRestore(provider)
			if err := provider.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
		}
		service, err := application.NewAcornFoxRuntimeService(provider)
		if err != nil {
			t.Fatal(err)
		}
		return provider, service
	}
	configuration := contracts.AcornFoxRuntimeConfiguration{Entrypoint: []string{"/bin/sh", "-c"}, Command: []string{`if [ ! -f /data/value.txt ]; then printf '%s' "$MARKER" > /data/value.txt; fi; exec python3 -m http.server 8080 --bind 0.0.0.0 --directory /data`}, Environment: []contracts.RuntimeEnvironmentVariable{{Name: "MARKER", Kind: contracts.RuntimeEnvironmentLiteral, Value: "initial"}}, Volumes: []contracts.AcornFoxRuntimeVolume{{Name: "data", MountPath: "/data", SizeBytes: 16 << 20}}}
	resources := contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 250, MemoryBytes: 128 << 20, PIDs: 64, DiskReservationBytes: 64 << 20}
	makeFact := func(version int, config contracts.AcornFoxRuntimeConfiguration) contracts.AcornFoxRuntimeReleaseFact {
		digest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(config, resources, 8080)
		if err != nil {
			t.Fatal(err)
		}
		release, err := domain.NewRelease("app_runtime_docker", "legacy", version, digest, map[string]domain.ImageDigest{"web": image}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fact, err := contracts.ProjectAcornFoxConfiguredRuntimeReleaseFact(*release, "env_runtime_docker", resources, 8080, time.Now(), config)
		if err != nil {
			t.Fatal(err)
		}
		return fact
	}
	fact := makeFact(1, configuration)
	provider, service := newRuntime(false)
	deploy := func(service contracts.AcornFoxRuntimeDriver, fact contracts.AcornFoxRuntimeReleaseFact, key string, recreate bool) contracts.AcornFoxRuntimeObservation {
		if _, err := service.Deploy(ctx, contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: key, Recreate: recreate}); err != nil {
			t.Fatal(err)
		}
		observed, err := service.Observe(ctx, contracts.AcornFoxRuntimeReference{Fact: fact})
		if err != nil {
			t.Fatal(err)
		}
		if observed.AppliedLimits.CPUMillis != 250 || observed.AppliedLimits.MemoryBytes != 128<<20 || observed.AppliedLimits.PIDs != 64 {
			t.Fatal("Docker resource readback differs")
		}
		return observed
	}
	checkBody := func(address, want string) {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		defer client.CloseIdleConnections()
		deadline := time.Now().Add(10 * time.Second)
		last := ""
		for time.Now().Before(deadline) {
			resp, err := client.Get("http://" + address + "/value.txt")
			if err == nil {
				raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
				last = string(raw)
				if resp.StatusCode == 200 && last == want {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("application response did not preserve data: got=%q want=%q", last, want)
	}
	initial := deploy(service, fact, "initial", false)
	checkBody(initial.InternalAddress, "initial")
	configureRestore(provider)
	if output, err := runtimeDockerCommand(ctx, "exec", initial.ContainerID, "/bin/sh", "-c", "printf kept > /data/value.txt"); err != nil {
		t.Fatalf("write test data: %s", output)
	}
	if err := service.Restart(ctx, contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "restart"}); err != nil {
		t.Fatal(err)
	}
	checkBody(initial.InternalAddress, "kept")
	replaced := deploy(service, fact, "recreate", true)
	if replaced.ContainerID == initial.ContainerID || replaced.InternalAddress != initial.InternalAddress {
		t.Fatal("replacement did not preserve port and replace container")
	}
	checkBody(replaced.InternalAddress, "kept")
	if output, err := runtimeDockerCommand(ctx, "stop", replaced.ContainerID); err != nil {
		t.Fatalf("simulate host stop: %s", output)
	}
	_, service = newRuntime(true)
	restored, err := service.Observe(ctx, contracts.AcornFoxRuntimeReference{Fact: fact})
	if err != nil {
		t.Fatal(err)
	}
	checkBody(restored.InternalAddress, "kept")
	if err := service.Destroy(ctx, contracts.AcornFoxRuntimeActionRequest{Fact: fact, IdempotencyKey: "stop-keep-data"}); err != nil {
		t.Fatal(err)
	}
	// A new release of the same application must reuse the accepted volume.
	nextFact := makeFact(2, configuration)
	next := deploy(service, nextFact, "new-release", false)
	checkBody(next.InternalAddress, "kept")
	if err := service.Destroy(ctx, contracts.AcornFoxRuntimeActionRequest{Fact: nextFact, IdempotencyKey: "stop-before-failure"}); err != nil {
		t.Fatal(err)
	}
	badConfig := configuration
	badConfig.Entrypoint = []string{"/does-not-exist"}
	badFact := makeFact(3, badConfig)
	if _, err := service.Deploy(ctx, contracts.AcornFoxRuntimeDeployRequest{Fact: badFact, IdempotencyKey: "failed-start"}); err == nil {
		t.Fatal("bad startup command was accepted")
	}
	goodFact := makeFact(4, configuration)
	good := deploy(service, goodFact, "recover-after-failed-start", false)
	checkBody(good.InternalAddress, "kept")
	if err := service.Destroy(ctx, contracts.AcornFoxRuntimeActionRequest{Fact: goodFact, IdempotencyKey: "final-container-stop"}); err != nil {
		t.Fatal(err)
	}
	spec := contracts.RuntimeSpec{ApplicationID: goodFact.ApplicationID}
	physical := runtimeVolumeName(prefix, spec, "data")
	if output, err := runtimeDockerCommand(ctx, "volume", "rm", physical); err != nil {
		t.Fatalf("simulate lost task data volume: %s", output)
	}
	lostFact := makeFact(5, configuration)
	if _, err := service.Deploy(ctx, contracts.AcornFoxRuntimeDeployRequest{Fact: lostFact, IdempotencyKey: "must-not-replace-lost-data"}); err == nil {
		t.Fatal("missing accepted data volume was silently recreated")
	}
	if _, err := runtimeDockerCommand(ctx, "volume", "inspect", physical); err == nil {
		t.Fatal("lost data volume was recreated")
	}
	t.Logf("REAL_DOCKER_CONFIG_PASS image=%s cpu_millis=250 memory_bytes=%d pids=64 restart=true recreate=true process_recovery=true new_release_data_retained=true failed_start_data_retained=true missing_volume_rejected=true", imageID, 128<<20)
}
