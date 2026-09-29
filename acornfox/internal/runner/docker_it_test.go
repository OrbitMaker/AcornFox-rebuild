package runner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// itBaseImage must already be present on the devbox (checked via docker images).
const itBaseImage = "alpine:3.22"

// newDockerIT skips unless ACORNFOX_DOCKER_IT=1 and a daemon is reachable.
func newDockerIT(t *testing.T) *Docker {
	t.Helper()
	if os.Getenv("ACORNFOX_DOCKER_IT") != "1" {
		t.Skip("set ACORNFOX_DOCKER_IT=1 to run Docker integration tests")
	}
	cli, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	d := NewDocker(cli)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := d.Ping(ctx); err != nil {
		t.Skipf("docker daemon not reachable: %v", err)
	}
	return d
}

// writeGzipTar writes a gzip-compressed tar containing files to path.
func writeGzipTar(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	path := filepath.Join(dir, "context.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o640); err != nil {
		t.Fatalf("write context: %v", err)
	}
	return path
}

// TestDockerLifecycle drives a full build/ensure/list/logs/diff/remove cycle and
// cleans up all objects it creates.
func TestDockerLifecycle(t *testing.T) {
	d := newDockerIT(t)
	ctx := context.Background()

	const app = "afit"
	const dep = "0123456789ab"
	name := ContainerName(app, dep)
	tag := ImageTag(app, dep)

	// A tiny image that opens a TCP port and writes a database-like file.
	dockerfile := "FROM " + itBaseImage + "\n" +
		"RUN touch /app.db\n" +
		"EXPOSE 8080\n" +
		`CMD ["sh","-c","touch /runtime.db; while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi' | nc -l -p 8080; done"]` + "\n"
	dir := t.TempDir()
	ctxPath := writeGzipTar(t, dir, map[string]string{"Dockerfile": dockerfile})

	// Guaranteed cleanup of everything this test creates.
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = d.RemoveContainer(cctx, app, name)
		_ = d.RemoveImage(cctx, app, tag)
		// The app network is created implicitly by EnsureContainer; remove it too.
		_, _ = d.cli.NetworkRemove(cctx, NetworkName(app), client.NetworkRemoveOptions{})
	})

	// Build.
	buildResp, err := d.Build(ctx, BuildRequest{App: app, DeploymentID: dep, ContextPath: ctxPath})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !buildResp.OK || buildResp.Image == nil {
		t.Fatalf("build failed: %+v", buildResp.Failure)
	}
	if buildResp.Image.App != app || buildResp.Image.DeploymentID != dep {
		t.Fatalf("image labels not set: %+v", buildResp.Image)
	}
	if len(buildResp.Image.ExposedPorts) == 0 || buildResp.Image.ExposedPorts[0] != 8080 {
		t.Fatalf("expected exposed port 8080, got %v", buildResp.Image.ExposedPorts)
	}

	// Rebuild returns the same image without building again.
	rebuild, err := d.Build(ctx, BuildRequest{App: app, DeploymentID: dep, ContextPath: ctxPath})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuild.Image == nil || rebuild.Image.ID != buildResp.Image.ID {
		t.Fatalf("rebuild produced a different image: %+v", rebuild.Image)
	}

	// Ensure container twice -> same ID (idempotent by name).
	info1, err := d.EnsureContainer(ctx, EnsureContainerRequest{
		App: app, DeploymentID: dep, Image: tag, Port: 8080, MemoryMB: 64, CPUMilli: 500,
	})
	if err != nil {
		t.Fatalf("EnsureContainer #1: %v", err)
	}
	info2, err := d.EnsureContainer(ctx, EnsureContainerRequest{
		App: app, DeploymentID: dep, Image: tag, Port: 8080, MemoryMB: 64, CPUMilli: 500,
	})
	if err != nil {
		t.Fatalf("EnsureContainer #2: %v", err)
	}
	if info1.ID != info2.ID {
		t.Fatalf("ensure not idempotent: %s != %s", info1.ID, info2.ID)
	}
	if info2.HostPort == 0 {
		t.Fatalf("expected a published host port, got 0")
	}

	// List shows exactly this container for the app.
	list, err := d.ListContainers(ctx, app)
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(list) != 1 || list[0].Name != name {
		t.Fatalf("unexpected container list: %+v", list)
	}
	if list[0].App != app || list[0].DeploymentID != dep || list[0].Role != RoleApp {
		t.Fatalf("container labels not observed: %+v", list[0])
	}

	// Give the container a moment to run its startup command.
	time.Sleep(2 * time.Second)

	// Logs should be retrievable (may be empty, but must not error).
	if _, err := d.Logs(ctx, app, name, 40); err != nil {
		t.Fatalf("Logs: %v", err)
	}

	// Diff should surface database-like files created at build/run time.
	files, err := d.Diff(ctx, app, name)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	found := false
	for _, f := range files {
		if f == "/app.db" || f == "/runtime.db" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a .db file in diff, got %v", files)
	}

	// Remove is idempotent: removing twice is success.
	if err := d.RemoveContainer(ctx, app, name); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if err := d.RemoveContainer(ctx, app, name); err != nil {
		t.Fatalf("RemoveContainer (second): %v", err)
	}

	// After removal the app has no containers.
	list, err = d.ListContainers(ctx, app)
	if err != nil {
		t.Fatalf("ListContainers after remove: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected no containers after remove, got %+v", list)
	}

	// Stop/remove of a missing container is success.
	if err := d.StopContainer(ctx, app, name); err != nil {
		t.Fatalf("StopContainer missing: %v", err)
	}

	// RemoveImage is idempotent too.
	if err := d.RemoveImage(ctx, app, tag); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if err := d.RemoveImage(ctx, app, tag); err != nil {
		t.Fatalf("RemoveImage (second): %v", err)
	}
}

// TestDockerVolumeLifecycle ensures a managed volume and lists it.
func TestDockerVolumeLifecycle(t *testing.T) {
	d := newDockerIT(t)
	ctx := context.Background()

	const app = "afitvol"
	volName := VolumePrefix(app) + "1"

	if err := d.EnsureVolume(ctx, app, volName); err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	// Idempotent.
	if err := d.EnsureVolume(ctx, app, volName); err != nil {
		t.Fatalf("EnsureVolume (second): %v", err)
	}
	t.Cleanup(func() {
		cli, err := client.New(client.FromEnv)
		if err != nil {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = cli.VolumeRemove(cctx, volName, client.VolumeRemoveOptions{Force: true})
	})

	vols, err := d.ListVolumes(ctx, app)
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	if len(vols) != 1 || vols[0].Name != volName || vols[0].App != app {
		t.Fatalf("unexpected volumes: %+v", vols)
	}
}
