package imageexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/dockermetrics"
)

func TestPinnedDockerRunnerUsesMetricsDaemonWithoutAmbientOverrides(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\"\nif [ -n \"$DOCKER_HOST$DOCKER_CONTEXT$DOCKER_CONFIG$DOCKER_TLS$DOCKER_TLS_VERIFY$DOCKER_CERT_PATH$DOCKER_API_VERSION\" ]; then printf 'dirty\\n'; else printf 'clean\\n'; fi\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_HOST", "tcp://unapproved.example:2376")
	t.Setenv("DOCKER_CONTEXT", "unapproved")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	var stdout, stderr bytes.Buffer
	if err := (defaultCommandRunner{dockerSocketPath: "/run/task-docker.sock"}).Run(context.Background(), "docker", []string{"inspect", "bound-cid"}, &stdout, &stderr); err != nil {
		t.Fatalf("fake Docker runner failed: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "--host\nunix:///run/task-docker.sock\ninspect\nbound-cid\nclean" {
		t.Fatal("Docker target or environment was not pinned")
	}
}

func TestManagedMetricsBoundsBindingAndRateWindow(t *testing.T) {
	q := appcontracts.ImageMetricsRequest{AdminID: "admin", DeploymentID: "dep"}
	if !q.Valid() || (appcontracts.ImageMetricsRequest{AdminID: "admin"}).Valid() {
		t.Fatal("metrics request identity bounds failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (*ContainerRuntime)(nil).ReadManagedImageMetrics(ctx, q); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request reached metrics authority")
	}
	for i := 0; i < cap(observationSlots); i++ {
		observationSlots <- struct{}{}
	}
	_, boundedErr := (&ContainerRuntime{}).ReadManagedImageMetrics(context.Background(), q)
	for i := 0; i < cap(observationSlots); i++ {
		<-observationSlots
	}
	if boundedErr == nil || len(observationSlots) != 0 {
		t.Fatal("shared metrics concurrency bound failed or leaked")
	}
	a := appcontracts.ManagedImageObservationBinding{AdminID: "admin", Runtime: appcontracts.ImageLifecycleBinding{ContainerID: "cid"}}
	b := a
	b.Runtime.ContainerID = "foreign"
	if sameObservationBinding(a, b) {
		t.Fatal("different runtime target accepted")
	}
	started := time.Now().UTC().Add(-time.Minute)
	state := appcontracts.ImageLifecycleResult{Running: true, VerifiedIdentity: true, ContainerID: "cid", ImageID: "sha256:image", ManifestDigest: "sha256:manifest", HostPort: 39001, ContainerPort: 80, ObservedAt: time.Now().UTC()}
	sample := dockermetrics.DockerRuntimeMetrics{ContainerID: "cid", Status: "running", ObservedAt: time.Now().UTC(), CPUUsageMillis: 100, CPUUsageAvailable: true, CPUUsageRateKnown: true, CPUUsageRatePercent: 15, CPURateWindowStartedAt: started.Add(-time.Second), MemoryUsageBytes: 2048, MemoryUsageAvailable: true, NetworkAvailable: false, PIDsAvailable: false}
	result := mapManagedMetrics(state, sample, started)
	if result.CPUPercent != nil || result.NetworkRxBytes != nil || result.NetworkTxBytes != nil || result.PIDsCurrent != nil || result.MemoryUsageBytes == nil || *result.MemoryUsageBytes != 2048 {
		t.Fatal("unknown or cross-restart metrics became numeric zero")
	}
	if err := result.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("valid partial sample rejected: %v", err)
	}
	sample.CPURateWindowStartedAt = started.Add(time.Second)
	sample.NetworkAvailable, sample.PIDsAvailable = true, true
	result = mapManagedMetrics(state, sample, started)
	if result.CPUPercent == nil || result.NetworkRxBytes == nil || result.PIDsCurrent == nil || *result.NetworkRxBytes != 0 || *result.PIDsCurrent != 0 {
		t.Fatal("known zero metrics lost or CPU rate omitted")
	}
	sample.CPUUsageAvailable, sample.MemoryUsageAvailable = false, false
	result = mapManagedMetrics(state, sample, started)
	if !result.Available || result.CPUUsageMillis != nil || result.MemoryUsageBytes != nil || result.NetworkRxBytes == nil || result.PIDsCurrent == nil {
		t.Fatal("partial Docker sample was discarded or unknown usage became zero")
	}
	if err := result.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("valid partial network/PID sample rejected: %v", err)
	}
	raw, _ := json.Marshal(result)
	if _, err := decodeManagedMetricsResult(raw); err != nil {
		t.Fatalf("typed metrics reply rejected: %v", err)
	}
	result.Available, result.UnavailableReason = false, "runtime_changed"
	result.SampledAt = time.Time{}
	result.ProcessStartedAt = time.Time{}
	result.CPUPercent, result.CPUUsageMillis, result.MemoryUsageBytes, result.NetworkRxBytes, result.NetworkTxBytes, result.PIDsCurrent = nil, nil, nil, nil, nil, nil
	if err := result.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("running but changing process must be unavailable: %v", err)
	}
	result.UnavailableReason = "not_running"
	if err := result.Validate(time.Now().UTC()); err == nil {
		t.Fatal("running process was falsely reported stopped")
	}
	result.State.Running = false
	if err := result.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("verified non-running process rejected: %v", err)
	}
	result.UnavailableReason = "read_unavailable"
	if err := result.Validate(time.Now().UTC()); err == nil {
		t.Fatal("non-running process was falsely reported as a failed live read")
	}
}
