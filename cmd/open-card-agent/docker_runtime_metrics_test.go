package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
)

func TestDockerRuntimeMetricsReaderUsesOnlyAllowlistedGETEndpointsAndRedactsFacts(t *testing.T) {
	type requestFact struct {
		method string
		path   string
	}
	var mu sync.Mutex
	var requests []requestFact
	listener, socketPath := newDockerRuntimeMetricsUnixListener(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, requestFact{method: request.Method, path: request.URL.RequestURI()})
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.RequestURI() {
		case "/containers/opencard-m4-web-01/json?size=1":
			_, _ = writer.Write([]byte(`{"Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","RestartCount":7,"SizeRw":4096,"State":{"Status":"exited","Running":false,"ExitCode":42,"Error":"secret-token-from-runtime"},"Config":{"Env":["API_KEY=secret-token-from-runtime"]},"Mounts":[{"Source":"/host/secret","Destination":"/run/secrets/api-key"}]}`))
		case "/containers/opencard-m4-web-01/stats?stream=false":
			_, _ = writer.Write([]byte(`{"read":"2026-08-25T00:00:02Z","preread":"2026-08-25T00:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":2000000000},"system_cpu_usage":10000000000,"online_cpus":2},"precpu_stats":{"cpu_usage":{"total_usage":1500000000},"system_cpu_usage":9000000000,"online_cpus":2},"memory_stats":{"usage":1234,"limit":9999},"networks":{"eth0":{"rx_bytes":10,"tx_bytes":20},"eth1":{"rx_bytes":30,"tx_bytes":40}},"secret":"secret-token-from-runtime"}`))
		case "/containers/opencard-m4-web-01/changes":
			_, _ = writer.Write([]byte(`[{"Kind":2,"Path":"/run/secrets/api-key"},{"Kind":1,"Path":"/tmp/private-token"}]`))
		default:
			http.Error(writer, "unexpected endpoint", http.StatusForbidden)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	reader, err := NewUnixDockerRuntimeMetricsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := reader.ReadContainerMetrics(context.Background(), "opencard-m4-web-01")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.ContainerID != strings.Repeat("a", 64) || metrics.Status != "exited" || metrics.HealthStatus != "" || metrics.Healthy {
		t.Fatalf("unexpected redacted runtime state: %#v", metrics)
	}
	if metrics.ExitCode != 42 || metrics.ExitReason != "exit_code_42" || metrics.RestartCount != 7 {
		t.Fatalf("unexpected exit facts: %#v", metrics)
	}
	if metrics.CPUUsageMillis != 2000 || metrics.CPUUsageDeltaMillis != 500 || !metrics.CPUUsageRateKnown || metrics.CPUUsageRatePercent != 100 || metrics.SampleIntervalMillis != 2000 {
		t.Fatalf("unexpected CPU sample: %#v", metrics)
	}
	if metrics.MemoryUsageBytes != 1234 || metrics.MemoryLimitBytes != 9999 || metrics.WritableLayerBytes != 4096 || !metrics.WritableLayerSizeKnown {
		t.Fatalf("unexpected memory/disk facts: %#v", metrics)
	}
	if metrics.NetworkRxBytes != 40 || metrics.NetworkTxBytes != 60 || metrics.ChangedPathCount != 2 {
		t.Fatalf("unexpected network/change facts: %#v", metrics)
	}
	encoded, err := json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-token") || strings.Contains(string(encoded), "/run/secrets") || strings.Contains(string(encoded), "/host/secret") {
		t.Fatalf("runtime result leaked inspect or changes payload: %s", encoded)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []requestFact{
		{method: http.MethodGet, path: "/containers/opencard-m4-web-01/json?size=1"},
		{method: http.MethodGet, path: "/containers/opencard-m4-web-01/stats?stream=false"},
		{method: http.MethodGet, path: "/containers/opencard-m4-web-01/changes"},
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("reader made a non-allowlisted Docker request: got %#v want %#v", requests, want)
	}
}

func TestDockerRuntimeMetricsReaderVerifiesInspectLimitsAgainstCgroup(t *testing.T) {
	const containerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	procRoot, cgroupRoot := filepath.Join(t.TempDir(), "proc"), filepath.Join(t.TempDir(), "cgroup")
	cgroupPath := filepath.Join(cgroupRoot, "system.slice", "docker-"+containerID+".scope")
	if err := os.MkdirAll(filepath.Join(procRoot, "123"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cgroupPath, 0o750); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(procRoot, "123", "cgroup"):  "0::/system.slice/docker-" + containerID + ".scope\n",
		filepath.Join(cgroupPath, "cpu.max"):      "25000 100000\n",
		filepath.Join(cgroupPath, "memory.max"):   "67108864\n",
		filepath.Join(cgroupPath, "pids.max"):     "32\n",
		filepath.Join(cgroupPath, "pids.current"): "3\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	listener, socketPath := newDockerRuntimeMetricsUnixListener(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.RequestURI() {
		case "/containers/opencard-m4-running/json?size=1":
			_, _ = writer.Write([]byte(`{"Id":"` + containerID + `","RestartCount":2,"SizeRw":9,"State":{"Status":"running","Running":true,"Pid":123,"ExitCode":0,"Health":{"Status":"healthy"}},"HostConfig":{"Memory":67108864,"CpuPeriod":100000,"CpuQuota":25000,"PidsLimit":32}}`))
		case "/containers/opencard-m4-running/stats?stream=false":
			_, _ = writer.Write([]byte(`{"read":"2026-08-25T00:00:01Z","preread":"2026-08-25T00:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":1000000},"system_cpu_usage":10000000,"online_cpus":1},"precpu_stats":{"cpu_usage":{"total_usage":0},"system_cpu_usage":9000000,"online_cpus":1},"memory_stats":{"usage":1024,"limit":67108864},"pids_stats":{"current":2},"networks":{}}`))
		case "/containers/opencard-m4-running/changes":
			_, _ = writer.Write([]byte(`[]`))
		default:
			http.Error(writer, "unexpected", http.StatusForbidden)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	reader, err := NewUnixDockerRuntimeMetricsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	reader.procRoot, reader.cgroupRoot = procRoot, cgroupRoot
	metrics, err := reader.ReadContainerMetrics(context.Background(), "opencard-m4-running")
	if err != nil {
		t.Fatal(err)
	}
	want := contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, PIDs: 32}
	if metrics.ContainerID != containerID || !metrics.CgroupVerified || metrics.PIDsCurrent != 3 || metrics.AppliedLimits != want || !metrics.Healthy || metrics.RestartCount != 2 {
		t.Fatalf("independent cgroup facts mismatch: %#v", metrics)
	}
}

func TestDockerRuntimeMetricsReaderRejectsUnsafeContainerIdentifiersBeforeDial(t *testing.T) {
	reader, err := NewUnixDockerRuntimeMetricsReader(filepath.Join(t.TempDir(), "missing.sock"))
	if err != nil {
		t.Fatal(err)
	}
	for _, containerID := range []string{
		"", " ", "../secret", "container/other", "container?size=1", "container#fragment",
		"container%2Fother", "container$other", "container\nother", ".", "-", "foo..bar", strings.Repeat("a", 129),
	} {
		t.Run(strings.ReplaceAll(containerID, "/", "_"), func(t *testing.T) {
			if _, err := reader.ReadContainerMetrics(context.Background(), containerID); err == nil {
				t.Fatalf("unsafe container identifier %q was accepted", containerID)
			}
		})
	}
}

func TestDockerRuntimeMetricsReaderNeverReturnsMalformedOrSecretResponseBodies(t *testing.T) {
	const secret = "secret-token-from-malformed-response"
	listener, socketPath := newDockerRuntimeMetricsUnixListener(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/containers/opencard-m4-web-02/json":
			_, _ = writer.Write([]byte(`{"State":` + secret))
		case "/containers/opencard-m4-web-03/json":
			_, _ = writer.Write([]byte(`{"State":{"Status":"running"}}`))
		case "/containers/opencard-m4-web-03/stats":
			_, _ = writer.Write([]byte(`{"cpu_stats":"` + secret + `"}`))
		case "/containers/opencard-m4-web-04/json":
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = writer.Write([]byte(`{"message":"` + secret + `"}`))
		case "/containers/opencard-m4-web-05/json":
			_, _ = writer.Write([]byte(`{"State":{"Status":"running"}}`))
		case "/containers/opencard-m4-web-05/stats":
			_, _ = writer.Write([]byte(`{"cpu_stats":{"cpu_usage":{"total_usage":1}},"memory_stats":{"usage":1,"limit":2}}`))
		case "/containers/opencard-m4-web-05/changes":
			_, _ = writer.Write([]byte(`{"Path":"` + secret + `"}`))
		default:
			http.Error(writer, "unexpected endpoint", http.StatusForbidden)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	reader, err := NewUnixDockerRuntimeMetricsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, containerID := range []string{"opencard-m4-web-02", "opencard-m4-web-03", "opencard-m4-web-04", "opencard-m4-web-05"} {
		t.Run(containerID, func(t *testing.T) {
			_, err := reader.ReadContainerMetrics(context.Background(), containerID)
			if err == nil {
				t.Fatal("malformed or non-200 Docker response was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("Docker response body leaked through error: %v", err)
			}
		})
	}
}

func TestDockerRuntimeMetricsReaderDoesNotFollowRedirects(t *testing.T) {
	listener, socketPath := newDockerRuntimeMetricsUnixListener(t)
	var redirected bool
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/containers/opencard-m4-web-06/json" {
			writer.Header().Set("Location", "http://127.0.0.1:1/escape")
			writer.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		redirected = true
		http.Error(writer, "redirect escaped Unix socket", http.StatusForbidden)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	reader, err := NewUnixDockerRuntimeMetricsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadContainerMetrics(context.Background(), "opencard-m4-web-06"); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected {
		t.Fatal("reader followed a redirect away from the configured Unix socket")
	}
}

func TestDockerRuntimeMetricsReaderAcceptsDockerNullForNoChanges(t *testing.T) {
	listener, socketPath := newDockerRuntimeMetricsUnixListener(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.RequestURI() {
		case "/containers/opencard-m4-null-changes/json?size=1":
			_, _ = writer.Write([]byte(`{"Id":"opencard-m4-null-changes","RestartCount":0,"State":{"Status":"exited","Running":false,"Pid":0,"ExitCode":0},"HostConfig":{"Memory":67108864,"CpuPeriod":100000,"CpuQuota":25000,"PidsLimit":32}}`))
		case "/containers/opencard-m4-null-changes/stats?stream=false":
			_, _ = writer.Write([]byte(`{"read":"2026-08-25T00:00:01Z","preread":"2026-08-25T00:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":0},"system_cpu_usage":1,"online_cpus":1},"precpu_stats":{"cpu_usage":{"total_usage":0},"system_cpu_usage":0,"online_cpus":1},"memory_stats":{"usage":0,"limit":67108864},"pids_stats":{"current":0},"networks":{}}`))
		case "/containers/opencard-m4-null-changes/changes":
			_, _ = writer.Write([]byte(`null`))
		default:
			http.Error(writer, "unexpected", http.StatusForbidden)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	reader, err := NewUnixDockerRuntimeMetricsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := reader.ReadContainerMetrics(context.Background(), "opencard-m4-null-changes")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.ChangedPathCount != 0 {
		t.Fatalf("null Docker changes was not treated as empty: %#v", metrics)
	}
}

func TestDockerRuntimeMetricsReaderDoesNotExposeSocketPathOnTransportFailure(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "private-docker.sock")
	reader, err := NewUnixDockerRuntimeMetricsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadContainerMetrics(context.Background(), "opencard-m4-web-07")
	if err == nil {
		t.Fatal("missing Docker socket was unexpectedly readable")
	}
	if strings.Contains(err.Error(), socketPath) || strings.Contains(err.Error(), "private-docker.sock") {
		t.Fatalf("transport error exposed the configured socket path: %v", err)
	}
}

func newDockerRuntimeMetricsUnixListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "opencard-m4-metrics-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, socketPath
}
