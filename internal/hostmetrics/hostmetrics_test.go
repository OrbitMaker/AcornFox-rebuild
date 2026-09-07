package hostmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeReader struct {
	mu    sync.Mutex
	files map[string][]byte
	fs    Filesystem
	fsErr error
}

func (r *fakeReader) ReadFile(path string, limit int64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.files[path]
	if !ok {
		return nil, errors.New("missing")
	}
	if int64(len(value)) > limit {
		return append([]byte(nil), value...), nil
	}
	return append([]byte(nil), value...), nil
}

func (r *fakeReader) Statfs(string) (Filesystem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fs, r.fsErr
}

func linuxFixture() *fakeReader {
	return &fakeReader{files: map[string][]byte{
		"/proc/stat":      []byte("cpu  100 0 100 700 100 0 0 0 0 0\n"),
		"/proc/meminfo":   []byte("MemTotal:       1000 kB\nMemAvailable:    400 kB\n"),
		"/proc/net/route": []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 00000000 0003 0 0 0 00000000 0 0 0\n"),
		"/proc/net/dev":   []byte("Inter-|   Receive                                                |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"),
	}, fs: Filesystem{Blocks: 100, AvailableBlocks: 40, BlockSize: 1024}}
}

func testSampler(reader Reader, now *time.Time) *Sampler {
	return NewSampler(Config{Reader: reader, OS: "linux", Now: func() time.Time { return *now }, LogicalCores: func() int { return 4 }})
}

func TestSamplerCPUDeltaAndNetworkRate(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	reader := linuxFixture()
	sampler := testSampler(reader, &now)
	sampler.Sample(context.Background())
	first := sampler.Snapshot()
	if first.Availability != WarmingUp || first.CPU == nil || first.CPU.UsagePercent != nil || first.Network == nil || first.Network.RXBytesPerSecond != nil {
		t.Fatalf("first snapshot = %#v", first)
	}
	reader.files["/proc/stat"] = []byte("cpu  150 0 150 750 100 0 0 0 0 0\n")
	reader.files["/proc/net/dev"] = []byte("  eth0: 1500 0 0 0 0 0 0 0 2500 0 0 0 0 0 0 0\n")
	now = now.Add(5 * time.Second)
	sampler.Sample(context.Background())
	got := sampler.Snapshot()
	if got.Availability != Available || got.CPU == nil || got.CPU.UsagePercent == nil || *got.CPU.UsagePercent != 66.67 {
		t.Fatalf("cpu snapshot = %#v", got)
	}
	if got.Memory == nil || got.Memory.UsedBytes != 600*1024 || got.Disk == nil || got.Disk.UsedBytes != 60*1024 {
		t.Fatalf("memory/disk snapshot = %#v", got)
	}
	if got.Network == nil || got.Network.RXBytesPerSecond == nil || got.Network.TXBytesPerSecond == nil || *got.Network.RXBytesPerSecond != 100 || *got.Network.TXBytesPerSecond != 100 {
		t.Fatalf("network snapshot = %#v", got.Network)
	}
}

func TestSamplerCounterResetAndInterfaceHandoverRemainUnknown(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	reader := linuxFixture()
	sampler := testSampler(reader, &now)
	sampler.Sample(context.Background())
	now = now.Add(5 * time.Second)
	reader.files["/proc/stat"] = []byte("cpu  150 0 150 750 100 0 0 0 0 0\n")
	sampler.Sample(context.Background())
	now = now.Add(5 * time.Second)
	reader.files["/proc/stat"] = []byte("cpu  10 0 10 70 10 0 0 0 0 0\n")
	reader.files["/proc/net/route"] = []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth1 00000000 00000000 0003 0 0 0 00000000 0 0 0\n")
	reader.files["/proc/net/dev"] = []byte(" eth1: 5 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n")
	sampler.Sample(context.Background())
	got := sampler.Snapshot()
	if got.Availability != WarmingUp || got.CPU == nil || got.CPU.UsagePercent != nil || got.Network == nil || got.Network.Interface != "eth1" || got.Network.RXBytesPerSecond != nil || got.Network.TXBytesPerSecond != nil {
		t.Fatalf("reset/handover snapshot = %#v", got)
	}
}

func TestSamplerMissingFilesystemAndStaleSnapshotAreUnavailable(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	reader := linuxFixture()
	reader.fsErr = errors.New("not mounted")
	sampler := testSampler(reader, &now)
	sampler.Sample(context.Background())
	missing := sampler.Snapshot()
	if missing.Availability != Unavailable || missing.CPU != nil || missing.Memory != nil || missing.Disk != nil || missing.Network != nil {
		t.Fatalf("missing filesystem snapshot = %#v", missing)
	}
	reader.fsErr = nil
	sampler.Sample(context.Background())
	now = now.Add(16 * time.Second)
	stale := sampler.Snapshot()
	if stale.Availability != Unavailable || stale.ObservedAt == nil || stale.CPU != nil || stale.Network != nil {
		t.Fatalf("stale snapshot = %#v", stale)
	}
}

func TestParsersRejectMalformedAndOversizedInputs(t *testing.T) {
	if _, err := parseCPU([]byte("cpu  1 x 3 4 5\n")); err == nil {
		t.Fatal("expected malformed cpu failure")
	}
	if _, err := parseMemory([]byte("MemTotal: 1 kB\n")); err == nil {
		t.Fatal("expected missing MemAvailable failure")
	}
	if _, err := parseDefaultInterface([]byte("Iface Destination Gateway Flags\neth0 00000000 0 0000\n")); err == nil {
		t.Fatal("expected no usable default route")
	}
	now := time.Unix(100, 0).UTC()
	reader := linuxFixture()
	reader.files["/proc/stat"] = make([]byte, maxProcFileBytes+1)
	sampler := testSampler(reader, &now)
	sampler.Sample(context.Background())
	if got := sampler.Snapshot(); got.Availability != Unavailable {
		t.Fatalf("oversized input snapshot = %#v", got)
	}
}

func TestHTTPHandlerIsStrictGETAndReturnsTypedResponse(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	sampler := testSampler(linuxFixture(), &now)
	sampler.Sample(context.Background())
	handler := NewHTTPHandler(sampler)
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/host/metrics", nil))
	if denied.Code != http.StatusMethodNotAllowed || denied.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method response = %d, allow=%q", denied.Code, denied.Header().Get("Allow"))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics", nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET response = %d, type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	var body Response
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.SchemaVersion != 1 || body.Availability != WarmingUp {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
}

func TestNonLinuxSamplerIsUnsupported(t *testing.T) {
	sampler := NewSampler(Config{OS: "darwin"})
	if got := sampler.Snapshot(); got.Availability != Unsupported || got.ObservedAt != nil || got.CPU != nil {
		t.Fatalf("non-linux snapshot = %#v", got)
	}
}

func TestSamplerStartStopsWithContextAndSnapshotsRaceSafely(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	sampler := testSampler(linuxFixture(), &now)
	ctx, cancel := context.WithCancel(context.Background())
	sampler.Start(ctx)
	deadline := time.Now().Add(time.Second)
	for sampler.Snapshot().ObservedAt == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sampler.Snapshot().ObservedAt == nil {
		t.Fatal("sampler did not take its startup sample")
	}
	cancel()
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				_ = sampler.Snapshot()
			}
		}()
	}
	wait.Wait()
}
