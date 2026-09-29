package hostmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestSamplerRecentCapacityOrderTimeExpiryAndDeepCopy(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	reader := linuxFixture()
	sampler := testSampler(reader, &now)

	for i := 0; i < 400; i++ {
		total := 100 + i*10
		idle := 700 + i*2
		reader.files["/proc/stat"] = []byte("cpu  " + strconv.Itoa(total) + " 0 " + strconv.Itoa(total) + " " + strconv.Itoa(idle) + " 100 0 0 0 0 0\n")
		rx := 1000 + i*100
		tx := 2000 + i*100
		reader.files["/proc/net/dev"] = []byte("  eth0: " + strconv.Itoa(rx) + " 0 0 0 0 0 0 0 " + strconv.Itoa(tx) + " 0 0 0 0 0 0 0\n")
		sampler.Sample(context.Background())
		if i < 399 {
			now = now.Add(time.Second)
		}
	}

	all := sampler.Recent(500)
	if len(all) != MaxRecentObservations {
		t.Fatalf("expected %d entries, got %d", MaxRecentObservations, len(all))
	}
	expectedOldest := time.Unix(1040, 0).UTC()
	if all[0].ObservedAt == nil || !all[0].ObservedAt.Equal(expectedOldest) {
		t.Fatalf("expected oldest timestamp %v, got %v", expectedOldest, all[0].ObservedAt)
	}
	expectedNewest := time.Unix(1399, 0).UTC()
	if all[len(all)-1].ObservedAt == nil || !all[len(all)-1].ObservedAt.Equal(expectedNewest) {
		t.Fatalf("expected newest timestamp %v, got %v", expectedNewest, all[len(all)-1].ObservedAt)
	}
	for i := 1; i < len(all); i++ {
		if !all[i].ObservedAt.After(*all[i-1].ObservedAt) {
			t.Fatalf("entries not ordered oldest to newest: [%d]=%v <= [%d]=%v", i, all[i].ObservedAt, i-1, all[i-1].ObservedAt)
		}
	}

	defaultRecent := sampler.Recent(0)
	if len(defaultRecent) != DefaultRecentLimit {
		t.Fatalf("expected %d default entries, got %d", DefaultRecentLimit, len(defaultRecent))
	}
	if !defaultRecent[len(defaultRecent)-1].ObservedAt.Equal(expectedNewest) {
		t.Fatalf("default recent does not end at newest: got %v", defaultRecent[len(defaultRecent)-1].ObservedAt)
	}

	if neg := sampler.Recent(-1); len(neg) != DefaultRecentLimit {
		t.Fatalf("expected %d negative-limit entries, got %d", DefaultRecentLimit, len(neg))
	}

	small := sampler.Recent(10)
	if len(small) != 10 {
		t.Fatalf("expected 10 entries, got %d", len(small))
	}
	if !small[9].ObservedAt.Equal(expectedNewest) {
		t.Fatalf("small limit does not end at newest: got %v", small[9].ObservedAt)
	}
	expectedSmallOldest := time.Unix(1390, 0).UTC()
	if !small[0].ObservedAt.Equal(expectedSmallOldest) {
		t.Fatalf("expected small oldest %v, got %v", expectedSmallOldest, small[0].ObservedAt)
	}

	now = now.Add(31 * time.Minute)
	expired := sampler.Recent(360)
	if len(expired) != 0 {
		t.Fatalf("expected 0 entries after time expiry, got %d", len(expired))
	}

	now = now.Add(time.Second)
	reader.files["/proc/stat"] = []byte("cpu  4200 0 4200 1500 100 0 0 0 0 0\n")
	reader.files["/proc/net/dev"] = []byte("  eth0: 42000 0 0 0 0 0 0 0 43000 0 0 0 0 0 0 0\n")
	sampler.Sample(context.Background())
	fresh := sampler.Recent(1)
	if len(fresh) != 1 || fresh[0].CPU == nil || fresh[0].CPU.UsagePercent == nil || fresh[0].Network == nil || fresh[0].Network.RXBytesPerSecond == nil {
		t.Fatalf("unexpected fresh sample: %#v", fresh)
	}

	origObserved := *fresh[0].ObservedAt
	origUsage := *fresh[0].CPU.UsagePercent
	origCores := fresh[0].CPU.LogicalCores
	origTotalMem := fresh[0].Memory.TotalBytes
	origMount := fresh[0].Disk.Mountpoint
	origIface := fresh[0].Network.Interface
	origRX := *fresh[0].Network.RXBytesPerSecond

	*fresh[0].ObservedAt = time.Unix(0, 0).UTC()
	*fresh[0].CPU.UsagePercent = -999.0
	fresh[0].CPU.LogicalCores = 0
	fresh[0].Memory.TotalBytes = 0
	fresh[0].Disk.Mountpoint = "/mutated"
	fresh[0].Network.Interface = "mutated0"
	*fresh[0].Network.RXBytesPerSecond = -999.0

	fresh2 := sampler.Recent(1)
	if len(fresh2) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(fresh2))
	}
	if !fresh2[0].ObservedAt.Equal(origObserved) {
		t.Fatalf("ObservedAt mutated: expected %v, got %v", origObserved, fresh2[0].ObservedAt)
	}
	if *fresh2[0].CPU.UsagePercent != origUsage {
		t.Fatalf("CPU.UsagePercent mutated: expected %v, got %v", origUsage, *fresh2[0].CPU.UsagePercent)
	}
	if fresh2[0].CPU.LogicalCores != origCores {
		t.Fatalf("LogicalCores mutated: expected %d, got %d", origCores, fresh2[0].CPU.LogicalCores)
	}
	if fresh2[0].Memory.TotalBytes != origTotalMem {
		t.Fatalf("Memory.TotalBytes mutated: expected %d, got %d", origTotalMem, fresh2[0].Memory.TotalBytes)
	}
	if fresh2[0].Disk.Mountpoint != origMount {
		t.Fatalf("Disk.Mountpoint mutated: expected %q, got %q", origMount, fresh2[0].Disk.Mountpoint)
	}
	if fresh2[0].Network.Interface != origIface {
		t.Fatalf("Network.Interface mutated: expected %q, got %q", origIface, fresh2[0].Network.Interface)
	}
	if *fresh2[0].Network.RXBytesPerSecond != origRX {
		t.Fatalf("Network.RXBytesPerSecond mutated: expected %v, got %v", origRX, *fresh2[0].Network.RXBytesPerSecond)
	}
}

func TestSamplerRecentFailureGapAndRestartEmpty(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	reader := linuxFixture()
	sampler := testSampler(reader, &now)

	empty := sampler.Recent(10)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("expected empty non-nil slice before samples, got %#v", empty)
	}

	darwinSampler := NewSampler(Config{OS: "darwin"})
	if got := darwinSampler.Recent(10); got == nil || len(got) != 0 {
		t.Fatalf("expected empty slice from non-linux sampler, got %#v", got)
	}

	t0 := now
	sampler.Sample(context.Background())
	h1 := sampler.Recent(10)
	if len(h1) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(h1))
	}
	if h1[0].Availability != WarmingUp || h1[0].ObservedAt == nil || !h1[0].ObservedAt.Equal(t0) {
		t.Fatalf("initial observation availability/time mismatch: %#v", h1[0])
	}
	if h1[0].CPU == nil || h1[0].CPU.UsagePercent != nil {
		t.Fatalf("expected nil CPU usage on first sample, got %#v", h1[0].CPU)
	}
	if h1[0].Network == nil || h1[0].Network.RXBytesPerSecond != nil {
		t.Fatalf("expected nil Network rate on first sample, got %#v", h1[0].Network)
	}

	now = now.Add(5 * time.Second)
	t1 := now
	reader.files["/proc/stat"] = []byte("cpu  150 0 150 750 100 0 0 0 0 0\n")
	reader.files["/proc/net/dev"] = []byte("  eth0: 1500 0 0 0 0 0 0 0 2500 0 0 0 0 0 0 0\n")
	sampler.Sample(context.Background())

	h2 := sampler.Recent(10)
	if len(h2) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(h2))
	}
	snap := sampler.Snapshot()
	if h2[1].Availability != snap.Availability || h2[1].Availability != Available || !h2[1].ObservedAt.Equal(t1) {
		t.Fatalf("second observation = %#v, snap = %#v", h2[1], snap)
	}
	if h2[1].CPU == nil || snap.CPU == nil || h2[1].CPU.UsagePercent == nil || *h2[1].CPU.UsagePercent != *snap.CPU.UsagePercent {
		t.Fatalf("expected matching CPU usage: recent=%#v snap=%#v", h2[1].CPU, snap.CPU)
	}
	if h2[1].Network == nil || snap.Network == nil || h2[1].Network.RXBytesPerSecond == nil || *h2[1].Network.RXBytesPerSecond != *snap.Network.RXBytesPerSecond {
		t.Fatalf("expected matching Network rate: recent=%#v snap=%#v", h2[1].Network, snap.Network)
	}

	now = now.Add(5 * time.Second)
	t2 := now
	reader.fsErr = errors.New("disk read error")
	sampler.Sample(context.Background())

	h3 := sampler.Recent(10)
	if len(h3) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(h3))
	}
	gap := h3[2]
	if gap.Availability != Unavailable {
		t.Fatalf("expected Unavailable gap observation, got %v", gap.Availability)
	}
	if gap.ObservedAt == nil || !gap.ObservedAt.Equal(t2) {
		t.Fatalf("gap observation must record sampling time: expected %v, got %v", t2, gap.ObservedAt)
	}
	if gap.CPU != nil || gap.Memory != nil || gap.Disk != nil || gap.Network != nil {
		t.Fatalf("gap observation must have nil metric payloads, got %#v", gap)
	}

	snapFail := sampler.Snapshot()
	if snapFail.Availability != Unavailable || snapFail.ObservedAt != nil {
		t.Fatalf("Snapshot() after failure must have nil ObservedAt: %#v", snapFail)
	}

	now = now.Add(5 * time.Second)
	t3 := now
	reader.fsErr = nil
	reader.files["/proc/stat"] = []byte("cpu  200 0 200 800 100 0 0 0 0 0\n")
	reader.files["/proc/net/dev"] = []byte("  eth0: 2000 0 0 0 0 0 0 0 3000 0 0 0 0 0 0 0\n")
	sampler.Sample(context.Background())

	h4 := sampler.Recent(10)
	if len(h4) != 4 {
		t.Fatalf("expected 4 observations, got %d", len(h4))
	}
	recovered := h4[3]
	if recovered.Availability != WarmingUp {
		t.Fatalf("observation right after failure must be WarmingUp, got %v", recovered.Availability)
	}
	if !recovered.ObservedAt.Equal(t3) {
		t.Fatalf("expected timestamp %v, got %v", t3, recovered.ObservedAt)
	}
	if recovered.CPU == nil || recovered.CPU.UsagePercent != nil {
		t.Fatalf("CPU usage must be nil after failure (rate cannot bridge gap), got %#v", recovered.CPU)
	}
	if recovered.Network == nil || recovered.Network.RXBytesPerSecond != nil {
		t.Fatalf("Network rate must be nil after failure (rate cannot bridge gap), got %#v", recovered.Network)
	}
	if recovered.Memory == nil || recovered.Disk == nil {
		t.Fatalf("Memory and Disk must be populated on recovered sample: %#v", recovered)
	}

	now = now.Add(5 * time.Second)
	t4 := now
	reader.files["/proc/stat"] = []byte("cpu  250 0 250 850 100 0 0 0 0 0\n")
	reader.files["/proc/net/dev"] = []byte("  eth0: 2500 0 0 0 0 0 0 0 3500 0 0 0 0 0 0 0\n")
	sampler.Sample(context.Background())

	h5 := sampler.Recent(10)
	if len(h5) != 5 {
		t.Fatalf("expected 5 observations, got %d", len(h5))
	}
	snapRecovered := sampler.Snapshot()
	if h5[4].Availability != snapRecovered.Availability || h5[4].Availability != Available || !h5[4].ObservedAt.Equal(t4) {
		t.Fatalf("expected Available observation at %v matching snapshot: recent=%#v, snap=%#v", t4, h5[4], snapRecovered)
	}
	if h5[4].CPU == nil || snapRecovered.CPU == nil || h5[4].CPU.UsagePercent == nil || *h5[4].CPU.UsagePercent != *snapRecovered.CPU.UsagePercent {
		t.Fatalf("expected computed rates matching snapshot: recent=%#v snap=%#v", h5[4], snapRecovered)
	}
	if h5[4].Network == nil || snapRecovered.Network == nil || h5[4].Network.RXBytesPerSecond == nil || *h5[4].Network.RXBytesPerSecond != *snapRecovered.Network.RXBytesPerSecond {
		t.Fatalf("expected computed network rates matching snapshot: recent=%#v snap=%#v", h5[4], snapRecovered)
	}
}
